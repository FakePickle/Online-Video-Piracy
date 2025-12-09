#!/usr/bin/env python3
"""
Secure RTSP client that receives encrypted frame payloads via GStreamer,
decrypts them with AES-GCM, displays them with OpenCV and writes them to an MP4 file.

Usage:
    python3 secure_client_recorder.py <rtsp_url> <user_id> [output.mp4]
"""

import hashlib
import queue
import struct
import sys
import time
from typing import Optional

import cv2
import gi
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from gi.repository import GLib, Gst

gi.require_version("Gst", "1.0")

# ============================================================
# CONFIG
# ============================================================
WIDTH, HEIGHT = 1920, 1080
TARGET_FPS = 30
MASTER_KEY = b"THIS_IS_YOUR_MASTER_KEY_CHANGE_ME_32B"  # 32 bytes; change in production


# ============================================================
# KEY + DNA
# ============================================================
def kdf(master: bytes, label: bytes) -> bytes:
    """Simple KDF: SHA-256(master || label)"""
    return hashlib.sha256(master + label).digest()


def generate_dna_bits(user_id: str):
    """Derive 32 bits of DNA from the user's SHA-256 digest"""
    h = hashlib.sha256(user_id.encode()).digest()
    bits = []
    for b in h[:4]:  # 4 bytes → 32 bits
        for i in range(8):
            bits.append((b >> i) & 1)
    return bits


# ============================================================
# SECURE CLIENT CLASS
# ============================================================
class SecureClient:
    def __init__(self, rtsp_url: str, user_id: str, output_mp4: Optional[str] = "output.mp4"):
        self.rtsp_url = rtsp_url
        self.user_id = user_id
        self.recv_buffer = bytearray()

        # Derive key + nonce prefix
        self.key = kdf(MASTER_KEY, user_id.encode())[:32]
        self.aesgcm = AESGCM(self.key)

        nonce_seed = kdf(MASTER_KEY, b"nonce-" + user_id.encode())
        self.nonce_prefix = nonce_seed[:8]  # 8 bytes

        self.dna = generate_dna_bits(user_id)
        self.frame_index = 0

        self.loop = None
        self.pipeline = None

        self.frame_queue = queue.Queue(maxsize=4)
        self.first_frame = True
        self.running = True

        self.frames = 0
        self.last_log = time.time()

        # Video writer for MP4 output
        self.output_mp4 = output_mp4
        fourcc = cv2.VideoWriter_fourcc(*"mp4v")  # widely-compatible
        self.writer = cv2.VideoWriter(self.output_mp4, fourcc, TARGET_FPS, (WIDTH, HEIGHT))
        if not self.writer.isOpened():
            print(f"[Client] WARNING: Could not open writer for {self.output_mp4}")

        print(f"[Client] Initialized → {user_id}")
        print(f"[Client] URL: {rtsp_url}")
        print(f"[Client] DNA bits sample: {self.dna[:8]} ...")
        print(f"[Client] Recording to: {self.output_mp4}")

    # --------------------------------------------------------
    # Pipeline message handling
    # --------------------------------------------------------
    def on_bus_message(self, bus, msg):
        t = msg.type

        if t == Gst.MessageType.EOS:
            print("[Client] EOS")
            self.stop()

        elif t == Gst.MessageType.ERROR:
            err, debug = msg.parse_error()
            print(f"[Client] ERROR: {err}")
            print(f"[Client] Debug: {debug}")
            self.stop()

        elif t == Gst.MessageType.STREAM_START:
            print("[Client] Stream started!")

        elif t == Gst.MessageType.STATE_CHANGED:
            if msg.src == self.pipeline:
                old, new, _ = msg.parse_state_changed()
                print(f"[Client] Pipeline: {old.value_nick} → {new.value_nick}")

        return True

    # --------------------------------------------------------
    # on_pad_added handler
    # --------------------------------------------------------
    def on_pad_added(self, src, pad):
        print(f"[Client] Pad added: {pad.get_name()}")
        caps = pad.get_current_caps()
        if caps:
            print(f"[Client] Pad caps: {caps.to_string()}")

        depay = self.pipeline.get_by_name("depay")
        sinkpad = depay.get_static_pad("sink")

        if not sinkpad.is_linked():
            r = pad.link(sinkpad)
            print(f"[Client] Pad link → {r}")

    # --------------------------------------------------------
    # Build GStreamer pipeline
    # --------------------------------------------------------
    def build_pipeline(self):
        Gst.init(None)

        self.pipeline = Gst.Pipeline.new("secure-client")

        src = Gst.ElementFactory.make("rtspsrc", "src")
        depay = Gst.ElementFactory.make("rtpgstdepay", "depay")
        appsink = Gst.ElementFactory.make("appsink", "sink")

        if not all([src, depay, appsink]):
            print("[Client] ERROR: element creation failed")
            return False

        # Configure rtspsrc
        src.set_property("location", self.rtsp_url)
        src.set_property("latency", 200)
        src.set_property("retry", 5)

        # appsink receives raw encrypted bytes (application/octet-stream)
        caps = Gst.Caps.from_string("application/octet-stream")
        appsink.set_property("caps", caps)
        appsink.set_property("emit-signals", True)
        appsink.set_property("sync", False)
        appsink.set_property("max-buffers", 1)
        appsink.set_property("drop", True)

        self.pipeline.add(src)
        self.pipeline.add(depay)
        self.pipeline.add(appsink)

        if not depay.link(appsink):
            print("[Client] ERROR: depay → appsink link failed")
            return False

        # Connect handlers
        src.connect("pad-added", self.on_pad_added)
        appsink.connect("new-sample", self.on_new_sample)

        bus = self.pipeline.get_bus()
        bus.add_signal_watch()
        bus.connect("message", self.on_bus_message)

        return True

    # --------------------------------------------------------
    # on_new_sample: GStreamer THREAD → decrypt only, NO imshow directly
    # --------------------------------------------------------
    def on_new_sample(self, sink):
        sample = sink.emit("pull-sample")
        if not sample:
            return Gst.FlowReturn.OK

        buffer = sample.get_buffer()
        success, mapinfo = buffer.map(Gst.MapFlags.READ)
        if not success:
            return Gst.FlowReturn.OK

        data = bytes(mapinfo.data)
        buffer.unmap(mapinfo)

        # Append incoming RTP payload to reassembly buffer
        self.recv_buffer.extend(data)

        while True:
            # We need at least 9 bytes for the fixed header
            if len(self.recv_buffer) < 9:
                break

            # big-endian frame index (4), dna_bit (1), cipher_len (4)
            frame_index = struct.unpack(">I", self.recv_buffer[0:4])[0]
            dna_bit = self.recv_buffer[4]
            cipher_len = struct.unpack(">I", self.recv_buffer[5:9])[0]

            if len(self.recv_buffer) < 9 + cipher_len:
                break  # wait for full ciphertext

            ciphertext = self.recv_buffer[9 : 9 + cipher_len]
            del self.recv_buffer[: 9 + cipher_len]

            # Construct nonce and AD
            nonce = self.nonce_prefix + frame_index.to_bytes(4, "big") + bytes([dna_bit])
            ad = self.user_id.encode() + frame_index.to_bytes(4, "big") + bytes([dna_bit])

            try:
                plaintext = self.aesgcm.decrypt(nonce, ciphertext, ad)
            except Exception as e:
                # Auth failure — produce a black/corrupted frame to discourage recording
                print(f"[Client][Frame {frame_index}] Decryption failed - possible tampering: {e}")
                corrupted_frame = np.zeros((HEIGHT, WIDTH, 3), dtype=np.uint8)
                # try to push corrupted frame (best-effort)
                try:
                    if not self.frame_queue.full():
                        self.frame_queue.put(corrupted_frame)
                    # write corrupted frame as well (so the recorded file reflects tamper)
                    if self.writer and self.writer.isOpened():
                        self.writer.write(corrupted_frame)
                except Exception:
                    pass
                continue

            # Server sends compressed JPEG bytes (encrypted). Try to decode.
            try:
                arr = np.frombuffer(plaintext, dtype=np.uint8)
                dec = cv2.imdecode(arr, cv2.IMREAD_COLOR)
                if dec is None:
                    # Fall back to raw frame assumption (H, W, 3) order
                    try:
                        frame = arr.reshape((HEIGHT, WIDTH, 3))
                    except Exception:
                        print(f"[Client][Frame {frame_index}] Decode fallback reshape failed")
                        continue
                else:
                    frame = dec
            except Exception:
                print(f"[Client][Frame {frame_index}] Decode failed")
                continue

            # Ensure frame has required size. If not, resize (avoid writer crash)
            if frame.shape[1] != WIDTH or frame.shape[0] != HEIGHT:
                frame = cv2.resize(frame, (WIDTH, HEIGHT), interpolation=cv2.INTER_LINEAR)

            # Put frame into display queue (non-blocking best-effort)
            try:
                if not self.frame_queue.full():
                    self.frame_queue.put(frame)
            except Exception:
                pass

            # Write frame to MP4 (best-effort)
            try:
                if self.writer and self.writer.isOpened():
                    self.writer.write(frame)
            except Exception as e:
                print(f"[Client] Error writing frame to {self.output_mp4}: {e}")

            # simple stats
            self.frames += 1
            if time.time() - self.last_log > 5.0:
                print(f"[Client] Frames written: {self.frames}")
                self.last_log = time.time()

        return Gst.FlowReturn.OK

    # --------------------------------------------------------
    # Display loop running in MAIN thread only
    # --------------------------------------------------------
    def display_loop(self):
        try:
            frame = self.frame_queue.get(timeout=0.01)
            cv2.imshow("Secure Decrypted Stream", frame)

            key = cv2.waitKey(1) & 0xFF
            if key == 27 or key == ord("q"):
                print("[Client] Quit pressed")
                self.stop()
                return False  # stop timer
        except queue.Empty:
            pass

        return True  # continue timer

    # --------------------------------------------------------
    # Run
    # --------------------------------------------------------
    def run(self):
        if not self.build_pipeline():
            print("[Client] Pipeline build failed")
            return

        print("[Client] PLAYING...")
        ret = self.pipeline.set_state(Gst.State.PLAYING)

        if ret == Gst.StateChangeReturn.FAILURE:
            print("[Client] ERROR: Couldn't start pipeline")
            return

        self.loop = GLib.MainLoop()

        # Install display callback on the MAIN thread - runs roughly every 10 ms
        GLib.timeout_add(10, self.display_loop)

        try:
            print("[Client] Main loop running")
            self.loop.run()
        except KeyboardInterrupt:
            print("[Client] Interrupted by user")
            self.stop()

    # --------------------------------------------------------
    # Stop
    # --------------------------------------------------------
    def stop(self):
        if not self.running:
            return

        print("[Client] Stopping...")
        self.running = False

        # stop pipeline
        try:
            if self.pipeline:
                self.pipeline.set_state(Gst.State.NULL)
        except Exception:
            pass

        # release writer
        try:
            if self.writer and self.writer.isOpened():
                self.writer.release()
                print(f"[Client] Released writer {self.output_mp4}")
        except Exception as e:
            print(f"[Client] Error releasing writer: {e}")

        # stop mainloop
        try:
            if self.loop and self.loop.is_running():
                self.loop.quit()
        except Exception:
            pass

        cv2.destroyAllWindows()
        print("[Client] Stopped.")


# ============================================================
# ENTRY POINT
# ============================================================
def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <rtsp_url> <user_id> [output.mp4]")
        sys.exit(1)

    url = sys.argv[1]
    user_id = sys.argv[2]
    out = sys.argv[3] if len(sys.argv) >= 4 else "output.mp4"

    print("\n============================================================")
    print("  Secure RTSP Client Recorder")
    print("============================================================\n")

    client = SecureClient(url, user_id, out)
    client.run()


if __name__ == "__main__":
    main()
