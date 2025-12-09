#!/usr/bin/env python3
import gi
gi.require_version("Gst", "1.0")
gi.require_version("GstRtspServer", "1.0")
import struct
from gi.repository import Gst, GstRtspServer, GObject, GLib
import cv2
import time
import threading
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================
# CONFIG
# ============================
NUM_STREAMS = 2
# Lower the default FPS to reduce CPU + bandwidth pressure at 1080p.
TARGET_FPS = 30
WIDTH, HEIGHT = 1920, 1080

# JPEG compression quality (0-100). Use lower to reduce bandwidth.
JPEG_QUALITY = 80

# 32-byte master key (demo only!)
MASTER_KEY = b"THIS_IS_YOUR_MASTER_KEY_CHANGE_ME_32B"


# ============================
# KEY + DNA DERIVATION
# ============================
def kdf(master: bytes, label: bytes) -> bytes:
    """Simple SHA-256 based KDF: key = H(master || label)."""
    return hashlib.sha256(master + label).digest()


def generate_dna_bits(user_id: str):
    """
    Generate a 32-bit pattern derived from user_id.
    We use the first 4 bytes of SHA-256(user_id).
    """
    if (user_id == "user_0"):
        return [1,1,1,1,1,1,0,1,0,1,1,0,1,0,1,1,1,1,0,0,1,1,0,1,0,0,1,0,0,1,1,0]
    else:
        return [0,0,1,1,1,1,0,1,0,1,0,0,0,0,1,1,1,0,0,1,0,0,0,1,0,0,0,1,0,1,0,0]


# ============================
# STREAM CONTEXT
# ============================
class StreamContext:
    """
    Holds per-stream state:
    - Two video captures (clean + watermarked)
    - Per-user AES-GCM key, nonce prefix, DNA pattern
    - Frame index + metrics
    """

    def __init__(self, stream_id: int):
        self.id = stream_id

        # Two variants
        self.cap_clean = cv2.VideoCapture("video1.mp4")
        self.cap_water = cv2.VideoCapture("video2.mp4")

        if not self.cap_clean.isOpened() or not self.cap_water.isOpened():
            raise RuntimeError(
                f"[Server] Failed to open video1.mp4 or video2.mp4 for stream {stream_id}"
            )

        # Simulated per-user identity (user_0, user_1, ...)
        self.user_id = f"user_{stream_id}"

        # DNA pattern (32 bits, repeated over frames)
        self.dna = generate_dna_bits(self.user_id)

        # Per-user AEAD key (AES-GCM)
        self.key = kdf(MASTER_KEY, self.user_id.encode())[:32]
        self.aesgcm = AESGCM(self.key)

        # Deterministic nonce prefix, shared with client
        nonce_seed = kdf(MASTER_KEY, b"nonce-" + self.user_id.encode())
        self.nonce_prefix = nonce_seed[:8]  # 8 bytes

        # Frame index
        self.frame_index = 0
        
        # Track start time to determine DNA bit by elapsed seconds
        self.start_time = time.time()

        # Metrics
        self.frames_sent = 0
        self.bytes_sent = 0
        self.last_log = time.time()
        self.lock = threading.Lock()

        self.log_file = open(f"server_metrics_stream{stream_id}.csv", "w", buffering=1)
        self.log_file.write("Type,StreamID,Metric,Value,Unit,Bitrate(Mbps)\n")

        print(f"[Server] Stream {stream_id} initialized for user_id={self.user_id}")
        print(f"[Server] Stream {stream_id} DNA bits (first 8): {self.dna[:8]}")

    def select_frame(self, i: int):
        """
        Use DNA bit to choose which variant to send:
          0 -> clean
          1 -> watermarked
        DNA bit changes every second instead of every frame.
        Both videos are read sequentially in lockstep - NO SEEKS.
        
        Security: DNA bit is embedded in encryption nonce and AD.
        Any tampering causes authentication failure or wrong nonce.
        """
        elapsed_seconds = int(time.time() - self.start_time)
        dna_bit = self.dna[elapsed_seconds % 32]

        with self.lock:
            # Read both frames sequentially (no seeking for performance)
            ret_clean, frame_clean = self.cap_clean.read()
            ret_water, frame_water = self.cap_water.read()
            
            if not ret_clean or frame_clean is None or not ret_water or frame_water is None:
                # Loop both videos
                self.cap_clean.set(cv2.CAP_PROP_POS_FRAMES, 0)
                self.cap_water.set(cv2.CAP_PROP_POS_FRAMES, 0)
                ret_clean, frame_clean = self.cap_clean.read()
                ret_water, frame_water = self.cap_water.read()
                if not ret_clean or frame_clean is None or not ret_water or frame_water is None:
                    return None, dna_bit
            
            # Select the appropriate frame based on DNA bit
            frame = frame_water if dna_bit == 1 else frame_clean

            frame = cv2.resize(frame, (WIDTH, HEIGHT))

        return frame, dna_bit

    def encrypt_frame(self, raw: bytes, dna_bit: int) -> bytes:
        """
        AES-GCM encryption of the raw frame bytes.
        DNA bit is cryptographically bound to the ciphertext.
        If DNA bit is tampered, decryption will fail or produce garbage.

        nonce = nonce_prefix (8 bytes) || frame_index (4 bytes, big-endian) || dna_bit (1 byte)
        AD    = user_id || frame_index || dna_bit
        """
        i = self.frame_index
        # DNA bit is now part of the nonce - changing it breaks decryption
        nonce = self.nonce_prefix + i.to_bytes(4, "big") + bytes([dna_bit])
        # DNA bit is ALSO in authenticated data - double protection
        ad = self.user_id.encode() + i.to_bytes(4, "big") + bytes([dna_bit])

        ciphertext = self.aesgcm.encrypt(nonce, raw, ad)
        self.frame_index += 1
        return ciphertext

    def update_metrics(self, nbytes: int):
        with self.lock:
            self.frames_sent += 1
            self.bytes_sent += nbytes
            now = time.time()
            dt = now - self.last_log

            if dt >= 1.0:
                fps = self.frames_sent / dt
                bitrate = (self.bytes_sent * 8.0) / dt / 1e6
                self.log_file.write(
                    f"Stream,{self.id},FPS,{fps:.3f},fps,{bitrate:.3f}\n"
                )
                self.frames_sent = 0
                self.bytes_sent = 0
                self.last_log = now


# ============================
# GST FACTORY (ENCRYPTED RTP)
# ============================
class SecureFactory(GstRtspServer.RTSPMediaFactory):
    """
    RTSP media factory that:
      - pulls frames from StreamContext
      - encrypts them with AES-GCM
      - pushes ciphertext as application/octet-stream
      - uses rtpgstpay for generic RTP transport
    """

    def __init__(self, ctx: StreamContext):
        super().__init__()
        self.ctx = ctx
        self.duration = Gst.SECOND // TARGET_FPS

        # IMPORTANT:
        # We are sending ENCRYPTED BYTES, NOT RAW VIDEO.
        # So caps are application/octet-stream and we use rtpgstpay.
        self.launch_string = (
            "appsrc name=mysrc is-live=true block=true format=GST_FORMAT_TIME "
            "caps=application/octet-stream "
            "! rtpgstpay name=pay0 pt=96"
        )

    def do_create_element(self, url):
        pipeline = Gst.parse_launch(self.launch_string)
        appsrc = pipeline.get_child_by_name("mysrc")
        appsrc.connect("need-data", self.on_need_data)
        return pipeline


    def on_need_data(self, src, length):
        i = self.ctx.frame_index
        frame, dna_bit = self.ctx.select_frame(i)
        if frame is None:
            return

        # Compress frame to JPEG to massively reduce bandwidth.
        # Adjust `JPEG_QUALITY` above to tune size vs quality.
        ret, encimg = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), JPEG_QUALITY])
        if not ret:
            return

        raw = encimg.tobytes()
        encrypted = self.ctx.encrypt_frame(raw, dna_bit)

        # ✅ FINAL STRICT WIRE FORMAT:
        # [frame_index:4][dna_bit:1][cipher_len:4][ciphertext:N]
        packet = (
            struct.pack(">I", i) +
            struct.pack("B", dna_bit) +
            struct.pack(">I", len(encrypted)) +
            encrypted
        )

        buf = Gst.Buffer.new_allocate(None, len(packet), None)
        buf.fill(0, packet)

        buf.pts = i * self.duration
        buf.duration = self.duration

        self.ctx.update_metrics(len(packet))
        src.emit("push-buffer", buf)




# ============================
# RTSP SERVER
# ============================
class SecureRtspServer(GstRtspServer.RTSPServer):
    def __init__(self):
        super().__init__()
        self.set_address("0.0.0.0")
        self.set_service("8554")

        self.contexts = [StreamContext(i) for i in range(NUM_STREAMS)]
        mounts = self.get_mount_points()

        for ctx in self.contexts:
            factory = SecureFactory(ctx)
            factory.set_shared(True)
            path = f"/test{ctx.id}"
            mounts.add_factory(path, factory)
            print(f"[Server] Mounted secure stream {ctx.id} at rtsp://0.0.0.0:8554{path}")


def main():
    Gst.init(None)
    GObject.threads_init()

    server = SecureRtspServer()
    server.attach(None)

    print(f"[Server] Secure RTSP running at rtsp://0.0.0.0:8554/test0..test{NUM_STREAMS-1}")

    try:
        GLib.MainLoop().run()
    except KeyboardInterrupt:
        print("\n[Server] Shutting down...")


if __name__ == "__main__":
    main()