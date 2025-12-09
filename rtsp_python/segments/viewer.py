#!/usr/bin/env python3
"""
dynamic_hls_client.py

Usage:
  python3 dynamic_hls_client.py http://127.0.0.1:8000/user/user_0/playlist.m3u8 user_0 out.mp4 --rep 3

This client:
 - downloads playlist
 - downloads each encrypted segment URL relative to playlist
 - decrypts them using the same KDF/nonce scheme
 - writes decrypted seg_XXXXX.ts files and concatenates them into out.mp4 using ffmpeg
 - collects metrics: CPU, bandwidth, jitter, frame rate, frame drops, 1% lows
"""
import argparse, requests, tempfile, shutil, subprocess
from pathlib import Path
from urllib.parse import urljoin
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import time
import psutil
import json
import statistics
import cv2

MASTER_KEY = b"THIS_IS_YOUR_MASTER_KEY_CHANGE_ME_32B"
DEFAULT_REP = 3

def kdf(master: bytes, label: bytes) -> bytes:
    return hashlib.sha256(master + label).digest()

def generate_dna_bits(user_id: str):
    if (user_id == "user_0"):
        return [1,1,1,0,0,0,0,1,0,1,1,0,1,0,1,1,1,1,0,0,1,1,0,1,0,0,1,0,0,1,1,0]
    else:
        return [0,0,1,1,1,1,0,1,0,1,0,0,0,0,1,1,1,0,0,1,0,0,0,1,0,0,0,1,0,1,0,0]


def download_text(url):
    r = requests.get(url)
    r.raise_for_status()
    return r.text

def decrypt_segment(ct_bytes: bytes, key: bytes, nonce_prefix: bytes, user_id: str, seg_index: int, dna_bit: int):
    nonce = nonce_prefix + seg_index.to_bytes(4, "big") + bytes([dna_bit])
    ad = user_id.encode() + seg_index.to_bytes(4, "big") + bytes([dna_bit])
    aes = AESGCM(key)
    pt = aes.decrypt(nonce, ct_bytes, ad)
    return pt

class MetricsCollector:
    def __init__(self):
        self.cpu_samples = []
        self.memory_samples = []
        self.bandwidth_samples = []
        self.download_times = []
        self.segment_sizes = []
        self.frame_times = []
        self.frame_rates = []
        self.jitter_samples = []
        self.process = psutil.Process()
        self.start_time = time.time()
        self.last_segment_time = None
        
    def record_download(self, size_bytes, duration_sec):
        self.segment_sizes.append(size_bytes)
        self.download_times.append(duration_sec)
        bandwidth_mbps = (size_bytes * 8) / (duration_sec * 1_000_000) if duration_sec > 0 else 0
        self.bandwidth_samples.append(bandwidth_mbps)
        
        # Calculate jitter (inter-segment time variation)
        current_time = time.time()
        if self.last_segment_time is not None:
            inter_segment_time = current_time - self.last_segment_time
            self.jitter_samples.append(inter_segment_time)
        self.last_segment_time = current_time
        
    def record_system_metrics(self):
        try:
            cpu_percent = self.process.cpu_percent(interval=0.1)
            memory_info = self.process.memory_info()
            self.cpu_samples.append(cpu_percent)
            self.memory_samples.append(memory_info.rss / (1024 * 1024))  # MB
        except:
            pass
    
    def analyze_video_file(self, video_path):
        """Analyze the output video for frame rate, drops, and 1% lows"""
        try:
            cap = cv2.VideoCapture(str(video_path))
            fps = cap.get(cv2.CAP_PROP_FPS)
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            duration = frame_count / fps if fps > 0 else 0
            
            # Read all frames and measure decode times
            frame_decode_times = []
            frames_decoded = 0
            
            while True:
                start = time.time()
                ret, frame = cap.read()
                decode_time = time.time() - start
                
                if not ret:
                    break
                    
                frame_decode_times.append(decode_time)
                frames_decoded += 1
            
            cap.release()
            
            # Calculate 1% lows (worst 1% of frame times)
            if frame_decode_times:
                sorted_times = sorted(frame_decode_times, reverse=True)
                one_percent_count = max(1, int(len(sorted_times) * 0.01))
                one_percent_lows = sorted_times[:one_percent_count]
                avg_1_percent_low = statistics.mean(one_percent_lows)
                one_percent_low_fps = 1.0 / avg_1_percent_low if avg_1_percent_low > 0 else 0
            else:
                one_percent_low_fps = 0
            
            # Calculate frame drops (expected vs actual)
            expected_frames = frame_count
            actual_frames = frames_decoded
            dropped_frames = max(0, expected_frames - actual_frames)
            drop_rate = (dropped_frames / expected_frames * 100) if expected_frames > 0 else 0
            
            return {
                'fps': fps,
                'frame_count': frame_count,
                'duration': duration,
                'frames_decoded': frames_decoded,
                'dropped_frames': dropped_frames,
                'drop_rate_percent': drop_rate,
                'avg_frame_decode_time_ms': statistics.mean(frame_decode_times) * 1000 if frame_decode_times else 0,
                '1_percent_low_fps': one_percent_low_fps
            }
        except Exception as e:
            print(f"[Metrics] Video analysis failed: {e}")
            return None
    
    def generate_report(self, video_path=None):
        report = {
            'session': {
                'total_duration_sec': time.time() - self.start_time,
                'segments_downloaded': len(self.segment_sizes),
                'total_bytes': sum(self.segment_sizes),
                'total_mb': sum(self.segment_sizes) / (1024 * 1024)
            },
            'cpu': {
                'mean_percent': statistics.mean(self.cpu_samples) if self.cpu_samples else 0,
                'max_percent': max(self.cpu_samples) if self.cpu_samples else 0,
                'min_percent': min(self.cpu_samples) if self.cpu_samples else 0,
                'stdev_percent': statistics.stdev(self.cpu_samples) if len(self.cpu_samples) > 1 else 0
            },
            'memory': {
                'mean_mb': statistics.mean(self.memory_samples) if self.memory_samples else 0,
                'max_mb': max(self.memory_samples) if self.memory_samples else 0,
                'min_mb': min(self.memory_samples) if self.memory_samples else 0
            },
            'bandwidth': {
                'mean_mbps': statistics.mean(self.bandwidth_samples) if self.bandwidth_samples else 0,
                'max_mbps': max(self.bandwidth_samples) if self.bandwidth_samples else 0,
                'min_mbps': min(self.bandwidth_samples) if self.bandwidth_samples else 0,
                'stdev_mbps': statistics.stdev(self.bandwidth_samples) if len(self.bandwidth_samples) > 1 else 0
            },
            'network': {
                'mean_download_time_sec': statistics.mean(self.download_times) if self.download_times else 0,
                'jitter_mean_sec': statistics.mean(self.jitter_samples) if self.jitter_samples else 0,
                'jitter_stdev_sec': statistics.stdev(self.jitter_samples) if len(self.jitter_samples) > 1 else 0,
                'jitter_max_sec': max(self.jitter_samples) if self.jitter_samples else 0
            }
        }
        
        # Add video analysis if path provided
        if video_path:
            video_metrics = self.analyze_video_file(video_path)
            if video_metrics:
                report['video'] = video_metrics
        
        return report
    
    def print_report(self, report):
        print("\n" + "="*60)
        print("CLIENT METRICS REPORT")
        print("="*60)
        
        print(f"\n[SESSION]")
        print(f"  Duration: {report['session']['total_duration_sec']:.2f} sec")
        print(f"  Segments: {report['session']['segments_downloaded']}")
        print(f"  Data: {report['session']['total_mb']:.2f} MB")
        
        print(f"\n[CPU UTILIZATION]")
        print(f"  Mean: {report['cpu']['mean_percent']:.2f}%")
        print(f"  Max: {report['cpu']['max_percent']:.2f}%")
        print(f"  Min: {report['cpu']['min_percent']:.2f}%")
        print(f"  StdDev: {report['cpu']['stdev_percent']:.2f}%")
        
        print(f"\n[MEMORY]")
        print(f"  Mean: {report['memory']['mean_mb']:.2f} MB")
        print(f"  Max: {report['memory']['max_mb']:.2f} MB")
        print(f"  Min: {report['memory']['min_mb']:.2f} MB")
        
        print(f"\n[BANDWIDTH]")
        print(f"  Mean: {report['bandwidth']['mean_mbps']:.2f} Mbps")
        print(f"  Max: {report['bandwidth']['max_mbps']:.2f} Mbps")
        print(f"  Min: {report['bandwidth']['min_mbps']:.2f} Mbps")
        print(f"  StdDev: {report['bandwidth']['stdev_mbps']:.2f} Mbps")
        
        print(f"\n[NETWORK]")
        print(f"  Avg Download Time: {report['network']['mean_download_time_sec']:.3f} sec")
        print(f"  Jitter Mean: {report['network']['jitter_mean_sec']:.3f} sec")
        print(f"  Jitter StdDev: {report['network']['jitter_stdev_sec']:.3f} sec")
        print(f"  Jitter Max: {report['network']['jitter_max_sec']:.3f} sec")
        
        if 'video' in report:
            print(f"\n[VIDEO PLAYBACK]")
            print(f"  FPS: {report['video']['fps']:.2f}")
            print(f"  Frame Count: {report['video']['frame_count']}")
            print(f"  Duration: {report['video']['duration']:.2f} sec")
            print(f"  Frames Decoded: {report['video']['frames_decoded']}")
            print(f"  Dropped Frames: {report['video']['dropped_frames']}")
            print(f"  Drop Rate: {report['video']['drop_rate_percent']:.2f}%")
            print(f"  Avg Decode Time: {report['video']['avg_frame_decode_time_ms']:.2f} ms")
            print(f"  1% Low FPS: {report['video']['1_percent_low_fps']:.2f}")
        
        print("="*60 + "\n")
    
    def save_report(self, report, filepath):
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[Metrics] Report saved to {filepath}")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("playlist_url")
    p.add_argument("user_id")
    p.add_argument("out_mp4")
    p.add_argument("--rep", type=int, default=DEFAULT_REP)
    p.add_argument("--metrics", help="Save metrics to JSON file")
    args = p.parse_args()
    
    # Initialize metrics collector
    metrics = MetricsCollector()

    playlist_url = args.playlist_url
    user_id = args.user_id
    out_mp4 = Path(args.out_mp4)
    rep = args.rep

    print("[Client] Downloading playlist:", playlist_url)
    txt = download_text(playlist_url)
    # parse playlist: non-comment lines are segment paths
    lines = [ln.strip() for ln in txt.splitlines() if ln.strip() and not ln.startswith("#")]
    if not lines:
        raise RuntimeError("No segments in playlist")

    # base URL for segments
    base = playlist_url.rsplit("/", 1)[0] + "/"

    key = kdf(MASTER_KEY, user_id.encode())[:32]
    nonce_prefix = kdf(MASTER_KEY, b"nonce-" + user_id.encode())[:8]
    dna = generate_dna_bits(user_id)

    tmpdir = Path(tempfile.mkdtemp(prefix="dec_hls_"))
    print("[Client] Temp dir:", tmpdir)
    seg_files = []
    for idx, seg_rel in enumerate(lines):
        seg_url = urljoin(base, seg_rel)
        print(f"[Client] Fetching [{idx}] {seg_url}")
        
        # Record system metrics before download
        metrics.record_system_metrics()
        
        # Download with timing
        download_start = time.time()
        r = requests.get(seg_url)
        download_duration = time.time() - download_start
        r.raise_for_status()
        ct = r.content
        
        # Record download metrics
        metrics.record_download(len(ct), download_duration)
        
        dna_bit = dna[((idx) // rep) % 32]
        try:
            pt = decrypt_segment(ct, key, nonce_prefix, user_id, idx, dna_bit)
        except Exception as e:
            print(f"[Client] Decrypt failed for segment {idx}: {e}")
            # write empty TS so ffmpeg concat won't fail later; better to fail loudly in real experiments
            pt = b''
        out_seg = tmpdir / f"seg_{idx:05d}.ts"
        out_seg.write_bytes(pt)
        seg_files.append(out_seg)

    # build concat list for ffmpeg
    list_file = tmpdir / "files.txt"
    with list_file.open("w") as fh:
        for f in seg_files:
            fh.write(f"file '{str(f)}'\n")

    # concat using ffmpeg
    cmd = ["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", str(list_file), "-c", "copy", str(out_mp4)]
    print("RUN:", " ".join(cmd))
    subprocess.run(cmd, check=True)
    print("[Client] Output written to", out_mp4)
    
    # Generate metrics report
    print("[Client] Analyzing video and generating metrics...")
    report = metrics.generate_report(video_path=out_mp4)
    metrics.print_report(report)
    
    # Save metrics to file if requested
    if args.metrics:
        metrics.save_report(report, args.metrics)
    
    # cleanup optionally
    # shutil.rmtree(tmpdir)

if __name__ == "__main__":
    main()
