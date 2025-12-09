#!/usr/bin/env python3
"""
dynamic_hls_server_no_crypto.py

A copy of your dynamic HLS server modified to **serve plaintext .ts segments** (no AES-GCM).
Metrics still collected. Playlist references .ts files.

Run:
  python3 dynamic_hls_server_no_crypto.py --master-orig master_orig --master-wm master_wm --host 0.0.0.0 --port 8000
Then:
  http://127.0.0.1:8000/user/user_0/playlist.m3u8
Segments:
  http://127.0.0.1:8000/user/user_0/segment_00000.ts
"""
from fastapi import FastAPI, Response, HTTPException
from fastapi.responses import PlainTextResponse, JSONResponse
import uvicorn
from pathlib import Path
import argparse
import hashlib
import time
import psutil
import statistics
from collections import defaultdict
import asyncio
import os

DEFAULT_REP = 1
MASTER_KEY = b"THIS_IS_YOUR_MASTER_KEY_CHANGE_ME_32B"  # unused now but kept for compatibility

app = FastAPI()

class ServerMetrics:
    def __init__(self):
        self.process = psutil.Process()
        self.start_time = time.time()
        self.request_times = []
        self.request_sizes = []
        self.encryption_times = []  # will remain zero (kept for schema compatibility)
        self.segment_requests = defaultdict(int)
        self.user_requests = defaultdict(int)
        self.last_request_time = None
        self.jitter_samples = []
        self.cpu_samples = []
        self.memory_samples = []
        self.bandwidth_samples = []
        
    def record_request(self, user_id: str, segment_idx: int, size_bytes: int, process_time: float, encrypt_time: float=0.0):
        current_time = time.time()
        # Jitter calculation uses actual inter-request gap (per server)
        if self.last_request_time is not None:
            jitter = current_time - self.last_request_time
            self.jitter_samples.append(jitter)
        self.last_request_time = current_time
        
        # Request metrics
        self.request_times.append(process_time)
        self.request_sizes.append(size_bytes)
        self.encryption_times.append(encrypt_time)
        self.segment_requests[segment_idx] += 1
        self.user_requests[user_id] += 1
        
        # Bandwidth (instantaneous for this request)
        bandwidth_mbps = (size_bytes * 8) / (process_time * 1_000_000) if process_time > 0 else 0
        self.bandwidth_samples.append(bandwidth_mbps)
        
    def sample_system_metrics(self):
        try:
            cpu = self.process.cpu_percent(interval=0)
            mem = self.process.memory_info().rss / (1024 * 1024)  # MB
            self.cpu_samples.append(cpu)
            self.memory_samples.append(mem)
        except:
            pass
    
    def get_report(self):
        uptime = time.time() - self.start_time
        total_requests = len(self.request_times)
        return {
            'uptime_sec': uptime,
            'total_requests': total_requests,
            'requests_per_sec': total_requests / uptime if uptime > 0 else 0,
            'cpu': {
                'mean_percent': statistics.mean(self.cpu_samples) if self.cpu_samples else 0,
                'max_percent': max(self.cpu_samples) if self.cpu_samples else 0,
                'min_percent': min(self.cpu_samples) if self.cpu_samples else 0,
                'samples': len(self.cpu_samples)
            },
            'memory': {
                'mean_mb': statistics.mean(self.memory_samples) if self.memory_samples else 0,
                'max_mb': max(self.memory_samples) if self.memory_samples else 0,
                'current_mb': self.process.memory_info().rss / (1024 * 1024)
            },
            'bandwidth': {
                'mean_mbps': statistics.mean(self.bandwidth_samples) if self.bandwidth_samples else 0,
                'max_mbps': max(self.bandwidth_samples) if self.bandwidth_samples else 0,
                'min_mbps': min(self.bandwidth_samples) if self.bandwidth_samples else 0,
                'total_mb': sum(self.request_sizes) / (1024 * 1024)
            },
            'latency': {
                'mean_ms': statistics.mean(self.request_times) * 1000 if self.request_times else 0,
                'p50_ms': statistics.median(self.request_times) * 1000 if self.request_times else 0,
                'p95_ms': (sorted(self.request_times)[int(len(self.request_times)*0.95)] * 1000 if self.request_times else 0),
                'p99_ms': (sorted(self.request_times)[int(len(self.request_times)*0.99)] * 1000 if self.request_times else 0),
                'max_ms': max(self.request_times) * 1000 if self.request_times else 0
            },
            'encryption': {
                'mean_ms': statistics.mean(self.encryption_times) * 1000 if self.encryption_times else 0,
                'max_ms': max(self.encryption_times) * 1000 if self.encryption_times else 0
            },
            'jitter': {
                'mean_sec': statistics.mean(self.jitter_samples) if self.jitter_samples else 0,
                'stdev_sec': statistics.stdev(self.jitter_samples) if len(self.jitter_samples) > 1 else 0,
                'max_sec': max(self.jitter_samples) if self.jitter_samples else 0
            },
            'top_segments': dict(sorted(self.segment_requests.items(), key=lambda x: x[1], reverse=True)[:10]),
            'users': dict(self.user_requests)
        }

metrics = ServerMetrics()

def kdf(master: bytes, label: bytes) -> bytes:
    return hashlib.sha256(master + label).digest()

def generate_dna_bits(user_id: str):
    # same deterministic sample dna for testing (kept for consistency)
    if (user_id == "user_0"):
        return [1,1,1,0,0,0,0,1,0,1,1,0,1,0,1,1,1,1,0,0,1,1,0,1,0,0,1,0,0,1,1,0]
    elif (user_id == "user_1"):
        return [0,0,1,1,1,1,0,1,0,1,0,0,0,0,1,1,1,0,0,1,0,0,0,1,0,0,0,1,0,1,0,0]
    else:
        h = hashlib.sha256(user_id.encode()).digest()
        bits = []
        for b in h[:4]:
            for i in range(8):
                bits.append((b >> i) & 1)
        return bits

class Config:
    master_orig: Path
    master_wm: Path
    rep: int

cfg = Config()
cfg.master_orig = Path(os.getenv("MASTER_ORIG", "./master_orig"))
cfg.master_wm = Path(os.getenv("MASTER_WM", "./master_wm"))
cfg.rep = int(os.getenv("REP", "1"))

# Background task to sample CPU
async def metrics_sampler():
    while True:
        metrics.sample_system_metrics()
        await asyncio.sleep(1)

@app.on_event("startup")
async def startup_event():
    # Start background metrics sampling
    asyncio.create_task(metrics_sampler())
    # validate master dirs
    if not cfg.master_orig.exists() or not cfg.master_wm.exists():
        raise RuntimeError("Master directories not present. Run segmenter first.")
    # count segments
    origs = sorted(cfg.master_orig.glob("seg_*.ts"))
    wms = sorted(cfg.master_wm.glob("seg_*.ts"))
    if len(origs) == 0 or len(wms) == 0:
        raise RuntimeError("No master segments found in master_orig or master_wm.")

@app.get("/metrics")
def get_metrics():
    """Return server metrics as JSON"""
    return JSONResponse(content=metrics.get_report())

@app.get("/user/{user_id}/playlist.m3u8", response_class=PlainTextResponse)
def playlist(user_id: str):
    """
    Return M3U8 playlist referencing plaintext .ts segment endpoints.
    """
    orig_files = sorted(cfg.master_orig.glob("seg_*.ts"))
    n = len(orig_files)
    lines = [
        "#EXTM3U",
        "#EXT-X-VERSION:3",
        f"# Generated-for: {user_id}",
        "#EXT-X-TARGETDURATION:1",
        "#EXT-X-MEDIA-SEQUENCE:0"
    ]
    for i in range(n):
        lines.append("#EXTINF:1.0,")
        # point to the server endpoint that will return plaintext .ts
        lines.append(f"segment_{i:05d}.ts")
    lines.append("#EXT-X-ENDLIST")
    return "\n".join(lines)

@app.get("/user/{user_id}/{seg_name}")
def serve_segment(user_id: str, seg_name: str):
    """
    Serve plaintext .ts segment for the user.
    """
    request_start = time.time()
    # parse index
    if not seg_name.startswith("segment_") or not seg_name.endswith(".ts"):
        raise HTTPException(status_code=404, detail="Not found")
    try:
        idx = int(seg_name[len("segment_"):len("segment_")+5])
    except Exception:
        raise HTTPException(status_code=400, detail="Bad segment name")

    # locate master files
    orig_path = cfg.master_orig / f"seg_{idx:05d}.ts"
    wm_path = cfg.master_wm / f"seg_{idx:05d}.ts"
    if not orig_path.exists() or not wm_path.exists():
        raise HTTPException(status_code=404, detail="Segment not available")

    # decide dna bit (keeps same logic to choose orig/wm)
    dna = generate_dna_bits(user_id)
    rep = cfg.rep
    bit_slot = ((idx // rep) % 32)
    dna_bit = dna[bit_slot]

    src = wm_path if dna_bit == 1 else orig_path
    plaintext = src.read_bytes()

    # No encryption step — measure zero encrypt time for schema compatibility
    encrypt_time = 0.0
    process_time = time.time() - request_start
    metrics.record_request(user_id, idx, len(plaintext), process_time, encrypt_time)

    # Return plaintext .ts as application/octet-stream
    return Response(content=plaintext, media_type="application/octet-stream")


