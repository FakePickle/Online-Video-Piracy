"""
evaluation/load_test.py

Concurrent subscriber load test for the 01-Parity edge server.

Simulates N subscribers each requesting sequential HLS segments and measures:
  - Throughput (segments/second, requests/second)
  - 50th / 95th / 99th percentile segment latency
  - Edge CPU utilisation (baseline vs under-load)
  - Cache hit ratio for variant segments

The "edge server" is modelled locally (no HTTP): each worker thread calls
the same code path that a real segment_server.py would use:
  1. Look up subscriber's current segment index.
  2. Derive variant selection via parity_selector.compute_variant_sequence.
  3. Read the segment bytes from VariantStore (simulating disk/cache I/O).
  4. Record latency and cache state.

Paper targets:
  - Client decode rate: > 37 fps
  - Edge CPU:           baseline ~38 %, under load ~45 %
  - P95 latency:        < 100 ms overhead per segment
  - Cache hit ratio:    > 80 % for hot segments
"""

from __future__ import annotations

import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import psutil

from edge.parity_selector import compute_variant_sequence, SEGMENTS_PER_PASS
from key_server.subscriber_db import SubscriberDB


# ---------------------------------------------------------------------------
# LRU segment cache (mirrors edge/cache.py)
# ---------------------------------------------------------------------------

class _LRUCache:
    """Simple thread-safe LRU cache keyed by (segment_index, variant)."""

    def __init__(self, max_size: int = 128) -> None:
        from collections import OrderedDict
        self._cache: OrderedDict[tuple, bytes] = OrderedDict()
        self._max   = max_size
        self._lock  = threading.Lock()
        self._hits  = 0
        self._miss  = 0

    def get(self, key: tuple) -> Optional[bytes]:
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                self._hits += 1
                return self._cache[key]
            self._miss += 1
            return None

    def put(self, key: tuple, value: bytes) -> None:
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            else:
                if len(self._cache) >= self._max:
                    self._cache.popitem(last=False)
                self._cache[key] = value

    @property
    def hit_ratio(self) -> float:
        total = self._hits + self._miss
        return self._hits / total if total > 0 else 0.0

    @property
    def stats(self) -> dict:
        return {"hits": self._hits, "misses": self._miss, "hit_ratio": self.hit_ratio}


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class LoadTestResult:
    n_subscribers:       int
    duration_s:          float
    total_requests:      int
    successful_requests: int
    failed_requests:     int
    segments_per_second: float
    latencies_ms:        list[float]

    # Percentiles
    p50_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    mean_latency_ms: float = 0.0

    # System
    baseline_cpu_pct:  float = 0.0
    peak_cpu_pct:      float = 0.0
    cache_hit_ratio:   float = 0.0

    def __post_init__(self) -> None:
        if self.latencies_ms:
            s = sorted(self.latencies_ms)
            n = len(s)
            self.p50_latency_ms  = s[int(n * 0.50)]
            self.p95_latency_ms  = s[int(n * 0.95)]
            self.p99_latency_ms  = s[min(int(n * 0.99), n - 1)]
            self.mean_latency_ms = statistics.mean(s)

    def passes_targets(self) -> dict[str, bool]:
        return {
            "p95_latency_under_100ms": self.p95_latency_ms < 100.0,
            "cache_hit_ratio_over_80pct": self.cache_hit_ratio > 0.80,
        }

    def summary(self) -> str:
        lines = [
            f"Subscribers       : {self.n_subscribers}",
            f"Duration          : {self.duration_s:.1f} s",
            f"Total requests    : {self.total_requests}  "
            f"(ok={self.successful_requests}, err={self.failed_requests})",
            f"Throughput        : {self.segments_per_second:.1f} seg/s",
            f"Latency (mean)    : {self.mean_latency_ms:.2f} ms",
            f"Latency P50/P95/P99: {self.p50_latency_ms:.2f} / "
            f"{self.p95_latency_ms:.2f} / {self.p99_latency_ms:.2f} ms",
            f"CPU baseline/peak : {self.baseline_cpu_pct:.1f}% / {self.peak_cpu_pct:.1f}%",
            f"Cache hit ratio   : {self.cache_hit_ratio:.1%}",
        ]
        targets = self.passes_targets()
        lines.append("Targets:")
        for name, ok in targets.items():
            lines.append(f"  {'PASS' if ok else 'FAIL'}  {name}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

def _subscriber_worker(
    subscriber_id: str,
    k_vendor: bytes,
    k_sub: bytes,
    variant_store,
    cache: _LRUCache,
    n_segments: int,
    latencies: list[float],
    errors: list[Exception],
) -> None:
    """
    Simulate one subscriber streaming `n_segments` segments sequentially.
    Appends per-request latency (ms) to `latencies`.
    """
    pairs = compute_variant_sequence(subscriber_id, k_vendor, k_sub,
                                      n_segments=n_segments)

    for seg_idx, variant in pairs:
        t0 = time.perf_counter()
        try:
            key = (seg_idx, variant)
            data = cache.get(key)
            if data is None:
                data = variant_store.read_segment(seg_idx, variant)
                cache.put(key, data)
        except Exception as e:
            errors.append(e)
            latencies.append((time.perf_counter() - t0) * 1000)
            continue

        latencies.append((time.perf_counter() - t0) * 1000)


# ---------------------------------------------------------------------------
# Load test runner
# ---------------------------------------------------------------------------

def run_load_test(
    n_subscribers: int,
    db: SubscriberDB,
    k_vendor: bytes,
    variant_store,
    segments_per_subscriber: int = SEGMENTS_PER_PASS + 1,
    cache_size: int = 256,
    max_workers: Optional[int] = None,
) -> LoadTestResult:
    """
    Run a concurrent load test.

    Args:
        n_subscribers:           Number of simultaneous subscribers.
        db:                      SubscriberDB (must have ≥ n_subscribers entries).
        k_vendor:                Vendor master key.
        variant_store:           VariantStore providing segment files.
        segments_per_subscriber: Segments each subscriber requests.
        cache_size:              LRU cache capacity in number of segments.
        max_workers:             Thread pool size (defaults to n_subscribers).
    """
    subscriber_ids = db.all_ids()[:n_subscribers]
    if len(subscriber_ids) < n_subscribers:
        raise ValueError(
            f"DB has only {len(subscriber_ids)} subscribers; need {n_subscribers}"
        )

    cache     = _LRUCache(max_size=cache_size)
    all_lats: list[float] = []
    all_errs: list[Exception] = []
    lock = threading.Lock()

    # Measure baseline CPU
    baseline_cpu = psutil.cpu_percent(interval=0.5)

    cpu_samples: list[float] = []
    cpu_stop = threading.Event()

    def _cpu_sampler():
        while not cpu_stop.is_set():
            cpu_samples.append(psutil.cpu_percent(interval=0.2))

    cpu_thread = threading.Thread(target=_cpu_sampler, daemon=True)
    cpu_thread.start()

    t_start = time.perf_counter()

    with ThreadPoolExecutor(max_workers=max_workers or n_subscribers) as pool:
        futures = []
        for sid in subscriber_ids:
            lats: list[float] = []
            errs: list[Exception] = []
            record = db.get(sid)
            fut = pool.submit(
                _subscriber_worker,
                sid, k_vendor, record.k_sub,
                variant_store, cache,
                segments_per_subscriber,
                lats, errs,
            )
            futures.append((fut, lats, errs))

        for fut, lats, errs in futures:
            fut.result()                # wait for all workers
            with lock:
                all_lats.extend(lats)
                all_errs.extend(errs)

    elapsed = time.perf_counter() - t_start
    cpu_stop.set()

    peak_cpu = max(cpu_samples) if cpu_samples else 0.0

    total      = len(all_lats)
    failed     = len(all_errs)
    successful = total - failed

    return LoadTestResult(
        n_subscribers       = n_subscribers,
        duration_s          = elapsed,
        total_requests      = total,
        successful_requests = successful,
        failed_requests     = failed,
        segments_per_second = successful / elapsed if elapsed > 0 else 0.0,
        latencies_ms        = all_lats,
        baseline_cpu_pct    = baseline_cpu,
        peak_cpu_pct        = peak_cpu,
        cache_hit_ratio     = cache.hit_ratio,
    )
