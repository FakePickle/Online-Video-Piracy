"""
evaluation/metrics_collect.py

Runtime metrics collection for the 01-Parity edge server evaluation.

Collects and logs:
  - FPS (client decode rate, target > 37 fps)
  - Edge CPU utilisation (baseline ~38 %, under load ~45 %)
  - P95 segment latency (target < 100 ms)
  - Cache hit ratio
  - Segment byte throughput

Output can be written to a CSV file or queried programmatically.

Usage
-----
    collector = MetricsCollector(output_csv="metrics.csv")
    collector.start()

    # ... run your segment serving loop ...
    collector.record_segment(
        subscriber_id="alice",
        segment_index=12,
        variant=1,
        latency_ms=23.4,
        bytes_served=48320,
        cache_hit=True,
    )

    collector.stop()
    report = collector.report()
    print(report.summary())
"""

from __future__ import annotations

import csv
import statistics
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import psutil


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class SegmentEvent:
    timestamp_s:   float
    subscriber_id: str
    segment_index: int
    variant:       int
    latency_ms:    float
    bytes_served:  int
    cache_hit:     bool


@dataclass
class MetricsReport:
    duration_s:        float
    total_segments:    int
    mean_fps:          float
    p50_latency_ms:    float
    p95_latency_ms:    float
    p99_latency_ms:    float
    mean_latency_ms:   float
    cache_hit_ratio:   float
    throughput_mbps:   float
    baseline_cpu_pct:  float
    mean_cpu_pct:      float
    peak_cpu_pct:      float

    def passes_targets(self) -> dict[str, bool]:
        return {
            "fps_over_37":              self.mean_fps > 37.0,
            "p95_latency_under_100ms":  self.p95_latency_ms < 100.0,
            "cache_hit_ratio_over_80pct": self.cache_hit_ratio > 0.80,
            "cpu_under_50pct":          self.mean_cpu_pct < 50.0,
        }

    def summary(self) -> str:
        lines = [
            f"Duration            : {self.duration_s:.1f} s",
            f"Total segments      : {self.total_segments}",
            f"Mean FPS            : {self.mean_fps:.1f}  (target > 37)",
            f"Latency mean        : {self.mean_latency_ms:.2f} ms",
            f"Latency P50/P95/P99 : {self.p50_latency_ms:.2f} / "
            f"{self.p95_latency_ms:.2f} / {self.p99_latency_ms:.2f} ms",
            f"Cache hit ratio     : {self.cache_hit_ratio:.1%}  (target > 80%)",
            f"Throughput          : {self.throughput_mbps:.2f} Mbps",
            f"CPU baseline/mean/peak: {self.baseline_cpu_pct:.1f}% / "
            f"{self.mean_cpu_pct:.1f}% / {self.peak_cpu_pct:.1f}%",
            "",
            "Targets:",
        ]
        for name, ok in self.passes_targets().items():
            lines.append(f"  {'PASS' if ok else 'FAIL'}  {name}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

class MetricsCollector:
    """
    Thread-safe collector for segment-serving events.

    Parameters
    ----------
    output_csv:      If set, events are streamed to this CSV file in real time.
    cpu_interval_s:  How often (seconds) to sample CPU utilisation.
    """

    _CSV_FIELDS = [
        "timestamp_s", "subscriber_id", "segment_index", "variant",
        "latency_ms", "bytes_served", "cache_hit",
    ]

    def __init__(
        self,
        output_csv: Optional[str | Path] = None,
        cpu_interval_s: float = 0.5,
    ) -> None:
        self._output_csv    = Path(output_csv) if output_csv else None
        self._cpu_interval  = cpu_interval_s

        self._events: list[SegmentEvent] = []
        self._cpu_samples: list[float]   = []
        self._lock = threading.Lock()

        self._start_time: Optional[float] = None
        self._stop_event  = threading.Event()
        self._cpu_thread: Optional[threading.Thread] = None

        self._baseline_cpu: float = 0.0
        self._csv_file = None
        self._csv_writer = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Begin collecting.  Must be called before record_segment."""
        self._baseline_cpu = psutil.cpu_percent(interval=0.5)
        self._start_time   = time.perf_counter()

        if self._output_csv:
            self._output_csv.parent.mkdir(parents=True, exist_ok=True)
            self._csv_file   = open(self._output_csv, "w", newline="", buffering=1)
            self._csv_writer = csv.DictWriter(self._csv_file, fieldnames=self._CSV_FIELDS)
            self._csv_writer.writeheader()

        self._stop_event.clear()
        self._cpu_thread = threading.Thread(target=self._cpu_sampler, daemon=True)
        self._cpu_thread.start()

    def stop(self) -> None:
        """Stop collecting."""
        self._stop_event.set()
        if self._cpu_thread:
            self._cpu_thread.join(timeout=2.0)
        if self._csv_file:
            self._csv_file.close()

    def _cpu_sampler(self) -> None:
        while not self._stop_event.is_set():
            sample = psutil.cpu_percent(interval=self._cpu_interval)
            with self._lock:
                self._cpu_samples.append(sample)

    # ------------------------------------------------------------------
    # Event recording
    # ------------------------------------------------------------------

    def record_segment(
        self,
        subscriber_id: str,
        segment_index: int,
        variant: int,
        latency_ms: float,
        bytes_served: int,
        cache_hit: bool,
    ) -> None:
        """Record one served segment event."""
        if self._start_time is None:
            raise RuntimeError("MetricsCollector.start() must be called first")

        event = SegmentEvent(
            timestamp_s   = time.perf_counter() - self._start_time,
            subscriber_id = subscriber_id,
            segment_index = segment_index,
            variant       = variant,
            latency_ms    = latency_ms,
            bytes_served  = bytes_served,
            cache_hit     = cache_hit,
        )

        with self._lock:
            self._events.append(event)

        if self._csv_writer:
            self._csv_writer.writerow({
                "timestamp_s":   f"{event.timestamp_s:.4f}",
                "subscriber_id": event.subscriber_id,
                "segment_index": event.segment_index,
                "variant":       event.variant,
                "latency_ms":    f"{event.latency_ms:.3f}",
                "bytes_served":  event.bytes_served,
                "cache_hit":     int(event.cache_hit),
            })

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def report(self) -> MetricsReport:
        """Compute and return a MetricsReport from all recorded events."""
        with self._lock:
            events      = list(self._events)
            cpu_samples = list(self._cpu_samples)

        if not events:
            duration = time.perf_counter() - (self._start_time or time.perf_counter())
            return MetricsReport(
                duration_s=duration, total_segments=0, mean_fps=0.0,
                p50_latency_ms=0.0, p95_latency_ms=0.0, p99_latency_ms=0.0,
                mean_latency_ms=0.0, cache_hit_ratio=0.0, throughput_mbps=0.0,
                baseline_cpu_pct=self._baseline_cpu, mean_cpu_pct=0.0, peak_cpu_pct=0.0,
            )

        duration   = (events[-1].timestamp_s - events[0].timestamp_s) or 1e-9
        latencies  = sorted(e.latency_ms for e in events)
        n          = len(latencies)

        cache_hits  = sum(1 for e in events if e.cache_hit)
        total_bytes = sum(e.bytes_served for e in events)

        return MetricsReport(
            duration_s       = duration,
            total_segments   = len(events),
            mean_fps         = len(events) / duration,
            p50_latency_ms   = latencies[int(n * 0.50)],
            p95_latency_ms   = latencies[int(n * 0.95)],
            p99_latency_ms   = latencies[min(int(n * 0.99), n - 1)],
            mean_latency_ms  = statistics.mean(latencies),
            cache_hit_ratio  = cache_hits / len(events),
            throughput_mbps  = total_bytes * 8 / 1e6 / duration,
            baseline_cpu_pct = self._baseline_cpu,
            mean_cpu_pct     = statistics.mean(cpu_samples) if cpu_samples else 0.0,
            peak_cpu_pct     = max(cpu_samples) if cpu_samples else 0.0,
        )
