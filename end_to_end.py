#!/usr/bin/env python
"""
end_to_end_demo.py  — runs the full pipeline on a local video file.

Usage:
    python end_to_end_demo.py source.mp4
"""

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import cv2

from edge.parity_selector import (
    MIN_SEGMENTS,
    SEGMENTS_PER_PASS,
    compute_variant_sequence,
)
from forensics.extractor import SegmentExtractor
from forensics.matcher import FingerprintMatcher
from key_server.hkdf import derive_mask_key, generate_k_vendor
from key_server.subscriber_db import SubscriberDB
from preprocessor.segmenter import create_variant_pair
from preprocessor.variant_store import VariantStore
from utils.ffmpeg import find_ffmpeg

REQUIRED_SEGMENTS = SEGMENTS_PER_PASS + 1


def probe_video_metadata(video_path: Path) -> dict:
    """Return duration/fps metadata using ffprobe."""
    ffprobe_name = "ffprobe.exe" if sys.platform == "win32" else "ffprobe"
    ffprobe = str(Path(find_ffmpeg()).with_name(ffprobe_name))
    cmd = [
        ffprobe,
        "-v",
        "error",
        "-select_streams",
        "v:0",
        "-show_entries",
        "stream=avg_frame_rate,r_frame_rate,nb_frames",
        "-show_entries",
        "format=duration",
        "-of",
        "json",
        str(video_path),
    ]
    data = json.loads(
        subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    )

    stream = data["streams"][0]
    duration = float(data["format"]["duration"])
    fps_text = stream.get("avg_frame_rate") or stream.get("r_frame_rate") or "0/1"
    num, den = fps_text.split("/")
    fps = float(num) / float(den) if float(den) else 0.0

    return {
        "duration_seconds": duration,
        "fps": fps,
        "estimated_frame_count": int(round(duration * fps)) if fps > 0 else None,
        "frame_duration_seconds": (1.0 / fps) if fps > 0 else None,
    }


def calculate_video_metrics(metadata: dict) -> dict:
    """Derive feasibility and sizing metrics for the forensic pipeline."""
    duration = metadata["duration_seconds"]
    frame_duration = metadata["frame_duration_seconds"]
    estimated_frames = metadata["estimated_frame_count"]

    max_segments = int(duration / frame_duration) if frame_duration else 0
    one_pass_target = duration / REQUIRED_SEGMENTS if REQUIRED_SEGMENTS else 0.0
    double_embed_target = duration / MIN_SEGMENTS if MIN_SEGMENTS else 0.0

    return {
        **metadata,
        "required_segments_one_pass": REQUIRED_SEGMENTS,
        "required_segments_double_embed": MIN_SEGMENTS,
        "max_segments_at_one_frame": max_segments,
        "one_pass_target_segment_duration": one_pass_target,
        "double_embed_target_segment_duration": double_embed_target,
        "supports_one_pass": max_segments >= REQUIRED_SEGMENTS,
        "supports_double_embed": max_segments >= MIN_SEGMENTS,
        "estimated_frame_count": estimated_frames,
    }


def print_video_metrics(metrics: dict) -> None:
    """Print a compact metrics summary for reports/debugging."""
    print("Video metrics:")
    print(f"  duration_seconds              = {metrics['duration_seconds']:.3f}")
    print(f"  fps                           = {metrics['fps']:.3f}")
    print(f"  estimated_frame_count         = {metrics['estimated_frame_count']}")
    print(f"  min_segment_duration_seconds  = {metrics['frame_duration_seconds']:.6f}")
    print(f"  max_segments_at_one_frame     = {metrics['max_segments_at_one_frame']}")
    print(f"  required_segments_one_pass    = {metrics['required_segments_one_pass']}")
    print(
        f"  required_segments_double      = {metrics['required_segments_double_embed']}"
    )
    print(
        "  target_segment_duration_1pass = "
        f"{metrics['one_pass_target_segment_duration']:.6f}"
    )
    print(
        "  target_segment_duration_2pass = "
        f"{metrics['double_embed_target_segment_duration']:.6f}"
    )
    print(
        "  supports_one_pass             = "
        f"{'yes' if metrics['supports_one_pass'] else 'no'}"
    )
    print(
        "  supports_double_embed         = "
        f"{'yes' if metrics['supports_double_embed'] else 'no'}"
    )


def play_segment_sequence_live(
    segment_paths: list[Path],
    subscriber_id: str,
    max_segments: int | None = None,
) -> None:
    """
    Display the selected segment sequence in a live OpenCV window.
    Press 'q' to stop playback early.
    """
    to_play = segment_paths if max_segments is None else segment_paths[:max_segments]
    window_name = f"01-Parity Live Output - {subscriber_id}"

    print(
        f"Starting live playback for {subscriber_id} "
        f"({len(to_play)} segment(s)). Press 'q' to close."
    )

    cv2.namedWindow(window_name, cv2.WINDOW_NORMAL)

    for seg_idx, segment_path in enumerate(to_play):
        cap = cv2.VideoCapture(str(segment_path))
        if not cap.isOpened():
            print(f"Skipping unreadable segment: {segment_path}")
            continue

        fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
        frame_delay_ms = max(1, int(1000 / fps))

        while True:
            ok, frame = cap.read()
            if not ok or frame is None:
                break

            overlay = frame.copy()
            cv2.putText(
                overlay,
                f"Subscriber: {subscriber_id}",
                (20, 35),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.9,
                (0, 255, 0),
                2,
                cv2.LINE_AA,
            )
            cv2.putText(
                overlay,
                f"Segment: {seg_idx + 1}/{len(to_play)}",
                (20, 70),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.8,
                (0, 255, 255),
                2,
                cv2.LINE_AA,
            )
            cv2.putText(
                overlay,
                segment_path.name,
                (20, 105),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.7,
                (255, 255, 255),
                2,
                cv2.LINE_AA,
            )

            cv2.imshow(window_name, overlay)
            key = cv2.waitKey(frame_delay_ms) & 0xFF
            if key == ord("q"):
                cap.release()
                cv2.destroyWindow(window_name)
                return

        cap.release()

    time.sleep(0.2)
    cv2.destroyWindow(window_name)


def ensure_sufficient_segments(
    video_path: Path, segments_dir: Path, mask_key: bytes
) -> VariantStore:
    """
    Build enough segment pairs for one full RS pass when the source permits it.
    """
    metrics = calculate_video_metrics(probe_video_metadata(video_path))
    print_video_metrics(metrics)

    target_segment_duration = metrics["one_pass_target_segment_duration"]
    min_segment_duration = metrics["frame_duration_seconds"]

    if min_segment_duration is None:
        raise RuntimeError("Could not determine the source video frame rate.")

    if target_segment_duration < min_segment_duration:
        raise RuntimeError(
            "Source video is too short for RS decoding.\n"
            f"  duration={metrics['duration_seconds']:.2f}s, fps={metrics['fps']:.2f}\n"
            f"  one RS pass needs at least {REQUIRED_SEGMENTS} segments\n"
            "  target segment duration for one pass would be "
            f"{target_segment_duration:.6f}s,\n"
            "  but the source can only go down to about "
            f"{min_segment_duration:.6f}s per one-frame segment.\n"
            "  max achievable segments at one-frame granularity = "
            f"{metrics['max_segments_at_one_frame']}.\n"
            "Use a longer source video, or reduce the fingerprint/RS budget."
        )

    store = VariantStore(segments_dir)
    if store.segment_count() >= REQUIRED_SEGMENTS:
        return store

    print(
        "Regenerating segment pairs "
        f"(need >= {REQUIRED_SEGMENTS}, found {store.segment_count()})..."
    )
    print(
        f"Using segment_duration={target_segment_duration:.3f}s "
        f"for a {metrics['duration_seconds']:.2f}s source"
    )

    if segments_dir.exists():
        shutil.rmtree(segments_dir)

    create_variant_pair(
        video_path, segments_dir, mask_key, segment_duration=target_segment_duration
    )
    return VariantStore(segments_dir)


args = sys.argv[1:]
if not args:
    raise SystemExit("Usage: python end_to_end.py source.mp4 [--live]")

live_output = "--live" in args
video = Path(next(arg for arg in args if not arg.startswith("--")))
out = Path("demo_output")

# --- 1. Generate secrets ---
K_VENDOR = generate_k_vendor()
mask_key = derive_mask_key(K_VENDOR)
print(f"K_vendor = {K_VENDOR.hex()[:16]}...")

# --- 2. Register subscribers ---
users = [
    "alice",
    "bob",
    "pop",
    "eve",
    "vik",
]
db = SubscriberDB(k_vendor=K_VENDOR)
alice = db.register("alice")
for user in users[1:]:
    db.register(user)


# --- 3. Pre-process video ---
store = ensure_sufficient_segments(video, out / "segments", mask_key)
print(f"  {store.segment_count()} segment pairs created")

# --- 4. Simulate Alice streaming ---
print("Generating Alice's variant sequence...")
pairs = compute_variant_sequence(
    "alice", K_VENDOR, alice.k_sub, n_segments=store.segment_count()
)
alice_segments = [store.get_segment_path(i, v) for i, v in pairs]

if live_output:
    play_segment_sequence_live(alice_segments, subscriber_id="alice")

# --- 5. Forensic identification ---
print("Running forensic extraction...")
extractor = SegmentExtractor(variant_store=store)
fp_bits, _ = extractor.extract_fingerprint_bits(alice_segments)

matcher = FingerprintMatcher(db, K_VENDOR)
results, diag = matcher.identify_by_fp_bits(fp_bits)

print(f"\nRS decode: {'OK' if diag['success'] else 'FAIL'} ")
print("Top suspects:")
for r in results[:3]:
    print(
        f"  #{r.rank} {r.subscriber_id:20s}  "
        f"hamming={r.hamming_dist}  {'<-- CORRECT' if r.exact_match else ''}"
    )
