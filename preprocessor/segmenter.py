"""
preprocessor/segmenter.py

ffmpeg wrapper that produces HLS segment pairs for 01-Parity.

For each input video this module creates:
  <output_dir>/variant_0/seg_XXXXX.ts   — original segments
  <output_dir>/variant_1/seg_XXXXX.ts   — DCT-watermarked segments
  <output_dir>/variant_0/playlist.m3u8
  <output_dir>/variant_1/playlist.m3u8

The watermarked segments have DCT AC coefficients shifted by +DELTA in
blocks selected by the secret mask, encoding bit=1 relative to variant_0.
The edge parity_selector then decides which variant to serve per segment
based on the subscriber's XOR chain state.
"""

from __future__ import annotations

import subprocess
import shutil
import tempfile
import math
from pathlib import Path
from typing import Optional

import cv2

from preprocessor.embedder import WatermarkEmbedder, PSNRError
from utils.ffmpeg import find_ffmpeg

# ---------------------------------------------------------------------------
# ffmpeg helpers
# ---------------------------------------------------------------------------

def _require_ffmpeg() -> str:
    """Return path to ffmpeg binary or raise if not found."""
    return find_ffmpeg()


def _run_ffmpeg(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    cmd = [_require_ffmpeg(), "-y", "-loglevel", "error", *args]
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


# ---------------------------------------------------------------------------
# Raw HLS segmentation (no watermark)
# ---------------------------------------------------------------------------

def segment_video(
    input_path: str | Path,
    output_dir: str | Path,
    segment_duration: float = 2.0,
    segment_prefix: str = "seg",
    codec: str = "libx264",
    crf: int = 23,
) -> list[Path]:
    """
    Segment `input_path` into HLS .ts files using ffmpeg.

    Returns a sorted list of the created segment paths.
    """
    input_path = Path(input_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    playlist  = output_dir / "playlist.m3u8"
    seg_tmpl  = str(output_dir / f"{segment_prefix}_%05d.ts")

    _run_ffmpeg(
        "-i", str(input_path),
        "-c:v", codec,
        "-crf", str(crf),
        "-force_key_frames", f"expr:gte(t,n_forced*{segment_duration})",
        "-sc_threshold", "0",
        "-c:a", "aac",
        "-hls_time", str(segment_duration),
        "-hls_segment_type", "mpegts",
        "-hls_segment_filename", seg_tmpl,
        "-hls_playlist_type", "vod",
        str(playlist),
    )

    segments = sorted(output_dir.glob(f"{segment_prefix}_*.ts"))
    return segments


# ---------------------------------------------------------------------------
# Variant pair creation
# ---------------------------------------------------------------------------

def create_variant_pair(
    input_path: str | Path,
    output_base: str | Path,
    mask_key: bytes,
    segment_duration: float = 2.0,
    codec: str = "libx264",
    crf: int = 23,
) -> tuple[list[Path], list[Path]]:
    """
    Create variant_0 (clean) and variant_1 (watermarked) segment pairs.

    Steps:
      1. Segment the video into .ts files (variant_0).
      2. Re-encode variant_0 with the DCT watermark to produce variant_1.

    Returns:
        (variant_0_segments, variant_1_segments) — parallel lists of Paths.

    Args:
        input_path:       Source video file.
        output_base:      Directory that will contain variant_0/ and variant_1/.
        mask_key:         32-byte secret for WatermarkEmbedder block selection.
        segment_duration: Target segment length in seconds (default 2 s).
        codec / crf:      Video encoding parameters for ffmpeg.
    """
    input_path  = Path(input_path)
    output_base = Path(output_base)

    v0_dir = output_base / "variant_0"
    v1_dir = output_base / "variant_1"

    # --- Step 1: create variant_0 segments ---
    v0_segs = segment_video(input_path, v0_dir, segment_duration, codec=codec, crf=crf)

    # --- Step 2: embed watermark into each variant_0 segment ---
    embedder = WatermarkEmbedder(mask_key=mask_key)
    v1_dir.mkdir(parents=True, exist_ok=True)
    v1_segs: list[Path] = []

    for seg_path in v0_segs:
        v1_path = v1_dir / seg_path.name
        _embed_segment(seg_path, v1_path, embedder, codec=codec, crf=crf)
        v1_segs.append(v1_path)

    # Write variant_1 playlist mirroring variant_0
    _write_playlist(v1_dir, v1_segs, segment_duration)

    return v0_segs, v1_segs


def _embed_segment(
    input_seg: Path,
    output_seg: Path,
    embedder: WatermarkEmbedder,
    codec: str = "libx264",
    crf: int = 23,
) -> None:
    """
    Read a .ts segment frame-by-frame, embed bit=1 watermark, re-encode.
    Uses a temporary .mp4 intermediate to avoid MPEG-TS write complexity.
    """
    with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        cap = cv2.VideoCapture(str(input_seg))
        if not cap.isOpened():
            raise RuntimeError(f"Cannot open segment: {input_seg}")

        fps    = cap.get(cv2.CAP_PROP_FPS) or 30.0
        width  = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        fourcc = cv2.VideoWriter_fourcc(*"mp4v")
        writer = cv2.VideoWriter(str(tmp_path), fourcc, fps, (width, height))

        frame_idx = 0
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            # embed_frame returns (result_frame, psnr); PSNRError propagates up
            result, _psnr = embedder.embed_frame(frame, frame_idx=frame_idx)
            writer.write(result)
            frame_idx += 1

        cap.release()
        writer.release()

        # Convert intermediate .mp4 → .ts
        _run_ffmpeg(
            "-i", str(tmp_path),
            "-c:v", codec, "-crf", str(crf),
            "-c:a", "aac",
            "-f", "mpegts",
            str(output_seg),
        )
    finally:
        tmp_path.unlink(missing_ok=True)


def _write_playlist(directory: Path, segments: list[Path], duration: float) -> None:
    """Write a minimal VOD HLS playlist."""
    playlist = directory / "playlist.m3u8"
    lines = [
        "#EXTM3U",
        "#EXT-X-VERSION:3",
        f"#EXT-X-TARGETDURATION:{max(1, math.ceil(duration))}",
        "#EXT-X-PLAYLIST-TYPE:VOD",
    ]
    for seg in segments:
        lines.append(f"#EXTINF:{duration:.3f},")
        lines.append(seg.name)
    lines.append("#EXT-X-ENDLIST")
    playlist.write_text("\n".join(lines) + "\n")
