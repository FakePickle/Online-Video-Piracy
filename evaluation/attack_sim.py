"""
evaluation/attack_sim.py

T1–T4 attack simulations for 01-Parity evaluation.

Attack definitions
------------------
T1  Identity       — re-stream with no modification.  Expected BER ≈ 0.
T2  Recompression  — re-encode at lower bitrate / different codec via ffmpeg.
                     Expected BER ≈ 0.005 (≈ 2–3 bit errors / 512 bits).
T3  Resize         — scale video to a lower resolution and back to original.
                     Expected BER ≈ 0 (scaling preserves macro-block structure).
T4  3-user collusion averaging — three subscribers download the content;
                     a pirate pixel-averages all three streams.
                     Expected BER ≈ 0.08 (≈ 41/512 errors), well below the
                     RS correction bound of 17.2 %.

Usage
-----
    result = apply_attack(
        AttackType.T2_RECOMPRESSION,
        input_paths=["/path/to/leaked.mp4"],
        output_path="/path/to/attacked.mp4",
        bitrate="500k",
    )
    print(result.output_path, result.metadata)
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Optional

import cv2
import numpy as np

from utils.ffmpeg import find_ffmpeg


# ---------------------------------------------------------------------------
# Attack types
# ---------------------------------------------------------------------------

class AttackType(Enum):
    T1_IDENTITY      = "identity"
    T2_RECOMPRESSION = "recompression"
    T3_RESIZE        = "resize"
    T4_COLLUSION     = "collusion"


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

@dataclass
class AttackResult:
    attack_type: AttackType
    output_path: Path
    metadata:    dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# ffmpeg helper
# ---------------------------------------------------------------------------

def _ffmpeg(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [find_ffmpeg(), "-y", "-loglevel", "error", *args],
        capture_output=True, text=True, check=True,
    )


# ---------------------------------------------------------------------------
# Individual attacks
# ---------------------------------------------------------------------------

def _t1_identity(input_path: Path, output_path: Path) -> AttackResult:
    """T1: copy as-is — no modification whatsoever."""
    shutil.copy2(input_path, output_path)
    return AttackResult(
        attack_type = AttackType.T1_IDENTITY,
        output_path = output_path,
        metadata    = {"description": "No-op copy"},
    )


def _t2_recompression(
    input_path: Path,
    output_path: Path,
    bitrate: str = "500k",
    codec:   str = "libx264",
    crf:     int = 35,
) -> AttackResult:
    """
    T2: re-encode at a lower bitrate using ffmpeg.

    Quantisation noise from re-compression slightly perturbs DCT
    coefficient values, producing a small BER (~0.5 %).
    """
    _ffmpeg(
        "-i", str(input_path),
        "-c:v", codec,
        "-b:v", bitrate,
        "-crf", str(crf),
        "-c:a", "aac",
        str(output_path),
    )
    return AttackResult(
        attack_type = AttackType.T2_RECOMPRESSION,
        output_path = output_path,
        metadata    = {"bitrate": bitrate, "codec": codec, "crf": crf},
    )


def _t3_resize(
    input_path: Path,
    output_path: Path,
    scale_factor: float = 0.5,
    codec: str = "libx264",
    crf:   int = 23,
) -> AttackResult:
    """
    T3: downsample to scale_factor × original resolution then upsample back.

    Bilinear resampling introduces mild low-pass filtering but preserves
    the macro-block-level watermark structure → BER ≈ 0.
    """
    # Probe original dimensions
    cap = cv2.VideoCapture(str(input_path))
    w   = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    h   = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    cap.release()

    small_w = max(2, int(w * scale_factor) & ~1)   # must be even for libx264
    small_h = max(2, int(h * scale_factor) & ~1)

    with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        # Downscale
        _ffmpeg(
            "-i", str(input_path),
            "-vf", f"scale={small_w}:{small_h}",
            "-c:v", codec, "-crf", str(crf), "-c:a", "aac",
            str(tmp_path),
        )
        # Upscale back
        _ffmpeg(
            "-i", str(tmp_path),
            "-vf", f"scale={w}:{h}",
            "-c:v", codec, "-crf", str(crf), "-c:a", "aac",
            str(output_path),
        )
    finally:
        tmp_path.unlink(missing_ok=True)

    return AttackResult(
        attack_type = AttackType.T3_RESIZE,
        output_path = output_path,
        metadata    = {"scale_factor": scale_factor, "original_size": (w, h)},
    )


def _t4_collusion(
    input_paths: list[Path],
    output_path: Path,
    codec: str = "libx264",
    crf:   int = 23,
) -> AttackResult:
    """
    T4: pixel-average N subscriber streams.

    All input videos must have the same frame count, resolution, and fps.
    The averaged output is written as a new video.

    For 3 subscribers: expected BER ≈ 0.08 (within RS correction bound).
    """
    if len(input_paths) < 2:
        raise ValueError("T4 collusion requires at least 2 input streams")

    # Open all captures
    caps = [cv2.VideoCapture(str(p)) for p in input_paths]
    for i, cap in enumerate(caps):
        if not cap.isOpened():
            raise RuntimeError(f"Cannot open input {i}: {input_paths[i]}")

    fps    = caps[0].get(cv2.CAP_PROP_FPS) or 30.0
    width  = int(caps[0].get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(caps[0].get(cv2.CAP_PROP_FRAME_HEIGHT))
    n      = len(caps)

    # Write to temp .mp4 then convert to requested container
    with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    fourcc = cv2.VideoWriter_fourcc(*"mp4v")
    writer = cv2.VideoWriter(str(tmp_path), fourcc, fps, (width, height))

    while True:
        frames = []
        for cap in caps:
            ret, frame = cap.read()
            if not ret:
                frames = []
                break
            frames.append(frame.astype(np.float32))

        if not frames:
            break

        averaged = np.mean(frames, axis=0).clip(0, 255).astype(np.uint8)
        writer.write(averaged)

    for cap in caps:
        cap.release()
    writer.release()

    # Re-encode to output format
    _ffmpeg(
        "-i", str(tmp_path),
        "-c:v", codec, "-crf", str(crf), "-c:a", "aac",
        str(output_path),
    )
    tmp_path.unlink(missing_ok=True)

    return AttackResult(
        attack_type = AttackType.T4_COLLUSION,
        output_path = output_path,
        metadata    = {"n_colluders": n, "input_paths": [str(p) for p in input_paths]},
    )


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def apply_attack(
    attack_type: AttackType,
    input_paths: list[str | Path],
    output_path: str | Path,
    **kwargs: Any,
) -> AttackResult:
    """
    Apply the specified attack and write the result to `output_path`.

    Args:
        attack_type:  One of AttackType.T1_* … T4_*.
        input_paths:  List of input video paths.
                      T1/T2/T3 use input_paths[0] only.
                      T4 uses all provided paths.
        output_path:  Destination file path.
        **kwargs:     Attack-specific parameters forwarded to the implementation.

    Returns:
        AttackResult with output path and metadata.
    """
    paths      = [Path(p) for p in input_paths]
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if attack_type is AttackType.T1_IDENTITY:
        return _t1_identity(paths[0], output_path)

    if attack_type is AttackType.T2_RECOMPRESSION:
        return _t2_recompression(paths[0], output_path, **kwargs)

    if attack_type is AttackType.T3_RESIZE:
        return _t3_resize(paths[0], output_path, **kwargs)

    if attack_type is AttackType.T4_COLLUSION:
        return _t4_collusion(paths, output_path, **kwargs)

    raise ValueError(f"Unknown attack type: {attack_type!r}")
