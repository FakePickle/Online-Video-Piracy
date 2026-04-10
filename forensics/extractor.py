"""
forensics/extractor.py

Extracts the per-subscriber fingerprint bit sequence from a leaked video.

Pipeline
--------
1. For each segment i, compare it against the reference variant_0[i] and
   variant_1[i] using differential HSV colour histograms.
2. The comparison yields a variant classification v_i ∈ {0, 1}.
3. Apply the XOR chain inverse: f_i = v_i XOR v_{i+1}.
4. Return the 512-bit fingerprint sequence (one pass) for RS decoding.

Frame reading
-------------
OpenCV cannot reliably read MPEG-TS (.ts) files on Windows with the default
VideoCapture backend.  ``_read_frames`` therefore tries OpenCV first and
falls back to ffmpeg subprocess frame extraction when OpenCV returns no
usable frames.  ffmpeg is already a project dependency so this is safe.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

import cv2
import numpy as np

from utils.ffmpeg import find_ffmpeg


# ---------------------------------------------------------------------------
# Frame reading — with ffmpeg fallback for .ts files
# ---------------------------------------------------------------------------

_SAMPLE_FRAMES = 8          # frames sampled per segment for comparison


def _read_frames_opencv(segment_path: Path, n_frames: int) -> list[np.ndarray]:
    """Try to read up to n_frames evenly-spaced frames via OpenCV."""
    cap = cv2.VideoCapture(str(segment_path))
    if not cap.isOpened():
        return []

    total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT)) or n_frames
    step  = max(1, total // n_frames)
    frames: list[np.ndarray] = []

    for i in range(n_frames):
        cap.set(cv2.CAP_PROP_POS_FRAMES, i * step)
        ret, frame = cap.read()
        if not ret or frame is None:
            break
        frames.append(frame)

    cap.release()
    return frames


def _read_frames_ffmpeg(segment_path: Path, n_frames: int) -> list[np.ndarray]:
    """
    Extract up to n_frames from segment_path using ffmpeg → temp PNG files.

    Used as a fallback when OpenCV cannot read the container (common for
    MPEG-TS on Windows).  Uses find_ffmpeg() which searches common install
    locations even when ffmpeg is not on PATH.
    """
    try:
        ffmpeg = find_ffmpeg()
    except RuntimeError:
        return []

    frames: list[np.ndarray] = []
    with tempfile.TemporaryDirectory() as tmpdir:
        out_pattern = str(Path(tmpdir) / "frame_%03d.png")
        cmd = [
            ffmpeg, "-y", "-loglevel", "error",
            "-i", str(segment_path),
            # Select one frame every (total_frames / n_frames) frames
            "-vf", f"thumbnail={max(1, 30 // n_frames)},scale=320:180",
            "-frames:v", str(n_frames),
            out_pattern,
        ]
        try:
            subprocess.run(cmd, capture_output=True, check=True)
        except subprocess.CalledProcessError:
            # thumbnail filter may fail on very short segments; fall back to
            # just grabbing the first n_frames frames
            cmd_simple = [
                ffmpeg, "-y", "-loglevel", "error",
                "-i", str(segment_path),
                "-vf", "scale=320:180",
                "-frames:v", str(n_frames),
                out_pattern,
            ]
            try:
                subprocess.run(cmd_simple, capture_output=True, check=True)
            except subprocess.CalledProcessError:
                return []

        for png in sorted(Path(tmpdir).glob("frame_*.png"))[:n_frames]:
            frame = cv2.imread(str(png))
            if frame is not None:
                frames.append(frame)

    return frames


def _read_frames(segment_path: Path, n_frames: int = _SAMPLE_FRAMES) -> list[np.ndarray]:
    """
    Read up to n_frames from segment_path.

    Tries OpenCV first (fast, in-process).  Falls back to ffmpeg subprocess
    if OpenCV returns nothing — handles MPEG-TS on Windows and any other
    container that OpenCV's default backend cannot decode.
    """
    frames = _read_frames_opencv(segment_path, n_frames)
    if not frames:
        frames = _read_frames_ffmpeg(segment_path, n_frames)
    return frames


# ---------------------------------------------------------------------------
# Histogram computation
# ---------------------------------------------------------------------------

_HSV_BINS   = (18, 8, 8)          # H: 18, S: 8, V: 8  → 1 152-dim vector
_HSV_RANGES = [0, 180, 0, 256, 0, 256]


def _segment_histogram(segment_path: Path, n_frames: int = _SAMPLE_FRAMES) -> Optional[np.ndarray]:
    """
    Compute an averaged, L1-normalised HSV histogram for segment_path.

    Returns None if no frames could be read (missing file, corrupt data, etc.).
    """
    frames = _read_frames(segment_path, n_frames)
    if not frames:
        return None

    hist_acc = np.zeros(_HSV_BINS[0] * _HSV_BINS[1] * _HSV_BINS[2], dtype=np.float32)

    for frame in frames:
        hsv  = cv2.cvtColor(frame, cv2.COLOR_BGR2HSV)
        hist = cv2.calcHist([hsv], [0, 1, 2], None, list(_HSV_BINS), _HSV_RANGES)
        hist_acc += hist.flatten()

    hist_acc /= len(frames)
    cv2.normalize(hist_acc, hist_acc, alpha=1.0, beta=0.0, norm_type=cv2.NORM_L1)
    return hist_acc


def _chi_squared_distance(h1: np.ndarray, h2: np.ndarray) -> float:
    """Chi-squared histogram distance (lower = more similar)."""
    denom = h1 + h2
    mask  = denom > 0
    diff  = (h1[mask] - h2[mask]) ** 2 / denom[mask]
    return float(diff.sum())


# ---------------------------------------------------------------------------
# Segment classifier
# ---------------------------------------------------------------------------

class SegmentExtractor:
    """
    Classifies each segment as variant_0 or variant_1, then recovers the
    fingerprint bit sequence via the XOR chain inverse.

    Parameters
    ----------
    variant_store:
        VariantStore providing reference segment paths.  Can be None if
        ``classify_segment`` is called with explicit reference paths.
    """

    def __init__(self, variant_store=None) -> None:
        self._store = variant_store

    # ------------------------------------------------------------------
    # Single segment classification
    # ------------------------------------------------------------------

    def classify_segment(
        self,
        segment_path: str | Path,
        ref_v0_path: str | Path,
        ref_v1_path: str | Path,
    ) -> tuple[int, float]:
        """
        Classify ``segment_path`` as variant_0 or variant_1 by comparing its
        HSV histogram against both reference segments.

        Returns (variant, confidence) where:
            variant     ∈ {0, 1}
            confidence  ∈ [0.0, 1.0]  — normalised margin between the two distances

        Raises RuntimeError if any of the three segments cannot be read.
        """
        segment_path = Path(segment_path)
        ref_v0_path  = Path(ref_v0_path)
        ref_v1_path  = Path(ref_v1_path)

        hist_leaked = _segment_histogram(segment_path)
        hist_v0     = _segment_histogram(ref_v0_path)
        hist_v1     = _segment_histogram(ref_v1_path)

        if hist_leaked is None:
            raise RuntimeError(
                f"Cannot read segment (tried OpenCV + ffmpeg): {segment_path}\n"
                "  — check that ffmpeg is on PATH and the file is not corrupt."
            )
        if hist_v0 is None:
            raise RuntimeError(f"Cannot read reference variant_0: {ref_v0_path}")
        if hist_v1 is None:
            raise RuntimeError(f"Cannot read reference variant_1: {ref_v1_path}")

        d0 = _chi_squared_distance(hist_leaked, hist_v0)
        d1 = _chi_squared_distance(hist_leaked, hist_v1)

        variant    = 0 if d0 <= d1 else 1
        total      = d0 + d1
        confidence = abs(d0 - d1) / total if total > 0 else 0.0

        return variant, confidence

    # ------------------------------------------------------------------
    # Full variant sequence extraction
    # ------------------------------------------------------------------

    def extract_variant_sequence(
        self,
        leaked_segment_paths: list[str | Path],
    ) -> list[tuple[int, float]]:
        """
        Classify every segment in ``leaked_segment_paths`` against the
        variant store's reference segments.

        Returns a list of (variant, confidence) tuples, one per segment.
        Requires ``self._store`` to be set.
        """
        if self._store is None:
            raise RuntimeError("VariantStore not set; pass it to __init__")

        results = []
        for idx, path in enumerate(leaked_segment_paths):
            ref_v0 = self._store.get_segment_path(idx, 0)
            ref_v1 = self._store.get_segment_path(idx, 1)
            v, conf = self.classify_segment(path, ref_v0, ref_v1)
            results.append((v, conf))

        return results

    # ------------------------------------------------------------------
    # XOR chain inverse: variants → fingerprint bits
    # ------------------------------------------------------------------

    @staticmethod
    def variants_to_fingerprint_bits(
        variant_sequence: list[tuple[int, float]],
    ) -> list[int]:
        """
        Apply the XOR chain inverse:  f_i = v_i XOR v_{i+1}

        Args:
            variant_sequence: List of (variant, confidence) pairs.

        Returns:
            List of len(variant_sequence) - 1 bits in {0, 1}.
        """
        variants = [v for v, _ in variant_sequence]
        return [variants[i] ^ variants[i + 1] for i in range(len(variants) - 1)]

    # ------------------------------------------------------------------
    # Convenience: full pipeline (classify + XOR inversion)
    # ------------------------------------------------------------------

    def extract_fingerprint_bits(
        self,
        leaked_segment_paths: list[str | Path],
    ) -> tuple[list[int], list[float]]:
        """
        End-to-end extraction: segment paths → (fp_bits, confidences).

        Returns:
            fp_bits:     List of extracted fingerprint bits.
            confidences: Per-bit confidence (minimum of the two adjacent
                         segment confidences).
        """
        seq   = self.extract_variant_sequence(leaked_segment_paths)
        bits  = self.variants_to_fingerprint_bits(seq)
        confs = [
            min(seq[i][1], seq[i + 1][1])
            for i in range(len(seq) - 1)
        ]
        return bits, confs
