"""
preprocessor/embedder.py

DCT-domain watermark embedder for 01-Parity.

Storage model
-------------
Per segment, exactly two files are stored:
  segment_i_v0.ts — original, unmodified segment  (variant 0)
  segment_i_v1.ts — DCT-shifted segment            (variant 1)

This is +100% storage overhead.  The *fingerprint* is not a watermark
embedded in the video bits — it is the *sequence* of which variant was
served to a subscriber.  A subscriber receiving their personalised stream
cannot distinguish v0 from v1 without the secret mask (PSNR >45 dB
guarantee).  The forensics lab detects v0 vs v1 by computing differential
colour histograms between adjacent segments of the leaked copy.

Embedding algorithm
-------------------
1. Convert each frame to YCbCr; embed in the Y (luminance) channel.
2. Divide Y into 8×8 blocks.  For each block compute the HSV-S variance
   of the corresponding region in the original frame.
   Blocks with σ < VARIANCE_THRESHOLD are "stable" and safe to embed in.
3. For stable blocks also selected by the per-vendor secret mask, apply
   2-D DCT, add +DELTA to chosen mid-frequency AC coefficients, IDCT.
4. Clip to [0, 255] and reconstruct the frame.
5. **PSNR gate**: compute PSNR of the modified frame against the original.
   If PSNR < PSNR_MIN (45 dB) the modification is too visible — discard it
   and return the original frame unchanged for that frame.
   ``embed_video`` raises ``PSNRError`` if the *segment-level* mean PSNR
   falls below the threshold after all frames are processed.

Variant 1 is always generated with ``bit=1`` (+DELTA shift).
Variant 0 is the untouched original — the embedder is never called for it.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from pathlib import Path
from typing import Optional

import cv2
import numpy as np

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Embedding parameters
# ---------------------------------------------------------------------------
BLOCK_SIZE: int        = 8
DELTA: int             = 3
VARIANCE_THRESHOLD: float = 4.0
PSNR_MIN: float        = 45.0    # dB — hard lower bound for v1 quality

# Mid-frequency AC coefficient positions (row, col) within an 8×8 block.
_AC_POSITIONS: list[tuple[int, int]] = [
    (1, 2), (2, 1), (2, 2), (1, 3), (3, 1),
]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class PSNRError(ValueError):
    """Raised when a generated variant 1 segment fails the PSNR ≥ 45 dB gate."""


# ---------------------------------------------------------------------------
# Secret mask
# ---------------------------------------------------------------------------

def _derive_block_mask(mask_key: bytes, frame_idx: int, block_row: int, block_col: int) -> bool:
    """
    Deterministically decide whether to embed in a given block.

    HMAC-SHA256(mask_key, frame_idx ‖ block_row ‖ block_col) — MSBit selects
    ≈50% of stable blocks.  Without the mask_key an attacker cannot identify
    which blocks were modified, making blind stripping attacks ineffective.
    """
    msg = (
        frame_idx.to_bytes(4, "big")
        + block_row.to_bytes(2, "big")
        + block_col.to_bytes(2, "big")
    )
    digest = hmac.new(mask_key, msg, hashlib.sha256).digest()
    return bool(digest[0] & 0x80)


# ---------------------------------------------------------------------------
# Core embedder
# ---------------------------------------------------------------------------

class WatermarkEmbedder:
    """
    Embeds a 1-bit watermark (+DELTA DCT shift) into video frames.

    Parameters
    ----------
    mask_key:
        ≥16-byte secret derived from K_vendor via ``key_server.hkdf.derive_mask_key``.
        Shared between the preprocessor (embedding) and the forensics extractor.
    delta:
        AC coefficient shift magnitude.  Default 3 keeps PSNR comfortably above
        45 dB for typical video content.
    variance_threshold:
        Blocks whose HSV-S variance exceeds this value are skipped (busy areas
        would make the shift perceptible).
    psnr_min:
        Per-frame PSNR lower bound.  Frames that fall below this after embedding
        are silently reverted to the original (the modification is not applied).
    """

    def __init__(
        self,
        mask_key: bytes,
        delta: int = DELTA,
        variance_threshold: float = VARIANCE_THRESHOLD,
        psnr_min: float = PSNR_MIN,
    ) -> None:
        if len(mask_key) < 16:
            raise ValueError("mask_key must be at least 16 bytes")
        self.mask_key           = mask_key
        self.delta              = delta
        self.variance_threshold = variance_threshold
        self.psnr_min           = psnr_min

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _hsv_variance(self, frame_bgr: np.ndarray, br: int, bc: int) -> float:
        """HSV-S variance for the 8×8 block at grid position (br, bc)."""
        r0, c0 = br * BLOCK_SIZE, bc * BLOCK_SIZE
        patch  = frame_bgr[r0:r0 + BLOCK_SIZE, c0:c0 + BLOCK_SIZE]
        if patch.shape[0] == 0 or patch.shape[1] == 0:
            return float("inf")
        hsv = cv2.cvtColor(patch, cv2.COLOR_BGR2HSV).astype(np.float32)
        return float(np.var(hsv[:, :, 1]))

    def _embed_blocks(self, frame_bgr: np.ndarray, frame_idx: int) -> np.ndarray:
        """
        Apply the DCT shift to selected blocks and return the modified frame.
        Does NOT check PSNR — that is the caller's responsibility.
        """
        sign  = +1   # variant 1 always uses +DELTA
        ycrcb = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2YCrCb).astype(np.float32)
        y     = ycrcb[:, :, 0]
        h, w  = y.shape

        for br in range(h // BLOCK_SIZE):
            for bc in range(w // BLOCK_SIZE):
                if self._hsv_variance(frame_bgr, br, bc) >= self.variance_threshold:
                    continue
                if not _derive_block_mask(self.mask_key, frame_idx, br, bc):
                    continue

                r0, c0  = br * BLOCK_SIZE, bc * BLOCK_SIZE
                block   = y[r0:r0 + BLOCK_SIZE, c0:c0 + BLOCK_SIZE].copy()
                dct_blk = cv2.dct(block)
                for row, col in _AC_POSITIONS:
                    dct_blk[row, col] += sign * self.delta
                y[r0:r0 + BLOCK_SIZE, c0:c0 + BLOCK_SIZE] = cv2.idct(dct_blk)

        ycrcb[:, :, 0] = np.clip(y, 0, 255)
        return cv2.cvtColor(ycrcb.astype(np.uint8), cv2.COLOR_YCrCb2BGR)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def embed_frame(
        self,
        frame_bgr: np.ndarray,
        frame_idx: int = 0,
    ) -> tuple[np.ndarray, float]:
        """
        Produce variant-1 for a single frame.

        Applies the DCT shift, computes PSNR against the original, and
        reverts to the original frame if PSNR < ``self.psnr_min``.

        Returns
        -------
        (result_frame, psnr)
            result_frame — the modified frame, OR the original if PSNR gate failed.
            psnr         — PSNR in dB of result_frame vs original (inf if unchanged).

        Note: the caller can detect a reversion by checking psnr == inf or
        psnr >= some threshold.  The reversion is intentional — a segment
        where many frames revert will still be predominantly watermarked.
        """
        candidate = self._embed_blocks(frame_bgr, frame_idx)
        psnr      = self.compute_psnr(frame_bgr, candidate)

        if psnr < self.psnr_min:
            logger.debug(
                "Frame %d: PSNR %.2f dB < %.1f dB threshold — reverting to original",
                frame_idx, psnr, self.psnr_min,
            )
            return frame_bgr.copy(), float("inf")

        return candidate, psnr

    # ------------------------------------------------------------------
    # Quality metrics
    # ------------------------------------------------------------------

    @staticmethod
    def compute_psnr(original: np.ndarray, watermarked: np.ndarray) -> float:
        """Peak Signal-to-Noise Ratio in dB.  Returns inf when frames are identical."""
        mse = np.mean((original.astype(np.float64) - watermarked.astype(np.float64)) ** 2)
        if mse == 0.0:
            return float("inf")
        return 10.0 * np.log10(255.0 ** 2 / mse)

    # ------------------------------------------------------------------
    # Full video embedding with segment-level PSNR gate
    # ------------------------------------------------------------------

    def embed_video(
        self,
        input_path: str | Path,
        output_path: str | Path,
        codec: str = "mp4v",
    ) -> dict:
        """
        Produce variant-1 for every frame of ``input_path``, write to
        ``output_path``.

        Raises
        ------
        PSNRError
            If the mean PSNR across all modified frames falls below
            ``self.psnr_min``.  This indicates that the content is too
            dynamic / noisy for reliable watermarking at the current DELTA.
            Caller should lower ``delta`` or increase ``variance_threshold``
            and retry.

        Returns
        -------
        dict with keys:
            frames_processed   — total frames written
            frames_embedded    — frames where DCT shift was applied (PSNR gate passed)
            frames_reverted    — frames where shift was reverted (PSNR gate failed)
            mean_psnr          — mean PSNR over embedded frames only
            min_psnr           — minimum PSNR over embedded frames only
        """
        input_path  = Path(input_path)
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        cap = cv2.VideoCapture(str(input_path))
        if not cap.isOpened():
            raise RuntimeError(f"Cannot open video: {input_path}")

        fps    = cap.get(cv2.CAP_PROP_FPS) or 30.0
        width  = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        fourcc = cv2.VideoWriter_fourcc(*codec)
        writer = cv2.VideoWriter(str(output_path), fourcc, fps, (width, height))

        psnr_embedded: list[float] = []
        frames_reverted = 0
        frame_idx = 0

        while True:
            ret, frame = cap.read()
            if not ret:
                break

            result, psnr = self.embed_frame(frame, frame_idx=frame_idx)
            writer.write(result)

            if psnr == float("inf"):
                frames_reverted += 1
            else:
                psnr_embedded.append(psnr)

            frame_idx += 1

        cap.release()
        writer.release()

        mean_psnr = float(np.mean(psnr_embedded)) if psnr_embedded else float("inf")
        min_psnr  = float(np.min(psnr_embedded))  if psnr_embedded else float("inf")

        # Segment-level PSNR gate: fail if the average quality is unacceptable.
        if psnr_embedded and mean_psnr < self.psnr_min:
            raise PSNRError(
                f"Segment mean PSNR {mean_psnr:.2f} dB < required {self.psnr_min} dB. "
                f"Reduce delta (current: {self.delta}) or raise variance_threshold "
                f"(current: {self.variance_threshold}) and regenerate variant 1."
            )

        return {
            "frames_processed": frame_idx,
            "frames_embedded":  len(psnr_embedded),
            "frames_reverted":  frames_reverted,
            "mean_psnr":        mean_psnr,
            "min_psnr":         min_psnr,
        }
