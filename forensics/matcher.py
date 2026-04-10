"""
forensics/matcher.py

Fingerprint DB lookup: given a recovered raw key (42 bytes), find the
most likely subscriber(s) via Hamming distance on the raw fingerprint.

Why Hamming on raw bytes?
-------------------------
After RS decoding succeeds the raw key is exact (no errors).  We match
on raw_key bytes rather than fingerprint bits because:
  1. The raw key is the unique per-subscriber identity material.
  2. Exact equality is sufficient when RS decoding is successful.
  3. Hamming distance on raw bytes handles the case where RS fails and we
     fall back to bit-level matching with partial correction.

Collusion analysis (T4 — 3-user averaging)
-------------------------------------------
When three subscribers average their streams, the resulting segment
histograms sit midway between the three sets of variant choices.
The extractor may produce a noisy bit sequence that partially matches
one or more of the three subscribers.  The matcher returns a ranked list
so the investigator can examine the top suspects.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from forensics.reed_solomon import RSDecoder
from key_server.subscriber_db import SubscriberDB
from edge.parity_selector import SEGMENTS_PER_PASS, RS_DATA


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class MatchResult:
    rank:          int
    subscriber_id: str
    hamming_dist:  int     # bit-level Hamming distance on raw fingerprint bytes
    confidence:    float   # 1 − hamming_dist / (RS_DATA * 8)
    exact_match:   bool    # True when hamming_dist == 0


# ---------------------------------------------------------------------------
# Matcher
# ---------------------------------------------------------------------------

class FingerprintMatcher:
    """
    Match a recovered fingerprint against the subscriber DB.

    Parameters
    ----------
    db:        SubscriberDB populated with all known subscribers.
    k_vendor:  Vendor master key (needed to call generate_fingerprint_bits
               if raw_key-level matching is insufficient).
    """

    def __init__(self, db: SubscriberDB, k_vendor: bytes) -> None:
        self._db       = db
        self._k_vendor = k_vendor
        self._decoder  = RSDecoder()

    # ------------------------------------------------------------------
    # Hamming helpers
    # ------------------------------------------------------------------

    @staticmethod
    def hamming_bytes(a: bytes, b: bytes) -> int:
        """Bit-level Hamming distance between two byte strings of equal length."""
        if len(a) != len(b):
            raise ValueError(
                f"Byte strings must have equal length: {len(a)} vs {len(b)}"
            )
        dist = 0
        for x, y in zip(a, b):
            dist += bin(x ^ y).count("1")
        return dist

    # ------------------------------------------------------------------
    # Primary matching: exact raw key
    # ------------------------------------------------------------------

    def identify_by_raw_key(
        self,
        recovered_raw_key: bytes,
        top_k: int = 5,
    ) -> list[MatchResult]:
        """
        Match `recovered_raw_key` (42 bytes) against all subscriber raw
        fingerprints.  Returns the top-k matches ranked by Hamming distance.

        When RS decoding succeeds, recovered_raw_key == subscriber raw key
        exactly, so the top-1 result will have hamming_dist=0.
        """
        if len(recovered_raw_key) != RS_DATA:
            raise ValueError(
                f"recovered_raw_key must be {RS_DATA} bytes, got {len(recovered_raw_key)}"
            )

        scores: list[tuple[str, int]] = []
        for record in self._db.all_records():
            d = self.hamming_bytes(recovered_raw_key, record.raw_fingerprint)
            scores.append((record.subscriber_id, d))

        scores.sort(key=lambda x: x[1])
        max_bits = RS_DATA * 8

        return [
            MatchResult(
                rank          = i + 1,
                subscriber_id = sid,
                hamming_dist  = d,
                confidence    = 1.0 - d / max_bits,
                exact_match   = (d == 0),
            )
            for i, (sid, d) in enumerate(scores[:top_k])
        ]

    # ------------------------------------------------------------------
    # Fallback matching: bit-level on full fingerprint sequence
    # ------------------------------------------------------------------

    def identify_by_fp_bits(
        self,
        fp_bits: list[int],
        top_k: int = 5,
    ) -> tuple[list[MatchResult], dict]:
        """
        Full-pipeline identification:
          1. RS-decode fp_bits → raw_key  (if possible)
          2. If decoding succeeds, use identify_by_raw_key.
          3. If decoding fails (>11 symbol errors), fall back to bit-level
             Hamming matching directly on the fp_bits vs reference fp_bits.

        Returns:
            (match_results, diagnostics_dict)
        """
        diag = self._decoder.decode_with_diagnostics(fp_bits)

        if diag["success"]:
            # Clean or correctable: exact raw-key matching
            results = self.identify_by_raw_key(diag["raw_key"], top_k=top_k)
        else:
            # Fallback: noisy bit matching (e.g. T4 collusion, heavy recompression)
            results = self._fallback_bit_matching(fp_bits, top_k=top_k)

        return results, diag

    def _fallback_bit_matching(
        self,
        fp_bits: list[int],
        top_k: int = 5,
    ) -> list[MatchResult]:
        """
        Match directly at the bit level when RS decoding fails.
        Uses the first SEGMENTS_PER_PASS bits only.
        """
        from edge.parity_selector import generate_fingerprint_bits, derive_subscriber_key

        n = min(len(fp_bits), SEGMENTS_PER_PASS)
        received = fp_bits[:n]

        scores: list[tuple[str, int]] = []
        for record in self._db.all_records():
            k_u  = record.k_u
            ref  = generate_fingerprint_bits(k_u)[:n]
            d    = sum(a != b for a, b in zip(received, ref))
            scores.append((record.subscriber_id, d))

        scores.sort(key=lambda x: x[1])

        return [
            MatchResult(
                rank          = i + 1,
                subscriber_id = sid,
                hamming_dist  = d,
                confidence    = 1.0 - d / n if n > 0 else 0.0,
                exact_match   = (d == 0),
            )
            for i, (sid, d) in enumerate(scores[:top_k])
        ]

    # ------------------------------------------------------------------
    # Collusion analysis helper
    # ------------------------------------------------------------------

    def collusion_suspects(
        self,
        fp_bits: list[int],
        n_colluders: int = 3,
        top_k: int = 10,
    ) -> list[MatchResult]:
        """
        For T4 collusion attacks, return the top-k individual suspects.

        Under pixel-averaging of `n_colluders` streams, the XOR chain
        differences are attenuated by ~50% per colluder beyond the first.
        This method returns a wider ranking so the investigator can check
        whether one or more of the top suspects are known to have colluded.
        """
        results, _ = self.identify_by_fp_bits(fp_bits, top_k=top_k)
        return results
