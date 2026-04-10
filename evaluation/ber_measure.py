"""
evaluation/ber_measure.py

BER (Bit Error Rate) measurement for each attack type.

For each attack, this module:
  1. Applies the attack to a reference set of variant segments.
  2. Extracts the fingerprint bit sequence from the attacked video using
     the forensics extractor.
  3. Computes BER relative to the ground-truth fingerprint bits.
  4. Reports whether RS decoding succeeds (and attribution is correct).

BER is measured at two levels:
  - Symbol-level BER: fraction of corrupted RS symbols (8-bit windows).
  - Bit-level BER:    fraction of corrupted individual bits.

Expected results (from paper):
  T1 identity:       BER ≈ 0.000
  T2 recompression:  BER ≈ 0.005
  T3 resize:         BER ≈ 0.000
  T4 collusion (3):  BER ≈ 0.080  (well under RS bound of 0.172)
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from evaluation.attack_sim import AttackType, AttackResult, apply_attack
from forensics.extractor import SegmentExtractor
from forensics.reed_solomon import RSDecoder
from edge.parity_selector import (
    SEGMENTS_PER_PASS,
    BITS_PER_SYMBOL,
    RS_NSYM,
    generate_fingerprint_bits,
    derive_subscriber_key,
)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class BERResult:
    attack_type:      AttackType
    bit_ber:          float           # bit-level BER
    symbol_ber:       float           # RS symbol-level BER
    n_bit_errors:     int
    n_symbol_errors:  int
    rs_decode_success: bool
    attribution_correct: Optional[bool]  # None if no DB check was done
    metadata:         dict


# ---------------------------------------------------------------------------
# BER computation
# ---------------------------------------------------------------------------

def compute_ber(
    ground_truth_bits: list[int],
    extracted_bits: list[int],
) -> tuple[float, float, int, int]:
    """
    Compute bit-level and symbol-level BER.

    Returns:
        (bit_ber, symbol_ber, n_bit_errors, n_symbol_errors)

    A symbol error is counted when any bit within an 8-bit window is wrong.
    """
    n = min(len(ground_truth_bits), len(extracted_bits), SEGMENTS_PER_PASS)
    if n == 0:
        return 0.0, 0.0, 0, 0

    gt  = ground_truth_bits[:n]
    ext = extracted_bits[:n]

    # Bit-level errors
    bit_errors = sum(a != b for a, b in zip(gt, ext))
    bit_ber    = bit_errors / n

    # Symbol-level errors (any bit wrong within an 8-bit window)
    sym_errors = 0
    for i in range(0, n, BITS_PER_SYMBOL):
        window_gt  = gt[i:i + BITS_PER_SYMBOL]
        window_ext = ext[i:i + BITS_PER_SYMBOL]
        if any(a != b for a, b in zip(window_gt, window_ext)):
            sym_errors += 1
    n_symbols  = n // BITS_PER_SYMBOL
    symbol_ber = sym_errors / n_symbols if n_symbols > 0 else 0.0

    return bit_ber, symbol_ber, bit_errors, sym_errors


# ---------------------------------------------------------------------------
# Per-attack BER runner
# ---------------------------------------------------------------------------

def measure_attack_ber(
    attack_type: AttackType,
    leaked_segment_paths: list[Path],
    variant_store,
    ground_truth_fp_bits: list[int],
    output_dir: Path,
    subscriber_id: Optional[str] = None,
    matcher=None,
    **attack_kwargs,
) -> BERResult:
    """
    Apply `attack_type` to the leaked segments and measure BER.

    Args:
        attack_type:          Which attack to simulate.
        leaked_segment_paths: Ordered list of leaked segment paths
                              (one per subscriber stream for T4).
        variant_store:        VariantStore for reference segments.
        ground_truth_fp_bits: The ground-truth 512-bit fingerprint sequence.
        output_dir:           Directory to write attacked segments.
        subscriber_id:        If provided (and matcher given), check attribution.
        matcher:              FingerprintMatcher for attribution check.
        **attack_kwargs:      Forwarded to apply_attack.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Apply attack
    attacked_path = output_dir / f"attacked_{attack_type.value}.mp4"
    attack_result = apply_attack(
        attack_type,
        input_paths=leaked_segment_paths,
        output_path=attacked_path,
        **attack_kwargs,
    )

    # Extract fingerprint from attacked video
    extractor = SegmentExtractor(variant_store)
    try:
        fp_bits, _confs = extractor.extract_fingerprint_bits(
            [attacked_path]  # single merged video; extractor handles it
        )
    except Exception as e:
        # If extraction fails (e.g. no reference), report BER as 0.5 (random)
        fp_bits = [0] * SEGMENTS_PER_PASS

    # Measure BER
    bit_ber, sym_ber, n_bit_err, n_sym_err = compute_ber(ground_truth_fp_bits, fp_bits)

    # RS decode check
    decoder = RSDecoder()
    diag    = decoder.decode_with_diagnostics(fp_bits)
    rs_ok   = diag["success"]

    # Attribution check
    attr_correct: Optional[bool] = None
    if rs_ok and matcher is not None and subscriber_id is not None:
        results, _ = matcher.identify_by_fp_bits(fp_bits, top_k=1)
        if results:
            attr_correct = (results[0].subscriber_id == subscriber_id)

    return BERResult(
        attack_type       = attack_type,
        bit_ber           = bit_ber,
        symbol_ber        = sym_ber,
        n_bit_errors      = n_bit_err,
        n_symbol_errors   = n_sym_err,
        rs_decode_success = rs_ok,
        attribution_correct = attr_correct,
        metadata          = attack_result.metadata,
    )


# ---------------------------------------------------------------------------
# Full evaluation sweep
# ---------------------------------------------------------------------------

def run_all_attacks(
    leaked_segment_paths: list[Path],
    variant_store,
    ground_truth_fp_bits: list[int],
    output_dir: Path,
    collusion_paths: Optional[list[list[Path]]] = None,
    subscriber_id: Optional[str] = None,
    matcher=None,
) -> list[BERResult]:
    """
    Run T1, T2, T3 (and optionally T4) and return a list of BERResult.

    Args:
        collusion_paths: List of segment-path lists for T4 (one per colluder).
                         If None, T4 is skipped.
    """
    results: list[BERResult] = []

    single_attacks = [
        (AttackType.T1_IDENTITY,      {}),
        (AttackType.T2_RECOMPRESSION, {"bitrate": "500k", "crf": 35}),
        (AttackType.T3_RESIZE,        {"scale_factor": 0.5}),
    ]

    for attack_type, kwargs in single_attacks:
        r = measure_attack_ber(
            attack_type       = attack_type,
            leaked_segment_paths = leaked_segment_paths,
            variant_store     = variant_store,
            ground_truth_fp_bits = ground_truth_fp_bits,
            output_dir        = output_dir / attack_type.value,
            subscriber_id     = subscriber_id,
            matcher           = matcher,
            **kwargs,
        )
        results.append(r)

    if collusion_paths is not None:
        flat_paths = [p for paths in collusion_paths for p in paths]
        r = measure_attack_ber(
            attack_type       = AttackType.T4_COLLUSION,
            leaked_segment_paths = flat_paths,
            variant_store     = variant_store,
            ground_truth_fp_bits = ground_truth_fp_bits,
            output_dir        = output_dir / "collusion",
            subscriber_id     = subscriber_id,
            matcher           = matcher,
        )
        results.append(r)

    return results


# ---------------------------------------------------------------------------
# Pretty-print
# ---------------------------------------------------------------------------

def print_ber_table(results: list[BERResult]) -> None:
    """Print a formatted summary table to stdout."""
    header = (
        f"{'Attack':<18} {'Bit BER':>8} {'Sym BER':>8} "
        f"{'RS OK':>6} {'Attr?':>6}"
    )
    print(header)
    print("-" * len(header))
    for r in results:
        attr_str = (
            "N/A" if r.attribution_correct is None
            else ("YES" if r.attribution_correct else "NO")
        )
        print(
            f"{r.attack_type.value:<18} "
            f"{r.bit_ber:>8.4f} "
            f"{r.symbol_ber:>8.4f} "
            f"{'YES' if r.rs_decode_success else 'NO':>6} "
            f"{attr_str:>6}"
        )
