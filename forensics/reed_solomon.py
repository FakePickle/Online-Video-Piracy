"""
forensics/reed_solomon.py

Reed-Solomon encode/decode wrapper for the forensics pipeline.

Thin façade over edge.parity_selector so the forensics team has a single
import point and doesn't need to depend on edge internals directly.

Typical forensics use-case
--------------------------
    decoder = RSDecoder()
    raw_key = decoder.decode(extracted_fp_bits)   # 512 bits → 42 bytes
    if raw_key is None:
        print("Too many errors — RS correction failed")
    else:
        print("Subscriber raw key:", raw_key.hex())
"""

from __future__ import annotations

from typing import Optional

from edge.parity_selector import (
    SEGMENTS_PER_PASS,
    RS_DATA,
    RS_TOTAL,
    RS_NSYM,
    BITS_PER_SYMBOL,
    _rsc,
    _bytes_to_bits,
    _bits_to_bytes,
    _aes_ctr_keystream,
    decode_subscriber_fingerprint,
    generate_fingerprint_bits,
    derive_subscriber_key,
)
import reedsolo


class RSDecoder:
    """
    Stateless RS(64, 42) decoder for the forensics pipeline.

    Wraps ``decode_subscriber_fingerprint`` with extra diagnostics.
    """

    # ------------------------------------------------------------------
    # Decode
    # ------------------------------------------------------------------

    def decode(self, fp_bits: list[int]) -> Optional[bytes]:
        """
        Attempt to RS-decode a (possibly corrupted) fingerprint bit sequence.

        Tolerates up to 11 RS symbol errors (≈17.2 % BER at bit level).

        Args:
            fp_bits: List of at least SEGMENTS_PER_PASS (512) bits.

        Returns:
            42-byte raw subscriber key material on success, None on failure.
        """
        return decode_subscriber_fingerprint(fp_bits)

    def decode_with_diagnostics(self, fp_bits: list[int]) -> dict:
        """
        Decode and return a diagnostics dict.

        Keys:
            success       : bool
            raw_key       : bytes or None
            n_bits        : int  — number of input bits
            n_symbol_errors: int or None  — estimated symbol errors (when decodable)
            ber_estimate  : float or None — estimated bit error rate
        """
        if len(fp_bits) < SEGMENTS_PER_PASS:
            return {
                "success": False,
                "raw_key": None,
                "n_bits": len(fp_bits),
                "n_symbol_errors": None,
                "ber_estimate": None,
                "error": f"Input too short: {len(fp_bits)} < {SEGMENTS_PER_PASS}",
            }

        codeword = _bits_to_bytes(fp_bits[:SEGMENTS_PER_PASS])
        try:
            decoded, _ecc, errata_pos = _rsc.decode(codeword)
            raw_key       = bytes(decoded)
            n_sym_errors  = len(errata_pos) if errata_pos else 0
            ber_estimate  = (n_sym_errors * BITS_PER_SYMBOL) / SEGMENTS_PER_PASS
            return {
                "success": True,
                "raw_key": raw_key,
                "n_bits": len(fp_bits),
                "n_symbol_errors": n_sym_errors,
                "ber_estimate": ber_estimate,
            }
        except reedsolo.ReedSolomonError as e:
            return {
                "success": False,
                "raw_key": None,
                "n_bits": len(fp_bits),
                "n_symbol_errors": None,
                "ber_estimate": None,
                "error": str(e),
            }

    # ------------------------------------------------------------------
    # Encode (used in evaluation to generate ground-truth fingerprints)
    # ------------------------------------------------------------------

    def encode(self, k_u: bytes) -> list[int]:
        """
        Return the 512-bit RS-coded fingerprint for subscriber key k_u.
        Delegates to generate_fingerprint_bits.
        """
        return generate_fingerprint_bits(k_u)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def code_params(self) -> dict:
        return {
            "n": RS_TOTAL,
            "k": RS_DATA,
            "nsym": RS_NSYM,
            "bits_per_symbol": BITS_PER_SYMBOL,
            "segments_per_pass": SEGMENTS_PER_PASS,
            "max_symbol_errors": RS_NSYM // 2,
            "max_ber": (RS_NSYM // 2) * BITS_PER_SYMBOL / SEGMENTS_PER_PASS,
        }
