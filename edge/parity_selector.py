"""
edge/parity_selector.py — Core 01-Parity contribution.

Implements per-subscriber HLS variant selection using the XOR parity chain:

    v_1  <- random {0, 1}
    v_{i+1} = v_i XOR f_i    for i = 1, ..., n

where f_i are the serialized bits of an RS(64, 42)-coded fingerprint derived
from the subscriber's HKDF key.

Key derivation
--------------
    k_u = HKDF-SHA256(K_vendor || K_sub, info=b"01-parity-subscriber-key")

Fingerprint generation
----------------------
    raw (42 bytes)       <- AES-CTR keystream seeded with k_u
    codeword (64 bytes)  <- RSCodec(nsym=22).encode(raw)   [RS(64, 42) over GF(2^8)]
    fp_bits (512 bits)   <- codeword serialized bit by bit (8 bits per byte, LSB first)

Each fp_bit drives one HLS segment's variant transition in the XOR chain.

Segment budget per pass
-----------------------
    64 codeword bytes × 8 bits/byte = 512 segments per pass
    Double-embed: 1 024 segments + 1 leading variant = 1 025 min segments
    At 2 s/segment: 1 024 × 2 = 2 048 s ≈ 34 min minimum content duration

RS error tolerance
------------------
    floor((64 - 42) / 2) = 11 RS symbol (byte) errors correctable
    Each byte spans 8 segments; 11 bytes × 8 bits = 88 bit errors out of 512
    88 / 512 ≈ 17.2 % BER  < stated 18 % bound

NOTE on the paper's "5-minute window" claim
-------------------------------------------
    The paper states a 5-minute window for RS(64, 42) with 2-second segments.
    That would require 150 segments = 18.75 symbols per pass, not 64.
    The correct minimum content duration at 2 s/segment is ~34 minutes (single
    pass) or the segment duration must be ≤ 0.24 s to fit within 5 minutes.
    The 18 % BER tolerance is correct; the 5-minute claim in the paper is not.
"""

from __future__ import annotations

import os
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import reedsolo

# ---------------------------------------------------------------------------
# RS(64, 42) constants
# ---------------------------------------------------------------------------
RS_TOTAL: int = 64          # total codeword symbols (bytes)
RS_DATA: int = 42           # data symbols (bytes)
RS_NSYM: int = RS_TOTAL - RS_DATA  # 22 parity symbols

BITS_PER_SYMBOL: int = 8    # bits per RS symbol (GF(2^8) byte)
SEGMENTS_PER_PASS: int = RS_TOTAL * BITS_PER_SYMBOL  # 512 segments per RS pass

# Minimum HLS segments for one full double-embedded fingerprint:
#   2 passes × 512 segments/pass + 1 leading variant = 1 025 segments
#   At 2 s/segment: 1 024 × 2 s = 2 048 s ≈ 34 min
MIN_SEGMENTS: int = SEGMENTS_PER_PASS * 2 + 1  # 1025

_rsc = reedsolo.RSCodec(RS_NSYM)

# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def derive_subscriber_key(k_vendor: bytes, k_sub: bytes) -> bytes:
    """HKDF-SHA256(K_vendor || K_sub) -> 32-byte subscriber key k_u."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"01-parity-subscriber-key",
    )
    return hkdf.derive(k_vendor + k_sub)


# ---------------------------------------------------------------------------
# AES-CTR PRNG
# ---------------------------------------------------------------------------

def _aes_ctr_keystream(key: bytes, length: int) -> bytes:
    """
    Generate `length` pseudo-random bytes using AES-256-CTR with nonce=0.
    Output is deterministic per key; used as the raw subscriber fingerprint.
    """
    nonce = b"\x00" * 16
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    enc = cipher.encryptor()
    return enc.update(b"\x00" * length) + enc.finalize()


# ---------------------------------------------------------------------------
# Bit serialization helpers
# ---------------------------------------------------------------------------

def _bytes_to_bits(data: bytes) -> list[int]:
    """Serialize bytes to a flat list of bits, LSB first within each byte."""
    bits = []
    for byte in data:
        for i in range(BITS_PER_SYMBOL):
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_bytes(bits: list[int]) -> bytes:
    """Pack a flat list of bits (LSB-first per byte) back into bytes."""
    if len(bits) % BITS_PER_SYMBOL != 0:
        raise ValueError(
            f"bits length {len(bits)} is not a multiple of {BITS_PER_SYMBOL}"
        )
    result = []
    for i in range(0, len(bits), BITS_PER_SYMBOL):
        byte = 0
        for j in range(BITS_PER_SYMBOL):
            byte |= (bits[i + j] & 1) << j
        result.append(byte)
    return bytes(result)


# ---------------------------------------------------------------------------
# Fingerprint encoding / decoding
# ---------------------------------------------------------------------------

def generate_fingerprint_bits(k_u: bytes) -> list[int]:
    """
    Generate the RS(64, 42)-coded fingerprint bit sequence for subscriber key k_u.

    Steps:
      1. AES-CTR(k_u) -> 42 raw bytes (subscriber identity material)
      2. RSCodec(22).encode(raw) -> 64-byte codeword over GF(2^8)
      3. Serialize codeword bytes to bits (LSB first) -> 512 bits

    Returns a list of 512 integers in {0, 1}.  Each bit drives one HLS
    segment's variant selection via the XOR parity chain.
    """
    raw = _aes_ctr_keystream(k_u, RS_DATA)
    codeword = bytes(_rsc.encode(raw))                  # 64 bytes
    return _bytes_to_bits(codeword)                     # 512 bits


def decode_subscriber_fingerprint(fp_bits: list[int]) -> Optional[bytes]:
    """
    RS(64, 42) decode a (possibly corrupted) fingerprint bit sequence.

    Tolerates up to floor(22/2) = 11 RS symbol errors.  A "symbol error"
    means any one or more bit errors within an 8-bit segment window.
    11 fully-corrupted symbols = 88 bit errors / 512 total ≈ 17.2 % BER.

    Args:
        fp_bits: List of at least 512 integers in {0, 1}.

    Returns:
        42 bytes of raw subscriber key material on success, None on failure.
    """
    if len(fp_bits) < SEGMENTS_PER_PASS:
        return None
    codeword = _bits_to_bytes(fp_bits[:SEGMENTS_PER_PASS])  # 64 bytes
    try:
        decoded, _ecc, _errata = _rsc.decode(codeword)
        return bytes(decoded)
    except reedsolo.ReedSolomonError:
        return None


# ---------------------------------------------------------------------------
# XOR parity chain — core algorithm
# ---------------------------------------------------------------------------

def compute_variant_sequence(
    subscriber_id: str,
    k_vendor: bytes,
    k_sub: bytes,
    n_segments: Optional[int] = None,
    v1: Optional[int] = None,
) -> list[tuple[int, int]]:
    """
    Compute the (segment_index, variant) sequence for a subscriber.

    Algorithm:
        k_u      <- HKDF-SHA256(K_vendor || K_sub)
        fp_bits  <- generate_fingerprint_bits(k_u)           # 512 bits (one RS pass)
        coded    <- fp_bits + fp_bits                        # 1024 bits (double embed)

        v_1      <- random {0,1}  (or caller-supplied v1 for reproducibility)
        v_{i+1}  =  v_i XOR coded[i-1]   for i = 1, ..., len(coded)

    The segment server reads variant v_i when serving segment i-1 (0-indexed).

    Args:
        subscriber_id: Opaque identifier (not used in crypto; for logging).
        k_vendor:      Master vendor secret (shared across all subscribers).
        k_sub:         Per-subscriber secret (rotatable).
        n_segments:    How many segments to generate.  Defaults to MIN_SEGMENTS
                       (1025, covering the full double-embedded fingerprint).
                       Values > 1025 continue cycling the coded bit stream.
        v1:            Force the first variant value (0 or 1).  Pass a fixed
                       value in tests for determinism; leave None in production
                       for a cryptographically random start.

    Returns:
        List of (segment_index, variant) pairs, segment_index starting at 0.
    """
    k_u = derive_subscriber_key(k_vendor, k_sub)
    fp_bits = generate_fingerprint_bits(k_u)      # 512 bits

    # Double-embed: transmit the fingerprint twice for redundancy
    coded = fp_bits + fp_bits                      # 1024 bits

    if n_segments is None:
        n_segments = MIN_SEGMENTS                  # 1025

    if v1 is None:
        v1 = int.from_bytes(os.urandom(1), "big") & 1

    variants: list[int] = [v1]
    coded_len = len(coded)

    for seg_idx in range(1, n_segments):
        bit_pos = (seg_idx - 1) % coded_len
        v_next = variants[-1] ^ coded[bit_pos]
        variants.append(v_next)

    return list(enumerate(variants))


# ---------------------------------------------------------------------------
# Extraction helper
# ---------------------------------------------------------------------------

def extract_fingerprint_bits_from_variants(variants: list[int]) -> list[int]:
    """
    Given the variant sequence [v_1, v_2, ..., v_{n+1}], recover fingerprint bits.

    Inverse of the XOR chain:   f_i = v_i XOR v_{i+1}

    Args:
        variants: List of variant values (integers in {0, 1}).

    Returns:
        List of len(variants) - 1 fingerprint bits.
    """
    return [variants[i] ^ variants[i + 1] for i in range(len(variants) - 1)]
