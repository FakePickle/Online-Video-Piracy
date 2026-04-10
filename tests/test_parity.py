"""
tests/test_parity.py

Unit tests for edge/parity_selector.py.

Test classes
------------
TestKeyDerivation        — HKDF is deterministic, per-subscriber unique, 32 bytes
TestFingerprintBits      — AES-CTR + RS encode output length, binary, deterministic
TestBitSerialization     — _bytes_to_bits / _bits_to_bytes round-trip
TestXORChain             — Round-trip invariant, segment indices, v1 injection,
                           inter-subscriber distinctness, cycling
TestReedSolomon          — Decode with 0, 11 symbol errors, >11 errors; BER bound
TestMinimumSegments      — MIN_SEGMENTS = 1025 constant enforced
TestFullPipeline         — End-to-end: variant sequence -> extract -> RS decode -> match
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from edge.parity_selector import (
    BITS_PER_SYMBOL,
    MIN_SEGMENTS,
    RS_DATA,
    RS_NSYM,
    RS_TOTAL,
    SEGMENTS_PER_PASS,
    _aes_ctr_keystream,
    _bits_to_bytes,
    _bytes_to_bits,
    compute_variant_sequence,
    decode_subscriber_fingerprint,
    derive_subscriber_key,
    extract_fingerprint_bits_from_variants,
    generate_fingerprint_bits,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

K_VENDOR = b"test-vendor-key-32-bytes-padded!"   # 32 bytes
K_SUB_A  = b"subscriber-alice-key"
K_SUB_B  = b"subscriber-bob--key-"


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

class TestKeyDerivation:
    def test_deterministic(self):
        assert derive_subscriber_key(K_VENDOR, K_SUB_A) == \
               derive_subscriber_key(K_VENDOR, K_SUB_A)

    def test_length_is_32_bytes(self):
        assert len(derive_subscriber_key(K_VENDOR, K_SUB_A)) == 32

    def test_different_sub_different_key(self):
        assert derive_subscriber_key(K_VENDOR, K_SUB_A) != \
               derive_subscriber_key(K_VENDOR, K_SUB_B)

    def test_different_vendor_different_key(self):
        k_vendor2 = b"other-vendor-key-32-bytes-padd!!"
        assert derive_subscriber_key(K_VENDOR, K_SUB_A) != \
               derive_subscriber_key(k_vendor2, K_SUB_A)


# ---------------------------------------------------------------------------
# Fingerprint bit generation
# ---------------------------------------------------------------------------

class TestFingerprintBits:
    def setup_method(self):
        self.k_u = derive_subscriber_key(K_VENDOR, K_SUB_A)

    def test_length_equals_segments_per_pass(self):
        bits = generate_fingerprint_bits(self.k_u)
        assert len(bits) == SEGMENTS_PER_PASS          # 512

    def test_all_binary(self):
        bits = generate_fingerprint_bits(self.k_u)
        assert all(b in (0, 1) for b in bits)

    def test_deterministic(self):
        assert generate_fingerprint_bits(self.k_u) == \
               generate_fingerprint_bits(self.k_u)

    def test_different_keys_different_bits(self):
        k_u_b = derive_subscriber_key(K_VENDOR, K_SUB_B)
        assert generate_fingerprint_bits(self.k_u) != \
               generate_fingerprint_bits(k_u_b)


# ---------------------------------------------------------------------------
# Bit serialization
# ---------------------------------------------------------------------------

class TestBitSerialization:
    def test_round_trip_single_byte(self):
        for val in [0x00, 0x01, 0x55, 0xAA, 0xFF]:
            bits = _bytes_to_bits(bytes([val]))
            assert _bits_to_bytes(bits) == bytes([val])

    def test_round_trip_multi_byte(self):
        data = bytes(range(64))
        assert _bits_to_bytes(_bytes_to_bits(data)) == data

    def test_lsb_first_ordering(self):
        bits = _bytes_to_bits(bytes([0b00000001]))   # value = 1
        assert bits[0] == 1                           # LSB is bit 0
        assert bits[1:] == [0] * 7

    def test_bits_to_bytes_length(self):
        bits = _bytes_to_bits(bytes(64))
        assert len(bits) == 512


# ---------------------------------------------------------------------------
# XOR chain
# ---------------------------------------------------------------------------

class TestXORChain:
    def _variants_for_alice(self, n: int, v1: int = 0) -> list[int]:
        pairs = compute_variant_sequence("alice", K_VENDOR, K_SUB_A,
                                         n_segments=n, v1=v1)
        return [v for _, v in pairs]

    def test_round_trip_one_pass(self):
        """f_i = v_i XOR v_{i+1} must recover the original 512 fingerprint bits."""
        k_u = derive_subscriber_key(K_VENDOR, K_SUB_A)
        expected = generate_fingerprint_bits(k_u)

        # One pass needs 512 transitions → 513 variant values
        variants = self._variants_for_alice(n=SEGMENTS_PER_PASS + 1, v1=0)
        recovered = extract_fingerprint_bits_from_variants(variants)
        assert recovered == expected

    def test_round_trip_double_embed(self):
        """Second pass (bits 512-1023) must equal the same fingerprint as the first."""
        k_u = derive_subscriber_key(K_VENDOR, K_SUB_A)
        expected = generate_fingerprint_bits(k_u)

        variants  = self._variants_for_alice(n=MIN_SEGMENTS, v1=0)   # 1025 variants
        bits_all  = extract_fingerprint_bits_from_variants(variants)  # 1024 bits

        first_pass  = bits_all[:SEGMENTS_PER_PASS]
        second_pass = bits_all[SEGMENTS_PER_PASS:]
        assert first_pass  == expected
        assert second_pass == expected

    def test_segment_indices_sequential(self):
        pairs = compute_variant_sequence("alice", K_VENDOR, K_SUB_A, n_segments=20, v1=0)
        assert [i for i, _ in pairs] == list(range(20))

    def test_variant_values_binary(self):
        pairs = compute_variant_sequence("alice", K_VENDOR, K_SUB_A, n_segments=50)
        assert all(v in (0, 1) for _, v in pairs)

    def test_v1_is_respected(self):
        pairs_0 = compute_variant_sequence("alice", K_VENDOR, K_SUB_A, n_segments=10, v1=0)
        pairs_1 = compute_variant_sequence("alice", K_VENDOR, K_SUB_A, n_segments=10, v1=1)
        assert pairs_0[0][1] == 0
        assert pairs_1[0][1] == 1

    def test_v1_flip_propagates_to_all_variants(self):
        """Flipping v1 flips every subsequent variant."""
        pairs_0 = compute_variant_sequence("alice", K_VENDOR, K_SUB_A,
                                            n_segments=200, v1=0)
        pairs_1 = compute_variant_sequence("alice", K_VENDOR, K_SUB_A,
                                            n_segments=200, v1=1)
        v0 = [v for _, v in pairs_0]
        v1 = [v for _, v in pairs_1]
        assert all(a != b for a, b in zip(v0, v1))

    def test_different_subscribers_differ(self):
        pairs_a = compute_variant_sequence("alice", K_VENDOR, K_SUB_A,
                                           n_segments=200, v1=0)
        pairs_b = compute_variant_sequence("bob",   K_VENDOR, K_SUB_B,
                                           n_segments=200, v1=0)
        va = [v for _, v in pairs_a]
        vb = [v for _, v in pairs_b]
        assert va != vb

    def test_cycling_beyond_coded_length(self):
        """Segments beyond the double-embed window cycle without error."""
        pairs = compute_variant_sequence("alice", K_VENDOR, K_SUB_A,
                                          n_segments=3000, v1=0)
        assert len(pairs) == 3000
        assert all(v in (0, 1) for _, v in pairs)


# ---------------------------------------------------------------------------
# Reed-Solomon encode/decode
# ---------------------------------------------------------------------------

class TestReedSolomon:
    def setup_method(self):
        self.k_u   = derive_subscriber_key(K_VENDOR, K_SUB_A)
        self.coded = generate_fingerprint_bits(self.k_u)   # 512 bits

    def test_decode_clean(self):
        result = decode_subscriber_fingerprint(self.coded)
        assert result is not None
        assert len(result) == RS_DATA                      # 42 bytes

    def test_decode_matches_original_raw_key(self):
        """decode(encode(raw)) == raw (lossless round-trip)."""
        raw    = _aes_ctr_keystream(self.k_u, RS_DATA)
        result = decode_subscriber_fingerprint(self.coded)
        assert result == raw

    def test_decode_corrects_11_symbol_errors(self):
        """
        RS(64, 42) corrects floor(22/2) = 11 RS symbol (byte) errors.

        A symbol error means any corruption within an 8-bit segment window.
        We flip all 8 bits of 11 different symbols (worst-case corruption).
        """
        corrupted = list(self.coded)
        # Flip all 8 bits for 11 different RS symbols (symbols 0, 3, 6, ..., 30)
        for sym_idx in range(0, 11 * 3, 3):                # 11 symbol indices
            base = sym_idx * BITS_PER_SYMBOL
            for bit_offset in range(BITS_PER_SYMBOL):
                corrupted[base + bit_offset] ^= 1
        result = decode_subscriber_fingerprint(corrupted)
        assert result is not None

    def test_decode_fails_beyond_capacity(self):
        """12 symbol errors exceed correction capacity."""
        corrupted = list(self.coded)
        for sym_idx in range(12):
            base = sym_idx * BITS_PER_SYMBOL
            # Flip just one bit per symbol (still counts as one symbol error each)
            corrupted[base] ^= 1
        result = decode_subscriber_fingerprint(corrupted)
        assert result is None

    def test_ber_bound(self):
        """
        11 symbol errors × 8 bits/symbol = 88 bit errors / 512 total ≈ 17.2 % BER < 18 %.
        """
        max_correctable_symbols = RS_NSYM // 2              # 11
        max_correctable_bits    = max_correctable_symbols * BITS_PER_SYMBOL  # 88
        ber = max_correctable_bits / SEGMENTS_PER_PASS      # 88/512
        assert ber < 0.18

    def test_rs_constants(self):
        assert RS_TOTAL          == 64
        assert RS_DATA           == 42
        assert RS_NSYM           == 22
        assert BITS_PER_SYMBOL   == 8
        assert SEGMENTS_PER_PASS == 512

    def test_decode_short_input_returns_none(self):
        assert decode_subscriber_fingerprint([0] * 100) is None


# ---------------------------------------------------------------------------
# Minimum segment constraint
# ---------------------------------------------------------------------------

class TestMinimumSegments:
    def test_min_segments_constant(self):
        """MIN_SEGMENTS = SEGMENTS_PER_PASS * 2 + 1 = 1025."""
        assert MIN_SEGMENTS == SEGMENTS_PER_PASS * 2 + 1

    def test_default_n_segments_is_min(self):
        pairs = compute_variant_sequence("alice", K_VENDOR, K_SUB_A, v1=0)
        assert len(pairs) == MIN_SEGMENTS

    def test_min_content_duration_seconds(self):
        """
        At 2 s/segment, 1025 segments require 1024 coded transitions.
        1024 transitions ÷ BITS_PER_SYMBOL = 128 RS symbols served = 2 full passes.
        Content duration = 1024 × 2 s = 2048 s ≈ 34 min.
        """
        segment_duration_s = 2
        n_coded_segments   = MIN_SEGMENTS - 1               # 1024
        min_duration_s     = n_coded_segments * segment_duration_s
        assert min_duration_s == 2048


# ---------------------------------------------------------------------------
# Full end-to-end pipeline
# ---------------------------------------------------------------------------

class TestFullPipeline:
    def test_end_to_end_no_errors(self):
        """
        subscriber key -> variant sequence -> extract bits -> RS decode
        must recover the original AES-CTR raw key material.
        """
        k_u          = derive_subscriber_key(K_VENDOR, K_SUB_A)
        original_raw = _aes_ctr_keystream(k_u, RS_DATA)

        # One full pass: SEGMENTS_PER_PASS transitions need +1 leading variant
        pairs    = compute_variant_sequence("alice", K_VENDOR, K_SUB_A,
                                             n_segments=SEGMENTS_PER_PASS + 1, v1=0)
        variants  = [v for _, v in pairs]
        extracted = extract_fingerprint_bits_from_variants(variants)  # 512 bits
        recovered  = decode_subscriber_fingerprint(extracted)

        assert recovered == original_raw

    def test_end_to_end_with_11_symbol_errors(self):
        """Pipeline survives 11 fully-corrupted RS symbols (worst case)."""
        k_u          = derive_subscriber_key(K_VENDOR, K_SUB_A)
        original_raw = _aes_ctr_keystream(k_u, RS_DATA)

        pairs     = compute_variant_sequence("alice", K_VENDOR, K_SUB_A,
                                              n_segments=SEGMENTS_PER_PASS + 1, v1=0)
        variants   = [v for _, v in pairs]
        extracted  = list(extract_fingerprint_bits_from_variants(variants))

        # Corrupt 11 RS symbols (all 8 bits of each symbol)
        for sym_idx in [0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50]:
            base = sym_idx * BITS_PER_SYMBOL
            for j in range(BITS_PER_SYMBOL):
                extracted[base + j] ^= 1

        recovered = decode_subscriber_fingerprint(extracted)
        assert recovered == original_raw

    def test_double_embed_both_passes_decode(self):
        """
        Both passes of the double-embedded stream must independently decode
        to the same subscriber key material.
        """
        k_u          = derive_subscriber_key(K_VENDOR, K_SUB_A)
        original_raw = _aes_ctr_keystream(k_u, RS_DATA)

        pairs    = compute_variant_sequence("alice", K_VENDOR, K_SUB_A,
                                             n_segments=MIN_SEGMENTS, v1=0)
        variants  = [v for _, v in pairs]
        bits_all  = extract_fingerprint_bits_from_variants(variants)  # 1024 bits

        pass1 = decode_subscriber_fingerprint(bits_all[:SEGMENTS_PER_PASS])
        pass2 = decode_subscriber_fingerprint(bits_all[SEGMENTS_PER_PASS:])

        assert pass1 == original_raw
        assert pass2 == original_raw

    def test_attribution_identifies_correct_subscriber(self):
        """
        Leaked stream from alice decodes to alice's key, not bob's.
        """
        k_u_a = derive_subscriber_key(K_VENDOR, K_SUB_A)
        k_u_b = derive_subscriber_key(K_VENDOR, K_SUB_B)

        raw_a = _aes_ctr_keystream(k_u_a, RS_DATA)
        raw_b = _aes_ctr_keystream(k_u_b, RS_DATA)
        assert raw_a != raw_b

        pairs_a   = compute_variant_sequence("alice", K_VENDOR, K_SUB_A,
                                              n_segments=SEGMENTS_PER_PASS + 1, v1=0)
        variants_a  = [v for _, v in pairs_a]
        extracted_a = extract_fingerprint_bits_from_variants(variants_a)

        recovered = decode_subscriber_fingerprint(extracted_a)
        assert recovered == raw_a
        assert recovered != raw_b
