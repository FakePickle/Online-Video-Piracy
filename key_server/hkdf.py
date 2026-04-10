"""
key_server/hkdf.py

Key derivation utilities for 01-Parity.

All key derivation in the system flows through this module.  The edge
parity_selector re-uses ``derive_subscriber_key`` directly; this module
adds helpers needed by the key server (fresh key generation, batch
derivation for the subscriber DB).
"""

from __future__ import annotations

import os
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Re-export for callers that want a single import point.
from edge.parity_selector import derive_subscriber_key  # noqa: F401

__all__ = [
    "derive_subscriber_key",
    "generate_k_sub",
    "generate_k_vendor",
    "derive_mask_key",
]

# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_k_sub(length: int = 32) -> bytes:
    """
    Generate a fresh, cryptographically random per-subscriber secret.

    This should be called once per subscriber at registration time and stored
    securely.  The value is never transmitted to the subscriber; it is used
    only by the key server to derive k_u on behalf of the edge nodes.
    """
    return secrets.token_bytes(length)


def generate_k_vendor(length: int = 32) -> bytes:
    """
    Generate a fresh, cryptographically random vendor master secret.

    Call once at system setup.  K_vendor is shared only between the key
    server and edge nodes via a secure channel (e.g., TLS mutual auth).
    """
    return secrets.token_bytes(length)


# ---------------------------------------------------------------------------
# Derived keys
# ---------------------------------------------------------------------------

def derive_mask_key(k_vendor: bytes, purpose: bytes = b"01-parity-dct-mask") -> bytes:
    """
    Derive the 32-byte DCT block-selection mask key from K_vendor.

    The mask key is shared with the preprocessor to ensure that the same
    blocks are modified during embedding and checked during extraction.
    It is NEVER shared with subscribers.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=purpose,
    )
    return hkdf.derive(k_vendor)
