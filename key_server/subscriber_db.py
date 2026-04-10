"""
key_server/subscriber_db.py

In-memory subscriber registry for 01-Parity.

Each subscriber record stores:
  - subscriber_id  : str
  - k_sub          : bytes  (32-byte random secret, never leaves the key server)
  - k_u            : bytes  (32-byte derived key = HKDF(K_vendor || K_sub))
  - raw_fingerprint: bytes  (42-byte AES-CTR output keyed by k_u)

The raw_fingerprint is the ground-truth identity token used by the forensics
matcher.  It is derived once at registration time and cached for fast lookup.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Optional

from key_server.hkdf import derive_subscriber_key, generate_k_sub
from edge.parity_selector import _aes_ctr_keystream, RS_DATA


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class SubscriberRecord:
    subscriber_id:   str
    k_sub:           bytes
    k_u:             bytes
    raw_fingerprint: bytes   # 42 bytes from AES-CTR(k_u)


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

class SubscriberDB:
    """
    Thread-safe in-memory subscriber registry.

    Usage
    -----
    db = SubscriberDB(k_vendor=K_VENDOR)
    db.register("alice")
    record = db.get("alice")
    key    = record.k_sub
    """

    def __init__(self, k_vendor: bytes) -> None:
        if len(k_vendor) < 16:
            raise ValueError("k_vendor must be at least 16 bytes")
        self._k_vendor = k_vendor
        self._records: dict[str, SubscriberRecord] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(
        self,
        subscriber_id: str,
        k_sub: Optional[bytes] = None,
    ) -> SubscriberRecord:
        """
        Register a new subscriber.

        If k_sub is None, a fresh random key is generated automatically.
        Raises ValueError if the subscriber_id is already registered.
        """
        with self._lock:
            if subscriber_id in self._records:
                raise ValueError(f"Subscriber {subscriber_id!r} already registered")

            if k_sub is None:
                k_sub = generate_k_sub()

            k_u             = derive_subscriber_key(self._k_vendor, k_sub)
            raw_fingerprint = _aes_ctr_keystream(k_u, RS_DATA)

            record = SubscriberRecord(
                subscriber_id   = subscriber_id,
                k_sub           = k_sub,
                k_u             = k_u,
                raw_fingerprint = raw_fingerprint,
            )
            self._records[subscriber_id] = record
            return record

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get(self, subscriber_id: str) -> SubscriberRecord:
        """Return the subscriber record or raise KeyError."""
        with self._lock:
            try:
                return self._records[subscriber_id]
            except KeyError:
                raise KeyError(f"Unknown subscriber: {subscriber_id!r}")

    def get_k_u(self, subscriber_id: str) -> bytes:
        """Return the 32-byte derived key for a subscriber."""
        return self.get(subscriber_id).k_u

    def get_raw_fingerprint(self, subscriber_id: str) -> bytes:
        """Return the 42-byte raw fingerprint for a subscriber."""
        return self.get(subscriber_id).raw_fingerprint

    def exists(self, subscriber_id: str) -> bool:
        with self._lock:
            return subscriber_id in self._records

    # ------------------------------------------------------------------
    # Enumeration
    # ------------------------------------------------------------------

    def all_ids(self) -> list[str]:
        """Return sorted list of all registered subscriber IDs."""
        with self._lock:
            return sorted(self._records.keys())

    def count(self) -> int:
        with self._lock:
            return len(self._records)

    def all_records(self) -> list[SubscriberRecord]:
        with self._lock:
            return list(self._records.values())

    # ------------------------------------------------------------------
    # Bulk registration (convenience for evaluation)
    # ------------------------------------------------------------------

    def register_bulk(self, subscriber_ids: list[str]) -> list[SubscriberRecord]:
        """Register multiple subscribers at once; returns their records."""
        return [self.register(sid) for sid in subscriber_ids]
