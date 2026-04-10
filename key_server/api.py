"""
key_server/api.py

Flask REST API that lets edge nodes fetch subscriber keys.

Endpoints
---------
POST   /subscribers                 Register a new subscriber.
GET    /subscribers/<id>/key        Return k_sub for an edge node to derive k_u.
GET    /subscribers/<id>            Return subscriber metadata (no k_sub).
GET    /subscribers                 List all registered subscriber IDs.
DELETE /subscribers/<id>            De-register a subscriber.

Security note
-------------
In production, every endpoint should require mutual TLS between the edge
node and the key server.  This prototype uses a static bearer token
(API_TOKEN env-var) as a lightweight stand-in.
"""

from __future__ import annotations

import os
from functools import wraps
from typing import Any

from flask import Flask, jsonify, request, Response

from key_server.subscriber_db import SubscriberDB

app  = Flask(__name__)
_db: SubscriberDB | None = None   # set by configure() before first request

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

def configure(k_vendor: bytes, api_token: str | None = None) -> None:
    """
    Initialise the key server with a vendor key and optional auth token.

    Must be called before ``app.run()`` or before the first test request.
    """
    global _db
    _db = SubscriberDB(k_vendor)
    app.config["API_TOKEN"] = api_token or os.environ.get("API_TOKEN", "")


def _get_db() -> SubscriberDB:
    if _db is None:
        raise RuntimeError("Key server not configured; call configure() first.")
    return _db


# ---------------------------------------------------------------------------
# Auth middleware
# ---------------------------------------------------------------------------

def _require_token(f):
    """Decorator: reject requests that don't carry the expected Bearer token."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = app.config.get("API_TOKEN", "")
        if token:
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer ") or auth[7:] != token:
                return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _record_to_dict(record, include_k_sub: bool = False) -> dict[str, Any]:
    d: dict[str, Any] = {"subscriber_id": record.subscriber_id}
    if include_k_sub:
        d["k_sub"] = record.k_sub.hex()
    return d


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.route("/subscribers", methods=["POST"])
@_require_token
def register_subscriber() -> tuple[Response, int]:
    """
    Register a new subscriber.

    Request body (JSON, optional):
        { "subscriber_id": "alice", "k_sub": "<hex>" }

    If subscriber_id is omitted a 400 is returned.
    If k_sub is omitted the server generates one automatically.
    """
    body          = request.get_json(silent=True) or {}
    subscriber_id = body.get("subscriber_id")
    k_sub_hex     = body.get("k_sub")

    if not subscriber_id:
        return jsonify({"error": "subscriber_id is required"}), 400

    k_sub = bytes.fromhex(k_sub_hex) if k_sub_hex else None

    try:
        record = _get_db().register(subscriber_id, k_sub=k_sub)
    except ValueError as e:
        return jsonify({"error": str(e)}), 409

    return jsonify(_record_to_dict(record, include_k_sub=True)), 201


@app.route("/subscribers/<subscriber_id>/key", methods=["GET"])
@_require_token
def get_subscriber_key(subscriber_id: str) -> tuple[Response, int]:
    """
    Return k_sub so the edge node can derive k_u locally.

    Response body:
        { "subscriber_id": "alice", "k_sub": "<hex>" }
    """
    try:
        record = _get_db().get(subscriber_id)
    except KeyError:
        return jsonify({"error": f"Subscriber {subscriber_id!r} not found"}), 404

    return jsonify(_record_to_dict(record, include_k_sub=True)), 200


@app.route("/subscribers/<subscriber_id>", methods=["GET"])
@_require_token
def get_subscriber(subscriber_id: str) -> tuple[Response, int]:
    """Return subscriber metadata without the secret key."""
    try:
        record = _get_db().get(subscriber_id)
    except KeyError:
        return jsonify({"error": f"Subscriber {subscriber_id!r} not found"}), 404

    return jsonify(_record_to_dict(record, include_k_sub=False)), 200


@app.route("/subscribers", methods=["GET"])
@_require_token
def list_subscribers() -> tuple[Response, int]:
    """Return all registered subscriber IDs."""
    return jsonify({"subscriber_ids": _get_db().all_ids(), "count": _get_db().count()}), 200


@app.route("/subscribers/<subscriber_id>", methods=["DELETE"])
@_require_token
def delete_subscriber(subscriber_id: str) -> tuple[Response, int]:
    """
    De-register a subscriber.  Returns 204 on success, 404 if not found.
    """
    db = _get_db()
    if not db.exists(subscriber_id):
        return jsonify({"error": f"Subscriber {subscriber_id!r} not found"}), 404

    with db._lock:
        del db._records[subscriber_id]

    return Response(status=204)


# ---------------------------------------------------------------------------
# Entry point (development server only)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import secrets as _secrets
    # Demo: run with a random vendor key.  In production, load from env/vault.
    _k_vendor = bytes.fromhex(os.environ.get("K_VENDOR_HEX", _secrets.token_hex(32)))
    _token    = os.environ.get("API_TOKEN", "dev-token")
    configure(_k_vendor, api_token=_token)
    print(f"[key_server] K_vendor = {_k_vendor.hex()}")
    print(f"[key_server] API token = {_token}")
    app.run(host="0.0.0.0", port=8080, debug=False)
