"""Tests for signed vs unsigned ``load_fingerprints`` behavior."""

from __future__ import annotations

import base64
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from intel._signing import (
    HashMismatchError,
    canonical_payload_bytes,
    compute_payload_hash_hex,
)
from intel._trust_store import TrustedKey, TrustStore, load_trust_store
from intel.scout_fingerprint_loader import load_fingerprints


def _pem(pub) -> str:
    return (
        pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
        .strip()
    )


def _signed_file(
    path: Path,
    priv: Ed25519PrivateKey,
    *,
    fingerprints: dict,
    tamper_hash: bool = False,
) -> None:
    inner = {"fingerprints": fingerprints}
    canonical = canonical_payload_bytes(inner)
    h = compute_payload_hash_hex(canonical)
    if tamper_hash:
        h = "0" * 64
    sig = priv.sign(canonical)
    b64 = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")
    ts = datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc = {
        "payload": inner,
        "signature": {
            "algorithm": "ed25519",
            "key_id": "scout-fingerprint-key-v1",
            "signed_at": ts,
            "payload_hash_sha256": h,
            "signature_b64": b64,
        },
    }
    path.write_text(json.dumps(doc), encoding="utf-8")


def test_unsigned_list_backward_compat(tmp_path: Path) -> None:
    p = tmp_path / "fp.json"
    p.write_text(
        json.dumps(
            {
                "alpha.example": {"sans": ["alpha.example", "beta.example"]},
                "beta.example": {"sans": ["beta.example", "alpha.example"]},
            }
        ),
        encoding="utf-8",
    )
    fps = load_fingerprints(p)
    assert "alpha.example" in fps
    assert "beta.example" in fps


def test_signed_with_valid_trust_store(tmp_path: Path) -> None:
    priv = Ed25519PrivateKey.generate()
    pem = _pem(priv.public_key())
    ts_path = tmp_path / "trust.json"
    ts_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "updated_at": "2026-04-21T00:00:00Z",
                "keys": [
                    {
                        "key_id": "scout-fingerprint-key-v1",
                        "algorithm": "ed25519",
                        "public_key_pem": pem,
                        "issued_at": "2026-04-21T00:00:00Z",
                        "authorized_for": ["domain_fingerprints"],
                        "revoked_at": None,
                        "revocation_reason": None,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    fp_path = tmp_path / "fp.json"
    _signed_file(
        fp_path,
        priv,
        fingerprints={"a.example": {"sans": ["a.example"]}},
    )
    ts = load_trust_store(ts_path)
    fps = load_fingerprints(fp_path, trust_store=ts)
    assert fps["a.example"]["domain"] == "a.example"


def test_signed_without_trust_store_warns_and_extracts(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="intel.scout_fingerprint_loader")
    priv = Ed25519PrivateKey.generate()
    fp_path = tmp_path / "fp.json"
    _signed_file(
        fp_path,
        priv,
        fingerprints={"b.example": {"sans": ["b.example"]}},
    )
    fps = load_fingerprints(fp_path, trust_store=None)
    assert "b.example" in fps
    assert "unverified" in caplog.text.lower() or "no trust store" in caplog.text.lower()


def test_require_signed_with_unsigned_raises(tmp_path: Path) -> None:
    from intel._signing import EnvelopeShapeError

    p = tmp_path / "fp.json"
    p.write_text(json.dumps({"x.example": {}}), encoding="utf-8")
    with pytest.raises(EnvelopeShapeError, match="expected signed envelope"):
        load_fingerprints(p, require_signed=True)


def test_signed_tampered_payload_hash_raises(tmp_path: Path) -> None:
    priv = Ed25519PrivateKey.generate()
    pem = _pem(priv.public_key())
    ts = TrustStore(
        schema_version=1,
        updated_at="2026-04-21T00:00:00Z",
        keys=[
            TrustedKey(
                key_id="scout-fingerprint-key-v1",
                algorithm="ed25519",
                public_key_pem=pem,
                issued_at="2026-04-21T00:00:00Z",
                authorized_for=["domain_fingerprints"],
            )
        ],
    )
    fp_path = tmp_path / "fp.json"
    _signed_file(
        fp_path,
        priv,
        fingerprints={"c.example": {}},
        tamper_hash=True,
    )
    with pytest.raises(HashMismatchError):
        load_fingerprints(fp_path, trust_store=ts)
