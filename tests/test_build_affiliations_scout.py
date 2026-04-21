"""Tests for ``build_affiliations_from_scout_fingerprints`` trust-store wiring."""

from __future__ import annotations

import base64
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from intel._signing import canonical_payload_bytes, compute_payload_hash_hex
from intel._trust_store import load_trust_store
from intel.affiliations import build_affiliations_from_scout_fingerprints


def _pem(pub) -> str:
    return (
        pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
        .strip()
    )


def _write_signed(
    path: Path,
    priv: Ed25519PrivateKey,
    fingerprints: dict,
) -> None:
    inner = {"fingerprints": fingerprints}
    canonical = canonical_payload_bytes(inner)
    h = compute_payload_hash_hex(canonical)
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


def test_build_affiliations_unsigned_backward_compat(tmp_path: Path) -> None:
    p = tmp_path / "fp.json"
    p.write_text(
        json.dumps(
            {
                "a.example": {"nameservers": ["ns1.rare.example"]},
                "b.example": {"nameservers": ["ns1.rare.example"]},
            }
        ),
        encoding="utf-8",
    )
    aff = build_affiliations_from_scout_fingerprints(p)
    assert len(aff) >= 1


def test_build_affiliations_signed_with_trust_no_unverified_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger="intel.scout_fingerprint_loader")
    priv = Ed25519PrivateKey.generate()
    pem = _pem(priv.public_key())
    fp = tmp_path / "domain_fingerprints.json"
    _write_signed(
        fp,
        priv,
        {
            "a.example": {"nameservers": ["ns1.rare.example"]},
            "b.example": {"nameservers": ["ns1.rare.example"]},
        },
    )
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
    ts = load_trust_store(ts_path)
    aff = build_affiliations_from_scout_fingerprints(fp, trust_store=ts, require_signed=True)
    assert aff
    assert "unverified" not in caplog.text.lower(), caplog.text
