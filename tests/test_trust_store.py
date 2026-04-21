"""Tests for ``intel._trust_store``."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from intel._signing import TrustStoreError
from intel._trust_store import TrustedKey, TrustStore, load_trust_store


def test_load_happy_path(tmp_path: Path) -> None:
    p = tmp_path / "ts.json"
    p.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "updated_at": "2026-04-21T00:00:00Z",
                "keys": [
                    {
                        "key_id": "k1",
                        "algorithm": "ed25519",
                        "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----",
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
    ts = load_trust_store(p)
    assert ts.schema_version == 1
    assert len(ts.keys) == 1
    assert ts.keys[0].key_id == "k1"


def test_missing_file(tmp_path: Path) -> None:
    p = tmp_path / "nope.json"
    with pytest.raises(TrustStoreError, match="not found"):
        load_trust_store(p)


def test_malformed_json(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text("{", encoding="utf-8")
    with pytest.raises(TrustStoreError, match="invalid JSON"):
        load_trust_store(p)


def test_keys_not_array(tmp_path: Path) -> None:
    p = tmp_path / "ts.json"
    p.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "updated_at": "2026-04-21T00:00:00Z",
                "keys": "not-a-list",
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(TrustStoreError, match="keys must be an array"):
        load_trust_store(p)


def test_missing_required_field(tmp_path: Path) -> None:
    p = tmp_path / "ts.json"
    p.write_text(
        json.dumps({"schema_version": 1, "updated_at": "2026-04-21T00:00:00Z"}),
        encoding="utf-8",
    )
    with pytest.raises(TrustStoreError, match="missing required field"):
        load_trust_store(p)


def test_get_key_found_and_not_found() -> None:
    k = TrustedKey(
        key_id="scout-fingerprint-key-v1",
        algorithm="ed25519",
        public_key_pem="pem",
        issued_at="2026-04-21T00:00:00Z",
        authorized_for=["domain_fingerprints"],
    )
    ts = TrustStore(schema_version=1, updated_at="2026-04-21T00:00:00Z", keys=[k])
    assert ts.get_key("scout-fingerprint-key-v1") is k
    assert ts.get_key("other") is None


def test_is_revoked() -> None:
    active = TrustedKey(
        key_id="a",
        algorithm="ed25519",
        public_key_pem="pem",
        issued_at="2026-04-21T00:00:00Z",
        authorized_for=["x"],
        revoked_at=None,
    )
    assert active.is_revoked() is False
    revoked = TrustedKey(
        key_id="b",
        algorithm="ed25519",
        public_key_pem="pem",
        issued_at="2026-04-21T00:00:00Z",
        authorized_for=["x"],
        revoked_at="2026-04-22T00:00:00Z",
    )
    assert revoked.is_revoked() is True
