"""Tests for Intel signing helpers in ``intel._signing``."""

from __future__ import annotations

import base64
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from intel._signing import (
    CanonicalizationError,
    SigningError,
    SigningKeyError,
    VerificationError,
    canonical_payload_bytes,
    compute_payload_hash_hex,
    generate_keypair,
    load_private_key_pem,
    sign_envelope,
    verify_envelope,
)
from intel._trust_store import TrustedKey, TrustStore


def test_sign_envelope_roundtrip_verify_envelope() -> None:
    priv = Ed25519PrivateKey.generate()
    pub_pem = (
        priv.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
        .strip()
    )
    payload = {"artifact_type": "intel_snapshot", "generated_at": "2026-04-21T00:00:00Z", "x": 1}
    env = sign_envelope(payload, priv, "intel-snapshot-key-v1")
    assert set(env.keys()) == {"payload", "signature"}
    sig = env["signature"]
    assert sig["algorithm"] == "ed25519"
    assert sig["key_id"] == "intel-snapshot-key-v1"
    assert len(sig["payload_hash_sha256"]) == 64
    assert sig["signature_b64"]
    assert "signed_at" in sig

    ts = TrustStore(
        schema_version=1,
        updated_at="2026-04-21T00:00:00Z",
        keys=[
            TrustedKey(
                key_id="intel-snapshot-key-v1",
                algorithm="ed25519",
                public_key_pem=pub_pem,
                issued_at="2026-04-21T00:00:00Z",
                authorized_for=["intel_snapshot"],
            )
        ],
    )
    out = verify_envelope(env, ts, expected_artifact_type="intel_snapshot")
    assert out == payload


def test_sign_envelope_byte_compatible_with_scout_inline_envelope() -> None:
    """Same canonical bytes + Ed25519 as manual Scout-style construction (fixed time)."""
    priv = Ed25519PrivateKey.generate()
    key_id = "scout-fingerprint-key-v1"
    payload = {"artifact_type": "domain_fingerprints", "fingerprints": {}}
    fixed = datetime(2026, 4, 21, 12, 0, 0, tzinfo=timezone.utc)
    with patch("intel._signing.datetime") as mock_dt:
        mock_dt.now.return_value = fixed
        mock_dt.timezone = timezone
        env_intel = sign_envelope(payload, priv, key_id)

    canonical = canonical_payload_bytes(payload)
    digest_hex = compute_payload_hash_hex(canonical)
    sig = priv.sign(canonical)
    sig_b64 = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")
    signed_at = fixed.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    env_manual = {
        "payload": payload,
        "signature": {
            "algorithm": "ed25519",
            "key_id": key_id,
            "signed_at": signed_at,
            "payload_hash_sha256": digest_hex,
            "signature_b64": sig_b64,
        },
    }
    assert env_intel == env_manual


def test_two_keys_different_signatures_same_payload() -> None:
    p1 = Ed25519PrivateKey.generate()
    p2 = Ed25519PrivateKey.generate()
    payload = {"k": "v"}
    e1 = sign_envelope(payload, p1, "k1")
    e2 = sign_envelope(payload, p2, "k1")
    assert e1["signature"]["signature_b64"] != e2["signature"]["signature_b64"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_generate_keypair_private_pem_mode_0600(tmp_path: Path) -> None:
    priv_path, pub_path = generate_keypair(tmp_path / "kp")
    assert priv_path.stat().st_mode & 0o777 == 0o600
    assert pub_path.is_file()
    load_private_key_pem(priv_path)


def test_load_private_key_pem_missing(tmp_path: Path) -> None:
    with pytest.raises(SigningKeyError, match="not found"):
        load_private_key_pem(tmp_path / "nope.pem")


def test_load_private_key_pem_malformed(tmp_path: Path) -> None:
    p = tmp_path / "bad.pem"
    p.write_text("not pem", encoding="utf-8")
    with pytest.raises(SigningKeyError, match="invalid PEM"):
        load_private_key_pem(p)


def test_load_private_key_pem_empty(tmp_path: Path) -> None:
    p = tmp_path / "empty.pem"
    p.write_bytes(b"")
    with pytest.raises(SigningKeyError, match="empty"):
        load_private_key_pem(p)


def test_load_private_key_pem_rsa_not_ed25519(tmp_path: Path) -> None:
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    p = tmp_path / "rsa.pem"
    p.write_bytes(pem)
    with pytest.raises(SigningKeyError, match="expected Ed25519PrivateKey"):
        load_private_key_pem(p)


def test_signing_and_verification_hierarchies_distinct() -> None:
    assert not issubclass(SigningError, VerificationError)
    assert not issubclass(VerificationError, SigningError)
    assert not isinstance(SigningError(), VerificationError)
    assert not isinstance(VerificationError(), SigningError)


def test_canonicalization_error_non_serializable() -> None:
    priv = Ed25519PrivateKey.generate()
    bad = {"x": object()}
    with pytest.raises(CanonicalizationError, match="canonicalize"):
        sign_envelope(bad, priv, "k")
