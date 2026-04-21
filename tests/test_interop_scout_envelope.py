"""Scout-shaped envelope interop: inline signing (cryptography only) + Intel verification.

Reproduces Sweeps_Scout's canonical JSON + Ed25519 signing without importing Scout,
then verifies via Intel's ``verify_envelope`` and ``load_fingerprints``.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from intel._signing import (
    HashMismatchError,
    SignatureVerificationError,
    UnauthorizedArtifactError,
    UntrustedKeyError,
    canonical_payload_bytes,
    compute_payload_hash_hex,
    verify_envelope,
)
from intel._trust_store import TrustedKey, TrustStore
from intel.scout_fingerprint_loader import load_fingerprints


KEY_ID = "scout-fingerprint-key-v1"


def _pem(pub) -> str:
    return (
        pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
        .strip()
    )


def _sign_envelope_scout_style(
    priv: Ed25519PrivateKey,
    payload: dict,
    *,
    key_id: str = KEY_ID,
) -> dict:
    """Canonicalize like Scout, sign canonical bytes, hash SHA-256 hex, base64url no padding."""
    canonical = canonical_payload_bytes(payload)
    digest_hex = compute_payload_hash_hex(canonical)
    sig = priv.sign(canonical)
    sig_b64 = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")
    signed_at = datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "payload": payload,
        "signature": {
            "algorithm": "ed25519",
            "key_id": key_id,
            "signed_at": signed_at,
            "payload_hash_sha256": digest_hex,
            "signature_b64": sig_b64,
        },
    }


def _trust_store_for(pub_pem: str) -> TrustStore:
    return TrustStore(
        schema_version=1,
        updated_at="2026-04-21T00:00:00Z",
        keys=[
            TrustedKey(
                key_id=KEY_ID,
                algorithm="ed25519",
                public_key_pem=pub_pem,
                issued_at="2026-04-21T00:00:00Z",
                authorized_for=["domain_fingerprints"],
            )
        ],
    )


@pytest.fixture
def keypair() -> tuple[Ed25519PrivateKey, str]:
    priv = Ed25519PrivateKey.generate()
    return priv, _pem(priv.public_key())


@pytest.fixture
def sample_payload() -> dict:
    return {
        "artifact_type": "domain_fingerprints",
        "generated_at": "2026-04-21T12:00:00Z",
        "fingerprints": {
            "example.com": {"sans": ["example.com"]},
            "iana.org": {"sans": ["iana.org"]},
        },
    }


def test_happy_path_load_fingerprints_and_verify_envelope(
    tmp_path: Path,
    keypair: tuple[Ed25519PrivateKey, str],
    sample_payload: dict,
) -> None:
    priv, pem = keypair
    ts = _trust_store_for(pem)
    envelope = _sign_envelope_scout_style(priv, sample_payload)
    path = tmp_path / "domain_fingerprints.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")

    fps = load_fingerprints(
        path,
        trust_store=ts,
        require_signed=True,
        expected_key_id=KEY_ID,
    )
    assert set(fps.keys()) == {"example.com", "iana.org"}
    assert fps["example.com"]["domain"] == "example.com"

    assert verify_envelope(envelope, ts, expected_artifact_type="domain_fingerprints") == sample_payload


def test_tampered_payload_after_signing_raises(
    tmp_path: Path,
    keypair: tuple[Ed25519PrivateKey, str],
    sample_payload: dict,
) -> None:
    priv, pem = keypair
    ts = _trust_store_for(pem)
    envelope = _sign_envelope_scout_style(priv, sample_payload)
    path = tmp_path / "domain_fingerprints.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")

    data = json.loads(path.read_text(encoding="utf-8"))
    fp = data["payload"]["fingerprints"]["example.com"]
    fp["sans"] = ["tampered.example"]
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(HashMismatchError, match="payload_hash_sha256 mismatch"):
        load_fingerprints(
            path,
            trust_store=ts,
            require_signed=True,
            expected_key_id=KEY_ID,
        )


def test_untrusted_key_id_in_verify_envelope(
    keypair: tuple[Ed25519PrivateKey, str],
    sample_payload: dict,
) -> None:
    priv, pem = keypair
    ts = _trust_store_for(pem)
    envelope = _sign_envelope_scout_style(priv, sample_payload, key_id="other-key-id")
    with pytest.raises(UntrustedKeyError, match="other-key-id"):
        verify_envelope(envelope, ts, expected_artifact_type="domain_fingerprints")


def test_wrong_artifact_type_unauthorized(
    keypair: tuple[Ed25519PrivateKey, str],
    sample_payload: dict,
) -> None:
    priv, pem = keypair
    ts = _trust_store_for(pem)
    envelope = _sign_envelope_scout_style(priv, sample_payload)
    with pytest.raises(UnauthorizedArtifactError, match="intel_snapshot"):
        verify_envelope(envelope, ts, expected_artifact_type="intel_snapshot")


def test_load_fingerprints_wrong_key_id_raises_before_verify(
    tmp_path: Path,
    keypair: tuple[Ed25519PrivateKey, str],
    sample_payload: dict,
) -> None:
    """Envelope key_id mismatch vs expected_key_id (loader policy)."""
    priv, pem = keypair
    ts = _trust_store_for(pem)
    envelope = _sign_envelope_scout_style(priv, sample_payload, key_id="wrong-key")
    path = tmp_path / "domain_fingerprints.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")

    with pytest.raises(SignatureVerificationError, match="does not match expected"):
        load_fingerprints(
            path,
            trust_store=ts,
            require_signed=True,
            expected_key_id=KEY_ID,
        )
