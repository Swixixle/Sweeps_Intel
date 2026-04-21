"""Ed25519 signature verification for signed JSON envelopes (see ``docs/SIGNING.md``)."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

if TYPE_CHECKING:
    from ._trust_store import TrustStore

logger = logging.getLogger(__name__)


class VerificationError(Exception):
    """Base class for trust and signature verification failures."""

    pass


class VerificationKeyError(VerificationError):
    """Public key loading or trust configuration failed."""

    pass


class TrustStoreError(VerificationKeyError):
    """Failed to load or parse ``trust_store.json``."""

    pass


class SignatureVerificationError(VerificationError):
    """Signature check failed (envelope shape, algorithm, or cryptographic verify)."""

    pass


class HashMismatchError(SignatureVerificationError):
    """``payload_hash_sha256`` did not match the canonical payload (sanity check)."""

    pass


class EnvelopeShapeError(SignatureVerificationError):
    """Malformed envelope (missing keys or wrong types)."""

    pass


class UntrustedKeyError(SignatureVerificationError):
    """``key_id`` is not present in the trust store."""

    pass


class RevokedKeyError(SignatureVerificationError):
    """The signing key is revoked in the trust store."""

    pass


class UnauthorizedArtifactError(SignatureVerificationError):
    """Key is not authorized for this artifact type."""

    pass


def canonical_payload_bytes(payload: dict[str, Any]) -> bytes:
    """Return UTF-8 bytes of canonical JSON for ``payload`` (must match Scout byte-for-byte)."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def compute_payload_hash_hex(canonical_bytes: bytes) -> str:
    """SHA-256 hex digest of canonical payload bytes."""
    return hashlib.sha256(canonical_bytes).hexdigest()


def decode_base64url(s: str) -> bytes:
    """Decode base64url (RFC 4648), re-adding ``=`` padding when missing."""
    t = s.strip()
    pad = (-len(t)) % 4
    return base64.urlsafe_b64decode(t + ("=" * pad))


def load_public_key_pem(path: Path) -> Ed25519PublicKey:
    """Load an Ed25519 public key from a PEM file."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError as e:
        raise VerificationKeyError(f"public key file not found: {path}") from e
    except OSError as e:
        raise VerificationKeyError(f"cannot read public key file {path}: {e}") from e
    try:
        key = serialization.load_pem_public_key(raw)
    except ValueError as e:
        raise VerificationKeyError(f"invalid PEM public key in {path}: {e}") from e
    if not isinstance(key, Ed25519PublicKey):
        raise VerificationKeyError(
            f"public key in {path} is {type(key).__name__}, expected Ed25519PublicKey"
        )
    return key


def load_public_key_pem_string(pem: str) -> Ed25519PublicKey:
    """Load an Ed25519 public key from PEM text (e.g. trust store entry)."""
    try:
        key = serialization.load_pem_public_key(pem.encode("utf-8"))
    except ValueError as e:
        raise VerificationKeyError(f"invalid PEM public key text: {e}") from e
    if not isinstance(key, Ed25519PublicKey):
        raise VerificationKeyError(
            f"PEM key is {type(key).__name__}, expected Ed25519PublicKey"
        )
    return key


def verify_envelope(
    envelope: dict[str, Any],
    trust_store: TrustStore,
    expected_artifact_type: str | None = None,
) -> dict[str, Any]:
    """Verify a signed envelope and return the inner ``payload`` dict."""
    # Local import avoids circular dependency with _trust_store at module load time.
    from ._trust_store import TrustStore as TrustStoreCls

    if not isinstance(trust_store, TrustStoreCls):
        raise TypeError(f"trust_store must be TrustStore, got {type(trust_store).__name__}")

    if not isinstance(envelope, dict):
        raise EnvelopeShapeError(f"envelope must be a JSON object, got {type(envelope).__name__}")

    payload = envelope.get("payload")
    sig_block = envelope.get("signature")
    if not isinstance(payload, dict):
        raise EnvelopeShapeError(
            'envelope must contain object "payload"; '
            f"got {type(payload).__name__ if payload is not None else 'missing'}"
        )
    if not isinstance(sig_block, dict):
        raise EnvelopeShapeError(
            'envelope must contain object "signature"; '
            f"got {type(sig_block).__name__ if sig_block is not None else 'missing'}"
        )

    algo = sig_block.get("algorithm")
    if algo != "ed25519":
        raise SignatureVerificationError(
            f"unsupported signature algorithm: expected 'ed25519', got {algo!r}"
        )

    key_id = sig_block.get("key_id")
    if not isinstance(key_id, str) or not key_id.strip():
        raise EnvelopeShapeError('signature block missing non-empty string "key_id"')

    trusted = trust_store.get_key(key_id)
    if trusted is None:
        raise UntrustedKeyError(f"key_id {key_id!r} is not in the trust store")

    if trusted.is_revoked():
        reason = trusted.revocation_reason or "no reason given"
        raise RevokedKeyError(
            f"key {key_id!r} is revoked (revoked_at={trusted.revoked_at!r}, reason={reason!r})"
        )

    if expected_artifact_type is not None:
        if expected_artifact_type not in trusted.authorized_for:
            raise UnauthorizedArtifactError(
                f"key {key_id!r} is not authorized for artifact type {expected_artifact_type!r}; "
                f"authorized_for={trusted.authorized_for!r}"
            )

    canonical = canonical_payload_bytes(payload)
    expected_hash = compute_payload_hash_hex(canonical)
    stated_hash = sig_block.get("payload_hash_sha256")
    if not isinstance(stated_hash, str):
        raise EnvelopeShapeError(
            'signature block missing string "payload_hash_sha256" '
            f"(got {type(stated_hash).__name__})"
        )
    if stated_hash != expected_hash:
        raise HashMismatchError(
            f"payload_hash_sha256 mismatch: envelope has {stated_hash!r}, "
            f"canonical payload hashes to {expected_hash!r}"
        )

    sig_b64 = sig_block.get("signature_b64")
    if not isinstance(sig_b64, str) or not sig_b64.strip():
        raise EnvelopeShapeError('signature block missing non-empty string "signature_b64"')

    try:
        sig_bytes = decode_base64url(sig_b64)
    except (ValueError, binascii.Error) as e:
        raise EnvelopeShapeError(f"invalid base64url in signature_b64: {e}") from e

    try:
        pub = load_public_key_pem_string(trusted.public_key_pem)
    except VerificationKeyError as e:
        raise VerificationKeyError(f"trust store public key for {key_id!r}: {e}") from e

    try:
        pub.verify(sig_bytes, canonical)
    except InvalidSignature as e:
        raise SignatureVerificationError(
            f"Ed25519 verification failed for key_id {key_id!r}: signature does not match canonical payload"
        ) from e

    logger.debug("envelope verified: key_id=%s", key_id)
    return payload
