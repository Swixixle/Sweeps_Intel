"""Trust store: JSON file listing Ed25519 public keys Intel trusts for verification."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._signing import TrustStoreError


@dataclass
class TrustedKey:
    key_id: str
    algorithm: str
    public_key_pem: str
    issued_at: str
    authorized_for: list[str]
    revoked_at: str | None = None
    revocation_reason: str | None = None

    def is_revoked(self) -> bool:
        return self.revoked_at is not None


@dataclass
class TrustStore:
    schema_version: int
    updated_at: str
    keys: list[TrustedKey] = field(default_factory=list)

    def get_key(self, key_id: str) -> TrustedKey | None:
        for k in self.keys:
            if k.key_id == key_id:
                return k
        return None


def _require_str(d: dict[str, Any], key: str, ctx: str) -> str:
    v = d.get(key)
    if not isinstance(v, str) or not v.strip():
        raise ValueError(f"{ctx}: missing or invalid string field {key!r}")
    return v


def _require_str_list(d: dict[str, Any], key: str, ctx: str) -> list[str]:
    v = d.get(key)
    if not isinstance(v, list):
        raise ValueError(f"{ctx}: field {key!r} must be a list")
    out: list[str] = []
    for i, x in enumerate(v):
        if not isinstance(x, str):
            raise ValueError(f"{ctx}: {key!r}[{i}] must be a string")
        out.append(x)
    return out


def _parse_trusted_key(raw: Any, idx: int) -> TrustedKey:
    ctx = f"keys[{idx}]"
    if not isinstance(raw, dict):
        raise ValueError(f"{ctx}: must be an object")
    d = raw
    key_id = _require_str(d, "key_id", ctx)
    algorithm = _require_str(d, "algorithm", ctx)
    public_key_pem = _require_str(d, "public_key_pem", ctx)
    issued_at = _require_str(d, "issued_at", ctx)
    authorized_for = _require_str_list(d, "authorized_for", ctx)
    revoked_at = d.get("revoked_at")
    if revoked_at is not None and not isinstance(revoked_at, str):
        raise ValueError(f"{ctx}: revoked_at must be a string or null")
    revocation_reason = d.get("revocation_reason")
    if revocation_reason is not None and not isinstance(revocation_reason, str):
        raise ValueError(f"{ctx}: revocation_reason must be a string or null")
    return TrustedKey(
        key_id=key_id,
        algorithm=algorithm,
        public_key_pem=public_key_pem,
        issued_at=issued_at,
        authorized_for=authorized_for,
        revoked_at=revoked_at,
        revocation_reason=revocation_reason,
    )


def load_trust_store(path: Path) -> TrustStore:
    """Load and validate a trust store JSON file per ``docs/SIGNING.md``."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as e:
        raise TrustStoreError(f"trust store file not found: {path}") from e
    except OSError as e:
        raise TrustStoreError(f"cannot read trust store {path}: {e}") from e

    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        raise TrustStoreError(f"invalid JSON in trust store {path}: {e}") from e

    if not isinstance(doc, dict):
        raise TrustStoreError(f"trust store root must be an object, got {type(doc).__name__}")

    try:
        sv = doc["schema_version"]
        if not isinstance(sv, int):
            raise ValueError("schema_version must be an integer")
        updated_at = _require_str(doc, "updated_at", "trust_store")
        raw_keys = doc["keys"]
        if not isinstance(raw_keys, list):
            raise ValueError("keys must be an array")
        keys = [_parse_trusted_key(x, i) for i, x in enumerate(raw_keys)]
    except KeyError as e:
        raise TrustStoreError(f"trust store {path} missing required field: {e.args[0]!r}") from e
    except ValueError as e:
        raise TrustStoreError(str(e)) from e

    return TrustStore(schema_version=sv, updated_at=updated_at, keys=keys)
