"""Tests for optional signing in ``intel.exporters``."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from intel._signing import SigningKeyError, verify_envelope
from intel._trust_store import TrustedKey, TrustStore
from intel.exporters import run_export


def _write_min_normalized(norm: Path) -> None:
    norm.mkdir(parents=True, exist_ok=True)
    (norm / "entities.json").write_text("[]", encoding="utf-8")
    (norm / "fingerprints.json").write_text("[]", encoding="utf-8")
    (norm / "relationships.json").write_text("[]", encoding="utf-8")


def _trust_for_snapshot(pub_pem: str) -> TrustStore:
    return TrustStore(
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


def _trust_for_blocklist(pub_pem: str) -> TrustStore:
    return TrustStore(
        schema_version=1,
        updated_at="2026-04-21T00:00:00Z",
        keys=[
            TrustedKey(
                key_id="intel-blocklist-key-v1",
                algorithm="ed25519",
                public_key_pem=pub_pem,
                issued_at="2026-04-21T00:00:00Z",
                authorized_for=["intel_block_candidates"],
            )
        ],
    )


def test_unsigned_backward_compat_bare_dicts(tmp_path: Path) -> None:
    norm = tmp_path / "normalized"
    pub = tmp_path / "published"
    _write_min_normalized(norm)
    run_export(tmp_path, norm, pub)
    snap = json.loads((pub / "intel_snapshot.json").read_text(encoding="utf-8"))
    blk = json.loads((pub / "block_candidates.json").read_text(encoding="utf-8"))
    assert "payload" not in snap
    assert "artifact_type" not in snap
    assert "payload" not in blk
    assert "artifact_type" not in blk
    assert "entities" in snap
    assert "domains" in blk


def test_signed_snapshot_envelope_verifies(tmp_path: Path) -> None:
    from intel._signing import generate_keypair

    norm = tmp_path / "normalized"
    pub = tmp_path / "published"
    _write_min_normalized(norm)
    _, pub_path = generate_keypair(tmp_path / "keys" / "snapshot")
    pub_pem = pub_path.read_text(encoding="utf-8").strip()

    run_export(
        tmp_path,
        norm,
        pub,
        sign_snapshot=True,
        snapshot_private_key_path=tmp_path / "keys" / "snapshot" / "private.pem",
    )

    raw = json.loads((pub / "intel_snapshot.json").read_text(encoding="utf-8"))
    assert "payload" in raw and "signature" in raw
    ts = _trust_for_snapshot(pub_pem)
    inner = verify_envelope(raw, ts, expected_artifact_type="intel_snapshot")
    assert inner["artifact_type"] == "intel_snapshot"
    assert "entities" in inner


def test_signed_blocklist_envelope_verifies(tmp_path: Path) -> None:
    from intel._signing import generate_keypair

    norm = tmp_path / "normalized"
    pub = tmp_path / "published"
    _write_min_normalized(norm)
    _, pub_path = generate_keypair(tmp_path / "keys" / "blocklist")
    pub_pem = pub_path.read_text(encoding="utf-8").strip()

    run_export(
        tmp_path,
        norm,
        pub,
        sign_blocklist=True,
        blocklist_private_key_path=tmp_path / "keys" / "blocklist" / "private.pem",
    )

    raw = json.loads((pub / "block_candidates.json").read_text(encoding="utf-8"))
    assert "payload" in raw and "signature" in raw
    ts = _trust_for_blocklist(pub_pem)
    inner = verify_envelope(raw, ts, expected_artifact_type="intel_block_candidates")
    assert inner["artifact_type"] == "intel_block_candidates"
    assert "domains" in inner


def test_sign_snapshot_without_key_raises(tmp_path: Path) -> None:
    norm = tmp_path / "normalized"
    pub = tmp_path / "published"
    _write_min_normalized(norm)
    with pytest.raises(SigningKeyError, match="snapshot_private_key_path"):
        run_export(tmp_path, norm, pub, sign_snapshot=True)


def test_sign_blocklist_without_key_raises(tmp_path: Path) -> None:
    norm = tmp_path / "normalized"
    pub = tmp_path / "published"
    _write_min_normalized(norm)
    with pytest.raises(SigningKeyError, match="blocklist_private_key_path"):
        run_export(tmp_path, norm, pub, sign_blocklist=True)


def test_independent_signing_snapshot_only(tmp_path: Path) -> None:
    from intel._signing import generate_keypair

    norm = tmp_path / "normalized"
    pub = tmp_path / "published"
    _write_min_normalized(norm)
    generate_keypair(tmp_path / "keys" / "snapshot")

    run_export(
        tmp_path,
        norm,
        pub,
        sign_snapshot=True,
        snapshot_private_key_path=tmp_path / "keys" / "snapshot" / "private.pem",
        sign_blocklist=False,
    )

    snap = json.loads((pub / "intel_snapshot.json").read_text(encoding="utf-8"))
    blk = json.loads((pub / "block_candidates.json").read_text(encoding="utf-8"))
    assert "payload" in snap
    assert "payload" not in blk
    assert "artifact_type" not in blk


def test_independent_signing_blocklist_only(tmp_path: Path) -> None:
    from intel._signing import generate_keypair

    norm = tmp_path / "normalized"
    pub = tmp_path / "published"
    _write_min_normalized(norm)
    generate_keypair(tmp_path / "keys" / "blocklist")

    run_export(
        tmp_path,
        norm,
        pub,
        sign_snapshot=False,
        sign_blocklist=True,
        blocklist_private_key_path=tmp_path / "keys" / "blocklist" / "private.pem",
    )

    snap = json.loads((pub / "intel_snapshot.json").read_text(encoding="utf-8"))
    blk = json.loads((pub / "block_candidates.json").read_text(encoding="utf-8"))
    assert "payload" not in snap
    assert "payload" in blk
    assert "artifact_type" not in snap
