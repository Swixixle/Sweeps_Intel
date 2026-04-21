from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "trust_store_entry.py"

SAMPLE_PEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAEsbRXMkmRD5UYp47ToCO2HQyXx6KFluHFNRxdcMhpkM=\n-----END PUBLIC KEY-----\n"
_ISSUED_AT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )


def test_happy_path_json_and_roundtrip_pem(tmp_path: Path) -> None:
    pem = tmp_path / "public.pem"
    pem.write_text(SAMPLE_PEM, encoding="utf-8")
    cp = _run(
        "--pem",
        str(pem),
        "--key-id",
        "intel-snapshot-key-v1",
        "--authorized-for",
        "intel_snapshot",
    )
    assert cp.returncode == 0, cp.stderr
    out = json.loads(cp.stdout)
    assert out["algorithm"] == "ed25519"
    assert out["authorized_for"] == ["intel_snapshot"]
    assert _ISSUED_AT_RE.match(out["issued_at"])
    pem_rt = out["public_key_pem"]
    assert "-----BEGIN PUBLIC KEY-----" in pem_rt
    assert "-----END PUBLIC KEY-----" in pem_rt
    assert "MCowBQYDK2VwAyEAEsbRXMkmRD5UYp47ToCO2HQyXx6KFluHFNRxdcMhpkM=" in pem_rt
    assert out["revoked_at"] is None
    assert out["revocation_reason"] is None


def test_missing_pem_exit_stderr_path(tmp_path: Path) -> None:
    missing = tmp_path / "nope.pem"
    cp = _run("--pem", str(missing), "--key-id", "k", "--authorized-for", "x")
    assert cp.returncode == 1
    assert str(missing) in cp.stderr


def test_non_pem_public_key_stderr(tmp_path: Path) -> None:
    bad = tmp_path / "bad.pem"
    bad.write_text("hello world not a pem", encoding="utf-8")
    cp = _run("--pem", str(bad), "--key-id", "k", "--authorized-for", "x")
    assert cp.returncode == 1
    assert "not a pem public key" in cp.stderr.lower()


def test_multiple_authorized_for_list(tmp_path: Path) -> None:
    pem = tmp_path / "public.pem"
    pem.write_text(SAMPLE_PEM, encoding="utf-8")
    cp = _run(
        "--pem",
        str(pem),
        "--key-id",
        "intel-blocklist-key-v1",
        "--authorized-for",
        "intel_block_candidates",
        "intel_snapshot",
    )
    assert cp.returncode == 0
    out = json.loads(cp.stdout)
    assert out["authorized_for"] == ["intel_block_candidates", "intel_snapshot"]


def test_issued_at_custom_preserved(tmp_path: Path) -> None:
    pem = tmp_path / "public.pem"
    pem.write_text(SAMPLE_PEM, encoding="utf-8")
    custom = "2026-04-21T00:00:00Z"
    cp = _run(
        "--pem",
        str(pem),
        "--key-id",
        "intel-blocklist-key-v1",
        "--authorized-for",
        "intel_block_candidates",
        "--issued-at",
        custom,
    )
    assert cp.returncode == 0
    out = json.loads(cp.stdout)
    assert out["issued_at"] == custom


@pytest.mark.skipif(
    not (REPO_ROOT / "keys" / "snapshot" / "public.pem").is_file(),
    reason="no keys/snapshot/public.pem",
)
def test_sample_against_repo_keys_public_pem() -> None:
    pem = REPO_ROOT / "keys" / "snapshot" / "public.pem"
    cp = _run(
        "--pem",
        str(pem),
        "--key-id",
        "intel-snapshot-key-v1",
        "--authorized-for",
        "intel_snapshot",
    )
    assert cp.returncode == 0, cp.stderr
    json.loads(cp.stdout)
