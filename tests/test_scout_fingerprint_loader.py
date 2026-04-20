from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from intel.scout_fingerprint_loader import iter_signal_pairs, load_fingerprints


def test_load_missing_file_warns(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="intel.scout_fingerprint_loader")
    p = tmp_path / "nope.json"
    assert load_fingerprints(p) == {}
    assert "missing" in caplog.text.lower() or "file missing" in caplog.text.lower()


def test_load_malformed_json(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="intel.scout_fingerprint_loader")
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    assert load_fingerprints(p) == {}
    assert "invalid json" in caplog.text.lower() or "json" in caplog.text.lower()


def test_tls_san_reciprocal(tmp_path: Path) -> None:
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
    pairs = list(iter_signal_pairs(fps))
    assert any(x[:3] == ("alpha.example", "beta.example", "tls_san_reciprocal") for x in pairs)


def test_tls_san_one_way(tmp_path: Path) -> None:
    p = tmp_path / "fp.json"
    p.write_text(
        json.dumps(
            {
                "a.example": {"sans": ["a.example", "b.example"]},
                "b.example": {"sans": ["b.example"]},
            }
        ),
        encoding="utf-8",
    )
    fps = load_fingerprints(p)
    pairs = list(iter_signal_pairs(fps))
    assert any(x[2] == "tls_san_one_way" for x in pairs)
    assert not any(x[2] == "tls_san_reciprocal" for x in pairs)


def test_shared_nameserver_filtered(tmp_path: Path) -> None:
    p = tmp_path / "fp.json"
    p.write_text(
        json.dumps(
            {
                "g.example": {"nameservers": ["ns1.rare-corp.example"]},
                "d.example": {"nameservers": ["ns1.rare-corp.example"]},
            }
        ),
        encoding="utf-8",
    )
    fps = load_fingerprints(p)
    pairs = list(iter_signal_pairs(fps))
    ns_pairs = [x for x in pairs if x[2] == "shared_nameserver_filtered"]
    assert len(ns_pairs) == 1
    assert ns_pairs[0][3]["shared_nameservers"] == ["ns1.rare-corp.example"]


def test_denylisted_nameserver_not_emitted(tmp_path: Path) -> None:
    p = tmp_path / "fp.json"
    p.write_text(
        json.dumps(
            {
                "e.example": {"nameservers": ["dana.ns.cloudflare.com"]},
                "z.example": {"nameservers": ["igor.ns.cloudflare.com"]},
            }
        ),
        encoding="utf-8",
    )
    fps = load_fingerprints(p)
    pairs = list(iter_signal_pairs(fps))
    assert not any(x[2] == "shared_nameserver_filtered" for x in pairs)


def test_tls_partial_skips_tls_signals(tmp_path: Path) -> None:
    p = tmp_path / "fp.json"
    p.write_text(
        json.dumps(
            {
                "a.example": {"sans": ["a.example", "b.example"], "partial": True},
                "b.example": {"sans": ["b.example", "a.example"]},
            }
        ),
        encoding="utf-8",
    )
    fps = load_fingerprints(p)
    pairs = list(iter_signal_pairs(fps))
    assert not any("tls_san" in x[2] for x in pairs)
