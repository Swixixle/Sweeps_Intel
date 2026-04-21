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


def test_shared_mx_emitted_despite_dns_partial_when_mx_populated() -> None:
    """Chumba/Luckyland-style: TLS/DNS partial but MX lists complete and overlapping."""
    fps = {
        "chumbacasino.com": {
            "domain": "chumbacasino.com",
            "sans": [],
            "nameservers": ["ns-1.awsdns.net"],
            "mx": [
                {"host": "mxa-008f4801.gslb.pphosted.com", "priority": 10},
                {"host": "mxb-008f4801.gslb.pphosted.com", "priority": 10},
            ],
            "tls_partial": True,
            "dns_partial": True,
        },
        "luckylandslots.com": {
            "domain": "luckylandslots.com",
            "sans": [],
            "nameservers": ["ns-2.awsdns.net"],
            "mx": [
                {"host": "mxa-008f4801.gslb.pphosted.com", "priority": 10},
                {"host": "mxb-008f4801.gslb.pphosted.com", "priority": 10},
            ],
            "tls_partial": True,
            "dns_partial": True,
        },
    }
    pairs = list(iter_signal_pairs(fps))
    mx_pairs = [p for p in pairs if p[2] == "shared_mx_filtered"]
    assert len(mx_pairs) == 1
    assert mx_pairs[0][3]["shared_mx_hosts"] == [
        "mxa-008f4801.gslb.pphosted.com",
        "mxb-008f4801.gslb.pphosted.com",
    ]
    assert not any(p[2].startswith("tls_san") for p in pairs)


def test_no_shared_mx_when_one_side_missing_mx() -> None:
    fps = {
        "a.example": {
            "nameservers": ["ns1.x.example"],
            "mx": [{"host": "mx.only.com", "priority": 1}],
            "dns_partial": True,
        },
        "b.example": {
            "nameservers": ["ns1.x.example"],
            "mx": [],
            "dns_partial": True,
        },
    }
    pairs = list(iter_signal_pairs(fps))
    assert not any(p[2] == "shared_mx_filtered" for p in pairs)


def test_shared_nameserver_only_when_mx_empty() -> None:
    fps = {
        "a.example": {
            "nameservers": ["ns1.rare-corp.example"],
            "mx": [],
            "dns_partial": True,
        },
        "d.example": {
            "nameservers": ["ns1.rare-corp.example"],
            "mx": [],
            "dns_partial": True,
        },
    }
    pairs = list(iter_signal_pairs(fps))
    assert any(p[2] == "shared_nameserver_filtered" for p in pairs)
    assert not any(p[2] == "shared_mx_filtered" for p in pairs)


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
