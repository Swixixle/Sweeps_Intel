from __future__ import annotations

import json
from pathlib import Path

from intel.affiliations import build_affiliations_from_scout_fingerprints
from intel.cluster import run_cluster
from intel.scout_fingerprint_loader import iter_signal_pairs, load_fingerprints


def test_scout_fingerprints_cluster_reciprocal_only_and_affiliations(tmp_path: Path) -> None:
    scout_dir = tmp_path / "data" / "research_candidates" / "scout_import"
    scout_dir.mkdir(parents=True)
    fp_path = scout_dir / "domain_fingerprints.json"
    doc = {
        "alpha.example": {"sans": ["alpha.example", "beta.example"]},
        "beta.example": {"sans": ["beta.example", "alpha.example"]},
        "gamma.example": {"nameservers": ["ns1.rare-corp.example"]},
        "delta.example": {"nameservers": ["ns1.rare-corp.example"]},
        "epsilon.example": {"nameservers": ["dana.ns.cloudflare.com"]},
        "zeta.example": {"nameservers": ["igor.ns.cloudflare.com"]},
    }
    fp_path.write_text(json.dumps(doc), encoding="utf-8")

    fps = load_fingerprints(fp_path)
    pairs = list(iter_signal_pairs(fps))
    assert any(p[2] == "tls_san_reciprocal" and p[0] == "alpha.example" for p in pairs)
    assert any(p[2] == "shared_nameserver_filtered" for p in pairs)
    assert not any(p[2] == "shared_nameserver_filtered" and "epsilon" in (p[0], p[1]) for p in pairs)

    aff = build_affiliations_from_scout_fingerprints(fp_path)
    assert any({a.left_id, a.right_id} == {"gamma.example", "delta.example"} for a in aff)
    assert not any(
        (a.left_id, a.right_id) in {("epsilon.example", "zeta.example"), ("zeta.example", "epsilon.example")}
        for a in aff
    )

    out = run_cluster(tmp_path, min_script_overlap=2)
    staged = Path(out["output"])
    data = json.loads(staged.read_text(encoding="utf-8"))
    clusters = data.get("clusters") or []
    assert any(
        "alpha.example" in cl.get("members", []) and "beta.example" in cl.get("members", []) for cl in clusters
    )
    assert not any(
        "gamma.example" in cl.get("members", []) and "delta.example" in cl.get("members", []) for cl in clusters
    )
