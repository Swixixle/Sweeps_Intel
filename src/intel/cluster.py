"""
Cluster likely-related brands from normalized + staged + extracted data.

Produces human-reviewable clusters with evidence lists. Does not modify
affiliations.py or production seeds.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from intel.schemas import SCHEMA_VERSION
from intel.scout_fingerprint_loader import iter_signal_pairs, load_fingerprints

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _norm_key(s: str | None) -> str:
    if not s or not isinstance(s, str):
        return ""
    t = " ".join(s.lower().split())
    return t.strip()


def _load_json(path: Path) -> Any:
    if not path.is_file():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _entity_primary_domain(ent: dict) -> str:
    doms = ent.get("domains") or []
    if doms and isinstance(doms[0], str):
        return doms[0].lower().strip()
    return ""


def _host_from_url(u: str) -> str:
    try:
        h = (urlparse(u).netloc or "").lower()
        if h.startswith("www."):
            h = h[4:]
        return h.split(":")[0]
    except Exception:
        return ""


def _fingerprint_scripts(fp: dict) -> set[str]:
    tech = fp.get("technical") or {}
    out: set[str] = set()
    for k in ("script_domains", "iframe_domains", "asset_domains"):
        for x in tech.get(k) or []:
            if isinstance(x, str) and x.strip():
                out.add(x.lower().strip())
    return out


class _UnionFind:
    def __init__(self) -> None:
        self._p: dict[str, str] = {}

    def find(self, x: str) -> str:
        self._p.setdefault(x, x)
        if self._p[x] != x:
            self._p[x] = self.find(self._p[x])
        return self._p[x]

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self._p[rb] = ra


def _merge_evidence(
    store: dict[tuple[str, str], list[dict]],
    a: str,
    b: str,
    ev: dict,
) -> None:
    if a > b:
        a, b = b, a
    key = (a, b)
    store.setdefault(key, []).append(ev)


def _load_scout_fingerprint_links(repo_root: Path, link: Callable[..., None]) -> int:
    """DEFINITIVE-only: reciprocal TLS SAN pairs from Scout ``domain_fingerprints.json``."""
    path = repo_root / "data" / "research_candidates" / "scout_import" / "domain_fingerprints.json"
    try:
        fps = load_fingerprints(path)
    except (TypeError, ValueError, OSError) as e:
        logger.warning("scout cluster links: could not load fingerprints from %s: %s", path, e)
        return 0
    n = 0
    try:
        for da, db, sig, detail in iter_signal_pairs(fps):
            if sig == "tls_san_reciprocal":
                link(da, db, "scout_tls_san_reciprocal", detail)
                n += 1
    except (TypeError, ValueError, KeyError) as e:
        logger.warning("scout cluster links: failed while iterating signal pairs: %s", e)
    return n


def run_cluster(
    repo_root: Path | None = None,
    *,
    min_script_overlap: int = 2,
) -> dict[str, Any]:
    root = repo_root or REPO_ROOT
    uf = _UnionFind()
    pair_evidence: dict[tuple[str, str], list[dict]] = defaultdict(list)

    def link(a: str, b: str, reason: str, detail: dict | None = None) -> None:
        if not a or not b or a == b:
            return
        uf.union(a, b)
        ev = {"reason": reason, "detail": detail or {}}
        _merge_evidence(pair_evidence, a, b, ev)

    # Normalized entities + fingerprints
    norm_ent_path = root / "data" / "normalized" / "entities.json"
    norm_fp_path = root / "data" / "normalized" / "fingerprints.json"
    norm_ents = _load_json(norm_ent_path) or []
    norm_fps = _load_json(norm_fp_path) or []

    ent_by_id: dict[str, dict] = {}
    for e in norm_ents:
        if isinstance(e, dict) and e.get("id"):
            ent_by_id[str(e["id"])] = e

    domain_to_scripts: dict[str, set[str]] = {}
    for fp in norm_fps:
        if not isinstance(fp, dict):
            continue
        eid = fp.get("entity_id")
        ent = ent_by_id.get(str(eid)) if eid else None
        if not ent:
            continue
        dom = _entity_primary_domain(ent)
        if not dom:
            continue
        domain_to_scripts[dom] = domain_to_scripts.get(dom, set()) | _fingerprint_scripts(fp)

    # Same legal_entity / parent_company within normalized
    legal_buckets: dict[str, list[str]] = defaultdict(list)
    parent_buckets: dict[str, list[str]] = defaultdict(list)
    for e in norm_ents:
        if not isinstance(e, dict):
            continue
        dom = _entity_primary_domain(e)
        if not dom:
            continue
        attrs = e.get("attributes") or {}
        le = _norm_key(attrs.get("legal_entity") if isinstance(attrs, dict) else None)
        if le:
            legal_buckets[le].append(dom)
        pc = _norm_key(attrs.get("parent_company") if isinstance(attrs, dict) else None)
        if pc:
            parent_buckets[pc].append(dom)

    for _k, doms in legal_buckets.items():
        base = doms[0]
        for d in doms[1:]:
            link(base, d, "same_legal_entity_normalized", {"value": _k})
    for _k, doms in parent_buckets.items():
        base = doms[0]
        for d in doms[1:]:
            link(base, d, "same_parent_company_normalized", {"value": _k})

    # Staged entities (research imports)
    staged_ent_path = root / "data" / "research_candidates" / "staged_entities.json"
    staged_raw = _load_json(staged_ent_path)
    staged_list: list[dict] = []
    if isinstance(staged_raw, dict):
        staged_list = list(staged_raw.get("entities") or [])

    staged_legal: dict[str, list[str]] = defaultdict(list)
    staged_parent: dict[str, list[str]] = defaultdict(list)
    for ent in staged_list:
        if not isinstance(ent, dict):
            continue
        dom = (ent.get("domain") or "").lower().strip()
        if not dom:
            continue
        le = _norm_key(ent.get("legal_entity"))
        pc = _norm_key(ent.get("parent_company"))
        if le:
            staged_legal[le].append(dom)
        if pc:
            staged_parent[pc].append(dom)

    for _k, doms in staged_legal.items():
        if len(doms) < 2:
            continue
        base = doms[0]
        for d in doms[1:]:
            link(base, d, "staged_same_legal_entity", {"legal_entity": _k})

    for _k, doms in staged_parent.items():
        if len(doms) < 2:
            continue
        base = doms[0]
        for d in doms[1:]:
            link(base, d, "staged_same_parent_company", {"parent_company": _k})

    for ent in staged_list:
        if not isinstance(ent, dict):
            continue
        dom = (ent.get("domain") or "").lower().strip()
        if not dom:
            continue
        le = _norm_key(ent.get("legal_entity"))
        pc = _norm_key(ent.get("parent_company"))
        if le:
            for e2 in norm_ents:
                if not isinstance(e2, dict):
                    continue
                d2 = _entity_primary_domain(e2)
                attrs = e2.get("attributes") or {}
                le2 = _norm_key(attrs.get("legal_entity") if isinstance(attrs, dict) else None)
                if le2 and le2 == le and d2:
                    link(dom, d2, "staged_legal_entity_match_normalized", {"legal_entity": le})
        if pc:
            for e2 in norm_ents:
                if not isinstance(e2, dict):
                    continue
                d2 = _entity_primary_domain(e2)
                attrs = e2.get("attributes") or {}
                pc2 = _norm_key(attrs.get("parent_company") if isinstance(attrs, dict) else None)
                if pc2 and pc2 == pc and d2:
                    link(dom, d2, "staged_parent_company_match_normalized", {"parent_company": pc})

    # Pairwise script overlap (normalized domains only)
    doms_sorted = sorted(domain_to_scripts.keys())
    for i, da in enumerate(doms_sorted):
        sa = domain_to_scripts[da]
        if len(sa) < min_script_overlap:
            continue
        for db in doms_sorted[i + 1 :]:
            sb = domain_to_scripts[db]
            inter = len(sa & sb)
            if inter >= min_script_overlap:
                link(
                    da,
                    db,
                    "script_domain_overlap",
                    {"overlap_count": inter, "intersection_sample": sorted(sa & sb)[:15]},
                )

    # Staged relationships (domain hints in raw_row)
    rel_path = root / "data" / "research_candidates" / "staged_relationships.json"
    rel_raw = _load_json(rel_path)
    rel_list: list[dict] = []
    if isinstance(rel_raw, dict):
        rel_list = list(rel_raw.get("relationships") or [])
    domain_re = re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I
    )
    for rel in rel_list:
        if not isinstance(rel, dict):
            continue
        raw = rel.get("raw_row")
        if not isinstance(raw, dict):
            continue
        blob = json.dumps(raw, ensure_ascii=False)
        found = {m.group(0).lower() for m in domain_re.finditer(blob)}
        found.discard("")
        if len(found) >= 2:
            fl = sorted(found)
            base = fl[0]
            for d in fl[1:]:
                link(base, d, "staged_relationship_domain_cooccurrence", {"relationship_type": rel.get("relationship_type")})

    # Extracted fingerprints: shared script domains across extracted entities
    ext_path = root / "data" / "research_candidates" / "extracted_fingerprints.json"
    ext_raw = _load_json(ext_path)
    ext_fps: list[dict] = []
    if isinstance(ext_raw, dict):
        ext_fps = list(ext_raw.get("fingerprints") or [])
    ext_scripts: dict[str, set[str]] = {}
    for fp in ext_fps:
        if not isinstance(fp, dict):
            continue
        dom = (fp.get("domain") or "").lower().strip()
        if not dom:
            continue
        inner = fp.get("fingerprint") if isinstance(fp.get("fingerprint"), dict) else fp
        ext_scripts[dom] = ext_scripts.get(dom, set()) | _fingerprint_scripts(inner)
    ext_doms = sorted(ext_scripts.keys())
    for i, da in enumerate(ext_doms):
        sa = ext_scripts[da]
        if len(sa) < min_script_overlap:
            continue
        for db in ext_doms[i + 1 :]:
            sb = ext_scripts[db]
            if len(sa & sb) >= min_script_overlap:
                link(
                    da,
                    db,
                    "extracted_script_domain_overlap",
                    {"overlap_count": len(sa & sb)},
                )

    # Claude / external affiliation dump (domains only; no seed promotion)
    aff_path = root / "data" / "research_candidates" / "claude_affiliations_dump.json"
    aff_raw = _load_json(aff_path)
    if isinstance(aff_raw, list):
        for item in aff_raw:
            if not isinstance(item, dict):
                continue
            fd = (item.get("from_domain") or item.get("left") or "").lower().strip()
            td = (item.get("to_domain") or item.get("right") or "").lower().strip()
            if fd and td and fd != td:
                link(
                    fd,
                    td,
                    "affiliation_dump_pair",
                    {
                        "relationship": item.get("relationship"),
                        "notes_present": bool(item.get("notes")),
                    },
                )

    # Discovery redirect chains (final host vs initial request host)
    disc_path = root / "data" / "candidates" / "discovered_domains.json"
    disc_raw = _load_json(disc_path)
    if isinstance(disc_raw, list):
        for row in disc_raw:
            if not isinstance(row, dict):
                continue
            chain = row.get("redirect_chain") or []
            if len(chain) < 2:
                continue
            h0 = _host_from_url(str(chain[0]))
            h1 = _host_from_url(str(chain[-1]))
            if h0 and h1 and h0 != h1:
                link(h0, h1, "discovery_redirect_chain", {"chain": chain})

    scout_tls_links = _load_scout_fingerprint_links(root, link)

    # Build cluster components
    all_nodes: set[str] = set(domain_to_scripts.keys())
    all_nodes |= set(ext_scripts.keys())
    for ent in staged_list:
        if isinstance(ent, dict) and ent.get("domain"):
            all_nodes.add(str(ent["domain"]).lower().strip())
    for (a, b) in pair_evidence:
        all_nodes.add(a)
        all_nodes.add(b)

    comp: dict[str, list[str]] = defaultdict(list)
    for n in all_nodes:
        comp[uf.find(n)].append(n)
    clusters_out: list[dict] = []
    for rep, members in sorted(comp.items(), key=lambda x: (-len(x[1]), x[0])):
        if len(members) < 2:
            continue
        mem_sorted = sorted(set(members))
        evidence_list: list[dict] = []
        for i, a in enumerate(mem_sorted):
            for b in mem_sorted[i + 1 :]:
                key = (a, b) if a <= b else (b, a)
                for ev in pair_evidence.get(key, []):
                    evidence_list.append({"domains": [a, b], **ev})
        clusters_out.append(
            {
                "cluster_id": f"cluster-{rep}",
                "members": mem_sorted,
                "member_count": len(mem_sorted),
                "evidence": evidence_list,
                "review_status": "pending",
                "evidence_tier": "inferred",
            }
        )

    report = {
        "generated_at": _utc_now_iso(),
        "schema_version": SCHEMA_VERSION,
        "cluster_count": len(clusters_out),
        "pair_count": len(pair_evidence),
        "parameters": {
            "min_script_overlap": min_script_overlap,
            "scout_tls_reciprocal_links": scout_tls_links,
        },
    }

    out_doc = {
        "generated_at": report["generated_at"],
        "schema_version": SCHEMA_VERSION,
        "clusters": clusters_out,
    }

    out_path = root / "data" / "research_candidates" / "staged_clusters.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(out_doc, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")

    rep_dir = root / "reports" / "clusters"
    rep_dir.mkdir(parents=True, exist_ok=True)
    ts = report["generated_at"].replace(":", "").replace("-", "")
    rep_path = rep_dir / f"cluster-{ts}.json"
    with rep_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")

    return {"output": str(out_path), "report": str(rep_path), "cluster_count": len(clusters_out)}


def main() -> None:
    ap = argparse.ArgumentParser(description="Cluster related brands from staged and normalized data.")
    ap.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="Repository root (default: auto-detect).",
    )
    ap.add_argument(
        "--min-script-overlap",
        type=int,
        default=2,
        help="Minimum shared script/asset/iframe domains to link two sites (default: 2).",
    )
    args = ap.parse_args()
    r = run_cluster(args.repo_root, min_script_overlap=args.min_script_overlap)
    print(json.dumps(r, indent=2))


if __name__ == "__main__":
    main()
