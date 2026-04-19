"""
Merge staged research artifacts into a single prioritized review queue.

Stronger evidence tiers sort first; does not promote anything to production.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from intel.schemas import SCHEMA_VERSION

REPO_ROOT = Path(__file__).resolve().parents[2]

TIER_RANK: dict[str, int] = {
    "first_party_verified": 100,
    "secondary_corroborated": 50,
    "inferred_or_unverified": 10,
    "inferred": 10,
    "pending": 5,
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _load_json(path: Path) -> Any:
    if not path.is_file():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _tier_base(tier: str | None) -> int:
    if not tier:
        return TIER_RANK["inferred_or_unverified"]
    return TIER_RANK.get(str(tier), 8)


def _score_staged_entity(ent: dict) -> int:
    base = _tier_base(ent.get("evidence_tier"))
    src = ent.get("sources") or ""
    bonus = min(40, len(str(src)) // 10)
    if ent.get("legal_entity"):
        bonus += 15
    if ent.get("parent_company"):
        bonus += 15
    return base + bonus


def _score_extracted_fp(rec: dict) -> int:
    base = _tier_base(rec.get("evidence_tier"))
    bonus = 5 * len(rec.get("legal_policy_urls") or [])
    bonus += 3 * len(rec.get("support_help_urls") or [])
    bonus += 2 * len(rec.get("contact_emails") or [])
    tech = (rec.get("fingerprint") or {}).get("technical") or {}
    bonus += min(20, len(tech.get("script_domains") or []))
    return base + bonus


def _score_cluster(cl: dict) -> int:
    base = _tier_base(cl.get("evidence_tier"))
    nmem = int(cl.get("member_count") or len(cl.get("members") or []))
    ev = cl.get("evidence") or []
    return base + 4 * nmem + min(60, 2 * len(ev))


def _score_discovered(row: dict) -> int:
    base = TIER_RANK["inferred_or_unverified"]
    chain = row.get("redirect_chain") or []
    if len(chain) >= 2:
        base += 25
    bonus = min(30, 3 * len(row.get("source_urls") or []))
    return base + bonus


def run_review_queue(repo_root: Path | None = None) -> dict[str, Any]:
    root = repo_root or REPO_ROOT
    rc = root / "data" / "research_candidates"
    cand = root / "data" / "candidates"
    ts = _utc_now_iso()
    items: list[dict[str, Any]] = []

    staged_ent = _load_json(rc / "staged_entities.json")
    if isinstance(staged_ent, dict):
        for ent in staged_ent.get("entities") or []:
            if not isinstance(ent, dict):
                continue
            cid = ent.get("candidate_id") or ent.get("domain")
            items.append(
                {
                    "kind": "staged_entity",
                    "id": str(cid),
                    "priority_score": _score_staged_entity(ent),
                    "review_status": ent.get("review_status") or "needs_review",
                    "evidence_tier": ent.get("evidence_tier"),
                    "sources": ent.get("sources"),
                    "notes": ent.get("notes"),
                    "payload_ref": {
                        "path": "data/research_candidates/staged_entities.json",
                        "candidate_id": ent.get("candidate_id"),
                        "domain": ent.get("domain"),
                    },
                }
            )

    staged_fp = _load_json(rc / "staged_fingerprints.json")
    if isinstance(staged_fp, dict):
        for fp in staged_fp.get("fingerprints") or []:
            if not isinstance(fp, dict):
                continue
            cid = fp.get("candidate_id")
            items.append(
                {
                    "kind": "staged_fingerprint",
                    "id": str(cid),
                    "priority_score": _tier_base(fp.get("evidence_tier")) + 5,
                    "review_status": fp.get("review_status") or "needs_review",
                    "evidence_tier": fp.get("evidence_tier"),
                    "sources": None,
                    "notes": None,
                    "payload_ref": {
                        "path": "data/research_candidates/staged_fingerprints.json",
                        "candidate_id": cid,
                    },
                }
            )

    staged_rel = _load_json(rc / "staged_relationships.json")
    if isinstance(staged_rel, dict):
        for i, rel in enumerate(staged_rel.get("relationships") or []):
            if not isinstance(rel, dict):
                continue
            rid = f"{rel.get('from_candidate_id','')}->{rel.get('to_candidate_id','')}"
            items.append(
                {
                    "kind": "staged_relationship",
                    "id": rid or f"rel_{i}",
                    "priority_score": _tier_base(rel.get("evidence_tier")) + 8,
                    "review_status": rel.get("review_status") or "needs_review",
                    "evidence_tier": rel.get("evidence_tier"),
                    "sources": rel.get("sources"),
                    "notes": rel.get("notes"),
                    "payload_ref": {
                        "path": "data/research_candidates/staged_relationships.json",
                        "index": i,
                    },
                }
            )

    ext_fp = _load_json(rc / "extracted_fingerprints.json")
    if isinstance(ext_fp, dict):
        for rec in ext_fp.get("fingerprints") or []:
            if not isinstance(rec, dict):
                continue
            dom = rec.get("domain") or ""
            items.append(
                {
                    "kind": "extracted_fingerprint",
                    "id": dom,
                    "priority_score": _score_extracted_fp(rec),
                    "review_status": rec.get("review_status") or "needs_review",
                    "evidence_tier": rec.get("evidence_tier"),
                    "sources": rec.get("source_url"),
                    "notes": None,
                    "payload_ref": {
                        "path": "data/research_candidates/extracted_fingerprints.json",
                        "domain": dom,
                    },
                }
            )

    clusters_doc = _load_json(rc / "staged_clusters.json")
    if isinstance(clusters_doc, dict):
        for cl in clusters_doc.get("clusters") or []:
            if not isinstance(cl, dict):
                continue
            cid = cl.get("cluster_id") or ""
            items.append(
                {
                    "kind": "cluster",
                    "id": str(cid),
                    "priority_score": _score_cluster(cl),
                    "review_status": cl.get("review_status") or "pending",
                    "evidence_tier": cl.get("evidence_tier"),
                    "sources": None,
                    "notes": f"members={cl.get('members')}",
                    "payload_ref": {
                        "path": "data/research_candidates/staged_clusters.json",
                        "cluster_id": cid,
                    },
                }
            )

    disc = _load_json(cand / "discovered_domains.json")
    if isinstance(disc, list):
        seen_dom: set[str] = set()
        for row in disc:
            if not isinstance(row, dict):
                continue
            dom = (row.get("domain") or "").lower().strip()
            if not dom or dom in seen_dom:
                continue
            seen_dom.add(dom)
            items.append(
                {
                    "kind": "discovered_domain",
                    "id": dom,
                    "priority_score": _score_discovered(row),
                    "review_status": "pending",
                    "evidence_tier": "inferred_or_unverified",
                    "sources": row.get("source_urls"),
                    "notes": None,
                    "payload_ref": {"path": "data/candidates/discovered_domains.json", "domain": dom},
                }
            )

    def sort_key(it: dict) -> tuple:
        return (-int(it["priority_score"]), str(it.get("kind")), str(it.get("id")))

    items.sort(key=sort_key)

    out = {
        "generated_at": ts,
        "schema_version": SCHEMA_VERSION,
        "item_count": len(items),
        "items": items,
    }
    out_path = rc / "review_queue.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")

    return {"output": str(out_path), "item_count": len(items)}


def main() -> None:
    ap = argparse.ArgumentParser(description="Build prioritized research review_queue.json.")
    ap.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    args = ap.parse_args()
    r = run_review_queue(args.repo_root.resolve())
    print(json.dumps(r, indent=2))


if __name__ == "__main__":
    main()
