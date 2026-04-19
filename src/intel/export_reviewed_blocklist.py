"""
Export domains to block from review_decisions.json (research output only).

Does not write production seeds or modify normalized intel JSON.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from intel.schemas import SCHEMA_VERSION

REPO_ROOT = Path(__file__).resolve().parents[2]

_DOMAINISH = re.compile(r"^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _load_json(path: Path) -> Any:
    if not path.is_file():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _norm_domain(d: str) -> str:
    d = d.strip().lower().rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    return d


def _index_clusters(path: Path) -> dict[str, dict[str, Any]]:
    doc = _load_json(path)
    if not isinstance(doc, dict):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for cl in doc.get("clusters") or []:
        if isinstance(cl, dict) and cl.get("cluster_id"):
            out[str(cl["cluster_id"])] = cl
    return out


def _index_entities(path: Path) -> dict[str, str]:
    doc = _load_json(path)
    if not isinstance(doc, dict):
        return {}
    out: dict[str, str] = {}
    for ent in doc.get("entities") or []:
        if not isinstance(ent, dict):
            continue
        cid = str(ent.get("candidate_id") or "")
        dom = (ent.get("domain") or "").strip()
        if cid and dom:
            out[cid] = _norm_domain(dom)
    return out


def domains_for_decision(
    decision: dict[str, Any],
    *,
    clusters_by_id: dict[str, dict[str, Any]],
    entity_domain_by_cid: dict[str, str],
) -> list[str]:
    rid = str(decision.get("record_id") or "")
    st = str(decision.get("source_type") or "")
    out: list[str] = []

    if rid.startswith("queue:"):
        rest = rid[6:]
        subkind, _, dom_rest = rest.partition(":")
        if subkind in ("discovered_domain", "extracted_fingerprint") and dom_rest.strip():
            out.append(_norm_domain(dom_rest.strip()))
        return out

    if st == "cluster":
        cl = clusters_by_id.get(rid)
        if cl:
            for m in cl.get("members") or []:
                if isinstance(m, str) and m.strip():
                    out.append(_norm_domain(m))
        return out

    if st == "entity" and rid in entity_domain_by_cid:
        out.append(entity_domain_by_cid[rid])
        return out

    if st == "fingerprint" and rid in entity_domain_by_cid:
        out.append(entity_domain_by_cid[rid])
        return out

    if st == "relationship" and "->" in rid:
        left, _, right = rid.partition("->")
        for token in (left.strip(), right.strip()):
            if token in entity_domain_by_cid:
                out.append(entity_domain_by_cid[token])
            elif _DOMAINISH.match(token):
                out.append(_norm_domain(token))
        return out

    if _DOMAINISH.match(rid):
        out.append(_norm_domain(rid))

    return out


def run_export_reviewed_blocklist(
    repo_root: Path | None = None,
    *,
    include_after_review: bool = False,
) -> dict[str, Any]:
    root = repo_root or REPO_ROOT
    rc = root / "data" / "research_candidates"
    pub = root / "data" / "published"
    pub.mkdir(parents=True, exist_ok=True)

    decisions_doc = _load_json(rc / "review_decisions.json")
    if not isinstance(decisions_doc, dict):
        decisions = []
    else:
        decisions = [d for d in (decisions_doc.get("decisions") or []) if isinstance(d, dict)]

    clusters_by_id = _index_clusters(rc / "staged_clusters.json")
    entity_domain_by_cid = _index_entities(rc / "staged_entities.json")

    allowed = {"block_now"}
    if include_after_review:
        allowed.add("block_after_review")

    entries: list[dict[str, Any]] = []
    domain_set: set[str] = set()

    for d in decisions:
        br = str(d.get("block_recommendation") or "")
        if br not in allowed:
            continue
        doms = domains_for_decision(
            d,
            clusters_by_id=clusters_by_id,
            entity_domain_by_cid=entity_domain_by_cid,
        )
        for dom in doms:
            if not dom:
                continue
            domain_set.add(dom)
            entries.append(
                {
                    "domain": dom,
                    "block_recommendation": br,
                    "record_id": d.get("record_id"),
                    "source_type": d.get("source_type"),
                    "likely_entity_type": d.get("likely_entity_type"),
                }
            )

    entries.sort(key=lambda x: (x["domain"], x["record_id"] or "", x["block_recommendation"]))
    domains_sorted = sorted(domain_set)

    ts = _utc_now_iso()
    json_doc = {
        "generated_at": ts,
        "schema_version": SCHEMA_VERSION,
        "include_after_review": include_after_review,
        "domain_count": len(domains_sorted),
        "domains": domains_sorted,
        "entries": entries,
    }
    json_path = pub / "reviewed_blocklist.json"
    with json_path.open("w", encoding="utf-8") as f:
        json.dump(json_doc, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")

    txt_path = pub / "reviewed_domains.txt"
    with txt_path.open("w", encoding="utf-8") as f:
        f.write("# Generated from review_decisions.json — verify before deploying.\n")
        for dom in domains_sorted:
            f.write(f"{dom}\n")

    return {
        "json_path": str(json_path),
        "txt_path": str(txt_path),
        "domain_count": len(domains_sorted),
        "entry_rows": len(entries),
    }


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Export block-now (and optional block-after-review) domains from review_decisions.json."
    )
    ap.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    ap.add_argument(
        "--include-after-review",
        action="store_true",
        help="Also include decisions with block_recommendation=block_after_review.",
    )
    args = ap.parse_args()
    r = run_export_reviewed_blocklist(args.repo_root.resolve(), include_after_review=args.include_after_review)
    print(json.dumps(r, indent=2))


if __name__ == "__main__":
    main()
