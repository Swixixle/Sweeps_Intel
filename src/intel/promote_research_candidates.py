from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

from .stage_research_import import _slug_domain, _split_pipe


OPERATORS_HEADER = [
    "id",
    "name",
    "domain",
    "categories",
    "status",
    "confidence",
    "legal_entity",
    "jurisdictions",
    "provider_names",
    "notes",
    "sources",
]

FINGERPRINTS_PARTIAL_HEADER = [
    "entity_id",
    "analytics_ids",
    "tag_manager_ids",
    "script_domains",
    "iframe_domains",
    "asset_domains",
    "support_widget_providers",
    "legal_entity_names",
    "footer_phrases",
    "title_terms",
    "bonus_terms",
    "provider_mentions",
    "signup_paths",
    "cashier_paths",
    "redemption_paths",
    "kyc_vendors",
    "payment_providers",
    "provider_names",
    "game_launcher_patterns",
    "cdn_patterns",
]

REL_HEADER = [
    "from_operator_id",
    "to_operator_id",
    "relationship",
    "confidence",
    "source",
    "evidence_url",
    "evidence_text",
    "from_candidate_id",
    "to_candidate_id",
    "review_status",
]


def _suggested_operator_id(domain: str) -> str:
    return f"operator_{_slug_domain(domain)}"


def _tier_confidence_cap(tier: str) -> float:
    return {
        "first_party_verified": 0.92,
        "secondary_corroborated": 0.78,
        "inferred_or_unverified": 0.55,
    }.get(tier, 0.55)


def load_staged_entities(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return list(data.get("entities") or []), data


def load_staged_fingerprints(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return list(data.get("fingerprints") or []), data


def load_staged_relationships(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return list(data.get("relationships") or []), data


def fingerprint_to_partial_row(
    fp: dict[str, Any],
    entity_id: str,
    legal_entity: str = "",
) -> dict[str, str]:
    tech = fp.get("technical") or {}
    content = fp.get("content") or {}
    flow = fp.get("flow") or {}
    row = {h: "" for h in FINGERPRINTS_PARTIAL_HEADER}
    row["entity_id"] = entity_id
    if legal_entity:
        row["legal_entity_names"] = legal_entity.replace(";", "|")
    row["analytics_ids"] = "|".join(tech.get("analytics_ids") or [])
    row["script_domains"] = "|".join(tech.get("script_domains") or [])
    sw = tech.get("support_widget_providers") or []
    row["support_widget_providers"] = "|".join(x for x in sw if x)
    row["title_terms"] = "|".join(content.get("title_terms") or [])
    row["footer_phrases"] = "|".join(content.get("footer_phrases") or [])
    row["provider_mentions"] = "|".join(content.get("provider_mentions") or [])
    paths = flow.get("cashier_paths") or []
    row["cashier_paths"] = "|".join(paths)
    return row


def run_promote(
    research_dir: Path,
    preview_dir: Path,
    *,
    apply_to_seeds: bool,
) -> int:
    staged_e = research_dir / "staged_entities.json"
    staged_f = research_dir / "staged_fingerprints.json"
    staged_r = research_dir / "staged_relationships.json"
    if not staged_e.exists():
        print(f"error: missing {staged_e}; run stage_research_import first", file=sys.stderr)
        return 1

    entities, _ = load_staged_entities(staged_e)
    fingerprints, _ = (
        load_staged_fingerprints(staged_f) if staged_f.exists() else ([], {})
    )
    relationships, _ = (
        load_staged_relationships(staged_r) if staged_r.exists() else ([], {})
    )

    approved = [e for e in entities if e.get("review_status") == "approved"]
    cid_to_entity = {e["candidate_id"]: e for e in entities}
    cid_to_fp = {f["candidate_id"]: f for f in fingerprints}

    preview_dir.mkdir(parents=True, exist_ok=True)

    op_rows: list[dict[str, str]] = []
    for e in approved:
        dom = e.get("domain", "").strip()
        oid = _suggested_operator_id(dom)
        cap = _tier_confidence_cap(e.get("evidence_tier", ""))
        base_conf = min(0.85, cap)
        raw = e.get("raw_row") or {}
        prov = (raw.get("provider_mentions") or e.get("provider_mentions") or "").strip()
        notes = (
            f"[research_promote tier={e.get('evidence_tier')}] "
            f"{e.get('notes', '')}".strip()
        )
        op_rows.append(
            {
                "id": oid,
                "name": e.get("brand") or dom,
                "domain": dom,
                "categories": "",
                "status": "inactive",
                "confidence": str(base_conf),
                "legal_entity": e.get("legal_entity", ""),
                "jurisdictions": e.get("jurisdiction", ""),
                "provider_names": prov,
                "notes": notes,
                "sources": e.get("sources", ""),
            }
        )

    op_path = preview_dir / "proposed_operators.csv"
    with op_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=OPERATORS_HEADER)
        w.writeheader()
        for r in op_rows:
            w.writerow({k: r.get(k, "") for k in OPERATORS_HEADER})

    fp_rows: list[dict[str, str]] = []
    for e in approved:
        cid = e["candidate_id"]
        oid = _suggested_operator_id(e["domain"])
        fp = cid_to_fp.get(cid)
        if fp:
            fp_rows.append(
                fingerprint_to_partial_row(fp, oid, e.get("legal_entity", ""))
            )

    fp_path = preview_dir / "proposed_fingerprints_partial.csv"
    with fp_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FINGERPRINTS_PARTIAL_HEADER)
        w.writeheader()
        for r in fp_rows:
            w.writerow(r)

    rel_out: list[dict[str, str]] = []
    approved_ids = {e["candidate_id"] for e in approved}
    for rel in relationships:
        if rel.get("review_status") != "approved":
            continue
        fc = rel.get("from_candidate_id")
        tc = rel.get("to_candidate_id")
        if fc not in approved_ids or tc not in approved_ids:
            continue
        fe = cid_to_entity.get(fc)
        te = cid_to_entity.get(tc)
        if not fe or not te:
            continue
        ev = rel.get("evidence") or {}
        rel_out.append(
            {
                "from_operator_id": _suggested_operator_id(fe["domain"]),
                "to_operator_id": _suggested_operator_id(te["domain"]),
                "relationship": rel.get("relationship", "related_to"),
                "confidence": str(rel.get("confidence", 0.6)),
                "source": rel.get("source", "research_promote"),
                "evidence_url": ev.get("url", ""),
                "evidence_text": ev.get("anchor_text", ""),
                "from_candidate_id": fc,
                "to_candidate_id": tc,
                "review_status": "approved",
            }
        )

    rel_path = preview_dir / "proposed_relationships.csv"
    with rel_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=REL_HEADER)
        w.writeheader()
        for r in rel_out:
            w.writerow(r)

    manifest = {
        "approved_entity_count": len(approved),
        "approved_relationship_count": len(rel_out),
        "preview_dir": str(preview_dir),
        "apply_to_seeds": apply_to_seeds,
    }
    (preview_dir / "promotion_manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )

    if apply_to_seeds:
        print(
            "error: refuse to auto-merge into production seeds from this tool; "
            "copy preview CSVs manually after review.",
            file=sys.stderr,
        )
        return 2

    print(f"wrote promotion preview under {preview_dir}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Build promotion previews from approved staged research only. Does not write production seeds.",
    )
    p.add_argument("--repo-root", type=Path, default=Path.cwd())
    p.add_argument("--research-dir", type=Path, default=None)
    p.add_argument("--preview-dir", type=Path, default=None)
    p.add_argument(
        "--apply-to-seeds",
        action="store_true",
        help="Refused: kept for CLI compatibility; exits with error if set.",
    )
    args = p.parse_args(argv)
    repo = args.repo_root.resolve()
    rd = args.research_dir or (repo / "data" / "research_candidates")
    pd = args.preview_dir or (rd / "promotion_preview")
    return run_promote(rd, pd, apply_to_seeds=args.apply_to_seeds)


if __name__ == "__main__":
    raise SystemExit(main())
