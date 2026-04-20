"""
Import cleaned Sweep_Scout candidate CSVs into staged_from_scout JSON.

Staging only: never writes production seeds or normalized intel.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from intel.schemas import SCHEMA_VERSION
from intel.stage_research_import import classify_evidence_tier

REPO_ROOT = Path(__file__).resolve().parents[2]

SCOUT_IMPORT_REL = Path("data/research_candidates/scout_import")
STAGED_SCOUT_REL = Path("data/research_candidates/staged_from_scout")

OPERATORS_CSV = "operators_candidates.csv"
PROMOTERS_CSV = "promoters_candidates.csv"
CORPORATE_CSV = "corporate_entities_candidates.csv"
REDIRECTS_CSV = "redirects_rebrands_candidates.csv"

PRIMARY_DOMAIN_KEYS: tuple[str, ...] = (
    "primary_domain",
    "domain",
    "primary_host",
    "canonical_domain",
    "primary",
)
OTHER_DOMAIN_KEYS: tuple[str, ...] = (
    "other_domains",
    "alias_domains",
    "alias_candidates",
    "additional_domains",
    "secondary_domains",
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _raw_row_dict(row: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in row.items():
        if k is None:
            continue
        key = str(k).strip()
        if v is None:
            out[key] = ""
        elif isinstance(v, (list, dict)):
            out[key] = json.dumps(v, ensure_ascii=False)
        else:
            out[key] = str(v).strip()
    return dict(sorted(out.items()))


def _first_nonempty(row: dict[str, str], keys: tuple[str, ...]) -> str:
    lk = {k.lower(): k for k in row}
    for cand in keys:
        k = lk.get(cand.lower())
        if k and row.get(k, "").strip():
            return row[k].strip()
    return ""


def _confidence_float(row: dict[str, str]) -> float | None:
    lk = {k.lower(): k for k in row}
    for name in ("confidence", "score", "conf"):
        k = lk.get(name)
        if not k or not row.get(k, "").strip():
            continue
        raw = row[k].strip().lower()
        if raw in ("high", "hi"):
            return 0.92
        if raw in ("medium", "med", "mid"):
            return 0.8
        if raw in ("low",):
            return None
        try:
            return float(row[k])
        except ValueError:
            pass
    return None


def _tier_from_row(row: dict[str, str]) -> str:
    notes = _first_nonempty(row, ("notes", "merge_notes", "description"))
    sources = _first_nonempty(row, ("sources", "source_set", "source"))
    cf = _confidence_float(row)
    base = classify_evidence_tier(notes, sources)
    if cf is not None and cf >= 0.9 and base == "inferred_or_unverified":
        return "secondary_corroborated"
    if cf is not None and cf < 0.5:
        return "inferred_or_unverified"
    return base


def _is_canonical_row(row: dict[str, str]) -> bool:
    lk = {k.lower(): k for k in row}
    for flag in ("canonical", "is_canonical", "is_primary", "canonical_row"):
        k = lk.get(flag)
        if k and row.get(k, "").strip():
            v = row[k].strip().lower()
            if v in ("1", "true", "yes", "canonical", "primary"):
                return True
    k = lk.get("row_type")
    if k and row.get(k, "").strip().lower() in ("canonical", "primary"):
        return True
    return False


def _duplicate_group_id(row: dict[str, str]) -> str:
    lk = {k.lower(): k for k in row}
    for name in ("duplicate_group_id", "duplicate_group", "merge_group_id", "group_id"):
        k = lk.get(name)
        if k and row.get(k, "").strip():
            return row[k].strip()
    return ""


def _read_csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return [_raw_row_dict(dict(r)) for r in reader]


def _entity_record(
    *,
    candidate_id: str,
    entity_type_hint: str,
    raw_source_file: str,
    row: dict[str, str],
    idx: int,
) -> dict[str, Any]:
    primary = _first_nonempty(row, PRIMARY_DOMAIN_KEYS)
    other = _first_nonempty(row, OTHER_DOMAIN_KEYS)
    notes = _first_nonempty(row, ("notes", "merge_notes", "description"))
    brand = _first_nonempty(row, ("brand", "name", "display_name", "title"))
    legal = _first_nonempty(row, ("legal_entity", "corporate_name", "entity_name"))
    parent = _first_nonempty(row, ("parent_company", "parent"))
    dup = _duplicate_group_id(row)
    lk = {k.lower(): k for k in row}
    merge_notes = ""
    for mn in ("merge_notes", "merge_note", "dedupe_notes"):
        k = lk.get(mn)
        if k and row.get(k, "").strip():
            merge_notes = row[k].strip()
            break
    source_set = ""
    for sk in ("source_set", "source_batch", "intake_batch"):
        k = lk.get(sk)
        if k and row.get(k, "").strip():
            source_set = row[k].strip()
            break

    has_alias = bool(other.strip())
    return {
        "candidate_id": candidate_id,
        "review_status": "needs_review",
        "evidence_tier": _tier_from_row(row),
        "entity_type_hint": entity_type_hint,
        "imported_from": "scout",
        "raw_source_file": raw_source_file,
        "scout_row_index": idx,
        "is_canonical_candidate": _is_canonical_row(row),
        "duplicate_group_id": dup,
        "merge_notes": merge_notes,
        "source_set": source_set,
        "primary_domain": primary,
        "other_domains": other,
        "domain": primary.split("/")[0].strip().lower() if primary else "",
        "brand": brand,
        "legal_entity": legal,
        "parent_company": parent,
        "notes": notes,
        "sources": _first_nonempty(row, ("sources", "source_urls", "source_url")),
        "confidence": _confidence_float(row),
        "alias_candidates_non_empty": has_alias,
        "alias_review_status": "needs_manual_verification" if has_alias else "not_applicable",
        "raw_row": row,
    }


def _redirect_record(
    *,
    candidate_id: str,
    raw_source_file: str,
    row: dict[str, str],
    idx: int,
) -> dict[str, Any]:
    return {
        "candidate_id": candidate_id,
        "review_status": "needs_review",
        "evidence_tier": _tier_from_row(row),
        "imported_from": "scout",
        "raw_source_file": raw_source_file,
        "scout_row_index": idx,
        "duplicate_group_id": _duplicate_group_id(row),
        "merge_notes": _first_nonempty(row, ("merge_notes", "notes")),
        "source_set": _first_nonempty(row, ("source_set", "sources")),
        "raw_row": row,
    }


def _build_duplicate_relationships(entities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in entities:
        gid = (e.get("duplicate_group_id") or "").strip()
        if gid:
            by_group[gid].append(e)

    rels: list[dict[str, Any]] = []
    ridx = 0
    for gid, members in sorted(by_group.items()):
        if len(members) < 2:
            continue
        canonical = next((m for m in members if m.get("is_canonical_candidate")), None)
        if canonical is None:
            canonical = members[0]
        cid_canon = str(canonical.get("candidate_id") or "")
        for m in members:
            mid = str(m.get("candidate_id") or "")
            if not mid or mid == cid_canon:
                continue
            ridx += 1
            rels.append(
                {
                    "relationship_id": f"scout_dup_{ridx:04d}",
                    "review_status": "needs_review",
                    "imported_from": "scout",
                    "relationship_type": "duplicate_alias_candidate",
                    "from_candidate_id": mid,
                    "to_candidate_id": cid_canon,
                    "duplicate_group_id": gid,
                    "evidence_tier": "inferred_or_unverified",
                    "notes": "Sweep_Scout duplicate group; alias not verified — manual review before production.",
                    "sources": "",
                }
            )
    return rels


def run_import_scout_candidates(
    repo_root: Path | None = None,
    *,
    scout_dir: Path | None = None,
    out_dir: Path | None = None,
) -> dict[str, Any]:
    root = (repo_root or REPO_ROOT).resolve()
    sd = scout_dir if scout_dir is not None else root / SCOUT_IMPORT_REL
    od = out_dir if out_dir is not None else root / STAGED_SCOUT_REL
    if not sd.is_absolute():
        sd = root / sd
    if not od.is_absolute():
        od = root / od
    scout_dir = sd
    out_dir = od
    out_dir.mkdir(parents=True, exist_ok=True)

    entities: list[dict[str, Any]] = []
    redirects: list[dict[str, Any]] = []

    counters = {"operators": 0, "promoters": 0, "corporate_entities": 0, "redirects": 0}

    def ingest_entities(path: Path, hint: str, prefix: str, key: str) -> None:
        nonlocal entities
        rows = _read_csv_rows(path)
        for i, row in enumerate(rows, start=1):
            counters[key] += 1
            cid = f"scout_{prefix}_{i:04d}"
            entities.append(
                _entity_record(
                    candidate_id=cid,
                    entity_type_hint=hint,
                    raw_source_file=path.name,
                    row=row,
                    idx=i,
                )
            )

    op_path = scout_dir / OPERATORS_CSV
    pr_path = scout_dir / PROMOTERS_CSV
    co_path = scout_dir / CORPORATE_CSV
    red_path = scout_dir / REDIRECTS_CSV

    ingest_entities(co_path, "corporate", "corporate", "corporate_entities")
    ingest_entities(op_path, "operator", "operator", "operators")
    ingest_entities(pr_path, "promoter", "promoter", "promoters")

    red_rows = _read_csv_rows(red_path)
    for i, row in enumerate(red_rows, start=1):
        counters["redirects"] += 1
        redirects.append(
            _redirect_record(
                candidate_id=f"scout_redirect_{i:04d}",
                raw_source_file=red_path.name,
                row=row,
                idx=i,
            )
        )

    relationships = _build_duplicate_relationships(entities)

    ts = _utc_now_iso()
    meta = {
        "generated_at": ts,
        "schema_version": SCHEMA_VERSION,
        "source_directory": str(scout_dir.resolve()),
        "row_counts_by_source_file": dict(counters),
    }

    ent_doc = {"entities": entities, **meta}
    rel_doc = {"relationships": relationships, **meta}
    red_doc = {"redirects": redirects, **meta}

    (out_dir / "staged_entities.json").write_text(
        json.dumps(ent_doc, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "staged_relationships.json").write_text(
        json.dumps(rel_doc, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "staged_redirects.json").write_text(
        json.dumps(red_doc, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    return {
        "output_dir": str(out_dir),
        "entity_count": len(entities),
        "relationship_count": len(relationships),
        "redirect_count": len(redirects),
        "counts": counters,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Import Sweep_Scout candidate CSVs into staged_from_scout JSON.")
    ap.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    ap.add_argument(
        "--scout-dir",
        type=Path,
        default=None,
        help="Override scout import directory (default: data/research_candidates/scout_import).",
    )
    ap.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Override output directory (default: data/research_candidates/staged_from_scout).",
    )
    args = ap.parse_args()
    r = run_import_scout_candidates(
        args.repo_root.resolve(),
        scout_dir=args.scout_dir.resolve() if args.scout_dir else None,
        out_dir=args.out_dir.resolve() if args.out_dir else None,
    )
    print(json.dumps(r, indent=2))


if __name__ == "__main__":
    main()
