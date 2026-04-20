"""
Summarize staged Sweep_Scout imports for human promotion review.

Does not write production seeds.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from intel.schemas import SCHEMA_VERSION

REPO_ROOT = Path(__file__).resolve().parents[2]
STAGED_SCOUT_REL = Path("data/research_candidates/staged_from_scout")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _load_json(path: Path) -> Any:
    if not path.is_file():
        return None
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def _promotion_action_entity(ent: dict[str, Any]) -> tuple[str, list[str]]:
    """Default policy encoded as recommendation + reasons."""
    reasons: list[str] = []
    hint = str(ent.get("entity_type_hint") or "")
    has_alias = bool(ent.get("alias_candidates_non_empty"))
    conf = ent.get("confidence")
    try:
        cf = float(conf) if conf is not None else None
    except (TypeError, ValueError):
        cf = None

    if hint == "corporate":
        if has_alias:
            reasons.append("policy:corporate_has_other_domains_unusual")
            return "needs_manual_verification", reasons
        reasons.append("policy:corporate_usually_safe_to_promote")
        return "safe_to_promote_now", reasons

    if hint == "operator":
        if has_alias:
            reasons.append("policy:other_domains_not_verified_aliases")
            return "needs_manual_verification", reasons
        if cf is not None and cf >= 0.85:
            reasons.append("policy:operator_primary_only_high_confidence")
            return "safe_to_promote_now", reasons
        if cf is not None and cf >= 0.7:
            reasons.append("policy:operator_primary_moderate_confidence")
            return "stage_only", reasons
        reasons.append("policy:operator_primary_low_or_missing_confidence")
        return "stage_only", reasons

    if hint == "promoter":
        reasons.append("policy:promoter_stage_only_by_default")
        return "stage_only", reasons

    reasons.append("policy:unknown_entity_type_hint")
    return "needs_manual_verification", reasons


def _promotion_action_redirect(_: dict[str, Any]) -> tuple[str, list[str]]:
    return "stage_only", ["policy:redirect_rebrand_requires_independent_verification"]


def run_review_scout_candidates(
    repo_root: Path | None = None,
    *,
    staged_dir: Path | None = None,
) -> dict[str, Any]:
    root = (repo_root or REPO_ROOT).resolve()
    sd = staged_dir if staged_dir is not None else root / STAGED_SCOUT_REL
    if not sd.is_absolute():
        sd = root / sd

    ent_doc = _load_json(sd / "staged_entities.json") or {}
    rel_doc = _load_json(sd / "staged_relationships.json") or {}
    red_doc = _load_json(sd / "staged_redirects.json") or {}

    entities = [e for e in (ent_doc.get("entities") or []) if isinstance(e, dict)]
    relationships = [r for r in (rel_doc.get("relationships") or []) if isinstance(r, dict)]
    redirects = [r for r in (red_doc.get("redirects") or []) if isinstance(r, dict)]

    by_hint: dict[str, int] = {}
    duplicate_ids: set[str] = set()
    alias_rows = 0
    entity_recs: list[dict[str, Any]] = []

    for e in entities:
        h = str(e.get("entity_type_hint") or "unknown")
        by_hint[h] = by_hint.get(h, 0) + 1
        dg = (e.get("duplicate_group_id") or "").strip()
        if dg:
            duplicate_ids.add(dg)
        if e.get("alias_candidates_non_empty"):
            alias_rows += 1
        action, reasons = _promotion_action_entity(e)
        entity_recs.append(
            {
                "candidate_id": e.get("candidate_id"),
                "entity_type_hint": h,
                "primary_domain": e.get("primary_domain"),
                "promotion_recommendation": action,
                "reasons": reasons,
                "duplicate_group_id": dg or None,
                "alias_candidates_non_empty": bool(e.get("alias_candidates_non_empty")),
            }
        )

    redirect_recs: list[dict[str, Any]] = []
    for r in redirects:
        action, reasons = _promotion_action_redirect(r)
        redirect_recs.append(
            {
                "candidate_id": r.get("candidate_id"),
                "promotion_recommendation": action,
                "reasons": reasons,
            }
        )

    needs_manual = sum(
        1
        for x in entity_recs + redirect_recs
        if x.get("promotion_recommendation") == "needs_manual_verification"
    )

    summary = {
        "generated_at": _utc_now_iso(),
        "schema_version": SCHEMA_VERSION,
        "staged_directory": str(sd.resolve()),
        "counts": {
            "staged_entities_total": len(entities),
            "staged_operators": by_hint.get("operator", 0),
            "staged_corporate_entities": by_hint.get("corporate", 0),
            "staged_promoters": by_hint.get("promoter", 0),
            "staged_redirects": len(redirects),
            "staged_relationships": len(relationships),
            "duplicate_group_ids_referenced": len(duplicate_ids),
            "rows_with_alias_or_other_domains": alias_rows,
            "rows_needs_manual_verification": needs_manual,
        },
        "duplicate_group_ids": sorted(duplicate_ids),
        "entity_promotion_rows": sorted(entity_recs, key=lambda x: str(x.get("candidate_id"))),
        "redirect_promotion_rows": sorted(redirect_recs, key=lambda x: str(x.get("candidate_id"))),
        "policy_defaults_comment": (
            "corporate: safe_to_promote_now unless other_domains set. "
            "operator primary only: safe/stage by confidence; other_domains always needs_manual_verification. "
            "redirects: stage_only. promoters: stage_only."
        ),
    }

    out_path = sd / "promotion_review_summary.json"
    out_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

    return {"output": str(out_path), "counts": summary["counts"]}


def main() -> None:
    ap = argparse.ArgumentParser(description="Build promotion_review_summary.json for staged Sweep_Scout imports.")
    ap.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    ap.add_argument("--staged-dir", type=Path, default=None, help="Override staged_from_scout directory.")
    args = ap.parse_args()
    r = run_review_scout_candidates(
        args.repo_root.resolve(),
        staged_dir=args.staged_dir.resolve() if args.staged_dir else None,
    )
    print(json.dumps(r, indent=2))


if __name__ == "__main__":
    main()
