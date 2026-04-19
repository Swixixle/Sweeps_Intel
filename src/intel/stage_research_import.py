from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def classify_evidence_tier(notes: str, sources: str) -> str:
    """Conservative tiering: strongest caution signals win."""
    blob = f"{notes or ''} {sources or ''}".lower()

    inferred_markers = (
        "not verified",
        "inferred",
        "likely ",
        " likely",
        "reported ultimate parent",
        "url pattern",
        "not directly verified",
        "403",
        " access denied",
        "blocked",
        "cloudflare",
        "js/",
        "could not verify",
        "not confirmed",
        "ambiguous",
    )
    secondary_markers = (
        "secondary sources",
        "third-party reporting",
        "third party reporting",
        " corroborated",
        "reported ",
        "per reporting",
        "news article",
    )
    first_markers = (
        "quoted verbatim",
        "official site",
        "official terms",
        "official provider page",
        "direct fetch",
        "first-party",
        "first party",
        "confirmed on",
    )
    # "confirmed" alone is weak; pair with official context
    if "confirmed" in blob and ("official" in blob or "terms" in blob or "site" in blob):
        first_blob = True
    else:
        first_blob = False

    if any(m in blob for m in inferred_markers):
        return "inferred_or_unverified"
    if any(m in blob for m in secondary_markers):
        return "secondary_corroborated"
    if first_blob or any(m in blob for m in first_markers):
        return "first_party_verified"
    return "inferred_or_unverified"


def _split_pipe(s: str) -> list[str]:
    if not s or not str(s).strip():
        return []
    return [p.strip() for p in str(s).split("|") if p.strip()]


def _norm_cluster_key(legal_entity: str, parent_company: str) -> str | None:
    le = (legal_entity or "").strip().lower()
    pc = (parent_company or "").strip().lower()
    if pc:
        return f"parent:{pc}"
    if le:
        return f"legal:{le}"
    return None


def _slug_domain(domain: str) -> str:
    d = (domain or "").strip().lower().split("/")[0].replace(".", "_")
    d = re.sub(r"[^a-z0-9_]+", "_", d)
    return d.strip("_") or "unknown"


def _cell_str(row: dict[str, Any], key: str) -> str:
    v = row.get(key)
    if v is None:
        return ""
    if isinstance(v, list):
        return "|".join(str(x) for x in v).strip()
    return str(v).strip()


def row_to_staged_entity(row: dict[str, Any], idx: int) -> dict[str, Any]:
    domain = _cell_str(row, "domain")
    brand = _cell_str(row, "brand") or domain
    cid = f"research_{idx:04d}"
    notes = _cell_str(row, "notes")
    sources = _cell_str(row, "sources")
    tier = classify_evidence_tier(notes, sources)
    raw = {str(k): _cell_str(row, k) for k in row if k is not None}
    return {
        "candidate_id": cid,
        "review_status": "needs_review",
        "evidence_tier": tier,
        "domain": domain,
        "brand": brand,
        "legal_entity": _cell_str(row, "legal_entity"),
        "parent_company": _cell_str(row, "parent_company"),
        "jurisdiction": _cell_str(row, "jurisdiction"),
        "company_number": _cell_str(row, "company_number"),
        "notes": notes,
        "sources": sources,
        "sources_list": _split_pipe(sources) if "|" in sources else ([sources] if sources else []),
        "raw_row": raw,
    }


def row_to_staged_fingerprint(candidate_id: str, row: dict[str, Any], tier: str) -> dict[str, Any]:
    pm = _split_pipe(row.get("provider_mentions", "") or "")
    scripts = _split_pipe(row.get("script_domains", "") or "")
    title_terms = _split_pipe(row.get("title_phrase", "") or "")
    footer = _split_pipe(row.get("footer_phrase", "") or "")
    analytics = _split_pipe(row.get("analytics_ids", "") or "")
    cashier = (row.get("cashier_path") or "").strip()
    sw = (row.get("support_widget") or "").strip()
    return {
        "candidate_id": candidate_id,
        "review_status": "needs_review",
        "evidence_tier": tier,
        "technical": {
            "analytics_ids": analytics,
            "script_domains": scripts,
            "support_widget_providers": [sw] if sw else [],
        },
        "content": {
            "title_terms": title_terms,
            "footer_phrases": footer,
            "provider_mentions": pm,
        },
        "flow": {
            "cashier_paths": [cashier.lower()] if cashier else [],
        },
        "raw_row_keys": list(row.keys()),
    }


def cluster_relationships(entities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[str, list[str]] = {}
    for e in entities:
        key = _norm_cluster_key(e.get("legal_entity", ""), e.get("parent_company", ""))
        if not key:
            continue
        buckets.setdefault(key, []).append(e["candidate_id"])

    rels: list[dict[str, Any]] = []
    for key, cids in buckets.items():
        cids = sorted(set(cids))
        if len(cids) < 2:
            continue
        for i, a in enumerate(cids):
            for b in cids[i + 1 :]:
                rels.append(
                    {
                        "from_candidate_id": a,
                        "to_candidate_id": b,
                        "relationship": "related_to",
                        "confidence": 0.55,
                        "source": "research_cluster_corporate",
                        "evidence_tier": "inferred_or_unverified",
                        "review_status": "needs_review",
                        "notes": f"Cluster key {key!r}; verify before treating as production relationship.",
                        "sources": "",
                        "evidence": {"url": "", "anchor_text": ""},
                    }
                )
    return rels


def load_claude_affiliations(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        return []
    out: list[dict[str, Any]] = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            continue
        out.append(
            {
                "import_id": f"claude_aff_{i:04d}",
                "review_status": "needs_review",
                "evidence_tier": classify_evidence_tier(
                    str(item.get("notes", "")),
                    str(item.get("sources", "")),
                ),
                "from_domain": (item.get("from_domain") or item.get("left") or "").strip(),
                "to_domain": (item.get("to_domain") or item.get("right") or "").strip(),
                "relationship": (item.get("relationship") or "related_to").strip(),
                "confidence": float(item.get("confidence", 0.5)),
                "notes": str(item.get("notes", "")),
                "sources": str(item.get("sources", "")),
                "raw": item,
            }
        )
    return out


def run_stage(
    input_csv: Path,
    out_dir: Path,
    affiliations_json: Path | None,
) -> None:
    with input_csv.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    entities: list[dict[str, Any]] = []
    fingerprints: list[dict[str, Any]] = []
    domain_to_cid: dict[str, str] = {}

    for i, row in enumerate(rows, start=1):
        if not (row.get("domain") or "").strip() and not (row.get("brand") or "").strip():
            continue
        ent = row_to_staged_entity(row, i)
        entities.append(ent)
        domain_to_cid[ent["domain"].lower()] = ent["candidate_id"]
        fingerprints.append(
            row_to_staged_fingerprint(ent["candidate_id"], row, ent["evidence_tier"])
        )

    rels = cluster_relationships(entities)

    if affiliations_json and affiliations_json.exists():
        for a in load_claude_affiliations(affiliations_json):
            fd = (a.get("from_domain") or "").lower().strip()
            td = (a.get("to_domain") or "").lower().strip()
            fc = domain_to_cid.get(fd)
            tc = domain_to_cid.get(td)
            rels.append(
                {
                    "import_id": a["import_id"],
                    "from_candidate_id": fc,
                    "to_candidate_id": tc,
                    "from_domain": a.get("from_domain"),
                    "to_domain": a.get("to_domain"),
                    "relationship": a["relationship"],
                    "confidence": a["confidence"],
                    "source": "claude_affiliations_dump",
                    "evidence_tier": a["evidence_tier"],
                    "review_status": "needs_review",
                    "notes": a["notes"],
                    "sources": a["sources"],
                    "resolution_status": "resolved" if (fc and tc) else "unresolved_domain",
                }
            )

    ts = _utc_now_iso()
    meta = {"generated_at": ts, "source_import": str(input_csv.resolve())}

    (out_dir / "staged_entities.json").write_text(
        json.dumps({"entities": entities, **meta}, indent=2) + "\n",
        encoding="utf-8",
    )
    (out_dir / "staged_fingerprints.json").write_text(
        json.dumps({"fingerprints": fingerprints, **meta}, indent=2) + "\n",
        encoding="utf-8",
    )
    (out_dir / "staged_relationships.json").write_text(
        json.dumps({"relationships": rels, **meta}, indent=2) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Stage external research (e.g. Claude CSV) into reviewable candidates. Never touches production seeds.",
    )
    p.add_argument("--repo-root", type=Path, default=Path.cwd())
    p.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Claude-style research CSV (default: data/research_candidates/claude_fingerprint_dump.csv)",
    )
    p.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Default: <repo-root>/data/research_candidates",
    )
    p.add_argument(
        "--affiliations",
        type=Path,
        default=None,
        help="Optional JSON list (default: data/research_candidates/claude_affiliations_dump.json if present)",
    )
    args = p.parse_args(argv)
    repo = args.repo_root.resolve()
    out_dir = args.out_dir or (repo / "data" / "research_candidates")
    inp = args.input or (out_dir / "claude_fingerprint_dump.csv")
    if not inp.exists():
        print(f"error: input CSV not found: {inp}", file=sys.stderr)
        return 1
    aff_path = args.affiliations
    if aff_path is None:
        default_aff = out_dir / "claude_affiliations_dump.json"
        aff_path = default_aff if default_aff.exists() else None

    run_stage(inp, out_dir, aff_path)
    print(f"wrote staged_* under {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
