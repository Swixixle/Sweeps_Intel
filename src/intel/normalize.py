from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from urllib.parse import urlparse
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from .relationships import validate_relationships
from .schemas import (
    Entity,
    Fingerprint,
    Relationship,
    RelationshipEvidence,
    empty_fingerprint,
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _split_pipe(s: str) -> list[str]:
    if not s or not str(s).strip():
        return []
    return [p.strip() for p in str(s).split("|") if p.strip()]


def _split_tokens(s: str) -> list[str]:
    if not s or not str(s).strip():
        return []
    parts = re.split(r"[|\s,]+", str(s).strip())
    return [p.strip() for p in parts if p.strip()]


def normalize_domain(host: str) -> str:
    h = host.lower().strip().rstrip(".")
    if h.startswith("www."):
        h = h[4:]
    if "/" in h and "://" not in h:
        h = h.split("/", 1)[0].strip()
    return h


def _parse_float(raw: str, default: float = 0.0) -> float:
    try:
        return float(str(raw).strip())
    except (TypeError, ValueError):
        return default


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _parse_domain_or_pattern(raw: str) -> tuple[list[str], list[str]]:
    domains: list[str] = []
    patterns: list[str] = []
    for tok in _split_tokens(raw):
        if tok.startswith("/"):
            patterns.append(tok)
            continue
        if "://" in tok:
            try:
                netloc = urlparse(tok).netloc.split("@")[-1]
                if netloc:
                    host = netloc.split(":")[0]
                    domains.append(normalize_domain(host))
            except Exception:
                continue
            continue
        domains.append(normalize_domain(tok))
    return domains, patterns


def _collect_domain_ownership(entities: list[Entity]) -> dict[str, list[str]]:
    owners: dict[str, list[str]] = defaultdict(list)
    for e in entities:
        for d in e.domains:
            owners[d].append(f"{e.entity_type}:{e.id}")
    return owners


def _warn_duplicate_domains(owners: dict[str, list[str]]) -> None:
    for domain, ids in sorted(owners.items()):
        if len(ids) > 1:
            print(f"warning: domain {domain!r} claimed by multiple entities: {', '.join(ids)}", file=sys.stderr)


def load_operators(rows: list[dict[str, str]], ts: str) -> list[Entity]:
    out: list[Entity] = []
    for row in rows:
        if not row.get("id", "").strip():
            continue
        domains = [normalize_domain(d) for d in _split_tokens(row.get("domain", ""))]
        if not domains:
            print(f"warning: skipping operator {row.get('id')!r} with no domain", file=sys.stderr)
            continue
        legal = (row.get("legal_entity") or "").strip()
        prov_names = _split_pipe(row.get("provider_names", ""))
        out.append(
            Entity(
                id=row["id"].strip(),
                name=(row.get("name") or row["id"]).strip(),
                entity_type="operator",
                domains=domains,
                categories=_split_pipe(row.get("categories", "")),
                status=row.get("status", "active").strip() or "active",  # type: ignore[arg-type]
                confidence=_parse_float(row.get("confidence", "0")),
                sources=_split_pipe(row.get("sources", "")),
                notes=(row.get("notes") or "").strip(),
                first_seen=ts,
                last_seen=ts,
                attributes={
                    "legal_entity": legal,
                    "jurisdictions": _split_pipe(row.get("jurisdictions", "")),
                    "blockable": True,
                    "evidence_only": False,
                    "provider_names": prov_names,
                },
            )
        )
    return out


def load_promoters(rows: list[dict[str, str]], ts: str) -> list[Entity]:
    out: list[Entity] = []
    for row in rows:
        if not row.get("id", "").strip():
            continue
        domains = [normalize_domain(d) for d in _split_tokens(row.get("domain", ""))]
        if not domains:
            print(f"warning: skipping promoter {row.get('id')!r} with no domain", file=sys.stderr)
            continue
        promotes_cats = _split_pipe(row.get("promotes_categories", ""))
        out.append(
            Entity(
                id=row["id"].strip(),
                name=(row.get("name") or row["id"]).strip(),
                entity_type="promoter",
                domains=domains,
                categories=promotes_cats,
                status=row.get("status", "active").strip() or "active",  # type: ignore[arg-type]
                confidence=_parse_float(row.get("confidence", "0")),
                sources=_split_pipe(row.get("sources", "")),
                notes=(row.get("notes") or "").strip(),
                first_seen=ts,
                last_seen=ts,
                attributes={
                    "legal_entity": "",
                    "jurisdictions": [],
                    "blockable": False,
                    "evidence_only": False,
                    "promoter_type": (row.get("promoter_type") or "").strip(),
                    "promotes_categories": promotes_cats,
                },
            )
        )
    return out


def load_providers(rows: list[dict[str, str]], ts: str) -> list[Entity]:
    out: list[Entity] = []
    for row in rows:
        if not row.get("id", "").strip():
            continue
        domains = [normalize_domain(d) for d in _split_tokens(row.get("domain", ""))]
        if not domains:
            print(f"warning: provider {row.get('id')!r} has no verified domain yet", file=sys.stderr)
        blockable = str(row.get("blockable", "true")).lower() in {"1", "true", "yes", "y"}
        out.append(
            Entity(
                id=row["id"].strip(),
                name=(row.get("name") or row["id"]).strip(),
                entity_type="provider",
                domains=domains,
                categories=[],
                status=row.get("status", "active").strip() or "active",  # type: ignore[arg-type]
                confidence=_parse_float(row.get("confidence", "0")),
                sources=_split_pipe(row.get("sources", "")),
                notes=(row.get("notes") or "").strip(),
                first_seen=ts,
                last_seen=ts,
                attributes={
                    "legal_entity": "",
                    "jurisdictions": [],
                    "blockable": blockable,
                    "evidence_only": False,
                    "provider_type": (row.get("provider_type") or "unknown").strip(),
                    "domains_pending_verification": not bool(domains),
                },
            )
        )
    return out


def load_payments(rows: list[dict[str, str]], ts: str) -> list[Entity]:
    out: list[Entity] = []
    for row in rows:
        if not row.get("id", "").strip():
            continue
        raw_pat = row.get("domain_or_pattern", "") or ""
        domains, path_patterns = _parse_domain_or_pattern(raw_pat)
        if not domains and not path_patterns:
            print(f"warning: skipping payment_path {row.get('id')!r} with no domain_or_pattern", file=sys.stderr)
            continue
        out.append(
            Entity(
                id=row["id"].strip(),
                name=(row.get("name") or row["id"]).strip(),
                entity_type="payment_path",
                domains=domains,
                categories=[],
                status=row.get("status", "active").strip() or "active",  # type: ignore[arg-type]
                confidence=_parse_float(row.get("confidence", "0")),
                sources=_split_pipe(row.get("sources", "")),
                notes=(row.get("notes") or "").strip(),
                first_seen=ts,
                last_seen=ts,
                attributes={
                    "legal_entity": "",
                    "jurisdictions": [],
                    "blockable": True,
                    "evidence_only": False,
                    "payment_type": (row.get("payment_type") or "unknown").strip(),
                    "domain_or_pattern": raw_pat.strip(),
                    "path_patterns": path_patterns,
                },
            )
        )
    return out


def load_relationships(rows: list[dict[str, str]]) -> list[Relationship]:
    out: list[Relationship] = []
    for row in rows:
        if not row.get("from_id", "").strip() or not row.get("to_id", "").strip():
            continue
        ev_url = (row.get("evidence_url") or "").strip()
        ev_text = (row.get("evidence_text") or "").strip()
        evidence = RelationshipEvidence(url=ev_url, anchor_text=ev_text) if (ev_url or ev_text) else None
        out.append(
            Relationship(
                from_id=row["from_id"].strip(),
                to_id=row["to_id"].strip(),
                relationship=(row.get("relationship") or "related_to").strip(),
                confidence=_parse_float(row.get("confidence", "0")),
                source=(row.get("source") or "manual_seed").strip(),
                evidence=evidence,
            )
        )
    return out


def run_normalize(repo_root: Path, seeds_dir: Path, out_dir: Path) -> None:
    ts = _utc_now_iso()
    entities: list[Entity] = []
    entities.extend(load_operators(_read_csv(seeds_dir / "operators.csv"), ts))
    entities.extend(load_promoters(_read_csv(seeds_dir / "promoters.csv"), ts))
    entities.extend(load_providers(_read_csv(seeds_dir / "providers.csv"), ts))
    entities.extend(load_payments(_read_csv(seeds_dir / "payment_paths.csv"), ts))
    rels = load_relationships(_read_csv(seeds_dir / "relationships.csv"))

    owners = _collect_domain_ownership(entities)
    _warn_duplicate_domains(owners)

    known_ids = {e.id for e in entities}
    validated, rel_errors = validate_relationships(rels, known_ids)
    for msg in rel_errors:
        print(f"warning: {msg}", file=sys.stderr)

    fingerprints: list[Fingerprint] = [empty_fingerprint(e.id) for e in entities]

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "entities.json").write_text(
        json.dumps([e.to_json() for e in entities], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "fingerprints.json").write_text(
        json.dumps([f.to_json() for f in fingerprints], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "relationships.json").write_text(
        json.dumps([r.to_json() for r in validated], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Normalize Sweeps_Intel seed CSVs into affiliation-aware JSON.")
    p.add_argument("--repo-root", type=Path, default=Path.cwd())
    p.add_argument("--seeds", type=Path, default=None, help="Default: <repo-root>/data/seeds")
    p.add_argument("--out", type=Path, default=None, help="Default: <repo-root>/data/normalized")
    args = p.parse_args(argv)
    repo = args.repo_root.resolve()
    seeds = args.seeds or (repo / "data" / "seeds")
    out = args.out or (repo / "data" / "normalized")
    run_normalize(repo, seeds, out)
    print(f"wrote entities.json, fingerprints.json, relationships.json under {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
