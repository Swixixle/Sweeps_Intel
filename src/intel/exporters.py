from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


EXCLUDE_DOMAINS = frozenset(
    {
        "pending-promoter-01.invalid",
        "pending-promoter-02.invalid",
        "pending-payment-01.invalid",
        "example.com",
        "example.org",
        "example.net",
    }
)


def _load_json_list(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def build_intel_snapshot(normalized_dir: Path, generated_at: str) -> dict:
    snap: dict = {
        "generated_at": generated_at,
        "entities": _load_json_list(normalized_dir / "entities.json"),
        "fingerprints": _load_json_list(normalized_dir / "fingerprints.json"),
        "relationships": _load_json_list(normalized_dir / "relationships.json"),
    }
    aff_path = normalized_dir / "affiliations.json"
    if aff_path.exists():
        snap["affiliations"] = _load_json_list(aff_path)
    return snap


def build_block_candidates(entities: list[dict], generated_at: str) -> dict:
    domains: set[str] = set()
    provenance: list[dict] = []

    for e in entities:
        et = e.get("entity_type")
        if e.get("status") != "active":
            continue
        attrs = e.get("attributes") or {}
        blockable = bool(attrs.get("blockable", True))

        if et == "operator" and blockable:
            for d in e.get("domains") or []:
                if d in EXCLUDE_DOMAINS:
                    continue
                domains.add(d)
                provenance.append({"entity_id": e.get("id"), "entity_type": et, "domain": d})

        if et == "provider" and blockable:
            for d in e.get("domains") or []:
                if d in EXCLUDE_DOMAINS:
                    continue
                domains.add(d)
                provenance.append({"entity_id": e.get("id"), "entity_type": et, "domain": d})

        if et == "payment_path" and blockable:
            if float(e.get("confidence") or 0) < 0.75:
                continue
            for d in e.get("domains") or []:
                if d in EXCLUDE_DOMAINS:
                    continue
                domains.add(d)
                provenance.append({"entity_id": e.get("id"), "entity_type": et, "domain": d})

    return {
        "generated_at": generated_at,
        "domains": sorted(domains),
        "source_entities": provenance,
    }


def run_export(repo_root: Path, normalized_dir: Path, published_dir: Path) -> None:
    generated_at = _utc_now_iso()
    entities = _load_json_list(normalized_dir / "entities.json")
    snapshot = build_intel_snapshot(normalized_dir, generated_at)
    block = build_block_candidates(entities, generated_at)
    published_dir.mkdir(parents=True, exist_ok=True)
    (published_dir / "intel_snapshot.json").write_text(
        json.dumps(snapshot, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (published_dir / "block_candidates.json").write_text(
        json.dumps(block, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Export intel_snapshot and block_candidates for downstream use.")
    p.add_argument("--repo-root", type=Path, default=Path.cwd())
    p.add_argument("--normalized", type=Path, default=None)
    p.add_argument("--published", type=Path, default=None)
    args = p.parse_args(argv)
    repo = args.repo_root.resolve()
    norm = args.normalized or (repo / "data" / "normalized")
    pub = args.published or (repo / "data" / "published")
    if not (norm / "entities.json").exists():
        raise SystemExit("missing entities.json; run normalize (and optionally affiliations) first")
    run_export(repo, norm, pub)
    print(f"wrote {pub / 'intel_snapshot.json'} and {pub / 'block_candidates.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
