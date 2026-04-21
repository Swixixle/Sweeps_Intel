from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from ._signing import (
    SigningKeyError,
    load_private_key_pem,
    sign_envelope,
)


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


def run_export(
    repo_root: Path,
    normalized_dir: Path,
    published_dir: Path,
    *,
    sign_snapshot: bool = False,
    snapshot_private_key_path: Path | None = None,
    snapshot_key_id: str = "intel-snapshot-key-v1",
    sign_blocklist: bool = False,
    blocklist_private_key_path: Path | None = None,
    blocklist_key_id: str = "intel-blocklist-key-v1",
) -> None:
    generated_at = _utc_now_iso()
    entities = _load_json_list(normalized_dir / "entities.json")
    snapshot = build_intel_snapshot(normalized_dir, generated_at)
    block = build_block_candidates(entities, generated_at)
    published_dir.mkdir(parents=True, exist_ok=True)

    if sign_snapshot:
        if snapshot_private_key_path is None:
            raise SigningKeyError("sign_snapshot=True requires snapshot_private_key_path")
        sk = load_private_key_pem(snapshot_private_key_path)
        snap_payload = {**snapshot, "artifact_type": "intel_snapshot"}
        snap_out = sign_envelope(snap_payload, sk, snapshot_key_id)
        (published_dir / "intel_snapshot.json").write_text(
            json.dumps(snap_out, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    else:
        (published_dir / "intel_snapshot.json").write_text(
            json.dumps(snapshot, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    if sign_blocklist:
        if blocklist_private_key_path is None:
            raise SigningKeyError("sign_blocklist=True requires blocklist_private_key_path")
        bk = load_private_key_pem(blocklist_private_key_path)
        block_payload = {**block, "artifact_type": "intel_block_candidates"}
        block_out = sign_envelope(block_payload, bk, blocklist_key_id)
        (published_dir / "block_candidates.json").write_text(
            json.dumps(block_out, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    else:
        (published_dir / "block_candidates.json").write_text(
            json.dumps(block, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def main(argv: list[str] | None = None) -> int:
    from ._signing import generate_keypair

    p = argparse.ArgumentParser(description="Export intel_snapshot and block_candidates for downstream use.")
    p.add_argument("--repo-root", type=Path, default=Path.cwd())
    p.add_argument("--normalized", type=Path, default=None)
    p.add_argument("--published", type=Path, default=None)
    p.add_argument("--sign-snapshot", action="store_true", help="Sign intel_snapshot.json envelope.")
    p.add_argument("--snapshot-private-key", type=Path, default=None, help="Ed25519 private key PEM for snapshot.")
    p.add_argument("--snapshot-key-id", type=str, default="intel-snapshot-key-v1")
    p.add_argument("--sign-blocklist", action="store_true", help="Sign block_candidates.json envelope.")
    p.add_argument("--blocklist-private-key", type=Path, default=None, help="Ed25519 private key PEM for blocklist.")
    p.add_argument("--blocklist-key-id", type=str, default="intel-blocklist-key-v1")
    p.add_argument(
        "--generate-keypair-snapshot",
        type=Path,
        default=None,
        metavar="DIR",
        help="Write snapshot keypair to DIR (private.pem + public.pem) and exit.",
    )
    p.add_argument(
        "--generate-keypair-blocklist",
        type=Path,
        default=None,
        metavar="DIR",
        help="Write blocklist keypair to DIR (private.pem + public.pem) and exit.",
    )
    args = p.parse_args(argv)
    repo = args.repo_root.resolve()

    if args.generate_keypair_snapshot is not None:
        priv, pub = generate_keypair(args.generate_keypair_snapshot.resolve())
        print(f"generated snapshot keypair: {priv} (private), {pub} (public)")
    if args.generate_keypair_blocklist is not None:
        priv, pub = generate_keypair(args.generate_keypair_blocklist.resolve())
        print(f"generated blocklist keypair: {priv} (private), {pub} (public)")
    if args.generate_keypair_snapshot is not None or args.generate_keypair_blocklist is not None:
        return 0

    norm = args.normalized or (repo / "data" / "normalized")
    pub = args.published or (repo / "data" / "published")
    if not (norm / "entities.json").exists():
        raise SystemExit("missing entities.json; run normalize (and optionally affiliations) first")
    run_export(
        repo,
        norm,
        pub,
        sign_snapshot=args.sign_snapshot,
        snapshot_private_key_path=args.snapshot_private_key.resolve() if args.snapshot_private_key else None,
        snapshot_key_id=args.snapshot_key_id,
        sign_blocklist=args.sign_blocklist,
        blocklist_private_key_path=args.blocklist_private_key.resolve() if args.blocklist_private_key else None,
        blocklist_key_id=args.blocklist_key_id,
    )
    print(f"wrote {pub / 'intel_snapshot.json'} and {pub / 'block_candidates.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
