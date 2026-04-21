#!/usr/bin/env python3
"""Emit a trust_store.json key entry from a PEM public key file (stdlib only)."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def _issued_at_default() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_and_read_pem(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"error: PEM file not found: {path}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"error: cannot read PEM file {path}: {e}", file=sys.stderr)
        sys.exit(1)
    if "-----BEGIN PUBLIC KEY-----" not in text or "-----END PUBLIC KEY-----" not in text:
        print(
            "error: not a PEM public key file "
            "(expected -----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----)",
            file=sys.stderr,
        )
        sys.exit(1)
    return text


def main() -> None:
    p = argparse.ArgumentParser(
        description="Print a trust_store.json key entry for a public.pem (JSON to stdout)."
    )
    p.add_argument("--pem", type=Path, required=True, help="Path to public.pem")
    p.add_argument("--key-id", required=True, help="Key identifier (e.g. intel-snapshot-key-v1)")
    p.add_argument(
        "--authorized-for",
        dest="authorized_for",
        nargs="+",
        required=True,
        metavar="PURPOSE",
        help="One or more artifact purposes this key may sign for",
    )
    p.add_argument(
        "--issued-at",
        dest="issued_at",
        default=None,
        metavar="ISO_UTC",
        help="Issue time (default: current UTC, format YYYY-MM-DDTHH:MM:SSZ)",
    )
    args = p.parse_args()

    pem_text = _validate_and_read_pem(args.pem.resolve())
    issued = args.issued_at if args.issued_at is not None else _issued_at_default()

    entry: dict[str, object] = {
        "key_id": args.key_id,
        "algorithm": "ed25519",
        "public_key_pem": pem_text,
        "issued_at": issued,
        "authorized_for": list(args.authorized_for),
        "revoked_at": None,
        "revocation_reason": None,
    }

    out = json.dumps(entry, indent=2, ensure_ascii=True)
    sys.stdout.write(out)
    if not out.endswith("\n"):
        sys.stdout.write("\n")


if __name__ == "__main__":
    main()
