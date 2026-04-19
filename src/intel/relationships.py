from __future__ import annotations

from collections.abc import Iterable

from .schemas import Relationship


def validate_relationships(
    rels: Iterable[Relationship],
    known_ids: set[str],
) -> tuple[list[Relationship], list[str]]:
    """Drop edges with missing endpoints; return (kept, errors)."""
    kept: list[Relationship] = []
    errors: list[str] = []
    for r in rels:
        if r.from_id not in known_ids:
            errors.append(f"unknown from_id {r.from_id!r} in relationship")
            continue
        if r.to_id not in known_ids:
            errors.append(f"unknown to_id {r.to_id!r} in relationship")
            continue
        kept.append(r)
    return kept, errors


def merge_relationships(
    base: list[Relationship],
    extra: list[Relationship],
) -> list[Relationship]:
    """Union by (from_id, to_id, relationship, source)."""
    seen: set[tuple[str, str, str, str]] = set()
    out: list[Relationship] = []
    for r in base + extra:
        k = (r.from_id, r.to_id, r.relationship, r.source)
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
    return out
