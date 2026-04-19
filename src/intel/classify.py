from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Kind = Literal["operator", "promoter", "provider", "payment_path", "unknown"]


@dataclass(frozen=True)
class DomainHit:
    kind: Kind
    entity_id: str
    name: str


class DomainIndex:
    """Maps registrable domain -> known entity (first match wins on conflict)."""

    def __init__(self, entities: list[dict]) -> None:
        self._map: dict[str, DomainHit] = {}
        for e in entities:
            et = e.get("entity_type")
            if et not in {"operator", "promoter", "provider", "payment_path"}:
                continue
            eid = e.get("id")
            name = e.get("name") or eid
            for d in e.get("domains") or []:
                if not d:
                    continue
                self._map.setdefault(d, DomainHit(et, eid, name))  # type: ignore[arg-type]

    def lookup(self, domain: str) -> DomainHit | None:
        return self._map.get(domain)

    def known_domains(self) -> frozenset[str]:
        return frozenset(self._map.keys())
