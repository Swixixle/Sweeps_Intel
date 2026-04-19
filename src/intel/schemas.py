from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

# Bumped only when on-disk JSON shapes intentionally change.
SCHEMA_VERSION = "sweeps_intel_v1"

EntityType = Literal["operator", "promoter", "provider", "payment_path"]
EntityStatus = Literal["active", "inactive", "deprecated", "unknown"]
@dataclass
class Entity:
    id: str
    name: str
    entity_type: EntityType
    domains: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    status: EntityStatus = "active"
    confidence: float = 0.0
    sources: list[str] = field(default_factory=list)
    notes: str = ""
    first_seen: str = ""
    last_seen: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FingerprintTechnical:
    nameservers: list[str] = field(default_factory=list)
    registrar: str = ""
    ssl_issuers: list[str] = field(default_factory=list)
    analytics_ids: list[str] = field(default_factory=list)
    tag_manager_ids: list[str] = field(default_factory=list)
    script_domains: list[str] = field(default_factory=list)
    iframe_domains: list[str] = field(default_factory=list)
    asset_domains: list[str] = field(default_factory=list)
    support_widget_providers: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FingerprintContent:
    legal_entity_names: list[str] = field(default_factory=list)
    footer_phrases: list[str] = field(default_factory=list)
    title_terms: list[str] = field(default_factory=list)
    bonus_terms: list[str] = field(default_factory=list)
    provider_mentions: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FingerprintFlow:
    signup_paths: list[str] = field(default_factory=list)
    cashier_paths: list[str] = field(default_factory=list)
    redemption_paths: list[str] = field(default_factory=list)
    kyc_vendors: list[str] = field(default_factory=list)
    payment_providers: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FingerprintProviderSignals:
    provider_names: list[str] = field(default_factory=list)
    game_launcher_patterns: list[str] = field(default_factory=list)
    cdn_patterns: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Fingerprint:
    entity_id: str
    technical: FingerprintTechnical = field(default_factory=FingerprintTechnical)
    content: FingerprintContent = field(default_factory=FingerprintContent)
    flow: FingerprintFlow = field(default_factory=FingerprintFlow)
    provider_signals: FingerprintProviderSignals = field(default_factory=FingerprintProviderSignals)

    def to_json(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "technical": self.technical.to_json(),
            "content": self.content.to_json(),
            "flow": self.flow.to_json(),
            "provider_signals": self.provider_signals.to_json(),
        }


@dataclass
class RelationshipEvidence:
    url: str = ""
    anchor_text: str = ""

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Relationship:
    from_id: str
    to_id: str
    relationship: str
    confidence: float
    source: str
    evidence: RelationshipEvidence | None = None

    def to_json(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "from_id": self.from_id,
            "to_id": self.to_id,
            "relationship": self.relationship,
            "confidence": self.confidence,
            "source": self.source,
        }
        if self.evidence and (self.evidence.url or self.evidence.anchor_text):
            d["evidence"] = self.evidence.to_json()
        return d


@dataclass
class AffiliationEvidence:
    type: str
    value: str
    weight: int

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Affiliation:
    left_id: str
    right_id: str
    score: int
    label: str
    evidence: list[AffiliationEvidence]
    generated_at: str

    def to_json(self) -> dict[str, Any]:
        return {
            "left_id": self.left_id,
            "right_id": self.right_id,
            "score": self.score,
            "label": self.label,
            "evidence": [e.to_json() for e in self.evidence],
            "generated_at": self.generated_at,
        }


@dataclass
class CandidateRecord:
    domain: str
    suggested_types: list[str]
    seen_on_urls: list[str]
    first_seen: str
    last_seen: str
    confidence: float
    source_run: str
    notes: str = ""

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def empty_fingerprint(entity_id: str) -> Fingerprint:
    return Fingerprint(entity_id=entity_id)
