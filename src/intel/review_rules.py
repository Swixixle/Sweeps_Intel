"""
Deterministic review rules for staged research records.

Does not modify production schemas, affiliations scoring, or seeds.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from intel.schemas import SCHEMA_VERSION

REPO_ROOT = Path(__file__).resolve().parents[2]

OPERATOR_TERMS: tuple[str, ...] = (
    "sweeps",
    "social casino",
    "casino",
    "sportsbook",
    "slots",
    "poker",
    "sweepstakes game",
    "fish game",
    "gold coins",
    "sweeps coins",
    "sweeps cash",
    "no purchase necessary",
    "redeem",
    "cash prizes",
)
PROMOTER_TERMS: tuple[str, ...] = (
    "best casinos",
    "top sweeps",
    "reviews",
    "promo code",
    "affiliate",
    "bonus guide",
    "comparison",
)
PROVIDER_TERMS: tuple[str, ...] = (
    "game studio",
    "gaming supplier",
    "slot studio",
    " slot provider",
    "game provider",
    "studio ",
    "provider of",
)
PAYMENT_TERMS: tuple[str, ...] = (
    "wallet",
    "cashier",
    "deposit",
    "checkout",
    "payment",
    "redemption",
    "kyc",
)

WEAK_NOTE_MARKERS: tuple[str, ...] = (
    "not verified",
    "reported",
    "403",
    "inferred",
    "url pattern",
    "could not verify",
    "blocked",
)

SENSITIVE_FIELDS: frozenset[str] = frozenset(
    {"parent_company", "cashier_path", "analytics_ids", "support_widget", "provider_mentions"}
)

PLACEHOLDER_DOMAIN_FRAGMENTS: tuple[str, ...] = (
    "placeholder",
    "pending",
    "unknown",
    "tbd",
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _load_json(path: Path) -> Any:
    if not path.is_file():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _norm_blob(*parts: str | None) -> str:
    return " ".join(p.lower() for p in parts if p and str(p).strip()).strip()


def _norm_key(s: str | None) -> str:
    if not s or not isinstance(s, str):
        return ""
    return " ".join(s.lower().split()).strip()


def _domain_key(host: str | None) -> str:
    if not host or not str(host).strip():
        return ""
    d = str(host).strip().lower().rstrip(".")
    if "/" in d:
        d = d.split("/", 1)[0]
    if d.startswith("www."):
        d = d[4:]
    return d


def _hosts_from_seed_domain_cell(cell: str) -> list[str]:
    out: list[str] = []
    for seg in str(cell or "").split("|"):
        s = seg.strip()
        if not s:
            continue
        h = _domain_key(s.split("/", 1)[0])
        if h:
            out.append(h)
    return out


def _load_confirmed_operator_domains(repo_root: Path, norm_ents: list[Any]) -> frozenset[str]:
    """Active operator hostnames from seeds CSV and normalized entities."""
    confirmed: set[str] = set()
    csv_path = repo_root / "data" / "seeds" / "operators.csv"
    if csv_path.is_file():
        with csv_path.open(encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                st = (row.get("status") or "active").strip().lower()
                if st in ("inactive", "deprecated", "unknown"):
                    continue
                for h in _hosts_from_seed_domain_cell(row.get("domain") or ""):
                    confirmed.add(h)
    for e in norm_ents:
        if not isinstance(e, dict):
            continue
        if str(e.get("entity_type") or "") != "operator":
            continue
        st = str(e.get("status") or "active").strip().lower()
        if st in ("inactive", "deprecated"):
            continue
        for d in e.get("domains") or []:
            if isinstance(d, str) and d.strip():
                k = _domain_key(d)
                if k:
                    confirmed.add(k)
    return frozenset(confirmed)


def _index_extracted_fingerprints_by_domain(path: Path) -> dict[str, dict[str, Any]]:
    doc = _load_json(path)
    out: dict[str, dict[str, Any]] = {}
    if not isinstance(doc, dict):
        return out
    for fp in doc.get("fingerprints") or []:
        if isinstance(fp, dict) and fp.get("domain"):
            out[_domain_key(str(fp["domain"]))] = fp
    return out


def _fingerprint_text_blob(fp_rec: dict[str, Any]) -> str:
    inner = fp_rec.get("fingerprint") if isinstance(fp_rec.get("fingerprint"), dict) else fp_rec
    if not isinstance(inner, dict):
        return ""
    content = inner.get("content") or {}
    flow = inner.get("flow") or {}
    return _norm_blob(
        " ".join(content.get("title_terms") or []),
        " ".join(content.get("footer_phrases") or []),
        " ".join(content.get("bonus_terms") or []),
        " ".join(flow.get("cashier_paths") or []),
        " ".join(flow.get("redemption_paths") or []),
    )


def _domain_cluster_touches_confirmed(
    domain: str,
    staged_clusters: list[dict[str, Any]],
    confirmed_operator_domains: frozenset[str],
) -> bool:
    d = _domain_key(domain)
    if not d:
        return False
    for cl in staged_clusters:
        members = [_domain_key(str(m)) for m in (cl.get("members") or []) if m]
        if d not in members:
            continue
        if any(m in confirmed_operator_domains for m in members if m):
            return True
    return False


def _redirect_shell_from_notes(notes: str, sources: str, extra_blob: str = "") -> bool:
    b = _norm_blob(notes, sources, extra_blob)
    return any(
        x in b
        for x in (
            "redirect",
            "rebrand",
            "formerly ",
            "previously ",
            "moved to",
            "now at",
        )
    )


def _expand_legal_keys(legal: str) -> set[str]:
    out: set[str] = set()
    if not legal or not str(legal).strip():
        return out
    for part in re.split(r"[|;,]+", str(legal)):
        k = _norm_key(part)
        if k:
            out.add(k)
    return out


def _count_term_hits(blob: str, terms: tuple[str, ...]) -> int:
    if not blob:
        return 0
    n = 0
    for t in terms:
        if t in blob:
            n += 1
    return n


def _weak_notes_blob(notes: str, sources: str) -> bool:
    b = _norm_blob(notes, sources)
    return any(m in b for m in WEAK_NOTE_MARKERS)


def _placeholder_domain(domain: str | None) -> bool:
    if not domain or not str(domain).strip():
        return True
    d = domain.lower().strip().rstrip(".")
    if d in ("example.com", "example.org", "localhost", "invalid", "test"):
        return True
    if d.endswith(".example.com") or d.endswith(".example.org"):
        return True
    return any(p in d for p in PLACEHOLDER_DOMAIN_FRAGMENTS)


def _tier_base_level(tier: str | None) -> str:
    t = (tier or "").strip()
    if t == "first_party_verified":
        return "high"
    if t == "secondary_corroborated":
        return "medium"
    return "low"


def _downgrade_conf(base: str) -> str:
    if base == "high":
        return "medium"
    if base == "medium":
        return "low"
    return "low"


def _infer_likely_entity_type(
    blob: str,
    raw: dict[str, Any],
    *,
    promotes_count: int,
    uses_provider_count: int,
    domain: str,
    has_legal_anchor: bool = False,
) -> tuple[str, list[str]]:
    reasoning: list[str] = []
    scores: dict[str, int] = {
        "operator": 0,
        "promoter": 0,
        "provider": 0,
        "payment_path": 0,
    }

    raw_type = _norm_key(str(raw.get("entity_type") or raw.get("entity_type_hint") or ""))
    if raw_type == "provider":
        scores["provider"] += 6
        reasoning.append("rule:raw_entity_type_provider")

    if has_legal_anchor:
        scores["operator"] += 2
        reasoning.append("rule:legal_entity_anchor_operator_hint")

    if (raw.get("provider_type") or "").strip():
        scores["provider"] += 4
        reasoning.append("rule:provider_type_field_present")

    op_hits = _count_term_hits(blob, OPERATOR_TERMS)
    if op_hits:
        scores["operator"] += op_hits * 2
        reasoning.append(f"rule:operator_term_hits:{op_hits}")

    pr_hits = _count_term_hits(blob, PROMOTER_TERMS)
    if pr_hits:
        scores["promoter"] += pr_hits * 2
        reasoning.append(f"rule:promoter_term_hits:{pr_hits}")

    pv_hits = _count_term_hits(blob, PROVIDER_TERMS)
    if pv_hits:
        scores["provider"] += pv_hits * 2
        reasoning.append(f"rule:provider_term_hits:{pv_hits}")

    pay_hits = _count_term_hits(blob, PAYMENT_TERMS)
    if pay_hits:
        scores["payment_path"] += pay_hits * 2
        reasoning.append(f"rule:payment_term_hits:{pay_hits}")

    if raw.get("domain_or_pattern") or raw.get("path_patterns"):
        scores["payment_path"] += 5
        reasoning.append("rule:domain_or_pattern_fields")

    if "." not in domain and domain.strip():
        scores["payment_path"] += 3
        reasoning.append("rule:non_hostname_domain_shape")

    if promotes_count >= 2:
        scores["promoter"] += 6
        reasoning.append(f"rule:multiple_promote_targets:{promotes_count}")

    if uses_provider_count >= 2:
        scores["provider"] += 6
        reasoning.append(f"rule:multiple_uses_provider_refs:{uses_provider_count}")

    # Deterministic tie-break: prefer operator > provider > payment_path > promoter
    order = ("operator", "provider", "payment_path", "promoter")
    best_score = max(scores.values())
    if best_score == 0:
        reasoning.append("rule:insufficient_entity_type_signals")
        return "unknown", reasoning

    candidates = [k for k in order if scores[k] == best_score]
    best = candidates[0]
    reasoning.append(f"rule:selected_type:{best}_score_{best_score}")
    return best, reasoning


def _field_confidence_entity(
    ent: dict[str, Any],
    fp: dict[str, Any] | None,
    *,
    tier: str | None,
) -> dict[str, str]:
    notes = str(ent.get("notes") or "")
    sources = str(ent.get("sources") or "")
    weak = _weak_notes_blob(notes, sources)
    base = _tier_base_level(tier)

    def level(field: str, has_value: bool) -> str:
        if not has_value:
            return "low"
        lev = base
        if weak and field in SENSITIVE_FIELDS:
            lev = _downgrade_conf(lev)
        return lev

    out: dict[str, str] = {
        "legal_entity": level("legal_entity", bool((ent.get("legal_entity") or "").strip())),
        "parent_company": level("parent_company", bool((ent.get("parent_company") or "").strip())),
        "domain": level("domain", bool((ent.get("domain") or "").strip()) and not _placeholder_domain(ent.get("domain"))),
        "brand": level("brand", bool((ent.get("brand") or "").strip())),
        "jurisdiction": level("jurisdiction", bool((ent.get("jurisdiction") or "").strip())),
        "company_number": level("company_number", bool((ent.get("company_number") or "").strip())),
    }
    if fp:
        tech = fp.get("technical") or {}
        content = fp.get("content") or {}
        flow = fp.get("flow") or {}
        cashier = " ".join(flow.get("cashier_paths") or [])
        sw = " ".join(tech.get("support_widget_providers") or [])
        analytics = " ".join(tech.get("analytics_ids") or [])
        pm = " ".join(content.get("provider_mentions") or [])
        out["support_widget"] = level("support_widget", bool(sw.strip()))
        out["analytics_ids"] = level("analytics_ids", bool(analytics.strip()))
        out["provider_mentions"] = level("provider_mentions", bool(pm.strip()))
        out["cashier_path"] = level("cashier_path", bool(cashier.strip()))
    return dict(sorted(out.items()))


def _contradictory_type_signals(op_hits: int, pr_hits: int) -> bool:
    return op_hits >= 2 and pr_hits >= 2


def _promotion_recommendation(
    *,
    likely_type: str,
    tier: str | None,
    legal_present: bool,
    cluster_attach: bool,
    strong_staged_cluster: bool,
    domain_ok: bool,
    weak_blob: bool,
    contradictory: bool,
    little_signal: bool,
    notes: str,
) -> tuple[str, list[str]]:
    r: list[str] = []
    tier = tier or ""
    strong_tier = tier == "first_party_verified"
    ok_secondary = tier == "secondary_corroborated"
    strong_type = likely_type in ("operator", "promoter", "provider", "payment_path")
    notes_l = (notes or "").lower()

    if contradictory:
        r.append("rule:promotion_reject_contradictory_signals")
        return "reject_for_now", r
    if not domain_ok:
        r.append("rule:promotion_reject_domain_placeholder_or_missing")
        return "reject_for_now", r
    if "403" in notes_l and ok_secondary:
        r.append("rule:promotion_stage_403_secondary")
        return "stage_only", r
    if little_signal or likely_type == "unknown":
        if strong_staged_cluster and ok_secondary:
            r.append("rule:promotion_stage_unknown_but_cluster_and_secondary")
            return "stage_only", r
        r.append("rule:promotion_reject_weak_or_unknown")
        return "reject_for_now", r

    anchor = legal_present or cluster_attach or strong_staged_cluster

    if strong_tier and strong_type and anchor and not weak_blob:
        r.append("rule:promotion_promote_first_party_strong_anchor")
        return "promote_now", r

    if ok_secondary and strong_type and anchor and legal_present:
        r.append("rule:promotion_promote_secondary_with_legal_anchor")
        return "promote_now", r

    if strong_staged_cluster and strong_type and (strong_tier or ok_secondary):
        r.append("rule:promotion_promote_strong_cluster_multiple_signals")
        return "promote_now", r

    if weak_blob or tier == "inferred_or_unverified":
        r.append("rule:promotion_stage_mixed_or_inferred")
        return "stage_only", r

    if ok_secondary and not legal_present:
        r.append("rule:promotion_stage_secondary_without_legal")
        return "stage_only", r

    r.append("rule:promotion_stage_default")
    return "stage_only", r


def _build_norm_index(norm_ents: list[dict[str, Any]]) -> dict[str, Any]:
    legal_to_ids: dict[str, list[str]] = defaultdict(list)
    parent_to_ids: dict[str, list[str]] = defaultdict(list)
    domain_to_id: dict[str, str] = {}
    company_no_to_ids: dict[str, list[str]] = defaultdict(list)

    for e in norm_ents:
        if not isinstance(e, dict) or not e.get("id"):
            continue
        eid = str(e["id"])
        attrs = e.get("attributes") or {}
        if not isinstance(attrs, dict):
            attrs = {}
        le = attrs.get("legal_entity") or ""
        pc = attrs.get("parent_company") or ""
        for k in _expand_legal_keys(str(le)):
            legal_to_ids[k].append(eid)
        pk = _norm_key(str(pc))
        if pk:
            parent_to_ids[pk].append(eid)
        doms = e.get("domains") or []
        if doms and isinstance(doms[0], str):
            domain_to_id[doms[0].lower().strip()] = eid
        cn = str(attrs.get("company_number") or "").strip()
        if cn:
            company_no_to_ids[cn.lower()].append(eid)

    return {
        "legal_to_ids": {k: sorted(set(v)) for k, v in sorted(legal_to_ids.items())},
        "parent_to_ids": {k: sorted(set(v)) for k, v in sorted(parent_to_ids.items())},
        "domain_to_id": dict(sorted(domain_to_id.items())),
        "company_no_to_ids": {k: sorted(set(v)) for k, v in sorted(company_no_to_ids.items())},
    }


def _cluster_recommendation_for_domain(
    *,
    domain: str,
    legal: str,
    parent: str,
    company_number: str,
    norm_index: dict[str, Any],
    staged_clusters: list[dict[str, Any]],
) -> tuple[str, list[str]]:
    reasoning: list[str] = []
    d = domain.lower().strip()

    matched_ids: list[str] = []
    for k in _expand_legal_keys(legal):
        for eid in norm_index["legal_to_ids"].get(k, []):
            matched_ids.append(eid)
    matched_ids = sorted(set(matched_ids))
    if matched_ids:
        reasoning.append(f"rule:cluster_attach_shared_legal:{','.join(matched_ids)}")
        return "attach_to_existing_cluster", reasoning

    pk = _norm_key(parent)
    if pk:
        pids = norm_index["parent_to_ids"].get(pk, [])
        if pids:
            reasoning.append(f"rule:cluster_attach_shared_parent:{','.join(pids)}")
            return "attach_to_existing_cluster", reasoning

    cn = company_number.strip().lower()
    if cn:
        cids = norm_index["company_no_to_ids"].get(cn, [])
        if cids:
            reasoning.append(f"rule:cluster_attach_company_number:{','.join(cids)}")
            return "attach_to_existing_cluster", reasoning

    prod_domains = set(norm_index["domain_to_id"].keys())
    for cl in staged_clusters:
        members = [str(m).lower().strip() for m in (cl.get("members") or [])]
        if d not in members:
            continue
        if any(m in prod_domains for m in members):
            reasoning.append("rule:cluster_attach_staged_cluster_touches_production_domain")
            return "attach_to_existing_cluster", reasoning
        if len(members) >= 2:
            ev = cl.get("evidence") or []
            strong = any(
                (isinstance(x, dict) and x.get("reason") in ("discovery_redirect_chain", "affiliation_dump_pair"))
                for x in ev
            )
            if strong:
                reasoning.append("rule:cluster_attach_redirect_or_affiliation_evidence")
                return "attach_to_existing_cluster", reasoning
            reasoning.append("rule:cluster_create_new_staged_cluster_only")
            return "create_new_cluster_candidate", reasoning

    reasoning.append("rule:cluster_no_action")
    return "no_cluster_action", reasoning


def _block_recommendation(
    *,
    likely_type: str,
    tier: str | None,
    field_conf: dict[str, str],
    redirect_shell: bool,
    evidence_only_provider: bool,
    confirmed_operator_domain: bool,
    cluster_touches_confirmed_operator: bool,
    operator_term_hits: int,
) -> tuple[str, list[str]]:
    r: list[str] = []
    tier = tier or ""
    highish = field_conf.get("legal_entity") == "high" or tier == "first_party_verified"
    ok_secondary = tier == "secondary_corroborated"

    if evidence_only_provider and likely_type == "provider":
        r.append("rule:block_do_not_evidence_only_provider")
        return "do_not_block", r

    # Conservative: do not auto-block promoter / provider domains from this layer.
    if likely_type == "promoter":
        r.append("rule:block_do_not_promoter_listing_domain")
        return "do_not_block", r

    if likely_type == "provider":
        r.append("rule:block_do_not_provider_studio_domain")
        return "do_not_block", r

    if confirmed_operator_domain:
        r.append("rule:block_now_confirmed_operator_seed_or_catalog")
        return "block_now", r

    if likely_type == "operator" and tier == "first_party_verified":
        if redirect_shell:
            r.append("rule:block_now_redirect_shell_operator")
        r.append("rule:block_now_operator_first_party")
        return "block_now", r

    if (
        redirect_shell
        and likely_type == "operator"
        and (highish or ok_secondary or operator_term_hits >= 2)
    ):
        r.append("rule:block_now_redirect_shell_operator")
        return "block_now", r

    if redirect_shell and likely_type == "operator":
        r.append("rule:block_after_review_redirect_shell_operator")
        return "block_after_review", r

    if likely_type == "operator" and cluster_touches_confirmed_operator:
        r.append("rule:block_after_review_operator_cluster_known_family")
        return "block_after_review", r

    if likely_type == "operator" and operator_term_hits >= 4:
        r.append("rule:block_now_high_confidence_sweeps_operator_signals")
        return "block_now", r

    if likely_type == "operator" and operator_term_hits >= 2:
        r.append("rule:block_after_review_operator_sweeps_signals")
        return "block_after_review", r

    if likely_type == "operator":
        r.append("rule:block_after_review_operator_mixed")
        return "block_after_review", r

    r.append("rule:block_do_not_weak_or_unknown")
    return "do_not_block", r


def _relationship_indices(rels: list[dict[str, Any]]) -> tuple[dict[str, int], dict[str, int]]:
    promote_targets: dict[str, set[str]] = defaultdict(set)
    uses_pv: dict[str, int] = defaultdict(int)
    for rel in rels:
        if not isinstance(rel, dict):
            continue
        rt = str(rel.get("relationship") or "").lower()
        fc = str(rel.get("from_candidate_id") or rel.get("from_domain") or "").strip()
        fd = fc.lower()
        if not fd:
            continue
        tc = str(rel.get("to_candidate_id") or rel.get("to_domain") or "").strip().lower()
        if any(x in rt for x in ("promote", "link_to", "affiliate", "markets")):
            if tc:
                promote_targets[fd].add(tc)
        if "uses_provider" in rt or rt == "provider_of":
            uses_pv[fd] += 1
    promote_count = {k: len(v) for k, v in sorted(promote_targets.items())}
    return promote_count, dict(uses_pv)


def decision_for_staged_entity(
    ent: dict[str, Any],
    fp_by_cid: dict[str, dict[str, Any]],
    *,
    norm_index: dict[str, Any],
    staged_clusters: list[dict[str, Any]],
    rel_promotes: dict[str, int],
    rel_uses_provider: dict[str, int],
    confirmed_operator_domains: frozenset[str] | None = None,
) -> dict[str, Any]:
    confirmed = confirmed_operator_domains or frozenset()
    cid = str(ent.get("candidate_id") or "")
    domain = str(ent.get("domain") or "").strip()
    dom_key = _domain_key(domain)
    raw = ent.get("raw_row") if isinstance(ent.get("raw_row"), dict) else {}
    fp = fp_by_cid.get(cid)

    title_terms: list[str] = []
    footer: list[str] = []
    if fp:
        title_terms = list((fp.get("content") or {}).get("title_terms") or [])
        footer = list((fp.get("content") or {}).get("footer_phrases") or [])

    blob = _norm_blob(
        ent.get("notes"),
        ent.get("brand"),
        ent.get("legal_entity"),
        ent.get("parent_company"),
        " ".join(title_terms),
        " ".join(footer),
    )
    if fp:
        flow = fp.get("flow") or {}
        blob = _norm_blob(blob, " ".join(flow.get("cashier_paths") or []))

    promotes_n = max(rel_promotes.get(cid.lower(), 0), rel_promotes.get(domain.lower(), 0))
    uses_n = max(rel_uses_provider.get(cid.lower(), 0), rel_uses_provider.get(domain.lower(), 0))

    legal_present = bool(_norm_key(str(ent.get("legal_entity") or "")))

    likely_type, type_reasoning = _infer_likely_entity_type(
        blob,
        raw,
        promotes_count=promotes_n,
        uses_provider_count=uses_n,
        domain=domain,
        has_legal_anchor=legal_present,
    )

    if dom_key and dom_key in confirmed and str(raw.get("entity_type") or "").strip().lower() != "provider":
        if likely_type != "operator":
            type_reasoning.append("rule:confirmed_operator_catalog_override_type")
        likely_type = "operator"

    op_hits = _count_term_hits(blob, OPERATOR_TERMS)
    pr_hits = _count_term_hits(blob, PROMOTER_TERMS)
    contradictory = _contradictory_type_signals(op_hits, pr_hits) and dom_key not in confirmed

    tier = str(ent.get("evidence_tier") or "")
    fc = _field_confidence_entity(ent, fp, tier=tier)

    domain_ok = bool(domain) and not _placeholder_domain(domain)
    weak_blob = _weak_notes_blob(str(ent.get("notes") or ""), str(ent.get("sources") or ""))

    cluster_rec, cluster_reasoning = _cluster_recommendation_for_domain(
        domain=domain,
        legal=str(ent.get("legal_entity") or ""),
        parent=str(ent.get("parent_company") or ""),
        company_number=str(ent.get("company_number") or ""),
        norm_index=norm_index,
        staged_clusters=staged_clusters,
    )
    cluster_attach = cluster_rec == "attach_to_existing_cluster"
    strong_staged_cluster = cluster_rec == "create_new_cluster_candidate"

    little_signal = likely_type == "unknown" and not legal_present and not fp

    prom, prom_reasoning = _promotion_recommendation(
        likely_type=likely_type,
        tier=tier,
        legal_present=legal_present,
        cluster_attach=cluster_attach,
        strong_staged_cluster=strong_staged_cluster,
        domain_ok=domain_ok,
        weak_blob=weak_blob,
        contradictory=contradictory,
        little_signal=little_signal,
        notes=str(ent.get("notes") or ""),
    )

    notes_l = str(ent.get("notes") or "").lower()
    redirect_shell = _redirect_shell_from_notes(
        str(ent.get("notes") or ""),
        str(ent.get("sources") or ""),
        blob,
    )

    evidence_only = "evidence_only" in notes_l or "evidence only" in notes_l
    cluster_touch = _domain_cluster_touches_confirmed(domain, staged_clusters, confirmed)
    blk, blk_reasoning = _block_recommendation(
        likely_type=likely_type,
        tier=tier,
        field_conf=fc,
        redirect_shell=redirect_shell,
        evidence_only_provider=evidence_only,
        confirmed_operator_domain=bool(dom_key and dom_key in confirmed),
        cluster_touches_confirmed_operator=cluster_touch,
        operator_term_hits=op_hits,
    )

    reasoning = (
        type_reasoning
        + cluster_reasoning
        + prom_reasoning
        + blk_reasoning
        + ([f"rule:contradictory_operator_promoter_signals"] if contradictory else [])
    )

    return {
        "record_id": cid or domain or "unknown_entity",
        "source_type": "entity",
        "likely_entity_type": likely_type,
        "field_confidence": fc,
        "promotion_recommendation": prom,
        "cluster_recommendation": cluster_rec,
        "block_recommendation": blk,
        "reasoning": reasoning,
    }


def decision_for_fingerprint(fp: dict[str, Any]) -> dict[str, Any]:
    cid = str(fp.get("candidate_id") or "")
    tier = str(fp.get("evidence_tier") or "")
    weak_tier = tier in ("inferred_or_unverified", "inferred")
    tech = fp.get("technical") or {}
    content = fp.get("content") or {}
    flow = fp.get("flow") or {}
    blob = _norm_blob(
        " ".join(content.get("title_terms") or []),
        " ".join(content.get("footer_phrases") or []),
        " ".join(content.get("provider_mentions") or []),
        " ".join(flow.get("cashier_paths") or []),
    )
    raw: dict[str, Any] = {}
    likely_type, type_reasoning = _infer_likely_entity_type(
        blob, raw, promotes_count=0, uses_provider_count=0, domain=""
    )
    base = _tier_base_level(tier)
    has_cashier = bool(flow.get("cashier_paths"))
    fc = {
        "support_widget": base if tech.get("support_widget_providers") else "low",
        "analytics_ids": base if tech.get("analytics_ids") else "low",
        "provider_mentions": _downgrade_conf(base) if weak_tier else base,
        "cashier_path": (
            "low"
            if not has_cashier
            else (_downgrade_conf(base) if weak_tier else base)
        ),
        "script_domains": base if tech.get("script_domains") else "low",
    }
    fc = dict(sorted(fc.items()))
    prom = "reject_for_now"
    pr: list[str] = ["rule:fingerprint_orphan_reject_without_domain"]
    cluster_rec = "no_cluster_action"
    cr: list[str] = ["rule:fingerprint_no_domain_for_cluster"]
    blk = "do_not_block"
    br: list[str] = ["rule:fingerprint_not_a_standalone_block_target"]
    reasoning = type_reasoning + pr + cr + br
    return {
        "record_id": cid or "unknown_fp",
        "source_type": "fingerprint",
        "likely_entity_type": likely_type,
        "field_confidence": fc,
        "promotion_recommendation": prom,
        "cluster_recommendation": cluster_rec,
        "block_recommendation": blk,
        "reasoning": reasoning,
    }


def decision_for_relationship(rel: dict[str, Any], idx: int) -> dict[str, Any]:
    fc = str(rel.get("from_candidate_id") or "")
    tc = str(rel.get("to_candidate_id") or "")
    rid = f"{fc}->{tc}" if fc and tc else f"relationship_{idx:04d}"
    rt = str(rel.get("relationship") or "").lower()
    likely = "unknown"
    rs: list[str] = []
    if any(x in rt for x in ("promote", "affiliate", "link")):
        likely = "promoter"
        rs.append("rule:relationship_suggests_promoter_edge")
    elif "uses_provider" in rt or "provider" in rt:
        likely = "provider"
        rs.append("rule:relationship_suggests_provider_edge")
    tier = str(rel.get("evidence_tier") or "")
    base = _tier_base_level(tier)
    return {
        "record_id": rid,
        "source_type": "relationship",
        "likely_entity_type": likely,
        "field_confidence": {"relationship": base, "evidence": base},
        "promotion_recommendation": "stage_only",
        "cluster_recommendation": "no_cluster_action",
        "block_recommendation": "do_not_block",
        "reasoning": rs + ["rule:relationship_record_not_domain_blocklist"],
    }


def decision_for_cluster(
    cl: dict[str, Any],
    norm_index: dict[str, Any],
    *,
    confirmed_operator_domains: frozenset[str] | None = None,
) -> dict[str, Any]:
    confirmed = confirmed_operator_domains or frozenset()
    cid = str(cl.get("cluster_id") or "")
    members_raw = [str(m).lower().strip() for m in (cl.get("members") or [])]
    members = [_domain_key(m) for m in members_raw if m]
    prod = set(norm_index["domain_to_id"].keys())
    reasoning: list[str] = []
    if any(m in prod for m in members):
        cluster_rec = "attach_to_existing_cluster"
        reasoning.append("rule:cluster_doc_touches_production_domain")
    else:
        cluster_rec = "create_new_cluster_candidate"
        reasoning.append("rule:cluster_doc_staged_only_members")

    family_hit = any(m in confirmed for m in members) or any(m in prod for m in members)
    if family_hit:
        blk = "block_after_review"
        reasoning.append("rule:cluster_block_after_review_operator_family")
    else:
        blk = "do_not_block"
        reasoning.append("rule:cluster_block_not_operator_family")

    return {
        "record_id": cid or "unknown_cluster",
        "source_type": "cluster",
        "likely_entity_type": "unknown",
        "field_confidence": {"cluster_evidence": _tier_base_level(str(cl.get("evidence_tier") or "inferred"))},
        "promotion_recommendation": "stage_only",
        "cluster_recommendation": cluster_rec,
        "block_recommendation": blk,
        "reasoning": reasoning,
    }


def decision_for_review_queue_item(
    item: dict[str, Any],
    *,
    norm_index: dict[str, Any],
    confirmed_operator_domains: frozenset[str] | None = None,
    staged_clusters: list[dict[str, Any]] | None = None,
    extracted_by_domain: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    confirmed = confirmed_operator_domains or frozenset()
    clusters = staged_clusters or []
    ext = extracted_by_domain or {}
    kind = str(item.get("kind") or "")
    iid = str(item.get("id") or "")
    if not iid:
        return None
    if kind not in ("discovered_domain", "extracted_fingerprint"):
        return None

    domain = _domain_key(iid)
    pref = item.get("payload_ref") if isinstance(item.get("payload_ref"), dict) else {}
    pd = pref.get("domain") if pref.get("domain") else None
    if pd:
        domain = _domain_key(str(pd))
    if not domain:
        return None

    tier = str(item.get("evidence_tier") or "")
    base = _tier_base_level(tier)
    src_blob = _norm_blob(str(item.get("notes") or ""), str(item.get("sources") or ""))
    fp_blob = _fingerprint_text_blob(ext.get(domain, {}))
    blob = _norm_blob(src_blob, fp_blob)

    lt, tr = _infer_likely_entity_type(
        blob, {}, promotes_count=0, uses_provider_count=0, domain=domain, has_legal_anchor=False
    )
    if domain in confirmed:
        if lt != "operator":
            tr = tr + ["rule:confirmed_operator_catalog_override_type"]
        lt = "operator"

    op_hits = _count_term_hits(blob, OPERATOR_TERMS)
    pr_hits = _count_term_hits(blob, PROMOTER_TERMS)
    contradictory = _contradictory_type_signals(op_hits, pr_hits) and domain not in confirmed

    cluster_rec, cluster_rs = _cluster_recommendation_for_domain(
        domain=domain,
        legal="",
        parent="",
        company_number="",
        norm_index=norm_index,
        staged_clusters=clusters,
    )

    redirect_shell = _redirect_shell_from_notes(
        str(item.get("notes") or ""),
        str(item.get("sources") or ""),
        blob,
    )
    cluster_touch = _domain_cluster_touches_confirmed(domain, clusters, confirmed)

    fc = {"domain": base}
    blk, blk_r = _block_recommendation(
        likely_type=lt,
        tier=tier,
        field_conf=fc,
        redirect_shell=redirect_shell,
        evidence_only_provider=False,
        confirmed_operator_domain=domain in confirmed,
        cluster_touches_confirmed_operator=cluster_touch,
        operator_term_hits=op_hits,
    )

    if _placeholder_domain(domain):
        prom, prom_r = "reject_for_now", ["rule:queue_discovered_reject_placeholder"]
    else:
        prom, prom_r = _promotion_recommendation(
            likely_type=lt,
            tier=tier,
            legal_present=False,
            cluster_attach=cluster_rec == "attach_to_existing_cluster",
            strong_staged_cluster=cluster_rec == "create_new_cluster_candidate",
            domain_ok=True,
            weak_blob=_weak_notes_blob(str(item.get("notes") or ""), str(item.get("sources") or "")),
            contradictory=contradictory,
            little_signal=lt == "unknown" and op_hits == 0 and domain not in confirmed,
            notes=str(item.get("notes") or ""),
        )
        prom_r = ["rule:queue_research_item_stage"] + prom_r

    record_kind = "discovered_domain" if kind == "discovered_domain" else "extracted_fingerprint"
    return {
        "record_id": f"queue:{record_kind}:{domain}",
        "source_type": "entity",
        "likely_entity_type": lt,
        "field_confidence": fc,
        "promotion_recommendation": prom,
        "cluster_recommendation": cluster_rec,
        "block_recommendation": blk,
        "reasoning": tr + cluster_rs + prom_r + blk_r,
    }


def run_review_rules(repo_root: Path | None = None) -> dict[str, Any]:
    root = repo_root or REPO_ROOT
    rc = root / "data" / "research_candidates"
    ts = _utc_now_iso()

    norm_ents = _load_json(root / "data" / "normalized" / "entities.json")
    if not isinstance(norm_ents, list):
        norm_ents = []
    norm_index = _build_norm_index(norm_ents)

    staged_ent_doc = _load_json(rc / "staged_entities.json")
    entities: list[dict[str, Any]] = []
    if isinstance(staged_ent_doc, dict):
        entities = [e for e in (staged_ent_doc.get("entities") or []) if isinstance(e, dict)]

    staged_fp_doc = _load_json(rc / "staged_fingerprints.json")
    fingerprints: list[dict[str, Any]] = []
    if isinstance(staged_fp_doc, dict):
        fingerprints = [f for f in (staged_fp_doc.get("fingerprints") or []) if isinstance(f, dict)]

    staged_rel_doc = _load_json(rc / "staged_relationships.json")
    rels: list[dict[str, Any]] = []
    if isinstance(staged_rel_doc, dict):
        rels = [r for r in (staged_rel_doc.get("relationships") or []) if isinstance(r, dict)]

    staged_cl_doc = _load_json(rc / "staged_clusters.json")
    clusters: list[dict[str, Any]] = []
    if isinstance(staged_cl_doc, dict):
        clusters = [c for c in (staged_cl_doc.get("clusters") or []) if isinstance(c, dict)]

    fp_by_cid = {str(f.get("candidate_id")): f for f in fingerprints if f.get("candidate_id")}
    entity_cids = {str(e.get("candidate_id")) for e in entities if e.get("candidate_id")}

    rel_promotes, rel_uses = _relationship_indices(rels)

    confirmed = _load_confirmed_operator_domains(root, norm_ents)
    extracted_by_domain = _index_extracted_fingerprints_by_domain(rc / "extracted_fingerprints.json")

    decisions: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for ent in entities:
        d = decision_for_staged_entity(
            ent,
            fp_by_cid,
            norm_index=norm_index,
            staged_clusters=clusters,
            rel_promotes=rel_promotes,
            rel_uses_provider=rel_uses,
            confirmed_operator_domains=confirmed,
        )
        decisions.append(d)
        seen.add(("entity", d["record_id"]))

    for fp in fingerprints:
        cid = str(fp.get("candidate_id") or "")
        if cid and cid in entity_cids:
            continue
        d = decision_for_fingerprint(fp)
        decisions.append(d)
        seen.add(("fingerprint", d["record_id"]))

    for idx, rel in enumerate(rels):
        d = decision_for_relationship(rel, idx)
        decisions.append(d)
        seen.add(("relationship", d["record_id"]))

    for cl in clusters:
        d = decision_for_cluster(cl, norm_index, confirmed_operator_domains=confirmed)
        decisions.append(d)
        seen.add(("cluster", d["record_id"]))

    rq = _load_json(rc / "review_queue.json")
    if isinstance(rq, dict):
        for item in rq.get("items") or []:
            if not isinstance(item, dict):
                continue
            d = decision_for_review_queue_item(
                item,
                norm_index=norm_index,
                confirmed_operator_domains=confirmed,
                staged_clusters=clusters,
                extracted_by_domain=extracted_by_domain,
            )
            if not d:
                continue
            key = (str(d["source_type"]), str(d["record_id"]))
            if key in seen:
                continue
            decisions.append(d)
            seen.add(key)

    decisions.sort(key=lambda x: (x["source_type"], x["record_id"]))

    out_doc = {
        "generated_at": ts,
        "schema_version": SCHEMA_VERSION,
        "decision_count": len(decisions),
        "decisions": decisions,
    }
    out_path = rc / "review_decisions.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(out_doc, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")

    rep_dir = root / "reports" / "review_rules"
    rep_dir.mkdir(parents=True, exist_ok=True)
    tag = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    rep_path = rep_dir / f"review-rules-{tag}.json"
    summary = {
        "generated_at": ts,
        "schema_version": SCHEMA_VERSION,
        "decision_count": len(decisions),
        "by_promotion": _count_by_key(decisions, "promotion_recommendation"),
        "by_block": _count_by_key(decisions, "block_recommendation"),
        "by_entity_type": _count_by_key(decisions, "likely_entity_type"),
    }
    with rep_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")

    return {"output": str(out_path), "report": str(rep_path), "decision_count": len(decisions)}


def _count_by_key(decisions: list[dict[str, Any]], key: str) -> dict[str, int]:
    out: dict[str, int] = defaultdict(int)
    for d in decisions:
        out[str(d.get(key) or "")] += 1
    return dict(sorted(out.items()))


def main() -> None:
    ap = argparse.ArgumentParser(description="Apply deterministic review rules to staged research records.")
    ap.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    args = ap.parse_args()
    r = run_review_rules(args.repo_root.resolve())
    print(json.dumps(r, indent=2))


if __name__ == "__main__":
    main()
