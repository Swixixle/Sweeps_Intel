from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from .schemas import Affiliation, AffiliationEvidence
from .scout_fingerprint_loader import iter_signal_pairs, load_fingerprints

# Scout TLS / DNS signal weights (pairwise domain-level affiliations from Scout fingerprints).
# These sit alongside run_affiliations() entity-pair weights (50 legal, 40 analytics, 20 provider,
# 15 cashier, 10 script/promoter, 5 registrar/NS). Reciprocal cross-SAN is the strongest
# independent tie we add here; one-way SAN is a hint; filtered NS/MX are corroborating only.
SCOUT_SIGNAL_WEIGHT_TLS_SAN_RECIPROCAL = 15
SCOUT_SIGNAL_WEIGHT_TLS_SAN_ONE_WAY = 7
SCOUT_SIGNAL_WEIGHT_SHARED_NS_FILTERED = 5
SCOUT_SIGNAL_WEIGHT_SHARED_MX_FILTERED = 4

SCOUT_SIGNAL_WEIGHTS: dict[str, int] = {
    "tls_san_reciprocal": SCOUT_SIGNAL_WEIGHT_TLS_SAN_RECIPROCAL,
    "tls_san_one_way": SCOUT_SIGNAL_WEIGHT_TLS_SAN_ONE_WAY,
    "shared_nameserver_filtered": SCOUT_SIGNAL_WEIGHT_SHARED_NS_FILTERED,
    "shared_mx_filtered": SCOUT_SIGNAL_WEIGHT_SHARED_MX_FILTERED,
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _norm_legal(raw: str) -> str:
    return " ".join(raw.lower().split())


def _label_for_score(score: int) -> str:
    if score >= 80:
        return "likely_same_network"
    if score >= 50:
        return "strong_affiliation"
    if score >= 25:
        return "possible_affiliation"
    return "weak_signal"


def _collect_provider_tokens(entity: dict, fp: dict | None) -> set[str]:
    attrs = entity.get("attributes") or {}
    names: set[str] = set()
    for x in attrs.get("provider_names") or []:
        if isinstance(x, str) and x.strip():
            names.add(x.strip().lower())
    if fp:
        content = fp.get("content") or {}
        for x in content.get("provider_mentions") or []:
            if isinstance(x, str) and x.strip():
                names.add(x.strip().lower())
        ps = fp.get("provider_signals") or {}
        for x in ps.get("provider_names") or []:
            if isinstance(x, str) and x.strip():
                names.add(x.strip().lower())
    if entity.get("entity_type") == "provider":
        n = entity.get("name") or ""
        if n.strip():
            names.add(n.strip().lower())
    return names


def _tech_sets(fp: dict) -> tuple[set[str], set[str], set[str], str, set[str]]:
    tech = fp.get("technical") or {}
    analytics = set(str(x) for x in (tech.get("analytics_ids") or []) if x)
    tags = set(str(x) for x in (tech.get("tag_manager_ids") or []) if x)
    ns = set(str(x).lower() for x in (tech.get("nameservers") or []) if x)
    registrar = str(tech.get("registrar") or "").strip().lower()
    scripts_assets_widgets = set()
    for x in tech.get("script_domains") or []:
        if x:
            scripts_assets_widgets.add(str(x).lower())
    for x in tech.get("asset_domains") or []:
        if x:
            scripts_assets_widgets.add(str(x).lower())
    for x in tech.get("support_widget_providers") or []:
        if x:
            scripts_assets_widgets.add(str(x).lower())
    return analytics, tags, ns, registrar, scripts_assets_widgets


def _flow_paths(fp: dict) -> set[str]:
    flow = fp.get("flow") or {}
    out: set[str] = set()
    for key in ("cashier_paths", "redemption_paths", "signup_paths"):
        for x in flow.get(key) or []:
            if x:
                out.add(str(x).lower())
    return out


def run_affiliations(normalized_dir: Path, out_path: Path) -> None:
    entities: list[dict] = json.loads((normalized_dir / "entities.json").read_text(encoding="utf-8"))
    fps: list[dict] = json.loads((normalized_dir / "fingerprints.json").read_text(encoding="utf-8"))
    rels: list[dict] = json.loads((normalized_dir / "relationships.json").read_text(encoding="utf-8"))

    by_id: dict[str, dict] = {e["id"]: e for e in entities}
    fp_by_entity: dict[str, dict] = {f["entity_id"]: f for f in fps}

    targets_to_promoters: dict[str, set[str]] = {}
    operator_to_providers: dict[str, set[str]] = {}
    for r in rels:
        if r.get("relationship") == "promotes":
            targets_to_promoters.setdefault(r["to_id"], set()).add(r["from_id"])
        if r.get("relationship") == "uses_provider":
            operator_to_providers.setdefault(r["from_id"], set()).add(r["to_id"])

    generated_at = _utc_now_iso()
    results: list[Affiliation] = []

    ids = [e["id"] for e in entities if (e.get("status") == "active")]
    for i, left_id in enumerate(ids):
        for right_id in ids[i + 1 :]:
            a = by_id.get(left_id)
            b = by_id.get(right_id)
            if not a or not b:
                continue
            fa = fp_by_entity.get(left_id)
            fb = fp_by_entity.get(right_id)

            evidence: list[AffiliationEvidence] = []
            score = 0

            la = str((a.get("attributes") or {}).get("legal_entity") or "").strip()
            lb = str((b.get("attributes") or {}).get("legal_entity") or "").strip()
            if la and lb and _norm_legal(la) == _norm_legal(lb):
                score += 50
                evidence.append(AffiliationEvidence(type="shared_legal_entity", value=la, weight=50))

            if fa and fb:
                aa, ta, nsa, rega, mixa = _tech_sets(fa)
                ab, tb, nsb, regb, mixb = _tech_sets(fb)
                shared_ids = (aa | ta) & (ab | tb)
                if shared_ids:
                    score += 40
                    evidence.append(
                        AffiliationEvidence(
                            type="shared_analytics_or_tag",
                            value=sorted(shared_ids)[0],
                            weight=40,
                        )
                    )

            prov_a = _collect_provider_tokens(a, fa)
            prov_b = _collect_provider_tokens(b, fb)
            overlap = prov_a & prov_b
            if overlap:
                score += 20
                evidence.append(
                    AffiliationEvidence(type="shared_provider", value=sorted(overlap)[0], weight=20)
                )

            shared_prov_entities = operator_to_providers.get(left_id, set()) & operator_to_providers.get(
                right_id, set()
            )
            if shared_prov_entities and not overlap:
                score += 20
                evidence.append(
                    AffiliationEvidence(
                        type="shared_provider",
                        value=sorted(shared_prov_entities)[0],
                        weight=20,
                    )
                )

            if fa and fb:
                pa, pb = _flow_paths(fa), _flow_paths(fb)
                shared_flow = pa & pb
                if shared_flow:
                    score += 15
                    evidence.append(
                        AffiliationEvidence(
                            type="shared_cashier_pattern",
                            value=sorted(shared_flow)[0],
                            weight=15,
                        )
                    )

            if fa and fb:
                _, _, _, _, mixa = _tech_sets(fa)
                _, _, _, _, mixb = _tech_sets(fb)
                shared_mix = mixa & mixb
                if shared_mix:
                    score += 10
                    evidence.append(
                        AffiliationEvidence(
                            type="shared_script_cdn_or_widget",
                            value=sorted(shared_mix)[0],
                            weight=10,
                        )
                    )

            prom_a = targets_to_promoters.get(left_id, set())
            prom_b = targets_to_promoters.get(right_id, set())
            shared_prom = prom_a & prom_b
            if shared_prom:
                score += 10
                evidence.append(
                    AffiliationEvidence(
                        type="shared_promoter_cluster",
                        value=sorted(shared_prom)[0],
                        weight=10,
                    )
                )

            if fa and fb:
                _, _, nsa, rega, _ = _tech_sets(fa)
                _, _, nsb, regb, _ = _tech_sets(fb)
                if rega and regb and rega == regb:
                    score += 5
                    evidence.append(AffiliationEvidence(type="shared_registrar", value=rega, weight=5))
                elif nsa and nsb and (nsa & nsb):
                    score += 5
                    evidence.append(
                        AffiliationEvidence(
                            type="shared_nameserver",
                            value=sorted(nsa & nsb)[0],
                            weight=5,
                        )
                    )

            score = min(score, 100)
            if score <= 0:
                continue

            results.append(
                Affiliation(
                    left_id=left_id,
                    right_id=right_id,
                    score=score,
                    label=_label_for_score(score),
                    evidence=evidence,
                    generated_at=generated_at,
                )
            )

    results.sort(key=lambda x: (-x.score, x.left_id, x.right_id))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps([r.to_json() for r in results], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _evidence_value_for_scout_detail(signal_type: str, detail: dict) -> str:
    if signal_type == "tls_san_reciprocal":
        return f"{detail.get('domain_a')}|{detail.get('domain_b')}|reciprocal_san"
    if signal_type == "tls_san_one_way":
        return f"{detail.get('domain_a')}|{detail.get('domain_b')}|one_way_san"
    if signal_type == "shared_nameserver_filtered":
        shared = detail.get("shared_nameservers") or []
        return str(shared[0]) if shared else "shared_ns"
    if signal_type == "shared_mx_filtered":
        shared = detail.get("shared_mx_hosts") or []
        return str(shared[0]) if shared else "shared_mx"
    return json.dumps(detail, sort_keys=True)


def build_affiliations_from_scout_fingerprints(fingerprints_path: Path) -> list[Affiliation]:
    """Pairwise ``Affiliation`` rows from Scout domain fingerprints (domain ids, not entity slugs)."""
    fps = load_fingerprints(fingerprints_path)
    generated_at = _utc_now_iso()
    aggregated: dict[tuple[str, str], list[tuple[str, dict, int]]] = {}

    for da, db, signal_type, detail in iter_signal_pairs(fps):
        weight = SCOUT_SIGNAL_WEIGHTS.get(signal_type)
        if weight is None:
            continue
        key = (da, db) if da <= db else (db, da)
        aggregated.setdefault(key, []).append((signal_type, detail, weight))

    results: list[Affiliation] = []
    for (left_domain, right_domain), items in sorted(aggregated.items()):
        evidence: list[AffiliationEvidence] = []
        score = 0
        for signal_type, detail, weight in sorted(items, key=lambda x: x[0]):
            evidence.append(
                AffiliationEvidence(
                    type=signal_type,
                    value=_evidence_value_for_scout_detail(signal_type, detail),
                    weight=weight,
                )
            )
            score += weight
        score = min(score, 100)
        if score <= 0:
            continue
        results.append(
            Affiliation(
                left_id=left_domain,
                right_id=right_domain,
                score=score,
                label=_label_for_score(score),
                evidence=evidence,
                generated_at=generated_at,
            )
        )

    results.sort(key=lambda x: (-x.score, x.left_id, x.right_id))
    return results


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Score pairwise entity affiliations into affiliations.json.")
    p.add_argument("--repo-root", type=Path, default=Path.cwd())
    p.add_argument("--normalized", type=Path, default=None)
    p.add_argument("--out", type=Path, default=None)
    args = p.parse_args(argv)
    repo = args.repo_root.resolve()
    norm = args.normalized or (repo / "data" / "normalized")
    out = args.out or (norm / "affiliations.json")
    if not (norm / "entities.json").exists():
        raise SystemExit("missing entities.json; run normalize first")
    run_affiliations(norm, out)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
