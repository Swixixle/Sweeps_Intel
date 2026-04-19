from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .enrich import dedupe_sorted_strings, extract_signals_from_html, normalize_fingerprint_dict
from .research_html import ADDRESS_HINT, EMAIL_RE, LEGAL_PATH, collect_links, fetch_url, normalize_host
from .stage_research_import import classify_evidence_tier


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _provider_names_from_entities(path: Path) -> list[str]:
    if not path.exists():
        return []
    entities = json.loads(path.read_text(encoding="utf-8"))
    names: list[str] = []
    for e in entities:
        if e.get("entity_type") == "provider":
            n = e.get("name") or ""
            if n.strip():
                names.append(n.strip())
    return sorted(set(names), key=str.lower)


def _legal_and_support_urls(html: str, base_url: str) -> tuple[list[str], list[str]]:
    legal: list[str] = []
    support: list[str] = []
    for u in collect_links(html, base_url, max_links=400):
        try:
            p = urlparse(u)
            path_q = f"{p.path} {p.query}".lower()
            host = (p.netloc or "").lower()
        except Exception:
            continue
        if LEGAL_PATH.search(path_q) or LEGAL_PATH.search(u.lower()):
            legal.append(u)
        if any(x in host for x in ("helpshift", "zendesk", "intercom", "freshdesk")):
            support.append(u)
    return dedupe_sorted_strings(legal, lower=False), dedupe_sorted_strings(support, lower=False)


def _merge_fp_base(domain: str, extracted: dict) -> dict:
    fp = {
        "entity_id": f"extracted::{domain}",
        "technical": {
            "nameservers": [],
            "registrar": "",
            "ssl_issuers": [],
            "analytics_ids": list(extracted.get("technical", {}).get("analytics_ids") or []),
            "tag_manager_ids": list(extracted.get("technical", {}).get("tag_manager_ids") or []),
            "script_domains": list(extracted.get("technical", {}).get("script_domains") or []),
            "iframe_domains": list(extracted.get("technical", {}).get("iframe_domains") or []),
            "asset_domains": list(extracted.get("technical", {}).get("asset_domains") or []),
            "support_widget_providers": list(
                extracted.get("technical", {}).get("support_widget_providers") or []
            ),
        },
        "content": {
            "legal_entity_names": [],
            "footer_phrases": list(extracted.get("content", {}).get("footer_phrases") or []),
            "title_terms": list(extracted.get("content", {}).get("title_terms") or []),
            "bonus_terms": list(extracted.get("content", {}).get("bonus_terms") or []),
            "provider_mentions": list(extracted.get("content", {}).get("provider_mentions") or []),
        },
        "flow": {
            "signup_paths": list(extracted.get("flow", {}).get("signup_paths") or []),
            "cashier_paths": list(extracted.get("flow", {}).get("cashier_paths") or []),
            "redemption_paths": list(extracted.get("flow", {}).get("redemption_paths") or []),
            "kyc_vendors": [],
            "payment_providers": [],
        },
        "provider_signals": {
            "provider_names": list(
                (extracted.get("provider_signals") or {}).get("provider_names") or []
            ),
            "game_launcher_patterns": list(
                (extracted.get("provider_signals") or {}).get("game_launcher_patterns") or []
            ),
            "cdn_patterns": list((extracted.get("provider_signals") or {}).get("cdn_patterns") or []),
        },
    }
    return normalize_fingerprint_dict(fp)


def run_extract(
    repo_root: Path,
    urls: list[str],
    *,
    normalized_dir: Path,
    research_dir: Path,
    reports_dir: Path,
    limit: int,
) -> dict:
    ts = _utc_now_iso()
    providers = _provider_names_from_entities(normalized_dir / "entities.json")
    fingerprints_out: list[dict] = []
    entities_out: list[dict] = []
    report_pages: list[dict] = []

    for i, url in enumerate(urls[:limit]):
        if not url.strip():
            continue
        final, html, status = fetch_url(url.strip())
        if not html or status < 0:
            report_pages.append({"url": url, "final_url": final, "status": status, "error": "no_html"})
            continue
        base = final or url
        ext = extract_signals_from_html(html, base, providers)
        legal_urls, support_urls = _legal_and_support_urls(html, base)
        emails = sorted(set(EMAIL_RE.findall(html)))[:20]
        addr_hints = sorted(set(m.group(0) for m in ADDRESS_HINT.finditer(html)))[:10]

        notes = f"extract status={status} final={base}"
        tier = classify_evidence_tier(notes, url)

        dom = normalize_host(base)
        if not dom:
            continue

        fp_merged = _merge_fp_base(dom, ext)
        rec = {
            "domain": dom,
            "source_url": url.strip(),
            "final_url": base,
            "http_status": status,
            "review_status": "needs_review",
            "evidence_tier": tier,
            "fingerprint": fp_merged,
            "legal_policy_urls": legal_urls,
            "support_help_urls": support_urls,
            "contact_emails": emails,
            "mailing_address_hints": addr_hints,
            "extracted_at": ts,
        }
        fingerprints_out.append(rec)
        entities_out.append(
            {
                "domain": dom,
                "suggested_name": dom.split(".")[0].title(),
                "source_url": url.strip(),
                "review_status": "needs_review",
                "evidence_tier": tier,
                "extracted_at": ts,
            }
        )
        report_pages.append({"url": url, "final_url": base, "status": status, "domain": dom})

    research_dir.mkdir(parents=True, exist_ok=True)
    meta = {"generated_at": ts, "count": len(fingerprints_out)}
    (research_dir / "extracted_fingerprints.json").write_text(
        json.dumps({"fingerprints": fingerprints_out, **meta}, indent=2) + "\n",
        encoding="utf-8",
    )
    (research_dir / "extracted_entities.json").write_text(
        json.dumps({"entities": entities_out, **meta}, indent=2) + "\n",
        encoding="utf-8",
    )

    rep_dir = reports_dir / "extraction"
    rep_dir.mkdir(parents=True, exist_ok=True)
    tag = ts.replace(":", "")
    rep = {"generated_at": ts, "urls_attempted": len(urls[:limit]), "succeeded": len(fingerprints_out), "pages": report_pages}
    rep_path = rep_dir / f"extract-{tag}.json"
    rep_path.write_text(json.dumps(rep, indent=2) + "\n", encoding="utf-8")
    return {"report_path": str(rep_path)}


def _urls_from_discovered(candidates_dir: Path, limit: int) -> list[str]:
    """Build URL list from discover outputs: domains plus page request/final URLs."""
    seen: set[str] = set()
    ordered: list[str] = []

    def add(u: str) -> None:
        u = u.strip()
        if not u or u in seen:
            return
        seen.add(u)
        ordered.append(u)

    p = candidates_dir / "discovered_domains.json"
    if p.exists():
        rows = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(rows, list):
            for r in rows:
                if not isinstance(r, dict):
                    continue
                d = r.get("domain")
                if d and str(d).strip():
                    add(f"https://{str(d).strip().rstrip('/')}/")

    pp = candidates_dir / "discovered_pages.json"
    if pp.exists():
        pages = json.loads(pp.read_text(encoding="utf-8"))
        if isinstance(pages, list):
            for row in pages:
                if not isinstance(row, dict):
                    continue
                for key in ("final_url", "requested_url"):
                    u = row.get(key)
                    if u and str(u).strip().lower().startswith(("http://", "https://")):
                        add(str(u).strip())

    return ordered[:limit]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Extract fingerprint signals from URLs (research only).")
    p.add_argument("--repo-root", type=Path, default=Path.cwd())
    p.add_argument("--urls-file", type=Path, default=None, help="One URL per line")
    p.add_argument(
        "--from-discovered",
        action="store_true",
        help="Use discovered_domains.json and discovered_pages.json under data/candidates/",
    )
    p.add_argument("--limit", type=int, default=30)
    p.add_argument("--normalized", type=Path, default=None)
    p.add_argument("--research-dir", type=Path, default=None)
    p.add_argument("--reports-dir", type=Path, default=None)
    args = p.parse_args(argv)
    repo = args.repo_root.resolve()
    norm = args.normalized or (repo / "data" / "normalized")
    rd = args.research_dir or (repo / "data" / "research_candidates")
    reps = args.reports_dir or (repo / "reports")
    urls: list[str] = []
    if args.urls_file and args.urls_file.exists():
        for ln in args.urls_file.read_text(encoding="utf-8").splitlines():
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            urls.append(s)
    if args.from_discovered:
        urls.extend(_urls_from_discovered(repo / "data" / "candidates", args.limit))
    if not urls:
        print("error: no URLs (use --urls-file and/or --from-discovered)", file=sys.stderr)
        return 1
    r = run_extract(repo, urls, normalized_dir=norm, research_dir=rd, reports_dir=reps, limit=args.limit)
    print(f"wrote extracted_*.json under {rd}")
    print(f"wrote {r['report_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
