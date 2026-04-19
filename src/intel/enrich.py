from __future__ import annotations

import argparse
import csv
import json
import re
from copy import deepcopy
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

TECH_STRING_LIST_KEYS = (
    "analytics_ids",
    "tag_manager_ids",
    "script_domains",
    "iframe_domains",
    "asset_domains",
    "support_widget_providers",
)
CONTENT_LIST_KEYS = (
    "legal_entity_names",
    "footer_phrases",
    "title_terms",
    "bonus_terms",
    "provider_mentions",
)
FLOW_LIST_KEYS = (
    "signup_paths",
    "cashier_paths",
    "redemption_paths",
    "kyc_vendors",
    "payment_providers",
)
PROVIDER_SIG_LIST_KEYS = (
    "provider_names",
    "game_launcher_patterns",
    "cdn_patterns",
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _split_pipe_cell(raw: str) -> list[str]:
    if not raw or not str(raw).strip():
        return []
    return [p.strip() for p in str(raw).split("|") if p.strip()]


def normalize_host_from_url(url: str) -> str | None:
    try:
        p = urlparse(url)
    except Exception:
        return None
    if not p.netloc:
        return None
    host = p.netloc.split("@")[-1].split(":")[0].lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host or None


def dedupe_sorted_strings(values: list[str], *, lower: bool = False) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        if not v or not str(v).strip():
            continue
        s = str(v).strip()
        key = s.lower() if lower else s
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return sorted(out, key=lambda x: x.lower())


def merge_string_lists(existing: list[str], additions: list[str], *, lower_domains: bool = False) -> list[str]:
    """Union existing + additions; additions must be non-empty strings. Deterministic sort."""
    acc: list[str] = []
    for x in existing or []:
        if x is None:
            continue
        s = str(x).strip()
        if not s:
            continue
        acc.append(s.lower() if lower_domains else s)
    for a in additions or []:
        if a is None:
            continue
        s = str(a).strip()
        if not s:
            continue
        acc.append(s.lower() if lower_domains else s)
    return dedupe_sorted_strings(acc, lower=lower_domains)


def empty_fingerprint_dict(entity_id: str) -> dict:
    return {
        "entity_id": entity_id,
        "technical": {
            "nameservers": [],
            "registrar": "",
            "ssl_issuers": [],
            "analytics_ids": [],
            "tag_manager_ids": [],
            "script_domains": [],
            "iframe_domains": [],
            "asset_domains": [],
            "support_widget_providers": [],
        },
        "content": {
            "legal_entity_names": [],
            "footer_phrases": [],
            "title_terms": [],
            "bonus_terms": [],
            "provider_mentions": [],
        },
        "flow": {
            "signup_paths": [],
            "cashier_paths": [],
            "redemption_paths": [],
            "kyc_vendors": [],
            "payment_providers": [],
        },
        "provider_signals": {
            "provider_names": [],
            "game_launcher_patterns": [],
            "cdn_patterns": [],
        },
    }


def normalize_fingerprint_dict(fp: dict) -> dict:
    """Sort all list fields in place for deterministic JSON."""
    tech = fp.get("technical") or {}
    for k in TECH_STRING_LIST_KEYS:
        if k in tech:
            tech[k] = dedupe_sorted_strings([str(x) for x in (tech.get(k) or []) if x])
    fp["technical"] = tech

    content = fp.get("content") or {}
    for k in CONTENT_LIST_KEYS:
        if k in content:
            content[k] = dedupe_sorted_strings([str(x) for x in (content.get(k) or []) if x])
    fp["content"] = content

    flow = fp.get("flow") or {}
    for k in FLOW_LIST_KEYS:
        if k in flow:
            flow[k] = dedupe_sorted_strings([str(x) for x in (flow.get(k) or []) if x], lower=True)
    fp["flow"] = flow

    ps = fp.get("provider_signals") or {}
    for k in PROVIDER_SIG_LIST_KEYS:
        if k in ps:
            ps[k] = dedupe_sorted_strings([str(x) for x in (ps.get(k) or []) if x])
    fp["provider_signals"] = ps
    return fp


def _tech_key_lower(k: str) -> bool:
    return k.endswith("_domains") or k in {"support_widget_providers", "analytics_ids", "tag_manager_ids"}


def merge_manual_row_into_fingerprint(fp: dict, row: dict[str, str]) -> None:
    tech = fp.setdefault("technical", {})
    for k in TECH_STRING_LIST_KEYS:
        vals = _split_pipe_cell(row.get(k, "") or "")
        if vals:
            tech[k] = merge_string_lists(tech.get(k) or [], vals, lower_domains=_tech_key_lower(k))

    content = fp.setdefault("content", {})
    for k in CONTENT_LIST_KEYS:
        vals = _split_pipe_cell(row.get(k, "") or "")
        if vals:
            content[k] = merge_string_lists(content.get(k) or [], vals)

    flow = fp.setdefault("flow", {})
    for k in FLOW_LIST_KEYS:
        vals = _split_pipe_cell(row.get(k, "") or "")
        if vals:
            flow[k] = merge_string_lists(flow.get(k) or [], vals, lower_domains=True)

    ps = fp.setdefault("provider_signals", {})
    for k in PROVIDER_SIG_LIST_KEYS:
        vals = _split_pipe_cell(row.get(k, "") or "")
        if vals:
            ps[k] = merge_string_lists(ps.get(k) or [], vals)


def load_partial_csv(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    out: dict[str, dict[str, str]] = {}
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            eid = (row.get("entity_id") or "").strip()
            if not eid:
                continue
            out[eid] = row
    return out


def _widget_from_script_host(host: str) -> str | None:
    h = host.lower()
    if "intercom.io" in h or "intercomcdn.com" in h:
        return "intercom"
    if "zendesk" in h:
        return "zendesk"
    if "driftt.com" in h or "drift.com" in h:
        return "drift"
    if "livechatinc.com" in h:
        return "livechat"
    return None


class _HTMLFingerprinter(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self._base = base_url
        self._in_title = False
        self._title_parts: list[str] = []
        self._footer_depth = 0
        self._footer_parts: list[str] = []
        self._inline_script_depth = 0
        self.script_srcs: list[str] = []
        self.iframe_srcs: list[str] = []
        self.asset_urls: list[str] = []
        self.inline_script_chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        ad = {k.lower(): (v or "") for k, v in attrs}
        if t == "title":
            self._in_title = True
        if t == "footer":
            self._footer_depth += 1
        if t == "script":
            src = ad.get("src")
            if src:
                self.script_srcs.append(urljoin(self._base, src.strip()))
            else:
                self._inline_script_depth += 1
        if t == "iframe":
            src = ad.get("src")
            if src:
                self.iframe_srcs.append(urljoin(self._base, src.strip()))
        if t == "img":
            src = ad.get("src")
            if src:
                self.asset_urls.append(urljoin(self._base, src.strip()))
        if t == "link":
            href = ad.get("href")
            rel = (ad.get("rel") or "").lower()
            if href and ("stylesheet" in rel or "preload" in rel):
                self.asset_urls.append(urljoin(self._base, href.strip()))

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t == "title":
            self._in_title = False
        if t == "script" and self._inline_script_depth > 0:
            self._inline_script_depth -= 1
        if t == "footer" and self._footer_depth > 0:
            self._footer_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._in_title:
            s = data.strip()
            if s:
                self._title_parts.append(s)
        if self._footer_depth > 0:
            s = data.strip()
            if s:
                self._footer_parts.append(s)
        if self._inline_script_depth > 0 and data:
            self.inline_script_chunks.append(data)


def extract_signals_from_html(html: str, base_url: str, provider_names: list[str]) -> dict:
    """Return nested partial fingerprint updates (technical/content/flow/provider_signals)."""
    parser = _HTMLFingerprinter(base_url)
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        pass

    tech: dict[str, list[str]] = {
        "analytics_ids": [],
        "tag_manager_ids": [],
        "script_domains": [],
        "iframe_domains": [],
        "asset_domains": [],
        "support_widget_providers": [],
    }

    for u in parser.script_srcs:
        h = normalize_host_from_url(u)
        if h:
            tech["script_domains"].append(h)
        if "googletagmanager.com" in (u or "").lower():
            m = re.search(r"[?&]id=(GTM-[A-Z0-9]+)", u, re.I)
            if m:
                tech["tag_manager_ids"].append(m.group(1))
        w = _widget_from_script_host(h or "")
        if w:
            tech["support_widget_providers"].append(w)

    for chunk in parser.inline_script_chunks:
        for pat in (
            r"gtag\(\s*['\"]config['\"]\s*,\s*['\"](G-[A-Z0-9]+)['\"]",
            r"['\"]UA-\d+-\d+['\"]",
        ):
            for m in re.finditer(pat, chunk, re.I):
                raw = m.group(1) if m.lastindex else m.group(0).strip("'\"")
                tech["analytics_ids"].append(raw.lower())

    for u in parser.iframe_srcs:
        h = normalize_host_from_url(u)
        if h:
            tech["iframe_domains"].append(h)

    for u in parser.asset_urls:
        h = normalize_host_from_url(u)
        if h:
            tech["asset_domains"].append(h)

    title = " ".join(parser._title_parts).strip()
    title_terms: list[str] = []
    if title:
        for w in re.split(r"[^\w]+", title.lower()):
            if len(w) >= 4:
                title_terms.append(w)

    footer_phrases: list[str] = []
    for chunk in parser._footer_parts:
        line = " ".join(chunk.split())
        if len(line) >= 12:
            footer_phrases.append(line[:500])

    provider_mentions: list[str] = []
    low = html.lower()
    for pn in provider_names:
        p = pn.strip()
        if len(p) >= 3 and p.lower() in low:
            provider_mentions.append(p)

    content = {
        "title_terms": dedupe_sorted_strings(title_terms, lower=True),
        "footer_phrases": dedupe_sorted_strings(footer_phrases, lower=False)[:20],
        "provider_mentions": dedupe_sorted_strings(provider_mentions, lower=False),
    }

    flow: dict[str, list[str]] = {"cashier_paths": [], "signup_paths": [], "redemption_paths": []}
    for m in re.finditer(r"""['\"](/[^'\"]*cashier[^'\"]*)['\"]""", html, re.I):
        flow["cashier_paths"].append(m.group(1).lower())
    for m in re.finditer(r"""['\"](/[^'\"]*redeem[^'\"]*)['\"]""", html, re.I):
        flow["redemption_paths"].append(m.group(1).lower())

    return {"technical": tech, "content": content, "flow": flow, "provider_signals": {}}


def merge_extracted_into_fingerprint(fp: dict, extracted: dict) -> None:
    tech_e = extracted.get("technical") or {}
    tech = fp.setdefault("technical", {})
    for k in TECH_STRING_LIST_KEYS:
        vals = tech_e.get(k) or []
        if vals:
            tech[k] = merge_string_lists(
                tech.get(k) or [],
                vals,
                lower_domains=_tech_key_lower(k),
            )

    content_e = extracted.get("content") or {}
    content = fp.setdefault("content", {})
    for k in ("title_terms", "footer_phrases", "provider_mentions"):
        vals = content_e.get(k) or []
        if vals:
            content[k] = merge_string_lists(
                content.get(k) or [],
                vals,
                lower_domains=(k == "title_terms"),
            )

    flow_e = extracted.get("flow") or {}
    flow = fp.setdefault("flow", {})
    for k in ("cashier_paths", "signup_paths", "redemption_paths"):
        vals = flow_e.get(k) or []
        if vals:
            flow[k] = merge_string_lists(flow.get(k) or [], vals, lower_domains=True)


def fetch_html(url: str, timeout: float = 20.0) -> str | None:
    req = Request(
        url,
        headers={
            "User-Agent": "SweepsIntelEnrich/0.1 (+https://github.com/Swixixle/Sweeps_Intel)",
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        },
        method="GET",
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read()
        return body.decode("utf-8", errors="replace")
    except (HTTPError, URLError, TimeoutError, OSError):
        return None


def _provider_names_for_scan(entities: list[dict]) -> list[str]:
    names: list[str] = []
    for e in entities:
        if e.get("entity_type") == "provider":
            n = e.get("name") or ""
            if n.strip():
                names.append(n.strip())
    return sorted(set(names), key=str.lower)


def run_enrich(
    repo_root: Path,
    normalized_dir: Path,
    seeds_dir: Path,
    *,
    fetch: bool,
    report_dir: Path,
) -> dict:
    entities: list[dict] = json.loads((normalized_dir / "entities.json").read_text(encoding="utf-8"))
    existing_raw: list[dict] = json.loads((normalized_dir / "fingerprints.json").read_text(encoding="utf-8"))
    by_id: dict[str, dict] = {f["entity_id"]: deepcopy(f) for f in existing_raw}
    entity_by_id = {e["id"]: e for e in entities}

    for e in entities:
        if e["id"] not in by_id:
            by_id[e["id"]] = empty_fingerprint_dict(e["id"])

    partial_path = seeds_dir / "fingerprints_partial.csv"
    partial_rows = load_partial_csv(partial_path)
    for eid, row in partial_rows.items():
        if eid not in by_id:
            by_id[eid] = empty_fingerprint_dict(eid)
        merge_manual_row_into_fingerprint(by_id[eid], row)

    provider_scan = _provider_names_for_scan(entities)
    report: dict = {
        "generated_at": _utc_now_iso(),
        "fetch_enabled": fetch,
        "partial_csv": str(partial_path) if partial_path.exists() else None,
        "entities_fetched": [],
        "fetch_failures": [],
    }

    if fetch:
        for e in entities:
            if e.get("status") != "active":
                continue
            if e.get("entity_type") not in {"operator", "promoter", "provider"}:
                continue
            domains = [d for d in (e.get("domains") or []) if d]
            if not domains:
                continue
            domain = domains[0]
            html: str | None = None
            final_url = ""
            for scheme in ("https", "http"):
                url = f"{scheme}://{domain}/"
                html = fetch_html(url)
                if html:
                    final_url = url
                    break
            eid = e["id"]
            if not html:
                report["fetch_failures"].append({"entity_id": eid, "domain": domain})
                continue
            extracted = extract_signals_from_html(html, final_url, provider_scan)
            merge_extracted_into_fingerprint(by_id[eid], extracted)
            report["entities_fetched"].append({"entity_id": eid, "url": final_url})

    out_list = [normalize_fingerprint_dict(by_id[eid]) for eid in sorted(by_id.keys())]

    (normalized_dir / "fingerprints.json").write_text(
        json.dumps(out_list, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    report_dir.mkdir(parents=True, exist_ok=True)
    ts = _utc_now_iso().replace(":", "")
    rep_path = report_dir / f"enrich-{ts}.json"
    rep_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report["report_path"] = str(rep_path)
    return report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Enrich fingerprints from manual CSV and optional HTML fetch.")
    p.add_argument("--repo-root", type=Path, default=Path.cwd())
    p.add_argument("--normalized", type=Path, default=None)
    p.add_argument("--seeds", type=Path, default=None)
    p.add_argument("--fetch", action="store_true", help="Fetch active operator/promoter/provider primary domains")
    p.add_argument("--reports", type=Path, default=None)
    args = p.parse_args(argv)
    repo = args.repo_root.resolve()
    norm = args.normalized or (repo / "data" / "normalized")
    seeds = args.seeds or (repo / "data" / "seeds")
    reps = args.reports or (repo / "reports" / "enrichment")
    if not (norm / "entities.json").exists():
        raise SystemExit("missing entities.json; run normalize first")
    if not (norm / "fingerprints.json").exists():
        raise SystemExit("missing fingerprints.json; run normalize first")
    r = run_enrich(repo, norm, seeds, fetch=args.fetch, report_dir=reps)
    print(f"wrote {norm / 'fingerprints.json'}")
    print(f"wrote {r.get('report_path')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
