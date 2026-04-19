from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from .classify import DomainIndex
from .relationships import merge_relationships
from .schemas import CandidateRecord, Relationship, RelationshipEvidence


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _load_entities(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_domain(host: str) -> str:
    h = host.lower().strip().rstrip(".")
    if h.startswith("www."):
        h = h[4:]
    return h


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        for k, v in attrs:
            if k.lower() == "href" and v:
                self.hrefs.append(v)


def fetch_html(url: str, timeout: float = 25.0) -> str | None:
    req = Request(
        url,
        headers={
            "User-Agent": "SweepsIntelMonitor/0.1 (+https://github.com/Swixixle/Sweeps_Intel)",
            "Accept": "text/html,application/xhtml+xml",
        },
        method="GET",
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            ctype = resp.headers.get("Content-Type", "")
            body = resp.read()
    except (HTTPError, URLError, TimeoutError, OSError) as e:
        print(f"warning: fetch failed for {url!r}: {e}", file=sys.stderr)
        return None
    if "html" not in ctype.lower() and ctype:
        pass
    try:
        return body.decode("utf-8", errors="replace")
    except Exception:
        return None


def extract_links(base_url: str, html: str, max_links: int = 800) -> list[str]:
    parser = _LinkExtractor()
    try:
        parser.feed(html)
    except Exception:
        return []
    out: list[str] = []
    for href in parser.hrefs:
        if len(out) >= max_links:
            break
        h = href.strip()
        if not h or h.startswith("#") or h.lower().startswith("javascript:") or h.lower().startswith("mailto:"):
            continue
        joined = urljoin(base_url, h)
        out.append(joined)
    return out


def host_from_url(url: str) -> str | None:
    try:
        p = urlparse(url)
    except Exception:
        return None
    if p.scheme not in {"http", "https"}:
        return None
    if not p.netloc:
        return None
    host = p.netloc.split("@")[-1]
    if ":" in host and not host.startswith("["):
        host = host.split(":")[0]
    return normalize_domain(host)


def read_seed_urls(path: Path) -> list[str]:
    if not path.exists():
        return []
    urls: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        urls.append(s)
    return urls


def run_monitor(
    repo_root: Path,
    normalized_dir: Path,
    seeds_dir: Path,
    candidates_dir: Path,
    report_dir: Path,
) -> None:
    ts = _utc_now_iso()
    run_tag = ts.replace(":", "").replace("-", "")

    entities = _load_entities(normalized_dir / "entities.json")
    rel_path = normalized_dir / "relationships.json"
    existing_rels: list[Relationship] = []
    if rel_path.exists():
        for r in json.loads(rel_path.read_text(encoding="utf-8")):
            ev = r.get("evidence") or {}
            evidence = (
                RelationshipEvidence(url=str(ev.get("url") or ""), anchor_text=str(ev.get("anchor_text") or ""))
                if (ev.get("url") or ev.get("anchor_text"))
                else None
            )
            existing_rels.append(
                Relationship(
                    from_id=r["from_id"],
                    to_id=r["to_id"],
                    relationship=r.get("relationship", "related_to"),
                    confidence=float(r.get("confidence") or 0),
                    source=str(r.get("source") or ""),
                    evidence=evidence,
                )
            )

    index = DomainIndex(entities)
    known = index.known_domains()

    seed_urls = read_seed_urls(seeds_dir / "seed_urls.txt")
    new_edges: list[Relationship] = []
    unknown_by_domain: dict[str, CandidateRecord] = {}

    pages_checked = 0
    links_total = 0

    for url in seed_urls:
        html = fetch_html(url)
        pages_checked += 1
        if not html:
            continue
        page_host = host_from_url(url)
        if not page_host:
            continue
        links = extract_links(url, html)
        links_total += len(links)
        page_hit = index.lookup(page_host)

        for link in links:
            target_host = host_from_url(link)
            if not target_host or target_host == page_host:
                continue
            target_hit = index.lookup(target_host)

            if target_hit is None and target_host not in known:
                rec = unknown_by_domain.get(target_host)
                if rec is None:
                    unknown_by_domain[target_host] = CandidateRecord(
                        domain=target_host,
                        suggested_types=["unknown"],
                        seen_on_urls=[url],
                        first_seen=ts,
                        last_seen=ts,
                        confidence=0.35,
                        source_run=run_tag,
                        notes="Outbound link from monitored seed page",
                    )
                else:
                    if url not in rec.seen_on_urls:
                        rec.seen_on_urls.append(url)
                    rec.last_seen = ts
                continue

            if page_hit and target_hit:
                if page_hit.kind == "promoter" and target_hit.kind == "operator":
                    rel_type = "promotes"
                else:
                    rel_type = "links_to"
                new_edges.append(
                    Relationship(
                        from_id=page_hit.entity_id,
                        to_id=target_hit.entity_id,
                        relationship=rel_type,
                        confidence=0.55 if rel_type == "promotes" else 0.45,
                        source=f"monitor_{run_tag}",
                        evidence=RelationshipEvidence(url=link, anchor_text=""),
                    )
                )

    merged_rels = merge_relationships(existing_rels, new_edges)

    candidates_dir.mkdir(parents=True, exist_ok=True)
    operators_c: list[dict] = []
    promoters_c: list[dict] = []
    providers_c: list[dict] = []
    for dom, rec in sorted(unknown_by_domain.items()):
        j = rec.to_json()
        if re.search(r"(casino|sweeps|slots|poker|betting)", dom):
            j["suggested_types"] = ["operator", "promoter", "unknown"]
            operators_c.append(j)
        elif re.search(r"(review|bonus|codes|aff)", dom):
            j["suggested_types"] = ["promoter", "unknown"]
            promoters_c.append(j)
        else:
            operators_c.append(j)

    (candidates_dir / "operators_candidates.json").write_text(
        json.dumps(operators_c, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (candidates_dir / "promoters_candidates.json").write_text(
        json.dumps(promoters_c, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (candidates_dir / "providers_candidates.json").write_text(
        json.dumps(providers_c, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    month = ts[:7]
    report_sub = report_dir / "monthly" / month
    report_sub.mkdir(parents=True, exist_ok=True)
    report_path = report_sub / f"monitor-{run_tag}.json"
    report = {
        "generated_at": ts,
        "pages_checked": pages_checked,
        "links_extracted": links_total,
        "new_unknown_domains": sorted(unknown_by_domain.keys()),
        "relationships_discovered": len(new_edges),
        "candidates_counts": {
            "operators_bucket": len(operators_c),
            "promoters_bucket": len(promoters_c),
            "providers_bucket": len(providers_c),
        },
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    (candidates_dir / "relationships_suggested.json").write_text(
        json.dumps([r.to_json() for r in new_edges], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(f"wrote candidates under {candidates_dir}")
    print(f"wrote report {report_path}")
    print(f"note: merged graph has {len(merged_rels)} edges if suggestions applied ({len(new_edges)} new)")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Crawl seed URLs and emit candidate domains + monitor report.")
    p.add_argument("--repo-root", type=Path, default=Path.cwd())
    p.add_argument("--normalized", type=Path, default=None)
    p.add_argument("--seeds", type=Path, default=None)
    p.add_argument("--candidates", type=Path, default=None)
    p.add_argument("--reports", type=Path, default=None)
    args = p.parse_args(argv)
    repo = args.repo_root.resolve()
    norm = args.normalized or (repo / "data" / "normalized")
    seeds = args.seeds or (repo / "data" / "seeds")
    cand = args.candidates or (repo / "data" / "candidates")
    reps = args.reports or (repo / "reports")
    if not (norm / "entities.json").exists():
        print("error: run normalize first (missing data/normalized/entities.json)", file=sys.stderr)
        return 1
    run_monitor(repo, norm, seeds, cand, reps)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
