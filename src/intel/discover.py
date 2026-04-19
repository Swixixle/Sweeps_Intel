from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from .research_html import collect_links, fetch_url, normalize_host


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_domain_list(path: Path | None) -> set[str]:
    if not path or not path.exists():
        return set()
    out: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip().lower()
        if not s or s.startswith("#"):
            continue
        if "/" in s and "://" not in s:
            s = s.split("/")[0]
        out.add(s.rstrip("."))
    return out


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


def run_discover(
    repo_root: Path,
    *,
    seeds_path: Path,
    candidates_dir: Path,
    reports_dir: Path,
    max_depth: int,
    max_same_host_pages: int,
    denylist_path: Path | None,
    allowlist_path: Path | None,
) -> dict:
    ts = _utc_now_iso()
    deny = _read_domain_list(denylist_path)
    allow = _read_domain_list(allowlist_path)

    domain_sources: dict[str, set[str]] = defaultdict(set)
    domain_redirects: dict[str, list[str]] = {}
    pages_out: list[dict] = []

    def allowed_domain(host: str | None) -> bool:
        if not host:
            return False
        if host in deny:
            return False
        if allow and host not in allow:
            return False
        return True

    seeds = read_seed_urls(seeds_path)
    queue: list[tuple[str, str]] = [(u, u) for u in seeds]  # (fetch_url, source_label)
    seen_fetch: set[str] = set()
    same_host_counts: dict[str, int] = defaultdict(int)

    while queue:
        url, source_from = queue.pop(0)
        if url in seen_fetch:
            continue
        seen_fetch.add(url)
        host = normalize_host(url)
        if not allowed_domain(host):
            continue

        final, html, status = fetch_url(url)
        chain = [url]
        if final and final != url:
            chain.append(final)

        outbound_domains: list[str] = []
        if html and status > 0:
            for link in collect_links(html, final or url):
                lh = normalize_host(link)
                if lh and allowed_domain(lh):
                    outbound_domains.append(lh)
                    domain_sources[lh].add(source_from)
            fh = normalize_host(final or url)
            if fh:
                domain_sources[fh].add(source_from)
                domain_redirects[fh] = chain

            if max_depth >= 1 and fh:
                for link in collect_links(html, final or url):
                    if same_host_counts[fh] >= max_same_host_pages:
                        break
                    lh = normalize_host(link)
                    if lh != fh:
                        continue
                    if link in seen_fetch:
                        continue
                    same_host_counts[fh] += 1
                    queue.append((link, source_from))

        pages_out.append(
            {
                "requested_url": url,
                "final_url": final,
                "http_status": status,
                "source_seed_or_page": source_from,
                "outbound_domains": sorted(set(outbound_domains)),
                "extracted_at": ts,
            }
        )

    domains_out: list[dict] = []
    for dom in sorted(domain_sources.keys()):
        domains_out.append(
            {
                "domain": dom,
                "source_urls": sorted(domain_sources[dom]),
                "redirect_chain": domain_redirects.get(dom, []),
                "discovered_at": ts,
            }
        )

    candidates_dir.mkdir(parents=True, exist_ok=True)
    (candidates_dir / "discovered_domains.json").write_text(
        json.dumps(domains_out, indent=2) + "\n",
        encoding="utf-8",
    )
    (candidates_dir / "discovered_pages.json").write_text(
        json.dumps(pages_out, indent=2) + "\n",
        encoding="utf-8",
    )

    rep_dir = reports_dir / "discovery"
    rep_dir.mkdir(parents=True, exist_ok=True)
    tag = ts.replace(":", "")
    report = {
        "generated_at": ts,
        "seed_urls_count": len(seeds),
        "unique_domains": len(domains_out),
        "pages_fetched": len(pages_out),
        "max_depth": max_depth,
        "max_same_host_pages": max_same_host_pages,
    }
    rep_path = rep_dir / f"discover-{tag}.json"
    rep_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return {"report": report, "report_path": str(rep_path)}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Discover outbound domains from seed URLs (bounded crawl).")
    p.add_argument("--repo-root", type=Path, default=Path.cwd())
    p.add_argument("--seeds", type=Path, default=None)
    p.add_argument("--candidates-dir", type=Path, default=None)
    p.add_argument("--reports-dir", type=Path, default=None)
    p.add_argument("--max-depth", type=int, default=1, help="1 = seed + limited same-host pages")
    p.add_argument("--max-same-host-pages", type=int, default=12)
    p.add_argument("--denylist", type=Path, default=None, help="Optional file: one domain per line")
    p.add_argument("--allowlist", type=Path, default=None, help="If set, only these registrable domains")
    args = p.parse_args(argv)
    repo = args.repo_root.resolve()
    seeds = args.seeds or (repo / "data" / "seeds" / "seed_urls.txt")
    cand = args.candidates_dir or (repo / "data" / "candidates")
    reps = args.reports_dir or (repo / "reports")
    if not seeds.exists():
        print(f"warning: {seeds} missing; nothing to crawl", file=sys.stderr)
    r = run_discover(
        repo,
        seeds_path=seeds,
        candidates_dir=cand,
        reports_dir=reps,
        max_depth=args.max_depth,
        max_same_host_pages=args.max_same_host_pages,
        denylist_path=args.denylist,
        allowlist_path=args.allowlist,
    )
    print(f"wrote discovered_domains.json and discovered_pages.json under {cand}")
    print(f"wrote {r['report_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
