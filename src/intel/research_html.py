"""Shared HTML fetch/link helpers for research discover/extract (stdlib)."""

from __future__ import annotations

import re
import sys
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


def fetch_url(
    url: str,
    timeout: float = 22.0,
    user_agent: str = "SweepsIntelResearch/0.1 (+https://github.com/Swixixle/Sweeps_Intel)",
) -> tuple[str | None, str | None, int]:
    """Return (final_url, html_body, status_or_-1). html None on failure."""
    req = Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        },
        method="GET",
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            final = resp.geturl()
            code = getattr(resp, "status", 200) or 200
            body = resp.read()
            ctype = (resp.headers.get("Content-Type") or "").lower()
    except HTTPError as e:
        return None, None, e.code
    except (URLError, TimeoutError, OSError) as e:
        print(f"warning: fetch failed for {url!r}: {e}", file=sys.stderr)
        return None, None, -1
    if "html" not in ctype and ctype and "text" not in ctype:
        try:
            return final, body.decode("utf-8", errors="replace"), code
        except Exception:
            return final, None, code
    try:
        return final, body.decode("utf-8", errors="replace"), code
    except Exception:
        return final, None, code


def normalize_host(url: str) -> str | None:
    try:
        p = urlparse(url)
    except Exception:
        return None
    if p.scheme not in {"http", "https"} or not p.netloc:
        return None
    host = p.netloc.split("@")[-1].split(":")[0].lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host or None


class LinkCollector(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base = base_url
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = {k.lower(): (v or "") for k, v in attrs}
        if tag.lower() == "a" and ad.get("href"):
            h = ad["href"].strip()
            if h and not h.startswith("#") and "javascript:" not in h.lower():
                self.hrefs.append(urljoin(self.base, h))


def collect_links(html: str, base_url: str, max_links: int = 600) -> list[str]:
    p = LinkCollector(base_url)
    try:
        p.feed(html)
        p.close()
    except Exception:
        return []
    return p.hrefs[:max_links]


LEGAL_PATH = re.compile(
    r"(terms|privacy|sweep|rules|policy|legal|responsible|eula|conditions)",
    re.I,
)
EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
)
# Rough US-style address line (very conservative)
ADDRESS_HINT = re.compile(
    r"\b\d{1,6}\s+[\w\s]+,?\s+[A-Za-z\s]+,?\s+[A-Z]{2}\s+\d{5}(-\d{4})?\b",
)
