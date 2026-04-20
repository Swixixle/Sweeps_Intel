"""Curated denylist of common infrastructure (CDN, shared hosting, default NS/MX)
that should be treated as noise, not signal, when clustering domains by shared infrastructure.

Rule of thumb: if a nameserver or MX is used by thousands of unrelated sites, it's noise.
If it's used by a small number of related-looking sites, it's signal. Err on the side of
leaving things OUT of this list — false positives here (marking real operator infra as noise)
are worse than false negatives (letting weak signals through to review)."""

from __future__ import annotations

# Nameservers: suffix match on full hostname (e.g. "cloudflare.com" matches "ns1.cloudflare.com").
NOISE_NAMESERVER_SUFFIXES: frozenset[str] = frozenset({
    "cloudflare.com",
    "googledomains.com",
    "google.com",
    "azure-dns.com",
    "dnsimple.com",
    "registrar-servers.com",
    "domaincontrol.com",
    "name-services.com",
})

# Nameservers: prefix match on any dot-separated label (e.g. "awsdns-" matches "awsdns-01.net").
NOISE_NAMESERVER_LABEL_PREFIXES: frozenset[str] = frozenset({
    "awsdns-",
})

# MX hosts: suffix match only (no prefix-labeled providers in current list).
NOISE_MX_SUFFIXES: frozenset[str] = frozenset({
    "google.com",
    "googlemail.com",
    "outlook.com",
    "mail.protection.outlook.com",
})


def _suffix_matches(host: str, suffix: str) -> bool:
    return host == suffix or host.endswith("." + suffix)


def is_noise_nameserver(ns: str) -> bool:
    """Return True if this nameserver hostname matches any denylist entry."""
    ns_lower = (ns or "").lower().strip().rstrip(".")
    if not ns_lower:
        return False
    for suffix in NOISE_NAMESERVER_SUFFIXES:
        if _suffix_matches(ns_lower, suffix):
            return True
    labels = ns_lower.split(".")
    for label in labels:
        for prefix in NOISE_NAMESERVER_LABEL_PREFIXES:
            if label.startswith(prefix):
                return True
    return False


def is_noise_mx(host: str) -> bool:
    """Return True if this MX host matches any denylist entry."""
    host_lower = (host or "").lower().strip().rstrip(".")
    if not host_lower:
        return False
    for suffix in NOISE_MX_SUFFIXES:
        if _suffix_matches(host_lower, suffix):
            return True
    return False


def filter_signal_nameservers(nameservers: list[str]) -> list[str]:
    """Return only nameservers that are NOT on the noise list — i.e. potential signal."""
    return [ns for ns in nameservers if ns and not is_noise_nameserver(ns)]


def filter_signal_mx_hosts(mx_records: list[dict]) -> list[str]:
    """Extract MX hostnames, filter out noise, drop the RFC 7505 null MX (host='.')."""
    out = []
    for rec in mx_records or []:
        host = (rec.get("host") or "").strip()
        if not host or host == ".":
            continue
        if is_noise_mx(host):
            continue
        out.append(host)
    return out
