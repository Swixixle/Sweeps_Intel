"""Load Scout ``domain_fingerprints.json`` and emit pairwise infrastructure signals.

Expected top-level JSON: object mapping apex domain (string) to a record dict.

Each record may include (flexible keys):

- ``sans``, ``san``, or ``tls.sans``: certificate SAN hostnames.
- ``nameservers`` or ``dns.nameservers``: NS hostnames.
- ``mx`` or ``dns.mx``: list of dicts with ``host`` (and optional priority).
- ``partial`` (bool): if true, skip TLS- and DNS-derived signals for this domain.
- ``tls.partial`` / ``dns.partial``: skip only that subsystem when true.

Domain strings are normalized (lowercase, no trailing dot, ``www.`` stripped) for comparison.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .infra_denylist import filter_signal_mx_hosts, filter_signal_nameservers

logger = logging.getLogger(__name__)


def _normalize_domain(d: str) -> str:
    x = (d or "").strip().lower().rstrip(".")
    if x.startswith("www."):
        x = x[4:]
    return x


def _coerce_str_list(val: Any) -> list[str]:
    if val is None:
        return []
    if isinstance(val, str):
        return [val] if val.strip() else []
    if isinstance(val, list):
        out: list[str] = []
        for x in val:
            if x is None:
                continue
            s = str(x).strip()
            if s:
                out.append(s)
        return out
    return []


def _coerce_mx_list(val: Any) -> list[dict]:
    if val is None:
        return []
    if not isinstance(val, list):
        return []
    out: list[dict] = []
    for x in val:
        if isinstance(x, dict):
            out.append(x)
    return out


def _parse_record(domain_key: str, raw: dict[str, Any]) -> dict[str, Any] | None:
    try:
        tls = raw.get("tls") if isinstance(raw.get("tls"), dict) else {}
        dns = raw.get("dns") if isinstance(raw.get("dns"), dict) else {}

        sans = _coerce_str_list(raw.get("sans"))
        if not sans:
            sans = _coerce_str_list(raw.get("san"))
        if not sans:
            sans = _coerce_str_list(tls.get("sans"))

        nameservers = _coerce_str_list(raw.get("nameservers"))
        if not nameservers:
            nameservers = _coerce_str_list(dns.get("nameservers"))

        mx = _coerce_mx_list(raw.get("mx"))
        if not mx:
            mx = _coerce_mx_list(dns.get("mx"))

        top_partial = bool(raw.get("partial"))
        tls_partial = bool(tls.get("partial")) or top_partial
        dns_partial = bool(dns.get("partial")) or top_partial

        return {
            "domain": domain_key,
            "sans": [_normalize_domain(s) for s in sans if s],
            "nameservers": nameservers,
            "mx": mx,
            "tls_partial": tls_partial,
            "dns_partial": dns_partial,
        }
    except (TypeError, ValueError, KeyError) as e:
        logger.warning("scout fingerprint: skip malformed record for %r: %s", domain_key, e)
        return None


def load_fingerprints(path: Path) -> dict[str, dict[str, Any]]:
    """Load ``domain_fingerprints.json``; return map normalized_domain -> parsed record dict."""
    if not path.is_file():
        logger.warning("scout fingerprint: file missing: %s", path)
        return {}
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as e:
        logger.warning("scout fingerprint: could not read %s: %s", path, e)
        return {}
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as e:
        logger.warning("scout fingerprint: invalid JSON in %s: %s", path, e)
        return {}
    if not isinstance(data, dict):
        logger.warning("scout fingerprint: expected object at root of %s, got %s", path, type(data).__name__)
        return {}

    out: dict[str, dict[str, Any]] = {}
    for k, v in data.items():
        if not isinstance(k, str) or not k.strip():
            continue
        dom_key = _normalize_domain(k)
        if not dom_key:
            continue
        if not isinstance(v, dict):
            logger.warning("scout fingerprint: skip non-object value for domain %r", k)
            continue
        parsed = _parse_record(dom_key, v)
        if parsed:
            out[dom_key] = parsed
    return out


def _san_set_for_peer_check(sans: list[str]) -> set[str]:
    return {s for s in sans if s}


def iter_signal_pairs(fingerprints: dict[str, dict[str, Any]]) -> Iterator[tuple[str, str, str, dict[str, Any]]]:
    """Yield ``(domain_a, domain_b, signal_type, detail)`` for domain pairs sharing infrastructure signals.

    ``domain_a`` < ``domain_b`` lexicographically. Signal order per pair: reciprocal TLS,
    one-way TLS, filtered shared NS, filtered shared MX.
    """
    domains = sorted(fingerprints.keys())
    for i, da in enumerate(domains):
        rec_a = fingerprints[da]
        for db in domains[i + 1 :]:
            rec_b = fingerprints[db]
            tls_skip = bool(rec_a.get("tls_partial")) or bool(rec_b.get("tls_partial"))
            dns_skip = bool(rec_a.get("dns_partial")) or bool(rec_b.get("dns_partial"))

            if not tls_skip:
                sa = _san_set_for_peer_check(list(rec_a.get("sans") or []))
                sb = _san_set_for_peer_check(list(rec_b.get("sans") or []))
                a_lists_b = db in sa
                b_lists_a = da in sb
                if a_lists_b and b_lists_a:
                    yield (
                        da,
                        db,
                        "tls_san_reciprocal",
                        {
                            "san_a_lists_b": a_lists_b,
                            "san_b_lists_a": b_lists_a,
                            "domain_a": da,
                            "domain_b": db,
                        },
                    )
                elif a_lists_b or b_lists_a:
                    yield (
                        da,
                        db,
                        "tls_san_one_way",
                        {
                            "san_a_lists_b": a_lists_b,
                            "san_b_lists_a": b_lists_a,
                            "domain_a": da,
                            "domain_b": db,
                        },
                    )

            if not dns_skip:
                ns_a = filter_signal_nameservers(list(rec_a.get("nameservers") or []))
                ns_b = filter_signal_nameservers(list(rec_b.get("nameservers") or []))
                inter_ns = sorted({x.lower() for x in ns_a} & {y.lower() for y in ns_b})
                if inter_ns:
                    yield (
                        da,
                        db,
                        "shared_nameserver_filtered",
                        {"shared_nameservers": inter_ns},
                    )

                mx_a = filter_signal_mx_hosts(list(rec_a.get("mx") or []))
                mx_b = filter_signal_mx_hosts(list(rec_b.get("mx") or []))
                inter_mx = sorted({x.lower() for x in mx_a} & {y.lower() for y in mx_b})
                if inter_mx:
                    yield (
                        da,
                        db,
                        "shared_mx_filtered",
                        {"shared_mx_hosts": inter_mx},
                    )
