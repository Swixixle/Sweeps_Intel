from __future__ import annotations

from intel.infra_denylist import is_noise_mx, is_noise_nameserver


def test_nameserver_cloudflare_suffix() -> None:
    assert is_noise_nameserver("ns.cloudflare.com") is True
    assert is_noise_nameserver("cloudflare.com") is True


def test_nameserver_suffix_not_inside_longer_tld_chain() -> None:
    assert is_noise_nameserver("cloudflare.com.evil-operator.net") is False


def test_nameserver_fake_cloudflare_substring_not_suffix() -> None:
    assert is_noise_nameserver("ns-fake-cloudflare.com.malicious.net") is False


def test_nameserver_awsdns_label_prefix() -> None:
    assert is_noise_nameserver("awsdns-01.net") is True
    assert is_noise_nameserver("awsdns-99.co.uk") is True


def test_nameserver_notawsdns_label_does_not_match_prefix_rule() -> None:
    assert is_noise_nameserver("notawsdns.example") is False


def test_mx_google_workspace_suffix() -> None:
    assert is_noise_mx("aspmx.l.google.com") is True


def test_mx_acme_google_substring_not_suffix() -> None:
    assert is_noise_mx("mail.acme-google.com") is False
