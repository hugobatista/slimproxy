from unittest.mock import MagicMock

import pytest
from proxy.http import httpStatusCodes
from proxy.http.exception import HttpRequestRejected
from proxy.http.parser import HttpParser

from slimproxy.plugins import (
    FilterByClientIpPlugin,
    FilterByDestPlugin,
    _normalize_host,
)


def make_ip_plugin(
    ips: str = "",
    mode: str = "whitelist",
    client_addr: tuple[str, int] | None = None,
) -> FilterByClientIpPlugin:
    plugin = FilterByClientIpPlugin.__new__(FilterByClientIpPlugin)
    plugin.flags = MagicMock()
    plugin.flags.slimproxy_filtered_client_ips = ips
    plugin.flags.slimproxy_filtered_client_ips_mode = mode
    plugin.flags.unix_socket_path = None
    plugin.client = MagicMock()
    plugin.client.addr = client_addr or ("127.0.0.1", 54321)
    return plugin


def make_plugin(allow_dests: str = "") -> FilterByDestPlugin:
    plugin = FilterByDestPlugin.__new__(FilterByDestPlugin)
    plugin.flags = MagicMock()
    plugin.flags.allow_dests = allow_dests
    return plugin


def make_request(host: str) -> MagicMock:
    request = MagicMock(spec=HttpParser)
    request.host = host
    return request


class TestFilterByClientIpPlugin:
    def test_whitelist_exact_ip_match(self):
        plugin = make_ip_plugin(
            ips="10.0.0.1,10.0.0.2",
            client_addr=("10.0.0.2", 50000),
        )
        request = make_request("example.com")
        result = plugin.before_upstream_connection(request)
        assert result is request

    def test_whitelist_cidr_match(self):
        plugin = make_ip_plugin(
            ips="192.168.100.0/24",
            client_addr=("192.168.100.51", 50000),
        )
        request = make_request("example.com")
        result = plugin.before_upstream_connection(request)
        assert result is request

    def test_whitelist_non_matching_rejected(self):
        plugin = make_ip_plugin(
            ips="10.0.0.0/8",
            client_addr=("192.168.1.1", 50000),
        )
        request = make_request("example.com")
        with pytest.raises(HttpRequestRejected) as exc:
            plugin.before_upstream_connection(request)
        assert exc.value.status_code == httpStatusCodes.I_AM_A_TEAPOT
        assert exc.value.reason == b"I'm a tea pot"

    def test_blacklist_match_rejected(self):
        plugin = make_ip_plugin(
            ips="10.0.0.0/8",
            mode="blacklist",
            client_addr=("10.0.0.5", 50000),
        )
        request = make_request("example.com")
        with pytest.raises(HttpRequestRejected) as exc:
            plugin.before_upstream_connection(request)
        assert exc.value.status_code == httpStatusCodes.I_AM_A_TEAPOT

    def test_blacklist_non_match_passes(self):
        plugin = make_ip_plugin(
            ips="10.0.0.0/8",
            mode="blacklist",
            client_addr=("192.168.1.1", 50000),
        )
        request = make_request("example.com")
        result = plugin.before_upstream_connection(request)
        assert result is request

    def test_single_ip_treated_as_32(self):
        plugin = make_ip_plugin(
            ips="10.0.0.1",
            client_addr=("10.0.0.1", 50000),
        )
        request = make_request("example.com")
        result = plugin.before_upstream_connection(request)
        assert result is request

    def test_ipv6_cidr_match(self):
        plugin = make_ip_plugin(
            ips="fd00::/8",
            client_addr=("fd01::1", 50000),
        )
        request = make_request("example.com")
        result = plugin.before_upstream_connection(request)
        assert result is request

    def test_ipv6_non_match_rejected(self):
        plugin = make_ip_plugin(
            ips="fd00::/8",
            client_addr=("fe80::1", 50000),
        )
        request = make_request("example.com")
        with pytest.raises(HttpRequestRejected):
            plugin.before_upstream_connection(request)

    def test_whitespace_handling(self):
        plugin = make_ip_plugin(
            ips=" 10.0.0.0/8 , 192.168.0.0/16 ",
            client_addr=("192.168.1.1", 50000),
        )
        request = make_request("example.com")
        result = plugin.before_upstream_connection(request)
        assert result is request

    def test_empty_ips_passes_all(self):
        plugin = make_ip_plugin(
            ips="",
            client_addr=("10.0.0.1", 50000),
        )
        request = make_request("example.com")
        result = plugin.before_upstream_connection(request)
        assert result is request

    def test_unparseable_client_ip_passes(self):
        plugin = make_ip_plugin(
            ips="10.0.0.0/8",
            client_addr=("not-an-ip", 50000),
        )
        request = make_request("example.com")
        result = plugin.before_upstream_connection(request)
        assert result is request


class TestFilterByDestPlugin:
    def test_no_filter_when_empty(self):
        plugin = make_plugin(allow_dests="")
        request = make_request("example.com")
        result = plugin.before_upstream_connection(request)
        assert result is request

    def test_allowed_host_passes(self):
        plugin = make_plugin(allow_dests="example.com,test.com")
        request = make_request("example.com")
        result = plugin.before_upstream_connection(request)
        assert result is request

    def test_unknown_host_rejected(self):
        plugin = make_plugin(allow_dests="example.com,test.com")
        request = make_request("evil.com")
        with pytest.raises(HttpRequestRejected) as exc:
            plugin.before_upstream_connection(request)
        assert exc.value.status_code == httpStatusCodes.FORBIDDEN
        assert exc.value.reason == b"Destination not allowed"

    def test_whitespace_handling(self):
        plugin = make_plugin(allow_dests=" example.com , test.com ")
        request = make_request("test.com")
        result = plugin.before_upstream_connection(request)
        assert result is request

    def test_case_insensitive_both_sides(self):
        plugin = make_plugin(allow_dests="Example.Com")
        request = make_request("example.com")
        result = plugin.before_upstream_connection(request)
        assert result is request

    def test_case_insensitive_request_uppercase(self):
        plugin = make_plugin(allow_dests="example.com")
        request = make_request("EXAMPLE.COM")
        result = plugin.before_upstream_connection(request)
        assert result is request

    def test_trailing_dot_in_allowlist(self):
        plugin = make_plugin(allow_dests="example.com.")
        request = make_request("example.com")
        result = plugin.before_upstream_connection(request)
        assert result is request

    def test_trailing_dot_in_request(self):
        plugin = make_plugin(allow_dests="example.com")
        request = make_request("example.com.")
        result = plugin.before_upstream_connection(request)
        assert result is request

    def test_port_in_request_stripped(self):
        plugin = make_plugin(allow_dests="example.com")
        request = make_request("example.com:443")
        result = plugin.before_upstream_connection(request)
        assert result is request

    def test_all_variations_combined(self):
        plugin = make_plugin(allow_dests="Example.Com")
        request = make_request("EXAMPLE.COM.:443")
        result = plugin.before_upstream_connection(request)
        assert result is request

    def test_ipv6_literal_preserved(self):
        plugin = make_plugin(allow_dests="[::1]")
        request = make_request("[::1]")
        result = plugin.before_upstream_connection(request)
        assert result is request

    def test_idn_normalization_unicode_allowlist(self):
        plugin = make_plugin(allow_dests="münchen.de")
        request = make_request("xn--mnchen-3ya.de")
        result = plugin.before_upstream_connection(request)
        assert result is request

    def test_idn_normalization_ascii_allowlist(self):
        plugin = make_plugin(allow_dests="xn--mnchen-3ya.de")
        request = make_request("münchen.de")
        result = plugin.before_upstream_connection(request)
        assert result is request

    def test_none_host_rejected(self):
        plugin = make_plugin(allow_dests="example.com")
        request = make_request("does-not-matter")
        request.host = None
        with pytest.raises(HttpRequestRejected) as exc:
            plugin.before_upstream_connection(request)
        assert exc.value.status_code == httpStatusCodes.FORBIDDEN

    def test_bytes_host_normalized(self):
        plugin = make_plugin(allow_dests="example.com")
        request = make_request("does-not-matter")
        request.host = b"Example.Com"
        result = plugin.before_upstream_connection(request)
        assert result is request


class TestNormalizeHost:
    def test_none(self):
        assert _normalize_host(None) == ""

    def test_bytes_ascii(self):
        assert _normalize_host(b"Example.Com") == "example.com"

    def test_idna_unicode_error_silently_ignored(self):
        result = _normalize_host("a" * 64 + ".com")
        assert result == "a" * 64 + ".com"
