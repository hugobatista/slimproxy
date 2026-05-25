from unittest.mock import MagicMock

import pytest
from proxy.http import httpStatusCodes
from proxy.http.exception import HttpRequestRejected
from proxy.http.parser import HttpParser

from slimproxy.plugins import FilterByClientIpPlugin, FilterByDestPlugin


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
