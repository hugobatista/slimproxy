from unittest.mock import MagicMock

import pytest
from proxy.http import httpStatusCodes
from proxy.http.exception import HttpRequestRejected
from proxy.http.parser import HttpParser

from slimproxy.plugins import FilterByDestPlugin


def make_plugin(allow_dests: str = "") -> FilterByDestPlugin:
    plugin = FilterByDestPlugin.__new__(FilterByDestPlugin)
    plugin.flags = MagicMock()
    plugin.flags.allow_dests = allow_dests
    return plugin


def make_request(host: str) -> MagicMock:
    request = MagicMock(spec=HttpParser)
    request.host = host
    return request


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
