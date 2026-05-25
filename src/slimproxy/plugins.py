import ipaddress

from proxy.common.flag import flags
from proxy.http import httpStatusCodes
from proxy.http.exception import HttpRequestRejected
from proxy.http.parser import HttpParser
from proxy.http.proxy import HttpProxyBasePlugin

flags.add_argument(
    "--allow-dests",
    type=str,
    default="",
    help="Comma-separated list of allowed upstream hosts.",
)

flags.add_argument(
    "--slimproxy-filtered-client-ips",
    type=str,
    default="127.0.0.1,::1",
    help="Comma-separated list of IPv4 and IPv6 CIDR ranges.",
)

flags.add_argument(
    "--slimproxy-filtered-client-ips-mode",
    type=str,
    default="blacklist",
    help='Default: blacklist. Can be either "whitelist" or "blacklist".',
)


class FilterByClientIpPlugin(HttpProxyBasePlugin):
    def before_upstream_connection(
        self,
        request: HttpParser,
    ) -> HttpParser | None:
        assert not self.flags.unix_socket_path and self.client.addr
        assert self.flags.slimproxy_filtered_client_ips_mode in (
            "blacklist",
            "whitelist",
        )

        raw = self.flags.slimproxy_filtered_client_ips
        if not raw:
            return request

        networks = [
            ipaddress.ip_network(cidr.strip(), strict=False)
            for cidr in raw.split(",")
            if cidr.strip()
        ]
        try:
            addr = ipaddress.ip_address(self.client.addr[0])
        except ValueError:
            return request

        matched = any(addr in net for net in networks)

        mode = self.flags.slimproxy_filtered_client_ips_mode
        if mode == "blacklist" and matched:
            raise HttpRequestRejected(
                status_code=httpStatusCodes.I_AM_A_TEAPOT,
                reason=b"I'm a tea pot",
            )
        if mode == "whitelist" and not matched:
            raise HttpRequestRejected(
                status_code=httpStatusCodes.I_AM_A_TEAPOT,
                reason=b"I'm a tea pot",
            )
        return request


class FilterByDestPlugin(HttpProxyBasePlugin):
    """Drop traffic for upstream hosts not in the allowlist."""

    def before_upstream_connection(
        self,
        request: HttpParser,
    ) -> HttpParser | None:
        if self.flags.allow_dests:
            allowed = {
                h.strip()
                for h in self.flags.allow_dests.split(",")
                if h.strip()
            }
            if request.host not in allowed:
                raise HttpRequestRejected(
                    status_code=httpStatusCodes.FORBIDDEN,
                    reason=b"Destination not allowed",
                )
        return request
