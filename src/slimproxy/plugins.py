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
