import ssl
import sys

import typer
from proxy import Proxy
from proxy.proxy import sleep_loop

from slimproxy.check import check_target
from slimproxy.firewall import ensure_firewall_rule, remove_firewall_rule

_firewall_hidden = sys.platform != "win32"

app = typer.Typer(
    name="slimproxy",
    help=(
        "Slim forward proxy with optional IP, auth, and destination filtering."
    ),
)


@app.command()
def run(
    hostname: str = typer.Option(
        "0.0.0.0",
        "--hostname",
        help="Address to bind to",
    ),
    port: int = typer.Option(
        3128,
        "--port",
        help="Port to listen on",
    ),
    basic_auth: str | None = typer.Option(
        None,
        "--basic-auth",
        help="Enable Basic auth (format: user:password)",
    ),
    allow_ips: str | None = typer.Option(
        None,
        "--allow-ips",
        help="Comma-separated client CIDRs to allow "
        "(e.g. 192.168.1.0/24,10.0.0.0/8)",
    ),
    allow_dests: str | None = typer.Option(
        None,
        "--allow-dests",
        help="Comma-separated upstream hosts to allow "
        "(e.g. api.opencode.ai,api.github.com)",
    ),
    log_level: str = typer.Option(
        "INFO",
        "--log-level",
        help="Log level",
    ),
    timeout: int = typer.Option(
        10,
        "--timeout",
        help="Connection timeout in seconds",
    ),
    firewall_rule: bool = typer.Option(
        False,
        "--firewall-rule",
        help="Add Windows Firewall rule for the proxy port (requires admin)",
        hidden=_firewall_hidden,
    ),
) -> None:
    """Start the forward proxy server."""
    proxy_args: list[str] = [
        "--hostname",
        hostname,
        "--port",
        str(port),
        "--log-level",
        log_level,
        "--timeout",
        str(timeout),
    ]

    if basic_auth:
        proxy_args.extend(["--basic-auth", basic_auth])

    plugins: list[str] = []
    if allow_ips:
        plugins.append(
            "proxy.plugin.filter_by_client_ip.FilterByClientIpPlugin"
        )
        proxy_args.extend(
            [
                "--filtered-client-ips",
                allow_ips,
                "--filtered-client-ips-mode",
                "whitelist",
            ]
        )
    if allow_dests:
        plugins.append("slimproxy.plugins.FilterByDestPlugin")
        proxy_args.extend(["--allow-dests", allow_dests])
    if plugins:
        proxy_args.extend(["--plugins", ",".join(plugins)])

    firewall_active = False
    if firewall_rule:
        if sys.platform == "win32":
            ensure_firewall_rule(port)
            firewall_active = True
        else:
            typer.echo(
                "--firewall-rule is only supported on Windows, ignoring.",
                err=True,
            )

    try:
        with Proxy(input_args=proxy_args) as proxy:
            typer.echo(
                f"Proxy listening on {proxy.flags.hostname}:{proxy.flags.port}",
            )
            if basic_auth:
                typer.echo("  Auth: enabled")
            if allow_ips:
                typer.echo(f"  Client IPs allowed: {allow_ips}")
            if allow_dests:
                typer.echo(f"  Destinations allowed: {allow_dests}")
            typer.echo("Press Ctrl+C to stop")
            sleep_loop(proxy)
    except KeyboardInterrupt:
        typer.echo("\nShutting down...")
    except Exception as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)
    finally:
        if firewall_active:
            remove_firewall_rule(port)


@app.command()
def check(
    targets: list[str] = typer.Argument(
        ["api.opencode.ai"],
        help="Hosts to test SSL against",
    ),
) -> None:
    """Check if SSL inspection is active for given targets."""
    cafile = ssl.get_default_verify_paths().openssl_cafile
    typer.echo(f"Python {sys.version}")
    typer.echo(f"Certificate store: {cafile or '(OS native)'}")
    typer.echo()

    for host in targets:
        typer.echo(check_target(host))

    typer.echo()
    typer.echo(
        "If Issuer is your company \u2192 SSL inspection is ON",
    )
    typer.echo(
        "If Issuer is a public CA "
        "(Let's Encrypt, DigiCert, etc.) \u2192 direct TLS",
    )


if __name__ == "__main__":
    app()
