import importlib.metadata
import ssl
import sys

import typer

try:
    _APP_VERSION = importlib.metadata.version("slimproxy")
except importlib.metadata.PackageNotFoundError:
    _APP_VERSION = "dev"

from proxy import Proxy
from proxy.proxy import sleep_loop

from slimproxy.check import check_target
from slimproxy.firewall import ensure_firewall_rule, remove_firewall_rule

_firewall_hidden = sys.platform != "win32"

_LOCALHOST_HOSTNAMES = frozenset({"127.0.0.1", "::1", "localhost"})


def _is_localhost(hostname: str) -> bool:
    return hostname in _LOCALHOST_HOSTNAMES


def _is_interactive() -> bool:
    return sys.stdin.isatty()


app = typer.Typer(
    name="slimproxy",
    help=(
        "Slim forward proxy with optional IP, auth, and destination"
        f" filtering. (v{_APP_VERSION})"
    ),
)


@app.callback(invoke_without_command=True)
def _main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", help="Show version and exit", is_eager=True
    ),
) -> None:
    if version:
        typer.echo(_APP_VERSION)
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        typer.echo(f"slimproxy {_APP_VERSION}")
        typer.echo()
        typer.echo(ctx.get_help())
        raise typer.Exit()


@app.command(
    help=f"Start the forward proxy server (slimproxy v{_APP_VERSION})",
)
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
    firewall_active = False
    if firewall_rule:
        if sys.platform == "win32":
            ensure_firewall_rule(port, allow_ips)
            firewall_active = True
        else:
            typer.secho(
                "--firewall-rule is only supported on Windows, ignoring.",
                err=True,
                fg=typer.colors.YELLOW,
            )

    if (
        sys.platform == "win32"
        and not _is_localhost(hostname)
        and not firewall_rule
    ):
        typer.secho(
            "WARNING: Ensure Windows Firewall allows inbound TCP traffic on "
            f"port {port}. "
            "Use --firewall-rule to add a rule automatically.",
            err=True,
            fg=typer.colors.YELLOW,
        )

    if basic_auth is None and not _is_localhost(hostname):
        typer.secho(
            "WARNING: No authentication configured. The proxy is accessible "
            f"from {hostname!r} without authentication. "
            "Consider using --basic-auth.",
            err=True,
            fg=typer.colors.YELLOW,
        )
        if _is_interactive():
            if typer.confirm("Would you like to configure authentication now?"):
                username = typer.prompt("Username:")
                password = typer.prompt(
                    "Password:", hide_input=True, confirmation_prompt=True
                )
                if not username or not password:
                    typer.secho(
                        "Error: username and password cannot be empty.",
                        err=True,
                        fg=typer.colors.RED,
                        bold=True,
                    )
                    raise typer.Exit(code=1)
                basic_auth = f"{username}:{password}"

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

    try:
        with Proxy(input_args=proxy_args) as proxy:
            typer.secho(
                f"Proxy listening on {proxy.flags.hostname}:{proxy.flags.port}",
                fg=typer.colors.GREEN,
                bold=True,
            )
            if basic_auth:
                typer.secho("  Auth: enabled", fg=typer.colors.CYAN)
            if allow_ips:
                typer.secho(
                    f"  Client IPs allowed: {allow_ips}",
                    fg=typer.colors.CYAN,
                )
            if allow_dests:
                typer.secho(
                    f"  Destinations allowed: {allow_dests}",
                    fg=typer.colors.CYAN,
                )
            typer.echo("Press Ctrl+C to stop")
            sleep_loop(proxy)
    except KeyboardInterrupt:
        typer.secho("\nShutting down...", fg=typer.colors.YELLOW)
    except Exception as exc:
        typer.secho(f"Error: {exc}", err=True, fg=typer.colors.RED, bold=True)
        raise typer.Exit(code=1)
    finally:
        if firewall_active:
            remove_firewall_rule(port)


@app.command(
    help=(
        "Check if SSL inspection is active for given targets"
        f" (slimproxy v{_APP_VERSION})"
    ),
)
def check(
    targets: list[str] = typer.Argument(
        ["api.opencode.ai"],
        help="Hosts to test SSL against",
    ),
) -> None:
    """Check if SSL inspection is active for given targets."""
    cafile = ssl.get_default_verify_paths().openssl_cafile
    typer.secho(f"Python {sys.version}", fg=typer.colors.BLUE, bold=True)
    typer.secho(
        f"Certificate store: {cafile or '(OS native)'}",
        fg=typer.colors.CYAN,
    )
    typer.echo()

    for host in targets:
        result = check_target(host)
        if "ERROR" in result:
            typer.secho(result, err=True, fg=typer.colors.RED)
        else:
            typer.echo(result)

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
