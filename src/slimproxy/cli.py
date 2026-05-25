import importlib.metadata
import socket
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
from slimproxy.firewall import (
    _elevate,
    ensure_firewall_rule,
    is_admin,
    remove_firewall_rule,
)

_firewall_hidden = sys.platform != "win32"

_LOCALHOST_HOSTNAMES = frozenset({"127.0.0.1", "::1", "localhost"})

_run_epilog = "\n\n".join(
    [
        "",
        "Examples:",
        "slimproxy run --wizard",
        "slimproxy run --basic-auth user:pass --allow-ips 192.168.1.0/24",
        "slimproxy run --allow-dests api.opencode.ai",
        "slimproxy run --port 8888 --log-level DEBUG",
        "slimproxy run --hostname 127.0.0.1 --port 8888",
        "slimproxy run --basic-auth user:pass --allow-ips 10.0.0.0/8"
        " --allow-dests api.opencode.ai",
    ]
)
if sys.platform == "win32":
    _run_epilog += "\n\n" + (
        "slimproxy run --firewall-rule --allow-ips 192.168.100.0/24"
        " --basic-auth myuser:mypassword\n"
        "slimproxy run --wizard"
    )

_check_epilog = "\n\n".join(
    [
        "",
        "Examples:",
        "slimproxy check api.opencode.ai",
        "slimproxy check api.opencode.ai api.github.com models.openai.com",
        "slimproxy check google.com",
    ]
)


def _is_localhost(hostname: str) -> bool:
    return hostname in _LOCALHOST_HOSTNAMES


def _is_interactive() -> bool:
    return sys.stdin.isatty()


def _is_bind_all(hostname: str) -> bool:
    return hostname in ("0.0.0.0", "::")


def _get_listen_addresses(hostname: str) -> list[str]:
    if not _is_bind_all(hostname):
        return [hostname]
    addrs: set[str] = set()
    try:
        _, _, ips = socket.gethostbyname_ex(socket.gethostname())
        addrs.update(ip for ip in ips if not ip.startswith("127."))
    except OSError:
        pass
    addrs.add("127.0.0.1")
    return sorted(addrs)


def _get_available_addresses() -> list[str]:
    addrs: set[str] = set()
    addrs.update(("0.0.0.0", "127.0.0.1", "::", "::1"))
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if isinstance(ip, str):
                if not ip.startswith("127.") and ip != "::1":
                    addrs.add(ip)
    except OSError:
        pass
    return sorted(addrs)


def _format_listen_url(addr: str, port: int, auth: str | None) -> str:
    if auth is None:
        return f"http://{addr}:{port}"
    user = auth.split(":", 1)[0]
    return f"http://{user}:****@{addr}:{port}"


_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")


def _run_wizard(
    cur_hostname: str,
    cur_port: int,
    cur_basic_auth: str | None,
    cur_allow_ips: str | None,
    cur_allow_dests: str | None,
    cur_log_level: str,
    cur_timeout: int,
    firewall_handled: bool,
) -> tuple[str, int, str | None, str | None, str | None, str, int, bool]:
    firewall_active = False

    if sys.platform == "win32":
        if not firewall_handled:
            typer.secho(
                "\n--- Firewall (Windows) ---\n",
                fg=typer.colors.CYAN,
                bold=True,
            )
            if typer.confirm("Add Windows Firewall rule?", default=False):
                ips = typer.prompt(
                    "Restrict to IPs"
                    " (CIDR, comma-separated, e.g. 192.168.1.0/24,10.0.0.0/8)",
                    default="",
                    show_default=False,
                )
                cur_allow_ips = ips.strip() or cur_allow_ips
                if not is_admin():
                    elevate_args = list(sys.argv)
                    if "--_wizard-firewall-handled" not in elevate_args:
                        elevate_args.append("--_wizard-firewall-handled")
                    if cur_allow_ips and "--allow-ips" not in elevate_args:
                        elevate_args.extend(["--allow-ips", cur_allow_ips])
                    _elevate(elevate_args)
                    sys.exit(0)
                firewall_active = True
        else:
            firewall_active = True

    typer.secho(
        "\n--- Network ---\n",
        fg=typer.colors.CYAN,
        bold=True,
    )
    addrs = _get_available_addresses()
    typer.echo("  Available addresses: " + ", ".join(addrs))
    hostname = typer.prompt("Hostname", default=cur_hostname)
    while True:
        raw = typer.prompt("Port", default=str(cur_port))
        try:
            port = int(raw)
            break
        except ValueError:
            typer.secho(
                "Error: port must be a number.",
                err=True,
                fg=typer.colors.RED,
            )
    while True:
        raw = typer.prompt(
            f"Log level ({'/'.join(_LOG_LEVELS)})",
            default=cur_log_level,
        )
        if raw.upper() in _LOG_LEVELS:
            log_level = raw.upper()
            break
        typer.secho(
            f"Error: must be one of {', '.join(_LOG_LEVELS)}.",
            err=True,
            fg=typer.colors.RED,
        )
    timeout = int(typer.prompt("Timeout (seconds)", default=str(cur_timeout)))

    if cur_basic_auth is not None:
        typer.secho(
            "\n--- Authentication ---\n",
            fg=typer.colors.CYAN,
            bold=True,
        )
        user = cur_basic_auth.split(":", 1)[0]
        typer.echo(f"  Auth already set for user: {user}")
        basic_auth = cur_basic_auth
        if typer.confirm("Change credentials?", default=False):
            username = typer.prompt("Username")
            password = typer.prompt(
                "Password", hide_input=True, confirmation_prompt=True
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
    else:
        typer.secho(
            "\n--- Authentication ---\n",
            fg=typer.colors.CYAN,
            bold=True,
        )
        if typer.confirm("Enable authentication?", default=False):
            username = typer.prompt("Username")
            password = typer.prompt(
                "Password", hide_input=True, confirmation_prompt=True
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
        else:
            basic_auth = None

    typer.secho(
        "\n--- Access Control ---\n",
        fg=typer.colors.CYAN,
        bold=True,
    )
    if cur_allow_ips is None and not firewall_active:
        raw = typer.prompt(
            "Restrict by client IPs"
            " (CIDR, comma-separated, e.g. 192.168.1.0/24,10.0.0.0/8)",
            default="",
            show_default=False,
        )
        allow_ips = raw.strip() or None
    else:
        typer.echo(f"  Client IPs: {cur_allow_ips or 'all'}")
        allow_ips = cur_allow_ips
    if cur_allow_dests is None:
        raw = typer.prompt(
            "Restrict by destination hosts"
            " (comma-separated, e.g. api.example.com,api.github.com)",
            default="",
            show_default=False,
        )
        allow_dests = raw.strip() or None
    else:
        typer.echo(f"  Destinations: {cur_allow_dests}")
        allow_dests = cur_allow_dests

    return (
        hostname,
        port,
        basic_auth,
        allow_ips,
        allow_dests,
        log_level,
        timeout,
        firewall_active,
    )


def _show_wizard_summary(
    hostname: str,
    port: int,
    basic_auth: str | None,
    allow_ips: str | None,
    allow_dests: str | None,
    log_level: str,
    timeout: int,
    firewall_active: bool,
) -> None:
    typer.secho("\n--- Summary ---\n", fg=typer.colors.GREEN, bold=True)
    typer.echo(f"  Hostname:          {hostname}")
    typer.echo(f"  Port:              {port}")
    typer.echo(f"  Log level:         {log_level}")
    typer.echo(f"  Timeout:           {timeout}s")
    if basic_auth:
        user = basic_auth.split(":", 1)[0]
        typer.echo(f"  Auth:              {user}:****")
    else:
        typer.echo("  Auth:              none")
    typer.echo(f"  Allowed IPs:       {allow_ips or 'all'}")
    typer.echo(f"  Allowed dests:     {allow_dests or 'all'}")
    if sys.platform == "win32" and firewall_active:
        msg = "rule added"
        if allow_ips:
            msg += f", restricted to {allow_ips}"
        typer.echo(f"  Firewall:          {msg}")


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
    epilog=_run_epilog,
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
        "(e.g. 192.168.1.0/24,10.0.0.0/8). "
        "When omitted, all IPs are allowed.",
    ),
    allow_dests: str | None = typer.Option(
        None,
        "--allow-dests",
        help="Comma-separated upstream hosts to allow "
        "(e.g. api.opencode.ai,api.github.com). "
        "When omitted, all destinations are allowed.",
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
    wizard: bool = typer.Option(
        False,
        "--wizard",
        help="Guided interactive setup wizard",
    ),
    _wizard_firewall_handled: bool = typer.Option(
        False,
        "--_wizard-firewall-handled",
        hidden=True,
        help="Internal flag for wizard firewall elevation",
    ),
) -> None:
    """Start the forward proxy server."""
    if wizard:
        if not _is_interactive():
            typer.secho(
                "Error: --wizard requires an interactive terminal.",
                err=True,
                fg=typer.colors.RED,
                bold=True,
            )
            raise typer.Exit(code=1)
        (
            hostname,
            port,
            basic_auth,
            allow_ips,
            allow_dests,
            log_level,
            timeout,
            wizard_firewall_active,
        ) = _run_wizard(
            hostname,
            port,
            basic_auth,
            allow_ips,
            allow_dests,
            log_level,
            timeout,
            _wizard_firewall_handled,
        )
        _show_wizard_summary(
            hostname,
            port,
            basic_auth,
            allow_ips,
            allow_dests,
            log_level,
            timeout,
            wizard_firewall_active,
        )
        if not typer.confirm(
            "\nStart proxy with these settings?", default=True
        ):
            raise typer.Exit()
        firewall_active = wizard_firewall_active
        if wizard_firewall_active and sys.platform == "win32":
            ensure_firewall_rule(port, allow_ips)
    else:
        firewall_active = False

    if not wizard and firewall_rule:
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
        and not wizard
    ):
        typer.secho(
            "WARNING: Ensure Windows Firewall allows inbound TCP traffic on "
            f"port {port}. "
            "Use --firewall-rule to add a rule automatically.",
            err=True,
            fg=typer.colors.YELLOW,
        )

    if basic_auth is None and not _is_localhost(hostname) and not wizard:
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

    if basic_auth and not _is_localhost(hostname):
        typer.secho(
            "WARNING: Basic Auth credentials are sent over cleartext HTTP "
            "and can be intercepted by anyone on the network.",
            err=True,
            fg=typer.colors.YELLOW,
        )

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
        plugins.append("slimproxy.plugins.FilterByClientIpPlugin")
        proxy_args.extend(
            [
                "--slimproxy-filtered-client-ips",
                allow_ips,
                "--slimproxy-filtered-client-ips-mode",
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
            typer.secho("Proxy listening on:", fg=typer.colors.GREEN, bold=True)
            for addr in _get_listen_addresses(hostname):
                typer.echo(f"  {_format_listen_url(addr, port, basic_auth)}")
            if basic_auth:
                typer.secho("  Auth: enabled", fg=typer.colors.CYAN)
            if firewall_active:
                msg = "  Firewall: rule added"
                if allow_ips:
                    msg += f", restricted to {allow_ips}"
                typer.secho(msg, fg=typer.colors.CYAN)
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
    epilog=_check_epilog,
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
