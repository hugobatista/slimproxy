import ctypes
import subprocess
import sys

_windows = sys.platform == "win32"


def is_admin() -> bool:
    if not _windows:
        return False
    return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]


def _elevate(args: list[str]) -> None:
    cmd_line = f"-m slimproxy {' '.join(args[1:])}"
    ret = ctypes.windll.shell32.ShellExecuteW(  # type: ignore[attr-defined]
        None, "runas", sys.executable, cmd_line, None, 1
    )
    if ret <= 32:
        raise RuntimeError(f"Failed to elevate privileges (error: {ret})")


def add_firewall_rule(port: int, remote_ips: str | None = None) -> None:
    name = f"slimproxy-port-{port}"
    args: list[str] = [
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name={name}",
        "dir=in",
        "action=allow",
        "protocol=TCP",
        f"localport={port}",
    ]
    if remote_ips:
        args.append(f"remoteip={remote_ips}")
    subprocess.run(
        args,
        check=True,
        capture_output=True,
        text=True,
    )


def remove_firewall_rule(port: int) -> None:
    name = f"slimproxy-port-{port}"
    subprocess.run(
        [
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f"name={name}",
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def ensure_firewall_rule(port: int, remote_ips: str | None = None) -> None:
    if not _windows:
        return
    if not is_admin():
        _elevate(sys.argv)
        sys.exit(0)
    try:
        remove_firewall_rule(port)
    except subprocess.CalledProcessError:
        pass
    add_firewall_rule(port, remote_ips)
