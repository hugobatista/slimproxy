import subprocess
from unittest.mock import patch

import pytest

from slimproxy.firewall import (
    _elevate,
    add_firewall_rule,
    ensure_firewall_rule,
    is_admin,
    remove_firewall_rule,
)


class TestIsAdmin:
    def test_non_windows(self):
        assert not is_admin()

    def test_windows_admin(self):
        with patch("slimproxy.firewall._windows", True):
            with patch("slimproxy.firewall.ctypes") as mock_ctypes:
                mock_ctypes.windll.shell32.IsUserAnAdmin.return_value = 1
                assert is_admin()

    def test_windows_not_admin(self):
        with patch("slimproxy.firewall._windows", True):
            with patch("slimproxy.firewall.ctypes") as mock_ctypes:
                mock_ctypes.windll.shell32.IsUserAnAdmin.return_value = 0
                assert not is_admin()


class TestElevate:
    def test_success(self):
        with patch("slimproxy.firewall.ctypes") as mock_ctypes:
            mock_ctypes.windll.shell32.ShellExecuteW.return_value = 42
            with patch(
                "slimproxy.firewall.sys.argv",
                ["slimproxy", "run", "--firewall-rule"],
            ):
                with patch("slimproxy.firewall.sys.executable", "python.exe"):
                    _elevate(["slimproxy", "run", "--firewall-rule"])

        mock_ctypes.windll.shell32.ShellExecuteW.assert_called_once_with(
            None,
            "runas",
            "python.exe",
            "-m slimproxy run --firewall-rule",
            None,
            1,
        )

    def test_failure(self):
        with patch("slimproxy.firewall.ctypes") as mock_ctypes:
            mock_ctypes.windll.shell32.ShellExecuteW.return_value = 0
            with patch(
                "slimproxy.firewall.sys.argv",
                ["slimproxy", "run", "--firewall-rule"],
            ):
                with patch("slimproxy.firewall.sys.executable", "python.exe"):
                    with pytest.raises(
                        RuntimeError,
                        match="Failed to elevate privileges",
                    ):
                        _elevate(["slimproxy", "run", "--firewall-rule"])


class TestAddFirewallRule:
    def test_adds_rule(self):
        with patch("slimproxy.firewall.subprocess.run") as mock_run:
            add_firewall_rule(3128)

        mock_run.assert_called_once_with(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=slimproxy-port-3128",
                "dir=in",
                "action=allow",
                "protocol=TCP",
                "localport=3128",
            ],
            check=True,
            capture_output=True,
            text=True,
        )

    def test_adds_rule_with_remote_ips(self):
        with patch("slimproxy.firewall.subprocess.run") as mock_run:
            add_firewall_rule(3128, remote_ips="192.168.1.0/24,10.0.0.0/8")

        mock_run.assert_called_once_with(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=slimproxy-port-3128",
                "dir=in",
                "action=allow",
                "protocol=TCP",
                "localport=3128",
                "remoteip=192.168.1.0/24,10.0.0.0/8",
            ],
            check=True,
            capture_output=True,
            text=True,
        )


class TestRemoveFirewallRule:
    def test_removes_rule(self):
        with patch("slimproxy.firewall.subprocess.run") as mock_run:
            remove_firewall_rule(3128)

        mock_run.assert_called_once_with(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                "name=slimproxy-port-3128",
            ],
            check=True,
            capture_output=True,
            text=True,
        )


class TestEnsureFirewallRule:
    def test_noop_on_non_windows(self):
        with patch("slimproxy.firewall.add_firewall_rule") as mock_add:
            ensure_firewall_rule(3128)

        mock_add.assert_not_called()

    def test_elevates_when_not_admin(self):
        with patch("slimproxy.firewall._windows", True):
            with patch("slimproxy.firewall.ctypes") as mock_ctypes:
                mock_ctypes.windll.shell32.IsUserAnAdmin.return_value = 0
                mock_ctypes.windll.shell32.ShellExecuteW.return_value = 42
                with patch(
                    "slimproxy.firewall.sys.argv",
                    ["slimproxy", "run", "--firewall-rule"],
                ):
                    with patch(
                        "slimproxy.firewall.sys.executable",
                        "python.exe",
                    ):
                        with pytest.raises(SystemExit) as exc:
                            ensure_firewall_rule(3128)

        assert exc.value.code == 0
        mock_ctypes.windll.shell32.ShellExecuteW.assert_called_once()

    def test_adds_rule_when_admin(self):
        with patch("slimproxy.firewall._windows", True):
            with patch("slimproxy.firewall.ctypes") as mock_ctypes:
                mock_ctypes.windll.shell32.IsUserAnAdmin.return_value = 1
                with patch(
                    "slimproxy.firewall.remove_firewall_rule"
                ) as mock_remove:
                    with patch(
                        "slimproxy.firewall.add_firewall_rule"
                    ) as mock_add:
                        ensure_firewall_rule(3128)

        mock_remove.assert_called_once_with(3128)
        mock_add.assert_called_once_with(3128, None)

    def test_adds_rule_when_admin_with_remote_ips(self):
        with patch("slimproxy.firewall._windows", True):
            with patch("slimproxy.firewall.ctypes") as mock_ctypes:
                mock_ctypes.windll.shell32.IsUserAnAdmin.return_value = 1
                with patch(
                    "slimproxy.firewall.remove_firewall_rule"
                ) as mock_remove:
                    with patch(
                        "slimproxy.firewall.add_firewall_rule"
                    ) as mock_add:
                        ensure_firewall_rule(3128, remote_ips="10.0.0.0/8")

        mock_remove.assert_called_once_with(3128)
        mock_add.assert_called_once_with(3128, "10.0.0.0/8")

    def test_admin_remove_failure_still_adds_rule(self):
        with patch("slimproxy.firewall._windows", True):
            with patch("slimproxy.firewall.ctypes") as mock_ctypes:
                mock_ctypes.windll.shell32.IsUserAnAdmin.return_value = 1
                with patch(
                    "slimproxy.firewall.remove_firewall_rule",
                    side_effect=subprocess.CalledProcessError(1, "netsh"),
                ) as mock_remove:
                    with patch(
                        "slimproxy.firewall.add_firewall_rule"
                    ) as mock_add:
                        ensure_firewall_rule(3128)

        mock_remove.assert_called_once_with(3128)
        mock_add.assert_called_once_with(3128, None)
