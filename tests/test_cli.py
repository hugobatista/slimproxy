import importlib
import importlib.metadata
import re
from unittest.mock import MagicMock, patch

import pytest
import typer
from typer.testing import CliRunner

from slimproxy.cli import (
    _format_listen_url,
    _get_available_addresses,
    _get_listen_addresses,
    _is_bind_all,
    _is_interactive,
    _is_localhost,
    _run_wizard,
    _show_wizard_summary,
    app,
)

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
runner = CliRunner()


def _strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


class TestCheckCommand:
    def test_with_default_targets(self):
        val = "test.example.com \u2192 Issuer: TestCorp CN: test.example.com"
        with patch("slimproxy.cli.check_target") as mock_check:
            mock_check.return_value = val
            result = runner.invoke(app, ["check"])
        assert result.exit_code == 0
        assert "Issuer" in result.stdout
        assert "TestCorp" in result.stdout

    def test_with_custom_targets(self):
        val = "custom.example.com \u2192 Issuer: Corp CN: custom.example.com"
        with patch("slimproxy.cli.check_target") as mock_check:
            mock_check.return_value = val
            result = runner.invoke(app, ["check", "custom.example.com"])
        assert result.exit_code == 0
        assert mock_check.call_count == 1
        assert mock_check.call_args[0][0] == "custom.example.com"

    def test_with_error_result(self):
        val = "bad.example.com \u2192 ERROR: Connection refused"
        with patch("slimproxy.cli.check_target") as mock_check:
            mock_check.return_value = val
            result = runner.invoke(app, ["check", "bad.example.com"])
        assert result.exit_code == 0
        assert "ERROR" in _strip_ansi(result.stderr)
        assert "Connection refused" in _strip_ansi(result.stderr)


class TestRunCommand:
    def test_help_succeeds(self):
        result = runner.invoke(app, ["run", "--help"])
        clean = _strip_ansi(result.stdout)
        assert result.exit_code == 0
        assert "--port" in clean
        assert "--basic-auth" in clean
        assert "--allow-ips" in clean
        assert "--allow-dests" in clean

    @patch("slimproxy.cli.sleep_loop", side_effect=KeyboardInterrupt())
    @patch("slimproxy.cli.Proxy")
    def test_startup_and_shutdown(self, mock_proxy, mock_sleep):
        mock_instance = MagicMock()
        mock_instance.flags.hostname = "127.0.0.1"
        mock_instance.flags.port = "13128"
        mock_proxy.return_value.__enter__.return_value = mock_instance

        result = runner.invoke(
            app,
            [
                "run",
                "--hostname",
                "127.0.0.1",
                "--port",
                "13128",
                "--log-level",
                "ERROR",
            ],
        )
        clean = _strip_ansi(result.stdout)
        assert result.exit_code == 0
        assert "http://127.0.0.1:13128" in clean
        assert "Shutting down" in clean

    @patch(
        "slimproxy.cli._get_listen_addresses",
        return_value=["10.0.0.5", "127.0.0.1"],
    )
    @patch("slimproxy.cli.sleep_loop", side_effect=KeyboardInterrupt())
    @patch("slimproxy.cli.Proxy")
    def test_with_all_options(self, mock_proxy, mock_sleep, mock_get_addrs):
        mock_instance = MagicMock()
        mock_instance.flags.hostname = "0.0.0.0"
        mock_instance.flags.port = "3128"
        mock_proxy.return_value.__enter__.return_value = mock_instance

        result = runner.invoke(
            app,
            [
                "run",
                "--basic-auth",
                "test:pass",
                "--allow-ips",
                "127.0.0.1/32,10.0.0.0/8",
                "--allow-dests",
                "example.com,test.com",
                "--log-level",
                "ERROR",
            ],
        )
        clean = _strip_ansi(result.stdout)
        assert result.exit_code == 0
        assert "http://test:****@10.0.0.5:3128" in clean
        assert "http://test:****@127.0.0.1:3128" in clean
        assert "Auth: enabled" in clean
        assert "Client IPs allowed" in clean
        assert "Destinations allowed" in clean

    def test_firewall_rule_not_in_help_on_linux(self):
        result = runner.invoke(app, ["run", "--help"])
        clean = _strip_ansi(result.stdout)
        assert result.exit_code == 0
        assert "--firewall-rule" not in clean

    def test_run_help_shows_firewall_example_on_windows(self):
        with patch("sys.platform", "win32"):
            import slimproxy.cli as cli_mod

            importlib.reload(cli_mod)
            result = runner.invoke(cli_mod.app, ["run", "--help"])
            clean = _strip_ansi(result.stdout)
            assert "firewall-rule" in clean
        importlib.reload(__import__("slimproxy").cli)

    def test_firewall_rule_ignored_on_non_windows(self):
        with patch("slimproxy.cli.sleep_loop", side_effect=KeyboardInterrupt()):
            with patch("slimproxy.cli.Proxy") as mock_proxy:
                mock_instance = MagicMock()
                mock_instance.flags.hostname = "127.0.0.1"
                mock_instance.flags.port = "13128"
                mock_proxy.return_value.__enter__.return_value = mock_instance

                result = runner.invoke(
                    app,
                    [
                        "run",
                        "--port",
                        "13128",
                        "--firewall-rule",
                        "--log-level",
                        "ERROR",
                    ],
                )

        assert result.exit_code == 0
        assert "only supported on Windows" in _strip_ansi(result.stderr)

    @patch("slimproxy.cli.sleep_loop", side_effect=KeyboardInterrupt())
    @patch("slimproxy.cli.Proxy")
    def test_firewall_rule_on_windows(self, mock_proxy, mock_sleep):
        mock_instance = MagicMock()
        mock_instance.flags.hostname = "0.0.0.0"
        mock_instance.flags.port = "3128"
        mock_proxy.return_value.__enter__.return_value = mock_instance

        with patch("sys.platform", "win32"):
            with patch("slimproxy.cli.ensure_firewall_rule") as mock_ensure:
                with patch("slimproxy.cli.remove_firewall_rule") as mock_remove:
                    result = runner.invoke(
                        app,
                        [
                            "run",
                            "--firewall-rule",
                            "--log-level",
                            "ERROR",
                        ],
                    )

        assert result.exit_code == 0
        mock_ensure.assert_called_once_with(3128, None)
        mock_remove.assert_called_once_with(3128)

    @patch("slimproxy.cli.sleep_loop", side_effect=KeyboardInterrupt())
    @patch("slimproxy.cli.Proxy")
    def test_firewall_rule_with_allow_ips_on_windows(
        self, mock_proxy, mock_sleep
    ):
        mock_instance = MagicMock()
        mock_instance.flags.hostname = "0.0.0.0"
        mock_instance.flags.port = "3128"
        mock_proxy.return_value.__enter__.return_value = mock_instance

        with patch("sys.platform", "win32"):
            with patch("slimproxy.cli.ensure_firewall_rule") as mock_ensure:
                with patch("slimproxy.cli.remove_firewall_rule") as mock_remove:
                    result = runner.invoke(
                        app,
                        [
                            "run",
                            "--firewall-rule",
                            "--allow-ips",
                            "10.0.0.0/8,192.168.1.0/24",
                            "--log-level",
                            "ERROR",
                        ],
                    )

        assert result.exit_code == 0
        mock_ensure.assert_called_once_with(3128, "10.0.0.0/8,192.168.1.0/24")
        mock_remove.assert_called_once_with(3128)

    def test_windows_non_localhost_firewall_warning(self):
        with patch("slimproxy.cli.sleep_loop", side_effect=KeyboardInterrupt()):
            with patch("slimproxy.cli.Proxy") as mock_proxy:
                with patch("sys.platform", "win32"):
                    mock_instance = MagicMock()
                    mock_instance.flags.hostname = "0.0.0.0"
                    mock_instance.flags.port = "13128"
                    mock_proxy.return_value.__enter__.return_value = (
                        mock_instance
                    )

                    result = runner.invoke(
                        app,
                        [
                            "run",
                            "--port",
                            "13128",
                            "--log-level",
                            "ERROR",
                        ],
                    )

        clean = _strip_ansi(result.stderr)
        assert result.exit_code == 0
        assert "WARNING" in clean
        assert "firewall" in clean.lower()

    def test_windows_with_firewall_no_warning(self):
        with patch("slimproxy.cli.sleep_loop", side_effect=KeyboardInterrupt()):
            with patch("slimproxy.cli.Proxy") as mock_proxy:
                with patch("sys.platform", "win32"):
                    with patch("slimproxy.cli.ensure_firewall_rule"):
                        with patch("slimproxy.cli.remove_firewall_rule"):
                            mock_instance = MagicMock()
                            mock_instance.flags.hostname = "0.0.0.0"
                            mock_instance.flags.port = "13128"
                            mock_proxy.return_value.__enter__.return_value = (
                                mock_instance
                            )

                            result = runner.invoke(
                                app,
                                [
                                    "run",
                                    "--firewall-rule",
                                    "--port",
                                    "13128",
                                    "--log-level",
                                    "ERROR",
                                ],
                            )

        assert result.exit_code == 0
        assert "Ensure Windows Firewall allows" not in result.stderr

    def test_windows_localhost_no_firewall_no_warning(self):
        with patch("slimproxy.cli.sleep_loop", side_effect=KeyboardInterrupt()):
            with patch("slimproxy.cli.Proxy") as mock_proxy:
                with patch("sys.platform", "win32"):
                    mock_instance = MagicMock()
                    mock_instance.flags.hostname = "127.0.0.1"
                    mock_instance.flags.port = "13128"
                    mock_proxy.return_value.__enter__.return_value = (
                        mock_instance
                    )

                    result = runner.invoke(
                        app,
                        [
                            "run",
                            "--hostname",
                            "127.0.0.1",
                            "--port",
                            "13128",
                            "--log-level",
                            "ERROR",
                        ],
                    )

        assert result.exit_code == 0
        assert "WARNING" not in result.stderr

    @patch("slimproxy.cli.Proxy")
    def test_error_handling(self, mock_proxy):
        mock_proxy.return_value.__enter__.side_effect = RuntimeError(
            "Bind failed: address in use"
        )
        result = runner.invoke(
            app,
            [
                "run",
                "--port",
                "13128",
                "--log-level",
                "ERROR",
            ],
        )
        assert result.exit_code == 1
        assert "Bind failed" in _strip_ansi(result.stderr)

    def test_no_warning_on_localhost(self):
        with patch("slimproxy.cli.sleep_loop", side_effect=KeyboardInterrupt()):
            with patch("slimproxy.cli.Proxy") as mock_proxy:
                mock_instance = MagicMock()
                mock_instance.flags.hostname = "127.0.0.1"
                mock_instance.flags.port = "13128"
                mock_proxy.return_value.__enter__.return_value = mock_instance

                result = runner.invoke(
                    app,
                    [
                        "run",
                        "--hostname",
                        "127.0.0.1",
                        "--port",
                        "13128",
                        "--log-level",
                        "ERROR",
                    ],
                )

        assert result.exit_code == 0
        assert "WARNING" not in result.stderr

    def test_no_warning_when_auth_provided(self):
        with patch("slimproxy.cli.sleep_loop", side_effect=KeyboardInterrupt()):
            with patch("slimproxy.cli.Proxy") as mock_proxy:
                mock_instance = MagicMock()
                mock_instance.flags.hostname = "127.0.0.1"
                mock_instance.flags.port = "13128"
                mock_proxy.return_value.__enter__.return_value = mock_instance

                result = runner.invoke(
                    app,
                    [
                        "run",
                        "--basic-auth",
                        "user:pass",
                        "--hostname",
                        "127.0.0.1",
                        "--port",
                        "13128",
                        "--log-level",
                        "ERROR",
                    ],
                )

        assert result.exit_code == 0
        assert "WARNING" not in result.stderr

    def test_warning_on_non_localhost_no_auth(self):
        with patch("slimproxy.cli.sleep_loop", side_effect=KeyboardInterrupt()):
            with patch("slimproxy.cli.Proxy") as mock_proxy:
                mock_instance = MagicMock()
                mock_instance.flags.hostname = "0.0.0.0"
                mock_instance.flags.port = "13128"
                mock_proxy.return_value.__enter__.return_value = mock_instance

                result = runner.invoke(
                    app,
                    ["run", "--port", "13128", "--log-level", "ERROR"],
                )

        clean = _strip_ansi(result.stderr)
        assert result.exit_code == 0
        assert "WARNING" in clean
        assert "No authentication configured" in clean
        assert "0.0.0.0" in clean

    def test_interactive_auth_configures(self):
        with patch("slimproxy.cli.sleep_loop", side_effect=KeyboardInterrupt()):
            with patch("slimproxy.cli.Proxy") as mock_proxy:
                with patch("slimproxy.cli._is_interactive", return_value=True):
                    with patch(
                        "slimproxy.cli.typer.confirm", return_value=True
                    ):
                        with patch(
                            "slimproxy.cli.typer.prompt",
                            side_effect=["myuser", "mypass"],
                        ):
                            mock_instance = MagicMock()
                            mock_instance.flags.hostname = "0.0.0.0"
                            mock_instance.flags.port = "13128"
                            mock_proxy.return_value.__enter__.return_value = (
                                mock_instance
                            )

                            result = runner.invoke(
                                app,
                                [
                                    "run",
                                    "--port",
                                    "13128",
                                    "--log-level",
                                    "ERROR",
                                ],
                            )

        assert result.exit_code == 0
        assert "Auth: enabled" in _strip_ansi(result.stdout)

    def test_interactive_auth_declined(self):
        with patch("slimproxy.cli.sleep_loop", side_effect=KeyboardInterrupt()):
            with patch("slimproxy.cli.Proxy") as mock_proxy:
                with patch("slimproxy.cli._is_interactive", return_value=True):
                    with patch(
                        "slimproxy.cli.typer.confirm", return_value=False
                    ):
                        mock_instance = MagicMock()
                        mock_instance.flags.hostname = "0.0.0.0"
                        mock_instance.flags.port = "13128"
                        mock_proxy.return_value.__enter__.return_value = (
                            mock_instance
                        )

                        result = runner.invoke(
                            app,
                            ["run", "--port", "13128", "--log-level", "ERROR"],
                        )

        assert result.exit_code == 0
        assert "Auth: enabled" not in result.stdout

    def test_interactive_auth_empty_rejected(self):
        with patch("slimproxy.cli._is_interactive", return_value=True):
            with patch("slimproxy.cli.typer.confirm", return_value=True):
                with patch(
                    "slimproxy.cli.typer.prompt",
                    side_effect=["", ""],
                ):
                    result = runner.invoke(
                        app,
                        ["run", "--port", "13128", "--log-level", "ERROR"],
                    )

        assert result.exit_code == 1
        assert "cannot be empty" in _strip_ansi(result.stderr)


class TestVersion:
    def test_version_flag(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert result.stdout.strip() == "0.1.0"

    def test_version_in_help(self):
        result = runner.invoke(app)
        assert result.exit_code == 0
        assert "0.1.0" in result.stdout
        assert "slimproxy" in result.stdout.splitlines()[0]

    def test_version_in_run_help(self):
        result = runner.invoke(app, ["run", "--help"])
        assert result.exit_code == 0
        assert "0.1.0" in result.stdout

    def test_version_in_check_help(self):
        result = runner.invoke(app, ["check", "--help"])
        assert result.exit_code == 0
        assert "0.1.0" in result.stdout

    def test_version_in_help_flag(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "0.1.0" in result.stdout

    def test_version_dev_fallback(self):
        import slimproxy.cli as cli_mod

        orig = cli_mod._APP_VERSION
        cli_mod._APP_VERSION = "dev"
        try:
            result = runner.invoke(app, ["--version"])
            assert result.exit_code == 0
            assert result.stdout.strip() == "dev"
        finally:
            cli_mod._APP_VERSION = orig

    def test_version_package_not_found(self):
        with patch(
            "importlib.metadata.version",
            side_effect=importlib.metadata.PackageNotFoundError,
        ):
            import slimproxy.cli as cli_mod

            importlib.reload(cli_mod)
            result = runner.invoke(cli_mod.app, ["--version"])
            assert result.exit_code == 0
            assert result.stdout.strip() == "dev"
        importlib.reload(__import__("slimproxy").cli)


class TestHelpers:
    def test_is_localhost_positive(self):
        assert _is_localhost("127.0.0.1")
        assert _is_localhost("::1")
        assert _is_localhost("localhost")

    def test_is_localhost_negative(self):
        assert not _is_localhost("0.0.0.0")
        assert not _is_localhost("192.168.1.1")
        assert not _is_localhost("example.com")

    def test_is_interactive_not_a_tty(self):
        assert not _is_interactive()

    def test_is_bind_all_positive(self):
        assert _is_bind_all("0.0.0.0")
        assert _is_bind_all("::")

    def test_is_bind_all_negative(self):
        assert not _is_bind_all("127.0.0.1")
        assert not _is_bind_all("192.168.1.1")

    def test_get_listen_addresses_specific_ip(self):
        result = _get_listen_addresses("192.168.1.1")
        assert result == ["192.168.1.1"]

    @patch("slimproxy.cli.socket.gethostname", return_value="myhost")
    @patch(
        "slimproxy.cli.socket.gethostbyname_ex",
        return_value=("myhost", [], ["10.0.0.5", "192.168.1.10"]),
    )
    def test_get_listen_addresses_bind_all(
        self, mock_gethostbyname_ex, mock_gethostname
    ):
        result = _get_listen_addresses("0.0.0.0")
        assert result == ["10.0.0.5", "127.0.0.1", "192.168.1.10"]

    @patch("slimproxy.cli.socket.gethostname", side_effect=OSError)
    def test_get_listen_addresses_fallback(self, mock_gethostname):
        result = _get_listen_addresses("0.0.0.0")
        assert result == ["127.0.0.1"]

    def test_format_listen_url_with_auth(self):
        result = _format_listen_url("10.0.0.1", 3128, "user:secret")
        assert result == "http://user:****@10.0.0.1:3128"

    def test_format_listen_url_no_auth(self):
        result = _format_listen_url("10.0.0.1", 3128, None)
        assert result == "http://10.0.0.1:3128"

    def test_get_available_addresses_always_includes_common(self):
        result = _get_available_addresses()
        assert "0.0.0.0" in result
        assert "127.0.0.1" in result
        assert "::" in result
        assert "::1" in result
        for addr in result:
            assert isinstance(addr, str)

    @patch(
        "slimproxy.cli.socket.getaddrinfo",
        side_effect=OSError("no network"),
    )
    def test_get_available_addresses_oserror_fallback(self, mock_getaddrinfo):
        result = _get_available_addresses()
        assert "0.0.0.0" in result
        assert "127.0.0.1" in result


class TestRunWizard:
    def test_all_defaults(self):
        with patch("slimproxy.cli.typer.prompt") as mock_prompt:
            with patch("slimproxy.cli.typer.confirm", return_value=False):
                mock_prompt.side_effect = [
                    "0.0.0.0",
                    "3128",
                    "INFO",
                    "10",
                    "",
                    "",
                ]
                result = _run_wizard(
                    "0.0.0.0", 3128, None, None, None, "INFO", 10, False
                )
        assert result == ("0.0.0.0", 3128, None, None, None, "INFO", 10, False)

    def test_with_auth(self):
        with patch("slimproxy.cli.typer.prompt") as mock_prompt:
            with patch("slimproxy.cli.typer.confirm") as mock_confirm:
                mock_confirm.side_effect = [True]
                mock_prompt.side_effect = [
                    "0.0.0.0",
                    "3128",
                    "INFO",
                    "10",
                    "testuser",
                    "testpass",
                    "",
                    "",
                ]
                result = _run_wizard(
                    "0.0.0.0", 3128, None, None, None, "INFO", 10, False
                )
        assert result == (
            "0.0.0.0",
            3128,
            "testuser:testpass",
            None,
            None,
            "INFO",
            10,
            False,
        )

    def test_with_existing_auth(self):
        with patch("slimproxy.cli.typer.prompt") as mock_prompt:
            with patch("slimproxy.cli.typer.confirm", return_value=False):
                mock_prompt.side_effect = [
                    "0.0.0.0",
                    "3128",
                    "INFO",
                    "10",
                    "",
                    "",
                ]
                result = _run_wizard(
                    "0.0.0.0",
                    3128,
                    "existing:pass",
                    None,
                    None,
                    "INFO",
                    10,
                    False,
                )
        assert result == (
            "0.0.0.0",
            3128,
            "existing:pass",
            None,
            None,
            "INFO",
            10,
            False,
        )

    def test_with_existing_auth_rotated(self):
        with patch("slimproxy.cli.typer.prompt") as mock_prompt:
            with patch("slimproxy.cli.typer.confirm") as mock_confirm:
                mock_confirm.side_effect = [True]
                mock_prompt.side_effect = [
                    "0.0.0.0",
                    "3128",
                    "INFO",
                    "10",
                    "newuser",
                    "newpass",
                    "",
                    "",
                ]
                result = _run_wizard(
                    "0.0.0.0", 3128, "old:pass", None, None, "INFO", 10, False
                )
        assert result == (
            "0.0.0.0",
            3128,
            "newuser:newpass",
            None,
            None,
            "INFO",
            10,
            False,
        )

    def test_with_existing_auth_empty_raises(self):
        with patch("slimproxy.cli.typer.prompt") as mock_prompt:
            with patch("slimproxy.cli.typer.confirm") as mock_confirm:
                mock_confirm.side_effect = [True]
                mock_prompt.side_effect = [
                    "0.0.0.0",
                    "3128",
                    "INFO",
                    "10",
                    "",
                    "",
                ]
                with pytest.raises(typer.Exit) as exc:
                    _run_wizard(
                        "0.0.0.0",
                        3128,
                        "old:pass",
                        None,
                        None,
                        "INFO",
                        10,
                        False,
                    )
        assert exc.value.exit_code == 1

    def test_with_auth_empty_raises(self):
        with patch("slimproxy.cli.typer.prompt") as mock_prompt:
            with patch("slimproxy.cli.typer.confirm") as mock_confirm:
                mock_confirm.side_effect = [True]
                mock_prompt.side_effect = [
                    "0.0.0.0",
                    "3128",
                    "INFO",
                    "10",
                    "",
                    "",
                ]
                with pytest.raises(typer.Exit) as exc:
                    _run_wizard(
                        "0.0.0.0", 3128, None, None, None, "INFO", 10, False
                    )
        assert exc.value.exit_code == 1

    def test_with_allow_ips(self):
        with patch("slimproxy.cli.typer.prompt") as mock_prompt:
            with patch("slimproxy.cli.typer.confirm", return_value=False):
                mock_prompt.side_effect = [
                    "0.0.0.0",
                    "3128",
                    "INFO",
                    "10",
                    "10.0.0.0/8",
                    "",
                ]
                result = _run_wizard(
                    "0.0.0.0", 3128, None, None, None, "INFO", 10, False
                )
        assert result == (
            "0.0.0.0",
            3128,
            None,
            "10.0.0.0/8",
            None,
            "INFO",
            10,
            False,
        )

    def test_with_allow_dests(self):
        with patch("slimproxy.cli.typer.prompt") as mock_prompt:
            with patch("slimproxy.cli.typer.confirm", return_value=False):
                mock_prompt.side_effect = [
                    "0.0.0.0",
                    "3128",
                    "INFO",
                    "10",
                    "",
                    "api.example.com",
                ]
                result = _run_wizard(
                    "0.0.0.0", 3128, None, None, None, "INFO", 10, False
                )
        assert result == (
            "0.0.0.0",
            3128,
            None,
            None,
            "api.example.com",
            "INFO",
            10,
            False,
        )

    def test_with_prefilled_ips_and_dests(self):
        with patch("slimproxy.cli.typer.prompt") as mock_prompt:
            with patch("slimproxy.cli.typer.confirm", return_value=False):
                mock_prompt.side_effect = [
                    "0.0.0.0",
                    "3128",
                    "INFO",
                    "10",
                ]
                result = _run_wizard(
                    "0.0.0.0",
                    3128,
                    None,
                    "10.0.0.0/8",
                    "api.example.com",
                    "INFO",
                    10,
                    False,
                )
        assert result == (
            "0.0.0.0",
            3128,
            None,
            "10.0.0.0/8",
            "api.example.com",
            "INFO",
            10,
            False,
        )

    def test_invalid_port(self):
        with patch("slimproxy.cli.typer.prompt") as mock_prompt:
            with patch("slimproxy.cli.typer.confirm", return_value=False):
                mock_prompt.side_effect = [
                    "0.0.0.0",
                    "abc",
                    "3128",
                    "INFO",
                    "10",
                    "",
                    "",
                ]
                result = _run_wizard(
                    "0.0.0.0", 3128, None, None, None, "INFO", 10, False
                )
        assert result == ("0.0.0.0", 3128, None, None, None, "INFO", 10, False)

    def test_invalid_log_level(self):
        with patch("slimproxy.cli.typer.prompt") as mock_prompt:
            with patch("slimproxy.cli.typer.confirm", return_value=False):
                mock_prompt.side_effect = [
                    "0.0.0.0",
                    "3128",
                    "BOGUS",
                    "INFO",
                    "10",
                    "",
                    "",
                ]
                result = _run_wizard(
                    "0.0.0.0", 3128, None, None, None, "INFO", 10, False
                )
        assert result == ("0.0.0.0", 3128, None, None, None, "INFO", 10, False)

    def test_firewall_windows_admin(self):
        with patch("sys.platform", "win32"):
            with patch("slimproxy.cli.is_admin", return_value=True):
                with patch("slimproxy.cli.typer.prompt") as mock_prompt:
                    with patch("slimproxy.cli.typer.confirm") as mock_confirm:
                        mock_confirm.side_effect = [True, False]
                        mock_prompt.side_effect = [
                            "",  # firewall IPs
                            "0.0.0.0",
                            "3128",
                            "INFO",
                            "10",
                            "",  # allow_dests
                        ]
                        result = _run_wizard(
                            "0.0.0.0",
                            3128,
                            None,
                            None,
                            None,
                            "INFO",
                            10,
                            False,
                        )
        assert result[-1] is True

    def test_firewall_windows_admin_with_ips(self):
        with patch("sys.platform", "win32"):
            with patch("slimproxy.cli.is_admin", return_value=True):
                with patch("slimproxy.cli.typer.prompt") as mock_prompt:
                    with patch("slimproxy.cli.typer.confirm") as mock_confirm:
                        mock_confirm.side_effect = [True, False]
                        mock_prompt.side_effect = [
                            "10.0.0.0/8",  # firewall IPs
                            "0.0.0.0",
                            "3128",
                            "INFO",
                            "10",
                            "",  # allow_dests
                        ]
                        result = _run_wizard(
                            "0.0.0.0",
                            3128,
                            None,
                            None,
                            None,
                            "INFO",
                            10,
                            False,
                        )
        assert result[-1] is True
        assert result[3] == "10.0.0.0/8"

    def test_firewall_windows_declined(self):
        with patch("sys.platform", "win32"):
            with patch("slimproxy.cli.typer.prompt") as mock_prompt:
                with patch("slimproxy.cli.typer.confirm") as mock_confirm:
                    mock_confirm.side_effect = [False, False]
                    mock_prompt.side_effect = [
                        "0.0.0.0",
                        "3128",
                        "INFO",
                        "10",
                        "",
                        "",
                    ]
                    result = _run_wizard(
                        "0.0.0.0",
                        3128,
                        None,
                        None,
                        None,
                        "INFO",
                        10,
                        False,
                    )
        assert result[-1] is False

    def test_firewall_windows_not_admin(self):
        with patch("sys.platform", "win32"):
            with patch("slimproxy.cli.is_admin", return_value=False):
                with patch("slimproxy.cli.typer.prompt") as mock_prompt:
                    with patch("slimproxy.cli.typer.confirm") as mock_confirm:
                        with patch("slimproxy.cli._elevate"):
                            mock_confirm.side_effect = [True]
                            mock_prompt.side_effect = [
                                "",  # firewall IPs
                            ]
                            with pytest.raises(SystemExit):
                                _run_wizard(
                                    "0.0.0.0",
                                    3128,
                                    None,
                                    None,
                                    None,
                                    "INFO",
                                    10,
                                    False,
                                )
        mock_confirm.assert_called_once()
        mock_prompt.assert_called_once()

    def test_firewall_windows_already_handled(self):
        with patch("sys.platform", "win32"):
            with patch("slimproxy.cli.typer.prompt") as mock_prompt:
                with patch("slimproxy.cli.typer.confirm", return_value=False):
                    mock_prompt.side_effect = [
                        "0.0.0.0",
                        "3128",
                        "INFO",
                        "10",
                        "",
                        "",
                    ]
                    result = _run_wizard(
                        "0.0.0.0",
                        3128,
                        None,
                        None,
                        None,
                        "INFO",
                        10,
                        True,
                    )
        assert result[-1] is True

    def test_firewall_windows_elevate_passes_allow_ips(self):
        with patch("sys.platform", "win32"):
            with patch("slimproxy.cli.is_admin", return_value=False):
                with patch("slimproxy.cli.typer.prompt") as mock_prompt:
                    with patch("slimproxy.cli.typer.confirm") as mock_confirm:
                        with patch("slimproxy.cli._elevate") as mock_elevate:
                            mock_confirm.side_effect = [True]
                            mock_prompt.side_effect = [
                                "10.0.0.0/8",
                            ]
                            with pytest.raises(SystemExit):
                                _run_wizard(
                                    "0.0.0.0",
                                    3128,
                                    None,
                                    None,
                                    None,
                                    "INFO",
                                    10,
                                    False,
                                )
        mock_elevate.assert_called_once()
        args = mock_elevate.call_args[0][0]
        assert "--_wizard-firewall-handled" in args
        assert "--allow-ips" in args
        assert "10.0.0.0/8" in args


class TestShowWizardSummary:
    def test_no_auth_no_firewall(self, capsys):
        _show_wizard_summary(
            "0.0.0.0", 3128, None, None, None, "INFO", 10, False
        )
        captured = capsys.readouterr()
        assert "Summary" in captured.out
        assert "auth:              none" in captured.out.lower()
        assert "firewall" not in captured.out.lower()

    def test_with_auth(self, capsys):
        _show_wizard_summary(
            "0.0.0.0", 3128, "user:pass", None, None, "INFO", 10, False
        )
        captured = capsys.readouterr()
        assert "user:****" in captured.out

    def test_with_ips_and_dests(self, capsys):
        _show_wizard_summary(
            "0.0.0.0",
            3128,
            None,
            "10.0.0.0/8",
            "api.example.com",
            "INFO",
            10,
            False,
        )
        captured = capsys.readouterr()
        assert "10.0.0.0/8" in captured.out
        assert "api.example.com" in captured.out

    def test_with_firewall_windows(self, capsys):
        with patch("sys.platform", "win32"):
            _show_wizard_summary(
                "0.0.0.0", 3128, None, None, None, "INFO", 10, True
            )
        captured = capsys.readouterr()
        assert "Firewall" in captured.out
        assert "rule added" in captured.out

    def test_with_firewall_windows_restricted(self, capsys):
        with patch("sys.platform", "win32"):
            _show_wizard_summary(
                "0.0.0.0",
                3128,
                None,
                "10.0.0.0/8",
                None,
                "INFO",
                10,
                True,
            )
        captured = capsys.readouterr()
        assert "restricted to 10.0.0.0/8" in captured.out


class TestWizardCliIntegration:
    def test_requires_tty(self):
        result = runner.invoke(app, ["run", "--wizard", "--log-level", "ERROR"])
        assert result.exit_code == 1
        assert "requires an interactive terminal" in _strip_ansi(result.stderr)

    @patch("slimproxy.cli.sleep_loop", side_effect=KeyboardInterrupt())
    @patch("slimproxy.cli.Proxy")
    def test_startup_after_wizard(self, mock_proxy, mock_sleep):
        mock_instance = MagicMock()
        mock_instance.flags.hostname = "0.0.0.0"
        mock_instance.flags.port = "3128"
        mock_proxy.return_value.__enter__.return_value = mock_instance

        with patch("slimproxy.cli._is_interactive", return_value=True):
            with patch("slimproxy.cli._run_wizard") as mock_wizard:
                mock_wizard.return_value = (
                    "0.0.0.0",
                    3128,
                    None,
                    None,
                    None,
                    "ERROR",
                    10,
                    False,
                )
                result = runner.invoke(
                    app,
                    ["run", "--wizard", "--log-level", "ERROR"],
                    input="y\n",
                )

        clean = _strip_ansi(result.stdout)
        assert result.exit_code == 0
        assert "start proxy with these settings?" in clean.lower()

    @patch("slimproxy.cli.sleep_loop", side_effect=KeyboardInterrupt())
    @patch("slimproxy.cli.Proxy")
    def test_cancelled_at_summary(self, mock_proxy, mock_sleep):
        with patch("slimproxy.cli._is_interactive", return_value=True):
            with patch("slimproxy.cli._run_wizard") as mock_wizard:
                mock_wizard.return_value = (
                    "0.0.0.0",
                    3128,
                    None,
                    None,
                    None,
                    "ERROR",
                    10,
                    False,
                )
                result = runner.invoke(
                    app,
                    ["run", "--wizard", "--log-level", "ERROR"],
                    input="n\n",
                )

        assert result.exit_code == 0

    @patch("slimproxy.cli.sleep_loop", side_effect=KeyboardInterrupt())
    @patch("slimproxy.cli.Proxy")
    def test_firewall_after_wizard_windows(self, mock_proxy, mock_sleep):
        mock_instance = MagicMock()
        mock_instance.flags.hostname = "0.0.0.0"
        mock_instance.flags.port = "3128"
        mock_proxy.return_value.__enter__.return_value = mock_instance

        with patch("slimproxy.cli._is_interactive", return_value=True):
            with patch("slimproxy.cli._run_wizard") as mock_wizard:
                with patch("slimproxy.cli.ensure_firewall_rule") as mock_fw:
                    with patch(
                        "slimproxy.cli.remove_firewall_rule"
                    ) as mock_remove:
                        with patch("sys.platform", "win32"):
                            mock_wizard.return_value = (
                                "0.0.0.0",
                                3128,
                                None,
                                "10.0.0.0/8",
                                None,
                                "ERROR",
                                10,
                                True,
                            )
                            result = runner.invoke(
                                app,
                                ["run", "--wizard", "--log-level", "ERROR"],
                                input="y\n",
                            )

        assert result.exit_code == 0
        mock_fw.assert_called_once_with(3128, "10.0.0.0/8")
        mock_remove.assert_called_once_with(3128)
