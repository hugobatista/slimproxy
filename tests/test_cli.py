import importlib
import importlib.metadata
import re
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from slimproxy.cli import _is_interactive, _is_localhost, app

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
        assert "Proxy listening" in clean
        assert "Shutting down" in clean

    @patch("slimproxy.cli.sleep_loop", side_effect=KeyboardInterrupt())
    @patch("slimproxy.cli.Proxy")
    def test_with_all_options(self, mock_proxy, mock_sleep):
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
        assert "Auth: enabled" in clean
        assert "Client IPs allowed" in clean
        assert "Destinations allowed" in clean

    def test_firewall_rule_not_in_help_on_linux(self):
        result = runner.invoke(app, ["run", "--help"])
        clean = _strip_ansi(result.stdout)
        assert result.exit_code == 0
        assert "--firewall-rule" not in clean

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
        mock_ensure.assert_called_once_with(3128)
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
                mock_instance.flags.hostname = "0.0.0.0"
                mock_instance.flags.port = "13128"
                mock_proxy.return_value.__enter__.return_value = mock_instance

                result = runner.invoke(
                    app,
                    [
                        "run",
                        "--basic-auth",
                        "user:pass",
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
