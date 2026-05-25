import re
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from slimproxy.cli import app

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
        assert result.exit_code == 0
        assert "Proxy listening" in result.stdout
        assert "Shutting down" in result.stdout

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
        assert result.exit_code == 0
        assert "Auth: enabled" in result.stdout
        assert "Client IPs allowed" in result.stdout
        assert "Destinations allowed" in result.stdout

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
        assert "only supported on Windows" in result.stderr

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
        assert "Bind failed" in result.stderr
