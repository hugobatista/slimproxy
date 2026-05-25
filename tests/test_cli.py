from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from slimproxy.cli import app

runner = CliRunner()


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
        assert result.exit_code == 0
        assert "--port" in result.stdout
        assert "--basic-auth" in result.stdout
        assert "--allow-ips" in result.stdout
        assert "--allow-dests" in result.stdout

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
