from unittest.mock import MagicMock, patch

from slimproxy.check import TARGETS, check_target


class TestCheckTarget:
    def test_success(self):
        mock_cert = {
            "issuer": [
                [("organizationName", "TestCorp")],
            ],
            "subject": [
                [("commonName", "test.example.com")],
            ],
        }
        mock_tls = MagicMock()
        mock_tls.getpeercert.return_value = mock_cert
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_tls

        with patch("ssl.create_default_context", return_value=mock_ctx):
            result = check_target("test.example.com")

        assert "TestCorp" in result
        assert "test.example.com" in result

    def test_ssl_cert_verification_error(self):
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__.side_effect = __import__(
            "ssl"
        ).SSLCertVerificationError("certificate verify failed")

        with patch("ssl.create_default_context", return_value=mock_ctx):
            result = check_target("bad.example.com")

        assert "SSL ERROR" in result
        assert "cert not trusted" in result

    def test_generic_error(self):
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__.side_effect = OSError(
            "Connection refused"
        )

        with patch("ssl.create_default_context", return_value=mock_ctx):
            result = check_target("unreachable.example.com")

        assert "ERROR" in result
        assert "Connection refused" in result

    def test_targets_are_defined(self):
        assert len(TARGETS) == 3
        assert "api.opencode.ai" in TARGETS
