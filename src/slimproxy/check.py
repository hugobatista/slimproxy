import socket
import ssl

TARGETS = ["api.opencode.ai", "api.github.com", "models.dev"]


def check_target(host: str) -> str:
    try:
        ctx = ssl.create_default_context()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(10)
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                tls.connect((host, 443))
                cert = tls.getpeercert()
                assert cert is not None
                issuer: dict[str, str] = {}
                for rdn in cert.get("issuer", ()):
                    for pair in rdn:
                        issuer[str(pair[0])] = str(pair[1])
                org = issuer.get("organizationName", "unknown")
                subj: dict[str, str] = {}
                for rdn in cert.get("subject", ()):
                    for pair in rdn:
                        subj[str(pair[0])] = str(pair[1])
                cn = subj.get("commonName", "unknown")
                return f"{host:25s} \u2192 Issuer: {org:30s} CN: {cn}"
    except ssl.SSLCertVerificationError as e:
        return f"{host:25s} \u2192 SSL ERROR (cert not trusted): {e}"
    except Exception as e:
        return f"{host:25s} \u2192 ERROR: {e}"
