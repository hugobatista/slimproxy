[![GitHub Tag](https://img.shields.io/github/v/tag/hugobatista/slimproxy?logo=github&label=latest)](https://go.hugobatista.com/gh/slimproxy/releases)
[![Lint](https://img.shields.io/github/actions/workflow/status/hugobatista/slimproxy/lint.yml?label=Lint)](https://go.hugobatista.com/gh/slimproxy/actions/workflows/lint.yml)
[![Test](https://img.shields.io/github/actions/workflow/status/hugobatista/slimproxy/test.yml?label=Test)](https://go.hugobatista.com/gh/slimproxy/actions/workflows/test.yml)
[![PyPI - Version](https://img.shields.io/pypi/v/slimproxy.svg)](https://pypi.org/project/slimproxy)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/slimproxy.svg)](https://pypi.org/project/slimproxy)
[![PyPI - License](https://img.shields.io/pypi/l/slimproxy.svg)](https://pypi.org/project/slimproxy)

A lightweight forward proxy CLI built on `proxy.py` — deploy anywhere Python runs. Useful when you need a quick proxy on a host where squid is overkill or unavailable (no Docker, Windows host, locked-down desktop, etc.) and you want to forward requests through that host.

Typical scenario: your enterprise-managed desktop has a forward proxy that intercepts and inspects traffic to certain endpoints (AI APIs, for example). Deploy slimproxy on a second, unmanaged machine on the same network, point your tools at it, and bypass the inspection.

## Installation

```bash
pip install slimproxy
```

Or from source:

```bash
uv sync
```

Or via Docker:

```bash
docker build -t slimproxy .
```

## Usage

### `run` — Start the proxy server

```bash
slimproxy run \
  --port 3128 \
  --basic-auth myuser:password123 \
  --allow-ips "192.168.1.0/24,10.0.0.0/8" \
  --allow-dests "api.opencode.ai,api.github.com,models.dev"
```

All options are optional. With no flags, the proxy listens on `0.0.0.0:3128` and forwards everything without auth or filtering.

Configure your client to use it:

```bash
export HTTPS_PROXY=http://myuser:password123@host:3128
opencode
```

### `check` — Detect SSL inspection

```bash
slimproxy check api.opencode.ai api.github.com
```

Connects to each target over TLS and prints the certificate issuer. If the issuer is your company, SSL inspection is active.

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--hostname` | `0.0.0.0` | Address to bind to |
| `--port` | `3128` | Listen port |
| `--basic-auth` | *(none)* | Enable Basic auth (`user:password` format) |
| `--allow-ips` | *(none)* | Comma-separated client CIDRs (e.g. `192.168.1.0/24`) |
| `--allow-dests` | *(none)* | Comma-separated upstream hosts (e.g. `api.opencode.ai`) |
| `--log-level` | `INFO` | Log level |
| `--timeout` | `10` | Connection timeout in seconds |

## Security

All three filters are optional and independent:

- **IP allowlist**: Clients outside the specified CIDR ranges are rejected with `418`
- **Basic auth**: Password checked against `--basic-auth` value on every CONNECT request
- **Dest allowlist**: Upstream hosts not in the list are rejected with `403`

The proxy speaks vanilla HTTP CONNECT — no TLS interception, no decryption. The end-to-end TLS handshake happens between the client and the target server.

## Docker

```bash
# Build
docker build -t slimproxy .

# Run
docker run -it --rm \
  -p 3128:3128 \
  slimproxy run --basic-auth myuser:password123
```

Published via GHCR on tagged releases:

```bash
docker run -it --rm \
  -p 3128:3128 \
  ghcr.io/hugobatista/slimproxy:latest run --basic-auth myuser:password123
```

## CI/CD

| Workflow | Trigger | Description |
|----------|---------|-------------|
| Lint | push/PR to `**.py` | ruff check + format |
| Test | push/PR to `**.py` | pytest + coverage |
| PyPI | release published | Build + publish to PyPI |
| GHCR | release published | Multi-arch Docker image to ghcr.io |
