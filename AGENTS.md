# AGENTS.md — slimproxy

## Project

Forward proxy CLI (`proxy.py` + `typer`). `slimproxy run` starts the server; `slimproxy check` tests for SSL inspection.

Single package at `src/slimproxy/`. Entrypoint: `slimproxy.cli:app` (Typer).

## Commands

```bash
uv sync --group dev                    # install all deps
uv run ruff check src/ tests/          # lint
uv run ruff format --check src/ tests/ # format check
uv run ruff format src/ tests/         # format
uv run mypy src --strict --no-incremental  # typecheck
uv run pytest src tests --cov=src/slimproxy --cov-fail-under=100 -v  # test
uv run hatch run check                 # lint + format-check + test + typecheck
uv build --no-dev                      # build wheel
```

## Key constraints

- **100% coverage required** — `--cov-fail-under=100`. `__init__.py` and `__main__.py` are omitted from coverage.
- **`uv.lock` is `.gitignore`d** — the lockfile is not committed. Dependencies pinned only by `pyproject.toml` ranges and `exclude-newer = "30 days"`.
- **mypy strict on `src/` only** — tests excluded. `proxy.py` stubs ignored via override.
- **Ruff**: line-length 80, target py311, rules E/F/I/N/W/UP.
- **Style**: no comments in source code unless complexity warrants. No docstrings on private helpers.

## Architecture

| File | Role |
|------|------|
| `src/slimproxy/cli.py` | Typer CLI — `run` command starts Proxy, `check` command tests TLS |
| `src/slimproxy/plugins.py` | `FilterByDestPlugin` (proxy.py `HttpProxyBasePlugin`) for dest allowlisting |
| `src/slimproxy/check.py` | TLS handshake helper for SSL inspection detection |
| `tests/test_cli.py` | CLI tests via `typer.testing.CliRunner` |
| `tests/test_plugins.py` | Plugin unit tests |
| `tests/test_check.py` | `check_target` unit tests |

- `run` uses `proxy.py`'s built-in `FilterByClientIpPlugin` for IP allowlisting and `--basic-auth` for auth. Only destination filtering is custom.
- Tests mock `proxy.Proxy` and network calls; no integration or Docker tests exist.

## Publishing

- **PyPI**: manual release trigger `pypi.yml` — builds with `uv build --no-dev`, publishes via `pypa/gh-action-pypi-publish`.
- **GHCR**: manual release trigger `ghcr.yml` — multi-arch (amd64 + arm64) Docker image published.
- **Release**: `create_draft_release.yml` — manual workflow_dispatch, creates draft release with auto-generated notes, pushes `release/v*` branch.
