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
uv run hatch run validate              # lint + format-check + test + typecheck (always run this before committing)
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
| `src/slimproxy/firewall.py` | Windows Firewall rule helpers (netsh + UAC elevation) |
| `tests/test_cli.py` | CLI tests via `typer.testing.CliRunner` |
| `tests/test_plugins.py` | Plugin unit tests |
| `tests/test_check.py` | `check_target` unit tests |
| `tests/test_firewall.py` | Firewall helper unit tests |

- `run` uses `proxy.py`'s built-in `FilterByClientIpPlugin` for IP allowlisting and `--basic-auth` for auth. Only destination filtering is custom.
- `run --wizard` launches an interactive guided setup prompting for all options. On Windows, firewall is asked first; if elevation is needed, UAC triggers immediately and the wizard resumes in the elevated session. `--_wizard-firewall-handled` (hidden) signals the elevated child to skip the firewall prompt.
- `run` warns on stderr when `--basic-auth` is omitted on a non-localhost interface. In a TTY, user is interactively prompted to configure credentials (with password confirmation).
- `run --firewall-rule` (Windows) auto-adds a firewall rule; UAC elevation via `ctypes.windll.shell32`.
- Tests mock `proxy.Proxy`, `typer.prompt`/`typer.confirm`, and `sys.stdin.isatty` for the auth and wizard prompt behavior.

## Publishing

- **PyPI**: manual release trigger `pypi.yml` — builds with `uv build --no-dev`, publishes via `pypa/gh-action-pypi-publish`.
- **GHCR**: manual release trigger `ghcr.yml` — multi-arch (amd64 + arm64) Docker image published.
- **Release**: `create_draft_release.yml` — manual workflow_dispatch, creates draft release with auto-generated notes, pushes `release/v*` branch.
