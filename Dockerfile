# Stage 0: Pin uv version (ARG expansion works in FROM)
ARG UV_VERSION=0.11.18
FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv-dist

# Stage 1: Export locked dependencies and build wheel
FROM python:3.13-slim AS builder

WORKDIR /tmp

COPY --from=uv-dist /uv /uvx /usr/local/bin/

COPY pyproject.toml README.md uv.lock ./
COPY src src/

RUN uv export --no-dev --no-emit-project -o requirements.txt \
 && uv build

# Stage 2: Runtime
FROM python:3.13-slim

LABEL org.opencontainers.image.source=https://github.com/hugobatista/slimproxy
LABEL security.scan="true"
LABEL maintainer="Hugo Batista <code at hugobatista.com>"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_ROOT_USER_ACTION=ignore

WORKDIR /app

COPY --from=builder /tmp/requirements.txt ./
RUN pip install --no-cache --upgrade pip \
 && pip install --no-cache --require-hashes -r ./requirements.txt \
 && addgroup --system app && adduser --system --group app

COPY --from=builder /tmp/dist/*.whl /tmp/
RUN pip install --no-cache /tmp/*.whl && rm /tmp/*.whl

USER app

HEALTHCHECK --interval=300s --timeout=10s --start-period=5s --retries=3 \
    CMD slimproxy --help || exit 1

ENTRYPOINT ["slimproxy"]
