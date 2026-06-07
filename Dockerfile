# Stage 0: Pin uv version
FROM ghcr.io/astral-sh/uv:0.11.18@sha256:78bc42400d77b0678ba95765305c826652ed5431f399257271dda681d0318f03 AS uv-dist

# Stage 1: Export locked dependencies and build wheel
FROM python:3.13-slim@sha256:b04b5d7233d2ad9c379e22ea8927cd1378cd15c60d4ef876c065b25ea8fb3bf3 AS builder

WORKDIR /tmp

COPY --from=uv-dist /uv /uvx /usr/local/bin/

COPY pyproject.toml README.md uv.lock ./
COPY src src/

RUN uv export --no-dev --no-emit-project -o requirements.txt \
 && uv build

# Stage 2: Runtime
FROM python:3.13-slim@sha256:b04b5d7233d2ad9c379e22ea8927cd1378cd15c60d4ef876c065b25ea8fb3bf3

ARG UID=1000
ARG GID=1000
ARG APP_USER=appuser

LABEL org.opencontainers.image.source=https://github.com/hugobatista/slimproxy
LABEL security.scan="true"
LABEL maintainer="Hugo Batista <code at hugobatista.com>"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_ROOT_USER_ACTION=ignore

RUN addgroup --system --gid ${GID} ${APP_USER} \
 && adduser --system --uid ${UID} --gid ${GID} --home /app --shell /sbin/nologin ${APP_USER} \
 && mkdir -p /app && chown -R ${APP_USER}:${APP_USER} /app

WORKDIR /app

COPY --chown=${UID}:${GID} --from=builder /tmp/requirements.txt ./
RUN pip install --no-cache --upgrade pip \
 && pip install --no-cache --require-hashes -r ./requirements.txt

COPY --chown=${UID}:${GID} --from=builder /tmp/dist/*.whl /tmp/
RUN pip install --no-cache /tmp/*.whl && rm /tmp/*.whl

USER ${APP_USER}

HEALTHCHECK --interval=300s --timeout=10s --start-period=5s --retries=3 \
    CMD slimproxy --help || exit 1

ENTRYPOINT ["slimproxy"]
