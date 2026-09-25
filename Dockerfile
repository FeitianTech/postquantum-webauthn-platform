# syntax=docker/dockerfile:1.7

# Stage 0: the new UI (web/, docs/UI_MIGRATION.md), built into static files.
# Production never runs Node: only web/out reaches the runtime image, where
# Flask serves it at /beta. The CSP scan runs on the very export that ships.
FROM node:22-slim AS web

ENV NEXT_TELEMETRY_DISABLED=1

WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
# The logic modules web/ imports in place until the cutover.
COPY frontend/static/scripts /src/frontend/static/scripts
RUN npm run build && npm run check:csp

# Stage 1: Builder
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install build dependencies
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        build-essential \
        git \
        libssl-dev \
        libssl3 \
        pkg-config; \
    rm -rf /var/lib/apt/lists/*

# uv reads the lockfile; the version is pinned so builds do not drift with uv releases.
COPY --from=ghcr.io/astral-sh/uv:0.12.15 /uv /usr/local/bin/uv

# Copy app source
WORKDIR /src
COPY pyproject.toml uv.lock README.md ./
COPY server/pyproject.toml ./server/pyproject.toml
COPY COPYING COPYING.APLv2 COPYING.MPLv2 ./
COPY fido2 ./fido2

# Install Python dependencies into /install from uv.lock, the same lock CI and
# local venvs install from. --locked fails the build if the lock is stale, and
# --require-hashes rejects anything not pinned by it. The vendored fido2 library
# is installed from source without dependencies (its own deps are in the lock).
RUN pip install --upgrade pip setuptools wheel && \
    uv export --locked --no-dev --no-emit-local --package fido2-example-server \
        -o /tmp/requirements.txt && \
    pip install --prefix=/install --no-cache-dir --no-deps --require-hashes \
        -r /tmp/requirements.txt && \
    pip install --prefix=/install --no-cache-dir --no-deps . && \
    # Remove build tools
    apt-get purge -y build-essential git pkg-config libssl-dev && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Stage 2: Runtime
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Only install minimal runtime deps. The upgrade pulls the base image's Debian
# packages up to current security releases: without it the image ships whatever
# perl-base, gzip, libpcre2 and libsqlite3 were current when the python:3.12-slim
# tag was built, which the Trivy gate in ci-security.yml rejects.
RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends libssl3 && \
    rm -rf /var/lib/apt/lists/* /root/.cache

# Copy Python packages from builder
COPY --from=builder /install /usr/local
# The same path as in a checkout, so server.app is the same package in both and
# every module has one import path. Only server/app, not server/: server/runtime
# holds local credential artifacts and .dockerignore does not exclude it.
COPY server/app /app/server/app
COPY frontend /app/frontend
COPY --from=web /src/web/out /app/web/out
COPY gunicorn.conf.py /app/gunicorn.conf.py
COPY tools/build_static_assets.py /tmp/build_static_assets.py
# The MDS snapshot is not in the image (see .dockerignore); the server fetches it
# from Cloud Storage on a cold start and falls back to this updater, which
# verifies the BLOB against the pinned trust root before writing it.
COPY tools/__init__.py tools/update_mds_snapshot.py /app/tools/

# Precompile the server's bytecode at build time; PYTHONDONTWRITEBYTECODE only
# stops writes at runtime, so every cold start would otherwise recompile it.
# Static assets get a content-hash build id and precompressed .gz variants; the
# web export, whose file names carry their own hashes, gets the .gz variants.
RUN rm -rf /usr/local/lib/python3.12/ensurepip \
    && python -m compileall -q -j 0 /app/server \
    && python /tmp/build_static_assets.py /app/frontend/static \
    && python /tmp/build_static_assets.py --precompress-only /app/web/out \
    && rm /tmp/build_static_assets.py

WORKDIR /app
ENV PYTHONPATH=/app:${PYTHONPATH}

CMD ["gunicorn", "-c", "/app/gunicorn.conf.py", "server.app.app:app"]
