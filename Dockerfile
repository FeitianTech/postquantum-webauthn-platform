# syntax=docker/dockerfile:1.7

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

# Only install minimal runtime deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends libssl3 && \
    rm -rf /var/lib/apt/lists/* /root/.cache

# Copy Python packages from builder
COPY --from=builder /install /usr/local
COPY server/app /app/server
COPY frontend /app/frontend
COPY gunicorn.conf.py /app/gunicorn.conf.py
COPY tools/build_static_assets.py /tmp/build_static_assets.py

# Precompile the server's bytecode at build time; PYTHONDONTWRITEBYTECODE only
# stops writes at runtime, so every cold start would otherwise recompile it.
# Static assets get a content-hash build id and precompressed .gz variants.
RUN rm -rf /usr/local/lib/python3.12/ensurepip \
    && python -m compileall -q -j 0 /app/server \
    && python /tmp/build_static_assets.py /app/frontend/static \
    && rm /tmp/build_static_assets.py

WORKDIR /app
ENV PYTHONPATH=/app:${PYTHONPATH}

CMD ["gunicorn", "-c", "/app/gunicorn.conf.py", "server.app:app"]
