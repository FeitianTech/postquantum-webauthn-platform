# syntax=docker/dockerfile:1.7

# Stage 1: install Python dependencies (including PQC extras) with prebuilt liboqs available.
FROM python:3.11-slim AS python-builder

ARG LIBOQS_PYTHON_VERSION=0.9.2

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CMAKE_BUILD_PARALLEL_LEVEL=1

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        git \
        libssl-dev \
        ninja-build \
    ; \
    rm -rf /var/lib/apt/lists/*

# 🧠 Copy the prebuilt liboqs instead of compiling it
COPY prebuilt_liboqs/linux-x86_64 /opt/liboqs
ENV LD_LIBRARY_PATH=/opt/liboqs/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH} \
    LIBOQS_DIR=/opt/liboqs \
    OQS_DIST_BUILD=1

WORKDIR /src

COPY pyproject.toml README.adoc ./
COPY COPYING COPYING.APLv2 COPYING.MPLv2 ./
COPY fido2 ./fido2
COPY server ./server

RUN pip install --upgrade pip setuptools wheel
RUN pip install --prefix=/install --no-cache-dir \
    "oqs @ git+https://github.com/open-quantum-safe/liboqs-python@${LIBOQS_PYTHON_VERSION}" \
    pqcrypto
RUN pip install --prefix=/install --no-cache-dir .
RUN pip install --prefix=/install --no-cache-dir ./server
RUN pip install --prefix=/install --no-cache-dir gunicorn


# Stage 2: create the final runtime image with only what is needed to run the app.
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        libssl3 \
    ; \
    rm -rf /var/lib/apt/lists/*

# 🧠 Copy prebuilt liboqs for runtime use
COPY prebuilt_liboqs/linux-x86_64 /opt/liboqs
COPY --from=python-builder /install /usr/local

# The Flask app expects to find its static assets within the package tree.
# Copy the server package so templates/certificates remain accessible without
# requiring editable installs in production.
WORKDIR /app
COPY server/server /app/server

ENV LD_LIBRARY_PATH=/opt/liboqs/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH} \
    LIBOQS_DIR=/opt/liboqs \
    OQS_DIST_BUILD=1 \
    PYTHONPATH=/app:${PYTHONPATH}

# Render (and many PaaS providers) expose the listening port via the PORT env var.
# Gunicorn binds to that port by default, falling back to 8000 locally.
CMD ["/bin/sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-8000} server.app:app"]
