# syntax=docker/dockerfile:1.7

# Stage 1: Builder
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CMAKE_BUILD_PARALLEL_LEVEL=1 \
    LD_LIBRARY_PATH=/opt/liboqs/lib:/usr/local/lib

# Install build dependencies
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        git \
        libssl-dev \
        libssl3 \
        ninja-build \
        pkg-config; \
    rm -rf /var/lib/apt/lists/*

# Copy prebuilt liboqs bundle
COPY prebuilt_liboqs/linux-x86_64 /opt/liboqs

RUN echo "/opt/liboqs/lib" > /etc/ld.so.conf.d/liboqs.conf && ldconfig \
    && ln -sf /opt/liboqs/lib/liboqs.so /usr/local/lib/liboqs.so

# Copy app source
WORKDIR /src
COPY pyproject.toml README.adoc ./
COPY COPYING COPYING.APLv2 COPYING.MPLv2 ./
COPY fido2 ./fido2
COPY frontend ./frontend
COPY server ./server

# Install Python dependencies into /install
RUN pip install --upgrade pip setuptools wheel && \
    pip install --prefix=/install --no-cache-dir \
        /opt/liboqs/liboqs_python*.whl \
        pqcrypto \
        gunicorn \
        google-api-core \
        google-auth \
        google-cloud-core \
        google-cloud-storage \
        . \
        ./server && \
    # Remove build tools
    apt-get purge -y build-essential cmake git ninja-build pkg-config libssl-dev && \
    apt-get autoremove -y && \
    rm -rf /opt/liboqs/include /opt/liboqs/lib/pkgconfig /var/lib/apt/lists/*

# Stage 2: Runtime
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LD_LIBRARY_PATH=/opt/liboqs/lib:/usr/local/lib

# Only install minimal runtime deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends libssl3 && \
    rm -rf /var/lib/apt/lists/* /root/.cache

# Copy liboqs and Python packages from builder
COPY prebuilt_liboqs/linux-x86_64 /opt/liboqs
COPY --from=builder /install /usr/local
COPY server/app /app/server
COPY frontend /app/frontend

RUN echo "/opt/liboqs/lib" > /etc/ld.so.conf.d/liboqs.conf && ldconfig \
    && ln -sf /opt/liboqs/lib/liboqs.so /usr/local/lib/liboqs.so \
    && rm -rf /usr/local/lib/python3.12/ensurepip

WORKDIR /app
ENV PYTHONPATH=/app:${PYTHONPATH}

# Gunicorn with 1 worker + 2 threads for fast start
CMD ["sh", "-c", "export LD_PRELOAD=/opt/liboqs/lib/liboqs.so; exec gunicorn --workers=1 --threads=2 --bind 0.0.0.0:${PORT:-8000} server.app:app"]