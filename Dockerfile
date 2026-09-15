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
COPY pyproject.toml README.md ./
COPY COPYING COPYING.APLv2 COPYING.MPLv2 ./
COPY fido2 ./fido2
COPY server ./server

# Install Python dependencies into /install. ./server is installed for its
# declared dependencies (Flask); the server code itself runs from /app/server.
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
COPY gunicorn.conf.py /app/gunicorn.conf.py
COPY tools/build_static_assets.py /tmp/build_static_assets.py

# Precompile the server's bytecode at build time; PYTHONDONTWRITEBYTECODE only
# stops writes at runtime, so every cold start would otherwise recompile it.
# Static assets get a content-hash build id and precompressed .gz variants.
RUN echo "/opt/liboqs/lib" > /etc/ld.so.conf.d/liboqs.conf && ldconfig \
    && ln -sf /opt/liboqs/lib/liboqs.so /usr/local/lib/liboqs.so \
    && rm -rf /usr/local/lib/python3.12/ensurepip \
    && python -m compileall -q -j 0 /app/server \
    && python /tmp/build_static_assets.py /app/frontend/static \
    && rm /tmp/build_static_assets.py

WORKDIR /app
ENV PYTHONPATH=/app:${PYTHONPATH}

CMD ["sh", "-c", "export LD_PRELOAD=/opt/liboqs/lib/liboqs.so; exec gunicorn -c /app/gunicorn.conf.py server.app:app"]
