# syntax=docker/dockerfile:1.7

FROM python:3.12-slim AS python-builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CMAKE_BUILD_PARALLEL_LEVEL=1 \
    LD_LIBRARY_PATH=/opt/liboqs/lib:/usr/local/lib

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

COPY prebuilt_liboqs/linux-x86_64 /opt/liboqs

RUN set -eux; \
    echo "/opt/liboqs/lib" > /etc/ld.so.conf.d/liboqs.conf; \
    ldconfig; \
    ln -sf /opt/liboqs/lib/liboqs.so /usr/local/lib/liboqs.so; \
    ldconfig; \
    ls -lah /opt/liboqs/lib/; \
    ldd /opt/liboqs/lib/liboqs.so.0.14.1-dev; \
    ldconfig -p | grep liboqs || true

WORKDIR /src
COPY pyproject.toml README.adoc ./
COPY COPYING COPYING.APLv2 COPYING.MPLv2 ./
COPY fido2 ./fido2
COPY server ./server

RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip setuptools wheel && \
    pip install --prefix=/install --no-cache-dir /opt/liboqs/liboqs_python*.whl pqcrypto gunicorn . ./server && \
    apt-get purge -y build-essential cmake git ninja-build pkg-config libssl-dev && \
    apt-get autoremove -y && \
    rm -rf /opt/liboqs/include /opt/liboqs/lib/pkgconfig /var/lib/apt/lists/*

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LD_LIBRARY_PATH=/opt/liboqs/lib:/usr/local/lib

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends libssl3; \
    rm -rf /var/lib/apt/lists/* /root/.cache

COPY prebuilt_liboqs/linux-x86_64 /opt/liboqs
COPY --from=python-builder /install /usr/local
COPY server/server /app/server

RUN set -eux; \
    echo "/opt/liboqs/lib" > /etc/ld.so.conf.d/liboqs.conf; \
    ln -sf /opt/liboqs/lib/liboqs.so /usr/local/lib/liboqs.so; \
    ldconfig; \
    rm -rf /usr/local/lib/python3.12/ensurepip

WORKDIR /app

ENV PYTHONPATH=/app:${PYTHONPATH}

CMD ["/bin/sh", "-c", "export LD_PRELOAD=/opt/liboqs/lib/liboqs.so; exec gunicorn --bind 0.0.0.0:${PORT:-8000} server.app:app"]