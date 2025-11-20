# Offline Ubuntu Server Deployment

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

# Copy your prebuilt liboqs bundle
COPY prebuilt_liboqs/linux-x86_64 /opt/liboqs

RUN set -eux; \
    echo "/opt/liboqs/lib" > /etc/ld.so.conf.d/liboqs.conf; \
    ldconfig; \
    ln -sf /opt/liboqs/lib/liboqs.so /usr/local/lib/liboqs.so; \
    ldconfig; \
    ls -lah /opt/liboqs/lib/

WORKDIR /src
COPY pyproject.toml README.adoc ./
COPY COPYING COPYING.APLv2 COPYING.MPLv2 ./
COPY fido2 ./fido2
COPY server ./server

# Install liboqs-python wheel + dependencies (no build)
# NOTE: Google Cloud dependencies removed for offline operation
# The server will use local file storage instead
RUN pip install --default-timeout=1000 --retries=10 --upgrade pip setuptools wheel && \
    pip install --default-timeout=1000 --retries=10 --prefix=/install --no-cache-dir \
        cbor2 \
        /opt/liboqs/liboqs_python*.whl \
        pqcrypto \
        gunicorn \
        . \
        ./server && \
    apt-get purge -y build-essential cmake git ninja-build pkg-config libssl-dev && \
    apt-get autoremove -y && \
    rm -rf /opt/liboqs/include /opt/liboqs/lib/pkgconfig /var/lib/apt/lists/*

FROM python:3.12-slim AS runtime

# Labels for image identification
LABEL maintainer="Post-Quantum WebAuthn Platform" \
      description="Offline-capable FIDO2/WebAuthn server with post-quantum cryptography" \
      version="1.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LD_LIBRARY_PATH=/opt/liboqs/lib:/usr/local/lib \
    FIDO_SERVER_STORAGE_PATH=/app/storage \
    PORT=8000 \
    ENABLE_GITHUB_LOGGING=false

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        libssl3 \
        curl; \
    rm -rf /var/lib/apt/lists/* /root/.cache; \
    groupadd -r webauthn && useradd -r -g webauthn webauthn

COPY prebuilt_liboqs/linux-x86_64 /opt/liboqs
COPY --from=python-builder /install /usr/local
COPY server/server /app/server

RUN set -eux; \
    echo "/opt/liboqs/lib" > /etc/ld.so.conf.d/liboqs.conf; \
    ln -sf /opt/liboqs/lib/liboqs.so /usr/local/lib/liboqs.so; \
    ldconfig; \
    rm -rf /usr/local/lib/python3.12/ensurepip; \
    mkdir -p /app/storage /app/server/session-credentials /app/server/static/session-metadata /app/server/instance; \
    chown -R webauthn:webauthn /app

WORKDIR /app
ENV PYTHONPATH=/app:${PYTHONPATH}

# Switch to non-root user
USER webauthn

# Expose the application port
EXPOSE 8000

# Health check for container orchestration
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/ || exit 1

# Start the server with gunicorn
CMD ["/bin/sh", "-c", "export LD_PRELOAD=/opt/liboqs/lib/liboqs.so; exec gunicorn --bind 0.0.0.0:${PORT:-8000} --workers ${GUNICORN_WORKERS:-2} --timeout ${GUNICORN_TIMEOUT:-120} --access-logfile - --error-logfile - server.app:app"]
