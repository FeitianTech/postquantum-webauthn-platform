# syntax=docker/dockerfile:1.7

FROM python:3.11-slim AS python-builder

ARG LIBOQS_PYTHON_VERSION=main

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CMAKE_BUILD_PARALLEL_LEVEL=1 \
    LIBOQS_DIR=/opt/liboqs \
    OQS_INSTALL_PATH=/opt/liboqs \
    LD_LIBRARY_PATH=/opt/liboqs/lib:/usr/local/lib \
    OQS_DIST_BUILD=1

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        git \
        libssl-dev \
        ninja-build; \
    rm -rf /var/lib/apt/lists/*

# Copy your prebuilt liboqs before installing liboqs-python
COPY prebuilt_liboqs/linux-x86_64 /opt/liboqs
RUN echo "/opt/liboqs/lib" > /etc/ld.so.conf.d/liboqs.conf && ldconfig

WORKDIR /src
COPY pyproject.toml README.adoc ./
COPY COPYING COPYING.APLv2 COPYING.MPLv2 ./
COPY fido2 ./fido2
COPY server ./server

RUN pip install --upgrade pip setuptools wheel
# During this step, liboqs-python will now detect /opt/liboqs and skip building
RUN pip install --prefix=/install --no-cache-dir \
    "liboqs-python @ git+https://github.com/open-quantum-safe/liboqs-python@main" \
    pqcrypto
RUN pip install --prefix=/install --no-cache-dir .
RUN pip install --prefix=/install --no-cache-dir ./server
RUN pip install --prefix=/install --no-cache-dir gunicorn

FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LIBOQS_DIR=/opt/liboqs \
    OQS_INSTALL_PATH=/opt/liboqs \
    OQS_DIST_BUILD=1 \
    LD_LIBRARY_PATH=/opt/liboqs/lib:/usr/local/lib

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        libssl3 git cmake build-essential libssl-dev; \
    echo "/opt/liboqs/lib" > /etc/ld.so.conf.d/liboqs.conf; \
    ldconfig; \
    rm -rf /var/lib/apt/lists/*

COPY prebuilt_liboqs/linux-x86_64 /opt/liboqs
COPY --from=python-builder /install /usr/local
COPY server/server /app/server

WORKDIR /app

RUN ls -l /opt/liboqs/lib && \
    python3 -c "import ctypes; ctypes.CDLL('/opt/liboqs/lib/liboqs.so'); print('liboqs prebuilt detected')" || true

ENV PYTHONPATH=/app:${PYTHONPATH}

CMD ["/bin/sh", "-c", "echo 'LD_LIBRARY_PATH='$LD_LIBRARY_PATH && gunicorn --bind 0.0.0.0:${PORT:-8000} server.app:app"]