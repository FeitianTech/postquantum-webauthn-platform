# syntax=docker/dockerfile:1.7

FROM python:3.11-slim AS python-builder

ARG LIBOQS_PYTHON_VERSION=main

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CMAKE_BUILD_PARALLEL_LEVEL=1 \
    LIBOQS_INSTALL_PATH=/opt/liboqs \
    LD_LIBRARY_PATH=/opt/liboqs/lib:/usr/local/lib \
    PKG_CONFIG_PATH=/opt/liboqs/lib/pkgconfig:${PKG_CONFIG_PATH} \
    OQS_DIST_BUILD=1

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        git \
        libssl-dev \
        ninja-build \
        pkg-config; \
    rm -rf /var/lib/apt/lists/*

# Copy prebuilt liboqs FIRST
COPY prebuilt_liboqs/linux-x86_64 /opt/liboqs
RUN echo "/opt/liboqs/lib" > /etc/ld.so.conf.d/liboqs.conf && ldconfig

# Verify the prebuilt library is accessible
RUN ls -la /opt/liboqs/lib/ && \
    ldconfig -p | grep liboqs || echo "Warning: liboqs not in ldconfig cache"

WORKDIR /src
COPY pyproject.toml README.adoc ./
COPY COPYING COPYING.APLv2 COPYING.MPLv2 ./
COPY fido2 ./fido2
COPY server ./server

RUN pip install --upgrade pip setuptools wheel

# Install liboqs-python - it should detect the prebuilt library
RUN pip install --prefix=/install --no-cache-dir \
    "liboqs-python @ git+https://github.com/open-quantum-safe/liboqs-python@main"

# Verify liboqs-python can import successfully
RUN PYTHONPATH=/install/lib/python3.11/site-packages python3 -c "import oqs; print('liboqs-python imported successfully')"

RUN pip install --prefix=/install --no-cache-dir pqcrypto
RUN pip install --prefix=/install --no-cache-dir .
RUN pip install --prefix=/install --no-cache-dir ./server
RUN pip install --prefix=/install --no-cache-dir gunicorn