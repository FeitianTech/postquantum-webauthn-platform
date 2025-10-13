#!/usr/bin/env bash
set -euo pipefail

LIBOQS_VERSION=${LIBOQS_VERSION:-0.9.2}
LIBOQS_PYTHON_VERSION=${LIBOQS_PYTHON_VERSION:-0.9.2}
LIBOQS_PREFIX=${LIBOQS_PREFIX:-/opt/liboqs}

if command -v docker >/dev/null 2>&1; then
  echo "[render-build] Docker is available. This build script is intended for Render's native runtimes."
fi

echo "[render-build] Installing system build dependencies"
apt-get update
apt-get install -y --no-install-recommends \
  build-essential \
  ca-certificates \
  cmake \
  git \
  libssl-dev \
  ninja-build \
  python3-venv
rm -rf /var/lib/apt/lists/*

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

printf '[render-build] Fetching liboqs %s\n' "$LIBOQS_VERSION"
git clone --depth 1 --branch "$LIBOQS_VERSION" https://github.com/open-quantum-safe/liboqs.git "$tmpdir/liboqs"

cmake -S "$tmpdir/liboqs" -B "$tmpdir/build" -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$LIBOQS_PREFIX" \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_BUILD_ONLY_LIB=ON
cmake --build "$tmpdir/build" --target install

export LD_LIBRARY_PATH="$LIBOQS_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export LIBOQS_DIR="$LIBOQS_PREFIX"
export OQS_DIST_BUILD=1

rm -rf .venv
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install "oqs @ git+https://github.com/open-quantum-safe/liboqs-python@${LIBOQS_PYTHON_VERSION}" pqcrypto
pip install -e .
pip install -e ./server
pip install gunicorn

echo "[render-build] Build finished"
