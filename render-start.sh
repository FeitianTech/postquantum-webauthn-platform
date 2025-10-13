#!/usr/bin/env bash
set -euo pipefail

LIBOQS_PREFIX=${LIBOQS_PREFIX:-/opt/liboqs}
export LIBOQS_DIR="$LIBOQS_PREFIX"
export LD_LIBRARY_PATH="$LIBOQS_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export OQS_DIST_BUILD=1

if [ ! -d .venv ]; then
  echo "[render-start] Missing .venv directory. Did the build step run?" >&2
  exit 1
fi

source .venv/bin/activate
exec gunicorn --bind 0.0.0.0:${PORT:-8000} server.app:app
