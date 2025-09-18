#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y git libssl-dev make cmake build-essential python3-pip
fi

cd "$SCRIPT_DIR"

python3 -m pip install --upgrade pip
sudo python3 -m pip install --upgrade --break-system-packages ".[pqc]"
python3 -c "import oqs"
