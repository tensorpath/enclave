#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -f "$SCRIPT_DIR/dist/enclave" ]; then
  echo "[Run] Missing dist enclave artifact. Building first..."
  "$SCRIPT_DIR/build_release.sh"
fi

echo "[Run] Starting Enclave host on :7339"
exec "$SCRIPT_DIR/dist/enclave"
