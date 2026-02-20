#!/bin/bash
set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HOST_BIN_OUT="build/enclave"

for cmd in go; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command '$cmd' not found" >&2
    exit 1
  fi
done

echo "=== Enclave Release: Packaging Artifacts ==="
mkdir -p "$SOURCE_DIR/build" "$SOURCE_DIR/dist"

cd "$SOURCE_DIR"

echo "[Host] Building enclave binary..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$HOST_BIN_OUT" ./cmd/enclave
echo "[Host] Binary built at $HOST_BIN_OUT"

echo "[Release] Preparing dist bundle..."
cp "$HOST_BIN_OUT" dist/enclave

echo "=== Enclave Build Complete ==="
echo "Artifacts ready in $SOURCE_DIR/dist/"
