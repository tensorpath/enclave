#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$SCRIPT_DIR/deploy"
CACHE_DIR="$DEPLOY_DIR/enclave-cache"
SKIP_DOCTOR=0

for arg in "$@"; do
  if [ "$arg" = "--skip-doctor" ]; then
    SKIP_DOCTOR=1
  fi
done

echo "=== TensorPath Redeploy Starting ==="

if [ "$SKIP_DOCTOR" -eq 0 ]; then
  "$DEPLOY_DIR/doctor_rootless.sh"
fi

BUILD_ARGS=()
for arg in "$@"; do
  if [ "$arg" != "--skip-doctor" ]; then
    BUILD_ARGS+=("$arg")
  fi
done

"$SCRIPT_DIR/build_release.sh" "${BUILD_ARGS[@]}"

echo "[Deploy] Syncing artifacts to deploy cache..."
mkdir -p "$CACHE_DIR"

if command -v podman-compose >/dev/null 2>&1; then
  COMPOSE_CMD="podman-compose"
else
  COMPOSE_CMD="podman compose"
fi

echo "[Deploy] Restarting services..."
bash -c "$COMPOSE_CMD -f '$DEPLOY_DIR/compose.yaml' down"
bash -c "$COMPOSE_CMD -f '$DEPLOY_DIR/compose.yaml' up -d --build"

echo "=== Redeploy Complete ==="
echo "Enclave is now running on port 7339."
