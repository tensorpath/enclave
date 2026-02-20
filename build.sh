#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[Deprecated] build.sh delegates to build_release.sh"
exec "$SCRIPT_DIR/build_release.sh" "$@"
