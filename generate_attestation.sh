#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR" && pwd)"

RELEASE_DIR="$REPO_ROOT/release_dist"
IMAGE_NAME="${IMAGE_NAME:-ghcr.io/tensorpath/enclave}"
IMAGE_DIGEST="${IMAGE_DIGEST:-}"

for arg in "$@"; do
  case "$arg" in
    --release-dir=*)
      RELEASE_DIR="${arg#*=}"
      ;;
    --image-name=*)
      IMAGE_NAME="${arg#*=}"
      ;;
    --image-digest=*)
      IMAGE_DIGEST="${arg#*=}"
      ;;
    *)
      echo "ERROR: unknown argument '$arg'" >&2
      echo "Usage: $0 [--release-dir=<path>] [--image-name=<name>] [--image-digest=<sha256:...>]" >&2
      exit 1
      ;;
  esac
done

RELEASE_DIR="$(cd "$RELEASE_DIR" && pwd)"
if [ ! -d "$RELEASE_DIR" ]; then
  echo "ERROR: release dir not found: $RELEASE_DIR" >&2
  exit 1
fi
OUTPUT_PREDICATE="$RELEASE_DIR/attestation-predicate.json"
OUTPUT_STATEMENT="$RELEASE_DIR/attestation-statement.json"

required=(
  "enclave_linux_amd64"
  "checksums.txt"
  "build_manifest.txt"
)
for f in "${required[@]}"; do
  if [ ! -f "$RELEASE_DIR/$f" ]; then
    echo "ERROR: missing required release artifact: $RELEASE_DIR/$f" >&2
    exit 1
  fi
done

sha_file() {
  sha256sum "$1" | awk '{print $1}'
}

artifact_sha() {
  local fname="$1"
  echo "sha256:$(sha_file "$RELEASE_DIR/$fname")"
}

runtime_contract_path="docs/runtime_contract.md"
policy_path="pkg/host/policy/agent_boundaries.rego"
runtime_contract_sha="sha256:$(sha_file "$REPO_ROOT/$runtime_contract_path")"
policy_sha="sha256:$(sha_file "$REPO_ROOT/$policy_path")"

if [ -z "$IMAGE_DIGEST" ]; then
  IMAGE_DIGEST="$(artifact_sha checksums.txt)"
fi

workflow_ref="${GITHUB_WORKFLOW_REF:-.github/workflows/release.yml}"
run_id="${GITHUB_RUN_ID:-local}"
source_repo="${GITHUB_REPOSITORY:-local/enclave}"
source_ref="${GITHUB_REF:-local}"
source_sha="${GITHUB_SHA:-local}"
built_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
origin_conversation_id="${ORIGIN_CONVERSATION_ID:-}"

cat > "$OUTPUT_PREDICATE" <<EOF
{
  "build": {
    "workflow": "$workflow_ref",
    "run_id": "$run_id",
    "source_repo": "github.com/$source_repo",
    "source_ref": "$source_ref",
    "source_sha": "$source_sha",
    "built_at": "$built_at"
  },
  "artifacts": {
    "enclave_linux_amd64": "$(artifact_sha enclave_linux_amd64)",
    "checksums.txt": "$(artifact_sha checksums.txt)",
    "build_manifest.txt": "$(artifact_sha build_manifest.txt)"
  },
  "runtime_contract": {
    "path": "$runtime_contract_path",
    "sha256": "$runtime_contract_sha"
  },
  "policy": {
    "constitution_rego_sha256": "$policy_sha",
    "verify_rego_version": "v1"
  },
  "lineage": {
    "origin": {
      "source": "github-actions",
      "execution": "release"
    },
    "execution_id": "$run_id",
    "origin_kind": "release",
    "origin_conversation_id": "$origin_conversation_id"
  }
}
EOF

cat > "$OUTPUT_STATEMENT" <<EOF
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "$IMAGE_NAME",
      "digest": {
        "sha256": "${IMAGE_DIGEST#sha256:}"
      }
    }
  ],
  "predicateType": "https://tensorpath.dev/attestations/enclave-runtime/v1",
  "predicate": $(cat "$OUTPUT_PREDICATE")
}
EOF

echo "Generated: $OUTPUT_PREDICATE"
echo "Generated: $OUTPUT_STATEMENT"
