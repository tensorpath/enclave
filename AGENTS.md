# Enclave Agent Map

Use this file as a map for Enclave work. Keep detailed rationale in docs, not here.

## Load First

- `docs/runtime_contract.md`

## Scope

Enclave is the trusted Execution Plane:

- Firecracker host orchestration
- guest-init runtime and BPF capture
- policy extraction/evaluation/compilation/enforcement
- audit persistence and WebSocket broadcast
- runtime readiness/degraded-state reporting (`/runtime/status`)

All the client input is untrusted hints and must be re-validated.

## Primary Paths

### Host

- `cmd/enclave/main.go`
- `pkg/host/proxy/proxy.go`
- `pkg/host/policy/`
- `pkg/host/audit/log_writer.go`
- `pkg/host/vmm/`

### Guest

- `cmd/guest-init/main.go`
- `cmd/guest-init/bpf/trace.c`

### API and Schema

- `api/v1/agent.proto`
- `schema.sql`

### Deploy

- `deploy/compose.yaml`
- `deploy/.env.example`
- `redeploy.sh`
- `deploy/doctor_rootless.sh`

## Policy Engine (Implemented)

- LLM/heuristic intent extractor in host policy package.
- OPA decision engine (`agent_boundaries.rego`) with safe result parsing.
- Compiler emits Tetragon policy files and applies via guest RPC.
- Strict mode supports fail-closed request handling.
- Policy lifecycle events (`POLICY:*`) are emitted into audit stream.
- Probe override path exists for deterministic enforcement validation.

## Development Commands

- `go test ./...`
- `./build_release.sh`
- `./redeploy.sh`
- `./deploy/doctor_rootless.sh`

## Working Rules

- Never trust client-provided role/intent without validation.
- Preserve lineage fields in persisted and streamed events.
- Treat policy apply success as explicit guest acknowledgement, not write success.
- Keep denial behavior deterministic for probe scenarios.
- Do not log secrets from `context_json` or extractor config.
- Enforce in-binary preflight for `/dev/kvm` and `/dev/vhost-vsock`.
- Default local audit persistence is SQLite at `~/.enclave/audit.sqlite3` unless `DATABASE_URL`/`POSTGRES_HOST` is set.
- Keep runtime operable in degraded mode and surface readiness via `/runtime/status`.

## Related Docs

- Runtime contract: `docs/runtime_contract.md`
