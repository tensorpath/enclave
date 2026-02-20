# Enclave Runtime Contract

This document defines the stable runtime interface shared by:
- local developer deploys (`deploy/compose.yaml`)
- Incus appliance deploys (reactor appliance image recipe in the Hub distribution surface)
- SDK clients (`docs/sdk.md`)

## 1. Network Interface

- Host API bind: `0.0.0.0:7339`
- ConnectRPC base path: `/agent.v1.AgentService/*`
- Health endpoint: `GET /ping` -> `pong`
- Audit websocket: `GET /ws/audit`

## 2. Runtime Assets

- Cache root: `~/.enclave/cache`
- Required artifacts:
  - `~/.enclave/cache/vmlinux`
  - `~/.enclave/cache/rootfs.cpio`
- Firecracker binary:
  - preferred in cache via hydrator
  - container images may also provide `/usr/local/bin/firecracker`

### Host Provider Contract

- Enclave host runtime executes on Linux only.
- `--provider` values: `auto | native | lima | wsl2`
  - `native`: direct Linux host with `/dev/kvm`
  - `lima`: Linux guest launched by Lima on macOS
  - `wsl2`: Linux guest launched by WSL2 on Windows
- macOS/Windows are launcher hosts; enforcement runtime still lives in Linux guest kernel context.

## 3. Database Defaults

- Database: Postgres
- Default DSN: `postgres://tensorpath:<configured-password>@postgres:5432/reactor`
- Appliance local DSN: `postgres://tensorpath:<configured-password>@localhost:5432/reactor`
- `DATABASE_URL` overrides all defaults.

## 4. Security Baseline

- Rootless Podman is the default local path.
- Container caps: `cap_drop: [ALL]`
- Security opts:
  - `no-new-privileges:true`
  - `seccomp:unconfined` (current compatibility baseline)
- Required devices:
  - `/dev/kvm`
  - `/dev/vhost-vsock`

## 5. Guest Runtime Expectations

- Guest init process is `/init` provided by the factory build.
- Tetragon policy directory: `/etc/tetragon/tetragon.tp.d/`
- Loopback setup requires `iproute2` in guest rootfs.

## 6. Compatibility Rule

Any change to this contract must update all three surfaces in the same PR:
1. local deploy (`deploy/*`)
2. appliance image (reactor image recipe in the Hub distribution surface)
3. SDK docs/defaults (`docs/sdk.md`)
