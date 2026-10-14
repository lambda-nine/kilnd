# kilnd

A per-node control daemon for [kiln](https://github.com/lambda-nine/kiln)
sandboxes. kilnd owns sandbox state, records every execution in SQLite, and
serves a versioned gRPC API on a Unix socket. It is the runtime control plane
the future agent harness will sit on; there is no LLM code here.

```
kilndctl ──gRPC over /run/kilnd/kilnd.sock──▶ kilnd ──argv──▶ kiln create / exec / ls / rm / gc
                                               │
                                               └──▶ /var/lib/kilnd/kilnd.db (SQLite)
```

## Security status

kilnd inherits kiln's boundary: kiln is **experimental, shared-kernel**
isolation, reviewed adversarially by AI models but not audited. Do not use
kilnd or kiln as a security boundary for hostile multi-tenant workloads.
kilnd runs as root, and anyone who can reach its socket can run commands in
sandboxes on this host. See [docs/threat-model.md](docs/threat-model.md).

## What it does

- **gRPC API `kilnd.v1`** ([proto/kilnd/v1/kilnd.proto](proto/kilnd/v1/kilnd.proto)):
  `Health`, `CreateSandbox`, `GetSandbox`, `ListSandboxes`, `DeleteSandbox`,
  `Exec` and `GetExecution`. Nothing in it is kiln-specific, so a microVM
  backend can implement the same API.
- **Runtime adapter trait** ([crates/kilnd/src/runtime/mod.rs](crates/kilnd/src/runtime/mod.rs)).
  The kiln implementation runs the installed `kiln` CLI with argument vectors
  (never a shell), a cleared environment, timeouts and bounded output. kiln's
  code is not copied or linked.
- **SQLite state** in `/var/lib/kilnd/kilnd.db` (directory 0700): sandboxes
  with their effective spec, backend ID, state, timestamps and failure
  reason; executions with argv, state, exit code, failure reason, timeout,
  timestamps, and stdout/stderr (first 1 MiB of each kept, total byte counts
  and a truncation flag).
- **Startup reconciliation** with `kiln gc` and `kiln ls`: ready sandboxes
  the backend lost become `lost`, interrupted creates become `failed`,
  half-finished deletes are retried, executions cut off by a crash become
  `interrupted`. It never removes a sandbox it didn't create, never marks
  anything lost if `kiln ls` failed, and running it twice changes nothing.
- **Operational limits:** root-owned socket usable by the `kilnd` group
  (directory 0750, socket 0660), per-execution timeouts that stop the command
  inside the sandbox, bounded output, stdin and argv, a cap on active
  sandboxes, graceful shutdown, and structured logs (text or JSON).
- **`kilndctl`**, a small client covering the whole API.

Sandboxes outlive kilnd: restarting or upgrading the daemon leaves them
running, and reconciliation picks them up again.

## Quick start (in kiln's Lima VM)

Full instructions: [docs/setup.md](docs/setup.md).

```sh
# on the Mac
git clone https://github.com/lambda-nine/kiln ~/Projects/lambda-nine/kiln
git clone https://github.com/lambda-nine/kilnd ~/Projects/lambda-nine/kilnd
cd ~/Projects/lambda-nine/kiln && limactl create --name=kiln lima.yaml && limactl start kiln

# in the VM, once: kiln itself (see kiln's README), then kilnd
limactl shell --workdir ~/Projects/lambda-nine/kilnd kiln
sudo apt-get install -y protobuf-compiler sqlite3
scripts/install.sh                      # kilnd + kilndctl, kilnd group, systemd service

sudo kilndctl health
id=$(sudo kilndctl create --memory 256M --pids 64 --disk 256M --label owner=me)
sudo kilndctl exec "$id" -- sh -c 'echo hello >/workspace/note; uname -a'
sudo kilndctl exec --timeout 5s "$id" -- sleep 60; echo "exit $?"   # 124
sudo kilndctl get "$id"
sudo kilndctl ls
sudo kilndctl rm "$id"
sudo kilndctl run -- echo one-shot      # create, exec, delete
```

Add yourself to the `kilnd` group (`sudo usermod -aG kilnd $USER`, then log
in again) to use `kilndctl` without sudo.

## Checks

```sh
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
git diff --check
```

CI runs these with Rust 1.88 on Ubuntu 24.04. The privileged checks run by
hand in the VM after `scripts/install.sh`:

```sh
scripts/integration-test.sh   # the manager against real kiln, temporary database
scripts/smoke.sh              # kilndctl → socket → service → kiln, checked in SQLite
```

## Layout

| Path | What |
|------|------|
| `proto/kilnd/v1/` | The versioned API |
| `crates/kilnd-api` | Generated Rust types and gRPC stubs |
| `crates/kilnd` | The daemon: manager, store, runtime adapters, server |
| `crates/kilndctl` | The client |
| `deploy/kilnd.service` | systemd unit |
| `scripts/` | Install, integration test, smoke test |
| `docs/` | [Architecture](docs/architecture.md), [threat model](docs/threat-model.md), [setup](docs/setup.md), [roadmap](docs/roadmap.md) |

## License

Copyright 2026 Stephen Estrada. Licensed under the
[Apache License, Version 2.0](LICENSE).
