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
- **One validation contract** ([docs/validation.md](docs/validation.md)) for
  IDs, images, allowlists, writable paths, labels and literal argv. Invalid
  requests are rejected before a lifecycle row or backend invocation, and kiln
  independently enforces the backend-facing subset.
- **SQLite state** in `/var/lib/kilnd/kilnd.db`: every hop of the absolute
  state path, including nested absolute or relative symlink targets, is
  resolved and trust-checked descriptor-relatively with a bounded link depth.
  The final directory is pinned by descriptor and root-owned 0700. Existing
  database, WAL, SHM and journal entries must be root-owned regular 0600 files
  with one link; the main database is opened with SQLite `NOFOLLOW`. Sandboxes
  with their effective spec, backend ID, state, timestamps and failure
  reason; executions with argv, state, legacy exit code, typed termination,
  runtime diagnostics, failure reason, timeout,
  timestamps, and stdout/stderr (first 1 MiB of each kept, observed byte
  counts, total-certainty bits and truncation facts).
- **Startup reconciliation** with scoped `kiln gc ID...` and `kiln ls`:
  ready sandboxes the backend lost become `lost`, interrupted creates become `failed`,
  half-finished deletes are retried, and executions cut off by a crash become
  `interrupted` only for the active backend. It passes only recorded stale
  backend IDs to garbage collection. It never removes a sandbox it didn't
  create, never marks anything lost from failed, truncated, partial, duplicate, or otherwise
  incomplete list evidence, and running it twice changes nothing. A managed
  backend omitted from the list is probed directly and must also lack its
  cgroup before absence is trusted. If the exact recorded backend later
  reappears and passes capability validation, `lost` returns to `ready`.
- **Operational limits:** root-owned socket usable by the `kilnd` group
  (directory 0750, socket 0660), per-execution timeouts that stop the command
  inside the sandbox, bounded output, stdin and argv, a cap on durable sandbox
  reservations, graceful shutdown, and structured logs (text or JSON).
- **Durable node budgets:** one SQLite transaction sums every retained
  sandbox reservation and inserts the `CREATING` row, so memory, PID and disk
  promises cannot be overcommitted by concurrent creates. Defaults reserve at
  most 3 GiB memory, 2,048 PIDs and 16 GiB disk for sandboxes. `LOST` remains
  reserved because it can recover; ambiguous `FAILED` creates remain reserved
  because no current operation can account for hidden resources without an ID.
  Delete refuses to release those ambiguous rows, even with an empty listing.
  `DELETING` releases only after an exact-ID negative probe, complete list
  absence and cgroup absence are durably recorded. Health exposes limits,
  reservations and rejection totals since daemon startup. Lowering limits
  below existing ownership degrades Health and rejects creates while
  Get/List/Delete stay available.
- **Admission bounds:** 64 connections, 8 HTTP/2 streams per connection,
  64 ordinary RPC handlers plus 4 reserved Health handlers, 2 MiB requests
  and 4 MiB responses. Exec admits at most 32 running or queued requests
  globally, one running plus 8 queued per sandbox, and 16 MiB of retained
  stdin. Admission is immediate; a full budget returns `RESOURCE_EXHAUSTED`
  (excess raw connections are closed). Slow callers can hold bounded slots.
  Health exposes current use, maxima and rejection totals since daemon startup.
- **Exclusive daemon ownership:** a persistent advisory lock in the state
  directory prevents a second process from opening the same database, while
  a separate socket-directory lock prevents endpoint takeover. Both are held
  before startup reconciliation and through shutdown cleanup. A live listener
  is never unlinked; on Linux, a stale socket is replaced after a bounded
  probe. Platforms where refusal can also mean backlog pressure fail closed.
- **Supervised creates:** after acceptance, `CreateSandbox` belongs to the
  daemon rather than the RPC future. A disconnected caller stops receiving
  the result, but creation still reaches `ready` or attempts compensation.
  Capacity reservation and the `CREATING` row are one durable transaction.
  Failed cleanup stays counted and retryable; successful compensation releases
  only after the exact backend is proven absent and the result is recorded.
  Shutdown drains this work before exit.
- **Supervised executions:** once an execution is recorded, it belongs to the
  daemon rather than the RPC future. A disconnected caller requests
  cancellation, but kilnd waits for backend cleanup, drains output capture,
  records a terminal outcome, and only then releases the sandbox. A queued
  request canceled before it starts is discarded without an execution row.
- **Supervised backend clients:** every subprocess restores standard signal
  defaults before exec. On Linux it also arms `PR_SET_PDEATHSIG` and rechecks
  the parent PID, so a daemon death at any point in the fork/pre-exec window
  cannot leave an unsupervised backend client running.
- **Serialized deletion:** for rows that may still own a backend, concurrent
  `DeleteSandbox` callers share the sandbox's coordination slot and one backend
  removal. Compensated `failed` history moves directly to `deleted` without a
  backend call. State is reloaded under that lock; `deleted` is immutable
  idempotent success, and conditional writes prevent stale failures from
  restoring `deleting` or rewriting timestamps.
  A call interrupted before or after backend removal leaves `deleting` for a
  safe retry (including an already-gone backend).
- **One Exec deadline:** the requested timeout includes queueing. Expiry
  before row insertion returns `DEADLINE_EXCEEDED`; after insertion the RPC
  returns a terminal `TIMED_OUT` execution after cleanup and publication,
  which may finish after the deadline. Permits remain held through cleanup
  and terminal-write retries.
- **Bounded queries:** List supports opaque pagination tokens (200 items and
  1 MiB per page by default); legacy complete-list calls fail explicitly
  when they cannot fit. `kilndctl ls` prints pages incrementally. GetSandbox
  reads recent execution metadata without loading captured output BLOBs while
  preserving byte totals, whether those totals are exact, and truncation facts.
  Health shares one backend probe with a 2-second timeout, caching successes
  for 5 seconds and failures for 1 second.
- **`kilndctl`**, a small client covering the whole API.

Sandboxes outlive kilnd: restarting or upgrading the daemon leaves them
running, and reconciliation picks them up again.

kilnd requires persistent-exec protocol v1 in both the installed kiln CLI and
each sandbox PID 1, plus CLI support for scoped `gc ID...` (minimum kiln
`40d9aa500320`). It checks capabilities and complete `gc --help` usage before
reconciliation and Exec;
old sandbox instances require explicit recreation. Command bytes use private
streams, so real exits 125/126/127 and signal termination remain distinct from
runtime failures. Schema 4 stores typed outcomes and truthful output-accounting
evidence; v1/v2/v3 databases migrate at open and older binaries refuse the
result. See [setup](docs/setup.md) before upgrading.

These bounds do not provide tenant fairness: authorized callers can monopolize
capacity, including with slow connections. Messages decode before service RPC
admission, under the connection, stream and message caps. SQLite/filesystem
work is synchronous, and history still grows without retention. Defaults and
flags are listed in [the architecture](docs/architecture.md#limits-and-defaults).

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
scripts/integration-test.sh   # real kiln plus dedicated-child admission FD/RSS stress
scripts/daemon-singleton-regressions.sh # duplicate startup cannot disturb live work
scripts/state-path-regressions.sh # hostile state ancestors/files fail before reconciliation
scripts/smoke.sh              # kilndctl → socket → service → kiln, checked through the API
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
