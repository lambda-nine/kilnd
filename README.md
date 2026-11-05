# kilnd

A per-node control daemon for [kiln](https://github.com/lambda-nine/kiln)
sandboxes. kilnd owns sandbox state, records every execution in SQLite, and
serves a versioned gRPC API on a Unix socket. It is the runtime control plane
the future agent harness will sit on; there is no LLM code here.

**Status: experimental.** kilnd's isolation is kiln's: experimental,
shared-kernel, reviewed adversarially by AI models but not audited, and **not a
boundary for hostile multi-tenant workloads.** The Firecracker microVM backend
(Phase 1b) is **disabled for production**: it is compiled only with the
non-default `firecracker-test-deployment` cargo feature, and release builds
refuse it. Tested on Ubuntu 24.04 (Linux 6.8+, cgroups v2) in kiln's Lima VM.
Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
Licensed under [Apache-2.0](LICENSE).

| Lambda IX repository | What it is |
|----------------------|------------|
| [kiln](https://github.com/lambda-nine/kiln) | Shared-kernel Linux sandbox runtime; kilnd drives its installed CLI through a root helper |
| **kilnd** (this repository) | Per-node control daemon, `kilndctl` client, and the guest broker for the Firecracker backend |
| [kiln-guest](https://github.com/lambda-nine/kiln-guest) | Builds the Firecracker guest image (kiln plus this repository's `kilnd-guest-broker`) that the test backend boots |
| [kiln-harness](https://github.com/lambda-nine/kiln-harness) | Provider-neutral agent loop that uses kilnd's API |

**Quickstart:** see [Quick start](#quick-start-in-kilns-lima-vm) below; it
installs kiln at a pinned commit, then kilnd, inside kiln's Lima VM on a Mac.
On an Ubuntu 24.04 host with Linux 6.8+, follow kiln's README to install kiln,
then run the "in the VM" half directly. Builds use `cargo` as shown here; a
`scripts/build.sh` wrapper with a closed compiler environment arrives with
Phase 1b B7.

```
kilndctl ──gRPC over /run/kilnd/kilnd.sock──▶ kilnd ──typed Unix IPC──▶ root kilnd-helper ──argv──▶ kiln
                                               │
                                               └──▶ /var/lib/kilnd/kilnd.db (SQLite)
```

## Security status

kilnd inherits kiln's boundary: kiln is **experimental, shared-kernel**
isolation, reviewed adversarially by AI models but not audited. Do not use
kilnd or kiln as a security boundary for hostile multi-tenant workloads.
kilnd runs as the unprivileged `kilnd` system account with no capabilities.
The root helper accepts only validated kiln operations from that service UID.
API callers can control only their own sandboxes; root can control all of them. See [docs/threat-model.md](docs/threat-model.md).

## What it does

- **gRPC API `kilnd.v1`** ([proto/kilnd/v1/kilnd.proto](proto/kilnd/v1/kilnd.proto)):
  `Health`, `CreateSandbox`, `GetSandbox`, `ListSandboxes`, `DeleteSandbox`,
  `Exec` and `GetExecution`. Nothing in it is kiln-specific, so a microVM
  backend can implement the same API.
- **Runtime adapter trait** ([crates/kilnd/src/runtime/mod.rs](crates/kilnd/src/runtime/mod.rs)).
  The kiln implementation calls a private root helper, which runs the installed `kiln` CLI with argument vectors
  (never a shell), a cleared environment, timeouts and bounded output. kiln's
  code is not copied or linked.
- **One validation contract** ([docs/validation.md](docs/validation.md)) for
  IDs, images, allowlists, writable paths, labels and literal argv. Invalid
  requests are rejected before a lifecycle row or backend invocation, and kiln
  independently enforces the backend-facing subset.
- **SQLite state** in `/var/lib/kilnd/kilnd.db`: every hop of the absolute
  state path, including nested absolute or relative symlink targets, is
  resolved and trust-checked descriptor-relatively with a bounded link depth.
  The final directory is pinned by descriptor and owned by `kilnd` with mode 0700. Existing
  database, WAL, SHM and journal entries must be `kilnd`-owned regular 0600 files
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
- **Operational limits:** `kilnd`-owned API socket usable by the `kilnd` group
  (directory 0750, socket 0660), per-execution timeouts that stop the command
  inside the sandbox, bounded output, stdin and argv, a cap on durable sandbox
  reservations, graceful shutdown, and structured logs (text or JSON).
- **Per-caller ownership:** each sandbox records the uid the kernel reports for
  the connection that created it. Group members can see and control only their
  own sandboxes and executions; anything else looks missing. Root sees everything,
  including sandboxes from before schema 7, which belong to root. The kilnd
  process and its account are trusted. There are no per-user quotas yet.
- **Durable node budgets:** one SQLite transaction sums every retained
  sandbox reservation and inserts the `CREATING` row, so memory, PID and disk
  promises cannot be overcommitted by concurrent creates. Defaults reserve at
  most 3 GiB memory, 2,048 PIDs and 16 GiB disk for sandboxes. `LOST` remains
  reserved because it can recover; ambiguous `FAILED` creates remain reserved
  because no current operation can account for hidden resources without an ID.
  Delete refuses to release those ambiguous rows, even with an empty listing.
  A create the backend proves failed before allocating anything, such as a
  missing image, releases as it durably becomes `FAILED`, and Delete retires
  that row without touching the backend.
  `DELETING` releases only after an exact-ID negative probe, complete list
  absence and cgroup absence are durably recorded. Unconfirmed execution cleanup
  turns a sandbox `QUARANTINED`: it refuses Exec and stays reserved until Delete.
  Schema 8 stores each reservation with its release provenance, and an execution
  reports whether its sandbox can take another call. Health exposes limits,
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
- **Ingress shares:** 4 of the 64 connection slots are held back for Health,
  GetSandbox and DeleteSandbox (one per UID), one UID may hold at most 32 of
  the rest and 32 ordinary RPC handlers, and GetSandbox and DeleteSandbox
  fall back to 4 reserved cleanup handlers (one per UID). A connection that
  has not sent the HTTP/2 preface within 5 seconds is closed. So one UID's
  idle or busy sockets cannot keep another UID from Health or cleanup.
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
- **Bounded queries:** List supports bounded pagination cursors (200 items and
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
each sandbox PID 1, plus CLI support for scoped `gc ID...` and persistent-create
certainty (capability feature `0x10`, minimum kiln `e48f0e785ad484d0b2947897f6d48d0756059d7e`). It checks
capabilities and complete `gc --help` usage before reconciliation, Create and
Exec. Sandboxes whose PID 1 predates `0x10` keep working;
older sandbox instances without protocol v1 require explicit recreation. Command bytes use private
streams, so real exits 125/126/127 and signal termination remain distinct from
runtime failures. Schema 7 stores typed outcomes, truthful output-accounting evidence, create
certainty and creator UID. Older databases migrate at open: historical create
certainty stays ambiguous and historical ownership becomes root. Older binaries
refuse the result. See [setup](docs/setup.md) before upgrading.

These bounds are not tenant isolation: authorized callers share one set of node
budgets, and per-UID shares only stop one UID from taking more than its share of
connections and RPCs. Messages decode before service RPC
admission, under the connection, stream and message caps. SQLite/filesystem
work is synchronous. Terminal history has age/count retention; charged and
unfinished rows remain protected. Defaults and
flags are listed in [the architecture](docs/architecture.md#limits-and-defaults).

## Quick start (in kiln's Lima VM)

Full instructions: [docs/setup.md](docs/setup.md).

```sh
# on the Mac
git clone https://github.com/lambda-nine/kiln ~/Projects/lambda-nine/kiln
git clone https://github.com/lambda-nine/kilnd ~/Projects/lambda-nine/kilnd
git -C ~/Projects/lambda-nine/kiln checkout --detach 00d61c546db7aa67ad283d10c2ca6165ca5f8166
cd ~/Projects/lambda-nine/kiln && limactl create --name=kiln lima.yaml && limactl start kiln

# in the VM, once: kiln itself (see kiln's README), then kilnd
limactl shell --workdir ~/Projects/lambda-nine/kilnd kiln
sudo apt-get install -y protobuf-compiler sqlite3
scripts/install.sh                      # daemon + helper + CLI, service account and hardened units

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
in again) to use `kilndctl` without sudo. Without sudo you see only the sandboxes
you created, so one made with `sudo` above stays visible only to root.

## Checks

```sh
scripts/build.sh default test
scripts/build.sh default clippy --all-targets
git diff --check
```

CI runs these with Rust 1.88 on Ubuntu 24.04. The privileged checks run by
hand in the VM after `scripts/install.sh`:

```sh
scripts/integration-test.sh   # real kiln plus dedicated-child admission FD/RSS stress
scripts/daemon-singleton-regressions.sh # duplicate startup cannot disturb live work
scripts/state-path-regressions.sh # hostile state ancestors/files fail before reconciliation
sudo python3 -I scripts/phase0-regressions.py # real UID ownership, helper, privilege and retention checks
scripts/smoke.sh              # kilndctl → socket → service → kiln, checked through the API
```

## Layout

| Path | What |
|------|------|
| `proto/kilnd/v1/` | The versioned API |
| `crates/kilnd-api` | Generated Rust types and gRPC stubs |
| `crates/kilnd` | The daemon: manager, store, runtime adapters, server |
| `crates/kilndctl` | The client |
| `deploy/` | Hardened daemon/helper services, private socket and tmpfiles |
| `scripts/` | Install, integration test, smoke test |
| `docs/` | [Architecture](docs/architecture.md), [threat model](docs/threat-model.md), [setup](docs/setup.md), [roadmap](docs/roadmap.md) |

## License

Copyright 2026 Stephen Estrada. Licensed under the
[Apache License, Version 2.0](LICENSE).

## Privilege boundary

The API socket is `kilnd:kilnd 0660` in `/run/kilnd` (0750); state stays
private to `kilnd` (0700 directory, 0600 DB/sidecars). `--helper-socket` defaults
to `/run/kilnd-helper/helper.sock`, `root:kilnd 0660` in a root-owned 0750
directory. Only the service UID passes the helper's peer check, including
rejecting root and ordinary API group members. `kilnd` refuses to run as root.
The helper checks the daemon's typed request again, uses fixed argv and a
cleared environment, and owns the existing CLI cleanup barriers. The daemon
checks that its helper peer is root. See the [protocol and threat analysis](docs/helper-protocol.md).

## History retention

History is pruned at startup and every `--prune-interval-secs` (60 by default).
Terminal executions have a seven day / 10,000 row limit (`--execution-max-age-secs`,
`--execution-max-count`). Deleted sandboxes and uncharged failed creates have a
seven day / 1,000 row limit (`--deleted-sandbox-max-age-secs`,
`--deleted-sandbox-max-count`). The first limit reached expires history; zero
age/count keeps none of the eligible history. Reserved or nonterminal sandbox
rows and unfinished executions never expire. Removing sandbox history removes
its terminal execution history too. SQLite reuses freed pages; pruning does not
securely erase old bytes from the DB, WAL, backups or storage.

`--output-storage full|metadata|none` controls future durable output. `full` is
the compatibility default; **`metadata` is recommended**, keeping observed byte
counts, certainty and capture truncation facts without stdout/stderr bytes.
`none` keeps neither output bytes nor output evidence (zero counts with unknown
totals). The immediate Exec response still carries captured output. Other
execution metadata, argv, labels and diagnostics can contain secrets. Changing
mode does not scrub historical rows or backups.
