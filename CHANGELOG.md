# Changelog

Notable changes to kilnd. Versions follow [Semantic Versioning](https://semver.org/);
before 1.0, any minor release may change the CLI or on-disk layout. The
`kilnd.v1` API only gains fields and RPCs.

## Unreleased

- Adds finite connection/stream/message and RPC admission bounds, global and
  per-sandbox Exec capacity with aggregate stdin permits, and queue-inclusive
  absolute deadlines while preserving daemon-owned cleanup and publication.
  Health exposes admission use/rejections and coalesces cached backend probes
  with timeout and panic recovery. List gains bounded stable pagination with
  opaque tokens, explicit legacy overflow errors and incremental CLI output;
  SQLite schema v2 preserves legacy list order on migration. GetSandbox reads
  execution metadata without fetching output BLOBs. New startup flags validate
  capacity relationships before state or socket side effects. Health probe
  timeout ownership now lasts through child reaping, idle sandbox admission
  slots are reclaimed, and a dedicated Linux child harness measures FD/RSS
  recovery under slow connections, queued stdin and concurrent Health.

- `CreateSandbox` work is daemon-owned after acceptance: client cancellation
  no longer strands `CREATING` rows or live unrecorded backends, failed state
  publication is compensated and retryable, and shutdown drains accepted
  creates before exit.
- Recorded executions are daemon-owned: disconnecting an `Exec` caller
  requests cancellation without dropping cleanup or finalization, queued
  disconnected calls are discarded, terminal writes retry while retaining
  ownership, and shutdown drains execution supervisors even after the
  transport reply deadline.
- Requires kiln at or after `3b42552` for per-execution cgroup teardown and
  cumulative runtime hardening.
- Startup now locks both the state and socket directories before
  reconciliation, refuses live socket owners, replaces only positively stale
  sockets on Linux, and conditionally removes only the socket inode this
  instance bound. Ambiguous platforms fail closed. Duplicate starts cannot
  interrupt active daemon-owned work.

## 0.1.0 - 2026-10-13

First vertical slice.

- `kilnd`: gRPC `kilnd.v1` (Health, CreateSandbox, GetSandbox, ListSandboxes,
  DeleteSandbox, Exec, GetExecution) on a root:kilnd Unix socket.
- Runtime adapter trait with a kiln CLI backend (argv only, cleared
  environment) and an in-memory fake for tests.
- SQLite state for sandboxes and executions, with bounded output.
- Startup reconciliation with `kiln gc` and `kiln ls`.
- Exec timeouts that stop the command inside the sandbox, per-sandbox exec
  ordering, graceful shutdown, structured text or JSON logs.
- `kilndctl` client, systemd unit, install, integration and smoke scripts.
- Requires kiln at or after `3736329`.
