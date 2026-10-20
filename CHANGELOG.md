# Changelog

Notable changes to kilnd. Versions follow [Semantic Versioning](https://semver.org/);
before 1.0, any minor release may change the CLI or on-disk layout. The
`kilnd.v1` API only gains fields and RPCs.

## Unreleased

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
