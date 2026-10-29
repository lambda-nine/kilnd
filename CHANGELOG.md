# Changelog

Notable changes to kilnd. Versions follow [Semantic Versioning](https://semver.org/);
before 1.0, any minor release may change the CLI or on-disk layout. The
`kilnd.v1` API only gains fields and RPCs.

## Unreleased

- Add atomic, durable node-wide sandbox budgets for retained count, requested
  memory, PIDs and disk. Create now checks all four sums and inserts
  `CREATING` in one SQLite transaction; reservations survive cancellation,
  panic, reconciliation and restart, and release only after proven backend
  absence plus a durable terminal transition. LOST and ambiguous failed
  creates remain charged, compensated creates recover capacity, and lowered
  limits degrade Health while preserving Get/List/Delete for cleanup. Health,
  kilndctl, CLI defaults, operator guidance and bounded real-runtime stress now
  expose and verify the reservation contract.

- Close backend subprocess inheritance gaps: every launcher now captures the
  parent PID before spawn, arms `PR_SET_PDEATHSIG`, and rechecks the parent
  before exec so death during the post-fork window cannot release an
  unsupervised client. Backend children also restore default HUP, INT, QUIT,
  TERM and PIPE dispositions instead of preserving an ignored signal across
  exec.

- Harden persistent state setup: validate trusted path ancestors, require an
  exact private state directory, resolve and validate every nested symlink hop
  descriptor-relatively, acquire its lock relative to the pinned directory,
  open SQLite with no-follow semantics, reject foreign-owned, permissive,
  symlinked, non-regular or hard-linked database and sidecar entries, and
  reject socket-parent aliases of state before permission changes or
  reconciliation.

- Define and enforce one API/backend validation contract for IDs, image and
  path fields, allowlists, labels and literal argv. Root writable/allowlist
  entries, malformed path components, empty `argv[0]`, NUL and excessive
  count/byte sizes now fail as client errors before persistence or backend
  work; Unicode/newline and flag-like argv remain literal. kilnd also proves
  accepted argv fits kiln's 1 MiB encoded transport frame.

- Scope startup garbage collection to stale backend IDs recorded by kilnd,
  preserving unmanaged live and stale sandboxes across reconciliation and
  shutdown. Restart interruption now updates only executions joined to the
  active backend's sandboxes.

- Concurrent `DeleteSandbox` calls now share one serialized backend removal.
  Delete reloads durable state after acquiring the sandbox lock, treats an
  existing `DELETED` row as immutable success, and uses conditional state
  transitions so stale results cannot rewrite deletion timestamps or move a
  terminal row back to `DELETING`. Interrupted removals remain retryable on
  either side of the backend side effect.

- Output accounting now distinguishes an exact EOF-proven byte total from an
  observed lower bound when capture settlement stops early. Truncation records
  only bytes actually discarded by the retention bound and remains stable in
  metadata-only reads. The additive v1 API exposes total certainty, schema 4
  preserves it, and v1/v2/v3 rows migrate as unknown rather than inheriting an
  unsupported exactness claim. GetSandbox projects persisted output metadata
  without fetching BLOBs; an isolated Linux regression measures the advertised
  100 executions with two 1 MiB streams each.

- Startup reconciliation now fails closed on truncated, partial, duplicate or
  contradictory backend listings. Omitted managed sandboxes require a direct
  negative probe and absent cgroup before becoming `LOST`; exact backends that
  provably reappear recover to `READY`. Reconciliation validates all evidence
  before changing durable state and remains idempotent across restarts.

- Adds backend-neutral typed command termination and runtime diagnostics to
  executions, the additive v1 API, schema 3, and kilndctl. Private machine
  stdio/status sockets preserve binary evidence through failures, cleanup,
  cancellation and reader panics; real exits 125/126/127 remain command results.
  Strict capability validation gates startup, live sandboxes, Health and Exec;
  create requires protocol 1. Requires persistent-exec v1 first supplied by kiln
  `f3da4b5319566de4912ed617caf81d4eb8e50b6f`, with follow-up
  `711440db3167cdf3a90d3aad44623ce56c2d01b1`, based on `3b42552`.
  v1/v2 stores migrate through v3 with unknown historical typed values before
  output accounting advances them to v4; older binaries refuse the current
  schema. Migration can precede startup capability failure.
  Late status settlement preserves runtime failure/cleanup precedence over
  cancellation, sandbox absence requires a bounded successful list observation,
  signal numbers use uint32 on the API, and persisted native codes are bounded.
  Presence observations require verified EOF on both CLI streams; bounded
  control-command drainage retains completion/error evidence and the original
  cancellation/deadline budget, preventing late inherited writers from implying absence.

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
