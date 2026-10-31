# kilnd threat boundaries

kilnd is a control plane for **experimental, shared-kernel** sandboxes. This
file says what it protects, what it trusts, and what it doesn't try to do.

## Trust levels

| Who | Trusted with |
|-----|--------------|
| root on the host | everything, including every caller's sandboxes through the API |
| the kilnd process and its account | everything kilnd manages. Ownership is enforced inside kilnd, so whoever controls that process or its state directory bypasses it. |
| members of the `kilnd` group | create sandboxes, and see, run commands in, and delete only the ones they created. Sandboxes share one kernel and kiln is experimental isolation, so still treat membership as near-root on a dev box. |
| code inside a sandbox | nothing on the host. It is contained by kiln (namespaces, cgroups, seccomp, Landlock, nftables), not by kilnd. |
| other local users | nothing. They can't reach the socket. |

## Boundaries kilnd enforces

- **Socket access.** `/run/kilnd` is `kilnd:kilnd 0750` and the socket
  `kilnd:kilnd 0660` (or service-user-only with `--socket-group ''`). kilnd refuses a
  socket directory it doesn't own, locks that directory before reconciliation,
  and, on Linux, won't replace anything at the socket path except an unchanged
  socket whose bounded connection probe returned `ECONNREFUSED`. Platforms
  where refusal can also mean backlog pressure fail closed. Shutdown unlinks
  the path only when its device and inode still match this instance. Each
  connection's uid, gid and pid are logged from `SO_PEERCRED`.
- **Per-caller ownership.** Create records the connection's kernel-reported uid
  as the sandbox's immutable owner. Get, Exec, Delete, GetExecution and List
  authorize that uid before backend execution, Exec admission or stored-output reads,
  and List filters in SQLite before limits and continuation. Only the owner and
  root (uid 0) pass; a foreign ID is `NOT_FOUND`, the same as a missing one, and
  page tokens are bound to the uid. A connection whose credentials cannot be read
  is `UNAUTHENTICATED`, never root. Rows older than schema 7 belong to root.
  Tokens are bounded plaintext cursors, not opaque: their global creation
  sequence gaps can reveal counts of other callers' inserts over an interval.
  They reveal no foreign IDs, specs or output and do not bypass ownership.
  Health is open to anyone who can reach the socket and reports node-wide
  aggregates.
- **No shell injection into the host.** kiln is spawned with an argument
  vector. Flag values use `--flag=value`, the command follows `--`, and
  images, allowlist entries, paths, labels and IDs are validated before use.
  The environment is cleared except for a fixed `PATH`. Inside the sandbox,
  argv is exec'd directly; `sh -c` happens only when the caller asks for it.
  Newlines, Unicode and flag-like arguments stay literal; only NUL and the
  documented count/byte violations are rejected. See the
  [request validation contract](validation.md).
- **Bounded resource use by callers.** One durable SQLite transaction reserves
  sandbox count plus aggregate requested memory, PIDs and disk before it
  inserts `CREATING`; cancellation, panic and restart cannot lose that promise.
  `CREATING`, `READY`, `DELETING` and `LOST` reserve their full effective spec.
  A create failure without a backend ID is ambiguous and remains reserved until
  authoritative reconciliation can account for hidden resources, unless the
  runtime returned typed proof that nothing was allocated and that result is
  durably recorded. Ordinary listing absence never releases it; that
  reconciliation is not yet supported.
  Successful
  compensation releases only after the exact backend is absent and the
  terminal transition is durable. Lowered budgets reject Create but retain the
  cleanup control plane. Per-sandbox limits, queue-inclusive exec timeout,
  argv/argc, stdin and stored output also bound individual requests. Immediate
  admission caps connections, ordinary
  RPCs, reserved Health RPCs, global and per-sandbox Exec requests, and their
  aggregate retained stdin. Exec tickets remain owned through cleanup and
  terminal publication. HTTP/2 streams, fixed windows, headers and frames are
  bounded; generated codecs cap request/response messages. Service RPC permits
  are acquired after decoding, so the connection/stream/message caps bound
  simultaneous decoding, not the service semaphore alone. List has explicit
  item and encoded-byte bounds; GetSandbox reads metadata without output BLOBs
  and preserves persisted total-certainty and truncation evidence.
  Health shares and caches one backend probe, with a bounded timeout and panic
  isolation. See [defaults](architecture.md#limits-and-defaults).
- **State integrity.** The database path is absolute. kilnd resolves every
  nested symlink hop descriptor-relatively, validates alias and ancestor
  ownership plus non-writability, creates missing components without following
  symlinks, and requires
  the final directory to be owned by the service UID `kilnd`, mode 0700. It pins that directory, opens the
  persistent instance lock relative to it, and validates the database plus
  SQLite sidecars as `kilnd`-owned regular 0600 single-link files. SQLite opens
  the main file with `NOFOLLOW`; unsafe pre-created state is rejected before
  socket binding or reconciliation. The resolved socket parent must also have
  a different device/inode from the pinned state directory before its mode or
  group can change. Newer schemas are refused. Per-sandbox
  deletion is serialized; the row is reloaded
  after acquiring that lock and lifecycle writes compare their expected state,
  so concurrent or stale delete results cannot rewrite `DELETED` timestamps or
  resurrect `DELETING`. A backend side effect whose caller is interrupted is
  reconciled by retry, treating an already-absent backend as success.
  Startup garbage collection receives only stale backend IDs recorded in
  kilnd's own rows; unmanaged live and stale sandboxes are retained. Restart
  execution interruption is likewise joined through each sandbox and limited
  to the active backend.
- **Typed reservation release.** Schema 8 records release explicitly. Legacy rows
  carry a tag computed from schema 7's exact predicate; absence-fenced rows need a
  foreign-key and trigger-checked reference to immutable evidence matching their own
  node, instance, allocation and plan. Reconciliation validates a complete inventory
  and all token evidence before any mutation or collection. These checks are defense
  in depth against kilnd bugs and malformed SQL, not a boundary against the `kilnd`
  account. Opening another SQLite connection already requires that account's
  database-file authority: disabling triggers with SQLITE_DBCONFIG_ENABLE_TRIGGER,
  spoofing a connection-local validator, dropping triggers and rewriting files are
  all out of scope. Triggers protect kilnd bugs and honest SQL mistakes through
  standard tools, not hostile connections. Permissions are the boundary: install
  checks kilnd ownership and 0700/0600 modes after legacy ownership transfer;
  startup checks before open and after SQLite setup. For Firecracker, the root-owned
  kilnd-helper node ledger (B3/B4) is authoritative even against a compromised
  kilnd user; it never frees capacity or host resources without its own ABSENT
  receipt, whatever the daemon DB says. B2 has no implemented node ledger yet.
  Every trusted accounting read independently decodes referenced FencedAbsence
  receipts in Rust and matches their complete binding and generation. Invalid or
  missing evidence remains charged and is projected QUARANTINED; Health is degraded,
  admission refuses, and prune retains it. Store connections set and verify
  trusted_schema=OFF, and the trigger validator is deterministic/innocuous.
  Schema 10 also stores a SHA-256 marker of immutable reservation membership,
  updated only by trusted insert/prune code in the same transaction. Startup and
  accounting reads compare it; missing/changed membership refuses reads/admission/
  prune as degraded with unknown totals, never free capacity. It cannot detect
  pre-migration loss or coordinated rewriting of both data and marker. See the
  [B2 storage design](design/phase1b-firecracker.md#84-schema-ownership-and-history-protection). Receipts are private,
  trusted backend evidence bounded to 16 KiB, never caller strings or guest assertions,
  and the API exposes none of them.
- **No request-owned exec work.** After an execution row is recorded, a
  daemon supervisor owns backend cleanup, pipe capture and finalization even
  if the RPC disappears. kiln places each command in an execution cgroup;
  the root helper waits for that cgroup to report empty after killing the CLI
  before acknowledging cleanup to kilnd. Daemon connection loss requests
  cancellation and helper-owned cleanup; CLI clients die with the helper
  (`PR_SET_PDEATHSIG` with a post-arm parent-PID check). They restore standard
  signal defaults before exec, and interrupted executions are recovered at
  startup.

## What it relies on kiln for

Isolation itself: namespaces, the user-ID shift, seccomp denylist, Landlock,
cgroup limits, XFS quotas and network policy. kiln's known limits apply in
full; see kiln's README and SECURITY.md. In particular, all sandboxes share
one host UID range, seccomp is a denylist, and a kernel bug reachable from a
sandbox compromises the host.

## Known gaps

- **Capacity is not fairness or isolation.** An authorized caller can occupy
  all bounded slots; there are no per-UID quotas or tenant scheduling. Slow
  clients consume only bounded connection/stream slots but can deny
  availability until disconnected. There is no body-progress or idle watchdog.
  Raw connection rejection closes the transport and cannot guarantee a gRPC
  status. Service permits end after response construction; transport caps
  bound slots held during response backpressure. These are capacity bounds,
  not measured allocator/RSS ceilings.
- **Node budgets cover kilnd-managed promises, not all root activity.** A
  trusted root user or direct `kiln` invocation can create unmanaged backends
  outside these reservations. Ambiguous no-ID creates remain charged even
  after all listed backends are removed; unexplained backends are not charged
  a fabricated spec.
- **Create certainty trusts the installed kiln CLI.** kilnd releases a
  reservation on exit status 124 from a CLI that advertised feature `0x10`, with
  no stdout and both pipes at EOF. It never parses diagnostics. The CLI is
  already trusted root-owned software that runs every sandbox; a kiln that broke
  this contract, or a replacement that advertised the feature falsely, could
  leave an unaccounted backend outside the budget. `--require-exec-protocol=1`
  stops a legacy binary swapped in after the gate. Anything else, including a
  crash before the marker is durable, fails closed and stays charged.
- **Failed creates retain history without consuming budget.** Rows released by
  typed proof, like `DELETED` rows and compensated `FAILED` rows, are not bounded
  by the node budgets. An authorized caller can grow the database and the default
  listing by repeating a preflight failure until the rows are deleted. Eligible terminal
  history is now bounded by configurable retention; charged rows stay.
  Memory, PIDs and disk are reserved from requested effective sandbox limits;
  they are not measurements of current RSS, task count or disk usage. CPU is
  intentionally schedulable and may be overcommitted rather than reserved. A
  legacy row's zero CPU, vCPU and host-PID values mean not reserved, not free.
- **The Firecracker backend does not exist yet.** Schema 8, absence evidence and
  dispositions are exercised only by `FakeRuntime`. No helper operation, node ledger,
  guest or VM exists; kilnd still runs kiln only, and that remains experimental
  shared-kernel isolation, not a boundary for hostile multi-tenant workloads.
  Daemon-local sums are never node totals for a backend with a node authority.
- **Deadlines are not hard real time.** SQLite and filesystem work is
  synchronous. Deadline delivery can be delayed by that work, and an expired
  recorded execution retains admission until backend cleanup and terminal
  publication finish. A queue-expired request has no row and returns
  `DEADLINE_EXCEEDED`; an execution timeout returns successful `TIMED_OUT`
  only after cleanup. A cached Health success can be up to 5 seconds old;
  finalization failures still degrade every response immediately.

- **Instance locks are cooperative.** Persistent `flock` files prevent
  cooperating kilnd processes from sharing a state or socket directory. They
  do not protect against root, a lock-unaware old daemon, or a process that
  deliberately ignores the locks. POSIX also has no atomic compare-and-unlink
  by inode; trusted directory ownership and the socket-directory lock close
  that race for supported instances. Stop old daemons before upgrading, and
  never delete a lock file to clear contention.
- **Socket reservation is not readiness.** The pathname is bound before
  reconciliation so contenders cannot mutate state first. Connections may
  wait until reconciliation finishes; use `Health`, not path existence, as
  the readiness check.
- **Terminal publication needs writable storage.** kilnd does not report an
  execution as successfully drained if its terminal update fails. It retains
  the outcome and sandbox lock, retries with bounded backoff, degrades health,
  and prevents graceful shutdown from completing. If an operator forcibly
  stops the daemon while storage remains unavailable, startup reconciliation
  later marks the still-`RUNNING` row `INTERRUPTED`.
- **Runtime cancellation is cooperative.** kilnd retains the sandbox lock and
  waits for `Runtime::exec`; a backend that never acknowledges cancellation
  can delay delete or shutdown indefinitely. The supported kiln backend
  returns only after its per-execution cgroup is empty and pipes are clean.
- **Output is stored as-is in the default `full` mode.** `metadata` is
  recommended: counts, certainty and truncation facts survive without output
  bytes. `none` discards that output evidence too. Retention bounds eligible
  terminal history by age and count; charged or unfinished work is never
  pruned. Pruning frees SQLite pages, not secure erasure of DB/WAL/backups.
  Argv, diagnostics and labels can also contain secrets. There is deliberately
  no regex secret redaction: it gives false confidence for arbitrary encoded,
  split or unfamiliar credentials. The [planned credential broker](roadmap.md#4-harness-anthropic-provider-and-agent-loop) should keep
  credentials out of sandbox-visible data in the first place.
- **Machine evidence has a private transport.** Four private Unix sockets
  separate status and workload stdio from bounded CLI diagnostics. Workload
  output cannot forge an outcome. Strict persistent-exec v1 decoding requires
  one frame and EOF; malformed or missing replies trigger host cleanup.
  Signal/core status and runtime failures remain separate, including real
  command exits 125/126/127. Readers preserve observed binary bytes/counts on
  error or panic and stay alive through the cleanup barrier. Captures settle
  with an explicit EOF timeout after drainage; failures retain partial evidence
  as an observed lower bound instead of claiming an exact total. Truncation is
  separately true only when observed bytes exceeded the retained prefix.
  Backend listings require clean EOF on both streams, no 64 KiB capture loss,
  strict newline-terminated records, unique IDs and valid shim PIDs. Startup,
  removal and failed-publication compensation directly probe omitted managed
  backends and check their cgroup before trusting absence, so a hidden registry record cannot turn a live sandbox
  into `LOST`. A validated exact backend may recover `LOST` to `READY`.
  CLI and every managed live sandbox must advertise required capabilities;
  incompatible replacements and old PID 1 instances fail closed.
  This requires persistent-exec v1 plus scoped `gc ID...` and persistent-create
  certainty (feature `0x10`), first combined in kiln `e48f0e785ad484d0b2947897f6d48d0756059d7e`. Older CLIs
  are refused before reconciliation, even with an empty database; a live PID 1
  only needs the execution bits. Complete `gc --help` usage supplements the protocol capability
  frame; compatibility validation never invokes global garbage collection.
  The tested Phase 0 companion is kiln `00d61c546db7aa67ad283d10c2ca6165ca5f8166`; see setup for the immutable
  installation pin.
- **A daemon crash during `kiln create`** can leave a kiln sandbox whose
  backend ID was never returned to kilnd. So can a CLI that dies or misreports
  after allocating. Reconciliation records the crashed row as an
  ambiguous `FAILED` reservation and logs the backend as unmanaged; it cannot
  safely pair the two or remove an operator-created sandbox. Delete refuses to
  release that reservation even when the ordinary listing is empty, because
  hidden or unpublished resources may survive. There is currently no supported
  authoritative reconciliation to clear a no-ID reservation. A trusted operator
  can investigate and remove stray resources, but an empty listing and a retry
  alone cannot return this capacity. Ordinary RPC cancellation is not this case: accepted creates
  are daemon-owned and finish or compensate after the caller disconnects.
- **Ownership is not resource isolation between group members.** It stops them
  from reaching each other's sandboxes through the API, but they share one kernel,
  one set of node budgets and one retention count, so one member can exhaust
  capacity or age out history for the others. There are no per-user quotas yet.
  Everyone with the same uid is one caller, and a connection keeps its connecting
  uid even if its descriptor is passed to another process.
- **No API authentication beyond Unix permissions and the peer uid,** and no TLS,
  by design: the socket is local. Remote access would need an authenticated proxy,
  which would appear to kilnd as a single uid.
- **The service account is trusted.** kilnd refuses root and runs with no
  capabilities. Its request/SQLite bugs do not directly execute in a root
  process. Root is reachable only through the [typed helper surface](helper-protocol.md):
  six kiln verbs, bounded frames and helper-created descriptor-only stdio, independent
  validation, no shell, fixed executable/argv and a cleared environment. The
  helper socket is root-owned and checks the exact service UID; sandbox UIDs,
  root and ordinary group members are rejected before parsing. The daemon
  checks that the helper peer is root. A compromised service account can call
  those operations for any kiln backend, including unmanaged ones: per-caller
  policy lives in kilnd. The helper and its shared direct adapter/process/
  protocol modules, installed kiln and the kernel remain privileged trusted
  code. This is a smaller root entry point, not protection against bugs in
  that trusted runtime or shared kernel.

The helper retains its own stdio endpoints and sends only their opposite
endpoints to kilnd. The daemon cannot change the helper endpoints' open file
status flags through SCM_RIGHTS. Per-syscall `MSG_DONTWAIT` on every helper
socket read/write and non-waiting AF_UNIX shutdown also protect its
current-thread listener from caller-induced blocking I/O. Stdin deadline,
cancellation and output-transfer bounds remain active under hostile flag
changes/backpressure. An attacker can still exhaust the 64 bounded helper
slots; this does not add fairness or protection from synchronous trusted
runtime/filesystem stalls. The root helper keeps systemd's address-family,
personality, realtime and kernel-log filters with ambient CAP_SETUID for
kiln's UID-map setup; see the [protocol](helper-protocol.md).
