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
  as the sandbox's immutable owner. Get, Exec, RenewSandbox, Delete, GetExecution and List
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
  receipts in Rust and matches their complete binding and generation: those of the
  live rows each time, and all of them whenever another connection has committed
  since kilnd last checked (SQLite's `data_version`; kilnd's own writes never change
  a receipt), at startup and at every prune. Invalid or
  missing evidence remains charged and is projected QUARANTINED; Health is degraded,
  admission refuses, and prune retains it. Store connections set and verify
  trusted_schema=OFF, and the trigger validator is deterministic/innocuous.
  Schema 10 also stores a SHA-256 marker of immutable reservation membership,
  updated only by trusted insert/prune code in the same transaction; schema 12
  verifies it and replaces it with additive aggregates (all rows, and the rows
  settled at the last full audit) so checks stay bounded as history grows. Every
  accounting read rehashes the charged and recently released rows against them; the
  first read after any other connection commits, startup and every prune rehash all
  history and check that settled plus live rows add up, so a row lost or released
  past the triggers is caught by the next decision. Missing/changed membership
  refuses reads/admission/prune as degraded with unknown totals, never free capacity,
  and a failed prune latches admission off. It cannot detect pre-migration loss,
  coordinated rewriting of both data and aggregates, or edits to the file that
  bypass SQLite. See the
  [B2 storage design](design/phase1b-firecracker.md#84-schema-ownership-and-history-protection). Receipts are private,
  trusted backend evidence bounded to 16 KiB, never caller strings or guest assertions,
  and the API exposes none of them.
- **A retried create never makes a second sandbox within its retention, and a
  key never crosses uids.** A `request_id` is scoped to the caller's kernel uid, so
  another caller can neither read nor take over a key, and a foreign sandbox stays
  `NOT_FOUND` to release. The record commits with its `CREATING` row, ages only on
  `CLOCK_BOOTTIME` from an anchor read after that commit (so no pause before it
  counts), with a 0.1 % margin and a fresh window after a reboot, and pins its row,
  so no wall-clock step, pause, crash or prune frees a key early. Records are bounded
  per uid and per node; at a cap new keyed creates are refused, never earlier records
  pruned, so one caller filling its share cannot evict another's retry protection
  (it can fill the node cap, as it can fill `--max-sandboxes`). Release is explicit,
  owner-authorized, irreversible and effective only in the transaction that sees the
  row `DELETED`; the duplicate risk after it is the client's by contract. The request
  digest is an unkeyed hash of the request the caller itself sent, returned to no
  one. Legacy kiln's crashed creates stay charged and are never released by a retry
  or a release.
- **Expiry deletes only through the ordinary delete path, and only what a policy
  asked for.** A sandbox expires only if its own create sent an expiry policy: an
  absent policy never expires, whatever the node defaults, so a client that predates
  expiry cannot lose a sandbox to it. Expiry publishes the same `DELETING` intent a
  Delete does and removes through the same path, so it frees nothing a Delete could
  not, and an ambiguous reservation Delete refuses (a legacy row without a backend
  ID) is never an expiry target. Only the owner and root may renew; observers (Get,
  List, Health, GetExecution) never count as activity, so another caller cannot keep a
  sandbox alive by watching it, and a foreign ID is `NOT_FOUND`. An idle expiry can
  never take a sandbox from under an admitted Exec: Exec admission and the idle
  compare-and-set are serialized by the slot's admission gate. Deadlines are
  `CLOCK_BOOTTIME`, so a wall-clock step (NTP or an operator) cannot shorten or extend
  one within a boot; only root can change the clock's rate, and root already
  administers the node. Across a reboot one rebase reads the wall clock once, which
  only moves when a dead reservation (every sandbox is `LOST` after a reboot) comes
  back. Removals are bounded by `--max-concurrent-expiry-deletes`, so a mass expiry
  cannot starve the helper's slots: a client Delete of an expiry-owned row takes the
  same permit, and a removal task exists only while it holds one, so neither churn
  nor Deletes can pile up waiting tasks or run a fifth removal, and the timer queue holds one entry per durable
  reservation however fast callers renew or run commands. Health and the
  `kilnd-reason` trailer reveal only node aggregates and the caller's own rows'
  reasons.
- **Exec cwd and env never reach a host command line, a log or history as values.**
  The root helper hands them to kiln in a sealed memfd (exactly
  `F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE`) named by descriptor number, so
  no value is in any process's `/proc/*/cmdline`, and the kiln CLI's environment stays
  the helper's cleared one; nothing caller-derived but argv after `--` is on the root
  command line. They are validated in kilnd, again in the helper at its ceilings and
  again in kiln; the cwd is interior to the sandbox (`..` and symlinks resolve inside
  its root, a host-only path such as `/var/lib/kilnd-helper` is `ENOENT`, and kiln
  enters it only after closing every inherited descriptor, so `/proc/self/fd/N`
  cannot name a host directory). History keeps the cwd, the override names and
  `env_sha256`; the in-memory env type's `Debug` redacts values and errors name entries
  by position. The helper logs a malformed request frame by parse category and
  position only, since serde's own message quotes the frame's values. The hash is an unkeyed integrity fingerprint that clients recompute, not
  confidentiality: a low-entropy value can be guessed from it, as from a create
  request digest that covers default env. Options never run without their gate: an
  unproven backend is `backend_unsupported`, a sandbox whose PID 1 lacks bit `0x20` is
  `sandbox_unsupported`, and an operator downgrade that slips past both fails the
  execution before any child starts.
- **Sandbox default env is plaintext in `kilnd.db` while the sandbox is live,** by
  design (decision 1 of the API additions): executions after a restart still need it.
  It is set to null in the statement that moves the row to `FAILED` or `DELETED`, and a
  `CHECK` makes a terminal row with values impossible, but clearing is logical: SQLite,
  its WAL, free pages and backups may keep the bytes until overwritten, as for output.
  The contract is that callers send no secrets in env or default env; a command that
  prints its environment puts the values in its own output, which is stored like any
  output.
- **ExecStream's live output cannot slow a command or take more than its share.**
  Live bytes are an observer's copy: the capture readers count and retain first, and
  their tap cannot fail, await or block, so capture evidence is the same with or
  without a stream. The helper sends each read on its own `SOCK_SEQPACKET` socket with
  `MSG_DONTWAIT` and drops it when the socket is full; kilnd's per-execution queue is
  bounded (256 KiB of allocated capacity, per-entry overhead and deque slots) and
  drops what does not fit. A client that
  stops reading loses live bytes only; its permits come back when the final message is
  handed to the transport, which may then hold it at the bound of a unary response a
  peer refuses to read. Streams are capped per node (16) and per uid (8, below the
  node's), and the node's cap is below the Exec admissions, so one uid cannot hold
  every stream and streams cannot hold every Exec. The live socket carries only the
  command's own output, never the CLI's diagnostics, and kilnd validates every
  message's stream, size and offsets. Live output is lossy by contract; the retained
  prefix and the totals in the final row stay the authority, and an inexact total is
  never reported as an exact tail.
- **No request-owned exec work.** After an execution row is recorded, a
  daemon supervisor owns backend cleanup, pipe capture and finalization even
  if the RPC disappears. kiln places each command in an execution cgroup;
  the root helper waits for that cgroup to report empty after killing the CLI
  before acknowledging cleanup to kilnd. Daemon connection loss requests
  cancellation and helper-owned cleanup; CLI clients die with the helper
  (`PR_SET_PDEATHSIG` with a post-arm parent-PID check). They restore standard
  signal defaults before exec, and interrupted executions are recovered at
  startup.

### Workspace checkpoints (helper side, off by default)

The helper's checkpoint group (milestone C3, [helper-protocol.md](helper-protocol.md#checkpoint-group-1))
adds root operations over attacker-controlled sandbox state: kiln's capture walker and
fresh-upper importer parse it, and the helper parses only kiln's own strict records.
Requests carry typed IDs, never paths or flags. The helper certifies artifact facts
(COMPLETE, ABSENT, a reader's end) bound to the artifact, nonce, helper epoch and boot;
uid policy, quotas and node budgets stay the daemon's trust boundary, as for sandboxes.
A compromised daemon can capture and remove artifacts of its own instance ID, as it can
create and remove sandboxes. Absence is certified only after every worker was reaped and
no process names the artifact; a stuck worker keeps the artifact charged rather than
freeing it. The group is disabled unless root starts the helper with
`--enable-checkpoints`, and the daemon does not use it before the feature's later
milestones.

## What it relies on kiln for

Isolation itself: namespaces, the user-ID shift, seccomp denylist, Landlock,
cgroup limits, XFS quotas and network policy. kiln's known limits apply in
full; see kiln's README and SECURITY.md. In particular, all sandboxes share
one host UID range, seccomp is a denylist, and a kernel bug reachable from a
sandbox compromises the host.

## Known gaps

- **Capacity is not fairness or isolation.** Since Phase 1b B7 one UID can
  hold at most its share of connections (32 of 64) and ordinary RPCs (32 of
  64), and Health and cleanup keep reserved connection slots and RPC lanes
  (B6-BI-03); a socket that never sends the HTTP/2 preface is closed after 5
  seconds. kilnd refuses to start with flags that would let one UID's share
  cover the whole general pool, or its share plus its reserved slot the whole
  budget (B7 milestone 2). There is still no tenant scheduling: a UID's own
  slow clients fill its share, and the reserve is first-come and bounded per
  UID, not per caller, so colluding UIDs can fill the general pool and every
  reserved slot (four UIDs holding 33, 29, 1 and 1 connections at the
  defaults). Root keeps one connection slot and one Health/cleanup RPC permit
  of its own beyond the budget, so the operator still reaches Health,
  GetSandbox and DeleteSandbox. A client that sends the preface can then idle
  on its slot. There is no body-progress or idle watchdog after the preface.
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
- **The Firecracker backend launches only under test.** B4 adds the real host lifecycle:
  a cgroup tree, a fully preallocated private work disk exposed through a fixed-size loop
  device with discard disabled, a bounded private tmpfs jail with read-only artifact binds,
  the patched jailer (`deploy/firecracker/`) executed by retained descriptor with a
  verified zero capability set, Stop, Remove, scoped Gc and the real absence observation.
  Production still serves no profile: the manifest gate refuses every catalog until B7, the
  manager does not consume the helper's READY until B6, and `main.rs` selects kiln only.
  B5's broker relay and console drainer run outside H, in their own cgroup leaves, without
  capabilities, under the relay or VMM credentials; every guest byte is parsed there, under
  cumulative frame, byte and time budgets, and a breach of either retires the VM. The B4 root tests
  approve a catalog through a `cfg(test)` gate only. Firecracker's own isolation and its
  seccomp filter are trusted, not re-proven: a VMM-credential process without that filter
  still meets the jail's 16 MiB and 1024-inode caps, cannot write outside `/run`, cannot
  resize or deallocate the work disk (on the 6.8 kernel tested, even `LOOP_SET_STATUS64`,
  which loop allows any writer, did not re-enable hole punching), and cannot touch the
  backing file. The jailer's extra capabilities (`CAP_MKNOD`, `CAP_SYS_CHROOT`,
  `CAP_SETPCAP`) reach only S and its jailer: every other helper worker and kiln child
  drops them, verifies every capability set and exits rather than continue on any
  failure. Cleanup unmounts and detaches only by exact journaled identity, taken from kernel IDs
  never reused within a boot and journaled with the boot ID: each jail mount's and bind's
  unique mount ID (`STATX_MNT_ID_UNIQUE`, journaled before it is attached), a loop
  attachment's disk sequence number with its full tuple, and the cgroup tree's inodes; a work
  file adds its birth time, since its inode number is reused once deleted. A journaled loop
  slot bound to anything else, another backing file included, is Unknown, and the absence
  observation reads each journaled slot itself. The reusable mount ID, inode,
  source and marker are secondary checks only, and a bind that was never journaled is never
  inferred from its name. The fault model is explicit: host root replacing one of these
  resources before cleanup, at any crash point, is refused, left in place and the allocation
  stays charged; host root mutating our own resource in place during teardown (for example
  `LOOP_SET_STATUS64` on our attachment) is out of scope, because host root is trusted and the
  kernel has no compare-and-clear. Since B4 recheck 3 this is one invariant the type system
  enforces: no signal, `cgroup.kill`, `rmdir`, `unlink`, `umount2` or `LOOP_CLR_FD` runs
  unless the caller holds a proof (`helper/firecracker/proven.rs`, the only place those calls
  are made, checked by a CI test) that the resource's current generation is a durable
  journaled generation from the current boot. Every process identity carries the boot ID; a
  missing, invalid or unreadable one proves nothing and is never signaled. `cgroup.kill`
  needs the journaled inodes of the whole `vm` subtree, so a replaced or extra child is never
  killed through its parent. An object at a deterministic name with only an intent, or no
  record, journaled is Unknown: nothing is deleted by its name and the allocation stays
  charged until the operator removes it. Work files are journaled while still unlinked, and
  Remove re-reads the journal after its stop fence. The Phase 1b tool build trusts its build UID and that
  UID's processes, and gates on the digests of the outputs it published. kiln itself remains experimental shared-kernel isolation, not a boundary
  for hostile multi-tenant workloads.
- **A compromised service account cannot take over another instance.** Root enrolls each
  instance under its own Unix account, with its unit and image, and attachment proves all
  three. Enrollment and startup refuse two instances on one UID or GID, and refuse root, the
  helper's account and the VM identity ranges. So another instance's memory, signals and
  database are cross-UID to the kernel, with no dependence on Yama or any other sysctl, and
  its daemon files can't be copied in the first place. Its allocation IDs mean nothing
  outside its own namespace, and its attach queue accepts only its own account. Instances
  still share the node's capacity, and an account can still fill the helper's shared framing
  and operation slots until their deadlines: refused work is retried, and nothing is released.
- **The node ledger is part of the root trusted base,** with SQLite and its schema.
  Its triggers stop mistakes through SQL. They cannot stop root or anything with file
  authority: `SQLITE_DBCONFIG_ENABLE_TRIGGER`, a schema rewrite, or a rollback of the
  files to an older consistent state. Startup audits refuse a changed schema, mismatched
  receipts, a rolled-back generation counter and lost claims, but a coordinated rollback
  of database and WAL is undetected, and a removed WAL can lose its last commits.
- **A dynamically linked executable is unsupported, not bound.** Only static images
  can be approved. B4's root tests run a static (`crt-static`) build as the helper image
  and pass its self-check, but `scripts/install.sh` still installs the dynamic helper: a
  static glibc helper would lose NSS-based resolution for kiln's allowlists. Until B7
  ships and pins a static helper, a node cannot satisfy the self-check whatever the gate
  says.
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
  The tested Phase 0 companion is kiln `00d61c546db7aa67ad283d10c2ca6165ca5f8166`; exec cwd and env
  need kiln's capability bit `0x20`, first in kiln `5cada841edd0bbe112550816fad221dfb1db6a47`, the
  tested companion for them. See setup for the immutable installation pins.
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
  helper socket is root-owned and checks the exact service UID for kiln; sandbox UIDs,
  root and ordinary group members are rejected before parsing, and an account root enrolled
  for a Firecracker instance can use only that instance's requests. The daemon
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
