# Changelog

Notable changes to kilnd. Versions follow [Semantic Versioning](https://semver.org/);
before 1.0, any minor release may change the CLI or on-disk layout. The
`kilnd.v1` API only gains fields and RPCs.

## Unreleased

- Phase 1b B6 milestone 1: the first whole Firecracker session through the public API.
  `FirecrackerRuntime` now follows Create to the helper's journaled READY and sends
  Validate, Exec, Remove and Gc by exact allocation token with the journaled boot and
  inner sandbox; a token's absence fence removes an admitted allocation first. kilnd
  gains `--backend firecracker`, accepted only with `--firecracker-test-deployment`
  naming `deploy/firecracker-test/deployment.json` at its exact non-production paths;
  the production helper still serves no profile. The privileged
  `b6_linux_root_a_whole_session_through_kilnd_and_kilndctl` runs the real daemon in its
  own enrolled unit and drives it with `kilndctl`.

- Phase 1b B5 break-it corrections (Daybreak, November 3). The ledger compacts settled
  execution rows into one `exec_history` summary in the settling transaction, caps stop
  reasons and settled cleanup workers per allocation, and answers an oversized reply with
  `oversized` instead of exiting; Exec polls cancellation, the deadline and the session
  watch beside a bounded BUSY write, and any unanswered journal write retires the VM; a
  worker `Endpoint` write that fails after any byte poisons the connection, and S reports
  such a job as dispatch-uncertain; relay failures carry their reach and only local ones
  restore READY; one control operation per allocation (`control_busy`), late probe
  failures still retire; a Result for another inner sandbox, a wrong broker digest or
  missing kiln features retire the VM; capture facts are unknown without a Result and
  count delivered bytes when forwarding stops. The guest broker answers Probe idle only
  for a live persistent sandbox. Remove's ledger calls are bounded by its deadline.

- Phase 1b B5 milestone 2. New `kilnd-guest-broker` crate: the guest broker baked into
  kiln-guest (pinned there at kilnd `fb9034d`, broker `d4eb4cac`), started by `/init` as
  guest root and never restarted, listening on vsock 5252 for the host only, with one
  persistent kiln sandbox per VM driven through `kilnd-exec-core`. The protocol crate gains
  the `KID1` identity and `/init` bootstrap codec and `SharedBudget`, and folds in milestone
  1's break-it findings (poisoned readers and writers, linear duplicate-key checks). The
  helper's S forks a broker relay R (relay cgroup leaf and UID/GID, no capabilities), which
  parses every guest byte, read at most 4 MiB/s per connection, and a console drainer D
  (rate-metered, drains to EOF); READY is journaled only after a matching Hello and
  Initialize. New `validate` and `exec` Firecracker operations, `present_ready` Inspect and
  `ready` List: EXEC_INTENT is durable before any byte is sent, and any interruption after
  dispatch stops the VM. Ledger phases `ready`, `exec_intent` and `busy`, resource kinds
  `broker` and `exec` (schema 1 unchanged). Production Firecracker stays disabled.
- Phase 1b B5 milestone 1. kilnd's direct-kiln process, status, capture and validation code
  moved unchanged into the new `kilnd-exec-core` crate, which kilnd re-exports from the old
  paths (`scripts/b5-move-audit.py` proves the move token by token). New
  `kilnd-broker-protocol` crate: the strict `KGB1` broker protocol version 1 codec (36-byte
  header, sixteen kinds, per-direction sequences, strict JSON, field bounds, cumulative frame,
  wire and payload budgets charged before any payload byte, per-connection order and
  deadline-bounded stream I/O) with unit, property and stream-adversary tests. No broker,
  host module or image change yet; production Firecracker stays disabled.

- Phase 1b B4 recheck 5 corrections. The cgroup proof enumerates children from the retained
  descriptor (`getdents64` on a duplicate), and a proven unmount resolves its name from the
  held parent descriptor (a thread's own working directory), so a mount over the helper's
  `/proc/self/fd` can no longer hide a replacement or redirect an unmount. Process,
  boot-ID and mount-table reads go beneath a private, never-attached procfs instance. The
  API socket is identified by device, inode, birth time and file handle (inode generation)
  through its directory descriptor, so an inode-reused replacement is never unlinked. `LoopInfo64` is opaque and
  only a slot this process configured can have autoclear cleared; `process::run` starts
  only the verified kiln CLI with typed arguments. `clippy.toml` also disallows truncation,
  whole-file overwrite, `fallocate`, `prctl`, `ptrace` and `process_vm_*`; new CI tests
  reject unapproved build scripts, generated `include!`s and `/proc/` or `cgroup.` paths
  outside the approved modules.

- Phase 1b B4 recheck 4 corrections. `executable::publish_object` copies into an unnamed
  `O_TMPFILE` inode, checks it through its descriptor and links that descriptor, then
  re-reads the name; there is no temporary name to replace or unlink. The destructive-action
  gate is now semantic: `clippy.toml` disallows the raw signal, removal, rename, unmount,
  `ioctl`, `syscall` and subprocess functions (calls and function values alike), and only
  `proven.rs`, the new typed wrapper module `crate::sys` and six named subprocess and socket
  functions may allow them; a CI test rejects any other allow, lint-group silencer, foreign
  declaration or inline assembly. `cgroup.kill` is written only inside `proven.rs`, and the
  generic cgroup writer takes a `ControlFile` that cannot name it. CI runs clippy on 1.88
  and 1.99.

- Phase 1b B4 recheck 3 corrections. Every destructive helper action (signals,
  `cgroup.kill`, cgroup and directory `rmdir`, file `unlink`, `umount2`, `LOOP_CLR_FD`) now
  requires a proof type from the new `helper/firecracker/proven.rs` that the resource is a
  durable journaled generation from the current boot; a CI test fails on any such call
  elsewhere. Process identities and stop targets carry a validated boot ID (an older row
  without one is never signaled and stays charged), and an unreadable host boot ID is an
  error. `cgroup.kill` proves the whole `vm` subtree first, so a replaced child is Replaced
  with no signal. Intents are journaled before the cgroup tree, directories and files; the
  directories' generations right after `mkdir`; work files are created unlinked and linked
  only once journaled. An object present with no journaled generation is Unknown, never
  deleted by its name. Remove reloads the journal after its stop fence. New ledger resource
  kinds `intent`, `work_dir` and `jail_dir`; the ledger keeps schema 1.

- Phase 1b B4 recheck 2 corrections. A journaled loop slot rebound to another backing file
  is Unknown and charged, not NotOurs; NotOurs remains only for an intent-only slot. Cleanup's
  leftover check and the absence observation read each journaled slot by major and minor, and
  cleanup journals `loop_released` once a generation is gone so a later binding of the slot
  is not mistaken for a replacement. The cgroup identity records the boot ID and every node's
  inode; a tree recorded in another boot, or a replaced child, is refused. Work-directory
  files add their `statx` birth time, so a replacement reusing the inode number is refused;
  a filesystem without `STATX_BTIME` refuses the launch. The ledger keeps schema 1: a B4
  ledger must be provisioned again.
- Phase 1b B4 recheck corrections. Teardown identity now comes from kernel IDs never reused
  within a boot, journaled with the boot ID: the jail tmpfs's and every bind's
  `STATX_MNT_ID_UNIQUE` (Linux 6.8+, no fallback), taken from the detached mount descriptor
  and journaled before it is attached, and the loop attachment's `BLKGETDISKSEQ`. Cleanup
  requires the journaled ID at the path, or on the loop descriptor, immediately before each
  unmount or `LOOP_CLR_FD`; the old tuple, source and marker are secondary. An unjournaled
  bind is Unknown, never inferred from its name. Loops attach with autoclear until their
  generation is journaled. The tool build stages privately and gates on the published
  digests. The formatter's `retained_fd` evidence waits for exit status 0. UID 0 without
  `CAP_SETPCAP` no longer takes the `NoNewPrivs` fallback and exits 76.
- Phase 1b B4 break-it corrections. Cleanup acts only on exact journaled identity: each jail
  tmpfs gets an allocation-specific source and a root-only nonce marker, journaled before it
  is mounted, and is built detached and attached whole. Its binds are journaled, and every
  mount is re-verified just before its unmount. Loop detach requires the full recorded tuple,
  block size included, on the descriptor that issues `LOOP_CLR_FD`. Mismatches are refused
  and stay charged. Helper workers and kiln children verify the launch-capability drop in
  every set and exit on any failure. The tool build pins its sysroot debs
  (`deploy/firecracker/mkfs-sysroot.lock`), the patch and both output digests. The
  formatter's tuple is recorded as inferred from its retained descriptor
  (`observation = retained_fd`) after a confirmed exec, not as observed. The ledger keeps
  schema 1: a B4 ledger must be provisioned again.
- Phase 1b B4: real Firecracker host lifecycle in `kilnd-helper`, test-approved only. S
  creates the allocation's cgroup tree, a fully preallocated XFS work disk exposed through a
  fixed-size loop device with discard disabled, and a bounded private tmpfs jail with
  read-only artifact binds; it launches the patched jailer (`deploy/firecracker/`, built by
  `scripts/build-phase1b-tools.sh`) by retained descriptor through a bootstrap gate, verifies
  the jailer's and VMM's actual images and the VMM's zero capability masks, hardens the jail
  and journals BOOTING. New helper operations `stop`, `remove` and `gc`; Remove releases only
  through the ABSENT fence after the real absence observation. The helper unit gains
  `CAP_MKNOD`, `CAP_SYS_CHROOT` and `CAP_SETPCAP`, which only S and its jailer keep, and write
  access to loop devices' sysfs queue settings. The node ledger gains phases and an
  append-only `resource_events` table (schema still 1: a B3 ledger must be provisioned
  again). Production still serves no profile and nothing reports READY. New: root
  regressions in `scripts/b4-vm-tests.sh`.
- Phase 1b B3 deployment: interrupted maintenance is fenced across a reboot and retried after a
  failed restore. Each command now writes `/var/lib/kilnd-helper/maintenance.json`, fsynced,
  before anything changes, and removes it last. `kilnd-maintenance-guard.service` runs
  `upgrade.sh --recover --boot` before the helper socket and every kilnd unit, which `Requires=`
  it, so a node comes back whole or stays down, and `kilnd-maintenance-finish.service` finishes
  the starts. Any error restoring a unit keeps the record, and an upgrade's journal and stage, and
  exits 3 until `--recover` succeeds. New: `scripts/kilnd-maintenance-tests.py`, also in CI, and
  reboot and failed-restore regressions in `scripts/deployment-regressions.py`.
- Phase 1b B3 deployment: `kilnd init-state` creates an instance's private state as its own
  account and prints its durable ID, which `scripts/add-instance.sh <name>` and the default
  instance's install then enroll before the unit starts; add-instance no longer takes an ID.
  Enrollment runs with activation masked, so no connection can bring the helper back, and
  restores exactly what was running, on a signal too. `scripts/upgrade.sh`, which
  `scripts/install.sh` runs on a configured node, replaces the images, refreshes every
  enrollment in one ledger transaction and restarts what was running, or puts everything back.
  New: `kilnd check-attachment`, `kilnd-helper enrollments`, `refresh-enrollments` and
  `restore-enrollments`, and `scripts/deployment-regressions.py`.
- Phase 1b B3: each enrolled Firecracker instance runs under its own Unix account, recorded
  by `kilnd-helper enroll --user` and refused if shared, root, the helper's or in a VM
  identity range, with `deploy/kilnd@.service` and `scripts/add-instance.sh`. Attachment
  requires that account, so instance isolation no longer depends on Yama. Allocation identity
  and every ledger row a claim or fence writes are keyed by (instance, allocation ID), and
  attach queues by the peer's kernel-reported UID, so one instance can no longer pre-fence
  another's token or fill its attach queue. The helper socket's group is now `kilnd-helper`,
  and enrolled accounts get no kiln requests. Earlier B3 ledgers must be provisioned again.
- Phase 1b B3: add the typed Firecracker helper group (disabled by default), approved
  plan verification, the root node ledger with durable claims and permanent absence
  fences, protected retained-descriptor executable handling, and fixed L/P/S/M/K worker
  processes. Fake resources only, under test; no VM launch, no READY reply, and every
  profile refused by the production gate. Kiln wire bytes are unchanged, except that a
  peer vanishing before its credentials can be read no longer ends the helper's listener.
  The helper's connection budget splits: 128 framing slots, then 60 normal and 4 reserved
  recovery operation slots after classification, so silent clients cannot occupy dispatch.
- Close the B3 break-it findings. Root enrolls Firecracker instances with `kilnd-helper
  enroll`, and attachment proves the peer's UID, unit cgroup and kilnd image; the database
  UUID authenticates nothing. Enrollment is bounded by policy, with one attachment slot per
  instance. Token gates follow the durable lookup and are partitioned by instance. Workers
  are never published without their journal row. Attachment needs Linux 6.5 or later.
- Add a durable per-instance quota on fences for tokens the ledger never admitted, so an
  attested instance can't grow the root ledger with random IDs. At the quota the fence
  fails closed and the charge stays. Fences for admitted tokens are never refused by it.

- Close B2 recheck findings in schema 10: audit release receipts in trusted Rust
  reads, retain invalid releases as charged/quarantined, degrade Health and refuse
  admission. Detect missing reservation membership with an atomic SHA-256 marker.
  Verify private kilnd ownership/modes at install/startup; document that hostile
  connections (including disabled triggers/spoofed validators) have file authority
  and are outside SQL guards. The B3/B4 root node ledger is authoritative and never
  frees node resources without its own ABSENT receipt. Mark the SQL validator
  innocuous and set/verify trusted_schema=OFF on every Store connection.

- Harden B2 accounting in schema 9: reject conflicts on every unique key before
  SQLite can replace-delete charged rows or fences, even with defensive pragmas
  off. Validate canonical typed AbsentFenced bytes and their column bindings in
  an SQL trigger; refuse an upgrade containing malformed schema-8 evidence.

- Phase 1b B2: add runtime preflight, typed receipts, execution dispositions and
  schema 8's stored reservation vectors and immutable release evidence, enforced in
  SQL; quarantine a kiln sandbox whose cleanup cannot be confirmed. Additive
  `kilnd.v1` fields. The fake models the absence-fenced backend; none is selectable.
- Serialize descriptor creation with fork on non-Linux hosts, where close-on-exec
  isn't atomic and a sibling child could hold a capture pipe past the drain grace.

- Fix B1's Python/Rust JSON mismatch with a production strict parser, ASCII
  canonicalizer and shared mutation/Unicode corpus; bind complete host specs
  including labels separately from guest execution specs, and isolate fixtures
  in test-only schemas/types with no production override.

- Freeze the Phase 1b `offline-768-v1` guest and launch contract (schema 2) as golden
  fixtures shared with kiln-guest, with an independent Rust check of its plan, digests
  and identity block. Fixtures only: production stays disabled without the broker.

- Bind the Phase 1b design's complete helper executable chain to verified inodes,
  add replacement-race gates, and record Stephen's October 31 design decisions.

- Specify the Phase 1b Firecracker runtime and guest broker design, including
  approved launch contracts, durable recovery, resource reservations and build gates.
- Address the Phase 1b design review with mandatory absence fences, node-global
  admission, live supervisor monitoring, bounded jail/I/O/workers and stronger gates.

- Isolate the lock CLOEXEC regression in a dedicated child so unrelated parallel
  forks cannot transiently retain its lock and cause a false inheritance failure.

- Remove unneeded AF_INET6 from the helper's supported IPv4-resolver deployment;
  retain AF_INET for hostname allowlists and AF_NETLINK for networking/nft, and
  assert the exact installed address-family set in the lifecycle regression.

- Honor non-Exec helper wire deadlines and cancellation through create, remove,
  list and scoped GC, capped by their internal limits; share the remaining
  removal budget with absence probes and preserve ambiguous create evidence.
  Wire-level regressions cover timeout without client cancellation and child reaping.

- Fix the helper stdio handoff ordering race on macOS: private protocol v3
  retains sent endpoints until recvmsg receipt, preventing premature output EOF
  and helper EPIPE. A deterministic regression forces send-before-receive;
  daemon and helper must be upgraded together.

- Fix PH0-1 root-helper availability: private protocol v2 creates stdio pairs in
  the helper and passes only peer endpoints to kilnd, rejecting all inbound
  descriptors. Per-syscall nonblocking socket I/O protects deadlines and the
  listener against mutable flags and backpressure; Linux regressions exercise
  flag mutation, stalled stdin and cancellation. Upgrade daemon/helper together.
- Preserve IPv4 host DNS resolution for hostname allowlists under the
  restored address-family filter; exercise full-network and hostname Create/Exec.
- Restore PH0-2 helper systemd address-family, personality, realtime and
  kernel-log filters with ambient CAP_SETUID for UID-map setup. Installed
  regressions require Seccomp 2 and exact effective/bounding capability masks.
- Clarify PH0-3: API page tokens are bounded plaintext cursors whose global
  sequence gaps can reveal cross-caller insertion counts; they are not opaque.

- Add startup/periodic age and count retention with reservation protection and full/metadata/none output storage.

- Run kilnd as its unprivileged system account with no capabilities; isolate
  validated kiln operations in a root socket-activated helper. Pass Exec stdio
  as descriptors, authenticate both peers, preserve cleanup evidence, and
  harden both systemd services. See docs/helper-protocol.md.

- Add durable per-caller ownership. Create records the connection's
  kernel-reported uid as an immutable `Sandbox.owner_uid` (field 10). Get, Exec,
  Delete, GetExecution and List are limited to the owner and root; a foreign
  sandbox or execution returns `NOT_FOUND` exactly like a missing one, and a
  connection without credentials gets `UNAUTHENTICATED`. Schema 7 assigns every
  existing row to root, so group members lose access to sandboxes created before
  the upgrade. List filtering happens in SQLite before limits, watermark and
  continuation. Page tokens are now `v2` and bound to the caller's uid, so
  `v1` tokens held across the upgrade fail with `INVALID_ARGUMENT`; restart the
  listing. Older binaries refuse schema 7. Node budgets stay shared: there are
  no per-user quotas yet.

- Stop definite pre-allocation create failures from permanently consuming node
  budgets. `Runtime::create` now returns a typed `CreateFailure`; ordinary errors
  convert to `AllocationAmbiguous` and only an explicit constructor claims
  `DefinitelyNotCreated`. The kiln adapter claims it only when its pre-create
  capability gate fails, or for direct-child exit status 124 with empty stdout
  and complete output EOF. Schema 5 adds a durable `create_certainty` written
  atomically with `FAILED`; every historical row stays ambiguous. Definite rows
  are uncharged and Delete retires them with no backend call; a failed durable
  update, panic, crash or other error stays charged across restart. The installed
  CLI must now advertise capability feature `0x10` (kiln `e48f0e785ad484d0b2947897f6d48d0756059d7e`);
  live PID 1 instances need only the execution bits. Privileged suites cover
  real missing-image and private-allowlist preflight failures and a real
  post-allocation failure.

- Collapse nested runtime conditionals using let chains supported by Rust 1.88,
  keeping strict Clippy clean on both MSRV 1.88 and Rust 1.99.

- Preserve containment regression coverage from `review/exec-tree-containment`:
  timeout readiness, normal leader exit with nohup/setsid descendants, raw CLI
  stdout/stderr EOF, private output EOF, graceful shutdown and abrupt daemon
  death. The smoke uses the current API for durable outcome checks.

- Make detached-child cancellation coverage wait for a marker written after
  successful setsid and live child creation. Verify both workload streams
  reach EOF, descendants disappear, and the sandbox remains reusable.

- Reject exec-capable CLIs lacking scoped `gc ID...` before reconciliation and
  workload launch, including on an empty database. A complete, bounded
  `gc --help` usage check supplements v1 capability frames without global GC.
  Minimum companion kiln is `40d9aa5003205d4c171e1b3eca61e9868064e98b`;
  the previously advertised `711440db3167` is insufficient. Privileged suites
  pass with tested kiln `46d84bdfe13e331f047e70e38848f7d74bcd2872`
  (`review/breakit-fixes`), now pinned in setup and the quick start.

- Recheck compensated history on every Delete state reload, including after
  waiting for create compensation. Queued deletion cannot remove a replacement
  using the old backend ID or temporarily reserve compensated history again.

- Require exact-backend absence evidence after both successful and failed
  removal, including failed-publication compensation. A live direct probe or
  surviving cgroup keeps the row and its reservation retryable. Ambiguous
  no-ID creates remain charged even with an empty listing; clearing them needs
  authoritative resource reconciliation, which is not currently supported.
  Store comments and operator guidance describe that retained-capacity limit.

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
