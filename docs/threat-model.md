# kilnd threat boundaries

kilnd is a control plane for **experimental, shared-kernel** sandboxes. This
file says what it protects, what it trusts, and what it doesn't try to do.

## Trust levels

| Who | Trusted with |
|-----|--------------|
| root on the host | everything |
| members of the `kilnd` group | full use of the API: create, run any command in, and delete any sandbox kilnd manages. Treat membership as near-root on a dev box. |
| code inside a sandbox | nothing on the host. It is contained by kiln (namespaces, cgroups, seccomp, Landlock, nftables), not by kilnd. |
| other local users | nothing. They can't reach the socket. |

## Boundaries kilnd enforces

- **Socket access.** `/run/kilnd` is `root:kilnd 0750` and the socket
  `root:kilnd 0660` (or root-only with `--socket-group ''`). kilnd refuses a
  socket directory it doesn't own, locks that directory before reconciliation,
  and, on Linux, won't replace anything at the socket path except an unchanged
  socket whose bounded connection probe returned `ECONNREFUSED`. Platforms
  where refusal can also mean backlog pressure fail closed. Shutdown unlinks
  the path only when its device and inode still match this instance. Each
  connection's uid, gid and pid are logged from `SO_PEERCRED`. There is no
  per-call authorization beyond this.
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
  the final directory to be root-owned 0700. It pins that directory, opens the
  persistent instance lock relative to it, and validates the database plus
  SQLite sidecars as root-owned regular 0600 single-link files. SQLite opens
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
- **No request-owned exec work.** After an execution row is recorded, a
  daemon supervisor owns backend cleanup, pipe capture and finalization even
  if the RPC disappears. kiln places each command in an execution cgroup;
  after killing the CLI, kilnd waits for that cgroup to report empty before
  releasing ownership. `kiln exec` clients also die with kilnd
  (`PR_SET_PDEATHSIG` with a post-arm parent-PID check); they restore standard
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
  listing by repeating a preflight failure until the rows are deleted. Durable
  history has no retention limit yet; see the roadmap.
  Memory, PIDs and disk are reserved from requested effective sandbox limits;
  they are not measurements of current RSS, task count or disk usage. CPU is
  intentionally schedulable and may be overcommitted rather than reserved.
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
- **Output is stored as-is.** Up to 1 MiB of each stream per execution goes
  into SQLite. Secrets a command prints are persisted (root-only) until the
  database is pruned, and there is no retention yet.
- **The database grows without bound.** Deleted sandboxes and every
  execution are kept for history.
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
  The tested companion is kiln `e48f0e785ad484d0b2947897f6d48d0756059d7e`; see setup for the immutable
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
- **Group members are not isolated from each other.** Any member can exec in
  or delete any sandbox. Per-caller ownership belongs to the harness layer or
  a later API version.
- **No API authentication beyond Unix permissions,** and no TLS, by design:
  the socket is local. Remote access would need an authenticated proxy.
- **kilnd runs as root,** because kiln does. A bug in kilnd's request handling
  is a bug in a root process; the attack surface is the socket, reachable
  only by root and the `kilnd` group.
