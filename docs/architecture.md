# kilnd architecture

## Where it sits

```
 harness (later): agent loop, memory, tool registry, LLM provider
        │  gRPC kilnd.v1 over /run/kilnd/kilnd.sock
 ┌──────▼──────────────────────────────────────────────────────┐
 │ kilnd (UID kilnd, no capabilities, current-thread tokio runtime)    │
 │  service.rs   proto ⇄ model translation, error → gRPC code  │
 │  manager.rs   validation, state machine, per-sandbox locks, │
 │               reconciliation, shutdown                      │
 │  store.rs     SQLite (WAL, synchronous=FULL)                │
 │  runtime/     Runtime trait; kiln.rs (helper client), fake.rs (tests) │
 │  process.rs   argv spawn, timeout, cancel, bounded capture  │
 └──────┬──────────────────────────────────────────────────────┘
        │  typed IPC + stdio FDs → root helper → fixed kiln argv
 ┌──────▼──────────────────────────────────────────────────────┐
 │ kiln CLI → detached shim per sandbox → kiln-init (PID 1)    │
 └─────────────────────────────────────────────────────────────┘
```

kilnd is a library crate plus a small `main.rs`. Everything below the gRPC
layer is testable without a socket, and everything below the manager is
testable without kiln, through the fake runtime.

## The runtime adapter

`runtime::Runtime` is the only backend-shaped seam: `prepare(context, spec) →
PreparedCreate`, `create(context, prepared) → CreatedSandbox`,
`inspect_allocation`, `fence_absent`, `exec(id, execution, spec, cancel)`,
`validate_sandbox`, `remove`, `list`, `gc(ids)`, `version` and `capabilities`.
The contract that matters most: when an exec times out or is canceled, the
command must be stopped before `exec` returns, and its outcome must say what that
means for the sandbox. `ExecOutcome` carries a disposition (`Reusable`, `Stopped`,
`Quarantined`) and cleanup evidence (`Unknown`, `NoChildStarted`, `RuntimeDrained`,
`SandboxStopped`). `remove` and `gc` return typed `AbsenceReceipt`s, not `()`.

`KilnRuntime` talks only to the root helper. The helper revalidates typed
requests and uses `DirectKilnRuntime` in `runtime/kiln_direct.rs` to drive the
installed CLI. The direct adapter is also used by root-only integration tests.
The helper wire keeps its v3 shape, adds no action and carries no disposition: the
client derives it from the same finish result the direct adapter uses. See the
[private protocol](helper-protocol.md).

Kiln's `prepare` wraps the unchanged spec with an empty plan and allocates nothing.
Its CPU, vCPU and host-PID amounts are zero, meaning explicitly not reserved. Token
recovery is `Unsupported`, and its absence receipt only wraps the existing strict
removal proof. Reusable requires the existing cleanup barrier; `CleanupFailed`,
including an unconfirmed helper exchange, becomes `Quarantined`.

The helper maps these operations to fixed argv:

| kilnd | kiln |
|-------|------|
| create | `kiln create --require-exec-protocol=1 --image=… --memory=… --cpus=… --pids=… --disk=… --net=…/--allow=… [--read-only --writable=…]`; stdout is the ID, exit 124 means a failure known before allocation |
| exec | `kiln exec --protocol=1 --status-fd=N --stdin-fd=I --stdout-fd=O --stderr-fd=E ID -- ARGV…`; private status and workload streams |
| delete | `kiln rm ID` |
| reconcile | `kiln ls`, scoped `kiln gc ID...`, then `kiln ls` again |
| health | `kiln capabilities --protocol=1` |

Every flag value uses `--flag=value` so it can't be parsed as another flag,
the command's argv follows `--`, and kilnd validates every value before it
reaches kiln (kiln validates again). Timeouts and cancellation kill the
`kiln exec` client; kiln's PID 1 notices the hangup, kills every process in
that command's per-execution cgroup, and finishes only after the cgroup is
empty. The killed CLI cannot receive PID 1's reply, so the root helper independently
waits for the host's `exec/cgroup.events` to report `populated 0` before it
finalizes or unlocks the sandbox. This also contains descendants that changed
process group or session. `kiln exec` is serial per sandbox, so kilnd queues
executions per sandbox rather than letting them pile up in kiln's socket
backlog.

The exact API/backend grammar and byte accounting are documented in the
[request validation contract](validation.md). Create and Exec validate before
inserting lifecycle rows or invoking the adapter. In particular, writable
root and allowlist root are rejected, and argv is literal UTF-8 data rather
than shell text. The configurable API argv limit counts bytes plus one per
argument; a separate check proves the four-byte-count/four-byte-length kiln
frame stays within its 1 MiB body limit.

Exec calculates one absolute Tokio deadline at handler receipt (or direct
manager entry). Queueing and process setup consume that same budget; the
runtime and process runner use `sleep_until(deadline)`. The row retains the
original requested/default timeout. Expiry while queued creates no row or
backend call and returns `DEADLINE_EXCEEDED`. Once a row exists, timeout
produces a successful terminal `TIMED_OUT` execution after backend cleanup
and SQLite publication. Cleanup is never timed out by the service.

The installed CLI must advertise persistent-exec v1 (features `0xf`) plus
persistent-create certainty (feature `0x10`), and support scoped GC. They first
coexist in kiln `e48f0e785ad484d0b2947897f6d48d0756059d7e`. Older artifacts, including
`40d9aa5003205d4c171e1b3eca61e9868064e98b`, which first combined v1 with scoped
GC, are refused. CLI capability validation
also requires complete, bounded `gc --help` output advertising `gc [ID]...`,
within the caller's deadline. It never invokes global GC to test compatibility.
Privileged verification uses kiln `e48f0e785ad484d0b2947897f6d48d0756059d7e`; setup pins that tested companion.
Both installed CLI and sandbox PID 1 capabilities are checked before each
execution, within its existing deadline. A live PID 1 is only asked for the
execution bits: it never allocates, so a sandbox started by an older CLI stays
usable. Create revalidates the CLI and requires
`--require-exec-protocol=1`, so a legacy binary swapped in after that gate
refuses before allocating; there is no machine legacy fallback. Package and
provenance strings aid diagnosis; capability frames decide compatibility.
If an ID capability probe fails, a side-effect-free `ls` observation consumes
the same absolute deadline. Only a successful complete list proving absence
becomes NotFound/Handshake and marks the managed sandbox LOST. A listed old
PID 1 stays Incompatible; failed or expired observations never imply absence.
List absence evidence requires verified EOF on both CLI streams with no read,
task or forced-stop error, untruncated CLI output and a valid table. The table
must have its exact tab-separated header, a newline-terminated three-field
record for every sandbox, valid unique IDs and numeric shim PIDs. A 64 KiB
capture cutoff, partial final record, duplicate or extra field is an error
before absence is considered. Even a syntactically complete list cannot prove
absence while that sandbox's cgroup still exists. The
generic runner retains internal completion metadata and prior captured bytes
on failures. Its post-child drain polls completion before the original cancel,
absolute deadline and 250 ms grace; drainage never grants a fresh deadline.
An inherited writer that outlives that bound makes the observation inconclusive.

The owned machine transport uses four private Unix stream socketpairs. Only
their four child ends cross exec; workload stdio and the status stream are
separate from bounded CLI stdout/stderr diagnostics. Workload output is binary
and each stream retains its first configured bytes while counting every byte
actually observed. EOF proves that count is the exact total; forced or failed
settlement leaves it as a lower bound. Shared capture state survives reader
errors and polling panics. The status codec requires one strict v1 frame and
EOF (at most 2088 bytes), with a two second frame deadline starting at the
first byte. CLI exit status is only a consistency check. Real exits 125, 126
and 127 remain command results; signal 15 remains distinct from exit 143.
Missing executables are LaunchFailed/Exec.

An execution returns a finish result, optional observed command termination,
and both captures. Completed without status becomes Internal/Report FAILED.
Timeout/cancel and malformed, missing or untrusted status kill and reap the
CLI and wait for the host cleanup barrier, unless trusted status proves
NoChildStarted or Drained. After reaping, status gets up to two seconds to
settle buffered bytes and EOF before deciding whether that barrier is needed.
Trusted runtime diagnostics take precedence over cancellation/timeout,
including PID 1 CleanupFailed. Late command status is retained alongside a
won cancellation/timeout. Received malformed status is Protocol/Report;
expected empty EOF after killing the CLI preserves cancellation/timeout.
Host cleanup failure always wins. Readers remain active through that barrier;
a separate two second capture settlement requires EOF afterwards. Capture
failure without a prior failure is Io/Capture; cleanup failure overrides other outcomes with
CleanupFailed/Cleanup. Previously observed status and bytes survive failures.
Runtime::exec returns this evidence directly; non-exec methods retain Results.

An allocation-token backend also needs preflight, recovery by exact token and
receipts bound to its identity. `FakeRuntime`'s `Fenced` mode exercises that contract
for the manager. `FirecrackerRuntime` is the unprivileged typed client for the helper's
Firecracker group: it reconstructs and verifies each prepared plan, and its create can
end only in a matching fence or a charged ambiguous failure, because this build has no
VM launch and no READY reply. `main.rs` still selects kiln only, and B7 alone may change
that. The helper's side is the [root node ledger](#firecracker-node-authority).

### Firecracker node authority

`helper/firecracker` holds approved plans, the root ledger and the fixed worker
processes ([protocol](helper-protocol.md#firecracker-group-schema-1),
[design](design/phase1b-firecracker.md#b3-implementation-notes-october-31-2026)). With
no `--firecracker-policy` the group answers Disabled. With one, a node ledger and
fixed workers run, and the production manifest gate still refuses every profile, so
every Preflight is a C0 refusal. Only an instance root enrolled can attach, and only from
its own Unix account, enrolled systemd unit and installed kilnd image; each has its own
attachment slot and queue, detached-work share and rejected-token quota, and allocation IDs
are keyed by instance throughout. Startup serves nothing until every worker
has its journal row.

`node.db` is SQLite in WAL/FULL with foreign keys on and `trusted_schema` off, in a
pinned root 0700 directory, with one single-link 0600 database and sidecars; only the
L process opens it. An explicit `--firecracker-init-ledger` creates it, and opening a
missing, partial, corrupt or foreign one fails closed. Startup rejects a changed schema
or row-level mismatch. One persistent lock excludes a second helper.

C2 is one transaction that claims the full reservation vector, the VMM and relay
UID/GID leases and the CID, and records INTENT, the plan, the executable leases, the
conditional stop authority and the supervisor's intent. BEFORE triggers guard every
unique key against each conflict algorithm. Each release goes through one
FULL-sync transaction: permanent retired token, matching receipt, then claim and lease
release, all or nothing. A fence needs every worker settled and the namespace
positively absent. Shared infrastructure counts once. A lowered ceiling denies new
admission and discounts nothing.

An installed executable is retained by descriptor after a no-symlink walk from `/`
with owner, mode, ACL and link checks, and every later check uses that descriptor.
A restart reopens only the exact journaled tuple, so a replacement inode with
identical bytes is refused. These are unprivileged property tests and root Linux
tests in B3.

B4 adds the real host lifecycle ([design](design/phase1b-firecracker.md#b4-implementation-notes-november-2-2026)):
`cgroup`, `storage`, `supervisor`, `monitor` and `lifecycle`. S builds the allocation's
cgroup tree, preallocated loop-backed work disk and bounded tmpfs jail, launches the
patched jailer by retained descriptor through a bootstrap gate, adopts and validates the
VMM, hardens the jail and journals BOOTING; every resource is journaled through L before
or as S owns it. Stop, Remove and scoped Gc contain through K's pinned-inode
`cgroup.kill`, clean up through a journaled cleanup-only S, and release only through the
existing ABSENT fence after a real namespace observation. Cleanup acts only on exact
journaled identities (the jail tmpfs's and binds' unique mount IDs, the loop slot's full
tuple and disk sequence number, the cgroup inodes with the boot ID, and file birth times) and
refuses anything else, so it stays charged. Production still serves no
profile and nothing reports READY.

## State machine

```
            create ok                 delete
 CREATING ───────────▶ READY ─────────────────▶ DELETING ──▶ DELETED
    │ create failed      │ backend gone            │ rm failed: stays DELETING
    ▼                    ▼ (exec or startup)       │ (retry delete, or startup retries)
  FAILED               LOST
    └──── delete ───▶ DELETED ◀──── delete ────┘

 READY ── cleanup unknown ──▶ QUARANTINED ── delete ──▶ DELETING
```

`QUARANTINED` means a backend may remain and cleanup or reuse cannot be established.
It refuses Exec with `FAILED_PRECONDITION`, never returns to `READY` by any path, and
stays charged until Delete proves it gone.

Executions: `RUNNING` → `EXITED` (with exit code) | `TIMED_OUT` | `CANCELED`
(caller disconnected, sandbox deleted, or daemon shutdown) | `FAILED` (backend error) |
`INTERRUPTED` (found running at startup).

A sandbox row is written as `CREATING` before `kiln create` runs, so a crash
mid-create leaves evidence. Creation then belongs to a tracked daemon task,
not the gRPC handler: disconnecting only drops the waiter. A failure records
`FAILED` with what the runtime proved about allocation (see
[Node resource reservations](#node-resource-reservations)). A successful
backend ID is published as `READY`; if that write fails, kilnd first records
`DELETING`, removes the backend, and records `FAILED`. Failed removal stays
`DELETING`, retains the backend ID, and counts against the retained reservation
ceiling. It is retryable. An execution row is written before `kiln exec` runs
and finished in one update afterwards. Once that row exists, a tracked
supervisor owns the request, sandbox lock, backend task, output capture, and
terminal update. The RPC is only a waiter: dropping it records the first
cancellation reason and requests cancellation, but cannot abandon cleanup. A
caller that disconnects while still queued is discarded before a row or
backend process is created.
The terminal update also commits `sandbox_reusable`, the cleanup evidence and the
sandbox's disposition in one transaction, before the slot is released: `Stopped`
becomes `LOST` and `Quarantined` becomes `QUARANTINED`, both still charged, and a
queued successor's reload refuses. `DELETING` keeps its intent. On an absence-fenced
row a claim without its evidence quarantines, and an otherwise clean finish becomes
`CleanupFailed`, keeping status and captures, so a timeout or exit never reads as clean
without a stop barrier, a drained completion or proof that no child started. Historical
rows report unknown evidence, as does an adapter panic on a legacy row, which otherwise
keeps its existing behavior; on an absence-fenced row a panic quarantines.
If the terminal SQLite update fails, the supervisor keeps the lock and outcome
and retries with bounded exponential backoff. Health is degraded and shutdown
cannot claim a completed drain until that publication succeeds.

### Node resource reservations

Per-sandbox cgroups and quotas bound one workload but do not stop the control
plane promising the same node capacity many times. Create therefore prepares
first, rechecks serving, then opens an SQLite `IMMEDIATE` transaction, sums every
charged row's stored vector with checked arithmetic, checks sandbox count plus every
vector dimension, and inserts the new `CREATING` row before committing. There is no
in-memory permit to lose on cancellation, panic or restart. A preflight rejection
leaves no row.

Schema 8 stores the reservation vector, both spec digests, full spec, profile,
artifact digest, disposition and boot identity on each row, and a release decision
that is never inferred at read time. Every older schema migrates through 7 and then
one atomic step, all in one transaction. Each legacy row's amounts come exactly from
its stored spec, with zero CPU, vCPU and host PIDs, and its tag comes exactly from
schema 7's predicate, so every old ambiguous failure stays charged.

Reservations on a legacy row follow ownership evidence:

- `CREATING`, `READY`, `DELETING`, `LOST` and `QUARANTINED` reserve their stored
  vector. `LOST` is retained because later reconciliation may restore the same
  backend to `READY`.
- `FAILED` without a backend ID remains reserved by default, because
  `Runtime::create` failures are `AllocationAmbiguous` unless proven otherwise.
  This covers every ordinary error, panics, task cancellation, a crash during
  create and every row older than schema 5. Delete refuses to release it even
  with an empty listing: no current Runtime operation can account for hidden or
  unpublished resources without the ID. Authoritative resource reconciliation
  would be needed to release this reservation.
- `FAILED` with the durable `definitely_not_created` marker releases. Only the
  explicit `CreateFailure::definitely_not_created` constructor can produce it,
  and one SQLite update writes the state and marker together, so there is no
  moment of released-but-unrecorded capacity. If that update fails the row stays
  `CREATING` and charged, and restart makes it ambiguous. Delete moves the row
  to `DELETED` without any backend call. A column `CHECK` keeps the marker off
  any row with a backend ID or a state that could own one.
- Successful failed-publication compensation records `FAILED` with the exact
  removed backend ID. That one `FAILED` shape releases immediately because
  removal or `NotFound` was proven before the durable transition. The kiln
  adapter requires a negative exact-ID probe, a complete list omitting that
  ID and an absent cgroup after both successful and failed `rm`. Deleting
  that historical row moves it directly to `DELETED` without touching a
  backend that may since have reused the ID. This rule is checked on every
  reload, including after waiting behind the create compensator's lock.
- `DELETED` releases. A failed or interrupted delete remains `DELETING` and
  cannot return capacity early.

The kiln adapter claims `definitely_not_created` in exactly two cases, and never
from diagnostics text:

- The capability gate that precedes every create failed, so no create process
  started.
- `kiln create`, from a CLI that just advertised feature `0x10`, completed as
  the direct child with exit status exactly 124, which kiln reserves for
  failures known before `new_id` (validation, configuration, image preflight).
  It must also have printed nothing to stdout and left both output pipes at
  EOF: an ID or a surviving descendant contradicts that claim.

From the spawn attempt on, everything else stays ambiguous: any other status, a
signal, a malformed success, deadline, cancellation, spawn or wait I/O failure.

An absence-fenced row has one rule instead: it is charged until its nullable
`release_evidence_id` references an immutable `release_evidence` row, whatever its
state, backend ID or certainty says. A composite foreign key binds that reference to
the row's own node, instance, allocation, plan digest and kind `absent_fenced`.
CHECKs and triggers forbid release before `FAILED`/`DELETED`, a prefilled backend ID,
changing any identity, plan, spec or reservation column, updating or deleting
evidence, deleting a charged row, returning to `READY` from a retired state, and
laundering a row between regimes or forging a legacy tag. These triggers also hold
on a connection with foreign keys off; every `Store` connection sets and verifies
foreign keys on before any schema work. `last_helper_generation` records the newest
generation the row published and only moves forward, with its ready or absence receipt:
a ready or absence receipt no newer than it fails closed, in `Store` and in SQL, and only
the row's own recorded release can replay. Evidence insert and terminal reference commit
in one transaction, and history pruning never removes evidence. `NotFound`, an empty
listing, a legacy receipt or a definite claim without a receipt releases nothing.

Delete on such a row publishes `DELETING` first, then proves absence by exact token:
removal if a record exists, `fence_absent` if none does. A row without a backend ID
can be fenced, unlike a legacy no-ID row. A failed READY publication compensates the
same way and stays charged until the receipt commits.

Budgets are configured promises, not live RSS or disk-use measurements.
Health reports both limits and reservations. `accounting_status` says where the
totals came from: `LOCAL_LEGACY` for kiln, whose CPU, vCPU and host-PID fields are
zero, and `UNAVAILABLE` when a node authority cannot be read, where totals are zero
rather than a local sum that looks authoritative. If an operator lowers a budget
below surviving ownership, startup reconciliation still completes and the API
remains available for Get/List/Delete. Health is `DEGRADED` and every new
Create is rejected until cleanup returns all sums within their ceilings.

## Instance ownership

Startup establishes two independent ownership domains before reconciliation:

1. `Store::open` requires an absolute state path. It resolves every absolute
   or relative symlink hop from pinned directory descriptors with
   `fstatat(AT_SYMLINK_NOFOLLOW)` and `readlinkat`, bounds link depth, and
   accepts only root/effective-uid-owned aliases. Directory traversal uses
   `openat(O_DIRECTORY|O_NOFOLLOW)`; missing components are created with
   descriptor-relative `mkdirat(0700)`. Ancestors
   must be owned by root or the effective uid and cannot be group/other
   writable unless they are sticky; the final directory must be owned by the
   effective uid and exactly 0700. The final directory descriptor stays open
   for the store lifetime.
2. The persistent `kilnd.lock` is opened relative to that pinned directory
   with `O_NOFOLLOW`, validated as a private single-link regular file, and
   locked nonblocking before SQLite is opened.
3. Existing `kilnd.db` and SQLite WAL/SHM/journal entries are opened
   descriptor-relatively with `O_NOFOLLOW` and must be effective-uid-owned,
   single-link regular files with mode 0600. A new database is tightened to
   0600 before schema work. SQLite opens the main file with
   `SQLITE_OPEN_NOFOLLOW`, and the pathname identity is checked before and
   after open.
4. The socket parent is trust-walked and pinned by descriptor. Its device/inode
   is compared with the pinned state directory, its persistent lock is opened
   descriptor-relatively, and group/mode changes use `fchown`/`fchmod` on the
   pinned descriptor. The supplied and resolved path identities are rechecked
   before binding. Lexical `..`, intermediate symlink and platform aliases
   therefore cannot widen state access by naming or racing the socket parent.
5. Socket binding takes a nonblocking advisory lock on the persistent
   `.kilnd.socket.lock` in the socket directory. An existing socket is probed
   with a bounded connection attempt: a successful connection is a live
   owner. On Linux, `ECONNREFUSED` plus an unchanged generation (device,
   inode, `statx` birth time and the `name_to_handle_at` file handle, which
   carries the inode generation number, all read without following through the
   pinned socket-directory descriptor) identifies a stale endpoint, which is removed
   with `unlinkat` on that descriptor after one more generation read
   (`crate::sys::socket`). An inode number reused by a replacement is
   refused. Platforms such as macOS, where refusal can also report a full
   live backlog, preserve the path and fail closed. Every other ambiguous
   result is also preserved and rejected.
6. The new listener is bound and its generation recorded through the
   directory descriptor. Only then may reconciliation
   invoke kiln or update SQLite.

The lock files are never unlinked. Their open descriptors are close-on-exec,
so kiln children cannot retain ownership after kilnd exits. The bound socket
is an RAII resource: graceful exit removes it only if the name still has the
generation recorded at bind time. A replacement is left
untouched.
The socket-directory lock remains held while Chapter 7 supervisors drain,
even if the transport listener has already closed.

These are resource-scoped advisory locks, not a defense against hostile root.
Separate state and socket directories can intentionally run another daemon;
operators must not point independent daemons at the same kiln backend.

## Reconciliation

At startup, after both ownership locks are held and the socket is reserved:

1. Validate installed CLI capabilities, load this backend's recorded IDs, and
   run `kiln ls`. If it fails, kilnd refuses to start rather
   than guess. EOF, capture bounds and every record are validated before the
   table is parsed.
2. Before any backend or durable reconciliation mutation, validate every
   listed live `READY`/`CREATING` sandbox and directly probe every managed
   backend omitted from the list. A reachable omitted backend proves the listing incomplete;
   an absent registry record is trusted only when its cgroup is also absent.
   Incompatibility, conflicting evidence or an inconclusive probe aborts startup
   without cleaning a backend or changing sandbox/execution rows.
3. Pass only listed stale IDs that occur in this backend's database rows to
   scoped garbage collection, then relist and revalidate. A stale unmanaged ID
   is reported and retained. If a requested stale ID remains, startup fails.
4. For each sandbox of this backend in the database, `READY`/`CREATING` with
   a live backend stays (or becomes)
   `READY`; with confirmed absence it becomes `LOST`; an exact backend that
   reappears for a `LOST` row and passes validation becomes `READY` again;
   `CREATING` without a backend ID becomes an ambiguous `FAILED`, since any
   typed result died with the daemon; `FAILED` is left as it is, keeping its
   certainty marker; `DELETING` is retried or completed.
5. Executions still `RUNNING` for this backend become `INTERRUPTED`. Other
   backends' rows are untouched. Daemon disconnect requests helper-owned Exec
   cancellation; helper death kills CLI clients through `PR_SET_PDEATHSIG` and
   its post-arm parent-PID check. Startup protocol/absence observations fail
   closed if a backend cannot validate while old cleanup is still in progress.

6. Live or stale kiln sandboxes kilnd doesn't know are logged as unmanaged and
   left alone across repeated startup reconciliation and daemon shutdown.

Running it again changes nothing.

## Concurrency

Both kilnd and its helper use tokio's current-thread runtime. The daemon
waits on IPC; the helper waits on child processes. Every privileged backend
launcher captures the helper PID before spawn, restores default HUP/INT/QUIT/TERM/PIPE dispositions,
arms `PR_SET_PDEATHSIG`, then rechecks the parent PID before exec. The recheck
closes the non-retroactive parent-death window; the current-thread runtime also
keeps the forking thread alive for the helper's lifetime. SQLite access goes
through one mutex-guarded connection, and each statement is short. Sandbox
count, memory, PID and disk reservation checks plus the `CREATING` insert share
one `IMMEDIATE` transaction, so concurrent creates and external SQLite writers
cannot split admission from durable ownership.

Each sandbox has a stable slot holding an async exec lock, an outstanding
request semaphore (one running plus the configured queue capacity), and the
running execution's cancellation handle. The registry stores weak references:
a live slot is never replaced under queued requests, while dead entries are
pruned on later slot access so create/delete churn does not grow memory. Client
disconnect, delete, and shutdown all record a first-wins reason through that
handle before canceling its private token.
For a row that may still own a backend, Delete marks the sandbox `DELETING`,
cancels the running execution, waits for the supervisor to finish and release
the lock, reloads the row, then runs `kiln rm`. Compensated `FAILED` history
moves atomically to `DELETED` without a backend call. The caller holds a strong
reference to the stable slot before it publishes delete intent, so queued
deletes cannot acquire replacement locks. Only one caller invokes the backend;
followers observe `DELETED` under the lock and return the existing row without
changing its timestamps. Delete
intent, completion and failure writes compare the expected state in the same
SQLite statement, preventing a stale result from overwriting a newer terminal
state. An interrupted or failed removal remains `DELETING`; a later call
retries, and backend `NotFound` completes the row. Executions waiting behind
the lock see `DELETING` and refuse.

Accepted create and exec operations live in a task tracker owned by the
manager. The RPC awaits a one-shot result but does not own the task.
Validation, capacity admission and registration happen synchronously before
the public method's first await on the current-thread runtime, so shutdown
cannot interleave between the serving check and tracker spawn. Backend work is
isolated so a panic becomes a persisted failure instead of dropping operation
state.

Admission uses only immediate semaphore acquisition, with no global wait
queue. Before an Exec supervisor is spawned it acquires global Exec,
per-sandbox outstanding and aggregate stdin permits. Its ticket owns them
through backend cleanup and successful terminal publication, even after the
RPC disappears. Queued disconnect, shutdown or deadline expiry releases the
ticket without inserting a row. Admission does not promise arrival order
before the sandbox lock wait.

Each accepted Unix stream owns a connection permit until the transport drops
the stream. Accepting at capacity drops that socket immediately; at most one
transient accepted descriptor exists beyond the cap. Only admitted peers are
logged. Transport rejection is a close, with no guaranteed gRPC status.
HTTP/2 has bounded streams, fixed 64 KiB stream / 256 KiB connection windows,
16 KiB headers and frames, and disabled adaptive windows. Per-connection
concurrency is limited with load shedding. Generated services cap decoded
requests and encoded responses. After decoding, every handler immediately
acquires an ordinary RPC or reserved Health RPC permit and holds it through
manager waiting and response construction. Thus decoding precedes service
admission; connection, stream and message caps bound that concurrent work.
Response transport backpressure can still occupy bounded connection/stream
slots after the handler returns.

Health coalesces uncached callers into one tracked, daemon-owned version
probe. A separate Tokio task isolates backend panics. Timeout signals
cancellation to that task, and the runtime explicitly kills and waits for its
child before singleflight ownership is released. Shutdown uses the same path.
A deadline publishes a failure to waiting Health callers while tracked cleanup
continues. No replacement probe starts until cleanup finishes, and callers
continue receiving that failure even after its normal cache TTL. Completion
caches a cloned success or error using a monotonic timestamp;
success and failure TTLs differ. Caller cancellation cannot cancel the probe.
Shutdown starts no probe and reports cached details when available.
Finalization-write degradation is recomputed on every call, including cache
hits. `HealthResponse.admission` reports configured maxima, current permits
in use, and cumulative rejections for connections, ordinary RPCs, Health RPCs,
global Exec admissions and retained stdin bytes.
Per-sandbox queue capacity and its cumulative rejection count are reported
separately from global Exec rejections.

## Bounded history reads

Schema v2 adds immutable positive `list_seq` values, a unique descending index,
and a partial descending index excluding deleted sandboxes. The transactional
v1 migration assigns sequences preserving its exact timestamp/ID ordering;
new inserts allocate the next sequence in their INSERT under the connection
mutex. Newer schemas are refused. Full internal lists for reconciliation also
use this order.

Schema v3 adds nullable command termination kind/value/core and bounded JSON
runtime diagnostics. Persistence caps messages at 2048 UTF-8 bytes and native
codes at 128 UTF-8 bytes, annotating native-code truncation in the message and
truncation flag. Oversized backend values cannot wedge terminal publication.
Terminal status, diagnostic, output, totals and timestamps
publish in the same UPDATE and remain owned across publication retries.
Full and metadata-only reads include typed evidence.

Schema v4 adds one certainty bit per output stream. `total_bytes_known=true`
means capture reached EOF, so `total_bytes` is exact; false means the count is
only an observed lower bound. `truncated` independently records that observed
bytes exceeded retained bytes. v1/v2/v3 opens migrate through v4, preserving
historical typed evidence but leaving historical output totals unknown rather
than asserting exactness.

Schema v5 adds `sandboxes.create_certainty`. Every historical row migrates as
`allocation_ambiguous`, whatever its failure text says, so failures recorded
before an upgrade stay charged. Every older version migrates through v5, and
older binaries refuse schema 5. Migration happens at store open and may precede
startup capability failure; back up before upgrading.

Schema v7 adds immutable `sandboxes.owner_uid` and an `(owner_uid, list_seq DESC)`
index. Every older version migrates through v7 in one transaction, and historical
rows belong to root rather than whoever runs the upgrade. The accept path reads
`peer_cred()` once and attaches the uid to every request on the connection. The
service authorizes before the manager's backend and admission paths, and
GetExecution reads only `executions.sandbox_id` until the parent sandbox passes.
Non-root List filters in SQLite, so the watermark, LIMIT and `has_more` never see
other owners. The canonical `v2:<deleted>:<uid>:<upper>:<last>` page token has
fixed-width fields, keeping the byte-bound accounting exact. Internal
reconciliation still reads every row.

The API represents signal numbers as `uint32` and retains legacy `exit_code`
only for EXITED, projecting signal termination as 128 + signal.
`command_status` distinguishes that signal from
an explicit exit with the same number. FAILED carries a runtime diagnostic;
TIMED_OUT and CANCELED retain any observed termination without an exit code.
`failure_reason` remains a human projection. Runtime stage `None` is preserved
as JSON `none` and protobuf `RUNTIME_STAGE_UNSPECIFIED`. `kilndctl exec` and
`kilndctl execution` write captured bytes first, then print signal, diagnostic,
total-certainty and truncation details separately on stderr. Exec shell codes
keep the legacy EXITED projection, 124 for timeout and 125 for other failures.

List pages capture the maximum matching sequence on the first page, fetch at
most `limit + 1` rows, and continue strictly below the last returned sequence.
Later inserts are excluded; updates do not move rows. This watermark is not a
snapshot of metadata or deletion state across pages. Tokens are bounded plaintext cursors, not opaque. They encode the version,
deleted filter, caller uid, global upper sequence and last sequence. The server
validates canonical ASCII and positive, ordered cursor ranges and binds the
cursor to the caller uid and filter. Clients should return the token unchanged.
Global sequence gaps can reveal counts of other callers' sandbox inserts over
an interval, though foreign IDs, specs and output stay hidden. Tokens are not
authenticated or encrypted and do not provide a confidentiality boundary.

Absent `page_size` with an empty token preserves complete-list semantics.
Legacy calls exceeding the item or byte bounds fail `RESOURCE_EXHAUSTED`
and instruct pagination, never silently truncate. Present zero uses
`min(100, max_list_page_size)`; oversized requested counts are
`INVALID_ARGUMENT`. Pages stop before the byte limit, including the final
continuation token in encoded-size accounting; one item that cannot fit fails
explicitly. `kilndctl ls` requests the server's bounded default and prints one
header, then pages incrementally. GetSandbox selects recent execution metadata
using empty BLOB literals for output while selecting persisted totals,
certainty and truncation flags. Its worst case is 100 rows whose retained output
could otherwise total 200 MiB; an isolated Linux child regression keeps the
metadata result alive and enforces an RSS increase below 32 MiB.

## Status policy

| Condition | Result |
|-----------|--------|
| Full service RPC, Exec or retained-stdin admission budget | `RESOURCE_EXHAUSTED` |
| Full raw connection budget | Transport close; no guaranteed gRPC status |
| Generated codec request/response message cap | tonic `OUT_OF_RANGE` |
| Queued Exec deadline expiry, before a row exists | `DEADLINE_EXCEEDED` |
| Execution deadline after insertion | Successful `TIMED_OUT` execution after cleanup |
| Malformed token, filter mismatch or oversized page size | `INVALID_ARGUMENT` |
| List exceeds legacy bounds or one item cannot fit | `RESOURCE_EXHAUSTED` |
| New create/Exec during shutdown | `UNAVAILABLE` |

## Shutdown and restarts

On SIGTERM or SIGINT, kilnd refuses new creates and execs and stops accepting
connections. A fixed `--shutdown-grace-secs` deadline starts immediately and
does not disappear if the transport exits early. At the deadline kilnd
cancels running executions (recorded as `CANCELED`); after a fixed 10-second
reply deadline it stops waiting for transport replies but continues draining
accepted create, compensation, and execution supervisors before removing the
socket and exiting. Thus the reply deadline does not bound owned cleanup.
Sandboxes keep running. Forced termination can still interrupt an operation;
startup reconciliation handles the state it can identify. After all accepted
operations drain, kilnd conditionally removes only its own socket generation and
then releases the socket- and state-directory locks. A crash releases the
kernel locks but can leave a stale socket for the next instance to probe.

The API daemon uses `KillMode=process` to preserve legacy shims started by
pre-helper root daemons; fresh deployments have no daemon child CLI processes.
The root helper uses `KillMode=process` because kiln's detached shims live in
its service cgroup and must survive helper restarts. systemd may report those
leftover shims. Both units have NoNewPrivileges and ProtectSystem=strict; the
daemon has an empty capability set and the helper has only kiln's required
namespace, mount, quota, network, ownership and cleanup capabilities.

## Limits and defaults

| Setting | Default | Flag |
|---------|---------|------|
| Socket | `/run/kilnd/kilnd.sock`, group `kilnd` | `--socket`, `--socket-group` |
| State | `/var/lib/kilnd/kilnd.db`, owner `kilnd`, directory 0700 / files 0600 | `--state-dir` |
| Root helper | `/run/kilnd-helper/helper.sock` | `--helper-socket` |
| Terminal execution history | 7 days / 10,000 rows | `--execution-max-age-secs`, `--execution-max-count` |
| Deleted / uncharged failed sandbox history | 7 days / 1,000 rows | `--deleted-sandbox-max-age-secs`, `--deleted-sandbox-max-count` |
| History prune interval | 60 s, plus startup | `--prune-interval-secs` |
| Durable output mode | `full`; `metadata` recommended; `none` drops evidence too | `--output-storage` |
| Exec timeout | 60 s, max 1 h | `--default-timeout-secs`, `--max-timeout-secs` |
| Output kept per stream | 1 MiB | `--max-output-bytes` |
| Retained sandbox reservations | 32 | `--max-sandboxes` |
| Reserved sandbox memory | 3 GiB | `--max-node-memory-bytes` |
| Reserved sandbox PIDs | 2,048 | `--max-node-pids` |
| Reserved sandbox disk | 16 GiB | `--max-node-disk-bytes` |
| Reserved host CPU, vCPU slots, host PIDs (not reserved by kiln) | 3000 millis, 3, 96 | `--max-node-host-cpu-millis`, `--max-node-virtual-cpu-slots`, `--max-node-host-pids` |
| stdin / argv per exec | 1 MiB / 256 KiB | (code) |
| argc per exec | 4096 | (code) |
| Admitted connections | 64 | `--max-connections` |
| Ordinary RPC / Health handlers | 64 / 4 | `--max-concurrent-rpcs`, `--max-concurrent-health` |
| Global Exec admissions | 32 | `--max-concurrent-execs` |
| Queued Exec per sandbox | 8, plus one running | `--max-queued-execs-per-sandbox` |
| Aggregate admitted Exec stdin | 16 MiB | `--max-queued-exec-stdin-bytes` |
| Streams per connection | 8 | `--max-streams-per-connection` |
| Request / response message | 2 MiB / 4 MiB | `--max-request-bytes`, `--max-response-bytes` |
| Maximum List page / response | 200 items / 1 MiB | `--max-list-page-size`, `--max-list-response-bytes` |
| Health probe timeout | 2 s | `--health-probe-timeout-secs` |
| Health success / failure cache | 5 s / 1 s | `--health-success-cache-secs`, `--health-failure-cache-secs` |
| Sandbox defaults | alpine, 512 MiB, 1 CPU, 128 pids, 1 GiB disk, no network | (code) |
| Sandbox maxima | 8 GiB, 8 CPUs, 4096 pids, 32 GiB disk | (code) |

Startup validates limits before opening state or binding: required counts,
bytes and times are nonzero (the per-sandbox queue may be zero), semaphore and
stream conversions fit, the default timeout is at most the maximum and maximum
milliseconds fit `u32`. Checked arithmetic enforces request capacity at least
stdin + argv + 64 KiB and response capacity at least twice retained output +
maximum argv + 64 KiB. List bytes cannot exceed response bytes, and pages are
at most 1000. Each node budget must hold at least one default sandbox.
These are finite capacity bounds, not a hard-real-time guarantee: synchronous
SQLite/filesystem work may block, slow clients may deny availability until
disconnected, and authorized callers can monopolize capacity without tenant
fairness or isolation. Terminal history has age/count retention. Pruning never removes a charged or
nonterminal sandbox, or an unfinished execution; deleting sandbox history
removes only terminal children. Zero age/count expires all eligible rows.
Freed pages are reused, not securely erased. Schema 6 adds a durable listing
sequence counter so pruning cannot make new inserts reuse an old page watermark.
Metadata output storage retains original counts/certainty/truncation facts,
while none drops output evidence; the immediate Exec response still returns
captured output. Policies affect future writes and do not scrub past history.

## Dependencies

tokio, tonic and prost (gRPC), rusqlite with bundled SQLite, clap, serde and
serde_json (spec and argv columns), tracing, thiserror, anyhow and libc.
Building needs `protoc`.
