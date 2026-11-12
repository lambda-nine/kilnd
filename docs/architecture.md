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
That is the minimum revision for everything but exec options. Privileged verification
uses the tested companions, which setup pins: kiln
`00d61c546db7aa67ad283d10c2ca6165ca5f8166` for everything else, and kiln
`5cada841edd0bbe112550816fad221dfb1db6a47`, the first with exec options (capability
bit `0x20`), for exec cwd and env (see [Exec cwd and env](#exec-cwd-and-env)).
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
end only in a matching fence or a charged ambiguous failure: the helper's READY (B5) is not
yet wired into the manager, which is B6's work. `main.rs` still selects kiln only, and B7
alone may change that. The helper's side is the [root node ledger](#firecracker-node-authority).

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

B5 adds the guest broker and the host half of its protocol
([design](design/phase1b-firecracker.md#b5-implementation-notes-november-3-2026)). The
`kilnd-guest-broker` crate is baked into the kiln-guest image at a pinned kilnd commit and
binary digest; `/init` starts it as guest root and powers the VM off if it dies. It listens
on vsock port 5252 for the host only, keeps one persistent kiln sandbox per VM and runs each
execution through the shared `kilnd-exec-core`. On the host, S forks two fork-only workers
after BOOTING: the relay R, in the allocation's `relay` cgroup leaf under the allocation's
relay UID/GID with no capabilities, does every byte of guest-facing parsing over vsock
connections S opens and checks against the journaled VMM; the console drainer D, in
`vm/console` under the VMM's credentials, drains and meters the serial console. S journals
READY only after the broker's Hello matches the journaled identity and Initialize created and
smoke-tested the inner sandbox. The helper's `validate` and `exec` operations then run on
that sandbox; EXEC_INTENT is durable before any byte is sent, and any interruption after
dispatch stops the VM through the existing barrier. Production still serves no profile.

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

Expiry adds no state: an idle or lifetime deadline passing on a `READY`, `LOST` or
`QUARANTINED` row is a second caller of the same `DELETING` path, with
`deletion_reason` `expired_idle` or `expired_lifetime` instead of `requested` (see
[Sandbox expiry](#sandbox-expiry)).

Executions: `RUNNING` → `EXITED` (with exit code) | `TIMED_OUT` | `CANCELED`
(caller disconnected, sandbox deleted, daemon shutdown or the sandbox's max lifetime,
recorded as `cancel_reason`) | `FAILED` (backend error) | `INTERRUPTED` (found running
at startup).

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

## API discovery and typed reasons

`Health.runtime_capabilities.features` lists what this daemon supports, and
`limits` (`ApiLimits`) every cap, minimum and default from the API additions design a
client could hit; a feature that is not listed has zero limits. Features come in
two sets. The static set is fixed by the code and flags: `SANDBOX_EXPIRY`,
`IDEMPOTENT_CREATE`, `TYPED_REASONS` and `REQUEST_ID_RELEASE` today. The dynamic set is what the backend proves in the shared
Health probe (`Runtime::proven_features`): it is empty at startup, replaced by each
successful probe and cleared by any failed or timed-out one, so it fails closed. The
kiln backend proves `EXEC_CWD`, `EXEC_ENV` and `SANDBOX_DEFAULT_ENV` together when the
helper's `features` probe finds the installed CLI's bit `0x20` and a host whose memfds
kiln accepts, and `EXEC_STREAM` when the helper reports it can carry live output
(`exec_stream` in the same probe; Linux only); Firecracker proves none. The create-time and
Exec-time gates read the same set Health publishes, so Health never lists an option
the daemon would refuse. An older
daemon lists no features and ignores unknown request fields, so a client sets a
field only when its feature is listed in a `SERVING` response, and re-reads the
list after every reconnect. `kilndctl` does this itself: `create` with an expiry
option and `renew` first read Health and refuse, sending nothing, unless it is
`SERVING` and lists `SANDBOX_EXPIRY`; `create --request-id` and
`rm --release-request-id` do the same for `IDEMPOTENT_CREATE` and
`REQUEST_ID_RELEASE`; a plain `create` sends no Health request.

Refusals defined by the additions, and the existing "is X, not ready" refusals of
Exec and RenewSandbox, carry a `kilnd-reason: <token>` metadata entry, and their
status message starts with the same token and `": "`. The gRPC code is unchanged
and so is the rest of the message. The tokens are `sandbox_not_ready` (CREATING),
`sandbox_failed`, `sandbox_lost`, `sandbox_quarantined`, and for a `DELETING` or
retained `DELETED` row its deletion reason: `expired_idle`, `expired_lifetime` or
`sandbox_deleted` (requested, or history from before schema 11). A never-existing,
foreign or pruned ID stays `NOT_FOUND` with no trailer, so "expired" and "never
existed" stay distinguishable while the row is retained. Idempotent create adds
`request_id_conflict` (`ALREADY_EXISTS`), `request_id_quota` (`RESOURCE_EXHAUSTED`),
`create_in_flight` (`DEADLINE_EXCEEDED`) and `create_unsettled` (`UNAVAILABLE`). Exec
cwd and env add `backend_unsupported:<feature>` (`UNIMPLEMENTED`: `exec_cwd`,
`exec_env`, `sandbox_default_env`) and `sandbox_unsupported:<feature>`
(`FAILED_PRECONDITION`: `exec_cwd`, `exec_env`), and `sandbox_feature_probe_failed`
(`UNAVAILABLE`, retryable) for a create with a default env whose new sandbox did not
prove exec options. A `grpc-timeout` header kilnd's parser rejects (anything but 1 to
8 ASCII digits and one of `H M S m u n`; tonic's own parser also takes a leading `+`)
is `INVALID_ARGUMENT invalid_grpc_timeout` before dispatch, on every RPC.
`execution_start_raced`
(`FAILED_PRECONDITION`, like `sandbox_not_ready`) means the conditional execution
insert saw the sandbox leave `READY` and a reload found it `READY` again: nothing ran,
retry. ExecStream adds `backend_unsupported:exec_stream` (`UNIMPLEMENTED`) and
`exec_stream_limit` (`RESOURCE_EXHAUSTED`).

## Sandbox expiry

`CreateSandboxRequest.expiry` (`max_lifetime_ms`, `idle_timeout_ms`) resolves once,
at create, into an effective policy stored with the row and never changed. An
absent message never expires, whatever the node is configured with, so a client
that predates expiry cannot be expired. In a present message a nonzero field is
used as given, within 10 s and the node maximum (`--max-sandbox-lifetime-secs`,
`--max-sandbox-idle-secs`; 0 is no cap), and never above `i64::MAX` ms, which the
signed schema columns can store even on a node with no cap, else `INVALID_ARGUMENT`
before anything is prepared; a zero field takes the node default for that field
(`--default-sandbox-lifetime-secs`, `--default-sandbox-idle-secs`, shipped as 0,
never).

Lifetime counts from the first `READY` publication and ignores activity. Idle counts
from the later of `READY` and the last activity, which is exactly an execution row's
insert, its terminal publication and a successful `RenewSandbox`. Get, List,
GetExecution, Health and Delete never count. While an execution runs or an admitted
Exec is queued (the slot's outstanding permits are not all free) idle is paused and
`ExpiryStatus.idle_paused` is true; the finish that releases the last permit restarts
it. Startup's terminal publications (an interrupted legacy execution, a fenced one
concluded across a crash) are finish activity too, in the same transaction. They run
before the cross-boot rebase, so a row still anchored in another boot gets only its
wall activity anchor and keeps that boot's boottime and ID; the rebase then derives
this boot's anchor from it, and neither anchor is stranded in a boot the other left. Nothing runs before `READY`. Deadlines run in `READY`, `LOST` and `QUARANTINED`,
because those rows still hold reservations; a legacy row without a backend ID is an
ambiguous reservation Delete refuses, so expiry never targets it. Renew is accepted
only in `READY`, and within a second of the last durable activity it writes nothing.

**Clocks.** Every decision within one boot reads `CLOCK_BOOTTIME`, which counts
suspend and never steps with the wall clock. The row stores the boottime and wall
time of `READY` and of the last activity with the kernel `boot_id` both boottime
anchors belong to. A deadline is `anchor + limit` in boottime, so it survives a
daemon restart exactly and ignores NTP and administrator steps. After startup
reconciliation and before the prune, the sweeper and serving, one `IMMEDIATE`
transaction rebases every row anchored in another boot: for each anchor it
subtracts `min(limit, max(0, now_wall - anchor_wall))` from current boottime and
writes the current boot ID with both anchors, and moves a pending expiry delete's
intent anchor by its whole wall age. That one wall read is unavoidable
across a reboot and harmless, since neither backend survives one: such a sandbox is
`LOST`, and a skewed estimate frees a dead reservation sooner or later. The API's
`*_unix_ms` fields are wall projections computed at read time and move if the wall
clock steps. For `--expiry-restart-grace-secs` (60) after startup no idle deadline
falls, so a client reconnecting after an upgrade can renew; lifetime has no grace.

**The sweeper** is one task owning an indexed timer queue: a hash map from sandbox
to its single next-action time, mirrored by an ordered set. The next action is the
earliest of the lifetime deadline, the idle deadline (absent while paused) and a
pending removal retry. Every activity, pause, resume, Renew and retry replaces that
sandbox's one entry in place, so the queue holds no stale entries and cannot grow
with churn. An entry exists only for a row with a policy in `READY`, `LOST` or
`QUARANTINED`, or in `DELETING` awaiting an expiry retry, and every such row holds a
durable reservation: the queue's length is at most the number of durable
reservations. Admission holds those at `--max-sandboxes`, except that reservations
made under a higher earlier cap remain after a restart with a lower one until they
drain, so the exact bound is `max(--max-sandboxes, reservations at startup)`, at
most 96 bytes an entry. Startup rebuilds it from a partial index. Its one timer
sleeps until the head or `--expiry-rescan-secs` (30), whichever is sooner; the
rescan recomputes from boottime, so a resume from suspend, when tokio's monotonic
timers stalled, is caught within one interval.

Two expiry paths share Delete's machinery:

- **Idle** `try_lock`s the slot's exec lock; if an execution holds it, the sandbox
  is not idle and the finish re-arms it. Holding the guard and the slot's admission
  gate, it requires every outstanding permit free, rereads the row and commits a
  compare-and-set that publishes `DELETING(expired_idle)` only if the state is live,
  `activity_seq` is unchanged and no reason is set. It drops both before running the
  ordinary delete, which retakes the lock with nothing to wait for. Exec rechecks
  `READY` and takes its outstanding permit under the same gate, so either the Exec is
  admitted first and expiry re-arms, or the CAS commits first and the Exec is refused
  `expired_idle` without ever holding a permit. A Renew bumps `activity_seq` in one
  `UPDATE ... WHERE state = 'ready'`, so whichever commits first wins.
- **Lifetime** takes no lock: it publishes `DELETING(expired_lifetime)` with the same
  first-wins write on `deletion_reason IS NULL`, requests cancellation of the running
  execution with `SANDBOX_EXPIRED_LIFETIME`, then joins the ordinary serialized
  teardown. The canceled execution ends `CANCELED` with that `cancel_reason`; a
  completed outcome already observed still wins; queued requests are refused
  `expired_lifetime`.

An execution's cancellation handle is published before its row, and the row is
inserted only while the sandbox is still `READY`, in one transaction with the start
activity. So a lifetime expiry or Delete whose intent commits first makes the insert
refuse, and one that commits after always finds the execution to cancel.
`deletion_reason` is written with the delete intent, only while null, and never
changes; a user Delete records `requested`, and a Delete of an expired row succeeds
as a follower and shows its expiry. At most `--max-concurrent-expiry-deletes` (4)
removals of expiry-owned rows run at once, and they use no client RPC permit; every
intent publishes at once, so a mass expiry refuses new work immediately while the
backend sees a bounded number of removals. A removal task exists only while it holds
one of those permits: a due delete that finds none free waits as a flag on its
pending entry, with no task and no queue entry, bounded by reservations like the
queue, and each returned permit starts the earliest waiting one. A client Delete of
an expiry-owned `DELETING` row is that removal's follower: it waits for an expiry
permit before the exec lock, and runs the attempt itself only when no expiry attempt
is running (otherwise the lock orders it behind that attempt, which it then
observes). So the limit holds across expiry and client Delete together, and a Delete
that finishes a row leaves nothing waiting behind it; a canceled follower returns
its permit and hands the attempt back to expiry. A Delete of a row whose first reason
is `requested` is an ordinary client removal, bounded by RPC admission, and never
takes an expiry permit. A failed removal leaves the row `DELETING` and charged,
retried with backoff from 5 s to 5 min; `HealthResponse.lifecycle` reports expiries,
pending and failed expiry deletes, and one pending longer than
`--expiry-degraded-after-secs` (600) makes Health `DEGRADED`. That age counts from
the intent, whose boottime is stored with it (schema 11's
`expiry_intent_boottime_ms`, rebased with the other anchors), so a restart never
grants a stale delete a fresh window. A crash after an intent commits is completed at
startup like any `DELETING` row, keeping its reason. At shutdown the sweeper stops
scheduling; removals already running are tracked operations and drain, and waiting
ones are completed at the next startup.

An expired sandbox leaves the default listing (`ListSandboxes` with
`include_deleted = false`) only once its removal completes, not at the moment it
expires: it first passes through `DELETING`, which that listing still shows, and
disappears from it on reaching `DELETED`. A client that checks absence by listing
waits for that, as it would after its own Delete.

## Idempotent create

`CreateSandboxRequest.request_id` makes a create retryable. Empty is today's create,
which is never idempotent. Otherwise it is 1 to 64 bytes, each printable ASCII
without space (`0x21`-`0x7e`), scoped to the caller's kernel uid (root's are root's
own), and echoed as `Sandbox.request_id`, which history keeps.

**The request digest** is SHA-256 over `kilnd.v1.create-request.1`, one zero byte and
the canonical JSON of the request *as sent*, before any default: an object with
exactly `default_env` (`[name, value]` pairs sorted by name bytes, then value bytes;
`[]` when none was sent, so digests from before default env are unchanged), `expiry`
(`null` when absent, else both fields, so absent and present-with-zeros differ) and
`spec` (every field, labels as an object, the network mode as its enum number), with
`request_id` left out. It uses the same canonical JSON contract and encoder as the spec
digests (sorted keys, fixed escapes, integers only). Hashing the request rather than
the effective spec keeps a retry matching after an operator changes a node default.
Proto3 cannot tell an unset scalar or message from its zero value, so neither can
the digest. `crates/kilnd/tests/data/create-request-digests.json` holds the golden
cases clients test their own digest code against.

**Order of checks** (`Manager::create_keyed`). The in-flight map, keyed by
`(owner_uid, request_id)`, holds each registered create's digest and a watch that
closes when its operation has fully finished: `READY` published, or `FAILED`
published *and* its fence or compensation done (Firecracker publishes `FAILED`
before the fence). Steps 2 to 5 run under one mutex with no await between them.

1. The RPC permit, the `request_id` grammar (`INVALID_ARGUMENT`) and the digest.
2. An in-flight entry: an unequal digest is `ALREADY_EXISTS request_id_conflict`
   at once; an equal one waits on the watch within the caller's own gRPC deadline
   (its `grpc-timeout`, less 5 % and at most 250 ms so the typed answer arrives
   first), else `DEADLINE_EXCEEDED create_in_flight`, then looks again. The deadline
   runs from when the request's headers reached the server, stamped by an interceptor
   before any body is read: tonic starts its own `grpc-timeout` clock there, so a body
   that arrives late cannot push the typed answer past tonic's untyped `CANCELLED`. A waiter
   holds only a watch subscription; a canceled RPC drops it and leaves nothing.
3. A stored record, read with its row in one snapshot: an unequal digest is
   `ALREADY_EXISTS`; an equal one returns the row in its state, `FAILED` and `DELETED`
   included. A `CREATING` row here has no live operation (only a failed store write
   mid-create leaves one, which the next start's reconciliation settles) and is
   `UNAVAILABLE create_unsettled`, never a fresh create. Steps 2 and 3 are answered
   during shutdown too.
4. Validation of the converted request (`INVALID_ARGUMENT`), the serving check, and
   the pending quota: durable records plus keyed creates holding a pending slot must
   be below both caps, else `RESOURCE_EXHAUSTED request_id_quota`. The slot is an
   RAII guard returned on every exit, cancellation included, once the admitting
   transaction has run. It bounds concurrent keyed creates and reserves no ID.
5. Registration in the in-flight map.
6. `prepare`, then the existing `IMMEDIATE` admission transaction, which also
   recounts the durable per-uid and node records (refusing `request_id_quota` at a
   cap), refuses a key another create already recorded, and inserts the record with
   the `CREATING` row: both commit or neither does. The record commits unanchored and
   a second transaction anchors it (below). The counts are two primary-key reads of
   `create_request_counts`, which triggers on `create_requests` keep.

Lookup precedes validation, so a retry finds an accepted request even if a node
limit changed since. A refusal before step 6 commits leaves no record, so a retry is a
fresh attempt. On Firecracker a retry never reaches `prepare` and takes no helper
token. If two attempts ever reached the transaction together, the loser would drop
its plan, which allocated nothing, and answer from step 2.

**The same answer.** Once a keyed create's row commits, the original call and every
retry return `OK` with the settled row: `READY`, or `FAILED` with its
`failure_reason` (an unkeyed create still turns a failure after the commit into an
RPC error, as before). The ID is reserved in the commit that inserts `CREATING`, so a
crash before it leaves neither and a retry creates normally. After it the result
depends on the backend. Firecracker binds the allocation to the request, so
reconciliation finds the VM (`READY`) or proves it absent through the helper ledger
(a released `FAILED`); a retry returns that row and Delete works. **Legacy kiln**
ignores the create context, so a row that crashed before its backend ID was
published has no recoverable identity: reconciliation makes it an ambiguous
`FAILED`, still charged, which Delete refuses, as for any unkeyed create, and every
retry returns it. Deleting it would release nothing; the charge stays until an
operator reconciles the backend. A client may move on with a new request ID, which
keeps kilnd's accounting right (the charge stays counted) but may leave an orphaned
kiln sandbox, so it should report the case rather than retry silently. A
request-bound kiln identity is later work. A crash during compensation leaves
`DELETING`, completed at startup.

**Records and retention (schema 12).** `create_requests` holds `owner_uid`,
`request_id`, `request_sha256`, `sandbox_id` (unique, referencing its row),
`created_at_ms` (display only), `retain_boot_id` and `retain_from_boottime_ms`, with
the primary key `(owner_uid, request_id)`. Triggers refuse a replace on either key, a
record for anything but its own new `CREATING` row, any update except the cross-boot
rebase of the two retention columns, deleting a record whose row is not `DELETED` or
released `FAILED`, and deleting a row its record pins, even on a connection with
foreign keys off. `sandboxes` gains `request_id` (fixed at insert) and
`request_id_released_at_ms` (written once, from `DELETED`, after the record is gone).
With R = `--create-request-retention-secs` (at least a day):

- A record commits unanchored (both retention columns null; a trigger refuses an
  insert with an anchor) and no prune can select it. Its anchor, this boot's ID and
  `CLOCK_BOOTTIME`, is written by a second `IMMEDIATE` transaction that reads the
  clocks only once it holds the write lock, after the inserting commit. So no pause
  before that commit (suspend, `SIGSTOP`, a stall, a VM pause) is counted against the
  window, which starts no earlier than the commit (the M2 break-it HIGH 1). If
  that transaction fails or the daemon dies first, the record stays unanchored and
  unprunable until the next prune anchors it from a reading under its own write lock,
  or the startup rebase does: later, never earlier. An anchor is never removed.
- After reconciliation and before admission, any prune or any keyed lookup, one
  `IMMEDIATE` transaction gives every record anchored in another boot, or unanchored,
  the current boot and boottime, read inside it: a fresh, full window, never a
  wall-clock estimate.
- Prune deletes a record only if it is anchored in this boot, its row is `DELETED`
  or released `FAILED`, and R + ⌈R/1000⌉ of boottime has passed. Boottime never steps,
  counts suspend and runs within NTP's 500 ppm slew, so that takes more than R of real
  time; a record from another boot cannot be selected until the rebase, which happens
  later than its create. No step reads the wall clock, so no wall step can shorten or
  stretch retention, and count caps never prune a record.
- A row with a record is outside the ordinary age and count prune; it can go only
  after its record. Release and prune are the only deletes, through one store
  function that rechecks the row in its own `IMMEDIATE` transaction.

**Bounded integrity checks (schema 12).** Schemas 10 and 11 kept one SHA-256 over
every sandbox row's immutable membership, and every accounting decision recomputed
it, so with retained request history (up to 32,768 pinned rows) admission and quota
fill were O(N) per create and could starve a node (the M2 break-it MEDIUM 2).
Schema 12 verifies that marker during the upgrade, then replaces it with
`reservation_membership`: the count and the sum modulo 2^256 of each row's own
SHA-256, for all rows and for the rows settled (uncharged) at the last full audit.
Inserting a row adds its hash; prune subtracts the rows it deletes. An `AFTER UPDATE`
trigger notes in `reservation_unsettled` every row that leaves the charged set, kilnd's
update or anyone's; it records only the ID, so it cannot vouch for a row. A partial
index, `sandboxes_charged`, finds charged rows without a scan.

- Every accounting decision (admission, keyed lookup, reads, release, Health) first
  reads SQLite's `PRAGMA data_version`. kilnd writes only through its one connection,
  so if no other connection has committed since this one last verified everything,
  all state since then is kilnd's own writing, and the decision hashes only the live
  rows (the charged ones and those unsettled since) and their release evidence, and
  requires settled + live = all. Otherwise (an operator's `sqlite3`, a restore, a
  writer past the triggers) it verifies everything, as every decision used to: every
  row against the stored total, the partition, the request counters against the
  records, and every fenced release's evidence. A row lost or released behind
  kilnd's back is therefore caught by the next decision. Read decisions commit their
  snapshot too, so the stamp of that verification and the quarantine it rebuilt
  (both in temporary tables) are kept: one external commit costs one full
  verification, not one per later lookup or refusal.
- Write decisions (admission, refusals included, an insert, a release) move the
  unsettled rows they have just verified into the settled aggregate. A released row is
  hashed only until the next write decision, so a decision's cost is bounded by the
  charged rows and the releases since the last write, never by retained history or
  the prune interval.
- The full audit, at startup (a mismatch refuses it) and at the start of every prune,
  verifies everything the same way, including the partition, so it never folds a
  bypassed release into settled history; then it re-derives the settled aggregate and
  clears the unsettled list. A mismatch fails the prune and latches the connection
  degraded, so admission, pruning and accounting reads refuse until a restart, which
  refuses too.
- Like the marker it replaces, the aggregate detects accidental or missing
  membership, not a writer with file authority who rewrites both, nor edits to the
  file that bypass SQLite (which `data_version` cannot see).

So within R a retry always finds its record and real row and never creates a second
sandbox. A live, `LOST` or charged row's record is kept however old.
`--max-create-requests-per-uid` (4,096) and `--max-create-requests` (32,768) bound the
records; `AdmissionStats` reports the node cap and count, the per-uid cap, the
caller's own count and quota refusals, `ApiLimits.create_request_retention_ms` is R,
and `HealthResponse.lifecycle` counts retries answered from a record and releases.

**Opt-in release.** `DeleteSandboxRequest.release_request_id` lets a client give up a
key it is done with, so records track live work rather than a day of history. Delete
runs exactly as without it. Only if the row it leaves is `DELETED` does one
`IMMEDIATE` transaction that sees it `DELETED` delete the record through the prune-safe
path and stamp `request_id_released_at_ms`, shown as `Sandbox.request_id_released`;
the row then follows ordinary retention and keeps its `request_id`. A row left
`DELETING` (a failed removal, or a follower that returned early) releases nothing and
nothing is remembered: the client repeats the call once absence is confirmed. No
record (never keyed, already released or pruned) is a no-op, and a row a prune already
removed is `NOT_FOUND`, which is absence. Owner or root only, like Delete.
**The contract:** a client sets it only while holding the create response for that
key, with no retry of that create pending or to come, and after confirming absence.
After release a create with the key makes a new sandbox; the client takes that
duplicate risk, because kilnd's retry protection for the key has ended. SQLite
orders a concurrent retry and the release: a retry that reads the record first
returns the `DELETED` row, one that reads after creates afresh.

## Exec cwd and env

`ExecRequest.cwd` and `ExecRequest.env`, and `CreateSandboxRequest.default_env` for
sandbox-wide defaults, are additive: with all three empty an Exec runs exactly as
before, through the same code and kiln's operation 4. kiln's half is its operation 5,
the `kiln exec --exec-options-fd` flag, stage 14 `Chdir` and capability bit `0x20`,
first in kiln `5cada841edd0bbe112550816fad221dfb1db6a47`; an older kiln keeps working
for everything else and simply proves no exec options.

**Validation**, in kilnd, again in the root helper at the code ceilings, and again in
kiln's CLI and PID 1; `INVALID_ARGUMENT` before anything is allocated. A cwd starts
with `/`, is at most `--max-exec-cwd-bytes` (4,096) and has no NUL; it is not
normalized, so `..` and symlinks resolve inside the sandbox's own root. An env list
has at most `--max-exec-env-entries` (64) entries; names match
`[A-Za-z_][A-Za-z0-9_]*` within `--max-exec-env-name-bytes` (128); values are UTF-8
without NUL within `--max-exec-env-value-bytes` (4,096); `len(name) + len(value) + 2`
totals at most `--max-exec-env-total-bytes` (32,768). A name given twice is refused,
not resolved. The same bounds hold for the request's env, the sandbox's default env
and their merge. Flags may lower each ceiling, never raise it.

**The merge.** kilnd overlays the sandbox's default env with the request's (the
request wins by name) and sends the effective overrides, sorted by name bytes, with
the cwd. kiln builds the command's environment from the fixed base every command gets
under kilnd (`HOME=/root`,
`PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, `TERM=xterm`)
overlaid by the overrides, so explicit entries win, `PATH` included, and drive the
program lookup; a relative program like `./fib.sh` resolves in the cwd. There is no
unset; an empty value is allowed.

**Through the privilege boundary.** The helper's kiln `exec` request gains `cwd` and
`env`, omitted when empty, so a request without options is byte-identical to before
(the B2 goldens pin it). The helper revalidates them in the one strict form kiln
accepts (env strictly ascending by name), writes kiln's options frame into a memfd
created `MFD_ALLOW_SEALING|MFD_CLOEXEC` (plus `MFD_EXEC` under `vm.memfd_noexec=1`),
seals it with exactly `F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE`, checks the
seals, and passes it to `kiln exec --protocol=1 ... --exec-options-fd=N` as its own
descriptor number. Nothing caller-derived reaches the root command line but the argv
after `--`, as before, so options never appear in `/proc/*/cmdline`. Under
`vm.memfd_noexec=2` every memfd carries `F_SEAL_EXEC`, which kiln refuses: the helper
proves no exec options there, and an Exec that still gets through fails
`exec_options_unavailable` with no child.

**Gates.** An option the backend has not proven is refused
`UNIMPLEMENTED backend_unsupported:<feature>`, the first in `Feature` order (cwd
before env), before its value is looked at and before any row, ticket, prepare call
or helper call; a create's default env is refused before `prepare`, so Firecracker's
token pointer does not move. At `READY` publication kilnd records the new sandbox's
exec feature bits, what its PID 1 advertises (the creating CLI's build), in
`sandboxes.exec_features`, once. An Exec that needs options (a cwd, env, or a sandbox
default env) on a sandbox without bit `0x20` there, or with none recorded (every row
from before schema 13), is refused `FAILED_PRECONDITION sandbox_unsupported:exec_cwd`
(or `exec_env`) before an execution row. A create with a default env is published
`READY` only if that probe recorded bit `0x20`: a failed probe or a missing bit removes
the backend (cleanup intent as `DELETING`, then `FAILED`, which releases the
reservation and clears the defaults; a failed removal stays `DELETING` and charged)
and the create is `UNAVAILABLE sandbox_feature_probe_failed`, retryable, with the
row's `failure_reason` starting with that token. A keyed create stores it like any
settled failure. The fenced path holds the same rule, though Firecracker proves no
options and refuses a default env before `prepare`. A sandbox with default env needs
`EXEC_ENV` for every Exec, so after an operator downgrade its commands are refused
rather than run without their defaults. The per-exec checks stay the authority: the
helper requires bit `0x20` from both the installed CLI and the sandbox's PID 1 before
starting the CLI, and the CLI probes PID 1 again; a downgrade that slips past the gate
is a `FAILED` execution with `INCOMPATIBLE`/`HANDSHAKE`, no child started and a
`failure_reason` starting `exec_options_unsupported`, never a run without the options.
The CLI's own probe has a two-second deadline; a PID 1 still busy with another control
connection fails it as `Protocol`/`Handshake`, which kilnd reports as
`UNAVAILABLE`/`HANDSHAKE`, `exec_options_unconfirmed`, no child started, retryable.

**A missing cwd** is a successful RPC whose execution is `FAILED`: `LAUNCH_FAILED`,
`RUNTIME_STAGE_CWD`, the errno name as `native_code` (`ENOENT`, `ENOTDIR`, `EACCES`,
`ELOOP`, `ENAMETOOLONG`), a `failure_reason` starting `cwd_not_found`,
`RUNTIME_DRAINED` and `sandbox_reusable`. Nothing falls back to `/`. A host-only path
such as `/var/lib/kilnd-helper` is `ENOENT` inside the sandbox.

**History keeps names and a hash, never values.** An execution records `cwd` as given
(a path, not a value), `env_names` (the effective overrides' names, sorted) and
`env_sha256`: lowercase hex SHA-256 of `kilnd.v1.exec-env.1`, a zero byte, then each
override sorted by name as `u32be len, name, u32be len, value`. A client recomputes it
to check that what ran is what it sent. It is an unkeyed integrity fingerprint, not
confidentiality: a low-entropy value can be guessed from it. Values are in no
execution row, response, helper reply or log line; the in-memory env type's `Debug`
redacts them, validation errors name entries by position, and a canary test checks
logs, every response and every logical database column.

**Sandbox defaults** are not in `SandboxSpec`, which Get and List echo and the spec
digests cover. Their names and hash are `Sandbox.default_env_names` and
`default_env_sha256` (the same encoding); the values are stored in
`sandboxes.default_env`, so executions after a restart still get them, and set to null
in the same statement that moves the row to `FAILED` or `DELETED`; a `CHECK` makes a
`FAILED` or `DELETED` row with values impossible. So the values are plaintext in
`kilnd.db` while the sandbox is live, by design. Clearing is logical: SQLite, its WAL
and free pages may keep the bytes until they are overwritten, as for output, and no
byte erasure is promised. The API's contract is that callers send no secrets.

**Store: schema 13.** `sandboxes` gains `default_env`, `default_env_names`,
`default_env_sha256` and `exec_features`; `executions` gains `cwd`, `env_names` and
`env_sha256`. Triggers fix the names, hashes and an execution's cwd at insert, record
`exec_features` once, allow default env values only on a `CREATING` insert and only
ever clear them. None of it is reservation membership. A schema 12 database migrates
in one transaction, its aggregates audited after.

**Admission.** Env bytes ride in the request that already holds a global Exec ticket,
so retained env memory is bounded by 32 tickets × 64 KiB (request plus default env),
2 MiB, with no new budget. `kilndctl exec --cwd DIR --env NAME[=VALUE]` and
`create --default-env NAME[=VALUE]` (a bare `NAME` passes kilndctl's own value, off
its command line) read Health first and refuse unless it lists the feature.

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
request semaphore (one running plus the configured queue capacity), an admission
gate (a short synchronous lock idle expiry and Exec admission share; see
[Sandbox expiry](#sandbox-expiry)), and the running execution's cancellation handle. The registry stores weak references:
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
the stream. The server reads the peer's credentials (`SO_PEERCRED`, one
`getsockopt` before any byte is read) and admits by UID (Phase 1b B7,
B6-BI-03): a general slot while the UID holds fewer than
`--max-connections-per-uid`, otherwise one of the `--reserved-connections`
slots held back for Health and cleanup (at most one per UID), otherwise, for
UID 0 only, one root slot beyond `--max-connections`, otherwise none. The
reserve is first-come and bounded per UID: colluding UIDs can hold all of it,
and the root slot keeps Health and cleanup reachable for the operator. A
connection on a reserved slot or the root slot serves only Health, GetSandbox
and DeleteSandbox; any other RPC on it is `RESOURCE_EXHAUSTED`. A connection that
has not delivered the 24-byte HTTP/2 client preface within
`--connection-preface-timeout-ms` fails its next read, so the transport closes
it and its slot returns; the deadline is polled with every read, so a socket
that sends nothing is woken for it. Accepting without a slot drops that socket
immediately; at most one transient accepted descriptor exists beyond the cap.
Only admitted peers are logged. Transport rejection is a close, with no
guaranteed gRPC status.
HTTP/2 has bounded streams, fixed 64 KiB stream / 256 KiB connection windows,
16 KiB headers and frames, and disabled adaptive windows. Per-connection
concurrency is limited with load shedding. Generated services cap decoded
requests and encoded responses. After decoding, every handler checks its
caller's UID and immediately acquires a reserved Health permit or an ordinary
RPC permit within the UID's `--max-concurrent-rpcs-per-uid` share, and holds
it through manager waiting and response construction. GetSandbox and
DeleteSandbox that the ordinary lane refuses take one of the
`--max-concurrent-cleanup` permits instead, at most one per UID; and UID 0's
Health, GetSandbox and DeleteSandbox that every lane refuses take its one root
permit. Thus decoding precedes service
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

Schema v11 adds the expiry policy (`expiry_lifetime_ms`, `expiry_idle_ms`, null for
never), the `READY` and last-activity anchors in wall time and boottime with their
`clock_boot_id`, `activity_seq`, `deletion_reason` and an expiry intent's wall and
boottime anchors (`expiry_intent_at_ms`, `expiry_intent_boottime_ms`) to `sandboxes`,
`cancel_reason` to `executions`, and a partial index on rows with a policy in a live
or `DELETING` state. Triggers keep the policy immutable, write `deletion_reason` once
and only with `DELETING` or `DELETED`, keep `activity_seq` increasing, move a `READY`
anchor or the intent's boottime anchor only together with its boot ID, write the
intent anchors only with an expiry reason and never on insert, and write
`cancel_reason` once. None of these columns enters the reservation digest or the
fenced identity triggers: they are lifecycle data, not reservation membership.
History migrates with nulls and sequence 0, which means never expires and reason
unknown. So the upgrade never rewrites a schema 10 membership marker before it
audits it: it audits the marker as it stands before any change, and a mismatch
refuses startup and rolls the whole migration back, leaving the database at schema 10
with its evidence intact. Only an upgrade from below 10 seeds a marker. Schema 12 then
replaces the verified marker with aggregates seeded from the same rows, and every
path runs the full audit before commit.

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
| Exec or RenewSandbox on a sandbox that is not `READY` | `FAILED_PRECONDITION` with a `kilnd-reason` trailer and token prefix |
| Expiry policy below 10 s or above the node maximum | `INVALID_ARGUMENT`, before anything is prepared |
| RenewSandbox on a foreign or unknown ID | `NOT_FOUND`, no trailer |

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

## ExecStream

`rpc ExecStream(ExecStreamRequest) returns (stream ExecStreamResponse)` is Exec with
live output. The request wraps an ordinary `ExecRequest` (argv, the same bounded
up-front stdin, cwd, env). Validation, feature gates, sandbox checks and admission run
in the same order as Exec, through the same function; every refusal before the
execution row is an RPC error with no message sent, and nothing was allocated. Once
the row exists the stream carries `ExecStarted` (`seq` 0, with the execution ID), then
`OutputChunk` and `OutputGap` messages, then exactly one `ExecFinished`. `seq` numbers
every message from 0 with no gaps: bytes may be lost, messages never are.

**Parity.** `ExecFinished.execution` is the stored row, read after terminal
publication by the same function GetExecution uses and converted by the same
function, so it equals GetExecution for that ID byte for byte, `mode` and both
retained outputs included. The row's `mode` (schema 14) is `stream`; a unary Exec's
is `unary`; rows from before it have none (`EXECUTION_MODE_UNSPECIFIED`).

**The live path never slows the command.**

- *Capture tap* (`kilnd-exec-core::live`). Each capture reader counts and retains a
  read first, then offers the same bytes, at the offset it observed, to an optional
  `LiveTap`. `offer` cannot fail, await or block; a panic inside it disables the tap
  for that reader instead of unwinding. The readers stay the only count authority: a
  tap that refuses or panics on every offer leaves the capture evidence byte-identical
  (a required test). The CLI's own diagnostics are never offered.
- *Helper live channel.* The helper's kiln `exec` request gains `live: bool` (omitted
  when false, so unary requests stay byte-identical). With it the descriptor envelope
  carries a fourth descriptor, kilnd's end of an anonymous `SOCK_SEQPACKET` pair. The
  helper's tap sends each read as one message `[stream u8][offset u64be][bytes]`, at
  most 16 KiB of data, with `MSG_DONTWAIT`, and drops it on `EAGAIN`; the message
  boundary makes a drop atomic, so offsets alone tell kilnd what is missing. The helper
  shuts the channel down after the execution settles and before its reply. The
  retained-prefix transfer after settlement is unchanged and stays authoritative.
  Darwin has no `SOCK_SEQPACKET` Unix sockets, so there the helper proves no live
  output.
- *kilnd's queue* (`exec_stream.rs`). The helper client reads the live socket into a
  per-execution queue bounded by `--exec-stream-buffer-bytes` (256 KiB). The bound
  counts what is allocated, not what is used: each entry's payload capacity, 64 bytes
  of overhead per entry (so one-byte writes cannot exceed it) and every deque slot.
  Coalescing grows an entry's payload geometrically up to one chunk and charges the
  new capacity, or exactly when only that fits. An offer that does not fit is dropped
  whole; contiguous bytes coalesce into chunks of at most
  `--exec-stream-chunk-bytes` (32 KiB). The RPC's response body drains the queue at
  whatever pace the transport polls it. Gaps are derived from offsets and take no
  queue space, and `ExecFinished` has its own slot, so neither is ever dropped. The
  reader that fills the queue never waits on it, so nothing on this path can stall
  the capture readers, the cleanup barrier or terminal publication.

**Gaps and their exactness.** Before the first chunk after an interior loss the
stream carries an `OutputGap` with the stream, the first missing offset and
`dropped_bytes`, exact by offset arithmetic. A tail loss (after the last delivered
chunk) is known only from the authoritative capture total, so after publication each
stream with missing tail bytes, or an inexact total, gets a tail `OutputGap` whose
`dropped_bytes_known` is true only when `Output.total_bytes_known` is; otherwise its
count is a lower bound. kilnd never synthesizes an exact tail from offsets: a helper
that dies after an `EAGAIN` drop and before settlement reports
`dropped_bytes_known = false`. `ExecFinished` reports each stream's `LiveDelivery`:
bytes delivered, bytes reported in gaps and the same flag. Live drop counts belong to
one delivery and are not stored.

**Disconnect.** Dropping the response stream (the peer going away, a transport
deadline) is a disconnect: the supervisor records `CLIENT_DISCONNECTED` first-wins and
cancels exactly as for a unary Exec, and a queued stream that disconnects never runs.
The final state is readable with GetExecution. A client that stays connected but stops
reading is not disconnected; it only loses live bytes, and the command finishes on
time.

**Permits end at handoff.** After terminal publication kilnd reads the row, puts
`ExecFinished` in the queue's final slot and releases the stream permit, the Exec
ticket, the sandbox's outstanding permit and the RPC permit at once. It does not wait
for the peer to take the message: tonic and hyper may hold it for HTTP/2 window
without polling again. The held message is at most two retained outputs plus 64 KiB,
the shape and bound of a unary `ExecResponse` a peer refuses to read, inside one of
the connection's eight HTTP/2 streams. A daemon crash ends the stream without
`ExecFinished`; after restart the row is `INTERRUPTED`, as for Exec.

**Timeout.** `timeout_ms` is checked against the stream limits: zero is
`--default-stream-timeout-secs` (30 min), above `--max-stream-timeout-secs` (2 h) is
`INVALID_ARGUMENT`. The helper's ceiling for a live exec is 4 h; a unary exec's stays
1 h. One absolute deadline is fixed when the request arrives, and every queue wait,
helper call and kiln budget derives from it. Clients should set no gRPC deadline, or
one longer than `timeout_ms` plus cleanup, because a transport deadline is a
disconnect.

**Admission.** A stream takes everything a unary Exec takes (an ordinary RPC permit
within its uid's share, a global Exec ticket, the sandbox's outstanding permit and its
stdin bytes) plus a stream permit: at most `--max-exec-streams` (16) on the node and
`--max-exec-streams-per-uid` (8) for one uid, else `RESOURCE_EXHAUSTED
exec_stream_limit`, checked first so a refused stream holds nothing. Startup refuses a
per-uid cap at or above the node cap and a node cap at or above
`--max-concurrent-execs`, so streams never take every Exec slot. Each admitted stream
adds one descriptor in kilnd and one in the helper, at most its queue and, at the end,
one final message, so 16 streams add at most about 37 MiB. Health's `AdmissionStats`
reports the cap, the current count and rejections; `kilndctl health` prints them.

**Backends.** The kiln backend proves `EXEC_STREAM` through the helper's `features`
probe; an M3b helper does not report it, so a daemon paired with one lists no stream.
Firecracker refuses with `UNIMPLEMENTED backend_unsupported:exec_stream` before any
row, ticket, prepare call or helper call; it needs broker live frames first.

**Store: schema 14.** `executions.mode` (`unary` or `stream`, `CHECK`ed, fixed at
insert by a trigger); null on history. Schemas 9 to 13 migrate in one transaction.
`kilndctl exec --stream` prints live bytes as they arrive and gaps on stderr, then
exits with the command's code; `kilndctl execution` shows the mode.


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
| Maximum sandbox lifetime / idle timeout a create may ask for (0: no cap) | 7 d / 24 h | `--max-sandbox-lifetime-secs`, `--max-sandbox-idle-secs` |
| Lifetime / idle for a zero field of a present expiry policy (0: never; never applies without a policy) | 0 / 0 | `--default-sandbox-lifetime-secs`, `--default-sandbox-idle-secs` |
| Minimum lifetime and idle timeout | 10 s | (code) |
| Idle expiry grace after startup | 60 s | `--expiry-restart-grace-secs` |
| Pending expiry delete age that degrades Health | 600 s | `--expiry-degraded-after-secs` |
| Expiry sweeper rescan | 30 s (1 to 300) | `--expiry-rescan-secs` |
| Expiry removals at once | 4 (1 to 16) | `--max-concurrent-expiry-deletes` |
| Renew write coalescing; expiry retry backoff | 1 s; 5 s to 5 min | (code) |
| Expiry timer queue | one entry per durable reservation, at most `max(--max-sandboxes, reservations at startup)`, 96 B each | (derived) |
| Create request record retention, on the boot clock (at least 1 d; pruning waits a further 0.1 %) | 86,400 s | `--create-request-retention-secs` |
| Create request records per uid / per node (per uid below node) | 4,096 / 32,768 | `--max-create-requests-per-uid`, `--max-create-requests` |
| `request_id` | 1-64 bytes, `0x21`-`0x7e` | (code) |
| Exec cwd (ceiling 4,096) | 4,096 bytes | `--max-exec-cwd-bytes` |
| Env entries / name / value / total per list (ceilings; also for default env and the merge) | 64 / 128 / 4,096 / 32,768 bytes | `--max-exec-env-entries`, `--max-exec-env-name-bytes`, `--max-exec-env-value-bytes`, `--max-exec-env-total-bytes` |
| Exec options memfd | at most 40 KiB (largest frame 37,272 bytes) | (code) |
| ExecStream timeout (helper ceiling 4 h) | 30 min, max 2 h | `--default-stream-timeout-secs`, `--max-stream-timeout-secs` |
| ExecStreams on the node / per uid (per uid below node, node below Exec admissions) | 16 / 8 | `--max-exec-streams`, `--max-exec-streams-per-uid` |
| ExecStream live queue / chunk (queue at least two chunks; chunk at most 64 KiB) | 256 KiB / 32 KiB | `--exec-stream-buffer-bytes`, `--exec-stream-chunk-bytes` |
| Helper live message | 16 KiB data | (code) |
| Sandbox maxima | 8 GiB, 8 CPUs, 4096 pids, 32 GiB disk | (code) |

Startup validates limits before opening state or binding: required counts,
bytes and times are nonzero (the per-sandbox queue may be zero), semaphore and
stream conversions fit, the default timeout is at most the maximum and maximum
milliseconds fit `u32`. Checked arithmetic enforces request capacity at least
stdin + argv + 64 KiB and response capacity at least twice retained output +
maximum argv + 64 KiB. List bytes cannot exceed response bytes, and pages are
at most 1000. Each node budget must hold at least one default sandbox.
Nonzero expiry maxima and defaults are at least 10 s, and a nonzero default is at
most its nonzero maximum. Create request retention is at least a day, and both
record caps are nonzero with the per-uid cap below the node's. The exec cwd and env
flags are at most their ceilings, and all but the value bound are nonzero. Stream
timeouts are nonzero, the default at most the maximum and the maximum at most the
helper's 4 h; the stream caps are nonzero, per uid below the node's and the node's
below the Exec admissions; the live queue holds at least two chunks and fits `u32`.
These are finite capacity bounds, not a hard-real-time guarantee: synchronous
SQLite/filesystem work may block, slow clients may deny availability until
disconnected, and authorized callers can monopolize capacity without tenant
fairness or isolation. Terminal history has age/count retention. Pruning never removes a charged or
nonterminal sandbox, a sandbox pinned by a create request record, or an unfinished execution; deleting sandbox history
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
