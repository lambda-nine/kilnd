# kilnd architecture

## Where it sits

```
 harness (later): agent loop, memory, tool registry, LLM provider
        │  gRPC kilnd.v1 over /run/kilnd/kilnd.sock
 ┌──────▼──────────────────────────────────────────────────────┐
 │ kilnd (root, one per node, current-thread tokio runtime)    │
 │  service.rs   proto ⇄ model translation, error → gRPC code  │
 │  manager.rs   validation, state machine, per-sandbox locks, │
 │               reconciliation, shutdown                      │
 │  store.rs     SQLite (WAL, synchronous=FULL)                │
 │  runtime/     Runtime trait; kiln.rs (CLI), fake.rs (tests) │
 │  process.rs   argv spawn, timeout, cancel, bounded capture  │
 └──────┬──────────────────────────────────────────────────────┘
        │  argv: kiln create|exec|ls|rm|gc   (env cleared, PATH fixed)
 ┌──────▼──────────────────────────────────────────────────────┐
 │ kiln CLI → detached shim per sandbox → kiln-init (PID 1)    │
 └─────────────────────────────────────────────────────────────┘
```

kilnd is a library crate plus a small `main.rs`. Everything below the gRPC
layer is testable without a socket, and everything below the manager is
testable without kiln, through the fake runtime.

## The runtime adapter

`runtime::Runtime` is the only kiln-shaped seam: `create(spec) → backend id`,
`exec(id, argv, stdin, deadline, max_output, cancel)`, `validate_sandbox`, `remove`, `list`, `gc(ids)`
and `version`. The contract that matters most: when an exec times out or is
canceled, the command must be stopped *inside* the sandbox and the sandbox
left usable. A Firecracker backend would implement the same trait over its
API socket and a guest agent.

`KilnRuntime` drives the installed CLI:

| kilnd | kiln |
|-------|------|
| create | `kiln create --require-exec-protocol=1 --image=… --memory=… --cpus=… --pids=… --disk=… --net=…/--allow=… [--read-only --writable=…]`; stdout is the ID |
| exec | `kiln exec --protocol=1 --status-fd=N --stdin-fd=I --stdout-fd=O --stderr-fd=E ID -- ARGV…`; private status and workload streams |
| delete | `kiln rm ID` |
| reconcile | `kiln ls`, scoped `kiln gc ID...`, then `kiln ls` again |
| health | `kiln capabilities --protocol=1` |

Every flag value uses `--flag=value` so it can't be parsed as another flag,
the command's argv follows `--`, and kilnd validates every value before it
reaches kiln (kiln validates again). Timeouts and cancellation kill the
`kiln exec` client; kiln's PID 1 notices the hangup, kills every process in
that command's per-execution cgroup, and finishes only after the cgroup is
empty. The killed CLI cannot receive PID 1's reply, so kilnd independently
waits for the host's `exec/cgroup.events` to report `populated 0` before it
finalizes or unlocks the sandbox. This also contains descendants that changed
process group or session. `kiln exec` is serial per sandbox, so kilnd queues
executions per sandbox rather than letting them pile up in kiln's socket
backlog.

Exec calculates one absolute Tokio deadline at handler receipt (or direct
manager entry). Queueing and process setup consume that same budget; the
runtime and process runner use `sleep_until(deadline)`. The row retains the
original requested/default timeout. Expiry while queued creates no row or
backend call and returns `DEADLINE_EXCEEDED`. Once a row exists, timeout
produces a successful terminal `TIMED_OUT` execution after backend cleanup
and SQLite publication. Cleanup is never timed out by the service.

The required persistent-exec protocol v1 was first supplied by kiln
`f3da4b5319566de4912ed617caf81d4eb8e50b6f`, with follow-up
`711440db3167cdf3a90d3aad44623ce56c2d01b1`, based on `3b42552`.
Both installed CLI and sandbox PID 1 capabilities are checked before each
execution, within its existing deadline. Create requires
`--require-exec-protocol=1`; there is no machine legacy fallback. Package and
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

## State machine

```
            create ok                 delete
 CREATING ───────────▶ READY ─────────────────▶ DELETING ──▶ DELETED
    │ create failed      │ backend gone            │ rm failed: stays DELETING
    ▼                    ▼ (exec or startup)       │ (retry delete, or startup retries)
  FAILED               LOST
    └──── delete ───▶ DELETED ◀──── delete ────┘
```

Executions: `RUNNING` → `EXITED` (with exit code) | `TIMED_OUT` | `CANCELED`
(caller disconnected, sandbox deleted, or daemon shutdown) | `FAILED` (backend error) |
`INTERRUPTED` (found running at startup).

A sandbox row is written as `CREATING` before `kiln create` runs, so a crash
mid-create leaves evidence. Creation then belongs to a tracked daemon task,
not the gRPC handler: disconnecting only drops the waiter. A successful
backend ID is published as `READY`; if that write fails, kilnd first records
`DELETING`, removes the backend, and records `FAILED`. Failed removal stays
`DELETING`, retains the backend ID, counts against the active limit, and is
retryable. An execution row is written before `kiln exec` runs and finished
in one update afterwards. Once that row exists, a tracked supervisor owns the
request, sandbox lock, backend task, output capture, and terminal update. The
RPC is only a waiter: dropping it records the first cancellation reason and
requests cancellation, but cannot abandon cleanup. A caller that disconnects
while still queued is discarded before a row or backend process is created.
If the terminal SQLite update fails, the supervisor keeps the lock and outcome
and retries with bounded exponential backoff. Health is degraded and shutdown
cannot claim a completed drain until that publication succeeds.

## Instance ownership

Startup establishes two independent ownership domains before reconciliation:

1. `Store::open` validates the state directory and takes a nonblocking
   advisory lock on its persistent `kilnd.lock` file before opening SQLite.
2. Socket binding takes a nonblocking advisory lock on the persistent
   `.kilnd.socket.lock` in the socket directory. An existing socket is probed
   with a bounded connection attempt: a successful connection is a live
   owner. On Linux, `ECONNREFUSED` plus unchanged device/inode identifies a
   stale endpoint. Platforms such as macOS, where refusal can also report a
   full live backlog, preserve the path and fail closed. Every other
   ambiguous result is also preserved and rejected.
3. The new listener is bound and its pathname identity recorded. Only then
   may reconciliation invoke kiln or update SQLite.

The lock files are never unlinked. Their open descriptors are close-on-exec,
so kiln children cannot retain ownership after kilnd exits. The bound socket
is an RAII resource: graceful exit removes it only if the pathname still has
the device and inode recorded at bind time. A replacement is left untouched.
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
   `CREATING` without a backend ID becomes `FAILED`; `DELETING` is retried
   or completed.
5. Executions still `RUNNING` for this backend become `INTERRUPTED`. Other
   backends' rows are untouched. Their `kiln exec` clients died with kilnd
   (`PR_SET_PDEATHSIG`), so kiln already stopped the commands.
6. Live or stale kiln sandboxes kilnd doesn't know are logged as unmanaged and
   left alone across repeated startup reconciliation and daemon shutdown.

Running it again changes nothing.

## Concurrency

kilnd runs on tokio's current-thread runtime. There is little CPU work; most
time is spent waiting on child processes. It also makes `PR_SET_PDEATHSIG`
reliable, because the thread that forks lives as long as the daemon. SQLite
access goes through one mutex-guarded connection, and each statement is
short. The active-sandbox cap is checked and the row inserted with no await in
between, so concurrent creates can't overshoot it.

Each sandbox has a stable slot holding an async exec lock, an outstanding
request semaphore (one running plus the configured queue capacity), and the
running execution's cancellation handle. The registry stores weak references:
a live slot is never replaced under queued requests, while dead entries are
pruned on later slot access so create/delete churn does not grow memory.
Client disconnect, delete, and shutdown all record a
first-wins reason through that handle before canceling its private token.
Delete marks the sandbox `DELETING`, cancels the running execution, waits for
the supervisor to finish and release the lock, reloads the row, then runs
`kiln rm`. The caller holds a strong reference to the stable slot before it
publishes delete intent, so queued deletes cannot acquire replacement locks.
Only one caller invokes the backend; followers observe `DELETED` under the
lock and return the existing row without changing its timestamps. Delete
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
Completion caches a cloned success or error using a monotonic timestamp;
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
than asserting exactness. Older binaries refuse schema 4. Migration happens at
store open and may precede startup capability failure; back up before upgrading.

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
snapshot of metadata or deletion state across pages. Tokens are opaque to
clients; the server accepts only canonical versioned ASCII tokens bound to the
deleted filter and validates positive, ordered cursor ranges.

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
operations drain, kilnd conditionally removes only its own socket inode and
then releases the socket- and state-directory locks. A crash releases the
kernel locks but can leave a stale socket for the next instance to probe.

The systemd unit uses `KillMode=process` because kiln's shims are forked from
kilnd's cgroup and must survive daemon restarts. systemd logs "left-over
process" for each shim on restart; that is expected.

## Limits and defaults

| Setting | Default | Flag |
|---------|---------|------|
| Socket | `/run/kilnd/kilnd.sock`, group `kilnd` | `--socket`, `--socket-group` |
| State | `/var/lib/kilnd/kilnd.db` | `--state-dir` |
| Exec timeout | 60 s, max 1 h | `--default-timeout-secs`, `--max-timeout-secs` |
| Output kept per stream | 1 MiB | `--max-output-bytes` |
| Active sandboxes | 32 | `--max-sandboxes` |
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
at most 1000.
These are finite capacity bounds, not a hard-real-time guarantee: synchronous
SQLite/filesystem work may block, slow clients may deny availability until
disconnected, and authorized callers can monopolize capacity without tenant
fairness or isolation. Durable history still grows without retention.

## Dependencies

tokio, tonic and prost (gRPC), rusqlite with bundled SQLite, clap, serde and
serde_json (spec and argv columns), tracing, thiserror, anyhow and libc.
Building needs `protoc`.
