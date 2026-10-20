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
`exec(id, argv, stdin, timeout, max_output, cancel)`, `remove`, `list`, `gc`
and `version`. The contract that matters most: when an exec times out or is
canceled, the command must be stopped *inside* the sandbox and the sandbox
left usable. A Firecracker backend would implement the same trait over its
API socket and a guest agent.

`KilnRuntime` drives the installed CLI:

| kilnd | kiln |
|-------|------|
| create | `kiln create --image=… --memory=… --cpus=… --pids=… --disk=… --net=…/--allow=… [--read-only --writable=…]`; stdout is the ID |
| exec | `kiln exec ID -- ARGV…` with stdin/stdout/stderr as pipes; exit code is the command's, 125 means kiln failed |
| delete | `kiln rm ID` |
| reconcile | `kiln gc`, then `kiln ls` |
| health | `kiln --version` |

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

The cumulative required kiln revision is `3b42552`. Earlier integration fixes
made a killed exec client stop its command without taking down the sandbox and
reserved exit code 125 for kiln failures; the per-execution cgroup closes the
remaining escaped-descendant gap.

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

1. `kiln gc` removes what dead shims left behind (kiln only touches sandboxes
   whose shim is gone).
2. `kiln ls` lists what is alive. If it fails, kilnd refuses to start rather
   than guess.
3. For each sandbox of this backend in the database: `READY`/`CREATING` with a
   live backend stays (or becomes) `READY`; without one it becomes `LOST`;
   `CREATING` without a backend ID becomes `FAILED`; `DELETING` is retried
   or completed.
4. Executions still `RUNNING` become `INTERRUPTED`. Their `kiln exec` clients
   died with kilnd (`PR_SET_PDEATHSIG`), so kiln already stopped the commands.
5. Live kiln sandboxes kilnd doesn't know are logged as unmanaged and left
   alone.

Running it again changes nothing.

## Concurrency

kilnd runs on tokio's current-thread runtime. There is little CPU work; most
time is spent waiting on child processes. It also makes `PR_SET_PDEATHSIG`
reliable, because the thread that forks lives as long as the daemon. SQLite
access goes through one mutex-guarded connection, and each statement is
short. The active-sandbox cap is checked and the row inserted with no await in
between, so concurrent creates can't overshoot it.

Each sandbox has a slot holding an async exec lock and the running execution's
cancellation handle. Client disconnect, delete, and shutdown all record a
first-wins reason through that handle before canceling its private token.
Delete marks the sandbox `DELETING`, cancels the running execution, waits for
the supervisor to finish and release the lock, then runs `kiln rm`.
Executions waiting behind the lock see `DELETING` and refuse.

Accepted create and exec operations live in a task tracker owned by the
manager. The RPC awaits a one-shot result but does not own the task.
Validation, capacity admission and registration happen synchronously before
the public method's first await on the current-thread runtime, so shutdown
cannot interleave between the serving check and tracker spawn. Backend work is
isolated so a panic becomes a persisted failure instead of dropping operation
state.

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
| Sandbox defaults | alpine, 512 MiB, 1 CPU, 128 pids, 1 GiB disk, no network | (code) |
| Sandbox maxima | 8 GiB, 8 CPUs, 4096 pids, 32 GiB disk | (code) |

## Dependencies

tokio, tonic and prost (gRPC), rusqlite with bundled SQLite, clap, serde and
serde_json (spec and argv columns), tracing, thiserror, anyhow and libc.
Building needs `protoc`.
