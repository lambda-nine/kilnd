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
`kiln exec` client; kiln's PID 1 notices the hangup and kills the command's
process group. `kiln exec` is serial per sandbox, so kilnd queues executions
per sandbox rather than letting them pile up in kiln's socket backlog.

Two kiln changes came out of integrating this (kiln commits `852d906` and
`3736329`): a killed exec client used to leave its command running, block
later execs, and then take the whole sandbox down; and `kiln exec` used exit
code 1 for its own failures, indistinguishable from the command's.

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
(sandbox deleted, or daemon shutdown) | `FAILED` (backend error) |
`INTERRUPTED` (found running at startup).

A sandbox row is written as `CREATING` before `kiln create` runs, so a crash
mid-create leaves evidence. An execution row is written before `kiln exec`
runs and finished in one update afterwards.

## Reconciliation

At startup, before the socket is bound:

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

Each sandbox has a slot holding an async exec lock and the running
execution's cancel token. Delete marks the sandbox `DELETING`, cancels the
running execution, waits for the lock, then runs `kiln rm`. Executions waiting
behind the lock see `DELETING` and refuse.

## Shutdown and restarts

On SIGTERM or SIGINT, kilnd refuses new creates and execs and stops accepting
connections. It lets in-flight requests finish for `--shutdown-grace-secs`
(30), then cancels running executions (recorded as `CANCELED`), waits up to 10
more seconds, removes the socket and exits. Sandboxes keep running.

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
