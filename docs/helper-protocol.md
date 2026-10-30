# Root helper boundary

The API daemon runs as the `kilnd` system account with an empty capability set.
It cannot invoke a privileged executable or read kiln's registry. `KilnRuntime`
connects to `/run/kilnd-helper/helper.sock`. systemd owns that socket as
`root:kilnd 0660` in a `root:kilnd 0750` directory; tmpfiles recreates its parent
at boot. The independent `kilnd-helper` service runs as root. It accepts only
connections whose kernel peer UID equals the configured `kilnd` account's UID,
including rejecting root connections. API group membership alone grants no
helper access. The daemon verifies that its helper peer is root.

The helper accepts a private v1 typed request enum. Its outer `operation` enum
has one `kiln` variant; a future backend needs a separately validated variant.
There are no Firecracker requests today. No request chooses an executable,
host path, environment, arbitrary kiln flags, or shell text. The root-owned
helper command line fixes the kiln executable. Its canonical file and every
ancestor must be root-owned and not group/other writable.

## Framing and descriptors

One connection carries one operation. First comes one byte `0x4b`, with
`SCM_RIGHTS` ancillary descriptors attached to that byte. Every non-Exec request
requires zero descriptors; Exec requires exactly three in stdin/stdout/stderr
order. The helper rejects other ancillary messages, truncated envelopes, excess
FDs and any stdio descriptor that is not an anonymous, connected AF_UNIX
SOCK_STREAM socket whose peer UID is `kilnd`. Every received descriptor is
owned immediately and close-on-exec, including on rejection. It cannot be used
as a root file-open/write API. Only the existing runtime's explicitly selected
child FDs cross exec.

Next is a four-byte big-endian nonzero JSON length, then exactly that many
bytes. Frames are limited to 2 MiB; request fields and enums are typed and
unknown fields are refused. The request has `version: 1`, `timeout_ms`, and
`operation`, plus an absolute `deadline_ns` from CLOCK_MONOTONIC. The helper
checks that this deadline fits the declared timeout and preserves it across
connection setup. The response uses the same length framing and a typed result,
followed by EOF. Multiple replies, incomplete frames and missing EOF never
constitute successful evidence. A cancellation byte, extra request data or
client EOF after the frame requests cancellation; it is not a second request.

Stdin is delivered on its passed socket and must reach EOF within two seconds,
with exactly the declared byte count, at most 1 MiB. Exec output is transferred
on its two passed sockets after the bounded unary execution settles. Control
JSON carries retained lengths, observed totals, certainty and truncation facts,
command status and diagnostics, never stdout/stderr payloads. Both ends keep
FD ownership until the response; explicit output shutdown proves EOF. The
existing runtime still handles kiln's four separate machine-protocol FDs and
capture/cleanup barriers. This transport does not promise live output streaming.

## Operations and limits

| Typed kiln operation | Fixed backend action |
| --- | --- |
| `capabilities {id: null}` | Negotiate installed CLI capabilities and scoped `gc --help` |
| `capabilities {id}` | Validate exact live backend, or prove absence using probe/list/cgroup evidence |
| `create {spec}` | Validated `kiln create --require-exec-protocol=1` with fixed flag mapping |
| `exec {id, argv, stdin_bytes, max_output}` | Validated literal argv after `--`, persistent-exec v1 |
| `ls` | Complete, bounded, strictly parsed `kiln ls` |
| `rm {id}` | Exact removal plus authoritative absence checks |
| `gc {ids}` | Scoped collection only; empty IDs never invokes global GC |

The helper reuses the API's image, allowlist, path, argv and backend-ID
validators. It independently checks labels, resource ceilings, descriptor
counts and sizes before any backend invocation. Hard ceilings are 8 GiB memory,
8 CPUs, 4096 PIDs, 32 GiB disk, 64 allowlist entries, 16 writable paths,
32 labels, 4096 argv entries / 256 KiB argv, 1 MiB stdin and 1 MiB retained
output per stream. GC has at most 1024 unique IDs per call; the daemon chunks
larger scopes. Exec deadlines are at most one hour; control requests at most
120 seconds. Header/body and output transfer have two second bounds, and there
are at most 64 active connections/operations. Excess connections close. Slow
clients consume bounded slots. Stdio readers continue counting after the
retained prefix reaches its limit.

The root runtime owns create/remove cleanup independently of a disconnected
client. Accepted creates retain the existing 120-second gate/create bound;
removals retain a 60-second remove plus 30-second absence probe. Exec honors
its deadline/cancellation, kills and reaps the CLI, and waits for the existing
execution-cgroup cleanup barrier before returning. Cancellation never abandons
that barrier. The client waits for the reply, with a final transport bound
covering the backend cleanup allowance. A failed helper exchange is an
ambiguous create failure, or an Exec CleanupFailed result retaining already observed output prefixes; it cannot claim
allocation absence, exact output totals, or successful execution.

## Trust and failure analysis

The helper is the only root entry point available through the daemon. It has
no API authentication logic, gRPC parser, SQLite history, labels-based lookup,
or general host command facility. It reuses the already reviewed direct kiln
adapter, process supervision, strict kiln protocol decoder and shared
validators. Those shared modules and the installed kiln CLI remain part of
the privileged trusted computing base and must be included in audits; counting
only the helper binary's entry point would understate it.

The service account and daemon are trusted to enforce per-caller ownership and
resource reservations. A compromised daemon can invoke every allowed helper
operation against kiln backends, including unmanaged IDs. The helper is not a
second tenant-policy database. It limits that compromise to validated kiln
operations; it cannot make experimental shared-kernel isolation safe against a
kernel or kiln privilege-escalation bug. Root remains fully trusted.

A daemon crash closes its control connection; the helper cancels an active
Exec and completes cleanup. A helper crash kills its direct CLI clients via
parent-death signals; kiln PID 1 performs command cleanup on client loss.
Detached sandbox shims survive helper restarts (`KillMode=process`), while the
unprivileged daemon uses ordinary control-group shutdown. A helper transport
failure reports failure, never reusable-success evidence. Startup reconciles
interrupted execution rows and applies the existing strict backend observations.
A create interrupted before its backend ID is durably published remains an
ambiguous, charged reservation, including if the helper completed allocation.

The helper's systemd sandbox leaves only kiln state, runtime network state,
cgroupfs and the required IP-forwarding sysctl writable. Its capability set
covers namespace/mount/quota, networking, UID maps, ownership and cleanup. It
cannot use the daemon unit's namespace/cgroup restrictions: kiln needs those
operations. Both units use NoNewPrivileges and ProtectSystem=strict. The daemon
has no capabilities and cannot reach kiln's root-owned data or networking state.
