# Root helper boundary

The API daemon runs as the `kilnd` system account with an empty capability set.
It cannot invoke a privileged executable or read kiln's registry. `KilnRuntime`
connects to `/run/kilnd-helper/helper.sock`. systemd owns that socket as
`root:kilnd 0660` in a `root:kilnd 0750` directory; tmpfiles recreates its parent
at boot. The independent `kilnd-helper` service runs as root. It accepts only
connections whose kernel peer UID equals the configured `kilnd` account's UID,
including rejecting root connections. API group membership alone grants no
helper access. The daemon verifies that its helper peer is root.

The helper accepts a private v3 typed request enum. Its outer `operation` enum
has one `kiln` variant; a future backend needs a separately validated variant.
There are no Firecracker requests today. No request chooses an executable,
host path, environment, arbitrary kiln flags, or shell text. The root-owned
helper command line fixes the kiln executable. Its canonical file and every
ancestor must be root-owned and not group/other writable.

## Framing and descriptors

One connection carries one operation. The caller first sends one byte `0x4b`
with **no descriptors**, for every operation including Exec. The helper rejects
all caller-supplied descriptors, unknown ancillary messages and truncated
envelopes; every received descriptor is owned immediately and close-on-exec,
including on rejection. No caller-selected fd is used for root I/O.

After validating the request, the helper sends its own `0x4b` envelope: zero
descriptors for other operations, exactly three for Exec in stdin/stdout/stderr
order. The helper creates three anonymous connected AF_UNIX SOCK_STREAM pairs,
keeps one endpoint of each, and passes only the opposite endpoint to kilnd.
The client acknowledges receipt with one byte `0x4b` on the control socket,
after recvmsg installs all three descriptors. Until that receipt, the helper
retains its copies of the sent endpoints without performing I/O on them. It
then drops those copies before stdio starts. This closes a Darwin ordering race:
closing the last installed descriptor while a Unix endpoint is still in flight
can deliver premature EOF to the receiver. The handoff, including the receipt,
is bounded by two seconds. Cancellation or EOF instead of a receipt aborts it. The client
requires anonymous connected streams with root peer credentials. Each pair's
two endpoints have distinct open file descriptions: changing `O_NONBLOCK` on
kilnd's endpoint cannot affect the endpoint the helper uses. Version 1 and 2 requests
are refused; daemon and helper must be upgraded together.

The caller's marker is followed by a four-byte big-endian nonzero JSON length,
then exactly that many request bytes (before the helper sends its envelope). Frames are limited to 2 MiB; request fields and enums are typed and
unknown fields are refused. The request has `version: 3`, `timeout_ms`, and
`operation`, plus an absolute `deadline_ns` from CLOCK_MONOTONIC. The helper
checks that this deadline fits the declared timeout and preserves it across
connection setup. The response uses the same length framing and a typed result,
followed by EOF. Multiple replies, incomplete frames and missing EOF never
constitute successful evidence. A cancellation byte, extra request data or
client EOF after the frame requests cancellation; it is not a second request.

Stdin is delivered on the helper-created socket and must reach EOF within two
seconds or the request deadline, whichever is earlier (cancellation also closes it),
with exactly the declared byte count, at most 1 MiB. Exec output is transferred
on its two helper-created sockets after the bounded unary execution settles. Control
JSON carries retained lengths, observed totals, certainty and truncation facts,
command status and diagnostics, never stdout/stderr payloads. Both ends keep
FD ownership through stdio completion; explicit output shutdown proves EOF. The
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

The root runtime retains ownership through child termination, reaping and
capture settlement after deadline or cancellation. Create, remove, list and GC
honor the original wire deadline and cancellation, capped at 120, 60, 30 and 30
seconds respectively. Remove's absence probe shares that deadline/token (and
has at most 30 seconds); cancellation or expiry cannot prove absence and cannot
release a reservation. A canceled create after invocation remains ambiguous
unless the existing typed pre-allocation evidence proves otherwise. Exec honors
its deadline/cancellation, kills and reaps the CLI, and waits for the existing
execution-cgroup cleanup barrier before returning. Cancellation never abandons
that barrier. The client waits for the reply, with per-operation transport allowances: Exec 70 seconds for cleanup, Create
five seconds, capability probes one second and other controls two seconds.
Health publishes its deadline failure while owned probe cleanup keeps draining,
without admitting a replacement probe. A failed helper exchange is an
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

The Phase 0 root audit surface is 3,444 physical production lines (including
comments and blanks): 889 in the entry point, server, framing, descriptor
handling, per-syscall socket I/O and typed protocol; 833 in the shared direct adapter; 1,108 in shared
process supervision and kiln protocol; and 614 in shared validation, model and
runtime contract. Test modules are excluded; small inline test hooks are counted
conservatively. The unprivileged helper client/adapter adds 380 lines. Libraries,
installed kiln, nft and the kernel are additional trusted code.

The service account and daemon are trusted to enforce per-caller ownership and
resource reservations. A compromised daemon can invoke every allowed helper
operation against kiln backends, including unmanaged IDs. The helper is not a
second tenant-policy database. It limits that compromise to validated kiln
operations; it cannot make experimental shared-kernel isolation safe against a
kernel or kiln privilege-escalation bug. Root remains fully trusted.

A daemon crash closes its control connection; the helper cancels an active
Exec and completes cleanup. A helper crash kills its direct CLI clients via
parent-death signals; kiln PID 1 performs command cleanup on client loss.
Detached sandbox shims survive helper restarts (`KillMode=process`), and the
unprivileged daemon preserves legacy shims from pre-helper upgrades. A helper transport
failure reports failure, never reusable-success evidence. Startup reconciles
interrupted execution rows and applies the existing strict backend observations.
A create interrupted before its backend ID is durably published remains an
ambiguous, charged reservation, including if the helper completed allocation.

The helper's systemd mount restrictions mark system files, `/dev`, `/proc/sys`
and `/sys` read-only, with writable exceptions for kiln state, runtime network
state, cgroupfs and the IP-forwarding sysctl. Mount read-only flags do not
prevent writes through device nodes or every process API; those are constrained
by fixed operations and the capability set. The helper retains CAP_SYS_ADMIN
for kiln's namespace/mount work and can undo mount restrictions if compromised;
these restrictions reduce ordinary write paths, not the authority of trusted root. Its capability set
covers namespace/mount/quota, networking, UID maps, ownership and cleanup. It
cannot use the daemon unit's namespace/cgroup restrictions: kiln needs those
operations. Both units use NoNewPrivileges and ProtectSystem=strict. The daemon
has no capabilities and cannot reach kiln's root-owned data or networking state.

The helper inherits systemd seccomp filters for `RestrictAddressFamilies=AF_UNIX
AF_NETLINK AF_INET AF_INET6`, `LockPersonality`, `RestrictRealtime` and `ProtectKernelLogs`.
AF_UNIX serves control/stdio; AF_NETLINK supports kiln's network setup. AF_INET
and AF_INET6 are needed by libc hostname resolution for allowlists (including
IPv6 host resolvers even though sandbox allowlists are IPv4). With
explicit `User=root`, systemd 255's seccomp credential transition drops effective
CAP_SETUID unless `AmbientCapabilities=CAP_SETUID` preserves it for UID-map
writes. The bounding/effective/permitted mask remains `0x2010eb`, ambient is
`0x80`, NoNewPrivs is 1 and Seccomp is 2. The installed regression verifies these
and a real Create/Exec lifecycle under the filtered unit.

The helper stays on a current-thread runtime: adding worker threads would only
move the risk to worker-pool exhaustion. All helper socket reads/writes use
`recv`/`send` (including descriptor envelopes) with `MSG_DONTWAIT` and readiness
retry, even on control sockets. AF_UNIX `shutdown(SHUT_WR)` signals EOF without
waiting for queued output to drain or consulting `O_NONBLOCK`. Request parsing,
endpoint handoff and output transfer each have a two-second bound; stdin also
honors the absolute request deadline and cancellation. The Linux regression
changes received endpoint flags after handoff while holding stdin open and
proves another request, the deadline and cancellation still progress; it also
withholds both output readers from a real Exec to exercise transfer timeout. A second
unit regression deliberately shares and changes a helper endpoint's flags,
then saturates its output queue, to verify per-syscall nonblocking I/O itself.
