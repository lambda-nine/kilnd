# Root helper boundary

The API daemon runs as the `kilnd` system account with an empty capability set.
It cannot invoke a privileged executable or read kiln's registry. `KilnRuntime`
connects to `/run/kilnd-helper/helper.sock`. systemd owns that socket as
`root:kilnd-helper 0660` in a `root:kilnd-helper 0750` directory; tmpfiles recreates its
parent at boot. The independent `kilnd-helper` service runs as root. It accepts only
connections whose kernel peer UID equals the configured `kilnd` account's UID, or an account
root enrolled for a Firecracker instance, and only the `kilnd` account gets kiln requests.
It rejects root connections. Group membership alone grants no helper access. The daemon verifies that its helper peer is root.

The helper accepts a private v3 typed request enum. Its outer `operation` enum
has `kiln` and `firecracker` variants, each separately validated. The Firecracker
group is described [below](#firecracker-group-schema-1); it is disabled by default
and cannot launch anything in this build. No request chooses an executable,
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
120 seconds. Header/body and output transfer have two second bounds.

Connections and operations have separate bounds. At most 128 connections can be
reading their frame, each for at most two seconds, and only a framed, classified
request takes an operation slot. There are 64 operation slots: 60 for anything and
4 reserved for recovery, which are kiln capabilities, `rm` and `gc` and Firecracker
`capabilities`, `inspect` and `fence_absent`. A normal operation, legacy or not, can
never take a reserved slot; a kiln request with no slot closes without a reply, as
before, and a group request answers `resource_exhausted`. Slow clients consume only
framing slots, for a bounded time. This is not fairness against every raw connection:
a peer holding 128 silent connections open can still delay framing. Only the service
UID can connect at all, and the reserve protects dispatch of whatever gets framed.
Stdio readers continue counting after the retained prefix reaches its limit.

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

## Firecracker group schema 2

`operation: {"firecracker": {group_version, instance_id, connection_epoch, operation}}`
travels inside the same v3 envelope, deadline, frame bound and peer checks. Schema 2 is
B7's retired-token compaction (design section 16): the helper issues every allocation
token, and a schema 1 daemon is refused as a wrong group version. Kiln
frames and every kiln reply are byte-identical to before; regression goldens pin
them. Replies use the separate `Response::Firecracker` branch. An old v3 helper
closes the connection on the unknown variant, which is how a client detects it.

The whole group frame must also be strict JSON: duplicate keys anywhere, including
inside labels, close the connection without a reply, as do floats, depth above 32,
unknown fields, a wrong group version and a misplaced epoch. No descriptor crosses
in either direction, except that B5's `exec` hands the caller three stdio sockets first,
exactly as kiln's Exec does. Nothing in the group can carry a path, UID, CID, PID, flag,
command or environment. Identities are typed 128-bit IDs and digests, profiles are
`[a-z0-9-]{1,64}`, and plan and receipt bytes are bounded lowercase hex.

| Operation | Budget | Result |
| --- | --- | --- |
| `attach_instance {database_uuid, highest_token}` | 5 s | `attached {node_id, connection_epoch, admission_open}`, and the connection stays open: its EOF is the detach. `highest_token` is the daemon's highest recorded complete token, or null; one that does not verify for this instance fails this attachment alone (`incompatible`), and a verified one at or above the issue pointer latches the node (see below) |
| `capabilities` | 2 s | Cached group and worker health. Without a policy: `enabled: false` |
| `accounting` | 5 s | Node totals with generation and once-only shared reserve, or `unknown`. No other namespace's identity. B7 adds the caller's own token figures (issue pointer, watermark, retained admitted and never-admitted rows, reserved share, pinned rows below the watermark, checkpoints, compaction lag), node retained totals, the share shortfall, a node fault by kind and a `degraded` reason |
| `preflight {sandbox_id, profile, spec}` | 30 s | `prepared {allocation_id, ..}`: the token the helper issued for this preflight, bound into the plan's substitutions, with plan bytes, digests and reservation; or a refusal with no session effects. A refusal before issuance (a full preparation slot, no headroom, the never-admitted floor, the latch) consumes no sequence |
| `create {allocation_id, sandbox_id, plan, plan_digest}` | 120 s | `accepted`, the token's `absent` fence, or `ambiguous {class}`. There is no READY variant |
| `inspect {allocation_id, plan_digest}` | 5 s | `present_ready {generation, boot_id, inner_id}` (B5: the phase is READY and no execution is in flight), `present_busy`, `stopped_with_resources`, `absent_fenced`, `incompatible` or `unknown`. A row with another plan digest is `incompatible`; a never-issued token is `incompatible`; an issued token with no row at or above the watermark is `unknown`; below it, `absent_fenced` with a receipt synthesized for this digest |
| `list` | 30 s | This namespace's records with `complete`; anything stale or unexplained makes it incomplete |
| `fence_absent {allocation_id, sandbox_id, plan_digest}` | 30 s | The permanent receipt, byte for byte, or `ambiguous {class}` |
| `stop {allocation_id, expected_generation, reason}` | 60 s | `stopped {generation, observations}` once STOP_INTENT is durable, the `vm` subtree is proven empty and S has exited, or `unknown {reason}`. Never a release. `expected_generation` is the C2 generation; `reason` is `delete`, `interrupted`, `unhealthy` or `operator` |
| `remove {allocation_id, plan_digest}` | 60 s | Stop, exact cleanup and the ABSENT fence: the permanent receipt, or `ambiguous {class}` with the charge held. Idempotent; acts only on the journaled resources of a row whose digest matches (another digest is `ambiguous {conflict}`); a compacted token gets a receipt synthesized for this digest and nothing acts; an unknown token is `ambiguous {conflict}` (only `fence_absent` fences those) |
| `gc {targets: [{allocation_id, plan_digest}]}` | 30 s | At most 1024 unique tokens, all tag-checked first: one that is not this instance's refuses the whole request. Per target: `removed {receipt}` (a compacted one's synthesized receipt included), `skipped {reason}` (live, quarantined or unknown) or `failed {class}` (a mismatched digest is `failed {conflict}`). Empty is a no-op |
| `validate {allocation_id, expected_boot_id, expected_inner_id}` | 5 s | B5. `ready {boot_id, inner_id}` after a broker Probe on the reserved control channel finds it idle on the journaled boot and inner sandbox; `busy {execution_token}` from the recorded state during an execution, with no guest polling; `incompatible` for another boot or inner sandbox; `unknown {reason}` otherwise. Never absence; a probe that fails or finds the broker in any other state retires the VM |
| `exec {allocation_id, expected_boot_id, execution_token, execution_id, argv, stdin_bytes, max_output}` | 3,600 s | B5. One execution in the persistent sandbox: `{finish, status, stdout, stderr, cleanup, reusable, dispatched}`, with `finish` `completed`, `timed_out`, `canceled` or `failed {diagnostic}` and `cleanup` `no_child_started`, `guest_cgroup_drained`, `vm_stopped` or `unknown`. argv at most 256 KiB, stdin at most 1 MiB, `max_output` 1 byte to 1 MiB. EXEC_INTENT is journaled before any byte is sent; only a validated, delivered result with the guest's drain evidence leaves the VM `reusable`. Any interruption after dispatch (deadline, the caller's disconnect, Stop, a protocol, transport or cleanup failure) sends Cancel, allows two seconds, then stops the VM through the barrier: `reusable: false`, and `vm_stopped` once K proved the `vm` subtree gone |

An instance must be enrolled by root first (`kilnd-helper enroll`, which takes the node
lock and uses no socket), under a Unix account no other instance holds. Attachment succeeds
only for a process running as that account by SO_PEERCRED and `/proc`, in exactly the
enrolled unit's cgroup, from the enrolled image by device, inode, size and digest, and
anything else gets `unauthorized`. A peer whose account doesn't serve the instance it names is
refused before it can queue, and each account has its own queue of attach attempts and a
few framing slots of its own. The connection's `SO_PEERPIDFD` pins
that process, so Linux 6.5 or later is required. The database UUID authenticates nothing.

Only one live attachment may hold an instance ID. Every other operation needs the
helper-issued epoch from that connection, and the same peer PID and UID, whose process must
still be alive. Allocation IDs resolve only in that authenticated instance: the same ID in
another instance is a different token, and neither can see or block the other. An epoch dies with its connection or the helper; accepted work and its claims
do not. An attested service whose stored database UUID differs gets
`admission_open: false`, and can only read.

Detach also revokes what is already in flight. Each attachment has a generation in a
shared page mapped before any fork; H clears it with one atomic store, without waiting
on L. Create rechecks it after P answers, L reads it at its commit point, and H rechecks
it after L's reply and again before S's gate. A commit that just beat the revocation
keeps its claim for an exact fence, and no effect starts.

**Tokens (B7).** An allocation ID is `seq ‖ tag`: eight big-endian bytes of the instance's
issue sequence, then eight bytes of HMAC-SHA-256 under the node's key, bound to the node and
instance. The key is written once into the node ledger at provisioning and crosses only the
private L-to-H channel. Before any gate, quota or ledger call, H checks every token a
request names (a Gc's whole vector) and refuses one whose tag does not verify for the
caller's instance, or whose sequence is 0, as `incompatible`: an old random ID, a flipped bit
and another instance's valid token are all refused there. L then classifies inside its
transaction: never issued, rows, compacted (below the instance's watermark with no rows:
absent forever), or unknown. A compactor in L deletes only absent, released and settled
rows below the watermark, on its own one-permit lane, in 16-token transactions.

**Rollback latch (B7).** A verified token at or above the issue pointer proves the node
ledger is behind a token it issued. L and H latch (L writes a durable fail-stop marker
first), the fault is committed, and from then on the node refuses Preflight, Create,
Validate, Exec and first attachments for every instance, while Inspect, List, Stop,
Remove, Gc and FenceAbsent keep draining. The same marker latches after any failed ledger
commit. Only root's offline commands end it, with the helper stopped:
`kilnd-helper offline-inventory --daemon-db <instance>=<kilnd.db> ... --report <file>` walks
every enrolled instance's owned resources against the ledger and reads each daemon
database read-only, destroying nothing; `kilnd-helper clear-node-faults --report <file>`
accepts only a current, explained, root-owned report, raises each issue pointer past the
daemon's highest verified token and deletes the faults in one transaction.
`kilnd-helper ledger-stats` prints each instance's pointers, watermark, retained rows and last
compaction.

Create and FenceAbsent from any process but the instance's live holder are refused as
`old_epoch` with no lookup and no state. From the holder, they look the token up in the
ledger before checking the epoch, the deadline or the catalog: an existing fence answers
unchanged, even under a stale epoch, and a conflicting record is never reported as absent.
A read-only lookup may answer up to 250 ms after an expired wire deadline, and that
authorizes nothing. After that lookup finds nothing, the first rejection closes the
token's in-memory gate, and only its durable fence ever answers for it again. A later
cause clearing does not reopen it. Gates are per instance, with a quota: a token whose plan
was malformed may be evicted, and a full table refuses that instance's new tokens with
`worker_exhausted`, while tokens the ledger owns and fences are unaffected. Each instance
also has a durable quota of fences for tokens the ledger never admitted: past it,
`fence_absent` for a never-seen token answers `ambiguous {resource_exhausted}` with nothing
written, and the charge stays. Fences for admitted tokens never meet this quota. Those two
operations run detached from their waiter, whose disconnect or timeout gets
`ambiguous {pending}` while permits and ownership stay put. The last four of the 64
operation slots serve only recovery, and a live attachment occupies none: each enrolled
instance has its own one.

A wire deadline bounds all of Create's forward setup, not just its first reply. C2's
reply, M's watch acknowledgement, S's identity and PREPARING records, the gate, and each
later effect inside S all check the same original deadline. Once it passes no new S
starts, a stop is recorded, and a permit with no process settles as never started. The
claim stays, and cleanup keeps its own separate bounds.

H, the listener, stays current-thread and does framing, peer checks, in-memory
state and dispatch. Its fixed fork-only workers hold everything else:

| Worker | Count | Does |
| --- | --- | --- |
| L | 1 | The sole SQLite connection to the root node ledger, serially |
| P | 2 slots | Hashing, catalog and plan verification, namespace reads. Read-only |
| S | 1 per accepted allocation | Gated until M acknowledges its watch and L records its identity and permit |
| M | 1 | Heartbeat and EOF watches, stop dispatch; fails closed when H goes silent |
| K | 2 slots | Stops an already-authorized subtree by verified identity, independent of L and S |

Worker sockets carry bounded framed typed messages, with absolute deadlines and
reader and writer tasks independent of any waiter. L's queue has four reserved
slots. Preflight refuses at once when both P slots are busy; Create may wait for one
among at most 16 waiters and never past its deadline. A worker stuck in a syscall
keeps its slot: a slot is reassigned only after that process has exited and been
reaped and its permit has settled in the ledger. A replacement's expected image and
identity are journaled before it is given any work (L, which must exist to write, does
this first thing). When M exits, every existing boot is fenced and contained through K
before a new M can exist, and those boots get no forward effects again.

A stale S heartbeat is an irrevocable stop, requested by both M and H, while the same S
keeps its slot and its charge. M's stop work over the two K slots is a bounded pending
set: a target waits for a slot's own reply instead of being dropped when both are
busy. M owns that set through H's death until every target settles, with no ownership
timeout. Private heartbeats keep idle K slots available while another K is stuck;
ledger replay remains a fallback. A K that can't finish leaves the stop unknown and charged.

From B4, S performs the real launch (design section "B4 implementation notes"): every
resource is journaled through H before or as it is owned (`record` / `recorded`, in order),
the `vm` node becomes M's stop target before J exists, and the launch ends at BOOTING. K's
stop is `cgroup.kill` on that pinned node, compared by inode, plus a pidfd signal to the
recorded VMM, compared by start time; a replaced node or reused PID is left alone. S's
session preparation holds one of the two P slots. Remove's cleanup runs in a fresh,
journaled cleanup-only S, and K removes the empty tree. A Stop whose ledger does not answer
within a second still revokes and contains under C2's authority, and answers `unknown`.

## Trust and failure analysis

The helper is the only root entry point available through the daemon. It has
no API authentication logic, gRPC parser, SQLite history, labels-based lookup,
or general host command facility. It reuses the already reviewed direct kiln
adapter, process supervision, strict kiln protocol decoder and shared
validators. Those shared modules and the installed kiln CLI remain part of
the privileged trusted computing base and must be included in audits; counting
only the helper binary's entry point would understate it.

At `d79341d` (before the receipt and control-deadline fixes), the Phase 0 root
audit surface is 3,444 physical production lines (including
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
AF_NETLINK AF_INET`, `LockPersonality`, `RestrictRealtime` and `ProtectKernelLogs`.
AF_UNIX serves control/stdio; AF_NETLINK supports kiln's network setup and nft.
AF_INET permits libc DNS resolution through the supported VM's IPv4 resolver.
AF_INET6 is excluded: kiln rejects IPv6 destinations and retains only public
IPv4 hostname answers for its nft policy. Hosts using only an IPv6 DNS resolver
must configure an IPv4-reachable resolver for this deployment. With
explicit `User=root`, systemd 255's seccomp credential transition drops effective
CAP_SETUID unless `AmbientCapabilities=CAP_SETUID` preserves it for UID-map
writes. The bounding/effective/permitted mask remains `0x2010eb`, ambient is
`0x80`, NoNewPrivs is 1 and Seccomp is 2. The installed regression verifies these
and a real Create/Exec lifecycle under the filtered unit.

The helper stays on a current-thread runtime: adding worker threads would only
move the risk to worker-pool exhaustion. Firecracker's blocking work runs in separate
fixed processes for the same reason. All helper socket reads/writes use
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
