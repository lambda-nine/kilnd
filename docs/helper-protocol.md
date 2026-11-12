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
order, and a fourth, the live socket, for an Exec with `live` (below). The helper creates three anonymous connected AF_UNIX SOCK_STREAM pairs,
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
capture/cleanup barriers. Only an Exec with `live` carries live output, lossy and on
its own socket (below); the settled transfer stays the authority.

## Operations and limits

| Typed kiln operation | Fixed backend action |
| --- | --- |
| `capabilities {id: null}` | Negotiate installed CLI capabilities and scoped `gc --help` |
| `capabilities {id}` | Validate exact live backend, or prove absence using probe/list/cgroup evidence |
| `features {id}` | The feature bits the installed CLI (`id: null`) or that sandbox's PID 1 advertises, and whether exec options can reach it: `{features, exec_options}` |
| `create {spec}` | Validated `kiln create --require-exec-protocol=1` with fixed flag mapping |
| `exec {id, argv, stdin_bytes, max_output[, cwd][, env][, live]}` | Validated literal argv after `--`, persistent-exec v1; with `cwd` or `env`, the options in a sealed memfd (below); with `live`, a fourth live-output descriptor (below) |
| `ls` | Complete, bounded, strictly parsed `kiln ls` |
| `rm {id}` | Exact removal plus authoritative absence checks |
| `gc {ids}` | Scoped collection only; empty IDs never invokes global GC |

**Exec options (API additions M3b).** `exec` takes two optional fields, `cwd` (a
string) and `env` (`[[name, value], ...]`), omitted from the JSON when empty, so a
request without them is byte-identical to before and still runs kiln's operation 4.
They are sandbox-interior data, never host paths, flags or environment: the kiln CLI's
own environment stays the helper's cleared one. The helper revalidates them with the
daemon's validators at the code ceilings (cwd absolute, at most 4,096 bytes, no NUL;
at most 64 entries, names `[A-Za-z_][A-Za-z0-9_]*` of at most 128 bytes, values UTF-8
without NUL of at most 4,096 bytes, `name + value + 2` totalling at most 32,768) and in
kiln's one strict form, entries strictly ascending by name bytes; anything else closes
the connection unanswered, as any invalid request does. It encodes kiln's options frame
(`KILNOPT\0`, version 1; see kiln's `docs/exec-protocol-v1.md`) into a memfd created
with `MFD_ALLOW_SEALING|MFD_CLOEXEC`, adding `MFD_EXEC` when `vm.memfd_noexec` is 1 so
the kernel adds no `F_SEAL_EXEC`, writes it, seals it with exactly
`F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE` and verifies the seals; it never
uses `MFD_NOEXEC_SEAL`. Under `vm.memfd_noexec=2` no acceptable memfd exists: `features`
reports `exec_options: false`, and an `exec` with options fails
`Unavailable`/`Prepare` with no child. The memfd is passed as the helper's own
descriptor number in `--exec-options-fd=N`, the only new flag; nothing else
caller-derived is on the root command line but the argv after `--`. Before starting
the CLI, the helper requires bit `0x20` from both the installed CLI and the sandbox's
PID 1 (the existing per-exec probes), else `Incompatible`/`Handshake` with no child;
the CLI probes PID 1 again itself. Values never appear in a reply: the helper's reply
types carry none, and the request's `Debug` redacts them.

**Live output (API additions M4).** `exec` takes `live: true`, omitted when false so
every other request is byte-identical. Its envelope then carries a fourth descriptor
after the three stdio sockets: one end of a fresh anonymous `AF_UNIX`
`SOCK_SEQPACKET` pair, shut down for writing on kilnd's side and for reading on the
helper's, retained without I/O until the stdio receipt like the others. The client
requires exactly four descriptors for a live exec and three otherwise, and checks the
fourth is an anonymous connected `SOCK_SEQPACKET` socket whose peer is root. The
helper's capture readers offer each read, after counting and retaining it, to a tap
that sends it as one message `[stream u8][offset u64be][bytes]` (stream 1 stdout, 2
stderr; 1 to 16 KiB of data) with `MSG_DONTWAIT|MSG_NOSIGNAL`. `EAGAIN` drops that
message and the reader moves on; a closed peer stops all further sends; nothing on
this path waits, so a slow consumer cannot slow capture or cleanup. The helper shuts
the channel down once the execution settles, before its reply. kilnd refuses a
message with an unknown stream, no data, more than 16 KiB, an overflowing offset or
an offset below the stream's last end, and treats the rest as a tail gap. A live exec
may have a deadline of up to four hours; any other exec's ceiling stays one hour.
Darwin has no `SOCK_SEQPACKET` Unix sockets, so a helper there reports no live output.

`features {id}` is a recovery request, like `capabilities`. An older helper closes the
connection on it, so a daemon paired with one lists no dynamic features and its Health
is not serving: daemon and helper are upgraded together. Its reply,
`{"features": {"features": N, "exec_options": B}}`, is a new variant; every existing
reply is byte-identical. Since M4 it adds `"exec_stream": true` when this helper can
carry live output, omitted when false; an M3b daemon, which does not know the field,
must be upgraded with its helper as always.

The helper reuses the API's image, allowlist, path, argv and backend-ID
validators. It independently checks labels, resource ceilings, descriptor
counts and sizes before any backend invocation. Hard ceilings are 8 GiB memory,
8 CPUs, 4096 PIDs, 32 GiB disk, 64 allowlist entries, 16 writable paths,
32 labels, 4096 argv entries / 256 KiB argv, 1 MiB stdin, 1 MiB retained
output per stream, a 4,096-byte cwd, 64 env entries / 32 KiB env and a 40 KiB options
memfd. GC has at most 1024 unique IDs per call; the daemon chunks
larger scopes. Exec deadlines are at most one hour (four for a live exec); control requests at most
120 seconds. Header/body and output transfer have two second bounds.

Connections and operations have separate bounds. At most 128 connections can be
reading their frame, each for at most two seconds, and only a framed, classified
request takes an operation slot. There are 64 operation slots: 60 for anything and
4 reserved for recovery, which are kiln `capabilities`, `features`, `rm` and `gc`, Firecracker
`capabilities`, `inspect` and `fence_absent`, and checkpoint `capabilities`, a non-verifying
`inspect`, `remove`, `inventory` and `acknowledge`. A normal operation, legacy or not, can
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

## Checkpoint group 1

Workspace checkpoints (design `kilnd-checkpoint-fork`, milestone C3) are a third group in
the same v3 envelope: `operation: {"checkpoint": {group_version, helper_epoch, operation}}`,
answered on its own `Response::Checkpoint` branch. Every kiln and Firecracker frame and
reply is byte-identical, an older helper closes the connection on the unknown variant,
and the whole frame must be strict JSON as for Firecracker. Only the `kilnd` account may
use it. **It is off by default:** without `kilnd-helper --enable-checkpoints`,
`capabilities` answers `enabled: false` and every other operation `disabled`. Nothing in
the daemon calls it yet: there is no RPC, Health field or feature for checkpoints, and
`RuntimeCapabilities.checkpoint` stays false.

No request carries a path, flag, command, descriptor or environment. Artifacts are named
by typed IDs (`ArtifactTarget`: a 32-hex instance, `cp-` and 32 hex, a nonzero
generation), the helper picks the executable and kiln picks the storage root. Every
worker is the configured kiln CLI with fixed, typed arguments, run by the one subprocess
runner (cleared environment, parent-death SIGKILL, killed at its deadline and reaped
before its future returns).

| Operation | Budget | Lane | Does |
| --- | --- | --- | --- |
| `capabilities` | 5 s | recovery | Group version, this helper's epoch and boot ID, whether the CLI grants leases (bit `0x40`) and lists `kiln checkpoint ls` format 1, limits, workers in use, untracked workers |
| `capture {binding}` | 300 s | copy | `kiln checkpoint capture` for `{target, operation nonce, source backend, R}`: `complete {evidence}`, `failed {reason, detail}` or `pending` |
| `restore {target, content_sha256, reader, spec}` | 300 s | copy | `kiln checkpoint inspect` (same generation and content digest), then `kiln create --from-checkpoint`: `created`, `not_created` or `ambiguous`, each with the reader's evidence |
| `inspect {target, verify, operation?}` | 30 s (300 s with `verify`) | cleanup (copy) | The namespace's view of the artifact, this epoch's activity on it, and an operation nonce's state |
| `remove {target, operation}` | 60 s | cleanup | Tombstone, cancel, wait for every reap, `kiln checkpoint rm`, then the absence checks: `absent {evidence}`, `retained {reason, detail}` or `pending` |
| `inventory {instance}` | 30 s | cleanup | That instance's artifacts, partial captures and removals, tracked operations and untracked workers |
| `acknowledge {target, operation}` | 5 s | recovery | The daemon stored that operation's evidence |

**Admission and supervision.** Two copy slots (capture, restore, verifying inspection)
and two cleanup slots (removal, inspection, inventory), separate from the helper's
operation slots. A full lane refuses at once with `workers`; nothing queues, and cleanup
never waits for copying. A capture is exclusive on its artifact and refuses `busy` beside
any other operation; restores and inspections are reader leases. Admitted capture,
restore and removal run in tasks the helper owns: the waiter's deadline, cancellation
byte or disconnect only ends the wait, with `pending`, and the outcome settles for a
later `inspect`. The worker's deadline is the request's own. A slot, lease or exclusive
hold is released only after the worker was reaped, so an unkillable worker keeps them
for ever and nothing claims cleanup.

**Epochs and nonces.** Each helper process draws a random epoch, reported by
`capabilities` and required on every other request; another epoch's request is
`stale_epoch` before anything else. An operation nonce is unique for the epoch: repeating
a settled one replays its reply, repeating a running one joins it, using it for another
artifact is `conflict`, and `inspect` of a nonce this epoch never saw retires it, so a
delayed request with it can never start afterwards. While the epoch tracks an artifact,
another generation of it is `conflict`; kiln's own record, which names the generation,
decides otherwise.

**Tombstones and removal.** `remove` first tombstones the artifact (under the same lock
every admission takes), then cancels its capture and readers. From then on nothing can
capture, restore or inspect it in this epoch, and a capture that settles afterwards is
`failed`, even if its worker exited 0. Only once every worker of the artifact was reaped
does `kiln checkpoint rm` run on the cleanup lane; then `kiln checkpoint ls` must list
nothing of it (no artifact, staging or removal), and the process table must show no
process whose arguments name it. Only then is it `absent`. A restored sandbox's shim
(a session leader) does not count: while restoring it holds the artifact's lock, which
keeps kiln's removal busy, and it never reads the artifact again. The tombstone stays
until its last worker has been quiet for 300 seconds (the longest request validity) and
the daemon acknowledged it, or for an hour unacknowledged; settled records follow the
same rule. Losing one only costs a retry: removal is idempotent.

**Evidence.** Each fact is an `Evidence` record: version, instance, checkpoint,
generation, operation nonce, helper epoch, boot ID and one fact, `complete` (kiln's
record and the binding's source and R), `absent {existed}` or
`reader_ended {copy: not_started | complete | unknown}`. Its canonical bytes are its JSON
in field order, at most 16 KiB, and its ID is `SHA-256("kilnd.checkpoint-evidence.1" ||
0x00 || bytes)`. `SealedEvidence::verify` accepts a fact only for the artifact,
generation, nonce and kind the daemon dispatched, and the runtime adapter checks every
reply that way (`CheckpointResponse::check`). Only `complete` and `not_started` copies
can release a fork's pin: `unknown` (a killed or failed `kiln create`, whose detached
shim may still be reading) keeps it until the artifact's absence.

**Restart.** Workers die with their helper (parent-death SIGKILL), so a new epoch starts
with none of its own. Its proof that an earlier epoch's straggler is gone is the process
table, read beneath the private procfs instance: any live process naming an artifact
blocks that artifact's absence, appears in `inventory` as an untracked worker (making the
inventory incomplete) and is counted in `capabilities`. An unreadable process table, or a
host with more than 65,536 processes, certifies nothing.

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
