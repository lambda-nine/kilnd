---
title: "Lambda IX Phase 1b"
subtitle: "FirecrackerRuntime and the guest broker"
author: "Stephen Estrada"
date: "October 31, 2026"
---

# 1. Decision and scope

**Build one cold-booted Firecracker microVM per kilnd sandbox/session, with one persistent kiln sandbox inside it.** Successive tool calls use `kiln exec`; each execution has kiln's separate descendant cgroup. The root helper owns every host side effect. The guest broker owns guest-side kiln operations. The harness and all model/provider credentials remain outside the VM.

This is an implementation specification, not an implemented backend or a security certification. Baseline: kilnd `734e275163bd6b028736af8261e4897d93169a5f`, helper protocol v3, SQLite schema 7, and kiln `00d61c546db7aa67ad283d10c2ca6165ca5f8166`. No production code changes accompany this document. Stephen's choices are in section 12; the recommended values below are provisional design defaults until those choices and the adversarial design review are settled.

Initial scope is Linux aarch64, cgroup v2, Firecracker/jailer 1.17.0, the approved hardened kiln-guest lineage, offline execution, no pool, no snapshot/restore/fork/pause, no guest image download, no host directory sharing, and no remote public API. Existing `KilnRuntime` remains supported and unchanged in public behavior. Choose one backend per daemon at startup using the existing generic `Manager<R: Runtime>`; do not introduce an unsupported `dyn Runtime` conversion.

## 1.1 Non-negotiable invariants

1. Authenticate the exact manifest bytes against an independently configured approved SHA-256, validate the complete schema and effective launch contract, and verify **every** artifact before creating any session disk, jail, cgroup, socket, network resource or process. Read-only preflight descriptors and bounded parser buffers are not session allocations. Recheck in the helper immediately before accepting allocation.
2. A durable daemon reservation precedes helper allocation. A durable root-owned helper intent precedes every externally visible side effect. Unknown allocation, execution cleanup or inventory is never equivalent to absence.
3. Charge configured guest RAM **plus overhead**, full private disk liability, integer vCPUs and PID allowances. Neither RSS/PSS nor THP provides an admission discount.
4. Only the helper launches jailer, configures outer cgroups or owns future TAP/nft operations. kilnd remains a non-root service with no capabilities and no direct access to VMM/device/disk control.
5. A timeout, lost connection, missing PID file, empty ordinary listing or unresponsive broker cannot release a reservation. Delete completes only after verified VMM exit and removal of all owned resources.
6. No virtio NIC in Phase 1b. Enabling networking later requires a separately approved device profile and authoritative host filtering, even against guest root.
7. No snapshots, including “warm seeds.” Reseeding cannot rerandomize the KASLR layout captured in a snapshot. Any future restore needs identity/entropy/credential refresh and disk-version binding; cross-tenant cloning needs a separate security decision.
8. Provider credentials never enter the guest, broker configuration, command environment, disks or image. The broker has no provider proxy operation. Arbitrary caller stdin/files can contain secrets; kilnd cannot detect or undo a caller deliberately supplying one.

## 1.2 Evidence update and launch-contract gate

The requested guest-contract work has arrived locally: kiln-guest `7d9d956`, with `results/launch-contract/summary.json` recording a matching A/B manifest digest:

```text
e855fbee1914cc6ea5e57a1250610e128412c85a905c94a48fb54afdaa47f3d3
```

That is **reference evidence, not approval to run this backend**. Its production contract fixes 768 MiB, one vCPU, THP, two drives, UID/GID 10000, no vsock, no outer cgroup limits and no new PID namespace. It has no broker. Silently adding vsock or changing jailer flags would violate that contract, even if the change appears safer.

Phase 1b therefore needs a new bundle/contract revision and a newly approved manifest digest. Section 3 defines the required semantics; final serialized field names and schema numbers must be agreed with kiln-guest and frozen as shared golden fixtures in build step B1. Until then the backend refuses the current production profile. There is no permissive “legacy contract” mode.

# 2. Architecture and trust

```text
harness + provider credentials (host)
          |
      kilnd.v1 / peer UID authorization
          |
kilnd: Manager + SQLite + FirecrackerRuntime (unprivileged)
          |
      typed private helper IPC, v3 envelope/receipt rules
          |
kilnd-helper (root): journal, admission recheck, jailer,
                    process/cgroup evidence, vsock relay
          |
      dedicated jail UID, PID/mount isolation, default seccomp
          |
Firecracker VMM + KVM [host-enforced outer resource boundary]
          |
      immutable guest kernel/root + private work block device
          |
/init --> guest broker (guest root, outside kiln namespace)
                    |
          one persistent kiln sandbox
                    |
          serialized kiln exec / per-execution cgroup
```

The host kernel, KVM, matching jailer/VMM, helper and operator approvals are trusted for isolation. kilnd and its account remain trusted for caller ownership and node admission. The helper narrows that authority to typed operations; it is not a second tenant authorization service. For Firecracker, unlike legacy kiln, its mutation scope is restricted to its own journaled namespace.

The broker, guest init, guest kernel and kiln are trusted for *within-session* execution reports. A guest-kernel compromise can forge a broker `Drained` report. Vsock and a nonce do not attest a guest kernel. Independent host proof that all guest commands are dead requires terminating the entire VM. The design uses that proof for timeout/cancellation after dispatch, protocol failure and uncertain cleanup. A normal successful execution can reuse the session on trusted kiln/broker evidence; mutually distrustful tenants never share that session. Do not market per-call guest status as host-verifiable attestation.

There is no Firecracker management API socket in the production profile: launch with `--no-api --config-file /config.json`. Cold boot needs no API mutation; stop uses pidfds/cgroups. This removes snapshot endpoints and a general HTTP control surface. The private vsock Unix socket is reachable only by the helper and that VM's jail UID, never exported to API callers or kilnd.

# 3. Approval, configuration and artifact preflight

## 3.1 Two separate image concepts

`SandboxSpec.image` keeps its current meaning: the inner tool rootfs, initially the approved bundled `alpine`. It is never a kernel path, bundle directory, OCI pull request or manifest digest. The boot bundle is selected by a root-owned deployment catalog, outside `kilnd.v1`:

```text
backend = firecracker
profile = offline-768-v1
approved_manifest_sha256 = <reviewed Phase 1b manifest bytes>
bundle_directory = <root-owned content-addressed directory>
firecracker/jailer = <absolute approved paths + SHA-256s>
instance_id = <durable random 128-bit daemon namespace>
vm_uid_range / vm_gid_range = <dedicated, reserved host ranges>
```

Installation creates the catalog and storage/cgroup roots, not CreateSandbox. A caller can select only an inner image present in the approved bundle's catalog. The daemon's default inner memory stays 512 MiB, CPU 1000 millis, PIDs 128 and writable quota 1 GiB. The 768 MiB VM profile accepts inner memory at most 512 MiB and CPU at most 1000 millis; larger requests fail before allocation. Do not silently clamp a request or expand the guest outside the approved profile.

## 3.2 Exhaustive preflight procedure

The manager generates instance/allocation/sandbox identity in memory before preflight, without inserting a row. The unprivileged adapter requests `Preflight` with that context; the helper independently performs the following, without session side effects:

1. Resolve the deployment profile in the root-owned catalog; do not accept caller filesystem paths. Validate trusted ancestors with descriptor-relative traversal, reject symlinks and non-regular artifact files, reject writable-by-service/jail-UID components, pin opened descriptors. Cap manifest bytes at 4 MiB and artifact sizes at catalog limits before reading. Reject duplicate JSON keys, unknown schema/fields, invalid integer ranges, extra artifacts and path components other than fixed safe names.
2. Hash the raw manifest bytes and compare to the independent approval. Never learn the approved digest from that same directory or a guest message. Authentication is distinct from kiln-guest's reproducibility comparison.
3. Validate architecture, VMM/jailer exact version and digests, kernel policy/config digest, inner image catalog and shifted ownership provenance, broker digest/protocol/capabilities, root digest, source/build provenance fields, work-disk policy and the full launch contract. All declared artifacts, including the separately retained kiln, broker and kernel config, must match size and digest. Authenticating only the artifacts actually attached to the VM is insufficient.
4. Expand the contract into a **complete** planned configuration and argv. Compare the actual objects to be serialized/launched, not a parallel description. Allowed dynamic fields are explicitly typed below. Reject extra devices, flags, duplicate flags, JSON keys, CPU templates, test parameters, debug endpoints, snapshot settings and boot-argument additions. Require guest init's production hardening checks before broker startup.
5. Validate the effective sandbox spec independently, then calculate the reservation using checked arithmetic. Reject network Full/Allow rather than silently running offline. Verify cgroup v2/controllers/`cgroup.kill`, KVM availability, mount/storage features, identity-range configuration, and binary ancestry. A read-only capability check may open `/dev/kvm` and query its API; it must not create a VM.
6. Select currently free UID/GID/CID candidates without reserving them, and generate nonce/work UUID in memory. Include these and every derived name in the exact plan. Return `PreparedCreate` including profile/manifest digest, exact effective spec digest, reservation, a versioned private plan and its digest. The manager atomically records it with the reservation. `Create` revalidates the bytes and plan under the registry/allocation locks, then atomically claims those candidates in INTENT. If another create claimed one first, fail before allocation; do not substitute another UID/CID or mutate a stored plan. The manager reports that retryable capacity collision with an uncharged failure row. A changed catalog never silently selects a different plan.

Artifacts live in a root-owned immutable/content-addressed store. Keep verified descriptors pinned through staging; do not verify one path and reopen an untrusted replacement. No jail UID can write an immutable artifact or its ancestor. Read-only bind mounts of staged kernel/root and a helper-owned config prevent a jailed process from changing those bytes. Trusted root is outside the attacker model. Revocation denies new creates/execs but **never** denies inspection or cleanup of already owned resources.

Hashing and disk preparation must not block the helper's current-thread socket loop. Use at most two supervised fixed-purpose validation workers established at service startup, with chunked reads, bounded result frames and the original deadline. No request creates a session preparation process until manifest/artifact/contract verification has succeeded. These workers get no caller-supplied executable, shell, environment or arbitrary path. Their PID/cgroup ownership is journaled before a session preparation worker starts. Startup health checks cached verified deployment identity; it does not hash gigabytes inside a two-second Health request. Cache entries must not substitute for the pre-create artifact check.

## 3.3 Required Phase 1b contract semantics

Freeze a new production-only `offline-768-v1` profile. The signed/approved manifest authenticates a template plus **exhaustive typed substitutions**, not arbitrary patches:

| Item | Required value / substitution |
|---|---|
| Boot | Cold only; exact reviewed command line and exact VMM-appended suffix; KASLR, allocation/free/stack initialization and lockdown checks remain mandatory |
| Machine | 1 vCPU, 768 MiB, SMT false, `huge_pages=Transparent`, dirty tracking false; CPU template absent |
| Drives, in order | `/kernel` boot image; `/rootfs` read-only root on vda; `/work` private writable XFS on vdb; `/identity` read-only raw identity block on vdc |
| Vsock | One device, `/vsock.sock`; guest CID from reserved integer range 3–65535; broker port 5252 |
| Network | No network-interfaces key/device, no metadata service, no TAP, no routes/NAT |
| Jailer | Matching pinned musl VMM; cgroup v2; new PID namespace; no daemonize; no API; default seccomp; fixed resource-limit recipe |
| Dynamic identity | 128-bit instance and allocation IDs; public sandbox ID; fresh boot nonce; reserved UID/GID and CID; exact derived cgroup/jail paths |
| Dynamic resources | Work disk size/UUID and validated inner spec; outer CPU/memory/PID values from the fixed accounting recipe, never arbitrary keys |
| Forbidden | Snapshot/restore, custom init/kernel args, test profiles, serial input, writable root, custom seccomp/CPU templates, extra devices or host mounts |

The identity block is a 4096-byte zero-padded raw record, no filesystem: magic `KID1`, big-endian u32 JSON length (1–4088), then canonical strict JSON. It binds instance ID, allocation ID, sandbox ID, 256-bit boot nonce, manifest digest, effective-launch digest, work UUID and inner-spec digest. It contains no reusable credential and is not proof against guest root. The launch digest covers canonical configuration/argv and the resolved resource recipe, including identity-drive presence/path; it excludes identity-block content to avoid a self-referential hash. The block's own SHA-256 is separately journaled. Init/broker must require exactly one valid record, zero padding and read-only vdc.

The exact guest command line is inherited from the newly approved bundle; initially retain the current reviewed line:

```text
console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda
rootfstype=squashfs ro init=/init loglevel=3
randomize_kstack_offset=on
```

Those three display lines serialize as one space-separated line. The current appended suffix is ` pci=off root=/dev/vda ro earlycon=uart,mmio,0x40002000`; freeze and test its actual value for the new three-drive/vsock topology. Never hard-code acceptance of an unverified changed suffix. These are build B1 exit criteria, not permission to weaken init's exact comparison.

# 4. Identities, journal and state machine

## 4.1 Names and durable ownership

Generate a cryptographic 128-bit `allocation_id` before reservation. It is distinct from the existing 64-bit public sandbox ID, and never reused. Backend ID is `fc-` plus 32 lowercase hexadecimal digits. Store `allocation_id` and the private plan in dedicated columns; **do not prefill `backend_id`**. Schema 7 treats FAILED-with-backend-ID as compensated and uncharged: pre-filling that column would create an early-release bug.

Each helper record has a version, instance/allocation/sandbox IDs, generation counter, plan/manifest/spec/launch digests, reservation, phase, UID/GID/CID, deterministic resource names, host boot ID, supervisor/VMM PID and `/proc` start time, cgroup inode, recorded artifact/work inodes, work UUID, boot nonce, last exec identity/state and stop/absence evidence. A single root-owned registry lock prevents two helper instances controlling the same namespace; per-allocation locks serialize create/exec/delete/reconcile. Generations are monotonic and use compare-and-update, not blind overwrites.

Root journal: `/var/lib/kilnd-helper/firecracker/<instance>/<allocation>.json`, mode 0600 in 0700 root directories. Update by writing an exclusive temporary file in the pinned parent, `fdatasync`, atomic rename, then `fsync` the parent before reporting durability. Sync new parent directories too. A bounded strict record with checksum detects torn/corrupt content; checksum is not authentication. Never store tenant stdout/argv/stdin here. Bound console diagnostics to 64 KiB per live VM; never use them as readiness authority.

Create first checks the token under its allocation lock. An existing allocation or conflicting plan can never be reported as DefinitelyNotCreated just because a new request fails validation; only the exact operation's no-allocation or removal proof may release its charge. A retained `ABSENT` tombstone fences every delayed/repeated Create for the same allocation. Missing journal is not an ordinary negative result: `FenceAbsent` first serializes against all accepted requests/workers, verifies the namespace and persists a tombstone. Never delete tombstones on an age timer. Initially keep a compact retired-ID ledger (64 MiB installation limit, fail new creates rather than drop fences); safe epoch-based compaction is follow-up work. API retention may delete history without deleting this replay fence.

## 4.2 Two coordinated state machines

```text
Daemon (existing states, plus additive QUARANTINED):

CREATING --ready receipt + durable publication--> READY
   |                                              |
   | ambiguous failure                            | uncertain exec/health
   v                                              v
 FAILED [charged]                            QUARANTINED [charged]
   |                                              |
   +---- exact allocation fence + cleanup ---------+
                                                  v
 READY / LOST / QUARANTINED ------------------> DELETING
                                                  |
                                        durable absence receipt
                                                  v
                                               DELETED

CREATING --pre-allocation rejection--> FAILED [uncharged]
CREATING --proven compensation-------> FAILED [uncharged]
READY --proved no live VM-----------> LOST [still charged]
```

```text
Root helper allocation journal:
INTENT -> PREPARING -> SPAWN_INTENT -> BOOTING -> READY
                                               |    |
                                               |    +-> EXEC_INTENT -> BUSY
                                               |                         |
                                               +-------- IDLE <----------+
any potentially allocated state -> STOP_INTENT -> STOPPED -> CLEANING
                                                        -> ABSENT (fenced)
uncertain identity / corrupt evidence -> QUARANTINED (no release)
```

`STOPPED` proves no execution remains but may still own disk/jail/cgroup state. Only `ABSENT` proves release. READY/IDLE identifies the same boot nonce and persistent inner sandbox; guest restart never silently resumes the session. The public `QUARANTINED` state means cleanup/reusability cannot be established, not that resources have disappeared.

## 4.3 Create ordering and crash matrix

Create is supervised by the daemon after acceptance, independent of its RPC waiter. A repeated helper Create with the same allocation/plan is an idempotent query/continuation, never a second VM. A new public Create retry is still a new sandbox; public idempotency is not smuggled into this milestone.

| Boundary | Durable action before proceeding | Crash/restart behavior |
|---|---|---|
| C0: preflight | No session resources; full approval/artifact/contract check | Reject safely; no reservation if not yet inserted |
| C1: reserve | SQLite IMMEDIATE: CREATING + owner UID + allocation/plan + explicit reservation | No helper record is ambiguous until FenceAbsent excludes a delayed Create and all resources |
| C2: helper accepts | Recheck plan; persist INTENT and reserved UID/GID/CID plus all names | Inventory by allocation even if no backend ID was returned; same token cannot allocate twice |
| C3: prepare | Persist PREPARING before disk, identity block, jail mounts or outer cgroup | Partial files/mounts/cgroups are owned, remain charged; cleanup exact recorded namespace |
| C4: spawn | Persist SPAWN_INTENT; child held at a parent gate until identity recorded | Gate EOF kills unlaunched child; stopped child is inside recorded containment before release |
| C5: boot | Persist supervisor/VMM identities and BOOTING before bootstrap can be acknowledged | Recover by host boot ID/start-time/cgroup, not PID number or API liveness; unknown means quarantine |
| C6: ready | Validate broker/identity/persistent sandbox; persist READY receipt | Lost reply can be queried by allocation. Adopt only an identical live boot with no uncertain exec |
| C7: publish | SQLite transaction writes READY/backend ID/boot identity/receipt generation | Crash before commit: CREATING can adopt C6; failure to publish triggers recorded compensation, never blind release |
| C8: compensate | Persist daemon DELETING where possible; helper STOP_INTENT regardless of daemon write failure | Return no ready result. Keep charged until helper ABSENT and one durable terminal/release update |

A crash between any two syscalls in C3 is covered by the prior full resource-name intent. Before launch the helper records a fixed-function supervisor child PID/start time, using a stopped-child handshake. The supervisor enters the per-session containment cgroup, arms and retains a parent-death signal with the post-arm PPID check, and launches jailer. The signal is handled by the supervisor as a stop request; no signal handler performs blocking cleanup. Its main loop kills the owned cgroup on helper loss, and journal recovery is the fallback if it dies before doing so. The supervisor survives ordinary kilnd restarts; it must not rely on kilnd's connection lifetime. If the helper itself dies, the supervisor kills the owned cgroup/VMM and exits; restart confirms completion. A helper restart may therefore lose sessions but never orphan unaccounted VMs. Use the journal and cgroup as fallback if parent-death signaling races or the supervisor is killed.

With `--new-pid-ns`, the jailer PID is **not** necessarily the VMM PID. The supervisor is a subreaper, opens a pidfd for the actual child, validates the jailer's PID-file candidate against start time, executable and cgroup membership, and retains evidence for both. A PID file alone is never enough. On restart, open a fresh pidfd and revalidate boot ID/start time/membership before signaling; a mismatch must not kill an unrelated reused PID. Killing a verified allocation-owned cgroup can settle a missing PID file.

No cross-database atomic transaction is claimed. Receipts/generations are the bridge: helper durable evidence first, daemon durable publication second. If the daemon database is unavailable, no admission is released, even after real cleanup. Retry publication with the existing bounded backoff/health degradation.

# 5. Guest broker and execution protocol

## 5.1 Placement, privilege and kiln integration

Recommend a Rust workspace binary `kilnd-guest-broker` in kilnd, baked at a pinned commit/digest into kiln-guest. It runs as guest root, launched and reaped by compiled `/init`, outside the persistent tool sandbox. Root is necessary for the existing kiln CLI's namespaces, UID maps, mounts and cgroups; claiming an unprivileged broker while delegating nothing would be false. It offers only typed initialization, validation and kiln execution, not an arbitrary guest-root shell.

Init first validates runtime hardening and mounts immutable root, bounded tmpfs and private XFS with `nosuid,nodev,noexec,prjquota`. The Phase 1b offline boot path omits external DNS/network bootstrap. It starts the broker with a cleared environment, fixed PATH, core dumps disabled, `no_new_privs`, a bounded FD limit, private broker state under `/run/kilnd-broker`, and no serial stdin. It monitors broker death and powers off on failure; no broker auto-restart around a potentially running command.

Keep broker/kernel memory outside the inner tool cgroup. Broker's only executable is the pinned `/usr/local/bin/kiln`; users' argv appear exclusively after `--` on `kiln exec`. It validates the CLI capability bits and scoped GC contract, then uses the existing fixed argv mapping:

```text
/usr/local/bin/kiln create --require-exec-protocol=1
  --image=alpine --memory=<inner_bytes> --cpus=<decimal_cores>
  --pids=<inner_pids> --disk=<inner_bytes> --net=none
  [--read-only --writable=<validated_path> ...]

/usr/local/bin/kiln exec --protocol=1 --status-fd=<owned_fd>
  --stdin-fd=<owned_fd> --stdout-fd=<owned_fd>
  --stderr-fd=<owned_fd> <validated_inner_id> -- <literal_argv...>
```

These are argv arrays, not shell strings. Labels are metadata and do not become root flags. The work disk persists between calls; each exec has a fresh kiln execution cgroup, but files and persistent sandbox PID 1 survive. Do not create a fresh inner sandbox for every call unless a later explicit mode specifies its storage/cleanup semantics.

Reuse/extract kilnd's reviewed direct-kiln process/status/capture/validation core into a small library; do not copy kiln runtime code or reimplement its machine protocol independently. The broker does not need the host's gRPC server, SQLite, API ownership or root-helper listener. Guest CLI clients retain parent-death signals and post-arm PPID checks. A future root broker split can reduce its parser privilege, but is not claimed here.

## 5.2 Transport and framing, broker protocol version 1

Helper connects to the exact recorded jail's `/vsock.sock`, checks inode/ownership and VMM identity, writes `CONNECT 5252\n` and reads a bounded `OK <decimal host-port>\n` (at most 32 bytes, two seconds). The returned port is an assigned **host** port, not necessarily 5252. The broker accepts AF_VSOCK host CID 2 only. It does not open guest-initiated host channels. No host `_PORT` listeners are installed. This follows the pinned [Firecracker vsock transport](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/docs/vsock.md).

There are at most two broker connections: one exec channel and one reserved control/health/cancel channel. No unbounded accept backlog (backlog 4); refuse excess connections and unknown peer CID before parsing. Channels have independently bounded writes/reads, so output backpressure cannot block cancellation.

Every frame has a fixed 36-byte header, integers in network byte order:

```text
magic[4] = "KGB1"
version:u16 = 1
kind:u16
flags:u32 = 0
payload_length:u32
request_id:[u8;16]
sequence:u32
payload[payload_length]
```

Control payloads are strict UTF-8 JSON, `deny_unknown_fields`, duplicate-key rejection, no floats, no JSON recursion beyond 8 and no strings beyond their field bound. Control frames are at most 384 KiB (argv is at most 256 KiB plus JSON escaping overhead: **also reject if encoded size exceeds 384 KiB**). Data frames are raw bytes, at most 64 KiB. The 4096-argument/256-KiB validation remains, with the encoded control limit an additional backend limit. Never allocate from an unchecked length. Types, order, request ID, per-direction sequence starting at zero, and total bytes are checked before dispatch. Overflow, trailing bytes after terminal close, duplicate terminal, unknown flags/version/kind and premature EOF are protocol failures.

Limits: stdin 1 MiB total; stdout/stderr retained prefix at most 1 MiB each; 64 KiB CLI diagnostics; diagnostic messages 2048 UTF-8 bytes. The broker drains/counts output after its retained prefix fills, with checked u64 counters. It does not buffer unbounded output or forward an unbounded stream to the host. The maximum resident payload/capture budget per active exec is 4 MiB plus fixed parser overhead, included in guest headroom.

Every frame has a two-second assembly/transfer deadline, started at the first header byte and never extended by trickling. Idle exec channels may wait for execution only until their execution deadline; the control channel uses two-second request/response bounds. Stdin must finish within two seconds of Exec acceptance or the remaining execution budget, whichever is smaller. No service busy-loop or blocking socket I/O: host helper uses per-syscall `MSG_DONTWAIT`, including Unix shutdown; broker uses nonblocking vsock reads/writes and readiness polling.

## 5.3 Message set and session binding

| Kind | Fields / behavior |
|---|---|
| `Hello` (1) | Host challenge[32], expected instance/allocation/sandbox IDs, boot nonce, manifest/launch/spec digests, supported protocol=1; one per connection before any other verb |
| `HelloReply` (2) | Echo challenge, identity from vdc, guest kernel boot ID, broker build digest, kiln CLI protocol/features, runtime-hardening booleans, work UUID/mount flags, persistent inner ID if already initialized |
| `Initialize` (3) | Exact inner spec, spec digest; allowed once per cold boot after Hello; a duplicate identical request returns the same result, a conflicting one closes/quarantines |
| `Ready` (4) | Bound identity/digests, inner ID, execution capability bits, idle=true, work quota verified, boot ID; emitted after persistent create and a supervised `true` smoke exec have drained |
| `Probe` (5), `ProbeReply` (6) | Expected boot/inner IDs; idle/busy and active execution token; no create/restart/mutation |
| `Exec` (7) | Execution token, public execution ID, argv, stdin_bytes, max_output, remaining_ms; only in initialized idle state |
| `Accepted` (8) | Execution token accepted, not a promise a child started; followed by stdin frames |
| `Stdin` (9), `StdinEnd` (10) | Declared bytes exactly, one end; no command starts before full validation/EOF equivalent |
| `Cancel` (11), `CancelAck` (12) | Execution token and typed reason; idempotent on active token, never cancels another token; acknowledgment is not cleanup proof |
| `Stdout` (13), `Stderr` (14) | Retained raw prefixes after execution settles; contiguous sequences, bounded totals |
| `Result` (15) | Typed finish, optional command termination, runtime diagnostic, both capture facts, cleanup evidence, inner ID and token; one final frame then clean write EOF |
| `Error` (16) | Bounded typed protocol/admission/incompatibility error; no success/absence inference |

For control-only exchanges request IDs are random. Exec request IDs are the execution token; reconnect never resends an Exec. New Hello challenges prevent stale responses on a reused path. The helper compares identity to its journal and independently observed process/cgroup, not to fields supplied by the guest alone. The bootstrap record proves routing and freshness under the trusted-image assumption; it is not a provider secret, bearer authorization for other sessions, or remote attestation.

Ready requires the newly approved init hardening checks, the broker handshake, successful persistent kiln initialization and empty execution cgroup. Serial `KG_READY`/`KG_FIRST_COMMAND` may be collected as diagnostics but cannot independently authorize readiness. The current guest's markers refer to a different initialization flow; update its definition and benchmark labels in B1/B5.

A guest cannot echo its enclosing rootfs's manifest hash by embedding that same final manifest recursively. Instead vdc supplies the host-pinned bundle identity; the broker separately reports its compiled build identity, kernel and kiln capabilities. Artifact authenticity is established on the host before boot, not from the echoed digest.

## 5.4 Time, output and typed outcomes

The API's one absolute host Tokio deadline still includes queueing, pre-exec probes and transport. The helper uses the same host `CLOCK_MONOTONIC` deadline carried by private IPC. Guest monotonic clocks have a different origin: **never copy host `deadline_ns` into the guest clock**. At send time compute a checked, rounded-down remaining millisecond budget (1–3,600,000); the broker starts its own deadline at acceptance. The helper's original host deadline is authoritative and may expire earlier. Any remaining value of zero prevents dispatch. Retries do not reset a budget.

`Result.finish` is Completed, TimedOut, Canceled or Failed(kind, stage); termination is Exited(code) or Signaled(signal, core_dumped), independently optional. Preserve real exits 124/125/126/127 and distinguish signal 15 from exit 143. Cleanup is `NoChildStarted`, `GuestCgroupDrained` or `Unknown`; the host can additionally establish `VmStopped`. Only trusted guest core logic emits the first two, never CLI stdout or an exit-code heuristic. Final frames carry kept length, observed total, total-known and truncated for each stream; EOF after both prefixes and the final frame is required. An interrupted result transfer preserves received bytes as lower bounds; do not promote the guest's unseen total to exact host capture evidence.

Normal completion requires the kiln private v1 status/EOF and the guest-side execution cgroup barrier; independently read `cgroup.events` populated=0 where needed, not `kill(pid, 0)`, process group exit, a socket close or `kiln exec` exit alone. Drain capture readers through cleanup, settle them with the existing two-second EOF rule, close all per-exec descriptors, and verify the persistent sandbox is idle before `Result`/reuse. A descendant using `setsid`, double fork or inherited pipes must remain in the execution cgroup.

## 5.5 Cancellation, distrust and durable exec ownership

The host helper journals `EXEC_INTENT {token, public_execution_id, boot_id}` **before sending Exec**, and `BUSY` on acceptance. Only one execution can be in flight; the broker never queues work. kilnd retains its existing one-running/eight-queued bound and durable RUNNING row before dispatch. The helper marks IDLE only after full validated result transfer and cleanup evidence; the daemon then publishes its terminal execution atomically before releasing its slot.

On timeout, RPC disconnect, Delete, shutdown or transport/protocol failure after dispatch:

1. Mark the allocation stopping/quarantined and stop admitting execs. Send Cancel on the reserved control channel; a missing/blocked channel does not delay escalation. The broker kills/reaps the kiln CLI, lets kiln PID 1 drain, and checks its cgroup independently.
2. **Default policy: retire this VM even if the broker says Drained.** Allow at most two seconds for cooperative guest output settlement, then use the helper's pidfd/cgroup stop barrier. This provides host-owned proof that no guest descendant remains and avoids trusting a compromised broker after interruption. It sacrifices the session; no invisible replacement/reboot is allowed.
3. Wait for VMM/supervisor exit and allocation cgroup populated=0. Verify identities before signals; use `cgroup.kill` for surviving owned tasks. If not settled within the 60-second cleanup attempt, return CleanupFailed with disposition Quarantined, hold durable reservations and refuse further Exec. A cleanup worker remains journal-owned/retryable; no success is claimed.
4. With host stop proof, a genuine timeout/cancel may return TimedOut/Canceled **with `reusable=false`** and the sandbox becomes LOST. A protocol/cleanup error remains Failed even if teardown succeeded. Observed command termination and output prefixes remain separate evidence. Delete subsequently removes the disk and all other resources before capacity returns.

Pre-dispatch cancellation with proof no Exec bytes could have been sent can preserve the ready VM. A normal completed result that was validated before the first cancellation wins over a later disconnect, as today. If the daemon/helper crashes during EXEC_INTENT/BUSY, startup stops the VM; it never retries the command or adopts the session based on a later “idle” claim. Mark the execution INTERRUPTED only after the host stop barrier, or FAILED/CleanupFailed with quarantine if that barrier is unavailable. Reconnection is for observation/cleanup only; commands are not replay-safe.

This intentionally extends the Runtime contract: cleanup success no longer always means reusable sandbox. Section 9 makes that explicit for every caller and test; otherwise a builder could accidentally run the next queued command in a retired guest.

# 6. Typed Firecracker helper operations

## 6.1 Private transport compatibility

Add `Operation::Firecracker(FirecrackerRequest)` alongside `Operation::Kiln`. Preserve the v3 envelope, fixed 2 MiB outer frame bound, absolute monotonic deadline, no incoming descriptors, strict fields, root/service-UID peer checks and helper-created Exec stdio pairs. For Firecracker Exec send the three **opposite** endpoints and wait for the same receipt byte before dropping handoff copies or doing I/O. Continue `MSG_DONTWAIT` on every helper read/write; never reintroduce caller-shared open file descriptions or wait for output on the listener thread.

Use an explicit Firecracker group schema version 1 inside the v3 request. Old v3 helpers reject the unknown operation; backend capability preflight must detect that before CREATING. If shared response structs change incompatibly for the legacy kiln branch, bump the whole helper protocol instead; do not silently broaden the v3 kiln contract. Prefer a new `Response::Firecracker(FirecrackerResponse)` so old kiln responses remain unchanged. Snapshot and raw API/argv/path verbs do not exist.

All requests carry the existing outer deadline/cancel and an exact `instance_id`. Allocation selectors are typed 128-bit IDs, never paths. Profiles are root-catalog names (ASCII `[a-z0-9-]`, 1–64 bytes). Digests are exactly 32 bytes encoded as 64 lowercase hex characters. No operation accepts a PID, UID, CID, host path, nft source, environment or executable from a public caller. The helper derives identities from its own registry; Create's plan must match its own recomputation.

| Request | Fields in addition to instance/group version | Reply and validation |
|---|---|---|
| `Capabilities` | none | Group/broker versions, available approved profiles and backend build; read-only, no boot. Cached identity with invalidation; two-second health budget |
| `Preflight` | allocation_id, sandbox_id, profile, effective `SandboxSpec` | Validated plan/reservation/digests; complete section 3 checks. At most 30 s, no session allocation |
| `Create` | allocation_id, sandbox_id, plan, plan_digest | Ready receipt/backend ID, typed pre-allocation failure or ambiguous failure. Recheck manifest, exact config and limits; journal first; 120 s total |
| `Inspect` | allocation_id | Exact PresentReady, PresentBusy, StoppedWithResources, AbsentFenced, Incompatible or Unknown evidence; no restart or cleanup; at most 5 s |
| `Validate` | allocation_id, expected boot ID/nonce, expected inner ID | Process/journal and broker capability/idle validation; no absence from socket failure; at most 5 s and remaining exec budget |
| `Exec` | allocation_id, expected boot ID, execution token/public execution ID, argv, stdin_bytes, max_output | Existing typed outcome plus reuse/cleanup disposition; 3,600 s cap; owns cancellation through stop barrier |
| `Stop` | allocation_id, expected generation, reason enum | Host stop receipt or Unknown/CleanupFailed; journal fence first; no disk deletion; at most 60 s per attempt |
| `Remove` | allocation_id | Persist stop intent, stop VM, remove exact owned resources and persist ABSENT; idempotent; at most 60 s per attempt |
| `List` | none | Complete root-journal inventory plus namespace/process/cgroup cross-check; snapshot generation and explicit complete=true; at most 30 s |
| `Gc` | unique allocation_ids, at most 1024 | Only named, proven dead/stale allocations; skips/refuses live or unknown; empty is no-op. Returns individually proven removal receipts; at most 30 s |
| `FenceAbsent` | allocation_id, sandbox_id, expected plan digest | For missing/unpublished Create recovery: serialize, reject/settle all delayed writers, inspect all derived resources, persist absence fence. Any conflict stays ambiguous; at most 30 s |

`Stop`/`Remove` are authorized containment, not a way to release capacity on a timeout. A deadline or disconnect ends an **attempt**, records retryable stop intent and returns inconclusive if evidence is unfinished. Accepted mutation ownership moves to a bounded helper supervisor, not the request future. Hard-killed/unreapable tasks can outlive an attempt; they retain journal, reservation and a health fault. The daemon's reconciliation worker retries with bounded backoff. A successful receipt includes instance/allocation, generation, plan digest and relevant process/absence observations, and only follows durable journal publication.

Legacy helper limits still apply: 64 operations overall, bounded stdin/argv/output and no arbitrary flags. Within those slots reserve four for Inspect/Stop/Remove/recovery; at most two simultaneous preparation jobs and one exec per allocation. Non-exec deadlines always use the original wire deadline, never fresh internal budgets. Return RESOURCE_EXHAUSTED on full sub-budgets; do not queue unbounded privileged jobs. Healthy sessions can survive kilnd restart; active helper requests lose their waiter, but their cleanup responsibility does not disappear.

## 6.2 Exact default launch

Install pinned binaries at root-owned paths:

```text
/opt/kilnd/firecracker/1.17.0/firecracker
/opt/kilnd/firecracker/1.17.0/jailer
```

For allocation `A` (32 hex digits), jailer ID is `fc-A`, jail root is `/var/lib/kilnd-helper/jails/firecracker/fc-A/root`, and the cgroup path is `kilnd-firecracker/I/fc-A` relative to cgroup v2 root, where `I` is the instance ID. The helper owns and pins the parent; jailer receives no externally supplied paths. Use sufficiently short fixed roots to keep Unix socket paths under Linux's limit; reject a deployment whose derived `/vsock.sock` path does not fit before creating it.

The helper precreates the session cgroup with `memory.max=939524096` (896 MiB), `memory.swap.max=0`, `memory.oom.group=1`, `pids.max=32`, `cpu.max="100000 100000"`; enables controllers in the ancestors, with no tasks in those internal nodes. The session leaf has no subtree controllers. The fixed supervisor enters this leaf before launching jailer. The helper verifies the leaf's inode and settings. No late migration of already allocated guest RAM is acceptable.

Construct this exact argument vector (display wrapping only):

```text
/opt/kilnd/firecracker/1.17.0/jailer
  --id fc-A
  --exec-file /opt/kilnd/firecracker/1.17.0/firecracker
  --uid U --gid U
  --chroot-base-dir /var/lib/kilnd-helper/jails
  --cgroup-version 2
  --parent-cgroup kilnd-firecracker/I/fc-A
  --new-pid-ns
  --resource-limit no-file=256
  --
  --no-api --config-file /config.json
```

`U` comes from the helper-reserved UID/GID range (recommend 300000–365535 after checking NSS/subuid/subgid and existing allocations), never from the API. There are deliberately **no** `--cgroup` arguments: in v2 mode the pinned jailer then joins the already configured parent path directly. Because a missing path would otherwise be silently ignored, the supervisor must already be in the verified leaf, and membership is checked again before readiness. `--new-pid-ns` changes PID ownership; use the supervisor rules in section 4.3. These semantics and supported flags are from the pinned [jailer contract](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/docs/jailer.md).

Jailer itself adds the Firecracker ID. The resulting VMM invocation is `/firecracker --id fc-A --no-api --config-file /config.json` inside its jail. The wrapper sets empty environment, stdin `/dev/null`, bounded captured stdout/stderr, no core dumps and its own restrictive umask. The supervisor unshares a network namespace with no configured links/routes before jailer; there is no host-network fallback. No `--daemonize`, custom seccomp, API socket, PCI flag or inherited extra FD is permitted.

Exact default config after CID substitution (key order immaterial, drive order material):

```json
{
  "boot-source": {
    "kernel_image_path": "/kernel",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rootfstype=squashfs ro init=/init loglevel=3 randomize_kstack_offset=on"
  },
  "machine-config": {
    "vcpu_count": 1,
    "mem_size_mib": 768,
    "smt": false,
    "huge_pages": "Transparent",
    "track_dirty_pages": false
  },
  "drives": [
    {"drive_id":"rootfs", "path_on_host":"/rootfs",
     "is_root_device":true, "is_read_only":true},
    {"drive_id":"work", "path_on_host":"/work",
     "is_root_device":false, "is_read_only":false},
    {"drive_id":"identity", "path_on_host":"/identity",
     "is_root_device":false, "is_read_only":true}
  ],
  "vsock": {"guest_cid": 3, "uds_path": "/vsock.sock"}
}
```

CID 3 above represents one reserved CID; use the allocated value. The approved schema explicitly authenticates that substitution. Firecracker defaults not represented in this config are fixed by the approved VMM version and the schema's absence requirements; changes to those defaults require review/repinning, not an untracked upgrade.

The helper service needs writable exceptions for its journal/jails and delegated cgroup subtree, plus KVM access. The current kiln-only capability set lacks jailer device-node/chroot authority: add only tested `CAP_MKNOD` and `CAP_SYS_CHROOT` where the pinned jailer requires them, retaining the existing namespace/UID/ownership capabilities. Verify actual effective/permitted/bounding/ambient sets. VMM must have UID/GID U, empty supplementary groups and **zero capabilities including ambient**, `NoNewPrivs=1`, default Firecracker seccomp and inherited service filters. No host AF_VSOCK permission is needed: the helper uses AF_UNIX. Do not remove Phase 0's address-family/personality/realtime/kernel-log filters to make launch work; integration must resolve any exact required delta and document it.

## 6.3 Later networking, explicitly not implemented here

There is no general `Tap`, `RunNft` or Firecracker API passthrough request. A later version may add a typed `NetworkPolicy` to the approved Create plan, internally causing helper-owned TAP creation and fixed nft transactions. It must journal names/ifindices and default-deny policy **before** the NIC becomes usable. An unsupported network request today is rejected before allocation.

That later gate requires per-session source MAC/IP validation; IPv4 public-destination filtering including private, link-local, metadata, multicast and host services; explicit IPv6 denial until supported; established return traffic only; constrained DNS; no guest-to-guest routes; anti-spoofing; and atomic ruleset installation/recovery. No global firewall flush, default-policy relaxation or shared mutable test address. Guest kiln policy only narrows the host policy. Removal disables the TAP before deleting nft rules; incomplete policy restore quarantines the VM. Reuse Phase 0's validators and DNS confinement tests, but never mistake guest nft for the outer wall.

# 7. Storage and resource admission

## 7.1 Private work disk and quota

The immutable Squashfs root and kernel are verified once per create from the approved store and attached read-only. No workload writes to them. Create uses an exclusive, regular, single-link private work file in the owned session directory, with no symlink traversal. There is no shared writable seed, host directory mount, tenant-supplied block image or host mount of a guest-written filesystem.

Let `D` be the requested inner writable quota. Set:

```text
W = max(512 MiB, round_up(D + 256 MiB, 64 MiB))
reserved_host_disk = W + 128 MiB
```

The 256 MiB leaves guest XFS/kiln bookkeeping headroom; 128 MiB covers per-session staging, identity, bounded console/journal and filesystem metadata allowance on the host. Reject if the approved artifact/staging footprint cannot fit that allowance. For the existing 1 GiB default quota, W=1280 MiB and host reservation=1408 MiB. Keep the inner quota intact; the larger device is not an enlarged workload promise.

The helper checks logical node disk reservations in kilnd and real storage headroom, then uses `openat(O_CREAT|O_EXCL|O_NOFOLLOW)` and full `posix_fallocate`/equivalent allocation for W. Unsupported preallocation fails; do not silently fall back to a sparse promise. Before formatting, persist the work file's inode/size and a fresh UUID. Execute the fixed host binary:

```text
/usr/sbin/mkfs.xfs -q -f -K -m uuid=<fresh-uuid> <derived-work-path>
```

Pin the installed formatter path/version through deployment configuration; the path above is the supported Ubuntu layout. `-K` prevents discard from undoing preallocation. Format only the new helper-created inode, before guest exposure, using a trusted path under the pinned directory and checked identity before/after. Sync the formatted file and parent before launch. No mkfs or repair operation ever runs on a disk after a guest has written it. Set the work inode to jail UID U, mode 0600; identity/config are read-only. Bind mounts/cleanup use recorded inode identity and mount IDs, not recursive deletion through arbitrary names.

Guest init mounts vdb at `/var/lib/kiln/runs` with `nosuid,nodev,noexec,prjquota`. Kiln creates its normal XFS project quota for the persistent sandbox, bounding blocks **and** inodes as in the current backend. Probe the live quota before Ready. Test direct work-path execution denied and normal overlay execution allowed; noexec on the underlying disk is not a claim that tool binaries cannot run.

The work file's fixed W bounds guest-root writes even if guest quota enforcement is bypassed. Full preallocation and a dedicated host storage budget prevent sparse-write overcommit; node storage must leave independent space for host services, SQLite and the immutable bundle store. If host XFS is available, additionally apply a host project hard quota to the entire session directory at its reserved disk size, but do not make guest XFS quota depend on host XFS availability. Cap non-work files explicitly on hosts without host project quotas.

Delete closes VMM/worker FDs, proves process exit, unmounts owned bind mounts (no lazy-unmount-as-proof), removes owned socket/device/file entries and private disk, syncs parents and removes the empty cgroup. Refuse unknown replacement inodes or mounts. Work deletion is destructive and authorized by DeleteSandbox; no export or disk retention is implied. Deleted blocks, DB/WAL and backups are not securely erased. Encryption/export/snapshots are separate features.

## 7.2 Durable reservation vector

Add an explicit stored reservation independent of `SandboxSpec`. Do not recalculate surviving reservations from today's defaults or a newly selected bundle. Schema migration preserves all legacy kiln charges exactly. The new Firecracker formula is versioned in the stored plan:

| Dimension | Phase 1b reservation / enforcement |
|---|---|
| Memory | Guest G + 128 MiB provisional host VMM/KVM/cache/supervisor allowance; default 896 MiB. Outer memory.max equals this; swap.max=0; oom.group=1 |
| Guest headroom | Inner workload <= G−256 MiB; kernel/broker/init/filesystem activity use that remaining guest capacity; it is **inside G**, not added again |
| CPU | 1 integer vCPU plus 1000 host CPU millis per VM; outer cpu.max one core; inner quota <= one core. No overcommit by default |
| Workload PIDs | Existing `spec.pids` promise (default 128), enforced by kiln inside guest |
| Guest service allowance | 32 additional guest tasks, planning charge; bounded broker/init services and FD limits |
| Host PIDs | 32 per session, enforced by outer pids.max, including supervisor/jailer/VMM threads and session preparation workers; measure before raising |
| Existing node PID sum | Conservatively sum workload + guest allowance + host allowance (192 default). Also expose host-PID subtotal; guest processes are not host tasks |
| Disk | W+128 MiB as above, not D and not current `du`; shared installed artifacts have a separate operator-provisioned storage budget |
| Sandbox count | One per session; booting, quarantined, deleting and ambiguous allocations all count |

128 MiB host overhead is a conservative initial **assumption**, not a measured worst-case bound. The spike's 32 MiB proposal predates the broker/production containment. The density test measured about 770 MiB PSS for a 768 MiB hardened guest, but excludes some external KVM/kernel costs and workload pressure. An outer OOM remains possible inside an inadequately sized allowance; it must be contained and reported. Stress measurement is a release gate before treating this as a supported production sizing profile.

Atomic admission uses the existing SQLite IMMEDIATE sum-and-insert transaction, now across the stored reservation vector. Add node ceilings for host CPU millis, vCPU slots and host PIDs, using checked arithmetic. Default VM profile: max three sessions, memory 3 GiB, vCPU slots 3, CPU 3000 millis, existing PID budget 2048 (plus explicit host-task budget sized for those sessions and the shared helper), and disk 16 GiB. Admission rejects on **any** dimension. Host system/service headroom is outside these sandbox budgets; configuring a budget larger than physical safe headroom is an operator error that startup should detect where measurable.

| Guest profile | Inner memory ceiling | Charge per VM | Memory-only capacity in a 3072 MiB sandbox budget |
|---|---:|---:|---:|
| Recommended 768 MiB | 512 MiB | 896 MiB | 3 (2688 MiB reserved, 384 MiB left) |
| Candidate 512 MiB | 256 MiB | 640 MiB | 4 (2560 MiB reserved, 512 MiB left) |

The 512 MiB profile needs its own approved launch contract and workload validation; it cannot preserve the current 512 MiB inner default. Four smaller sessions also require four vCPU slots/CPU capacity and adequate disk. If “3 GiB node” means **total physical RAM**, not kilnd's sandbox budget, reserve at least 512 MiB for host/services first: at a 2560 MiB sandbox budget the corresponding memory-only limits are two 768 MiB guests or four 512 MiB guests. These are arithmetic planning limits, not measured workload-density claims.

No pool members initially. A future pool size of one is a fresh cold-booted, never-used guest charged exactly like a session, including disk, PIDs and CPU. It would leave only two active 768 MiB sessions while maintaining one spare in this budget. Assignment would atomically transfer ownership/reservation, never double-free or recycle a tenant-used disk, and requires a new readiness/identity contract. Do not implement “pool=1” by cloning a snapshot.

# 8. Delete, list, GC, reconcile and retention

## 8.1 Delete ordering

Authorize owner/root before helper work. Under the existing stable per-sandbox coordination slot, durably change to DELETING with compare-and-set before canceling a running execution. Queued execs reload state and refuse. Serialize all Delete callers; followers return the same final row/timestamps.

Helper Remove persists STOP_INTENT and an irrevocable create/exec fence. Stop the VMM even if the broker is unavailable; guest shutdown may be attempted for at most two seconds but is never required proof. Wait for VMM and all supervisor/preparation tasks to exit, empty cgroup, FD/device closure and all owned mounts/files/sockets to be removed. PID reuse, inconsistent resource identity, EBUSY or an expired proof attempt returns Unknown/cleanup failure. Persist ABSENT after directory sync, then return the removal receipt. Only the daemon's subsequent durable DELETED/release transaction frees admission.

If a crash occurs after VMM exit but before file cleanup, STOPPED remains charged. After resource removal but before ABSENT, re-inspect and finish the tombstone. After ABSENT but before SQLite commit, replay the same receipt and complete publication. Disk ENOSPC/fsync failure must never manufacture absence. A wholly missing record can only become an absence receipt through FenceAbsent. `RuntimeError::NotFound` by itself is not sufficient for the new path.

## 8.2 Inventory and scoped collection

`List` combines the root journal, fixed owned filesystem namespaces, cgroup membership and process identity. Read under a registry generation snapshot; retry a bounded number of times on concurrent mutation or return inconclusive. Include allocations that never reached ready/backend-ID publication. A complete response is bounded to 1024 active allocations and 1 MiB encoded inventory; excess/duplicates/corruption/partial frames are errors, not a truncated “complete” list. Retired fences use their separate compact ledger, not live listing slots.

Return each record's generation, allocation ID, plan digest, status and ownership scope. Status is Ready, Busy, StoppedWithResources, Stale, Quarantined or Unknown; only a healthy idle handshake is reusable. A missing process does not imply a missing work file; a missing journal with an unexplained cgroup/jail makes inventory incomplete. Never adopt an unknown directory solely because it looks like `fc-*`. Unknown resources block new allocations within the affected registry until resolved, remain visible to operators, and are not globally garbage-collected.

`Gc(ids)` accepts only this instance's recorded, individually proven dead/stale allocations and removes their remaining resources through the same absence barrier as Remove. It does not kill live VMs, even if not in the daemon's current API list. Recheck live identity under the per-allocation lock immediately before acting. No empty/global GC and no deletion of another daemon's or legacy kiln's resources. Return individual receipts; partial progress followed by error remains discoverable and charged until durably reconciled.

## 8.3 Startup and periodic reconciliation

Hold existing state/socket ownership locks and the helper registry lock before action. First validate all inventory/compatibility evidence without changing daemon rows or GC state. Never mark omitted sessions LOST from an incomplete list. Then reconcile exact allocation tokens:

- CREATING + identical helper READY/IDLE + no uncertain exec: re-handshake the same boot, publish READY. CREATING with partial allocation: fence/compensate, not another boot. Missing helper record: FenceAbsent, or charged failure if that proof cannot finish.
- READY with healthy identical boot and no execution ambiguity: preserve. Helper BOOTING/unknown boot, broker identity mismatch or incompatible deployment: quarantine, never declare Ready. Proven VMM absence becomes LOST but remains charged until resource cleanup/Delete.
- RUNNING execution or helper EXEC_INTENT/BUSY across a process crash: stop the VM, establish host cleanup, publish INTERRUPTED and LOST together (or cleanup failure/QUARANTINED). Do not mark an execution interrupted and immediately dispatch its queued successor before cleanup.
- DELETING: retry Remove and publish its durable absence. FAILED-with-allocation and unreleased reservation: compensate by exact token or retain quarantine; unlike the legacy no-ID failure, this allocation can be accounted for.
- ABSENT helper receipt + charged daemon row: release only through the matching terminal transaction. LOST is not automatically rebooted. A stopped boot never resurrects; an unchanged live VM temporarily unavailable to observation can recover only if no stop fence/uncertain execution exists.
- Helper-owned resource absent from daemon DB: report/quarantine the registry and reject new admission; do not invent an owner, release unknown capacity or delete live work. An operator-restored stale DB is not silently reconciled by guessing.

A host reboot invalidates all recorded PID identities. It does not erase work disks, jail state or reservations. Confirm old processes cannot exist via the changed host boot ID, then remove remaining owned resources normally. If proof is unavailable, serve degraded read/authorized cleanup operations where possible, deny Create/Exec and preserve rows. Do not weaken existing kiln startup behavior merely to make Firecracker recoverable.

Periodic reconciliation runs at 30-second intervals with jitter and singleflight ownership, plus on failed operations; stop attempts back off 1, 2, 4, 8, then 30 seconds. Work remains charged between attempts. A lower configured budget degrades Health and rejects new creates without preventing cleanup. No hidden guest restart or network repair is performed by Health.

## 8.4 Schema, ownership and history protection

Introduce explicit `reservation_released` with release evidence, rather than extending schema 7's `backend_id IS NOT NULL` inference. Migrate every legacy row using **exactly** schema 7's existing reserved predicate and spec-derived amounts; never reinterpret old ambiguous failures. For new Firecracker rows, release is allowed only for a durable pre-allocation no-work result or exact ABSENT receipt. A cleanup-failed FAILED row may have an allocation/backend identity and still be charged.

Store reservation components, allocation ID, prepared plan/version/digest, boot identity, helper generation, last cleanup disposition and evidence in dedicated columns/tables. Persist the API state/execution outcome/reservation-release decision atomically. Constraints forbid a released nonterminal Firecracker allocation and conflicting plan/identity updates. Older binaries must refuse the upgraded schema. Migration, prune SQL, reservation summation, manager compensation and delete fast paths must change in the same mergeable step; modifying only the Runtime adapter is unsafe.

Keep immutable caller UID, root override, foreign-as-NOT_FOUND behavior and SQL owner filtering before pagination. Helper metadata does not replace those checks. Keep `full|metadata|none` output semantics and existing age/count policies; retain charged, quarantined, unfinished and publication-pending rows. Pruning must consult explicit release evidence and cannot erase replay fences. Diagnostics/argv/specs may still contain private information; no new “secure erase” claim.

# 9. Runtime and public API changes

## 9.1 Internal contract, not a replacement abstraction

Retain Runtime's create/exec/remove/list/gc/version/validation roles. Add preparation and allocation recovery, and make cleanup disposition explicit. Suggested Rust-domain signatures below are normative about inputs/results; ordinary borrowing/lifetimes may be chosen locally. Futures remain `Send`; the trait remains generic, not object-safe.

```rust
struct PreparedCreate {
    spec: SandboxSpec,
    reservation: ResourceReservation,
    plan_version: u32,
    plan_digest: Digest,
    backend_plan: Vec<u8>, // strict bounded internal codec, <=128 KiB
}
struct CreateContext {
    instance_id: Id128,
    allocation_id: Id128,
    sandbox_id: String,
}
struct CreatedSandbox {
    backend_id: String,
    receipt: RuntimeReceipt,
}
enum SandboxDisposition {
    Reusable,
    Stopped,     // no command remains; resources may remain
    Quarantined, // cannot establish cleanup/reuse
}
struct ExecutionContext {
    execution_id: String,
    execution_token: Id128,
}
```

Required Runtime method changes:

```text
prepare(context, spec, deadline, cancel)
    -> Result<PreparedCreate, RuntimeError>
create(context, prepared, deadline, cancel)
    -> Result<CreatedSandbox, CreateFailure>
inspect_allocation(context, prepared_digest, deadline, cancel)
    -> Result<AllocationObservation, RuntimeError>
fence_absent(context, prepared_digest, deadline, cancel)
    -> Result<AbsenceReceipt, RuntimeError>
exec(id, execution_context, spec, cancel) -> ExecOutcome
remove(id, deadline, cancel) -> Result<AbsenceReceipt, RuntimeError>
list(deadline, cancel) -> Result<BackendInventory, RuntimeError>
gc(ids, deadline, cancel) -> Result<Vec<AbsenceReceipt>, RuntimeError>
```

`name`, `version` and side-effect-free `validate_sandbox` remain. Add disposition and cleanup-evidence fields to `ExecOutcome`; no change to `CommandStatus`, capture truthfulness or first-wins cancellation semantics. `AllocationObservation` distinguishes Present, StoppedWithResources, AbsentFenced, Unknown and Unsupported. `BackendInventory` contains records, generation and completeness; it must not erase Unknown entries into Stale. Receipts are backend-produced typed evidence bounded to 16 KiB, matched by identity/generation and persisted; they are not caller-supplied strings or guest assertions.

`KilnRuntime.prepare` returns the unchanged spec reservation; its existing strict removal proof is wrapped in an absence receipt. It returns Unsupported for allocation-token recovery and retains its legacy ambiguous-create behavior. It reports Reusable only after the existing verified cleanup barrier, Quarantined on cleanup failure. No fabricated Firecracker-grade proof for legacy kiln. FakeRuntime implements every disposition, loss and crash boundary for manager tests.

The manager checks pre-cancel/deadline, invokes prepare **before** reserving, then writes C1 and starts create with the exact prepared plan. After an await in preflight, recheck shutdown/serving and bind tracked ownership before committing a new create. A paused/preflight-only call cannot allocate after shutdown because an earlier serving check passed. Delete/reconcile/exec publication use typed evidence, not only `Result<()>`, enum state or NotFound. Each runtime's proof logic stays internal; the generic manager handles only reservation, ownership, lifecycle and reuse.

Backend selection belongs in `main.rs`: dispatch to the existing `serve::<KilnRuntime>` or `serve::<FirecrackerRuntime>` composition, with separate validated backend config. `FirecrackerRuntime` is an unprivileged typed helper client only. No direct Linux privileged fallback under macOS or when the helper is missing.

## 9.2 Additive kilnd.v1 proposals

No field is removed, renumbered or repurposed. No Firecracker-specific kernel path, CID, TAP, memory snapshot or jailer argument appears in the API. Proposed numbers are free at baseline 734e275; recheck at implementation merge:

| Addition | Purpose |
|---|---|
| `SandboxState.QUARANTINED = 7` | Known potentially owned backend cannot safely execute; Delete/reconciliation required |
| `Sandbox.reservation = 11` (`ResourceReservation`) | Effective host commitments distinct from requested tool limits |
| `Sandbox.runtime_profile = 12` (string) | Operator-selected immutable execution profile; descriptive, not caller-selectable |
| `Sandbox.runtime_artifact_digest = 13` (string) | Backend-neutral provenance digest; empty for legacy historical rows |
| `Execution.optional sandbox_reusable = 15` (bool) | Absent for historical unknown evidence; false explicitly tells clients this session cannot take another call |
| `Execution.cleanup_evidence = 16` (enum) | Unknown / NoChildStarted / RuntimeDrained / SandboxStopped; no stronger attestation claim |
| `NodeResourceStats` fields 10–15 | Max/reserved host CPU millis, vCPU slots and host PIDs |
| `HealthResponse.runtime_capabilities = 11` | Generic capabilities including network modes, interruption-preserves-session=false, checkpoint=false; not raw provider details |

`ResourceReservation` uses u64 fields: `memory_bytes=1`, `disk_bytes=2`, `pids=3`, `host_cpu_millis=4`, `virtual_cpu_slots=5`, `host_pids=6`. `pids` is the conservative aggregate explained in section 7; host_pids is a component, not another amount to add. Existing memory/disk NodeResourceStats continue to mean node capacity promises, now correctly including backend overhead. The sandbox spec remains the tool limits.

Unsupported profiles/images/network return `FAILED_PRECONDITION` (invalid grammar remains `INVALID_ARGUMENT`); budget exhaustion is `RESOURCE_EXHAUSTED`. A queued timeout still creates no row and returns `DEADLINE_EXCEEDED`. A dispatched timeout can return a terminal TIMED_OUT execution after teardown and publication, with reusable=false and the sandbox LOST. Quarantined sandboxes reject Exec with `FAILED_PRECONDITION`. Clients must check state/reusability, not assume that a successful Exec RPC means the session survived.

Update `kilndctl` display/help for these fields without changing existing exit-code projection. Public streaming Exec, per-call environment/cwd, session sub-sandboxes, TTLs, public idempotent Create and restore APIs remain separate work.

# 10. Test and adversarial acceptance plan

All production assertions below are **required future tests**, not tests performed for this design document. Fake-based tests run on macOS and Linux. Privileged tests run only in a dedicated Linux test allocation/VM under the shared VM lock; never silently alter installed services or consume all shared host memory.

## 10.1 Unit, property and fake-runtime tests

- Golden approved manifest/contract/config/argv fixtures shared with kiln-guest. Mutate every security-critical field independently: unapproved digest; coordinated image+manifest substitution; valid manifest with wrong artifact; extra/missing/renamed artifact; size/hash mismatch; symlink/hardlink/path substitution; duplicate keys; unknown schema/field; debug/test args; `nokaslr`; init zeroing off; writable root; changed vCPU/RAM/THP; extra NIC/vsock/drive; custom seccomp; API/snapshot flags. Assert **zero** session allocations, helper workers with resource side effects and reservation insertion on preflight rejection.
- Deterministic crash/fault injection before and after every C0–C8 journal sync, rename, spawn gate, reply and SQLite commit. Repeat Remove/reconcile twice; final state and timestamps are idempotent. Inject ENOSPC, fsync/write failure, missing/partial journal, corrupt generation, stale DB restore, worker panic, lost create response, and delayed duplicate Create racing FenceAbsent. Never release ambiguous capacity or launch after a tombstone.
- Prove schema migration preserves all legacy charges and owner_uid=0 historical semantics. Specifically FAILED with a newly known backend ID but no absence proof remains charged. Zero-count/zero-age prune preserves quarantine, charged failures and unfinished/publication-pending executions. Output storage modes retain today's semantics.
- Reservation arithmetic: maximum integers, rounding/overflow, RAM overhead rather than inner memory or PSS, 3×896 fits but 4×896 fails at 3 GiB, concurrent sum-and-insert, CPU/vCPU/PID/disk exhaustion, changed limits on restart, lowered budget, and future pooled charges in fake plans.
- Broker framing fuzz/property tests: every header boundary, trickled bytes, 0/oversized length, bad version/kind/flags/sequence/token, duplicate/trailing terminal, forged stdout status, stdin undershoot/overshoot, partial binary output, arbitrary non-UTF8 data frames, JSON depth/escaping, accounting overflow and unknown outcomes. Memory remains bounded; cancellation control progresses under full output buffers.
- Host/guest deadline clocks have unrelated origins; queueing/preflight/setup consume one host budget. Guest never gets a reset on reconnect. Test pre-cancel, timeout at dispatch, result-vs-cancel races, missing result EOF, genuine exits 124–127 and signal 15, hung capture reader, cleanup-error precedence and reusable=false publication before unlocking queued work.
- Root transport regressions from protocol v3 remain: receipt withheld/early/duplicate/cross-connection, SCM_RIGHTS injection, descriptor leaks, mutated O_NONBLOCK, stalled stdin/stdout, expired non-exec deadline, 64-slot exhaustion and recovery. Firecracker adds no root path or arbitrary command primitive.
- Ownership: foreign caller cannot Probe/Exec/Delete or inspect output via the new fields, root retains authorized visibility, pagination filters first, helper only accepts the exact service UID. Wrong instance/allocation/plan IDs never reach another session.

## 10.2 Privileged VM integration

1. Validate installed root/service capabilities and ownership, safe binary ancestors, cgroup delegation, exact argv/config and no management API socket. Inspect the actual VMM UID/GID/empty capability sets, namespaces, seccomp, start time and cgroup membership. Measure charged RAM from launch, not after migration. Host services remain outside the session cgroup.
2. Cold boot the new approved bundle; validate three drive identities/modes, fresh work UUID and per-boot nonce/kernel boot ID, hardening checks, broker readiness and persistent sandbox capability. Show a command writes a file and the next reads it. The current schema-1/no-broker bundle must be rejected before allocation.
3. Execute binary stdin/stdout, limit-exceeding output, genuine exit/signal outcomes, missing executable, Landlock denied writes, quota/inode exhaustion, a fork bomb and an inner OOM. Then run a successful command for all cases where reuse was reported. Check private disk and neighboring VM isolation.
4. Run a detached descendant with `setsid`, double fork, blocked output and inherited pipe writers. Cancel and time out separately. Verify VMM pidfd exit and cgroup empty, reusable=false, no successor runs in the old boot and no descendants remain. Kill broker, guest PID 1, VMM, supervisor, helper and kilnd at each exec boundary. A fake/compromised broker saying Drained cannot prevent retirement on these paths.
5. Create two simultaneous VMs with distinct UID/CID/jails/work disks. Cross-wire vsock paths, identity drives, work UUIDs and nonce replies in a test-only harness; none reaches READY. Attempt CID reuse and identity allocator reuse while old cleanup is incomplete. Reused host PID must not be signaled. Unknown replacement inode is quarantined rather than recursively deleted.
6. Kill/restart kilnd at every create/delete boundary; demonstrate adoption only at C6, exact compensation otherwise, and no duplicate VM. Repeat with helper death and host reboot. Drop helper replies and force SQLite terminal-write errors: capacity remains held until the exact receipt is recorded. Late Create after FenceAbsent cannot resurrect anything.
7. OOM containment: use a safe outer test cgroup and separate controller outside it. Stress guest RAM, block caches and VMM overhead; record peak memory/current/events, host availability, PIDs and disk. Three sessions are an admission target, not an entitlement to destabilize this dev node. Verify failures stay confined and produce honest cleanup evidence.
8. Confirm no guest NIC, no TAP/nft/route changes, no guest-host IP connectivity, no serial command input, no provider credentials in bundle/identity/control environment. Deliberate guest AF_VSOCK host-initiated-listener misuse cannot access another jail or arbitrary host Unix services.
9. Deny snapshot/restore by construction: no API socket, flags, helper variants or boot mode. A supplied snapshot/disk pair, even self-consistent, is unsupported before allocation. Keep future snapshot/disk mismatch and two-clone uniqueness tests marked **blocked until a separate approved feature**, never silently skipped while declaring snapshot support.
10. Run existing locked tests/Clippy and the installed kiln/kilnd regression suites to prove backend selection, ownership, helper transport, retention and legacy compensation have not regressed. No unreviewed widening of capabilities or address families.

## 10.3 Evidence and review gates

Preserve per-test approved digest, exact config/argv, host boot ID, versions, namespace/cgroup identities and bounded raw logs. Never log the boot nonce in routine API logs; store only its digest there. Record create-ready and first-tool-result latency separately from kiln-guest's earlier serial-marker boot metric. Do not reuse the spike's tiny idle-PSS density claim for hardened guests.

Before implementation begins, Stephen's requested **Daybreak Blue** pass should attack this document, especially: preflight TOCTOU, identity-block routing, future-work fencing after absence, dual-journal ordering, the schema-7 FAILED-with-ID trap, VMM-vs-jailer PID tracking, guest-forged drain proof, output accounting and the supervision gate. This task has not run or claimed that independent review. The coordinating task schedules it. Each subsequent implementation slice needs the same independent adversarial pass before landing, plus relevant tests; no merge authority is implied here.

# 11. Build order and file-level implementation map

Use separately mergeable changes against main, with no production backend enabled until B7. Do not open a dependent stack and treat its top merge as the complete feature. Each slice retains the legacy backend and contains its own tests/docs; code in kiln stays in the kiln repository.

## B1 — Freeze the guest and launch contract

**Files:** kiln-guest `scripts/launch_contract.py`, manifest builder/validator, `src/init.c`, bundle input pins and `tests/test_launch_contract.py`; new shared golden fixtures under kilnd `crates/kilnd/tests/fixtures/firecracker/`. Agree the schema revision and exact permitted substitutions from section 3, including identity vdc and broker lifecycle. Keep production deployment disabled while the broker artifact is absent.

**Exit:** negative mutation tests pass; the current no-vsock manifest is refused for Phase 1b; fixtures have no placeholder security fields. Changing numeric schema/field names is mechanical; changing a semantic constraint requires design review.

## B2 — Runtime evidence and durable accounting

**Files:** `crates/kilnd/src/runtime/mod.rs`, `runtime/fake.rs`, `runtime/kiln.rs`, `runtime/kiln_direct.rs`, `model.rs`, `store.rs`, `manager.rs`, their tests, `service.rs`, `main.rs`, `proto/kilnd/v1/kilnd.proto`, `crates/kilndctl/src/main.rs`, and relevant docs/changelog.

Implement section 9 types/methods and schema migration, explicit release evidence, dispositions/quarantine, stored reservation vector, owner/retention integration and additive API fields. Kiln adapters wrap existing proof; no new privileged action. CPU/vCPU additions use explicit legacy “not reserved” values rather than retroactively inventing a CPU promise for old rows.

**Exit:** all legacy tests, migrations and fake crash matrices pass; no new create path can release from FAILED+backend-ID alone; runtime fake demonstrates a timed-out stopped session refusing the next queued exec.

## B3 — Approved plans and root journal, no VM launch

**New host modules:** `crates/kilnd/src/runtime/firecracker.rs` (typed unprivileged client); `helper/firecracker/{mod,config,manifest,journal,identity,inventory}.rs`. Extend `helper/{protocol,client,server}.rs`, helper CLI/install/deploy files and tests. `manifest` implements strict parse/hash/contract verification; `config` generates the exact plan; `journal` owns sync/fence ordering; `identity` owns allocation/UID/CID uniqueness; `inventory` returns complete or inconclusive observations. No root path in public models.

Implement Capabilities/Preflight/Inspect/List/FenceAbsent using fake resources and worker supervision. Write `PreparedCreate` and receipts using the existing strict framing patterns, keeping no caller descriptors and all v3 receipt rules.

**Exit:** substitution/TOCTOU/frame/deadline/ledger tests pass; rejected manifests create zero session resources; repeated fenced tokens cannot allocate; legacy helper tests remain green.

## B4 — Host allocation, stop and removal

**New modules:** `helper/firecracker/{storage,cgroup,supervisor,lifecycle}.rs`; fixed supervisor mode in `src/bin/kilnd-helper.rs` or a separate installed `src/bin/kilnd-vm-supervisor.rs` with an inherited private control channel, never public arbitrary arguments. Update service capabilities and installation paths narrowly. `lifecycle` owns the C2–C8 state transitions and receipts; storage/cgroup modules accept typed journal identities, never request paths.

Implement disk preparation and exact jailer config/argv, stopped-child gate, process identities, absence barrier and scoped GC. Test using a fixed non-command-listening guest fixture; Create must not report production READY without B5's broker.

**Exit:** real host teardown at every crash boundary leaves no owned resource when ABSENT is reported; stale PID/inode tests protect unrelated resources; prelaunch cgroup charge is proved; no ordinary Create can yet bypass broker readiness.

## B5 — Broker core and image integration

**New crates:** `crates/kilnd-exec-core/` for extracted existing kiln process/status/capture/model-validation pieces; `crates/kilnd-broker-protocol/` for the strict frame/message codec; `crates/kilnd-guest-broker/` for `main.rs`, `session.rs`, `server.rs`, `kiln.rs`. Host modules `helper/firecracker/{broker,exec}.rs` use the protocol crate. Reexport moved host types as needed to keep B2 interfaces stable. Audit the extraction as a behavior-preserving move before adding guest changes; do not pull gRPC/SQLite/host helper server into the guest binary.

Broker state is Uninitialized -> Initializing -> Idle -> Executing -> Draining -> Idle, with Faulted terminal until VM termination. The pseudocode is: validate Hello against vdc; initialize one exact spec once; prepare kiln persistent sandbox; smoke/validate; admit one token; fully receive bounded stdin; call reviewed direct-kiln execution core; drain/check; emit typed result. Any initialization uncertainty faults the guest, never creates a second inner sandbox. Control Cancel never waits on the exec output writer.

kiln-guest embeds the broker at a pinned kilnd commit/binary digest, adds the vdc reader and supervision hook, and rebuilds two clean bundles. Extend its source/input provenance to include the two crates/core, lockfile and exact compiler inputs.

**Exit:** fake broker adversaries pass; actual guest persistent exec/cancel/kill tests pass; two independent clean-worktree builds match under the pinned environment; full guest integration plus two warmups and twenty cold boots are recorded for the new contract before approval.

## B6 — Full manager lifecycle and recovery

**Files:** manager/store/runtime/helper integration tests plus new `scripts/firecracker-regressions.py`, `scripts/firecracker-crash-matrix.py` and documented isolated test deployment config. Wire recovery by allocation, stop-on-interruption, terminal publication and complete inventory; preserve authorization and retention behavior.

**Exit:** all section 10 lifecycle attacks pass on the actual daemon/helper/broker chain, including lost create response, blocked output, detached descendants, host PID reuse, cross-session paths and helper death. No reservation is freed while a VM/disk may exist. Quarantine remains controllable through Delete.

## B7 — Capacity and opt-in deployment

**Files:** setup/threat-model/architecture/validation/roadmap docs, CLI help and operator catalog examples. Install the reviewed approved digest; only now allow `--backend firecracker`. Networking, pooling and snapshots remain unsupported.

**Exit:** overhead/CPU/PID/disk stress supports the chosen profile, density conditions are recorded honestly, legacy privileged suites pass, Daybreak findings are resolved or explicitly accepted by Stephen, and Stephen's section 12 decisions are reflected in the fixtures. No claim of hostile multi-tenant production readiness follows merely from these tests.

# 12. Decisions for Stephen

These are choices to settle before B1/B2 are frozen, not permission requests to delay this design deliverable.

| Decision | Options and trade-offs | Recommendation |
|---|---|---|
| Guest RAM | 512 MiB permits four memory-budget slots but only a 256 MiB tool cgroup; 768 MiB preserves the existing 512 MiB tool default and gives three slots in a 3 GiB sandbox budget | **768 MiB**, reserve 896 MiB total provisionally; remeasure the 128 MiB overhead allowance under load |
| Session mapping | One kilnd sandbox = one VM + one persistent kiln sandbox is simple and preserves files; many independently addressed inner sandboxes need new identity, quota, concurrency and trust rules; fresh sandbox each call changes persistence | **One-to-one session mapping**, serialized tool execs with separate execution cgroups; no mutually distrustful sub-sandboxes |
| Warm pool | 0 avoids idle resource commitments and assignment complexity; 1 can lower first-call latency but consumes one of three 768 MiB slots and needs an identity-transfer protocol | **0** until measured cold-create latency justifies spending a slot; never snapshot-based |
| Broker repository | kiln-guest keeps image/runtime together but separates host/guest protocol evolution; a kilnd crate shares codecs and cleanup semantics, while kiln-guest pins/bakes its output | **New kilnd workspace crate**, image integration in kiln-guest at an exact reviewed commit/digest |
| Interruption policy | Trust a healthy guest drain and preserve workspace, or terminate the VM for independent host cleanup proof; whole-VM termination loses continued access to that workspace | **Terminate on post-dispatch timeout/cancel/uncertainty**, expose reusable=false; preserve only fully completed normal executions or proven pre-dispatch cancellation |
| Management socket | API socket aids live reconfiguration but adds lifecycle/snapshot surface; fixed config + no-api supports this cold-only scope | **No API socket**, stop through pidfd/cgroup evidence |
| Disk strategy | Sparse private files improve initial speed but can fail later from overcommit; full preallocation costs create time/storage up front; reflink seeds complicate shared capacity and identity | **Fresh fully preallocated XFS**, no seed/reflink in the initial implementation |
| Network and snapshot scope | Adding them now expands the host policy and recovery proof considerably | **Offline, cold-only**; require new approved profiles and separate adversarial gates for either feature |

# 13. Source and evidence ledger

Local evidence is deliberately distinguished from future design obligations. Paths below are relative to the Lambda IX workspace unless stated otherwise.

- kilnd baseline: `CLAUDE.md`, `README.md`, `docs/architecture.md`, `docs/threat-model.md`, `docs/roadmap.md`, `docs/helper-protocol.md`; `crates/kilnd/src/runtime/{mod,kiln,kiln_direct}.rs`, helper protocol/server, manager/store/model/admission/retention/service and `proto/kilnd/v1/kilnd.proto` at `734e275`.
- Spike: `research/2026-10-30-firecracker-spike.md`, especially “Proposed Phase 1 backend” and “What the Runtime trait needs.” Its tiny idle guests and snapshot feasibility do not authorize production sizing or restore.
- Guest: kiln-guest README, `scripts/launch_contract.py`, `dist/bundle-a/manifest.json` and `results/launch-contract/{summary,reproducibility}.json` observed at `7d9d956`; current bundle digest in section 1.2. The new broker profile remains unbuilt/unapproved.
- Capacity: `kiln-guest/results/boot-regression/DENSITY.md`; hardened 768 MiB guest about 770 MiB PSS, contained five-VM OOM and the correction to cgroup membership before allocation. Three sessions per 3 GiB sandbox budget is planning, not a measured backend throughput claim.
- Adversarial constraints: `reviews/2026-10-30-guest-breakit.md` (KG-06 admission, KG-07 restore); `reviews/2026-10-30-guest-reattack.md` (KR-01 full launch binding, snapshot/KASLR, build and DNS boundaries); `reviews/2026-10-30-phase0-breakit.md`, `reviews/2026-10-30-helper-recheck.md`, `reviews/2026-10-30-receiptack-recheck.md` (descriptor authority, receipt lifetime and original wire deadlines). Later guest evidence addresses the old kernel/build/DNS findings; it does not implement this backend's admission.
- Pinned upstream mechanics: [jailer v1.17.0](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/docs/jailer.md) and [vsock v1.17.0](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/docs/vsock.md), consulted for exact flags, PID/cgroup behavior and host-port handshake. All additional lifecycle, reservation and broker rules above are this design's requirements, not claims that Firecracker supplies them automatically.

The design is ready for the requested adversarial review. Production implementation, final Phase 1b bundle approval and Stephen's choices remain open.

# 14. Document rendering

The Markdown is the source of truth. From this worktree's root, render the same text using pandoc and tectonic (house fonts/margins match the kiln-learning notes):

```sh
pandoc docs/design/phase1b-firecracker.md \
  --from=markdown --standalone --toc --toc-depth=2 \
  --syntax-highlighting=none --pdf-engine=tectonic \
  -V documentclass=article -V fontsize=10pt \
  -V papersize=letter -V geometry:margin=0.72in \
  --include-in-header=docs/design/phase1b-pdf-header.tex \
  -o ../research/phase1b-firecracker-design.pdf
```

The PDF is a local review artifact; the source and style are on `design/phase1b`. No PR, merge, production installation or VM run is part of this task.
