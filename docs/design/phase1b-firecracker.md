---
title: "Lambda IX Phase 1b"
subtitle: "FirecrackerRuntime and the guest broker"
author: "Stephen Estrada"
date: "October 31, 2026"
---

# 1. Decision and scope

**Build one cold-booted Firecracker microVM per kilnd sandbox/session, with one persistent kiln sandbox inside it.** Successive tool calls use `kiln exec`; each execution has kiln's separate descendant cgroup. The root helper owns every host side effect. The guest broker owns guest-side kiln operations. The harness and all model/provider credentials remain outside the VM.

This is an implementation specification, not an implemented backend or a security certification. Baseline: kilnd `734e275163bd6b028736af8261e4897d93169a5f`, helper protocol v3, SQLite schema 7, and kiln `00d61c546db7aa67ad283d10c2ca6165ca5f8166`. No production code changes accompany this document. Stephen confirmed section 12's decisions on **October 31, 2026**. Guest RAM, session mapping, pool size, broker location and interruption policy are settled; the 128 MiB per-session/shared overhead estimates still require B7 measurement.

Initial scope is Linux aarch64, cgroup v2, the pinned Firecracker/jailer 1.17.0 lineage with the final capability-drop requirement in section 6.2, the approved hardened kiln-guest lineage, offline execution, no pool, no snapshot/restore/fork/pause, no guest image download, no host directory sharing, and no remote public API. Existing `KilnRuntime` remains supported and unchanged in public behavior. Daybreak Blue's October 31 recheck closed all seven original findings and requested one executable-handoff correction. This revision specifies that correction; section 15 maps it. Clearance of the correction remains a review gate. Choose one backend per daemon at startup using the existing generic `Manager<R: Runtime>`; do not introduce an unsupported `dyn Runtime` conversion.

## 1.1 Non-negotiable invariants

1. Authenticate the exact manifest bytes against an independently configured approved SHA-256, validate the complete schema and effective launch contract, and verify **every** artifact before creating any session disk, jail, cgroup, socket, network resource or process. Carry each verified host executable through execution by retained descriptor under section 3.4; a matching pathname/argv is insufficient. Read-only preflight descriptors and bounded parser buffers are not session allocations. Recheck in the helper immediately before accepting allocation.
2. A durable daemon reservation precedes a node-global helper capacity claim and allocation. After C1, only a matching durable ABSENT replay-fence receipt can release that daemon reservation. A durable root-owned helper intent precedes every externally visible side effect. Unknown allocation, execution cleanup or inventory is never equivalent to absence.
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

Phase 1b therefore needs a new bundle/contract revision and a newly approved manifest digest. Section 3 defines the required semantics; final serialized field names and schema numbers must be agreed with kiln-guest and frozen as shared golden fixtures in build step B1 (now manifest and contract schema 2, in `crates/kilnd/tests/fixtures/firecracker/`). Until then the backend refuses the current production profile. There is no permissive “legacy contract” mode.

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

The host kernel, KVM, matching jailer/VMM, helper and operator approvals are trusted for isolation. kilnd and its account remain trusted for caller ownership and daemon-local admission. The root-owned helper node ledger is the independent authority for Firecracker node capacity and host resources, including against a compromised kilnd account. The helper narrows that authority to typed operations; it is not a second tenant authorization service. For Firecracker, unlike legacy kiln, its mutation scope is restricted to its own journaled namespace.

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
executables = <role -> protected content-addressed path, size, SHA-256, dependency closure>
instance_id = <durable random 128-bit daemon namespace>
vm_uid_range / vm_gid_range = <distinct dedicated host ranges>
node_ledger / node_ceilings = <one root-owned authority for the node>
```

Installation creates the catalog and storage/cgroup roots, not CreateSandbox. A caller can select only an inner image present in the approved bundle's catalog. The daemon's default inner memory stays 512 MiB, CPU 1000 millis, PIDs 128 and writable quota 1 GiB. The 768 MiB VM profile accepts inner memory at most 512 MiB and CPU at most 1000 millis; larger requests fail before allocation. Do not silently clamp a request or expand the guest outside the approved profile.

## 3.2 Exhaustive preflight procedure

The manager generates instance/allocation/sandbox identity in memory before preflight, without inserting a row. The unprivileged adapter requests `Preflight` with that context; the helper independently performs the following, without session side effects:

1. Resolve the deployment profile in the root-owned catalog; do not accept caller filesystem paths. Validate trusted ancestors with descriptor-relative traversal, reject symlinks and non-regular artifact files, require every executable/store ancestor from `/` to be root-owned and non-writable by **any** non-root principal (mode, ACL and parent rename authority), pin opened descriptors. Section 3.4 governs executable installation and use, including formatter and worker images. Cap manifest bytes at 4 MiB and artifact sizes at catalog limits before reading. Reject duplicate JSON keys, unknown schema/fields, invalid integer ranges, extra artifacts and path components other than fixed safe names.
2. Hash the raw manifest bytes and compare to the independent approval. Never learn the approved digest from that same directory or a guest message. Authentication is distinct from kiln-guest's reproducibility comparison.
3. Validate architecture, every host executable identity/dependency closure under section 3.4, VMM/jailer exact version and digests, kernel policy/config digest, inner image catalog and shifted ownership provenance, broker digest/protocol/capabilities, root digest, source/build provenance fields, work-disk policy and the full launch contract. All declared artifacts, including the separately retained kiln, broker and kernel config, must match size and digest. Authenticating only the artifacts actually attached to the VM is insufficient.
4. Expand the contract into a **complete** planned configuration and argv. Compare the actual objects to be serialized/launched, not a parallel description. Allowed dynamic fields are explicitly typed below. Reject extra devices, flags, duplicate flags, JSON keys, CPU templates, test parameters, debug endpoints, snapshot settings and boot-argument additions. Require guest init's production hardening checks before broker startup.
5. Validate the effective sandbox spec independently, then calculate the reservation using checked arithmetic. Reject network Full/Allow rather than silently running offline. Verify cgroup v2/controllers/`cgroup.kill`, KVM availability, mount/storage features, identity-range configuration, and binary ancestry. A read-only capability check may open `/dev/kvm` and query its API; it must not create a VM.
6. Select currently free UID/GID/CID candidates without reserving them, and generate nonce/work UUID in memory. Include these and every derived name in the exact plan. Return `PreparedCreate` including profile/manifest digest, `host_spec_sha256` over the complete effective `SandboxSpec` including labels, plus `guest_exec_spec_sha256` over the label-free guest execution projection, reservation, a versioned private plan and its digest. The manager atomically records it with the reservation. `Create` revalidates the bytes and plan under the registry/allocation locks, then atomically claims those candidates in INTENT. If another create claimed one first, do not substitute another UID/GID/CID or mutate a stored plan. A C0 rejection has no daemon row. After C1, a collision, catalog mismatch, expired request or any other rejection remains charged until the exact token has a durable ABSENT receipt under section 4.1. The helper may return an immediate retryable error with AllocationAmbiguous, but never uncharged evidence from an unfenced rejection. A changed catalog never silently selects a different plan.

Artifacts live in a root-owned immutable/content-addressed store. Keep verified descriptors pinned through staging **and actual execution**; never authorize a fresh pathname lookup from an earlier hash. No non-root principal may write an immutable artifact or rename any of its ancestors. The protected executable store and generation leases in section 3.4 cover the entire privileged child chain. Read-only bind mounts of staged kernel/root and a helper-owned config prevent a jailed process from changing those bytes. Trusted root is outside the attacker model. Revocation denies new creates/execs but **never** denies inspection or cleanup of already owned resources.

The helper listener never performs filesystem/SQLite/process setup work inline. Section 6.4 defines the mandatory bounded process model for validation, ledger writes, lifecycle work, relays and recovery. Service validation workers exist at startup; no request starts a session worker before approval succeeds and C2 claims node capacity. Startup Health reads cached identity and worker status; it neither hashes artifacts nor waits for fsync inside the socket loop. A cache never substitutes for the pre-create artifact check.

## 3.3 Required Phase 1b contract semantics

Freeze a new production-only `offline-768-v1` profile. The signed/approved manifest authenticates a template plus **exhaustive typed substitutions**, not arbitrary patches:

| Item | Required value / substitution |
|---|---|
| Boot | Cold only; exact reviewed command line and exact VMM-appended suffix; KASLR, allocation/free/stack initialization and lockdown checks remain mandatory |
| Machine | 1 vCPU, 768 MiB, SMT false, `huge_pages=Transparent`, dirty tracking false; CPU template absent |
| Drives, in order | `/kernel` boot image; `/rootfs` read-only root on vda; `/work` private writable XFS on vdb; `/identity` read-only raw identity block on vdc |
| Vsock | One device, `/run/vsock.sock` on bounded jail tmpfs; guest CID from reserved integer range 3–65535; broker port 5252 |
| Network | No network-interfaces key/device, no metadata service, no TAP, no routes/NAT |
| Jailer | Matching pinned musl VMM; reviewed descriptor-handoff and capability-drop patch; cgroup v2; new PID namespace; no daemonize; no API; default seccomp; fixed resource-limit recipe |
| Executable provenance | Section 3.4: role/size/SHA-256, protected ancestry, FD execution, exact dependency closure and handoff version for J/V/formatter/all helper workers; node-local device/inode tuples come only from verified installed descriptors |
| Dynamic identity | 128-bit instance and allocation IDs; public sandbox ID; fresh boot nonce; **distinct** typed uid and gid substitutions, even when numerically equal; separate relay UID/GID leases; reserved CID; exact derived cgroup/jail paths |
| Dynamic resources | Work disk size/UUID and validated inner spec; exact-size loop block binding; jail tmpfs 16 MiB / 1024 inodes; outer and worker CPU/memory/PID values from sections 6.4/7, never arbitrary keys |
| Forbidden | Snapshot/restore, custom init/kernel args, test profiles, serial input, writable root, custom seccomp/CPU templates, extra devices or host mounts |

The identity block is a 4096-byte zero-padded raw record, no filesystem: magic `KID1`, big-endian u32 JSON length (1–4088), then canonical strict JSON. It binds instance ID, allocation ID, sandbox ID, 256-bit boot nonce, manifest digest, effective-launch digest, work UUID and `guest_exec_spec_sha256`. It contains no reusable credential and is not proof against guest root. The launch digest covers canonical configuration/argv and the resolved resource recipe, including identity-drive presence/path; it excludes identity-block content to avoid a self-referential hash. The block's own SHA-256 is separately journaled. Init/broker must require exactly one valid record, zero padding and read-only vdc.

The exact guest command line is inherited from the newly approved bundle; initially retain the current reviewed line:

```text
console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda
rootfstype=squashfs ro init=/init loglevel=3
randomize_kstack_offset=on
```

Those three display lines serialize as one space-separated line. The current appended suffix is ` pci=off root=/dev/vda ro earlycon=uart,mmio,0x40002000`; freeze and test its actual value for the new three-drive/vsock topology. Never hard-code acceptance of an unverified changed suffix. These are build B1 exit criteria, not permission to weaken init's exact comparison. **B1 measured this:** real Firecracker 1.17.0 boots with three drives and vsock append the same suffix, and the contract freezes it (kiln-guest `results/phase1b-b1/suffix-probe.json`).

### Canonical JSON and the two spec digests (B1 correction)

All manifest, recipe, plan, spec and identity JSON uses one byte contract. Input
is strict UTF-8, at most 4 MiB, without a BOM, trailing data, unpaired surrogate
escapes or duplicate **decoded** object keys (including escaped aliases). Root
depth is zero; each object key/value and array element adds one; reject any node
past depth 32, including keys. A guest control frame additionally obeys section
5.2's smaller depth and encoded-size bounds.

Canonical bytes are ASCII, no whitespace or final newline, comma/colon separators,
object keys sorted lexicographically by Unicode scalar value, and array order
preserved. Strings have no Unicode normalization. Escape quote and backslash;
use `\b`, `\f`, `\n`, `\r`, `\t` for those five controls; encode all other
U+0000–001F and every scalar above U+007E with lowercase four-digit `\u` escapes.
Astral scalars use UTF-16 surrogate-pair escapes. Do not escape slash. Booleans
and null spell `true`, `false`, `null`. Integers range from -9223372036854775808
through 18446744073709551615, with ordinary decimal spelling: no plus sign,
leading zero, negative zero, fraction, exponent, float or non-finite constant.
Raw manifest approval still hashes the **original bytes**, not canonical bytes.

`host_spec_sha256` hashes the canonical complete effective `SandboxSpec`, including
labels and every filled default. `guest_exec_spec_sha256` hashes exactly its
label-free execution projection. The daemon's immutable prepared plan and future
B2 durable journal carry the full spec and both digests; Create replay and recovery
recompute and compare both before accepting a plan. A label-only mutation changes
the host digest and plan digest, while the guest digest and identity block remain
unchanged. Only `guest_exec_spec_sha256` goes into vdc, Hello and Initialize.
Neither digest may be called an ambiguous “exact spec digest”. B1 provides the
production `SpecBinding` codec/verification; B2 still owns the journal migration
and lifecycle integration described in section 9.

Fixtures are outside the production schema namespace: `kiln-test-manifest-v1`,
`kiln-test-plan-v1`, profile `test-only-b1`. Constructors live only in test code,
with a `FixturePlan` type and no conversion to `PreparedCreate`. Production manifest
validation rejects them unconditionally, regardless of independent approval;
there is no fixture boolean or CLI switch. Relabeling their schema or clearing
their fixture flag cannot make them deployable. Schema 2 remains disabled until
the reviewed B4/B5/B7 artifacts and approval gates are implemented.

Both repositories check in the identical `conformance.json` corpus. Both suites
assert accept/reject verdicts and exact canonical bytes/SHA-256, including valid
non-ASCII writable paths, Unicode scalar ordering and surrogate edges, number
spellings/bounds, duplicates, schema confusion, every contract/manifest/plan/
substitution/spec/binding leaf mutation, and all named attacks. Rust uses the
production strict parser, canonicalizer, frozen recipe validator and launch
rederivation; fixture envelopes remain test-only. Recomputed approvals do not
turn a mutated recipe into an accepted launch.

## 3.4 Executable identity from verification through exec

**Use one protected store and descriptor-based handoff for every host executable in the Firecracker helper chain.** Mirror kiln-guest `e1082f2`'s root-private installation, descriptor-relative ancestry walk, hashing through an open FD and retained-jailer-FD execution (`scripts/privileged_launch.py`, `tests/test_vmm_path_race.py`). Extend that rule to the VMM's final exec, formatter and every separate supervisor/worker/relay/drainer binary. This is a specification for kilnd, not a claim that kiln-guest already implements those extensions.

The installer, outside Create, copies from already authenticated source descriptors into `/opt/kilnd/exec/sha256/<digest>/<role-name>`. It checks the completed private copy's size/digest, makes it root-owned 0555 with no setuid/setgid bits or file capabilities, fsyncs it, atomically publishes it without replacing an existing digest object, and fsyncs its parent. Existing objects must match; never repair one in place. No hardlinks to a build cache. Missing objects fail C0; Create cannot install/download them. Approved role names include `jailer`, `firecracker`, `mkfs.xfs` and the explicitly enumerated helper binaries, not caller-selected names.

Walk from an opened `/` using descriptor-relative `openat`/`openat2` with no symlinks or magic-link resolution. Every directory component must be root-owned, with no group/world write bits and no extended/default ACL granting non-root write or creation authority; reject unsupported permission checks. Check each **parent's** rename authority, not just its child's ownership. New store directories use 0700 and no extended/default ACL. Open each final regular file with `O_RDONLY|O_NOFOLLOW|O_CLOEXEC`, check ownership/mode/ACL/link count/size and hash that same FD. Reject writable aliases, unexpected hardlinks and non-regular files. Record `(role, st_dev, st_ino, size, sha256, installation_generation)` from the FD. The root catalog binds the digest/size and handoff recipe; node-local device/inode values are verified substitutions, never values supplied by kilnd's public client.

The bounded helper executable table retains these read-only FDs and the protected directory handles. Preflight includes their exact identity vector in the prepared plan; Create revalidates that vector before C2. Acquire a generation lease for every accepted allocation/worker and keep the objects immutable until all references and cleanup obligations end. No installer replaces/deletes a leased object; upgrades publish a new digest/generation. After helper restart, reopening is allowed only by protected traversal followed by exact device/inode/size/digest comparison with the journal. A replacement inode, even with the same bytes, cannot satisfy an old plan. A missing/stale preflight handle or catalog generation requires revalidation, never a path-only fallback. Trusted root is outside the attack model, but routine upgrades must obey these leases.

Execute each approved ELF using [Linux's descriptor-exec interface](https://man7.org/linux/man-pages/man2/execveat.2.html), `execveat(verified_fd, "", argv, clean_env, AT_EMPTY_PATH)`; `argv[0]` remains the contract's display name, not lookup authority. Hashing/validation run in the existing bounded workers, never H's listener. H verifies its own `/proc/self/exe` against the protected installed identity before spawning infrastructure workers or accepting traffic. Fork-only worker modes may inherit that already verified helper image; record that inherited executable identity. Re-exec and separate worker binaries use the same retained-FD rule. No PATH lookup, shell, shebang interpreter, unlisted child command or fallback `execve(path)` is allowed. Static ELF is preferred. For a dynamic formatter/worker, its exact loader and complete library/configuration closure must also be approved and installed with protected ancestry and immutable generation leases; bind the actual loader/search paths to that closure, clear loader-influencing environment and reject an unsupported/unbound closure before allocation. Pinning only the main ELF is insufficient. The source `/usr/sbin/mkfs.xfs` may be an installation input, never runtime execution authority.

**Jailer-to-VMM handoff:** use the narrowly patched, digest-pinned jailer in section 6.2. The helper read-only binds the retained verified Firecracker inode at the jail's `/firecracker`; the patched jailer must neither recopy nor chown that executable. S launches J by its retained jailer FD, passing only two additional, helper-created bootstrap FDs: FD 3 is the read-only verified VMM executable, FD 4 a private bounded supervisor control socket. In the gated launch child, keep the jailer exec FD at a nonconflicting descriptor >=5 with CLOEXEC; duplicate V/control to 3/4 and clear CLOEXEC only on those two so they survive J exec. The private bootstrap record binds version=1, plan generation, VMM device/inode/size/digest, the exact `--exec-file` label and pinned jail-root identity. No incoming public/helper-v3 request may supply these descriptors. J's FD sanitization preserves exactly 3/4 initially, validates them and marks them CLOEXEC. All other unexpected FDs are closed.

Before privileged jail setup, J waits at a post-exec bootstrap gate while S observes `/proc/<J>/exe` through the pidfd-validated process, compares its device/inode and FD-computed digest with the journal, and durably records the observation. Only then does S send Continue. Bootstrap messages have a fixed 4 KiB bound and the original create deadline; EOF, malformed identity, timeout or failed publication stops setup. The approved patch must implement this gate; unmodified upstream jailer is incompatible. This supplements the existing S/J spawn gates without claiming to gate the jailer's later clone.

J validates FD 3 against the bootstrap identity and the `/firecracker` read-only bind, performs the approved namespace/cgroup/capability setup, then its V child calls `execveat(3, "", vmm_argv, empty_env, AT_EMPTY_PATH)`. The `--exec-file` path is an exact contract-bound label/basename; J never reopens it for copy or execution. FD 3/4 close on successful VMM exec; no bootstrap/control/executable FD survives into Firecracker. The VMM remains the approved static musl image. Its observed `/proc/<V>/exe` device/inode/digest must equal FD 3's journaled identity before BOOTING/READY publication. A read-only bind preserves the source inode: there is no undocumented copied-inode equivalence. Replacement of a source or installed pathname cannot redirect either exec.

Bind `--chroot-base-dir` to the pinned helper-owned root-private hierarchy as well; all its parents stay root-owned and immune to non-root rename. The allocation's bounded jail contents may later have the permissions in section 7.1, but cannot redirect the retained executable or its protected store object. Journal expected executable identities before each spawn/exec, then attach observed identity evidence to the process record. Any disagreement fences and contains the allocation; no alternate path or new image is tried. C0 detects unsafe installations with **zero** session side effects; after C1 keep the reservation until matching ABSENT, including when a launch identity check fails after C2. Once-only store bytes/inodes and retained FD limits belong in the existing shared budget, not an unaccounted cache.

# 4. Identities, journal and state machine

## 4.1 Names and durable ownership

Generate a cryptographic 128-bit `allocation_id` before reservation. It is distinct from the existing 64-bit public sandbox ID, and never reused. Backend ID is `fc-` plus 32 lowercase hexadecimal digits. Store `allocation_id` and the private plan in dedicated columns; **do not prefill `backend_id`**. Schema 7 treats FAILED-with-backend-ID as compensated and uncharged: pre-filling that column would create an early-release bug.

Each helper record has a version, node/instance/allocation/sandbox IDs, generation, plan/manifest/spec/launch digests, the full reservation, phase, independently typed VMM and relay UID/GID leases, CID, deterministic names, host boot ID, worker/supervisor/jailer/VMM PID and start time, cgroup inodes, expected/observed executable device/inode/size/digests and installation generations, artifact/work inodes, loop device/backing identity, tmpfs mount ID, work UUID, nonce, exec state and stop/absence evidence. Allocation IDs are unique across the entire node, not merely within an instance. Generations compare-and-update; they never blindly overwrite newer evidence.

**One root-owned node ledger is authoritative:** `/var/lib/kilnd-helper/firecracker/node.db`, SQLite WAL with synchronous=FULL, foreign keys enabled, 0600 files/sidecars under a pinned root-owned 0700 directory. One persistent node lock excludes a second helper even if it selects a different instance namespace; the installed service uses one fixed root-owned node policy/ledger path. The ledger process alone opens SQLite and uses fixed prepared statements. It stores allocation intents, capacity claims, identity ownership, worker intents, terminal receipts and permanent retired-token fences in transactions. This replaces the first draft's independent JSON files: a JSON export is diagnostic, never allocation or release authority. SQLite and this bounded schema are now explicitly part of the root TCB. File staging still uses fdatasync and parent-directory fsync; sync ledger directory creation too. Never store tenant stdout/argv/stdin in the ledger.

**Instances are enrolled by root.** `kilnd-helper enroll --instance <id> --unit <systemd unit>` runs as root or from the installer, never over the kilnd socket. It takes the node lock, so it runs with the helper stopped, and writes the instance's row in the node ledger: the expected systemd unit, that unit's exact cgroup, and the installed kilnd image's device, inode, size and digest, read through the protected walk (root-owned, not writable by anyone else, single link, no setuid, setgid, ACL or file capability). Each unit serves one instance. Replacing the kilnd image requires enrolling again. Root policy's `max_enrolled_instances` (default 8, at most 64) bounds the total; lowering it removes nothing. Removing an enrollment is B6's repair flow.

Before Preflight, `AttachInstance` establishes a long-lived authenticated control connection. It succeeds only when the connecting process runs as the kilnd UID (real, effective, saved and filesystem), sits in exactly the enrolled unit's cgroup (a child cgroup does not count), and runs the enrolled image by device, inode, size and digest. Stat fields are compared before hashing, so only the enrolled inode is ever hashed. The connection's own pidfd (`SO_PEERPIDFD`, Linux 6.5 or later, and refused without it) pins the connector. L reads `/proc/<pid>` through one pidfd and directory descriptor and rechecks the start time afterward, and H requires the connector still alive after L answers, so a reused PID cannot lend its identity. **The database UUID is only a reconciliation identifier, never an authenticator:** copying a daemon's files gives a process nothing. It is recorded by the first attestation and a mismatch closes admission. An unenrolled instance ID is refused with no ledger call and no state.

Only one live holder may use an instance ID. Operations carry a helper-generated connection epoch, invalidated on detach/restart, and the attested process's pidfd must still be alive for it to count. Create and FenceAbsent from any process other than the live holder are refused before any lookup: they get no token fact and allocate nothing. Accepted work remains ledger-owned after detach; a new connection cannot clear its claims. Multiple distinct instances are supported, but share the same node ledger and budgets (section 7.3).

**Every post-C1 release requires ABSENT.** C0 rejection creates no daemon row and no reservation. Once C1 commits, the helper first looks up the token under its per-allocation serialization, before revalidation or allocator selection. An existing ABSENT row is returned unchanged; an existing active or conflicting plan is never DefinitelyNotCreated. For a new token rejected before INTENT, `FenceAbsent` closes its admission gate, cancels or invalidates every queued dispatch generation, waits for all previously issued side-effect permits/workers to settle, verifies all derived resources absent, and commits the retired-token entry plus matching ABSENT receipt in one FULL-sync transaction. Only then can the helper return AbsentFenced/DefinitelyNotCreated. A lock alone, absence in one invocation, deadline, error string or empty listing does not suffice. Late requests check the durable fence again before any side effect.

Receipts identify node, instance, allocation, plan digest, monotonically increasing helper generation and kind `AbsentFenced`. A prior candidate collision or revalidation failure with no fence returns AllocationAmbiguous and the daemon keeps its FAILED row charged while fencing is retried. A ledger failure or a stuck accepted worker forbids the receipt. Retired entries remain even when API history expires. Initially reserve a 64 MiB retired-ID ledger allowance; stop accepting new tokens before the space needed to fence already accepted tokens would be exhausted. A quarter of that allowance is set aside for tokens the ledger never admitted, divided equally among the policy's possible instances, and each instance's quota is checked in the fence's own transaction. At its quota, FenceAbsent for a never-seen token fails closed with no row written, and the daemon keeps its charge; a token the ledger admitted is never refused by this quota. Admission reserves the whole set-aside up front, so never-admitted fences and admitted tokens together always fit the allowance. Never prune fences by age; epoch-safe compaction is separate work. Bound console retention to 64 KiB combined; its mandatory drain/rate policy is in section 5.6.

**Daemon database boundary (B2):** `/var/lib/kilnd/kilnd.db` is owned by the kilnd service UID: directory 0700, regular single-link database and SQLite sidecars 0600. Installation checks these modes/owners after any legacy root-to-service transfer; startup validates them before opening and again after SQLite setup. These filesystem permissions protect access. A process able to open its own SQLite connection already has kilnd's file authority and is equivalent to a schema/file rewriter. A connection that disables triggers (`SQLITE_DBCONFIG_ENABLE_TRIGGER`) or registers a spoofed validator is explicitly out of scope for SQL guards. Triggers defend kilnd bugs and honest direct-SQL mistakes through standard tools; they cannot bind another connection's configuration or function implementation. The root-owned node ledger above never frees node capacity or host resources without its own ABSENT receipt, whatever this daemon database says. B3/B4 implement that authority; B2 does not claim it exists yet.

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

C0 rejection: no row, no reservation
CREATING --rejection without ABSENT--> FAILED [charged]
CREATING --matching ABSENT receipt--> FAILED [uncharged]
READY --proved no live VM-----------> LOST [still charged]
```

```text
Root helper allocation journal:
INTENT + node claim -> PREPARING -> SPAWN_INTENT -> BOOTING -> READY
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
| C0: preflight | No session resources; full approval/artifact/contract check | Rejection has no daemon failure row or reservation |
| C1: reserve | SQLite IMMEDIATE: CREATING + owner UID + allocation/plan + explicit reservation | No helper record is ambiguous until FenceAbsent excludes a delayed Create and all resources |
| C2: helper accepts | One node-ledger transaction: capacity vector + UID/GID/CID claim + INTENT + names + conditional stop authority | Rejection before this transaction still needs ABSENT to release C1. After commit the node claim survives every daemon failure |
| C3: prepare | Persist PREPARING and worker permits before disk, identity block, jail mounts or outer cgroup; register gated S and its monitor before S works | Partial files/mounts/cgroups are owned, remain charged; cleanup exact recorded namespace |
| C4: spawn | Persist SPAWN_INTENT with executable identity vector; record gated J identity/pinned cgroups; verify S/M watches, FD exec and J post-exec observation before setup | Gate EOF stops setup. The gate does not gate the jailer's later clone; cgroup ownership already covers that child |
| C5: boot | Observe jailer parent exit; adopt actual VMM; persist validated identity and BOOTING before readiness | Unexpected supervisor loss triggers live stop; normal jailer exit is not VMM exit. Cgroup intent owns the clone before its PID is published |
| C6: ready | Validate broker/identity/persistent sandbox; persist READY receipt | Lost reply can be queried by allocation. Adopt only an identical live boot with no uncertain exec |
| C7: publish | SQLite transaction writes READY/backend ID/boot identity/receipt generation | Crash before commit: CREATING can adopt C6; failure to publish triggers recorded compensation, never blind release |
| C8: compensate | Persist daemon DELETING where possible; helper STOP_INTENT regardless of daemon write failure | Return no ready result. Keep charged until helper ABSENT and one durable terminal/release update |

A crash between C3 syscalls is covered by prior resource names and worker permits. The allocation parent cgroup is the ownership boundary before jailer starts; the VMM can run before its PID file/identity receipt exists. No PID-publication gate is claimed for jailer's internal clone. Late worker results include their operation generation and cannot reopen a fenced allocation. Section 6.4 defines who may execute each side effect and how disconnected work stays owned.

## 4.4 Live process ownership and monitor failure

The exact process graph is helper H -> lifecycle supervisor S -> jailer J -> VMM V. A separate node monitor M runs outside every allocation cgroup. H/M retain a pidfd for S; S calls `PR_SET_CHILD_SUBREAPER` **before** releasing J. The pinned `--new-pid-ns` jailer clones V, writes a PID file and exits; S expects J's normal zero exit and adopts V. J's exit never constitutes VM cleanup. This is grounded in the pinned [jailer clone/exit source](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/src/jailer/src/env.rs).

S lives in the allocation's `control` leaf; J/V live in `vm/vmm`, and the console drainer in `vm/console`. The internal `vm` subtree contains both and has no direct tasks. M pins both cgroup descriptors and watches S/V pidfds plus worker heartbeats. The helper records S's identity while S waits at a private gate; M must acknowledge a watch before that gate opens. S reports V only after opening a pidfd and validating host boot ID, start time, executable **device/inode/digest against the retained-FD journal record** and exact `vm/vmm` cgroup inode. The PID file is only a candidate. H/M independently register the V watch before READY. The dedicated UID/GID, no unrelated allowed processes in that VMM leaf and prior C2 ownership also cover the interval before V's identity is published.

An unexpected S exit while H is healthy causes M/H to atomically set an in-memory stop fence before servicing another Validate/Exec, enqueue a durable STOP_INTENT, and dispatch `cgroup.kill` against the pinned `vm` subtree through recovery workers. A reusable response/dispatch must hold the same state generation, find both monitors healthy and perform a nonblocking pidfd-readiness check on S/V at the dispatch linearization point; stale Ready receipts cannot authorize it. A death racing a dispatch already admitted is an in-flight interruption and is retired, not reported as reusable success. Detection/dispatch target is 250 ms under the tested load envelope; kernel exit itself is confirmed, never assumed from that target.

An unexpected V exit similarly fences the allocation, drains/kills remaining `vm` tasks and reaps descendants; only pidfd exit plus populated=0 permits STOPPED. S may then clean mounts/files through its lifecycle state; READY/IDLE is not retained. J's nonzero exit, absent/forged PID file or uncertain child identity instead fences and stops the owned VM cgroup. After restart, open a fresh pidfd and revalidate identity before signaling; mismatch never falls back to numeric `kill(pid)`, only the independently verified allocation cgroup.

S retains a helper-parent-death notification with the post-arm PPID check. If H dies, S requests stop and kills the VM subtree; root ledger recovery is the fallback if S also dies. If M exits, its heartbeat expires (one second), or a watch cannot be armed, H immediately denies Create/Validate/Exec for affected allocations and invokes stop via reserved recovery capacity. M and S also have a fail-closed one-second H heartbeat, so a live-but-stalled H is not equivalent to supervision. These watches are event/clock driven, not the daemon's 30-second reconciliation loop.

C2 durably records conditional stop authority for supervisor/monitor/helper loss, timeout and protocol/resource breaches. Normally write STOP_INTENT before issuing kill. If the ledger writer is blocked, revoke reuse in memory and execute that **already durable conditional stop intent** without waiting for a new fsync; later record the event. Return only Unavailable/Unknown until journal evidence settles, never a successful stop, execution failure receipt or ABSENT that was not persisted. This preserves containment when the very storage needed to record an emergency is unavailable. Monitor health faults remain visible and charges survive.

No cross-database atomic transaction is claimed. Root node-ledger receipts precede daemon publication. If either ledger is unavailable, no corresponding admission is released. Repeat publication with bounded backoff/health degradation.

## 4.5 Recovery dispositions beyond the create matrix

These outcomes are mandatory fault-test assertions. “Charged” means both ledgers where C2 committed; C1-only failures still hold the daemon reservation even if no node claim exists. A stopped VM is never enough to release disk/identity capacity.

| Crash/event boundary | Required disposition and replay |
|---|---|
| Post-C1 collision, revalidation/deadline error or panic before INTENT | FAILED/charged until the exact ABSENT fence is durable; a queued duplicate returns that fence even after the original cause disappears |
| Capacity transaction commits but reply is lost | Node claim survives; retry exact token, never allocate another claim; daemon remains charged |
| S dies before or after J's normal exit, H remains healthy | Immediate stop fence, durable STOP_INTENT or previously authorized emergency kill; no reusable Validate/Exec; observe V exit and empty VM subtree |
| V dies while S lives, or M dies/stalls | Revoke Ready; stop remaining owned tasks and quarantine until proof; monitor repair never silently resumes that boot |
| H dies during EXEC_INTENT/BUSY | S/M contain V; restart replays ownership/charges and stops uncertain execution; no command replay |
| Worker blocks or request waiter disappears | Worker identity/permit remains live and charged; no replacement or late side effect after a fence; independent recovery continues |
| V exits before files/mounts/loop cleanup | STOPPED/charged; retry exact cleanup; no ABSENT yet |
| Cleanup finishes but ABSENT transaction/fsync fails | Still charged; re-inspect and finish the fence; missing files alone cannot release |
| ABSENT commits, reply or daemon terminal commit is lost | Helper claim is released; daemon remains conservatively charged until matching receipt replay and terminal/evidence transaction |
| Host reboots | Old PID evidence invalid; helper ledger/claims remain; prove changed boot epoch, clean durable resources and complete ABSENT |
| Daemon database is missing/restored/stale; node ledger survives | Block that instance's admission, retain every node claim, reconcile exact database/instance/allocation identities; never infer free capacity from the restored local sum |
| Node ledger is missing/corrupt or cannot sync | Node admission/reuse unavailable; emergency containment uses previously issued authority where available; no guessed absence, fresh empty registry or successful durable receipt |

# 5. Guest broker and execution protocol

## 5.1 Placement, privilege and kiln integration

Use the decided Rust workspace binary `kilnd-guest-broker` in kilnd, baked at a pinned commit/digest into kiln-guest. It runs as guest root, launched and reaped by compiled `/init`, outside the persistent tool sandbox. Root is necessary for the existing kiln CLI's namespaces, UID maps, mounts and cgroups; claiming an unprivileged broker while delegating nothing would be false. It offers only typed initialization, validation and kiln execution, not an arbitrary guest-root shell.

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

Helper connects to the exact recorded jail's `/run/vsock.sock`, checks inode/ownership and VMM identity, writes `CONNECT 5252\n` and reads a bounded `OK <decimal host-port>\n` (at most 32 bytes, two seconds). The returned port is an assigned **host** port, not necessarily 5252. The broker accepts AF_VSOCK host CID 2 only. It does not open guest-initiated host channels. No host `_PORT` listeners are installed. This follows the pinned [Firecracker vsock transport](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/docs/vsock.md).

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

Control payloads are strict UTF-8 JSON, `deny_unknown_fields`, duplicate-key rejection, no floats, no JSON recursion beyond 8 and no strings beyond their field bound. Host-to-guest control frames are at most 384 KiB (argv is at most 256 KiB plus JSON escaping overhead: **also reject if encoded size exceeds 384 KiB**). Guest-to-host control frames additionally obey section 5.6's 64 KiB cumulative encoded limit. Data frames are raw bytes, at most 64 KiB. The 4096-argument/256-KiB validation remains, with the encoded control limit an additional backend limit. Never allocate from an unchecked length. Types, order, request ID, per-direction sequence starting at zero, and total bytes are checked before dispatch. Overflow, trailing bytes after terminal close, duplicate terminal, unknown flags/version/kind and premature EOF are protocol failures.

Limits: stdin 1 MiB total; stdout/stderr retained prefix at most 1 MiB each; 64 KiB CLI diagnostics retained locally in the broker, narrowed to at most 2048 UTF-8 bytes in a wire diagnostic message. The broker drains/counts output after its retained prefix fills, with checked u64 counters. It does not buffer unbounded output or forward an unbounded stream to the host. The maximum resident payload/capture budget per active exec is 4 MiB plus fixed parser overhead, included in guest headroom.

Frame assembly/transfer and expected request/response stages are bounded to two seconds as specified in section 5.6; connection/stage timers start before the first byte and trickling never resets them. Waiting for command completion is bounded by the original execution deadline. Stdin must finish within two seconds of Exec acceptance or the remaining execution budget, whichever is smaller. No service busy-loop or blocking socket I/O: host helper uses per-syscall `MSG_DONTWAIT`, including Unix shutdown; broker uses nonblocking vsock reads/writes and readiness polling.

## 5.3 Message set and session binding

| Kind | Fields / behavior |
|---|---|
| `Hello` (1) | Host challenge[32], expected instance/allocation/sandbox IDs, boot nonce, manifest/launch digests and `guest_exec_spec_sha256`, supported protocol=1; one per connection before any other verb |
| `HelloReply` (2) | Echo challenge, identity from vdc, guest kernel boot ID, broker build digest, kiln CLI protocol/features, runtime-hardening booleans, work UUID/mount flags, persistent inner ID if already initialized |
| `Initialize` (3) | Exact label-free execution spec, `guest_exec_spec_sha256`; allowed once per cold boot after Hello; a duplicate identical request returns the same result, a conflicting one closes/quarantines |
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
3. Wait for VMM exit and the `vm` subtree populated=0; fence and settle every worker permit that could start another guest or command. A trusted cleanup-only S may remain in `control`, still charged. Verify identities before signals; use `cgroup.kill` for surviving owned VM tasks. If not settled within the 60-second cleanup attempt, return CleanupFailed with disposition Quarantined, hold durable reservations and refuse further Exec. A cleanup worker remains journal-owned/retryable; no success is claimed.
4. With host stop proof, a genuine timeout/cancel may return TimedOut/Canceled **with `reusable=false`** and the sandbox becomes LOST. A protocol/cleanup error remains Failed even if teardown succeeded. Observed command termination and output prefixes remain separate evidence. Delete subsequently removes the disk and all other resources before capacity returns.

Pre-dispatch cancellation with proof no Exec bytes could have been sent can preserve the ready VM. A normal completed result that was validated before the first cancellation wins over a later disconnect, as today. If the daemon/helper crashes during EXEC_INTENT/BUSY, startup stops the VM; it never retries the command or adopts the session based on a later “idle” claim. Mark the execution INTERRUPTED only after the host stop barrier, or FAILED/CleanupFailed with quarantine if that barrier is unavailable. Reconnection is for observation/cleanup only; commands are not replay-safe.

This intentionally extends the Runtime contract: cleanup success no longer always means reusable sandbox. Section 9 makes that explicit for every caller and test; otherwise a builder could accidentally run the next queued command in a retired guest.

## 5.6 Hostile transport and console work

Enforce these bounds at the **host relay**, even if guest root has replaced the broker. A valid per-frame length never authorizes an unbounded stream. Per execution, cumulative stdout and stderr payloads may each be at most their negotiated retained-prefix limit (at most 1 MiB each); all other guest control payloads combined may be at most 64 KiB. Count both channels and headers: at most 128 guest-to-host frames, including empty frames, and at most `stdout_limit + stderr_limit + 64 KiB + 128*36` wire bytes. Each non-exec exchange has a separate guest-to-host 64 KiB/16-frame cap; only one control request may be outstanding. Unsolicited or repeated control replies fail immediately, including while idle. During BUSY, Validate reports the recorded busy state and host process watches establish liveness; do not spend the execution frame allowance on periodic guest polling. Cancel/CancelAck is idempotent and budgeted once per token. Each limit is checked before allocating/reading the advertised body. Exceeding any bound, a sequence overflow or output after Result is a protocol breach: fence reuse, request durable stop and retire the VM. Guest-observed totals can be larger than kept prefixes, but cannot authorize additional transport. Host-to-guest stdin remains at most 1 MiB and is subject to equivalent counters and write deadlines.

Start timers at connect/accept, **before the first byte**. UDS connect/CONNECT/OK, Hello, each newly accepted control exchange and Exec acceptance have absolute two-second stage budgets bounded by the original operation deadline. An unsolicited/unassigned accepted channel gets two seconds to identify its role; at most two are retained. A frame's entire header and body must arrive within two seconds once that frame is due; trickled bytes never reset it. After Accepted, waiting for a legitimate long-running command's first output/result is bounded by the original execution deadline, not a new two-second execution limit. Once result transfer starts, all retained output/Result/EOF must settle within two seconds. Every write, including Cancel and output delivery to kilnd, has a bounded settlement deadline; never-read peers cannot pin a worker indefinitely. No new deadline extends the original execution budget.

A relay reads or writes at most **64 KiB or four frames**, whichever comes first, before yielding and checking cancellation, generation, cumulative counts and remaining time. Limit reading to 4 MiB/s with a 256 KiB burst; backpressure within the same deadlines is allowed, accumulated work is not. Parsing has bounded JSON depth/fields and no per-byte logging. One session-specific unprivileged relay process, outside H's listener runtime, handles both channels with a reserved control queue. Its memory/CPU/PIDs are charged to that allocation (section 6.4). A breached or stalled relay cannot take a recovery worker or run code on the root listener.

Console stdout/stderr is a separate hostile source. A dedicated drainer in `vm/console` continuously reads **to EOF**, retaining only the first 64 KiB combined and checked counters; after the prefix it discards, rather than ceasing to read. Do not stream serial bytes to journald or API logs. Read in 64 KiB quanta, enforce 1 MiB/s sustained traffic with a 256 KiB burst and a 50 CPU-millis cgroup cap. Rate excess requests VM retirement; until exit, continue bounded draining/discarding under that CPU cap so a full pipe cannot block the stop path. The original prefix is useful diagnostic evidence only. Drainer death, counter overflow or inability to sustain the bounded drain also retires the VM. Output collection may be partial on forced termination, never fabricated as complete.

Limit breaches normally persist STOP_INTENT before a typed failure response. If that write is unavailable, section 4.4's precommitted emergency authority permits containment, but the response is only Unknown/Unavailable and the reservation remains. Healthy Inspect/Stop/Remove use separate scheduling and reserved workers, with fairness proven under simultaneous vsock and console attacks in B5/B6.

# 6. Typed Firecracker helper operations

## 6.1 Private transport compatibility

Add `Operation::Firecracker(FirecrackerRequest)` alongside `Operation::Kiln`. Preserve the v3 envelope, fixed 2 MiB outer frame bound, absolute monotonic deadline, no incoming descriptors, strict fields, root/service-UID peer checks and helper-created Exec stdio pairs. For Firecracker Exec send the three **opposite** endpoints and wait for the same receipt byte before dropping handoff copies or doing I/O. Continue `MSG_DONTWAIT` on every helper read/write; never reintroduce caller-shared open file descriptions or wait for output on the listener thread.

Use an explicit Firecracker group schema version 1 inside the v3 request. Old v3 helpers reject the unknown operation; backend capability preflight must detect that before CREATING. If shared response structs change incompatibly for the legacy kiln branch, bump the whole helper protocol instead; do not silently broaden the v3 kiln contract. Prefer a new `Response::Firecracker(FirecrackerResponse)` so old kiln responses remain unchanged. Snapshot and raw API/argv/path verbs do not exist.

All requests carry the existing outer deadline/cancel, exact `instance_id` and active helper-issued connection epoch (except AttachInstance). Allocation selectors are typed 128-bit IDs, never paths. Profiles are root-catalog names (ASCII `[a-z0-9-]`, 1–64 bytes). Digests are exactly 32 bytes encoded as 64 lowercase hex characters. No operation accepts a PID, UID, CID, host path, nft source, environment or executable from a public caller. The helper derives identities from its own registry; Create's plan must match its own recomputation.

| Request | Fields in addition to instance/group version | Reply and validation |
|---|---|---|
| `AttachInstance` | instance_id, database_uuid | Refused unless root enrolled the instance and the peer proves the enrolled UID, unit cgroup and image (section 4.1). Long-lived binding to that process; one live holder per namespace, epoch for subsequent requests; the database UUID is reconciliation state only; no allocation or capacity release |
| `Capabilities` | none | Group/broker versions, available approved profiles and backend build; read-only, no boot. Cached identity with invalidation; two-second health budget |
| `Accounting` | none | Node-global ceilings/claims including once-only shared reserves, generation and freshness; no other instance's session identities; five-second budget, Unknown if authoritative snapshot unavailable |
| `Preflight` | allocation_id, sandbox_id, profile, effective `SandboxSpec` | Validated plan/reservation/digests; complete section 3 checks. At most 30 s, no session allocation |
| `Create` | allocation_id, sandbox_id, plan, plan_digest | Ready receipt/backend ID, matching ABSENT receipt, or charged ambiguous failure. Recheck manifest, exact config and limits; journal first; 120 s total |
| `Inspect` | allocation_id | Exact PresentReady, PresentBusy, StoppedWithResources, AbsentFenced, Incompatible or Unknown evidence; no restart or cleanup; at most 5 s |
| `Validate` | allocation_id, expected boot ID/nonce, expected inner ID | Process/journal and broker capability/idle validation; no absence from socket failure; at most 5 s and remaining exec budget |
| `Exec` | allocation_id, expected boot ID, execution token/public execution ID, argv, stdin_bytes, max_output | Existing typed outcome plus reuse/cleanup disposition; 3,600 s cap; owns cancellation through stop barrier |
| `Stop` | allocation_id, expected generation, reason enum | Host stop receipt or Unknown/CleanupFailed; journal fence first; no disk deletion; at most 60 s per attempt |
| `Remove` | allocation_id | Persist stop intent, stop VM, remove exact owned resources and persist ABSENT; idempotent; at most 60 s per attempt |
| `List` | none | Complete root-journal inventory plus namespace/process/cgroup cross-check; snapshot generation and explicit complete=true; at most 30 s |
| `Gc` | unique allocation_ids, at most 1024 | Only named, proven dead/stale allocations; skips/refuses live or unknown; empty is no-op. Returns individually proven removal receipts; at most 30 s |
| `FenceAbsent` | allocation_id, sandbox_id, expected plan digest | For missing/unpublished Create recovery: serialize, reject/settle all delayed writers, inspect all derived resources, persist absence fence. Any conflict stays ambiguous; at most 30 s |

`Stop`/`Remove` are authorized containment, not a way to release capacity on a timeout. A deadline or disconnect ends an **attempt**, records retryable stop intent and returns inconclusive if evidence is unfinished. Accepted mutation ownership moves to a bounded helper supervisor, not the request future. Hard-killed/unreapable tasks can outlive an attempt; they retain journal, reservation and a health fault. The daemon's reconciliation worker retries with bounded backoff. A successful receipt includes instance/allocation, generation, plan digest and relevant process/absence observations, and only follows durable journal publication.

Legacy helper limits still apply: 64 operations overall, bounded stdin/argv/output and no arbitrary flags. Within those slots reserve four for Inspect/Stop/Remove/recovery; these are dispatch slots, not a claim that async tasks isolate blocking syscalls. Section 6.4 gives the separate process and cgroup limits; at most two preparation jobs and one exec per allocation may run across the node. Non-exec deadlines always use the original wire deadline, never fresh internal budgets. Return RESOURCE_EXHAUSTED on full sub-budgets; do not queue unbounded privileged jobs. Healthy sessions can survive kilnd restart; active helper requests lose their waiter, but their cleanup responsibility does not disappear.

## 6.2 Exact default launch

Install pinned binaries under section 3.4's protected content-addressed tree. `J_SHA` and `V_SHA` below are the approved lowercase SHA-256 values, expanded exactly from the root catalog; they are not caller substitutions:

```text
/opt/kilnd/exec/sha256/V_SHA/firecracker
/opt/kilnd/exec/sha256/J_SHA/jailer
```

For allocation `A` (32 hex digits), jailer ID is `fc-A`, jail root is `/var/lib/kilnd-helper/jails/firecracker/fc-A/root`, and allocation cgroup is `kilnd-firecracker/I/fc-A` relative to the cgroup v2 root. `I` is the instance ID; the helper pins all ancestors. Derived `/run/vsock.sock` paths must fit Linux's Unix socket length before allocation. Section 7.1's bounded tmpfs is mounted before jailer can write anything.

The allocation parent has `memory.max=939524096` (896 MiB), `memory.swap.max=0`, `memory.oom.group=1`, `pids.max=32`, `cpu.max="100000 100000"`, and no direct tasks. Enable memory/pids/cpu controllers through its internal nodes. Leaf `control` contains S and preparation tasks; leaf `relay` has `memory.max=16777216`, `pids.max=4`, `cpu.max="5000 100000"`. Internal `vm` contains leaves `vmm` and `console`; the console leaf has `memory.max=4194304`, `pids.max=2`, `cpu.max="5000 100000"`. Other descendants inherit the parent ceilings. These are component caps **inside** the total, not additional reservations. There is no late migration of already allocated guest RAM. S remains in `control`; its gated J child enters the verified `vm/vmm` leaf before exec. The monitor and recovery workers stay outside all allocation parents.

Construct this exact argument vector (display wrapping only), then invoke it through `execveat(jailer_fd, "", argv, empty_env, AT_EMPTY_PATH)` under section 3.4. The first line is argv[0], **not** an executable pathname lookup:

```text
/opt/kilnd/exec/sha256/J_SHA/jailer
  --id fc-A
  --exec-file /opt/kilnd/exec/sha256/V_SHA/firecracker
  --uid U --gid G
  --chroot-base-dir /var/lib/kilnd-helper/jails
  --cgroup-version 2
  --parent-cgroup kilnd-firecracker/I/fc-A/vm/vmm
  --new-pid-ns
  --resource-limit no-file=256
  --
  --no-api --config-file /config.json
```

`U` and `G` are separately typed values from disjoint-per-allocation UID and GID leases (initial ranges 300000–365535, checked against NSS/subuid/subgid and existing allocations). Equal numeric UID/GID pairs are allowed; treating one as a substitute for the other is not. There are no `--cgroup` arguments: the pinned jailer joins the existing parent path directly. Its silent behavior for a missing path is compensated by prior verified J membership and the inherited cgroup boundary. `--new-pid-ns` uses section 4.4's subreaper and monitor, not the jailer process as VMM liveness evidence. See the pinned [jailer contract](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/docs/jailer.md).

Jailer adds `--id fc-A` and three internal timing arguments (`--start-time-us`, `--start-time-cpu-us`, `--parent-cpu-time-us`, each an unsigned decimal microsecond value) before `--no-api --config-file /config.json`. The complete VMM argv is `/firecracker` followed by those fixed pairs and the two configured options. These timing values are jailer-derived diagnostics, explicitly excluded from the semantic launch digest; their names/order/types remain contract-bound. No caller chooses them. S sets empty environment, stdin `/dev/null`, no core dumps, restrictive umask and section 5.6's captured/drained stdout/stderr. S unshares a network namespace with no configured links/routes before J; there is no host-network fallback. No daemonize, API socket, custom seccomp or PCI flag is permitted. Only section 3.4's two fixed bootstrap FDs may cross into J; both close on VMM exec, and no other extra FD is permitted.

**Pinned jailer patch prerequisite:** section 3.4's descriptor handoff, read-only executable bind, bootstrap gate and FD sanitization are mandatory extensions to the pinned 1.17.0 lineage. The same reviewed artifact implements the following capability-drop requirement: changing UID alone is not proof of an empty bounding set. The approved jailer artifact must explicitly clear supplementary groups, ambient/inheritable capabilities and every bounding-set bit while it still has the necessary privilege, then set the selected real/effective/saved GID and UID, clear remaining capability sets and set `no_new_privs` before exec. These are narrowly reviewed final-handoff changes, not an arbitrary wrapper accepted through `--exec-file`. No stock-jailer or pathname-exec fallback exists. Pin its source patch and binary digest separately in the approved bundle/catalog, using its content-addressed installed path above. B1 freezes that requirement; B4 proves the actual `/proc/<vmm>/status` values. The current upstream UID/GID handoff must not be assumed to satisfy the zero-bounding-set gate. No production code or approved patched binary is supplied by this design.

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
  "vsock": {"guest_cid": 3, "uds_path": "/run/vsock.sock"}
}
```

CID 3 above represents one reserved CID; use the allocated value. The approved schema explicitly authenticates that substitution. Firecracker defaults not represented in this config are fixed by the approved VMM version and the schema's absence requirements; changes to those defaults require review/repinning, not an untracked upgrade.

The helper service needs writable exceptions for its journal/jails and delegated cgroup subtree, plus KVM access. The current kiln-only capability set lacks jailer device-node/chroot authority: add tested `CAP_MKNOD`, `CAP_SYS_CHROOT` and the final bounding-set drop's `CAP_SETPCAP`, scoped to the workers that require them, retaining the existing namespace/UID/ownership capabilities. Verify actual effective/permitted/bounding/ambient sets. VMM must have the reserved UID U and GID G, an empty `Groups:` list and **zero effective, permitted, inheritable, bounding and ambient capabilities**, `NoNewPrivs=1`, default Firecracker seccomp and inherited service filters. No host AF_VSOCK permission is needed: the helper uses AF_UNIX. Do not remove Phase 0's address-family/personality/realtime/kernel-log filters to make launch work; integration must resolve any exact required delta and document it.

## 6.3 Later networking, explicitly not implemented here

There is no general `Tap`, `RunNft` or Firecracker API passthrough request. A later version may add a typed `NetworkPolicy` to the approved Create plan, internally causing helper-owned TAP creation and fixed nft transactions. It must journal names/ifindices and default-deny policy **before** the NIC becomes usable. An unsupported network request today is rejected before allocation.

That later gate requires per-session source MAC/IP validation; IPv4 public-destination filtering including private, link-local, metadata, multicast and host services; explicit IPv6 denial until supported; established return traffic only; constrained DNS; no guest-to-guest routes; anti-spoofing; and atomic ruleset installation/recovery. No global firewall flush, default-policy relaxation or shared mutable test address. Guest kiln policy only narrows the host policy. Removal disables the TAP before deleting nft rules; incomplete policy restore quarantines the VM. Reuse Phase 0's validators and DNS confinement tests, but never mistake guest nft for the outer wall.

## 6.4 Fixed workers, blocking syscalls and detached ownership

H's current-thread socket runtime performs only bounded nonblocking framing, peer authorization, in-memory generation/limit checks and dispatch. Filesystem access, `/proc` walks, hashing, SQLite transactions, fsync, fallocate, mkfs, mount/unmount, cgroup operations, inventory and removal never execute synchronously on that runtime. Cached Capabilities/health may be served while storage is stalled; cached Inspect must say Unknown/stale when a fresh observation cannot finish. An accepted deadline still expires on time.

| Class | Fixed node limit and placement | Work and failure ownership |
|---|---|---|
| Ledger writer L | 1 process, shared helper cgroup | Fixed SQLite transactions, journal fsync and the bounded attachment proof (section 4.1) on its own queue lane, with the enrolled inode's digest remembered by stat identity; no tenant I/O. Bounded queue; a stalled L denies new admission and publication, never releases claims |
| Preparation P | 2 job slots across **all** instances | Startup read-only hashing in the shared cgroup; after C2, session hashing/fallocate/mkfs and children in that allocation's `control` leaf. One active preparation job per allocation |
| Lifecycle S | 1 per accepted allocation, `control` leaf | At most one blocking mount/process/teardown/inventory job at a time, no unbounded thread creation. Operates after a journaled permit; remains owner after request disconnect |
| Broker relay R | 1 per allocation, `relay` leaf | Unprivileged bounded parsing/transport; no root filesystem or ledger operations. Two channels share the section 5.6 fairness rules |
| Console drainer D | 1 per allocation, `vm/console` leaf | Continuous bounded capture/discard; no root operations; death causes containment |
| Monitor M | 1 node process, shared helper cgroup | Nonblocking pidfd/gate/heartbeat events and stop dispatch only; no blocking journal, filesystem or cgroup writes in its loop |
| Recovery K | 2 process slots, shared helper cgroup, reserved exclusively | Pinned-cgroup kill, pidfd/process/cgroup proof and final empty-cgroup removal; never hashing, formatting, general inventory, full directory cleanup or waiting for L |

R has its own allocation-specific UID/GID leases, distinct from VMM U:G, kilnd's service UID and every other allocation; claim them in C2 and release only with ABSENT. Drop groups/capabilities, prohibit new privileges and supply only private relay/control FDs. R cannot authenticate to the public helper socket as kilnd or select privileged operations; its narrow internal channel reports bounded events for its already-bound allocation. D may use its own VM's U:G with only console pipe/control FDs. Both workers' identity and resource limits are contract-bound, not guest-selected.

These are process **limits**, not replacement-on-timeout threads. Persistent control components and jobs together also obey the shared/per-allocation PID and memory ceilings in section 7. Reassigning a slot requires prior worker exit/reap and settled permits. A D-state or otherwise unkillable worker consumes its original slot indefinitely, remains visible with PID/start-time/cgroup/operation generation and leaves its allocation charged/quarantined. Its waiter may time out; its ownership cannot time out. Never spawn replacements over the count. Exhaustion returns ResourceExhausted/Unavailable within the request deadline and degrades Health; it does not borrow a recovery slot.

L journals a WORKER_INTENT and operation generation before spawning a gated worker; after spawn it records the worker's host boot ID, PID/start time, expected executable device/inode/size/digest under section 3.4, cgroup and allowed resource names before releasing the gate. Every executable launched by a worker, including the formatter and any re-exec of S/L/P/R/D/M/K, obeys that same rule; fork-only modes record their inherited verified helper image. Initial infrastructure workers are registered at service startup before accepting traffic: every slot needs its durable row with an exact reply, retried within a 30 second budget, and past that the group does not start and kiln alone is served. A replacement L necessarily forks before it can write. It stays private, is discarded and reaped unless predecessor settlement and its own `RecordInfrastructure` both return the exact reply, and the fault is surfaced in Capabilities while the slot keeps refusing ledger traffic. Creating a new allocation's cgroup uses a registered infrastructure worker and the C2 namespace intent; all allocation-heavy work starts only after the worker moves into and validates its assigned cgroup. Monitor acknowledgment is also required before S/J gates open. Every side effect checks its permit; a fence revokes future permits, and ABSENT waits for all issued workers to settle. Persisted identity before side effects, not an impossible durable PID before fork, is the invariant.

P and S do not hold the global capacity transaction or a root-listener lock across a blocking syscall. S serializes this allocation's mutations; independent K can invoke already-authorized emergency containment even if S is stuck. Inventory is bounded incremental work in S (or one available P slot for an unallocated namespace), and returns incomplete on deadline/worker shortage. No synchronous recursive traversal runs in H. L's blocked fsync can delay durable answers for **all** allocations; independent K still kills under C2's conditional authority, while H returns honest Unknown/Unavailable. No design can promise successful durable cleanup through a failed node storage stack.

A normal Remove lets S finish owned mount/file cleanup, closes its side-effect permits, then reaps S/P/R/D; K verifies the final empty allocation cgroup and removes it. L may publish ABSENT and free the node claim only after those observations. Partial cleanup retains the claim. If a recovery syscall itself becomes uninterruptible, that fixed K slot remains occupied; H still answers within deadlines and reports degraded cleanup. B4 demonstrates one stuck worker of each class and full P/S slot exhaustion without listener starvation or a healthy allocation borrowing those slots; it distinguishes a completed Stop from a bounded Unknown response when the shared kernel/ledger prevents proof.

# 7. Storage and resource admission

## 7.1 Private work disk and mandatory jail bounds

The immutable Squashfs root and kernel are verified on every create from the approved store and attached read-only. Create uses an exclusive regular single-link private work file under a helper-owned 0700 allocation directory outside the jail; no symlink traversal, tenant-supplied block image or host mount of guest-written XFS is allowed. There is no shared writable seed or host directory exposed to the guest.

Let D be the requested inner writable quota. Set:

```text
W = max(512 MiB, round_up(D + 256 MiB, 64 MiB))
reserved_host_disk = W + 128 MiB
```

The 256 MiB leaves guest XFS/kiln bookkeeping headroom. The 128 MiB host allowance covers bounded staging, identity, metadata and per-allocation ledger/control files; reject an approved footprint that cannot fit it. For the existing 1 GiB quota, W=1280 MiB and the host disk reservation is 1408 MiB. Keep the inner quota intact.

After the node-global C2 claim and real free-space check, P uses `openat(O_CREAT|O_EXCL|O_NOFOLLOW)` and full `posix_fallocate`/equivalent for W. Unsupported preallocation fails, without a sparse fallback. Persist the inode/size and fresh UUID before formatting. Invoke the approved formatter by its retained verified FD under section 3.4. `F_SHA` is its catalog digest; the following is the exact logical argv, not a PATH or pathname execution:

```text
/opt/kilnd/exec/sha256/F_SHA/mkfs.xfs -q -f -K -m uuid=<fresh-uuid> <derived-work-path>
```

`-K` prevents discard undoing preallocation. Format only the new inode before exposure; verify identity before/after and sync file/parent. Never mkfs/repair a disk after a guest has written it. The backing file stays root-owned 0600 and inaccessible to jail UID/GID.

Expose the work volume as a **helper-owned loop block device**, size limit exactly W, rather than a writable regular backing file inside the jail. Persist LOOP_INTENT with the chosen slot's major/minor, backing device/inode, offset=0 and size limit **before** LOOP_CONFIGURE/binding, then persist the verified attachment before exposure. An unexpectedly busy slot is a conflict, never permission to replace its backing. Binding, cleanup and crash recovery validate all of those identities. Bind only the device node as `/work`, owned U:G and mode 0600; no loop-control device, host `/dev` directory or backing-file path enters the jail. The unprivileged VMM cannot grow/truncate the root-owned backing file or resize the block device. Disable discard/unmap paths that could punch holes in the allocation guarantee. B4 must prove the pinned Firecracker synchronous block backend accepts this fixed-size block device and cannot enlarge/rebind it under the VMM credentials/seccomp; an unsupported backend fails closed, without a regular-file fallback. Loop attachment is privileged typed storage work, never a caller-selected device.

Guest init mounts vdb at `/var/lib/kiln/runs` with `nosuid,nodev,noexec,prjquota`. Kiln's persistent sandbox project quota bounds blocks and inodes, probed before Ready. Test direct work-path execution denied and normal overlay execution allowed. Guest root can bypass its inner quota but cannot exceed W; this is a physical outer bound, not trust in guest enforcement.

**Every writable jail byte and inode is bounded from the first jailer write.** Before launching J, S mounts the entire jail root as private tmpfs with `size=16M,nr_inodes=1024,mode=0700,nosuid`. Charge its pages/metadata to the allocation; include its full 16 MiB in the provisional host memory allowance. Executing the VMM and accessing KVM require exec/device access, so do not falsely specify noexec/nodev on this whole mount. Kernel/rootfs/config/identity are verified read-only bind mounts; `/work` is the bounded block device. No other writable bind, host filesystem or external logging path exists. The VMM executable is a read-only bind of the retained approved inode, not a writable jailer copy; check that remaining cache/control files fit the cap before accepting this profile. Node metadata and immutable-store headroom are reserved separately below.

The pinned jailer chowns `/`, `/dev`, `/dev/net` and `/run` to its UID, so root ownership before launch alone is insufficient. After J's expected exit and V's identity validation, S stops V through its pidfd. It hardens the root, `/dev` and `/dev/net` to root-owned 0755 and cache files to root-owned 0444, preserving only the explicitly needed device-node U:G access. It independently verifies that `/firecracker` remains the root-owned 0555 read-only bind of the expected inode, leaves only `/run` writable by U:G, checks the resulting mount tree and resumes V. Do this before Ready; a missing/failed hardening step retires the VM. Even a malicious pre-hardening VMM, a retained writable FD or unexpected path creation remains bounded by the **whole-jail** tmpfs cap. Fixed artifact mounts are read-only independent of chmod. All walks/hardening use pinned directory descriptors, no-follow opens and mount IDs; reject replacement entries instead of following links.

An optional host XFS project quota can narrow the host session-storage allowance, but is not its security mechanism. Portability relies on the preallocated root-only W backing file, exact-size loop exposure, mandatory whole-jail tmpfs byte/inode cap and fixed-size helper metadata. Fill files, sockets and inodes as U:G in B4 and show the node journal/recovery headroom stays available. Quota/ENOSPC faults retire only the affected allocation and never relax these limits.

Delete proves VMM/worker exit and FD closure, unmounts owned binds/tmpfs (no lazy unmount as absence proof), detaches the loop device with verified backing identity, proves no pending loop attachment/holder, removes the private backing file and bounded control files, syncs parents and removes the empty cgroup. A crash after loop setup but before recorded attachment requires inventory of the reserved slot/backing identity; ambiguity stays charged. Refuse unknown inodes/mounts/devices. Deletion is destructive and authorized by DeleteSandbox; there is no export/retention or secure-erasure claim. Encryption/export/snapshots remain separate features.

## 7.2 Durable reservation vector

Add an explicit stored reservation independent of `SandboxSpec`. Do not recalculate surviving reservations from today's defaults or a newly selected bundle. Schema migration preserves all legacy kiln charges exactly. The new Firecracker formula is versioned in the stored plan:

| Dimension | Phase 1b reservation / enforcement |
|---|---|
| Memory | Guest G + 128 MiB provisional VMM/KVM/cache/S/P/R/D allowance, including full 16 MiB jail tmpfs; default 896 MiB. Outer memory.max equals this; swap.max=0; oom.group=1 |
| Guest headroom | Inner workload <= G−256 MiB; kernel/broker/init/filesystem activity use that remaining guest capacity; it is **inside G**, not added again |
| CPU | 1 integer vCPU plus 1000 host CPU millis per VM; outer cpu.max one core; inner quota <= one core. No overcommit by default |
| Workload PIDs | Existing `spec.pids` promise (default 128), enforced by kiln inside guest |
| Guest service allowance | 32 additional guest tasks, planning charge; bounded broker/init services and FD limits |
| Host PIDs | 32 per session, enforced by outer pids.max, including S/J/VMM threads, preparation jobs/children, relay and console drainer; measure before raising |
| Existing node PID sum | Conservatively sum workload + guest allowance + host allowance (192 default). Also expose host-PID subtotal; guest processes are not host tasks |
| Disk | W+128 MiB as above, not D and not current `du`; shared installed artifacts have a separate operator-provisioned storage budget |
| Sandbox count | One per session; booting, quarantined, deleting and ambiguous allocations all count |

128 MiB host overhead is a conservative initial **assumption**, not a measured worst-case bound. The spike's 32 MiB proposal predates the broker/production containment. The density test measured about 770 MiB PSS for a 768 MiB hardened guest, but excludes some external KVM/kernel costs and workload pressure. An outer OOM remains possible inside an inadequately sized allowance; it must be contained and reported. Stress measurement is a release gate before treating this as a supported production sizing profile.

## 7.3 Node-global admission and shared overhead

The daemon still uses its SQLite IMMEDIATE sum-and-insert transaction at C1 for local policy and durable ambiguity. It is **not** the node authority. At C2 the single root ledger atomically checks every vector component across all instances and all unreleased intents, then claims capacity plus distinct UID/GID/CID leases in the same transaction as INTENT. No resource side effect precedes that transaction. Per-instance quotas may narrow, never expand, this aggregate. Concurrent Create calls in separate daemon databases cannot both spend the last slot. Booting, busy, stopped, quarantined, ambiguous-after-INTENT and future pool members all retain their helper claim until matching ABSENT. A C1-only row remains locally charged even if the helper has not yet claimed capacity.

Default node policy: three VM slots, **3072 MiB total Firecracker memory budget including shared workers**, three vCPU slots, 3500 host CPU millis (3000 session + 500 shared), 2048 aggregate accounted PIDs with an explicit 128 host-task ceiling (96 session + 32 shared), and 16 GiB total backend storage. All arithmetic is checked; any exceeded component rejects admission, then obtains ABSENT before releasing the C1 row. The root catalog fixes node ceilings; a daemon cannot supply a larger node budget. Startup compares measurable physical/free capacity, existing reservations and configured host/service headroom. Lower limits degrade Health/deny admission, never delete work or discount existing commitments.

Reserve shared infrastructure **once per node**, before any session: 128 MiB RAM, 500 CPU millis, 32 PIDs for H/L/M/K plus shared validation/control processes, and 512 MiB on durable storage for the node ledger/WAL, bounded queues/control metadata and retired fences (64 MiB of that is the fence allowance). Give those shared processes their own cgroup with those ceilings outside all VM parents. Bound WAL/checkpoint growth and queues; stop new claims while retaining room for all outstanding stop/absence records. The immutable bundle store has a separate root-configured size/inode cap, initially 1 GiB, also deducted from the 16 GiB backend budget; do not sum it once per daemon. Provision actual filesystem free space for these reservations plus host-service headroom. The per-session 128 MiB disk allowance is neither license for arbitrary jail writes nor a substitute for shared journal space.

| Guest profile | Inner memory ceiling | Charge per VM | Capacity in a 3072 MiB backend budget, after 128 MiB shared reserve |
|---|---:|---:|---:|
| Decided 768 MiB | 512 MiB | 896 MiB | 3 (2816 MiB total including shared; 256 MiB left) |
| Candidate 512 MiB | 256 MiB | 640 MiB | 4 (2688 MiB total including shared; 384 MiB left) |

The 512 MiB profile needs its own approved contract and workload validation; it cannot preserve the current 512 MiB inner default. Four smaller guests also require a four-slot CPU/PID policy. If “3 GiB node” means **physical RAM**, reserve at least 512 MiB for other host/services first: a 2560 MiB backend budget including shared workers permits two 768 MiB guests or three 512 MiB guests. These are arithmetic planning limits; the 128 MiB per-session and 128 MiB shared memory allowances still require B7 measurement.

Daemons report node totals from the helper ledger, with freshness/generation and unavailable status when it cannot be read, rather than presenting a local sum as global. Keep owner-filtered API lists and private per-instance metadata; global totals reveal no other session identities. Each enrolled instance has one attachment slot, its own queue for attach attempts, its own share of the 128 detached operations, and its own quota of 4096/N non-durable token gates (N is the policy's enrollment maximum), none of them drawn from a common pool. Attach writes only its own row, once, and that first binding refuses past the fence-headroom floor; a reattachment writes nothing. AttachInstance and startup reconciliation compare database UUID/instance, all owned allocations and helper receipts before admitting. A missing/stale/restored daemon DB never reduces helper charges. Unknown or conflicting ownership quarantines admission; helper-ledger loss/corruption disables Create/Exec for the node until resource inventory and operator repair establish authority. Never recreate an empty ledger over possibly live resources. Helper restart replays all unreleased claims before serving; raw node capacity is not recalculated from idle PSS or currently visible PIDs.

No pool members initially. A future pool of one is a fresh cold-booted, never-used guest with the same global claim vector, leaving two active 768 MiB sessions while holding one spare under this policy. Assignment needs an atomic ledger ownership transfer and new identity handshake; it never releases/reclaims capacity in the middle, reuses a tenant disk or clones a snapshot.

# 8. Delete, list, GC, reconcile and retention

## 8.1 Delete ordering

Authorize owner/root before helper work. Under the existing stable per-sandbox coordination slot, durably change to DELETING with compare-and-set before canceling a running execution. Queued execs reload state and refuse. Serialize all Delete callers; followers return the same final row/timestamps.

Helper Remove persists STOP_INTENT and an irrevocable create/exec fence. Stop the VMM even if the broker is unavailable; guest shutdown may be attempted for at most two seconds but is never required proof. Wait for VMM exit, then cleanup through S and settle/reap all supervisor/preparation/relay tasks; verify empty cgroup, FD/device/loop closure and removal of every owned mount/file/socket as in sections 6.4/7.1. PID reuse, inconsistent resource identity, EBUSY or an expired proof attempt returns Unknown/cleanup failure. Persist ABSENT after directory sync, then return the removal receipt. The ABSENT transaction releases the helper's node claim; only the daemon's subsequent durable DELETED/evidence transaction releases its local reservation. This ordering can temporarily double-count a completed allocation, never undercount a live one.

If a crash occurs after VMM exit but before file cleanup, STOPPED remains charged. After resource removal but before ABSENT, re-inspect and finish the tombstone. After ABSENT but before SQLite commit, replay the same receipt and complete publication. Disk ENOSPC/fsync failure must never manufacture absence. A wholly missing record can only become an absence receipt through FenceAbsent. `RuntimeError::NotFound` by itself is not sufficient for the new path.

## 8.2 Inventory and scoped collection

`List` combines the root journal, fixed owned filesystem namespaces, cgroup membership and process identity. Read under a registry generation snapshot; retry a bounded number of times on concurrent mutation or return inconclusive. Include allocations that never reached ready/backend-ID publication. A complete response is bounded to 1024 active allocations and 1 MiB encoded inventory; excess/duplicates/corruption/partial frames are errors, not a truncated “complete” list. Retired fences use their separate compact ledger, not live listing slots.

Return each record's generation, allocation ID, plan digest, status and ownership scope. Status is Ready, Busy, StoppedWithResources, Stale, Quarantined or Unknown; only a healthy idle handshake is reusable. A missing process does not imply a missing work file; a missing journal with an unexplained cgroup/jail makes inventory incomplete. Never adopt an unknown directory solely because it looks like `fc-*`. Unknown resources block new allocations within the affected registry until resolved, remain visible to operators, and are not globally garbage-collected.

`Gc(ids)` accepts only this instance's recorded, individually proven dead/stale allocations and removes their remaining resources through the same absence barrier as Remove. It does not kill live VMs, even if not in the daemon's current API list. Recheck live identity under the per-allocation lock immediately before acting. No empty/global GC and no deletion of another daemon's or legacy kiln's resources. Return individual receipts; partial progress followed by error remains discoverable and charged until durably reconciled.

## 8.3 Startup and periodic reconciliation

Hold existing daemon state/socket ownership locks and establish AttachInstance before action; the helper alone owns its node registry lock. Rebuild the node claims first, then compare this daemon's exact namespace and database UUID. First validate all inventory/compatibility evidence without changing daemon rows or GC state. Never mark omitted sessions LOST from an incomplete list. Then reconcile exact allocation tokens:

- CREATING + identical helper READY/IDLE + no uncertain exec: re-handshake the same boot, publish READY. CREATING with partial allocation: fence/compensate, not another boot. Missing helper record: FenceAbsent, or charged failure if that proof cannot finish.
- READY with healthy identical boot and no execution ambiguity: preserve. Helper BOOTING/unknown boot, broker identity mismatch or incompatible deployment: quarantine, never declare Ready. Proven VMM absence becomes LOST but remains charged until resource cleanup/Delete.
- RUNNING execution or helper EXEC_INTENT/BUSY across a process crash: stop the VM, establish host cleanup, publish INTERRUPTED and LOST together (or cleanup failure/QUARANTINED). Do not mark an execution interrupted and immediately dispatch its queued successor before cleanup.
- DELETING: retry Remove and publish its durable absence. FAILED-with-allocation and unreleased reservation: compensate by exact token or retain quarantine; unlike the legacy no-ID failure, this allocation can be accounted for.
- ABSENT helper receipt + charged daemon row: release only through the matching terminal transaction. LOST is not automatically rebooted. A stopped boot never resurrects; an unchanged live VM temporarily unavailable to observation can recover only if no stop fence/uncertain execution exists.
- Helper-owned resource absent from daemon DB: report/quarantine the registry and reject new admission; do not invent an owner, release unknown capacity or delete live work. An operator-restored stale DB is not silently reconciled by guessing.

A host reboot invalidates all recorded PID identities. It does not erase work disks, jail state or reservations. Confirm old processes cannot exist via the changed host boot ID, then remove remaining owned resources normally. If proof is unavailable, serve degraded read/authorized cleanup operations where possible, deny Create/Exec and preserve rows. Do not weaken existing kiln startup behavior merely to make Firecracker recoverable.

Periodic reconciliation runs at 30-second intervals with jitter and singleflight ownership, plus on failed operations; stop attempts back off 1, 2, 4, 8, then 30 seconds. Work remains charged between attempts. A lower configured budget degrades Health and rejects new creates without preventing cleanup. No hidden guest restart or network repair is performed by Health.

## 8.4 Schema, ownership and history protection

Replace schema 7's `backend_id IS NOT NULL` inference with typed release evidence. For Firecracker, `reservation_released` is derived from a validated evidence reference, never an independently writable boolean. Migrate every legacy row using **exactly** schema 7's existing reserved predicate and spec-derived amounts; never reinterpret old ambiguous failures. For new Firecracker rows, **every release after C1 requires a matching durable ABSENT receipt**, including rejection before INTENT. C0 rejection has no row. A cleanup-failed FAILED row may have an allocation/backend identity and still be charged.

Add an immutable `release_evidence` table keyed by receipt ID, with NOT NULL node/instance/allocation/plan digest/helper generation/kind fields and a unique identity tuple. A Firecracker row's nullable `release_evidence_id` has a composite foreign key matching its own immutable identity/plan and `AbsentFenced` kind; SQL CHECKs/triggers reject mismatches, active-state releases and evidence mutation. Foreign keys are mandatory on every kilnd-owned connection. Legacy release provenance has a separate tagged representation and cannot satisfy a Firecracker reference. In the same transaction insert validated evidence, set the terminal row and evidence reference; absence of the reference means charged regardless of state/backend ID. Store the complete effective host spec and both explicitly named digests (`host_spec_sha256`, `guest_exec_spec_sha256`), reservation components, prepared plan/version, boot identity and cleanup disposition alongside it. Persist the API state/execution outcome/reservation-release decision atomically. Constraints forbid a released nonterminal Firecracker allocation and conflicting plan/identity updates. Older binaries must refuse the upgraded schema. Migration, prune SQL, reservation summation, manager compensation and delete fast paths must change in the same mergeable step; modifying only the Runtime adapter is unsafe.

**B2 SQL hardening (schema 9):** Store connections register deterministic and SQLITE_INNOCUOUS SQLite scalar function `kilnd_fenced_absence_valid` before preparing schema statements. A BEFORE INSERT trigger decodes the complete bounded receipt through production `FencedAbsence::decode`, requires byte-for-byte equality with its canonical encoding, and compares receipt/node/instance/allocation IDs, plan digest and helper generation with the constrained columns. The type encodes `AbsentFenced` implicitly; the column must be `absent_fenced`, and extra JSON kind fields are refused. Missing/duplicate/unknown fields, noncanonical hex/JSON, truncation and column mismatches fail closed. With triggers enabled, a standard external connection without the function cannot insert evidence, including valid bytes. The function name does not authenticate its implementation on another connection. This validates the typed encoding and binding; backend authority still comes from the private Store/runtime boundary, not a cryptographic signature. Upgrading schema 8 decodes every existing receipt directly in Rust in the migration transaction and refuses invalid evidence without changing rows or fences.

BEFORE INSERT and BEFORE UPDATE collision guards cover every unique sandbox key (ID, list sequence, non-null backend/backend ID and allocation ID), plus explicit SQLite rowid collisions. They raise ABORT before any conflict algorithm can implicitly delete a row, independently of foreign keys or recursive triggers. The other current tables are audited: `daemon_identity` guards its singleton primary key and forbids updates/deletes; `release_evidence` guards receipt ID, allocation ID and rowid (the two composite unique indexes include allocation ID), and forbids updates/deletes; `executions` guards ID/rowid collisions; `history_sequence` guards singleton replacement and identity changes while allowing normal sequence increments. No helper fence/journal tables exist yet in B2; B3 must apply the same rule to every such unique key. Foreign keys and recursive triggers remain enabled on Store connections as defense in depth.

**B2 trusted reads (schema 10):** All reservation sums, admission, get/list dispositions and prune selection audit a single SQLite snapshot before deciding released versus charged. Rust calls production `FencedAbsence::decode` and compares every receipt field with both evidence columns and the referenced row: receipt/node/instance/allocation IDs, plan digest, helper generation and `absent_fenced` kind; only terminal releases count. This does not call the SQL validator. Missing, invalid or mismatched evidence is projected as CHARGED/QUARANTINED, including a corrupt DELETED row in ordinary lists. The original reference/bytes remain durable for diagnosis, and a connection-local temporary quarantine set is rebuilt for each snapshot. Health reports degraded with the retained charge, new admission refuses, and prune retains the row. Every Store connection sets and verifies `trusted_schema=OFF`; the innocuous validator still supports legitimate `release_fenced` writes.

**Membership integrity marker:** `reservation_integrity` stores one versioned SHA-256 fingerprint over sandbox IDs, list sequences and immutable identity/spec/reservation/plan fields, ordered by binary ID and encoded with type tags and lengths. Only trusted Store insert and prune code refreshes it, in the same IMMEDIATE transaction as the membership change, after checking the previous marker. No trigger updates it. Startup and every accounting snapshot recompute and compare it. A deleted/replaced/changed row, missing marker or mismatch yields a degraded accounting error with unknown totals, never zero/free capacity; get/list, admission and prune refuse. Ordinary lifecycle and release transitions leave the marker unchanged. Legitimate pruning refreshes it atomically, while evidence/fences remain permanent. Schema 10 seeds the marker atomically from the migration snapshot; it cannot detect losses before first seeding or a coordinated hostile rewrite of rows and marker. This is diagnostic defense in depth within the file-permission boundary, not authentication or a substitute for the root node ledger. Auditing is linear in retained membership/evidence and immutable plan bytes; capacity/retention bounds apply.

Keep immutable caller UID, root override, foreign-as-NOT_FOUND behavior and SQL owner filtering before pagination. Helper metadata does not replace those checks. Keep `full|metadata|none` output semantics and existing age/count policies; retain charged, quarantined, unfinished and publication-pending rows. Pruning must consult explicit release evidence and cannot erase replay fences. Diagnostics/argv/specs may still contain private information; no new “secure erase” claim.

# 9. Runtime and public API changes

## 9.1 Internal contract, not a replacement abstraction

Retain Runtime's create/exec/remove/list/gc/version/validation roles. Add preparation and allocation recovery, and make cleanup disposition explicit. Suggested Rust-domain signatures below are normative about inputs/results; ordinary borrowing/lifetimes may be chosen locally. Futures remain `Send`; the trait remains generic, not object-safe.

```rust
struct PreparedCreate {
    spec: SandboxSpec, // complete effective host spec, including labels
    host_spec_sha256: Digest,
    guest_exec_spec_sha256: Digest,
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
| `NodeResourceStats` fields 10–15 | Max/reserved host CPU millis, vCPU slots and host PIDs, sourced from the node authority |
| `HealthResponse.runtime_capabilities = 11` | Generic capabilities including network modes, interruption-preserves-session=false, checkpoint=false; not raw provider details |

`ResourceReservation` uses u64 fields: `memory_bytes=1`, `disk_bytes=2`, `pids=3`, `host_cpu_millis=4`, `virtual_cpu_slots=5`, `host_pids=6`. `pids` is the conservative aggregate explained in section 7; host_pids is a component, not another amount to add. Existing memory/disk NodeResourceStats continue to mean node capacity promises, now correctly including backend overhead. Expose an additive backend-neutral accounting generation/freshness status (next unused field, checked at implementation) so stale/unavailable helper totals are never silently replaced with local values. Shared reservations count once in node totals and do not appear as a caller-owned sandbox. The sandbox spec remains the tool limits.

Unsupported profiles/images/network return `FAILED_PRECONDITION` (invalid grammar remains `INVALID_ARGUMENT`); budget exhaustion is `RESOURCE_EXHAUSTED`. A queued timeout still creates no row and returns `DEADLINE_EXCEEDED`. A dispatched timeout can return a terminal TIMED_OUT execution after teardown and publication, with reusable=false and the sandbox LOST. Quarantined sandboxes reject Exec with `FAILED_PRECONDITION`. Clients must check state/reusability, not assume that a successful Exec RPC means the session survived.

Update `kilndctl` display/help for these fields without changing existing exit-code projection. Public streaming Exec, per-call environment/cwd, session sub-sandboxes, TTLs, public idempotent Create and restore APIs remain separate work.

# 10. Test and adversarial acceptance plan

All production assertions below are **required future tests**, not tests performed for this design document. Fake-based tests run on macOS and Linux. Privileged tests run only in a dedicated Linux test allocation/VM under the shared VM lock; never silently alter installed services or consume all shared host memory.

## 10.1 Unit, property and fake-runtime tests

- Golden approved manifest/contract/config/argv fixtures shared with kiln-guest. Mutate every security-critical field independently: unapproved digest; coordinated image+manifest substitution; valid manifest with wrong artifact; extra/missing/renamed artifact; size/hash mismatch; symlink/hardlink/path substitution; duplicate keys; unknown schema/field; debug/test args; `nokaslr`; init zeroing off; writable root; changed vCPU/RAM/THP; extra NIC/vsock/drive; custom seccomp; API/snapshot flags. Assert **zero** session allocations, helper workers with resource side effects and reservation insertion on preflight rejection.
- Deterministic crash/fault injection before and after every C0–C8 journal sync, rename, spawn gate, reply and SQLite commit. Repeat Remove/reconcile twice; final state and timestamps are idempotent. Inject ENOSPC, fsync/write failure, missing/partial journal, corrupt generation, stale DB restore, worker panic, lost create response, and delayed duplicate Create racing FenceAbsent. Never release ambiguous capacity or launch after a tombstone.
- Prove schema migration preserves all legacy charges and owner_uid=0 historical semantics. Specifically FAILED with a newly known backend ID but no absence proof remains charged. Zero-count/zero-age prune preserves quarantine, charged failures and unfinished/publication-pending executions. Output storage modes retain today's semantics.
- Reservation arithmetic: checked maximums/rounding, RAM overhead rather than PSS, 3×896+128 shared fits but 4×896+128 fails at 3 GiB; concurrent cross-instance node transactions, all vector dimensions, changed/lowered limits on restart and future pool charges. Exactly three of four concurrent claims can reach INTENT under the three-slot policy; failed C1 callers still require ABSENT.
- Broker framing fuzz/property tests: every header boundary, trickled bytes, 0/oversized length, bad version/kind/flags/sequence/token, duplicate/trailing terminal, forged stdout status, stdin undershoot/overshoot, partial binary output, arbitrary non-UTF8 data frames, JSON depth/escaping, accounting overflow and unknown outcomes. Memory remains bounded; cancellation control progresses under full output buffers.
- Host/guest deadline clocks have unrelated origins; queueing/preflight/setup consume one host budget. Guest never gets a reset on reconnect. Test pre-cancel, timeout at dispatch, result-vs-cancel races, missing result EOF, genuine exits 124–127 and signal 15, hung capture reader, cleanup-error precedence and reusable=false publication before unlocking queued work.
- Executable replacement properties (KR-05): replace each source parent or installed name after hashing and before dispatch, including J, V, formatter and every separate worker image. An unchanged plan cannot authorize a different device/inode/digest, even when a replacement has identical bytes. Cover writable/ACL-granted ancestors, non-root rename authority, symlinks/hardlinks, stale descriptor generations, interpreter/loader substitution and FD close/reuse. C0 rejection has zero session effects; later mismatch remains charged until ABSENT. Fakes model both expected and **actual executed** tuples, not only argv or prior hashes.
- Root transport regressions from protocol v3 remain: receipt withheld/early/duplicate/cross-connection, SCM_RIGHTS injection, descriptor leaks, mutated O_NONBLOCK, stalled stdin/stdout, expired non-exec deadline, 64-slot exhaustion and recovery. Firecracker adds no root path or arbitrary command primitive.
- Ownership: foreign caller cannot Probe/Exec/Delete or inspect output via the new fields, root retains authorized visibility, pagination filters first, helper only accepts the exact service UID. Wrong instance/allocation/plan IDs never reach another session.

- Enforce typed release evidence at the SQL layer: direct updates cannot free C1 using FAILED/backend ID/boolean, a missing/wrong-kind/wrong-identity receipt, forged legacy provenance, foreign-key-disabled connection or evidence mutation. Migration/pruning and fake-runtime paths all exercise the same constraints.
- Deterministically queue two identical Creates. Make the first fail before INTENT, pause ABSENT fsync, and verify failure publication stays charged. After fsync/publication, remove the collision and release the duplicate; it must return the same fence. Repeat catalog mismatch/restoration, expired deadline, panic, capacity exhaustion and lost reply; test old connection epochs after AttachInstance replacement.
- Model each blocking worker class with a separately controlled stall. Prove fixed slot counts, detached waiter ownership, generation fencing, rejection under exhaustion and fresh progress when workers actually exit. Cached inspection is explicitly Unknown while fresh proof is unavailable. Exercise conditional emergency stop with L/fsync blocked; no durable success or capacity release may escape.

## 10.2 Privileged VM integration

1. Validate installed root/service capabilities and ownership, safe binary ancestors, cgroup delegation, exact argv/config and no management API socket. Inspect separately typed VMM UID/GID, empty `Groups:`, zero CapEff/CapPrm/CapInh/CapBnd/CapAmb, NoNewPrivs=1, namespaces, seccomp, start time and cgroup membership; test unequal U/G as well as equal numeric pairs. Measure charged RAM from launch, not after migration. Host services remain outside the session cgroup.
2. Cold boot the new approved bundle; validate three drive identities/modes, fresh work UUID and per-boot nonce/kernel boot ID, hardening checks, broker readiness and persistent sandbox capability. Show a command writes a file and the next reads it. The current schema-1/no-broker bundle must be rejected before allocation.
3. Execute binary stdin/stdout, limit-exceeding output, genuine exit/signal outcomes, missing executable, Landlock denied writes, quota/inode exhaustion, a fork bomb and an inner OOM. Then run a successful command for all cases where reuse was reported. Check private disk and neighboring VM isolation.
4. Run a detached descendant with `setsid`, double fork, blocked output and inherited pipe writers. Cancel and time out separately. Verify VMM pidfd exit and cgroup empty, reusable=false, no successor runs in the old boot and no descendants remain. Kill broker, guest PID 1, VMM, supervisor, helper and kilnd at each exec boundary. A fake/compromised broker saying Drained cannot prevent retirement on these paths.
5. Create two simultaneous VMs with distinct UID/GID/CID/jails/work disks. Cross-wire vsock paths, identity drives, work UUIDs and nonce replies in a test-only harness; none reaches READY. Attempt CID reuse and identity allocator reuse while old cleanup is incomplete. Reused host PID must not be signaled. Unknown replacement inode is quarantined rather than recursively deleted.
6. Kill/restart kilnd at every create/delete boundary; demonstrate adoption only at C6, exact compensation otherwise, and no duplicate VM. Repeat with helper death and host reboot. Drop helper replies and force SQLite terminal-write errors: capacity remains held until the exact receipt is recorded. Late Create after FenceAbsent cannot resurrect anything.
7. OOM containment: use a safe outer test cgroup and separate controller outside it. Stress guest RAM, block caches and VMM overhead; record peak memory/current/events, host availability, PIDs and disk. Three sessions are an admission target, not an entitlement to destabilize this dev node. Verify failures stay confined and produce honest cleanup evidence.
8. Confirm no guest NIC, no TAP/nft/route changes, no guest-host IP connectivity, no serial command input, no provider credentials in bundle/identity/control environment. Deliberate guest AF_VSOCK host-initiated-listener misuse cannot access another jail or arbitrary host Unix services.
9. Deny snapshot/restore by construction: no API socket, flags, helper variants or boot mode. A supplied snapshot/disk pair, even self-consistent, is unsupported before allocation. Keep future snapshot/disk mismatch and two-clone uniqueness tests marked **blocked until a separate approved feature**, never silently skipped while declaring snapshot support.
10. Run existing locked tests/Clippy and the installed kiln/kilnd regression suites to prove backend selection, ownership, helper transport, retention and legacy compensation have not regressed. No unreviewed widening of capabilities or address families.

11. With H and both daemons healthy, SIGKILL only S both before and after J exits. Verify stop detection/dispatch within the 250 ms tested envelope, no newly admitted Exec/reusable Validate after the fence, V pidfd exit and VM subtree empty. A previously admitted dispatch must become interrupted/non-reusable. Separately kill J/V/M, withhold the PID file, replace it and force PID reuse outside the cgroup; no unrelated process is signaled. Prove J's normal zero exit leaves a healthy V running.
12. Run a test payload with exactly the VMM credentials inside the jail, before and after hardening. Fill one file/many files/sockets/inodes, add symlinks and replace entries/mounts. Mandatory tmpfs byte/inode caps hold without host XFS quotas; root-owned artifacts stay immutable; work resize/truncate/rebind/discard attempts cannot exceed or deallocate W. Teardown cannot follow links or delete a replacement inode; journal/daemon DB headroom remains usable. Validate loop attachment/detachment crash points and the actual pinned VMM block backend.
13. Simultaneously run endless valid vsock frames (including empty frames/trickled frames), no-first-byte/never-read channels and a serial flood. Cumulative byte/frame counters, absolute stage deadlines and console rate/CPU caps terminate the hostile sessions; memory remains flat. A healthy fourth allocation's Inspect/Stop/Remove completes inside its stated deadlines, with durable success under healthy storage. Use an isolated four-allocation test host/profile with adequate reserved resources, or protocol fakes for scheduling tests; never pretend four 896 MiB VMs fit the default three-slot policy.
14. Stall artifact reads/hash, fallocate, mkfs, ledger fsync, file fsync, mount/unmount, cgroup operations and inventory one class at a time; then exhaust P and per-allocation lifecycle slots. Independent Capabilities/Inspect/Stop stay responsive and no extra worker is spawned. For allocation-local stalls, healthy Stop succeeds; for shared ledger/kernel failure, bounded Unknown with independent kill dispatch is the required honest result. Recover only after the original workers exit/settle; confirm charges/FDs/permits are not lost.
15. Start two actual daemons with distinct databases/sockets/instance IDs sharing one helper. Race four 896 MiB requests against three node slots: exactly three reach INTENT and the rejected token obtains a durable ABSENT fence before local release. Kill either daemon, restore an older DB and remove its DB in separate runs; helper charges survive and ownership mismatch blocks new admission. Repeat disk/vCPU exhaustion, same-instance simultaneous attachment, helper restart/ledger replay and release-reply loss. Record the global vector and shared overhead, not the sum of successful local API calls.

16. Reproduce kiln-guest `e1082f2`'s KR-05 source-parent race as an unrelated unprivileged UID: rename the old build/source tree after verification, plant a replacement, and separately try renaming each protected installation ancestor. The old source rename may succeed; protected-tree replacement must be denied or launch must refuse. Pause immediately before S executes J and between J verification and V exec; replace the Firecracker `--exec-file` name in a test-only root fault injection as well. The only allowed outcomes are refusal or execution of the retained approved inode. Assert actual `/proc/<J>/exe` and `/proc/<V>/exe` **device, inode and FD-computed digest** against their pre-exec journal records, not only path strings, configured hashes or exit codes. Repeat every race for the formatter and each separately executed S/L/P/R/D/M/K image; verify fork-only workers inherit the approved image. A test-only exec-stop fixture may hold short-lived children for `/proc` inspection; production does not acquire a ptrace dependency. Missing evidence fails the test. Check bootstrap FDs do not survive V exec, no fallback path is attempted, preflight mismatches create no session resource, and every post-C1 mismatch holds its charge until ABSENT.

## 10.3 Evidence and review gates

Preserve per-test approved digest, exact config/argv, expected and actually executed device/inode/digest tuples for J/V/formatter/workers, host boot ID, versions, namespace/cgroup identities and bounded raw logs. Never log the boot nonce in routine API logs; store only its digest there. Record create-ready and first-tool-result latency separately from kiln-guest's earlier serial-marker boot metric. Do not reuse the spike's tiny idle-PSS density claim for hardened guests.

Daybreak Blue reviewed `c81de00`, then rechecked `1e448d2` in `reviews/2026-10-31-phase1b-design-recheck.md`. The recheck **closed all seven original findings** and identified one remaining executable-handoff requirement. Section 3.4 and the B1/B3/B4 gates address it; section 15 maps the correction. This is not a claim that the correction itself has passed re-review. The coordinating task schedules that narrow recheck before implementation. Each implementation slice also needs an independent adversarial pass and its local gates before landing; no merge authority is implied here.

# 11. Build order and file-level implementation map

Use separately mergeable changes against main, with no production backend enabled until B7. Do not open a dependent stack and treat its top merge as the complete feature. Each slice retains the legacy backend and contains its own tests/docs; code in kiln stays in the kiln repository.

## B1 — Freeze the guest and launch contract

**Files:** kiln-guest `scripts/launch_contract.py`, manifest builder/validator, `src/init.c`, bundle input pins and `tests/test_launch_contract.py`; new shared golden fixtures under kilnd `crates/kilnd/tests/fixtures/firecracker/`. Agree the schema revision and exact permitted substitutions from section 3, including identity vdc, broker lifecycle and the executable identity/FD-handoff recipe for jailer, Firecracker, formatter and all separate helper images. Keep production deployment disabled while the broker artifact is absent.

**Exit:** Python/Rust shared conformance and negative mutation tests pass with identical verdicts/canonical bytes/digests; the two spec digests bind host labels and guest execution separately; fixture schemas/types cannot enter production validation or PreparedCreate; the current no-vsock manifest is refused; fixtures have no placeholder security fields. UID and GID are separate typed substitutions (include an unequal pair); the contract freezes empty Groups and zero effective/permitted/inheritable/bounding/ambient capability masks, exact jail tmpfs byte/inode limits, loop device recipe, worker/cgroup limits and timing-argv exception. Pin and review the complete descriptor/capability-drop handoff; B4 must prove actual VMM masks and executable identity before approval. The executable contract freezes protected ancestry (ownership, modes, ACLs and parent rename authority), size/digest per role, allowed node-local inode identity, dependency closure, generation leases and FD 3/4 handoff. Add explicit source-parent/installed-name replacement fixtures after verification and before exec; the Linux retained-FD fixture records the actual executable device/inode/digest and must match its expected tuple. Contract tests reject an observed replacement even if argv or the earlier digest matches. These fixtures need no guest boot; B4 tests the actual J/V chain. Changing semantic constraints requires design review.

## B2 — Runtime evidence and durable accounting

**Files:** `crates/kilnd/src/runtime/mod.rs`, `runtime/fake.rs`, `runtime/kiln.rs`, `runtime/kiln_direct.rs`, `model.rs`, `store.rs`, `manager.rs`, their tests, `service.rs`, `main.rs`, `proto/kilnd/v1/kilnd.proto`, `crates/kilndctl/src/main.rs`, and relevant docs/changelog.

Implement section 9 types/methods and schema migration, explicit release evidence, dispositions/quarantine, stored reservation vector, owner/retention integration and additive API fields. Kiln adapters wrap existing proof; no new privileged action. CPU/vCPU additions use explicit legacy “not reserved” values rather than retroactively inventing a CPU promise for old rows.

**Exit:** all legacy tests/migrations and fake crash matrices pass. SQL constraints require an identity-matching typed AbsentFenced evidence reference for every Firecracker release after C1; FAILED/backend ID/boolean/legacy proof alone cannot release. Direct malformed SQL updates through trigger-enabled standard tools fail, every kilnd-owned connection enforces foreign keys and trusted_schema=OFF, trusted Rust reads reject invalid evidence and missing membership, and prune cannot erase charged failures or fences. The runtime fake proves a timed-out stopped session refuses its queued successor.

## B3 — Approved plans and root journal, no VM launch

**New host modules:** `crates/kilnd/src/runtime/firecracker.rs` (typed unprivileged client); `helper/firecracker/{mod,config,manifest,executable,journal,identity,inventory,workers}.rs`. Extend `helper/{protocol,client,server}.rs`, helper CLI/install/deploy files and tests. `manifest` implements strict parse/hash/contract verification; `executable` owns protected descriptor traversal, role identities, generation leases and exec handoff; `config` generates the exact plan; `journal` owns node-global vector claims, sync/fence ordering and receipts; `identity` owns allocation/UID/GID/CID uniqueness; `workers` owns fixed slots, gated permits and detached ownership; `inventory` returns complete or inconclusive observations. No root path in public models.

Implement AttachInstance/Capabilities/Accounting/Preflight/Inspect/List/FenceAbsent using fake resources and the concrete L/P/S/M/K worker model; exercise Create admission/rejection/fencing with fake side effects. Write `PreparedCreate` and receipts using the existing strict framing patterns, keeping no caller descriptors and all v3 receipt rules.

**Exit:** a process that copied a daemon's files gets no Inspect, List, Create or Fence authority after holder death or helper restart, while the enrolled unit's next process reattaches; attachment floods cannot take another instance's slot and root ledger growth is bounded; rejected Creates cannot block another instance's Create or FenceAbsent; no worker is published without its journal row. Substitution/TOCTOU/framing/deadline/ledger and legacy tests pass; C0 rejection creates zero session resources. For every post-C1 rejection class in section 10.1, pause ABSENT sync, publish charged failure, then replay two queued identical Creates after the cause disappears: neither can allocate once the fence commits. L atomically claims all node dimensions and identities across fake instances; exactly three of four default requests reach INTENT. Stall each worker class/ledger sync in fakes: H remains responsive, emergency containment is independent, slots are not replaced and no durable receipt appears early. KR-05 fake/property tests replace each executable's source or installation parent after hashing, at C1/C2 and just before dispatch; retain/reuse/close FDs and restart the helper to exercise generation recovery. Assert the modeled actual executable device/inode/digest equals the exact stored plan for J, V, formatter and every separate worker; a fresh pathname resolution cannot authorize a replacement. Cover the J-to-V FD boundary explicitly, not only S-to-J.

## B4 — Host allocation, stop and removal

**New modules:** `helper/firecracker/{storage,cgroup,supervisor,monitor,lifecycle}.rs`; fixed supervisor mode in `src/bin/kilnd-helper.rs` or a separate installed `src/bin/kilnd-vm-supervisor.rs` with an inherited private control channel, never public arbitrary arguments. Update service capabilities and installation paths narrowly. `lifecycle` owns the C2–C8 state transitions and receipts; storage/cgroup modules accept typed journal identities, never request paths.

Implement preallocated loop-backed work storage, mandatory jail tmpfs/hardening, exact jailer config/argv, section 3.4's retained-FD/readonly-bind/bootstrap patch and capability drop, gated workers, H/S/J/V/M identities and watches, absence barrier and scoped GC. Test using a fixed non-command-listening guest fixture; Create must not report production READY without B5's broker.

**Exit:** real teardown at every crash boundary has no owned VM, loop, mount, worker or file when ABSENT is reported. With H healthy, kill S before/after J exit and prove immediate fencing, live VMM containment and no newly admitted exec; prove J zero exit is not V exit. Check real UID/GID/Groups/all capability masks; no launch proceeds on a bounding-set mismatch. VMM-credential byte/inode/socket/symlink/work-resize attacks hit mandatory bounds without consuming journal headroom. Stall every real blocking class and exhaust pools as section 10.2 requires while independent Capabilities/Inspect/Stop progress. Stale PID/inode tests protect unrelated resources; prelaunch charge is proved; production Ready still requires B5. Run section 10.2's KR-05 replacement races as a non-root UID and the stronger test-only root name swap at both launch boundaries; assert actual J/V `/proc/.../exe` device/inode/digest against the journal. Repeat for the actual formatter and every separately executed supervisor/worker image, capturing short-lived exec identities with the test fixture. Pass only if the approved inode ran or launch refused, no fallback/FD leak occurred, C0 had zero session effects and post-C1 failures stayed charged until ABSENT. A prior hash plus matching argv is not passing evidence.

## B5 — Broker core and image integration

**New crates:** `crates/kilnd-exec-core/` for extracted existing kiln process/status/capture/model-validation pieces; `crates/kilnd-broker-protocol/` for the strict frame/message codec; `crates/kilnd-guest-broker/` for `main.rs`, `session.rs`, `server.rs`, `kiln.rs`. Host modules `helper/firecracker/{broker,exec}.rs` use the protocol crate. Reexport moved host types as needed to keep B2 interfaces stable. Audit the extraction as a behavior-preserving move before adding guest changes; do not pull gRPC/SQLite/host helper server into the guest binary.

Broker state is Uninitialized -> Initializing -> Idle -> Executing -> Draining -> Idle, with Faulted terminal until VM termination. The pseudocode is: validate Hello against vdc; initialize one exact spec once; prepare kiln persistent sandbox; smoke/validate; admit one token; fully receive bounded stdin; call reviewed direct-kiln execution core; drain/check; emit typed result. Any initialization uncertainty faults the guest, never creates a second inner sandbox. Control Cancel never waits on the exec output writer.

kiln-guest embeds the broker at a pinned kilnd commit/binary digest, adds the vdc reader and supervision hook, and rebuilds two clean bundles. Extend its source/input provenance to include the two crates/core, lockfile and exact compiler inputs.

**Exit:** framing/cumulative wire-byte/frame-count/first-byte/never-read adversaries pass, including endless otherwise valid frames and trickle timing. Three concurrent hostile transport/console sources leave memory flat and let a healthy fourth Inspect/Stop/Remove meet deadlines under the resource-safe fixture in section 10.2; each offender retires. Confirm console drains after its retained prefix and relay/console CPU is charged outside H. Actual persistent exec/cancel/kill tests pass; two clean-worktree builds match; full guest integration and two warmups/twenty cold boots are recorded for the new contract before approval.

## B6 — Full manager lifecycle and recovery

**Files:** manager/store/runtime/helper integration tests plus new `scripts/firecracker-regressions.py`, `scripts/firecracker-crash-matrix.py` and documented isolated test deployment config. Wire recovery by allocation, stop-on-interruption, terminal publication and complete inventory; preserve authorization and retention behavior.

**Exit:** all section 10 attacks pass on the actual chain, including the two-daemon four-request race and full global-ledger crash matrix: daemon death, stale/lost/restored DB, helper restart, capacity commit/reply loss and ABSENT/publication loss. Disk/vCPU exhaustion and duplicate instance attachments cannot oversubscribe; a surviving node ledger never discounts a lost daemon. Repeat B5 simultaneous hostile-I/O fairness with actual lifecycle requests. No reservation is freed while a VM/disk/worker may exist; quarantine remains controllable through Delete, with honest Unknown when proof is blocked.

## B7 — Capacity and opt-in deployment

**Files:** setup/threat-model/architecture/validation/roadmap docs, CLI help and operator catalog examples. Install the reviewed approved digest; only now allow `--backend firecracker`. Networking, pooling and snapshots remain unsupported.

**Exit:** node-global stress across at least two daemon namespaces supports the chosen profile, accounting for all per-allocation S/P/R/D and VMM/KVM costs plus shared H/L/M/K, the full tmpfs allowance, journal/WAL/fence and bundle-store headroom. Measure peak CPU/PIDs/memory/storage and workload density; reapprove limits if 128 MiB per-session or shared allowances fail. Legacy privileged suites pass; Daybreak recheck closes the findings (or Stephen explicitly accepts any residual risk); Stephen's section 12 choices are reflected in fixtures. These tests alone do not establish hostile multi-tenant production readiness.

# 12. Decisions confirmed by Stephen — October 31, 2026

Stephen confirmed the first five decisions below on **October 31, 2026**, matching the proposed recommendations. The remaining defaults stand as design decisions. None is awaiting approval; the provisional overhead estimates and implementation/review gates remain to be validated.

| Decision | Alternatives and trade-offs considered | Adopted decision (October 31, 2026) |
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
- Executable-handoff reference: kiln-guest `e1082f2af3a7f112789377c8a9f7d98db66cb092`, README validation section, `scripts/privileged_launch.py`, `tests/test_vmm_path_race.py` and `results/kr05/README.md`. It supplies protected installation/retained-jailer-inode regressions; section 3.4 explicitly extends the rule to the entire Phase 1b helper chain. Guest manifest/artifact identity did not change.
- Capacity: `kiln-guest/results/boot-regression/DENSITY.md`; hardened 768 MiB guest about 770 MiB PSS, contained five-VM OOM and the correction to cgroup membership before allocation. Three sessions per 3 GiB sandbox budget is planning, not a measured backend throughput claim.
- Adversarial constraints: `reviews/2026-10-30-guest-breakit.md` (KG-06 admission, KG-07 restore); `reviews/2026-10-30-guest-reattack.md` (KR-01 full launch binding, snapshot/KASLR, build and DNS boundaries); `reviews/2026-10-30-phase0-breakit.md`, `reviews/2026-10-30-helper-recheck.md`, `reviews/2026-10-30-receiptack-recheck.md` (descriptor authority, receipt lifetime and original wire deadlines). Later guest evidence addresses the old kernel/build/DNS findings; it does not implement this backend's admission.
- Design review: `reviews/2026-10-31-phase1b-design-attack.md` at the first design commit `c81de00`; all seven findings accepted in section 15. The report specifies deterministic attacks; it says no standalone PoC was necessary.
- Design recheck: `reviews/2026-10-31-phase1b-design-recheck.md` reviewed `1e448d2`, closed all seven original findings and required race-free executable handoff plus B1/B3/B4 replacement tests. That narrow correction is specified here, awaiting its own clearance.
- Pinned upstream mechanics: [jailer v1.17.0](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/docs/jailer.md) and [vsock v1.17.0](https://github.com/firecracker-microvm/firecracker/blob/v1.17.0/docs/vsock.md), consulted for exact flags, PID/cgroup behavior and host-port handshake. All additional lifecycle, reservation and broker rules above are this design's requirements, not claims that Firecracker supplies them automatically.

Stephen's section 12 decisions are settled as of October 31, 2026. Production implementation, the required hardened jailer/broker artifacts, final bundle approval and the narrow executable-handoff recheck remain open. The earlier seven findings are closed by Daybreak's recheck, not merely marked resolved by this author.

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

The PDF is a local review artifact; the source and style are versioned with this design. Rendering grants no production approval. B1 contract tests run on macOS and Linux/root; B4/B5 still owe the live production-chain evidence.

# 15. Review response

Daybreak Blue's October 31 recheck at `1e448d2` **closed all seven original findings** listed below. Its one new executable-handoff finding is accepted and addressed in this revision; none is rejected. This does not claim implementation or re-review of the new correction has passed. Stephen confirmed section 12's decisions on October 31, 2026.

| Finding | Revision and local gate |
|---|---|
| 1. Post-C1 uncharged rejection/replay | Sections 3.2, 4.1–4.3, 4.5, 8.4 and 9.1 require matching durable ABSENT for every post-C1 release, permanent replay fences and typed SQL evidence. B2/B3 force the pre-INTENT rejection plus queued-duplicate race with paused fsync |
| 2. Per-database rather than node capacity | Sections 4.1 and 7.3 choose one root SQLite node ledger, atomic full-vector/identity claims, instance attachment and once-only shared reserves; 8.3/9.2 cover reconciliation/stats. B3/B6/B7 require multi-instance admission, DB-loss/restore and capacity evidence |
| 3. Jailer clone and supervisor death | Sections 4.3–4.5 and 6.2/6.4 specify H/S/J/V/M, subreaper, pidfds, preowned cgroups, live monitor and irrevocable stop on S/V/M loss. B4 tests S death with H alive before/after J exit and PID-file/reuse attacks |
| 4. Writable-jail storage bound | Sections 3.3, 6.2 and 7.1 bind mandatory whole-jail 16 MiB/1024-inode tmpfs, post-jailer hardening and exact-size root-owned loop-backed work storage. B1/B4/B7 test/fund aggregate limits without optional host XFS quotas |
| 5. Hostile vsock/console work | Section 5.6 bounds cumulative bytes/frames, first-byte/stage timing, read quanta, rates and console draining; 6.4/7 charge isolated workers. B5/B6 require three simultaneous adversaries with healthy recovery progress |
| 6. Current-thread helper stalls | Section 6.4 defines fixed L/P/S/R/D/M/K processes, journaled permits, no slot replacement while stuck, detached ownership and independent recovery; 4.4 defines precommitted emergency containment when fsync is unavailable. B3/B4 fault every blocking class and exhaustion |
| 7. Gates and crash dispositions | Section 4.5 explicitly maps recovery/charge outcomes; section 10 supplies deterministic tests; every B1–B7 exit now names the relevant evidence. B1/B4 also distinguish UID/GID and require empty Groups plus zero effective/permitted/inheritable/bounding/ambient capabilities |
| Recheck 1. Executable identity lost at launch (KR-05) | Sections 3.1–3.4, 4.1/4.3–4.4, 6.2/6.4 and 7.1 require protected ancestry, retained-FD execution and expected/observed identity for J/V/formatter/all helper images. The explicit J-to-V handoff has no pathname-copy/exec fallback. Sections 10.1/10.2 and B1/B3/B4 race source/installed-name replacement and assert the actual executable device/inode/digest |

The retained-descriptor handoff and zero-bounding-set requirement require the narrow jailer patch in sections 3.4/6.2, pinned and reviewed before B4. New loop-device and worker mechanisms also require their stated compatibility/fault tests. They are build prerequisites, not silent exceptions to the approved launch contract.

## B1 implementation review corrections (October 31, 2026)

The B1 break-it report's three findings are accepted: sections 3.2/3.3 now
freeze strict cross-language canonical bytes, distinguish the host/guest spec
digests and isolate fixtures from production schemas. The shared corpus replaces
Rust's hash-change-only negative evidence with validation of all mutations.
Actual jailer/VMM capability masks, retained-FD handoff and broker readiness
remain B4/B5 gates; synthetic B1 evidence does not claim those gates passed.

## B2 implementation notes (October 31, 2026)

B2 implements sections 8.4, 9 and 7.2's accounting against `FakeRuntime` only; B3
and B4 still own the helper, node ledger and backend. Conservative readings taken:

- `SpecBinding` applies the offline profile, so legacy kiln rows use the same canonical
  digest helper without it. Only absence-fenced plans go through `SpecBinding`.
- Kiln rows store no allocation identity or plan: both are absent from migrated rows,
  and kiln has no token recovery to use them. Only absence-fenced rows bind them.
- Section 9.1 has no Runtime stop operation. Recovery of a RUNNING execution therefore
  publishes INTERRUPTED and LOST only when inspection already reports host stop evidence,
  and otherwise FAILED/CleanupFailed and QUARANTINED. A live VM is not stopped by B2.
- A legacy adapter panic keeps its existing READY behavior, reporting unknown reuse;
  on an absence-fenced row it quarantines. Legacy CleanupFailed quarantines as specified.
- A live supervisor whose READY reply was lost compensates rather than adopts; only
  restart recovery adopts. Periodic retry belongs to B6: until then Delete and startup
  reconciliation retry release.
- `NodeResourceStats` accounting fields took the next free numbers, 16 through 18.
- `last_helper_generation` carries only the ready and absence generations. A row that
  never published READY records zero, so any positive absence generation passes until
  B3's ledger supplies more; Inspect/Stop observations are compared but not persisted.


## B2 boundary recheck validation (October 31, 2026)

- `cargo test --locked`: passed (297 library tests, 3 daemon tests, 16 API tests,
  21 Firecracker contract tests, CLI tests; 9 privileged integration tests are
  explicitly ignored on macOS). Clippy with `--locked --all-targets -- -D warnings`
  passed on Rust 1.88.0 and 1.99.0; `git diff --check` and shell/Python syntax passed.
- Earlier `reviews/poc-b2` attacks rerun as landed inverse regressions:
  `external_replace_cannot_release_charged_row_without_evidence` and
  `encoded_absence_is_validated_on_store_and_independent_connections` passed.
  The complete unique-key/conflict matrix passed with foreign keys/recursive
  triggers off, checks ignored, writable/trusted schema and legacy alter mode on,
  defensive mode off, and triggers enabled. No schema rewrite was used there.
- `reviews/poc-b2-2` exact trigger-disabled DELETE and spoofed-validator `x'00'`
  statements rerun in permanent tests: the DELETE itself still succeeds under
  file authority, but all trusted accounting reads/admission/prune and startup
  refuse the missing membership as degraded; spoofed evidence remains charged,
  projects QUARANTINED in get/list/pagination, blocks admission, survives prune
  and is still degraded after restart. The deliberate DROP TRIGGER control
  also deletes successfully but its missing membership is detected.
- The trusted-schema PoC is now inverted: legitimate `release_fenced` succeeds
  with `trusted_schema=OFF` on disk, in memory and after restart. Additional Rust
  read tests corrupt every evidence identity column, generation and kind, remove
  evidence/references, and corrupt bytes. All retain the full charge and quarantine.
  A manager test verifies degraded Health and denied admission despite spare budget.
- The prior migration crash harness was rerun with its final-schema expectation
  changed from 9 to 10 and its synthetic schema-8 fixture dropping the new marker.
  With 30,000 canonical receipts and 18 SIGKILL timings: 17 recovered as coherent
  schema 8, one as complete schema 10; no mixed schema, lost receipt or failed
  quick_check. Normal migration took 0.983359 seconds. Invalid-receipt upgrade
  refused atomically and remained schema 8.
- In the locked Lima VM, installed this branch and migrated the actual dev database
  from schema 7 to 10: all 119 sandbox rows survived, quick_check passed, and the
  real ambiguous failure `sb-7d028a9321df8d7b` retained its 64 MiB/128 PID/16 MiB
  charge. Health reported one reservation and legacy CPU/vCPU/host-PID zeros.
  Directory/database/WAL/SHM/lock owners and modes were kilnd 0700/0600.
  Integration (including FD/RSS admission stress), singleton, state-path, Phase 0
  and smoke checks passed. Phase 0 now tests rejection of its out-of-band SQL
  membership fixture, then restores the genuine snapshot to check startup prune.
- Restored the original main `734e275` binaries and schema-7 dev database afterwards;
  original binary checksum, 119 rows, ambiguous reservation, Health and quick_check
  were verified. The design PDF was rendered again from this source.

## B3 implementation notes (October 31, 2026)

B3 implements section 11's B3 scope against fake resources. No semantic constraint
changed. Conservative readings taken where this document left room:

- **Inspect and List in B3.** There is no READY, so `PresentReady` is absent from the
  wire. An accepted allocation inspects as `PresentBusy`, which the runtime maps to
  Unknown: `AllocationObservation::Present` needs a boot receipt that cannot exist yet.
- **A fence over an accepted token.** Section 4.1 describes a token rejected before
  INTENT; section 4.5's lost-reply row and the required races also need one for a token
  whose INTENT committed. FenceAbsent releases that claim in the same transaction only
  if S has really exited and every worker row is settled. It removes nothing: a resource
  S made stays a refusal (`ResourcesPresent`), since cleanup is B4's Remove. A worker row
  with no recorded identity never had an open gate, so it settles as never started.
- **Lookup past an expired deadline.** "Fence lookup first" and "no fresh budgets" meet at
  an expired request. Only the read-only lookup may answer, within 250 ms of the deadline.
  It returns an existing fence or refuses, and no later step runs. A fence attempt that
  reaches the token lock after its own deadline refuses and leaves the gate as it was.
- **Stale namespace ownership.** The enrolled service presenting a different database UUID
  attaches with admission closed and cannot rebind. It can read, and it cannot fence or
  claim until an operator resolves it; the design's repair flow is B6.
- **Peer start time.** H cannot read `/proc`, so L reads and compares it at attach. It is
  recorded with the attachment; the binding H checks on each call is the 128-bit epoch,
  the peer PID and the attested process's pidfd, whose number can't be reused while alive.
- **Infrastructure identity.** The contract has no separate worker image, so L/P/S/M/K
  journal the inherited `kilnd-helper` tuple. With no approved profile no image is pinned,
  and those rows and admission are absent. S models dispatch by comparing each role's
  retained descriptor with the plan and journals that actual tuple. R and D don't exist yet.
- **Slot waits.** Preflight refuses when both P slots are busy. Create revalidation may
  wait among at most 16 waiters up to its wire deadline, or concurrent admission would
  fail on a transient; it never adds a process or borrows K.
- **Fence headroom.** Each token is bounded at 4096 bytes. Space for never-admitted tokens,
  including C1 rows the helper has not seen, is reserved from the 64 MiB allowance (see the
  break-it corrections for the quota). Preflight and C2 refuse a new token past that; a
  fence for an admitted token is always allowed.
- **POSIX record locks.** Closing any descriptor for a file drops all of a process's locks
  on it, including SQLite's. The ledger therefore inspects its files with `fstatat` once
  a connection can exist. Opening `-shm` after SQLite would release its DMS lock.
- **Startup work.** Policy, manifest and executable verification run in H before its
  listener serves, as section 3.4 requires of the self-check. A stuck store can therefore
  delay a configured helper's start, but only when a policy opts in. A lock still held
  after five seconds leaves the group disabled for that run, with kiln unaffected.
- **Test seams.** Fake catalog approval, fake resources and fault points are `cfg(test)`
  only: production has no such variant, flag or environment hook. Fixture schemas are
  refused under the test gate as well. A test manifest is production-shaped and made at
  test time, and test walks skip ACL checks because a scratch filesystem may lack the
  xattrs; the root Linux tests enforce them from `/`.

**Review corrections (October 31, 2026).** An engineering review reproduced six control
failures; these fixes change no semantic constraint:

- **Monitor exit** fences and contains every existing boot through K before its slot can
  be reassigned, and those boots never regain forward effects. Every replacement worker
  settles its predecessor's permit after the reap and journals its expected image and
  identity before receiving work; if L can't answer, no replacement happens. L must exist
  to write, so it alone forks first and journals as its first act.
- **Stale S heartbeats** now stop: H and M each request containment independently, with S's
  slot, permit and charge kept. Any fence also revokes S, and S reads every queued command
  before each effect.
- **Emergency fan-out** is a bounded pending set in M that only an original K slot's reply
  drains, owned through H's EOF until every target settles, without an ownership timeout.
  M keeps idle K slots alive with private heartbeats while another K is stuck; K leaves
  only after M stops sending for three seconds. Ledger replay remains a fallback.
  `exit4_helper_loss_retains_pending_stops_without_an_ownership_timeout` stalls both K
  processes past 30 seconds, then proves the original slots finish every pending stop. H also retries its own
  dispatch each tick, one per subtree.
- **Detach revokes pending admissions.** Generations live in a shared page mapped before any
  fork. The commit-point read sits after every test stall, immediately before COMMIT. H
  rechecks after P, after L's reply and before S's gate. A closed-admission attachment never
  publishes a generation. A commit that wins the race keeps its claim, and gets no effects.
- **The deadline carries through C3.** Everything forward uses the original wire deadline,
  including `OpenGate`, which S checks before each effect. Detached work keeps its claim and
  its cleanup, not unlimited start authority. An expired read-only lookup may return a fence
  and nothing else: an accepted token answers `Expired`, not `Accepted`.
- **Framing and dispatch are separate budgets:** 128 framing slots, then 60 normal plus 4
  reserved operation slots after classification, including legacy operations (kiln
  capabilities, `rm` and `gc` are reserved), and one attachment slot per enrolled
  instance. This protects dispatch, not raw connection fairness: 128 silent connections
  can still delay framing.

**Exit tests** (`crates/kilnd/src/helper/firecracker/`): exit 1 `tests.rs::exit1_*`
(including `exit1_absolute_wire_deadlines_*` and `exit1_a_full_operation_budget_*`), `server.rs`,
`config.rs` and `manifest.rs` mutation tests; exit 2 `tests.rs::exit2_*`, including all
eight forced races, the real Manager path, and `exit2_old_epoch_revoked_*` during P, queued
in L and racing C2; exit 3 `tests.rs::exit3_*` and
`journal/tests.rs::exit3_*`; exit 4 `tests.rs::exit4_*`, with stopped and stalled real
processes behind the real listener, including `exit4_monitor_exit_fences_before_replacement`,
`exit4_monitor_requests_a_stale_supervisors_stop_without_help_from_h` and
`exit4_helper_loss_contains_all_three_allocations_with_two_recovery_slots`; exit 5 `executable/tests.rs::exit5_*`,
`tests.rs::exit5_*` and journal lease tests, plus the root Linux
`exit5_linux_root_*` tests in `scripts/integration-test.sh`; exit 6
`journal/tests.rs::exit6_*` and `tests.rs::exit6_*`.

**Remaining, by design:** B4 owns real storage, cgroups, jail, loop device, the patched
jailer and the actual J/V chain with `/proc` evidence, real namespace observation and
Remove/Stop, S/M pidfds and parent-death signals, host capability and free-space checks
at preflight, capability grants, and a static helper image. B5 owns the broker, R, D and
READY. B6 owns manager recovery, reconciliation and DB-repair flows. B7 alone may lift the
production gate and let `main.rs` select this backend.

Linux validation corrections preserve the same contract: the Firecracker client relies
on the original wire deadline instead of sending a redundant cancel byte when that
deadline expires, avoiding a Linux response-close/EOF race. Explicit cancellation and
strict EOF validation remain. `exit1_deadline_does_not_race_response_eof_with_a_redundant_cancel_byte`
checks the absence of that write. The root traversal test requires successful ACL and
capability injection, removes each fault, restores ACL-derived mode bits and verifies
the positive control before the next independent attack.

## B3 break-it corrections (October 31, 2026)

The Daybreak Blue review (`reviews/2026-10-31-b3-breakit.md`) found the release invariant
intact and four control-plane failures. The decisions below are made; sections 4.1, 6.4,
7.3 and the B3 exit reflect them.

- **B3-01, instance takeover with a copied database UUID.** First-use enrollment is gone.
  Root enrolls each instance (section 4.1), and AttachInstance proves the peer's UID, exact
  unit cgroup and image. The database UUID authenticates nothing.
  `tests/control_plane.rs::b3_01_takeover_fails_after_death_restart_and_with_copied_files`
  and its root run against the kernel's cgroups,
  `b3_linux_root_takeover_fails_against_real_cgroups`, try a wrong-cgroup thief and a
  copied-image thief, each with every copied ID and the live epoch, while the holder lives,
  after it dies and after a helper restart. Each is refused Inspect, List, Create and
  Fence and leaves no state; the enrolled unit's next process then has full authority.
- **Reading another account's image.** `/proc/<pid>/exe` is a ptrace-read check, and the
  helper's bounding set has no CAP_SYS_PTRACE. Rather than add one, L takes the peer's
  filesystem IDs for that one open and restores them at once, in a single-threaded process.
  A peer that makes itself non-dumpable is refused, which fails closed.
  `b3_linux_root_attestation_needs_no_cap_sys_ptrace` proves this with the capability dropped.
- **Connector identity.** H takes `SO_PEERPIDFD` on every Firecracker connection. A connector
  still alive after L answers held its number throughout, so L read that process; and a
  socket left behind by a process whose PID was later reused speaks for no one. A helper on
  a kernel older than 6.5 refuses every attachment.
- **B3-02, attachment starvation and unbounded enrollment.** No common attachment pool
  remains. Enrollment is root-only and bounded; an unenrolled ID is refused in H with no L
  call; the set of enrolled instances can't change while a helper holds the node lock, so H
  loads it once at startup. Attach writes only its own row, once, and refuses that first
  write past the fence-headroom floor. `b3_02_no_flood_of_attachments_*`,
  `b3_02_attach_churn_*`, and `journal/tests.rs::b3_02_*`.
- **B3-03, rejected Creates filling the gate table.** The durable lookup now runs before any
  reject state exists. A flow holds an open entry only for per-token serialization, which
  leaves with the flow; only a closed gate whose token the ledger doesn't own is retained.
  Gates are partitioned by attested instance and keyed by (instance, allocation), so another
  instance's rejection can't close a token's gate. Ledger-owned tokens need no entry and are
  answered from L however full the table is, including after a restart.
- **What is evictable.** A token whose plan failed its own bytes or its binding to the token
  is evictable: a daemon verifies both before C1, so no charge can depend on it. Any other
  rejection might be post-C1, and stays closed until its fence, keeping section 4.1's rule
  exact. When those fill an instance's quota, that instance's new tokens get
  `WorkerExhausted` before any work, while its ledger-owned tokens and its fences still
  proceed. Fence attempts on unknown tokens can close gates past that check, so memory is
  also capped outright; dropping one of those harms only that instance and is safe, because
  every request still starts at the durable lookup and only ABSENT releases.
  `b3_03_rejected_creates_cannot_block_*` is the review's PoC turned around, and
  `b3_03_ledger_owned_tokens_answer_*` and `b3_03_a_token_id_from_another_instance_*` cover
  the rest.
- **Never-admitted fence quota** (a gap found while fixing B3-02, not in the review).
  `commit_fence` on a token the ledger never saw wrote a permanent row with no headroom
  check, so an attested hostile instance could grow `retired_tokens` past the allowance
  with random IDs. The allowance's 16384 entries now split as follows: a quarter (4096) is
  the never-admitted pool, and each instance's quota is the pool over the larger of
  `max_enrolled_instances` and the enrolled rows: 512 at the default of 8. Quotas therefore
  sum to within the pool under any policy, including one lowered below its rows. The
  count is durable, derived from the ledger's own rows inside the fence transaction, so
  racing fences and restarts can't pass it. At the quota the reply is
  `ambiguous {resource_exhausted}`, nothing is written, the daemon keeps its charge and
  release stays safe. H also checks before its P dispatch, so a refused flood occupies no
  shared P slot. Admitted tokens are outside the quota in both directions. Headroom
  is now every allocation row, plus the whole pool, plus one, so no fill of the pool can
  take space from admitted tokens. Preflight refuses this instance's new tokens once a
  quarter of its quota remains, so that charged C1 rows can still fence.
  `tests/control_plane.rs::b3_02_a_random_id_fence_flood_*` and
  `journal/tests.rs::b3_02_never_admitted_*`.
- **B3-04, workers published after failed journaling.** See section 6.4.
  `b3_04_startup_serves_nothing_*`, `b3_04_startup_that_cannot_journal_*` and
  `b3_04_a_replacement_ledger_stays_private_*`, using the `L.record_infrastructure.fail` and
  `L.settle.fail` fault markers.

**Schema.** `instances` gains the enrollment columns and `database_uuid` becomes nullable. It
stays schema version 1 because no B3 ledger has shipped; a ledger from an earlier B3 build
fails its schema audit, closed, and needs provisioning again.

**Known limits, accepted or open:**

- **Same-UID flooding.** Any same-UID process can still fill the 128 framing slots (already
  accepted above), and can keep one instance's eight attach waiters busy with attempts that
  L refuses. That delays a new attachment but cannot displace a holder or take a slot, and
  only attempts refused by proof are involved. It is the same class as raw framing.
- **Same-UID processes in general.** Enrolled units sharing one service UID can signal each
  other, and can ptrace each other unless Yama restricts it. A compromised daemon's
  children inside its own unit pass the proof for that instance, which is that unit's own
  authority. The kilnd unit must not set `Delegate=`, so that its cgroup stays root-writable
  only. Running more than one instance on a node needs per-instance accounts or
  `kernel.yama.ptrace_scope` of at least 1, which B7's multi-daemon test should require.
- **Never-admitted fences are a lifetime budget.** Fences are permanent, so a quota spent
  stays spent until epoch-safe compaction exists. A daemon that really does exhaust it,
  through many pre-INTENT rejections, keeps those charges until an operator acts. A
  policy with a lower `max_enrolled_instances` gives each instance more. Compaction and
  that repair remain separate work (B6).
