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

Each helper record has a version, node/instance/allocation/sandbox IDs, generation, plan/manifest/spec/launch digests, the full reservation, phase, independently typed VMM and relay UID/GID leases, CID, deterministic names, host boot ID, worker/supervisor/jailer/VMM PID and start time, cgroup inodes, expected/observed executable device/inode/size/digests and installation generations, artifact/work inodes, loop device/backing identity, tmpfs mount ID, work UUID, nonce, exec state and stop/absence evidence. An allocation's identity is (instance, allocation ID): the same ID in another instance is another token, and every ledger row and in-memory table is keyed by the pair. Generations compare-and-update; they never blindly overwrite newer evidence.

**One root-owned node ledger is authoritative:** `/var/lib/kilnd-helper/firecracker/node.db`, SQLite WAL with synchronous=FULL, foreign keys enabled, 0600 files/sidecars under a pinned root-owned 0700 directory. One persistent node lock excludes a second helper even if it selects a different instance namespace; the installed service uses one fixed root-owned node policy/ledger path. The ledger process alone opens SQLite and uses fixed prepared statements. It stores allocation intents, capacity claims, identity ownership, worker intents, terminal receipts and permanent retired-token fences in transactions. This replaces the first draft's independent JSON files: a JSON export is diagnostic, never allocation or release authority. SQLite and this bounded schema are now explicitly part of the root TCB. File staging still uses fdatasync and parent-directory fsync; sync ledger directory creation too. Never store tenant stdout/argv/stdin in the ledger.

**Instances are enrolled by root, each under its own Unix account.** `kilnd-helper enroll --instance <id> --unit <systemd unit> --user <account>` runs as root or from the installer, never over the kilnd socket. It takes the node lock, so it runs with the helper stopped, and writes the instance's row in the node ledger: the account's UID and GID, the expected systemd unit, that unit's exact cgroup, and the installed kilnd image's device, inode, size and digest, read through the protected walk (root-owned, not writable by anyone else, single link, no setuid, setgid, ACL or file capability). Each unit serves one instance and each account serves one instance. Enrollment refuses a UID or GID bound to another instance, root, the helper's own account and anything inside the VM identity ranges; a single instance can keep the `kilnd` account, and each further one gets `kilnd-<name>` from `scripts/add-instance.sh` and `deploy/kilnd@.service`. Startup refuses a ledger that breaks any of this. Each instance's state directory and database belong to its own account, mode 0700, so cross-instance signals, ptrace and file access are all cross-UID operations and depend on no host sysctl. Replacing the kilnd image requires enrolling again. Root policy's `max_enrolled_instances` (default 8, at most 64) bounds the total; lowering it removes nothing. Removing an enrollment is B6's repair flow.

Before Preflight, `AttachInstance` establishes a long-lived authenticated control connection. It succeeds only when SO_PEERCRED and `/proc` both show the connecting process running as the instance's enrolled account (real, effective, saved and filesystem UID and GID), sits in exactly the enrolled unit's cgroup (a child cgroup does not count), and runs the enrolled image by device, inode, size and digest. Stat fields are compared before hashing, so only the enrolled inode is ever hashed. The connection's own pidfd (`SO_PEERPIDFD`, Linux 6.5 or later, and refused without it) pins the connector. L reads `/proc/<pid>` through one pidfd and directory descriptor and rechecks the start time afterward, and H requires the connector still alive after L answers, so a reused PID cannot lend its identity. **The database UUID is only a reconciliation identifier, never an authenticator:** copying a daemon's files gives a process nothing. It is recorded by the first attestation and a mismatch closes admission. An unenrolled instance ID, or one this account doesn't serve, is refused with no ledger call and no state.

Only one live holder may use an instance ID. Operations carry a helper-generated connection epoch, invalidated on detach/restart, and the attested process's pidfd must still be alive for it to count. Create and FenceAbsent from any process other than the live holder are refused before any lookup: they get no token fact and allocate nothing. Accepted work remains ledger-owned after detach; a new connection cannot clear its claims. Multiple distinct instances are supported, under distinct accounts, and share the same node ledger and budgets (section 7.3).

**Every post-C1 release requires ABSENT.** C0 rejection creates no daemon row and no reservation. Once C1 commits, the helper first looks up the token under its per-allocation serialization, before revalidation or allocator selection. An existing ABSENT row is returned unchanged; an existing active or conflicting plan is never DefinitelyNotCreated. For a new token rejected before INTENT, `FenceAbsent` closes its admission gate, cancels or invalidates every queued dispatch generation, waits for all previously issued side-effect permits/workers to settle, verifies all derived resources absent, and commits the retired-token entry plus matching ABSENT receipt in one FULL-sync transaction. Only then can the helper return AbsentFenced/DefinitelyNotCreated. A lock alone, absence in one invocation, deadline, error string or empty listing does not suffice. Late requests check the durable fence again before any side effect.

Receipts identify node, instance, allocation, plan digest, monotonically increasing helper generation and kind `AbsentFenced`. A prior candidate collision or revalidation failure with no fence returns AllocationAmbiguous and the daemon keeps its FAILED row charged while fencing is retried. A ledger failure or a stuck accepted worker forbids the receipt. Retired entries remain even when API history expires. Initially reserve a 64 MiB retired-ID ledger allowance; stop accepting new tokens before the space needed to fence already accepted tokens would be exhausted. A quarter of that allowance is set aside for tokens the ledger never admitted, divided equally among the policy's possible instances, and each instance's quota is checked in the fence's own transaction. At its quota, FenceAbsent for a never-seen token fails closed with no row written, and the daemon keeps its charge; a token the ledger admitted is never refused by this quota. Admission reserves the whole set-aside up front, so never-admitted fences and admitted tokens together always fit the allowance. Never prune fences by age; epoch-safe compaction is separate work. Bound console retention to 64 KiB combined; its mandatory drain/rate policy is in section 5.6.

**Daemon database boundary (B2):** `/var/lib/kilnd/kilnd.db`, or `/var/lib/kilnd-<name>/kilnd.db` for a further instance, is owned by that instance's account: directory 0700, regular single-link database and SQLite sidecars 0600. Installation checks these modes/owners after any legacy root-to-service transfer; startup validates them before opening and again after SQLite setup. These filesystem permissions protect access. A process able to open its own SQLite connection already has kilnd's file authority and is equivalent to a schema/file rewriter. A connection that disables triggers (`SQLITE_DBCONFIG_ENABLE_TRIGGER`) or registers a spoofed validator is explicitly out of scope for SQL guards. Triggers defend kilnd bugs and honest direct-SQL mistakes through standard tools; they cannot bind another connection's configuration or function implementation. The root-owned node ledger above never frees node capacity or host resources without its own ABSENT receipt, whatever this daemon database says. B3/B4 implement that authority; B2 does not claim it exists yet.

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

**Probe health (B5-04).** Probe answers Idle only for a persistent sandbox that is alive now, not from cached state: the broker runs kiln's fixed capability request against the inner ID (`kiln capabilities <id>`, the existing argv mapping, answered only by the sandbox's live init over its control socket) and checks that its cgroup exists, within 1.5 seconds. A failure faults the session for good, so the reply is Faulted, which the host treats as a breach and retires the VM. During an execution Probe still reports the recorded Executing or Draining state without the check.

**Identity checks (B5-06, B5-10).** HelloReply's `broker_sha256` must equal the `kilnd-guest-broker` artifact the plan's approved manifest pins (S takes it from its profile's verified manifest, whose digest must be the plan's `manifest_sha256`). Hello and Ready must both report kiln protocol 1 with features `0x1f` (the private v1 protocol's four and persistent-create certainty). A Result's `inner_id` must be the journaled inner sandbox. Any mismatch is a protocol failure that retires the VM.

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

**Containment is always polled (B5-02).** No ledger call is ever awaited inside the execution's wait. BUSY is its own future, polled beside cancellation, the deadline and the 50 ms session watch (S's exit, V's death, a fence), so a stalled L can never hide them. Every journal write on the Validate and Exec paths is bounded (five seconds); one that is not durable within its bound is uncertainty, like a timeout, and retires the VM. Containment itself needs no ledger: the in-memory stop fence revokes S's permit and K kills the `vm` subtree through `proven.rs` under section 4.4's precommitted emergency authority, while STOP_INTENT is queued for when L answers. The reservation stays until absence is proven. An EXEC_INTENT write whose outcome is unknown retires the VM before anything is dispatched, since the journal may still commit it.

**The pre-dispatch split (B5-07).** Every relay failure carries its reach. `Local` is a host-side failure no guest behavior caused, before any byte of the job reached the guest or R: short or late stdin from kilnd (our own validation), no remaining budget at send time, an occupied relay channel, a missing stdio descriptor. Only `Local` may journal `undispatched` and restore READY. `Guest` is a guest that broke the session protocol before any Exec byte: a malformed frame, a wrong binding, boot or inner sandbox, missing hardening, a wrong broker digest or kiln features, a Faulted or refusing broker, a VMM that gives no `OK`. Nothing ran, so the reply is `dispatched: false` with known-zero capture, but the guest is not reusable: H retires the VM (without a Cancel). `Dispatched` is everything from the job's first frame byte or descriptor on (B5-03), and retires the VM as an interruption.

Pre-dispatch cancellation with proof no Exec bytes could have been sent can preserve the ready VM. A normal completed result that was validated before the first cancellation wins over a later disconnect, as today. If the daemon/helper crashes during EXEC_INTENT/BUSY, startup stops the VM; it never retries the command or adopts the session based on a later “idle” claim. Mark the execution INTERRUPTED only after the host stop barrier, or FAILED/CleanupFailed with quarantine if that barrier is unavailable. Reconnection is for observation/cleanup only; commands are not replay-safe.

This intentionally extends the Runtime contract: cleanup success no longer always means reusable sandbox. Section 9 makes that explicit for every caller and test; otherwise a builder could accidentally run the next queued command in a retired guest.

## 5.6 Hostile transport and console work

Enforce these bounds at the **host relay**, even if guest root has replaced the broker. A valid per-frame length never authorizes an unbounded stream. Per execution, cumulative stdout and stderr payloads may each be at most their negotiated retained-prefix limit (at most 1 MiB each); all other guest control payloads combined may be at most 64 KiB. Count both channels and headers: at most 128 guest-to-host frames, including empty frames, and at most `stdout_limit + stderr_limit + 64 KiB + 128*36` wire bytes. Each non-exec exchange has a separate guest-to-host 64 KiB/16-frame cap; only one control request may be outstanding. Unsolicited or repeated control replies fail immediately, including while idle. During BUSY, Validate reports the recorded busy state and host process watches establish liveness; do not spend the execution frame allowance on periodic guest polling. Cancel/CancelAck is idempotent and budgeted once per token. Each limit is checked before allocating/reading the advertised body. Exceeding any bound, a sequence overflow or output after Result is a protocol breach: fence reuse, request durable stop and retire the VM. Guest-observed totals can be larger than kept prefixes, but cannot authorize additional transport. Host-to-guest stdin remains at most 1 MiB and is subject to equivalent counters and write deadlines.

Start timers at connect/accept, **before the first byte**. UDS connect/CONNECT/OK, Hello, each newly accepted control exchange and Exec acceptance have absolute two-second stage budgets bounded by the original operation deadline. An unsolicited/unassigned accepted channel gets two seconds to identify its role; at most two are retained. A frame's entire header and body must arrive within two seconds once that frame is due; trickled bytes never reset it. After Accepted, waiting for a legitimate long-running command's first output/result is bounded by the original execution deadline, not a new two-second execution limit. Once result transfer starts, all retained output/Result/EOF must settle within two seconds. Every write, including Cancel and output delivery to kilnd, has a bounded settlement deadline; never-read peers cannot pin a worker indefinitely. No new deadline extends the original execution budget.

**Frames are all or nothing (B5-03).** Every worker channel (S↔R and each worker's channel to H) uses one `Endpoint`. A write given up before its first byte reached the kernel drops that frame whole and the stream stays usable. A write that fails or times out after any byte was handed over **poisons** the endpoint: it shuts the socket both ways, so the peer reads a torn frame and EOF and never a late delivery, and every later send returns the stored error; the unsent tail is never flushed. For a job, S's sequence is the vsock connect, the descriptors, then the frame: a refused connect is the guest side's (`Guest`), a refused descriptor send leaves R untouched (`Local`), and once the descriptors are queued any failure, even before the frame's first byte, is `Dispatched`. A poisoned S→R stream ends S's steady loop and retires the VM. R's reports to S are written whole or R ends. A frame too large to encode is refused before any byte and never poisons.

**One control operation per allocation (B5-05, B5-09).** H holds a control slot per allocation. A Probe takes it and keeps it until R's job reports its end, even past Validate's deadline: a late report is still judged and a late breach still retires the VM, and a relay that never reports within ten seconds after the deadline is itself a breach. A second Validate queues for the slot within its own deadline and then answers `control_busy`, never a breach. Exec admission takes the slot before marking the allocation busy, so a Probe can never observe our own execution starting. Cancel uses the slot only when it is free; an occupied slot never delays escalation. R's own refusal of a second job on a busy channel is `Local` and is never treated as a broker breach.

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

For allocation `A` (32 hex digits), jailer ID is `fc-A`, jail root is `/var/lib/kilnd-helper/jails/firecracker/fc-A/root`, and allocation cgroup is `kilnd-firecracker/I/fc-A` relative to the cgroup v2 root. `I` is the instance ID; the helper pins all ancestors. A jailer ID and jail root are node-global, so the helper gives this contract's formula, in place of the bare token, the first 32 hex digits of SHA-256 over a fixed label, `I` and the allocation ID (see the B3 recheck corrections). The formula, its fixtures and every path length are unchanged, and the plan's own `allocation_id` substitution is still the real token. Derived `/run/vsock.sock` paths must fit Linux's Unix socket length before allocation. Section 7.1's bounded tmpfs is mounted before jailer can write anything.

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

Expose the work volume as a **helper-owned loop block device**, size limit exactly W, rather than a writable regular backing file inside the jail. Persist LOOP_INTENT with the chosen slot's major/minor, backing device/inode, offset=0, size limit and logical block size (512) **before** LOOP_CONFIGURE/binding. LOOP_CONFIGURE sets `LO_FLAGS_AUTOCLEAR`; on the configuring descriptor S then reads the attachment's generation, its disk sequence number (`BLKGETDISKSEQ`), and journals it with the boot ID as the `loop` record. Only then does it clear autoclear on that descriptor and re-verify the tuple and generation. The clear (`sys::ioctl::loop_clear_autoclear`, B4 recheck 5) takes only the `ConfiguredLoop` that `LOOP_CONFIGURE` returned for this process's own slot; it reads `LOOP_GET_STATUS64` itself on that descriptor, requires the configured backing device and inode, offset 0, size limit, autoclear still set and the configured disk sequence number, and writes back exactly that status less the one flag. `LoopInfo64` is opaque, so no caller can build or edit a status to submit, so a crash before the record leaves no attachment once S's descriptor closes. An unexpectedly busy slot is a conflict, never permission to replace its backing. Binding, cleanup and crash recovery validate all of those identities: before LOOP_CLR_FD, on the same opened slot descriptor that then detaches it, cleanup requires the journaled boot ID, the full recorded tuple (including the kernel's `BLKGETSIZE64` and `BLKSSZGET`) and the journaled disk sequence number, read again immediately before the ioctl. Once a generation is journaled, its slot bound to anything other than that generation is Unknown: left bound and charged, never detached. That covers another backing file, the recorded backing inode with any other offset, size limit or block size, and another disk sequence number (detached and rebound, even with the exact tuple). A slot with only an intent is never detached: its autoclear attachment is waited out briefly and otherwise Unknown; only there is another backing file NotOurs, because a busy candidate slot can be another allocation's. A generation from another boot is gone by definition and the slot is not touched. After cleanup detaches a generation, or finds its slot free, it journals `loop_released` for it; from then on that slot is not the allocation's, so a retry or the absence observation never takes a later binding there for a replacement. Cleanup's leftover check and the absence observation read every journaled, unreleased slot itself by major and minor, not only slots backed inside the work directory, and a bound one blocks ABSENT. Bind only the device node as `/work`, owned U:G and mode 0600; no loop-control device, host `/dev` directory or backing-file path enters the jail. The unprivileged VMM cannot grow/truncate the root-owned backing file or resize the block device. Disable discard/unmap paths that could punch holes in the allocation guarantee. B4 must prove the pinned Firecracker synchronous block backend accepts this fixed-size block device and cannot enlarge/rebind it under the VMM credentials/seccomp; an unsupported backend fails closed, without a regular-file fallback. Loop attachment is privileged typed storage work, never a caller-selected device.

Guest init mounts vdb at `/var/lib/kiln/runs` with `nosuid,nodev,noexec,prjquota`. Kiln's persistent sandbox project quota bounds blocks and inodes, probed before Ready. Test direct work-path execution denied and normal overlay execution allowed. Guest root can bypass its inner quota but cannot exceed W; this is a physical outer bound, not trust in guest enforcement.

**Every writable jail byte and inode is bounded from the first jailer write.** Before launching J, S mounts a private tmpfs with `size=16M,nr_inodes=1024,mode=0700,nosuid` on the allocation's jail directory, so the entire jail root (a directory on it) lies inside the bound. The mount carries an allocation-specific source `kilnd-jail-<nonce>` and, beside the jail root and outside the VMM's chroot, a root-only 0400 marker holding the same random 128-bit nonce, both journaled before it exists. The tmpfs is created detached (`fsopen`/`fsmount`) and its marker and jail root are written there. S then reads the mount's 64-bit unique mount ID (`statx` with `STATX_MNT_ID_UNIQUE`, Linux 6.8+; a kernel that does not report it refuses the launch, with no fallback) from the detached mount descriptor and journals it with the boot ID, and only then attaches it onto the jail directory's descriptor (`move_mount`). Each read-only bind is made the same way: `open_tree(OPEN_TREE_CLONE)` of the verified descriptor, `mount_setattr` to read-only/nosuid/nodev/private while detached, its unique ID journaled for all five before any is attached, then `move_mount`. A detached mount dies with its descriptor, so no crash leaves an attached mount whose unique ID was never journaled. Charge its pages/metadata to the allocation; include its full 16 MiB in the provisional host memory allowance. Executing the VMM and accessing KVM require exec/device access, so do not falsely specify noexec/nodev on this whole mount. Kernel/rootfs/config/identity are verified read-only bind mounts; `/work` is the bounded block device. No other writable bind, host filesystem or external logging path exists. The VMM executable is a read-only bind of the retained approved inode, not a writable jailer copy; check that remaining cache/control files fit the cap before accepting this profile. Node metadata and immutable-store headroom are reserved separately below.

The pinned jailer chowns `/`, `/dev`, `/dev/net` and `/run` to its UID, so root ownership before launch alone is insufficient. After J's expected exit and V's identity validation, S stops V through its pidfd. It hardens the root, `/dev` and `/dev/net` to root-owned 0755 and cache files to root-owned 0444, preserving only the explicitly needed device-node U:G access. It independently verifies that `/firecracker` remains the root-owned 0555 read-only bind of the expected inode, leaves only `/run` writable by U:G, checks the resulting mount tree and resumes V. Do this before Ready; a missing/failed hardening step retires the VM. Even a malicious pre-hardening VMM, a retained writable FD or unexpected path creation remains bounded by the **whole-jail** tmpfs cap. Fixed artifact mounts are read-only independent of chmod. All walks/hardening use pinned directory descriptors, no-follow opens and mount IDs; reject replacement entries instead of following links.

An optional host XFS project quota can narrow the host session-storage allowance, but is not its security mechanism. Portability relies on the preallocated root-only W backing file, exact-size loop exposure, mandatory whole-jail tmpfs byte/inode cap and fixed-size helper metadata. Fill files, sockets and inodes as U:G in B4 and show the node journal/recovery headroom stays available. Quota/ENOSPC faults retire only the affected allocation and never relax these limits.

Delete proves VMM/worker exit and FD closure, unmounts owned binds/tmpfs (no lazy unmount as absence proof) only after proving each is the journaled one immediately before its own unmount, detaches the loop device with the verified journaled generation and full binding tuple, proves no pending loop attachment/holder, removes the private backing file and bounded control files, syncs parents and removes the empty cgroup. A crash after LOOP_CONFIGURE but before the recorded generation leaves an autoclear attachment that goes with S's descriptor; anything still bound to the backing inode without a journaled generation is ambiguous and stays charged. Refuse unknown inodes/mounts/devices. A mount is the allocation's only if the unique mount ID at its path, read immediately before its unmount, is the journaled one from this boot; its reusable `{mount_id, st_dev, st_ino}`, source and marker must also match but are secondary, because the kernel hands a fresh replacement the whole reusable tuple and root can copy the source and marker. A mount is never the allocation's by its deterministic path or a contract bind name: a bind under the jail whose unique ID was never journaled is Unknown, quarantined and charged, with nothing unmounted. A live owner holds the descriptors the journaled IDs were read from; after a crash, cleanup uses only the journaled unique IDs and boot ID.

**Teardown fault model (B4 recheck, November 2, 2026).** Copyable markers and check-then-ioctl sequences cannot beat a concurrent host-root actor, so B4's exact-identity guarantee is defined by kernel IDs that are never reused within a boot, plus the boot ID (`/proc/sys/kernel/random/boot_id`), journaled with every identity: a different boot ID means every recorded mount and loop attachment is gone by definition.

- *In scope:* root replacing a resource before cleanup, at any crash point, a reboot included — a fresh tmpfs or bind at the path, a loop slot detached and rebound with any backing file or tuple, a cgroup node removed and recreated, or a work-directory file deleted and recreated. That is refused: the unique mount ID, the disk sequence number, the cgroup inode with its boot ID, or the file's birth time differs, the allocation is Unknown and stays charged, and the replacement is left exactly as it is. cgroupfs inode numbers are never reused within a boot but start again at each boot, so `CgroupIdentity` carries the boot ID and records every node; a tree recorded in another boot is gone and anything at its path is Replaced. Files outlive a reboot and their inode numbers are reused once deleted, so a `FileIdentity` adds the `statx` birth time (`STATX_BTIME`), which no system call sets; a filesystem that does not report it refuses the launch.
- *Out of scope:* host root mutating one of our own resources in place, during teardown — for example `LOOP_SET_STATUS64` on our attachment between cleanup's comparison and `LOOP_CLR_FD`, which leaves the disk sequence number unchanged. Host root is trusted and the kernel has no compare-and-clear; detaching an attachment whose generation (disk sequence number and backing inode) matches is correct, because it is ours.
- *The helper's own environment is part of the trusted computing base (B4 recheck 5).* An actor that can mount over or change the helper's own mount namespace, `/proc` view, memory or descriptors (by `ptrace`, `setns` into the helper, or code injection) has compromised the helper, and that is out of scope. Even so, no proof relies on a pathname lookup through `/proc`, as defense in depth and because the descriptor-native form is simply correct: cgroup children are listed with `getdents64` on the retained descriptor, an unmount resolves its name from the held parent descriptor, and process, boot-ID and mount-table reads go beneath a private procfs instance (*The `/proc/self/fd` sweep* below).
- *The compile-time gate guards against honest mistakes by kilnd developers (B4 recheck 5).* It is not a defence against malicious source changes; code review covers those. A deliberately obfuscated bypass, such as `build.rs` code generation, names assembled from fragments or `include!` of generated code, is out of scope. Cheap checks still close the obvious routes: a test fails on any build script but `kilnd-api`'s and on any `include!` or `OUT_DIR` outside its protobuf stubs.
- *Kernel facts relied on,* verified on the VM's 6.8.0-147 by `b4_linux_root_kernel_generation_ids_are_never_reused`: a replacement tmpfs gets a new unique mount ID although the reusable tuple is reused; a detached mount keeps its unique ID when attached; detach plus reattach of the same slot, inode and tuple changes the disk sequence number; `LOOP_SET_STATUS64` does not. B4 recheck 2 added, on the same kernel: ext4 gave a recreated work file the deleted file's inode number at once, with a later birth time (`b4_linux_root_cleanup_refuses_a_work_file_reusing_the_inode`). Also observed: while cleanup's descriptor on a slot is open, another opener's `LOOP_CLR_FD` only marks it autoclear and a rebinding `LOOP_CONFIGURE` fails `EBUSY`, so a replacement cannot land inside cleanup's own comparison-to-clear window. Deletion is destructive and authorized by DeleteSandbox; there is no export/retention or secure-erasure claim. Encryption/export/snapshots remain separate features.

**The destructive-action invariant (B4 recheck 3, November 2, 2026).** No destructive action may run on a resource unless the caller holds proof that the resource's current generation equals a durable journaled generation from the current boot. A resource with no such proof is Unknown: it stays charged, nothing is done to it, and it never counts toward ABSENT. The destructive actions are signals (`pidfd_send_signal`, `kill`), writes to `cgroup.kill`, `rmdir` of a cgroup or directory, `unlink` of a file, `umount2` and `LOOP_CLR_FD`. The type system enforces it: `crates/kilnd/src/helper/firecracker/proven.rs` holds one proof type per resource kind (`ProvenProcess`, `ProvenCgroupVm` and `ProvenCgroupTree`, `ProvenFile`, `ProvenDir`, `ProvenMount`, `ProvenLoop`), none `Clone` and none constructible outside that module. Only its verification functions make them, each from the journaled identity, the current boot ID and the live kernel object, returning `Result<Proven*, Unprovable>` (`Gone`, `Replaced` or `Unknown`). Every destructive helper takes its proof, and the raw capabilities appear nowhere else: since B4 recheck 4 clippy enforces it semantically for the whole workspace (*The clippy gate* below), with the lexical test `proven::tests::no_destructive_call_outside_the_gate` kept as defense in depth. Each check stays as close to its action as the kernel allows, which is the decided residual window: a pidfd for processes, the `vm` node's descriptor for `cgroup.kill` with its children re-listed from that descriptor (`getdents64` on a rewound duplicate) just before, the parent's descriptor with the child's inode or birth time re-read just before each `rmdir` and `unlinkat`, the loop descriptor the generation was compared on, and for mounts a fresh descriptor's unique mount ID read just before `umount2` of the single name resolved from the held parent descriptor (that descriptor must be closed first, or a non-lazy unmount is busy). No proof reads a `/proc/self/fd` pathname (B4 recheck 5).

- *Boot ID everywhere.* Every durable process identity (`ProcessId`, so `ResourceRecord::Vmm`, `StopTarget`, M's and K's targets and the worker rows) carries a validated boot ID. A process whose PID and start time match is proven only when its journaled boot ID is this boot's. A different boot ID only shows that the journaled process is gone, and never leads to a signal. An absent or invalid one, from an older row, proves nothing: that process is never signaled and stays charged until it is provably gone. An unreadable host boot ID is an error, never `unknown`.
- *The cgroup tree.* `cgroup.kill` needs `ProvenCgroupVm`: the boot ID and the journaled inodes of the parent, `vm`, `vm/vmm` and `vm/console`, and no other cgroup anywhere below `vm`. A replaced or unexpected child is Replaced, with no signal. Removal needs `ProvenCgroupTree`, which covers every node and admits no other cgroup below the parent. H's monitor target, K's emergency target, `kill_recorded`, `contain` and `remove_tree` all go through these.
- *No identity-free deletion.* An intent is journaled before the cgroup tree, the work and jail directories and each work file are created, and the generation right after creation, before the next step. Work files are created unlinked (`O_TMPFILE`), journaled, then linked, so no crash leaves a named file without a generation. A present object with only an intent, or with no record at all, is Unknown, and nothing is deleted by its deterministic name. An intent-only object that verifiably is not present is fine. Remove reloads the allocation's complete journal after the stop fence, so a record S committed after Remove's first read is honoured.

| Destructive call (`crates/kilnd/src/helper/`) | Site | Proof taken |
|---|---|---|
| `pidfd_send_signal` (SIGKILL, SIGSTOP, SIGCONT) | `proven::signal`, used by `proven::kill_and_wait` / `stop_process` (K, S's `stop_vm`) and S's hardening of V | `ProvenProcess` |
| `kill` (macOS fixtures only, no pidfd) | `proven::signal` | `ProvenProcess` (start time and boot ID compared just before) |
| `kill(SIGKILL)` of S's formatter, and (B5) of S's relay R and console drainer D if either outlives a one-second wait after S closes its sockets | `proven::UnreapedChild::kill_unreaped` | `UnreapedChild`, made only by `proven::fork_child`; never after it is reaped |
| write to `cgroup.kill` | `proven::write_cgroup_kill` (private), reached only from `proven::kill_cgroup_vm`, via `cgroup::kill_recorded` (H, M, K, S's `contain`, cleanup). The generic `cgroup::write_control` is private and takes a `ControlFile` enum with no `cgroup.kill` variant | `ProvenCgroupVm` |
| cgroup `rmdir` (`unlinkat(AT_REMOVEDIR)`) | `proven::remove_cgroup_tree`, via `cgroup::remove_tree` (K) | `ProvenCgroupTree` |
| directory `rmdir` | `proven::remove_directory`, via `storage::remove_jail_dirs` and `storage::remove_work` | `ProvenDir` |
| `unlinkat` of a work, identity or config file | `proven::unlink_file`, via `storage::remove_work` | `ProvenFile` |
| `umount2` of each bind and the jail tmpfs | `proven::unmount`, via `storage::unmount_jail`: on a thread with its own filesystem context (`unshare(CLONE_FS)`) whose working directory is the held parent descriptor (`fchdir`), `umount2(name, UMOUNT_NOFOLLOW)` | `ProvenMount` |
| `LOOP_CLR_FD` | `proven::clear_loop`, via `storage::detach_loop` | `ProvenLoop` |
| `LOOP_SET_STATUS64` clearing `LO_FLAGS_AUTOCLEAR` | `sys::ioctl::loop_clear_autoclear`, via `storage::persist_loop` | `ConfiguredLoop`, made only by `loop_configure_autoclear` on this process's slot; the status is read and validated inside, and only the flag changes |
| `ptrace(PTRACE_DETACH)` of S's formatter (test-only exec-stop observation) | `proven::UnreapedChild::detach_trace` | `UnreapedChild` |
| `unlinkat` of kilnd's API socket (`crates/kilnd/src/sys.rs`, not the helper) | `sys::socket::remove_socket_generation`, via `server::SocketPathGuard::cleanup` and `server::remove_stale_socket_after_probe` | the `SocketGeneration` (device, inode, birth time and, on Linux, the `name_to_handle_at` file handle with its inode generation number) it was bound or found as, read again through the socket directory's descriptor immediately before |
| truncation of kilnd's own lock file (`crates/kilnd/src/lock.rs`) | `ExclusiveFileLock::finish_acquire` | the just-locked inode, re-verified at its stable pathname |
| mode-0 `fallocate` of a new work file | `sys::preallocate`, via `storage::preallocate` | Not destructive: allocates and extends a file created unlinked; no other mode is reachable |
| write of `0` to `/sys/block/loop<minor>/queue/discard_max_bytes` | `sys::write_sysfs(SysfsControl::LoopDiscardOff)`, via `storage::attach_loop` | Not destructive: a fixed value to a fixed file of the slot just configured |
| `pidfd_send_signal` with the constant signal 0 | `sys::pidfd_alive`, used by `peer.rs` | Not destructive: a liveness probe through a pidfd; the signal number is not a parameter |
| `kill(pid, 0)` | `sys::process_exists`, used by macOS `workers::process_state` | Not destructive: an existence probe on macOS fixtures only |

The executable store has no destructive call at all since B4 recheck 4: `executable::publish_object` copies into an unnamed `O_TMPFILE` inode and links that descriptor, so it neither publishes nor cleans up through a name (*B4 recheck 4 corrections*). The other helper writers create without a temporary name: the ledger's `node.db` is created once with `O_EXCL` and never replaced (SQLite's own `-wal`/`-shm`/`-journal` maintenance in the root-only ledger directory is the one dependency-internal unlink, outside the B4 lifecycle); work, identity and config files are `O_TMPFILE` then `linkat` (`storage::publish`); and the plan, policy and journal records are SQLite rows. `scripts/build-phase1b-tools.sh` publishes into its output directory with a random `mktemp` name and a rename, as the trusted build UID and never as root; its post-publish digest comparison is the gate, and every installer compares the digest again. It is not a helper path.

*The `/proc/self/fd` sweep (B4 recheck 5).* Root in the helper's mount namespace can bind-mount any view over `/proc/self/fd`, so a pathname through it names whatever that view says, not the descriptor. Every use in the crate, and what became of it:

| Use | Before | Now |
|---|---|---|
| `proven::child_cgroups` (the `cgroup.kill` and removal proofs) | `read_dir("/proc/self/fd/N")` | `sys::read_dir_fd`: `getdents64` on an `F_DUPFD_CLOEXEC` duplicate of the retained node descriptor, rewound with `lseek(0)` |
| `proven::unmount` | `umount2("/proc/self/fd/<parent>/<name>")` after checking the real parent | `umount2(name)` from a thread whose working directory is the parent descriptor (below) |
| `storage::list` (the jail hardening walk) | `read_dir("/proc/self/fd/N")` | `sys::read_dir_fd` |
| `cgroup::allocation_names` (inventory) | `read_dir("/proc/self/fd/N")` | `sys::read_dir_fd` |
| `storage::attach_jail` (private propagation of the jail tmpfs) | `mount(MS_PRIVATE)` on `/proc/self/fd/N` | `mount_setattr` with `propagation = MS_PRIVATE` on the mount's own descriptor (`AT_EMPTY_PATH`) |
| `executable::publish_object` and `storage::publish` | `linkat(AT_FDCWD, "/proc/self/fd/N", dir, name, AT_SYMLINK_FOLLOW)` | Unchanged, deliberately. A redirected link can put the wrong inode under the name, but the name is then re-read without following and must show the held descriptor's device, inode and birth time; a mismatch is an error, the object is never authorized or journaled, and nothing is unlinked. `AT_EMPTY_PATH` would need `CAP_DAC_READ_SEARCH`, which the helper does not have (*B4 recheck 4 corrections*) |
| test fixtures (`executable/tests.rs`, `kiln_process` and `kiln_integration` descriptor counts) | `read_dir("/proc/self/fd")` | Unchanged: test-only, never an authorization |

The other `/proc` pathname reads moved beneath `sys::procfs`, a private procfs superblock the helper makes with `fsopen("proc")` and `fsmount` and never attaches, so no mount in any namespace can shadow a path below it. Lookups are `openat2` beneath its root with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV`, except the one `exe` magic link of `observe_process_image`, opened below `<pid>` there. That covers the process state and start time behind `ProvenProcess` (`<pid>/stat`), the boot ID behind every proof (`sys/kernel/random/boot_id`), the VMM's `status` and `fd` table, the mount table (`<own pid>/mountinfo`), cgroup membership after a join, and peers' `/proc/<pid>` directories. The root descriptor is cached with the instance's unique mount ID and re-verified on every use, so a forked worker that closed every descriptor, or a reused descriptor number, makes a fresh instance instead of reading another file. Without `CAP_SYS_ADMIN` (only an unprivileged test run) it falls back to `/proc`; as root, failing to make the instance is an error. Process start times and the boot ID are read only there.

*Unmounting without a pathname root.* Linux 6.8 has no unmount by descriptor: `umount2` takes a pathname; `open_tree` without `OPEN_TREE_CLONE` only returns another descriptor of the attached mount; `move_mount` can move a mount but not detach it, and `fsmount` makes new mounts only. The narrowest 6.8-compatible form is therefore to make the held parent descriptor the starting point of a one-component lookup: a short-lived thread unshares its filesystem context (`unshare(CLONE_FS)` copies root, working directory and umask for that thread alone, so no other thread's relative lookups move), `fchdir`s to the parent descriptor, re-reads the unique mount ID at `name` (an `O_PATH | O_NOFOLLOW` descriptor that is closed before the unmount), and calls `umount2(name, UMOUNT_NOFOLLOW)`. Both resolve exactly one component, a validated name with no `/`, from the parent's own dentry and mount. `openat2(RESOLVE_NO_XDEV)` cannot express this check: the target is itself a mount crossing. The remaining interval between that read and `umount2` is the decided narrow window.

*The clippy gate (B4 recheck 4).* `clippy.toml` at the workspace root lists as `disallowed-methods` every raw destructive, raw-syscall and subprocess capability: `libc::kill`, `killpg`, `tgkill`, `pidfd_send_signal`, `syscall`, `unlink`, `unlinkat`, `rmdir`, `remove`, `umount`, `umount2`, `unmount`, `rename`, `renameat`, `renameat2`, `renameatx_np`, `ioctl`, `execve`, `execv`, `execvp`, `execvpe`, `execveat`, `fexecve`, `posix_spawn`, `posix_spawnp` and `system`; `std::fs::remove_file`, `remove_dir`, `remove_dir_all` and `rename` and their `tokio::fs` equivalents; `std::process::Command::new` and `tokio::process::Command::new`; and `std::process::Child::kill`, `tokio::process::Child::kill` and `start_kill`. Since B4 recheck 5 it also lists truncation and overwrite (`std::fs::File::set_len`, `File::create`, `OpenOptions::truncate` and `std::fs::write`, the `tokio::fs` equivalents, `libc::truncate`, `ftruncate`, `fallocate`, `fallocate64` and `posix_fallocate`) and raw process and memory control (`libc::prctl`, `ptrace`, `process_vm_writev`, `process_vm_readv` and `pidfd_getfd`). Neither `nix` nor `rustix` is a direct dependency. The lint resolves paths, so it fires on a function taken as a value, a `use ... as` alias or a function-pointer constant exactly as on a call; the recheck-4 PoC (`let raw_kill = libc::kill;`) fails clippy on Rust 1.88 and 1.99. Entries marked `allow-invalid` exist only on some targets; on Linux every one resolves except `pidfd_send_signal`, which libc does not wrap (it is reachable only through `libc::syscall`, itself disallowed), and the macOS-only `unmount` and `renameatx_np`. CI runs clippy over all targets with `-D warnings -D clippy::disallowed_methods` on 1.88 and 1.99. There is no `disallowed-types` entry: every listed capability is a function, and `Command` has no other constructor.

| Approved module or item (`crates/kilnd/src/`, or `crates/kilnd-exec-core/src/` where marked *core*) | Allows | Why |
|---|---|---|
| `helper/firecracker/proven.rs` (whole module) | every raw destructive call | The gate: each one sits behind a proof type |
| `sys.rs` (whole module) | `libc::syscall`, `libc::ioctl`, `libc::prctl`, `libc::ptrace`, `libc::fallocate`, one `unlinkat`, and `kill(pid, 0)` on macOS | The typed wrappers: `close_range`, `pidfd_open`, `pidfd_alive` (signal fixed at 0), `capget` and `capset` (re-exported from the core since B5), `execveat_empty` (the only way the helper starts the jailer, Firecracker or mkfs.xfs, from a retained descriptor), `read_dir_fd` (`getdents64`), `procfs` (`openat2` beneath the private instance), one function per fixed `prctl` request (`sys::prctl`: ambient, bounding-set, no-new-privs, parent-death and subreaper requests, plus the dumpable flag), `ptrace_traceme`, `preallocate` (mode-0 `fallocate` only), `write_sysfs` (the `SysfsControl` enum's files only), the creation-only mount API (`DetachedMount` is made only by `fsmount` or `open_tree_clone`, so `move_mount` and `mount_setattr` act only on a mount this process created), `sys::ioctl` (`LOOP_GET_STATUS64` into an opaque `LoopInfo64`, `LOOP_CTL_GET_FREE`, `BLKGETDISKSEQ`, `BLKGETSIZE64`, `BLKSSZGET`, `LOOP_CONFIGURE`, which the kernel refuses on a bound slot and which returns the `ConfiguredLoop`, and clearing `LO_FLAGS_AUTOCLEAR` on that `ConfiguredLoop` only), and `sys::socket`'s generation-checked unlink of kilnd's API socket. `LOOP_CLR_FD` is not there: it is only in `proven::clear_loop`, which takes a `ProvenLoop` |
| *core* `sys.rs` (whole module, B5) | `libc::syscall`, `libc::prctl` | The child setup's subset of the typed wrappers, moved unchanged from kilnd's `sys.rs` with `process::prepare_child`, which issues them between fork and exec: `capget`, `capset`, and the fixed `prctl` capability-ambient, bounding-set, no-new-privs and parent-death requests. kilnd's `sys` re-exports them. `no_destructive_call_outside_the_gate` scans it like kilnd's `sys.rs` |
| *core* `process.rs`, `run` | `tokio::process::Command::new`, `Child::start_kill` | kilnd's one subprocess runner, for the fixed `process::Tool` variants only: `Tool::Kiln`, a `KilnBinary` verified at every launch (an absolute path to a regular executable owned by root or this user and writable by neither group nor others) with `KilnArgs` from typed constructors (`capabilities`, `ls`, `rm`, scoped `gc`, `gc --help`, `create`), and SIGKILL of its own unreaped child, whose PID cannot be reused before it is reaped. There is no arbitrary-program variant |
| *core* `runtime/kiln_process.rs`, `probe`, `OwnedExec::spawn`, `OwnedExec::kill_reap` | `tokio::process::Command::new`, `Child::start_kill` | The kiln CLI probe and `kiln exec`, both taking the verified `KilnBinary` (and the probe typed `KilnArgs`), and SIGKILL of their own unreaped children |
| `lock.rs`, `ExclusiveFileLock::finish_acquire` | `std::fs::File::set_len` | Truncating this process's own just-locked lock file before writing its diagnostic PID, after the inode was re-verified at the stable pathname |
| `cfg(test)` items, test modules and files | anything | Fixtures compiled only under `cfg(test)` (test modules, and test-only fault and fake-effect items), or integration-test crates |

Each allow is `#[allow(clippy::disallowed_methods)]` (inner for a whole module) with an `// Approved (design 7.1):` justification immediately above it. The CI test `proven::tests::disallowed_allows_only_in_approved_modules` scans every Rust source in the workspace and fails on an `allow` or `expect` of `disallowed_methods`, `disallowed_types` or anything that would silence them (`clippy::style`, `clippy::all`, `warnings`, also inside `cfg_attr`) other than exactly these, on a `#[cfg(test)]` item, or on a test-only file (a `tests.rs` its parent declares `#[cfg(test)] mod tests;`, or an integration test); on one without the justification; on any `[lints]` table or `.cargo/config`; and on a `clippy.toml` that drops a required path. (`kilnd-api`'s generated code no longer allows `clippy::all`.) `proven::tests::no_foreign_declarations_or_inline_assembly` rejects a local `extern` block, inline assembly, `#[link]`, `link_name` or `dlsym` anywhere, which clippy cannot see through. Since B4 recheck 5, `proven::tests::no_unapproved_build_scripts_or_generated_includes` fails on any build script other than `kilnd-api/build.rs`, a `build` key in a manifest, and any `include!`, `include_proto!` or `OUT_DIR` other than `kilnd-api`'s `tonic::include_proto!("kilnd.v1")`, since generated code is invisible to every source check; and `proven::tests::proc_and_control_paths_only_in_approved_modules` fails on a production string literal containing `/proc/` or `cgroup.` outside `sys.rs`, `cgroup.rs` and `proven.rs`, except four justified ones (the two publish `linkat` paths above, kiln's read-only `exec/cgroup.events`, and one `cfg(test)` fixture). Every helper write under `/proc` or `/sys` goes through `cgroup::write_control`'s `ControlFile` enum, `proven::write_cgroup_kill` (the two `/sys/fs/cgroup` writers) or `sys::write_sysfs` (the one `/sys/block` file); nothing writes under `/proc`. The lexical test now matches whole expressions with comments and whitespace removed, so an allowed expression cannot hide another on the same line, and its needles also catch aliases (`libc::kill` without a call), `rename`, subprocesses, `start_kill`, raw `syscall`, `ioctl`, `prctl`, `ptrace` and `fallocate` outside `sys.rs`, truncation (`set_len`, `.truncate(true)`, `File::create(`, `truncate`, `ftruncate`), `process_vm_writev`, `pidfd_getfd`, foreign declarations and inline assembly; it scans the helper and `sys.rs`, where its one `unlinkat` is allow-listed by exact expression.

Test fixtures are excluded from the gate. Outside the approved items above, nothing in the workspace calls or names any listed capability.

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

Daemons report node totals from the helper ledger, with freshness/generation and unavailable status when it cannot be read, rather than presenting a local sum as global. Keep owner-filtered API lists and private per-instance metadata; global totals reveal no other session identities. Each enrolled instance has one attachment slot, a queue for attach attempts that only its own account can join, a few framing slots of its own, its own share of the 128 detached operations, and its own quota of 4096/N non-durable token gates (N is the policy's enrollment maximum), none of them drawn from a common pool. Attach writes only its own row, once, and that first binding refuses past the fence-headroom floor; a reattachment writes nothing. AttachInstance and startup reconciliation compare database UUID/instance, all owned allocations and helper receipts before admitting. A missing/stale/restored daemon DB never reduces helper charges. Unknown or conflicting ownership quarantines admission; helper-ledger loss/corruption disables Create/Exec for the node until resource inventory and operator repair establish authority. Never recreate an empty ledger over possibly live resources. Helper restart replays all unreleased claims before serving; raw node capacity is not recalculated from idle PSS or currently visible PIDs.

No pool members initially. A future pool of one is a fresh cold-booted, never-used guest with the same global claim vector, leaving two active 768 MiB sessions while holding one spare under this policy. Assignment needs an atomic ledger ownership transfer and new identity handshake; it never releases/reclaims capacity in the middle, reuses a tenant disk or clones a snapshot.

## 7.4 Per-allocation journal retention (B5-01)

No per-allocation row may grow without bound under ordinary use, and nothing L sends may depend on an allocation's history for its size.

- **Executions.** An allocation holds at most the in-flight execution's `exec` rows (`intent`, `busy`) plus one fixed-size `exec_history` summary: how many executions settled, and the last one's token, execution ID and state. The transaction that records an execution's settlement (`idle`, `undispatched` or `interrupted`) writes the new summary and deletes every older `exec` and `exec_history` row of that allocation. A second settlement of the same token updates the state without counting it twice. The `resource_events_no_delete` trigger permits only that: an `exec` or `exec_history` row may be deleted only when a newer `exec_history` row of the same allocation exists; every other resource row stays permanent. `AllocationState` reads only execution rows at or after the latest summary, so its encoded size does not depend on how many executions ran (about 400 bytes of execution evidence after 3 or 100,000).
- **Stop reasons.** Each Stop or Remove attempt may record a reason; the first sixteen per allocation are kept, and later stops only move the phase to `stop_intent`.
- **Cleanup workers.** Each cleanup attempt journals a worker intent. When a new one is recorded, settled rows of the same allocation and mode beyond the newest eight are deleted; the `worker_intents_no_delete` trigger permits only that. Unsettled and node-level rows stay permanent, so recovery and accounting see every worker that could still be running.
- **Everything else** is written once per boot (one boot per allocation) or once per loop slot, and is already bounded.
- **Defense in depth.** L never exits because an answer is too large: it replies `oversized {bytes}` instead, H raises a health fault (`ledger_fault` in Capabilities), and the caller treats the state as Unknown, so Stop and Remove contain the VM and the allocation stays charged.

The ledger keeps schema version 1: no B5 ledger has shipped, and one from an earlier B5 build fails its schema audit, closed, and needs provisioning again (the B3 rule).

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
- Ownership: foreign caller cannot Probe/Exec/Delete or inspect output via the new fields, root retains authorized visibility, pagination filters first, helper only accepts the exact service UID for kiln, and for Firecracker only the account enrolled for the instance named. Wrong instance/allocation/plan IDs never reach another session.

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

**B4 recheck 6 hardening follow-ups** (`reviews/2026-11-03-b4-recheck6.md`, ranked; none blocks B5):

1. *Fail closed when a socket filesystem cannot export a file handle* (MEDIUM). `name_to_handle_at` returning `EOPNOTSUPP` becomes the all-zero handle, so the API socket's generation silently falls back to device, inode and birth time; ramfs accepts Unix sockets and returns `EOPNOTSUPP`. Reject `EOPNOTSUPP`, or validate an explicit allowlist of socket filesystems that export handles (`sys.rs` socket generation).
2. *Make the destructive-method gate dependency-aware* (LOW). Clippy's list names libc/std/tokio paths; a future system-call crate could expose an equivalent the lexical backstop misses. Reject new syscall-wrapper dependencies by manifest allowlist, or require their destructive methods to join `clippy.toml` in the same change.
3. *Serialize initialization of the private procfs cache* (LOW). The cache publishes its mount ID and descriptor through two atomics; concurrent first callers can each create a procfs root, and the losers' descriptors leak for the process's life. Use `OnceLock` or a mutex.
4. *Give `read_dir_fd` an independent file description* (LOW). `F_DUPFD_CLOEXEC` shares the directory offset, so its rewind also rewinds the original description. Reopen `.` beneath the held descriptor instead, preserving the fd-native property.

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

The PDF is a local review artifact; the source and style are versioned with this design. Rendering grants no production approval. B1 contract tests run on macOS and Linux/root. B4 and B5 ran the live chain (pinned bundle, patched jailer, Firecracker, broker READY and persistent exec) under test approval only; B6 wires it into the manager and B7 alone may enable production.

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

**Known limits, accepted or open.** The B3 recheck corrections below revised the two about
service accounts, since instances no longer share one.

- **Flooding by one's own account.** A process under an instance's own account can keep that
  instance's eight attach waiters busy with attempts L refuses. That delays only its own
  new attachment, and is that account's own authority.
- **Children of a compromised daemon.** Its children inside its own unit pass the proof for
  that instance, which is that unit's own authority. The kilnd unit must not set
  `Delegate=`, so that its cgroup stays root-writable only.
- **Never-admitted fences are a lifetime budget.** Fences are permanent, so a quota spent
  stays spent until epoch-safe compaction exists. A daemon that really does exhaust it,
  through many pre-INTENT rejections, keeps those charges until an operator acts. A
  policy with a lower `max_enrolled_instances` gives each instance more. Compaction and
  that repair remain separate work (B6).

## B3 recheck corrections (November 1, 2026)

The Daybreak Blue recheck (`reviews/2026-10-31-b3-recheck.md`) found the first four failures
repaired and three cross-instance ones left, all from enrolled instances sharing one Unix
UID. These decisions are made; sections 4.1, 6.1, 6.2, 6.4 and 7.3 reflect them.

- **B3R-01, a copied token pre-fenced by another instance.** A hostile instance could read a
  victim's C1 row and fence its allocation ID first, which the node-global key made
  permanent for the victim. Allocation identity is now (instance, allocation ID). Every
  table a claim or fence writes has that composite key, as do `sandbox_id` and `backend_id`
  uniqueness, and every lookup resolves only in the caller's authenticated instance. A
  fence row from one instance cannot conflict with another's token: the attacker spends its
  own quota and retires a name in its own namespace. H's supervisors and M's stop queue use
  the same pair, so a stop for one can't land on the other.
  `tests/control_plane.rs::b3r_01_*` includes the report's real manager test, paused after
  C1, and `journal/tests.rs::b3r_01_*` the ledger's half; the same with two real accounts is
  `b3r_01_linux_root_*`.
- **Node-global names stay node-global.** Three things really are one namespace. UID, GID and
  CID leases are kernel identities, so their active-lease index stays node-wide; a preflight
  picks free ones, and a collision answers exactly and can be fenced. Capacity stays one
  budget, by design. And jailer IDs and jail roots are node-global paths: two instances with
  the same allocation ID must not share one, and the longer path an instance directory
  would make doesn't fit `sockaddr_un`. So names come from a digest of (instance, allocation
  ID), reaching one of another instance's is a SHA-256 second preimage, and B1's frozen
  contract and fixtures didn't need to change. S and K follow the plan's names in B4.
  `backend_id` stays `fc-<allocation>`: it names an allocation inside its own instance, and
  is what the daemon stores.
- **B3R-02, instance isolation relied on Yama.** Each enrolled instance now has its own UID
  and GID, section 4.1. Cross-instance memory access, signals and database reads are
  cross-UID, so the Yama prerequisite is gone rather than enforced.
  `b3r_02_linux_root_another_account_cannot_reach_memory_signals_or_state_at_yama_zero` sets
  scope 0, shows the instance's own account can open the daemon's memory, and shows another
  account can't; the original setting is restored. The ledger's `UNIQUE` columns and
  triggers refuse a shared account, its open audit refuses a ledger with one, and H refuses
  to serve any instance if a row names root, the helper or a VM identity range.
- **Kiln stays the service account's.** The listener admits the `kilnd` account and enrolled
  accounts, before reading anything. kiln's registry has no instances, so an enrolled account
  that isn't the service account gets no reply to a kiln request. Until B7 can select
  Firecracker, a `kilnd@<name>` daemon therefore stops at its kiln startup reconciliation.
- **The socket's group.** `kilnd-helper` is new, for reaching the helper socket and nothing
  else. Adding instances to the `kilnd` group instead would give each one the default
  instance's API socket. The socket's real check is still the peer's UID.
- **B3R-03, an unproven peer could fill a victim's attach queue.** A waiter's queue was chosen
  by the instance the request named. It is now chosen by the peer's SO_PEERCRED UID, and an
  account joins only the queue of the instance it serves: anything else, including an
  account nobody enrolled, is refused before queueing, with no L call. L's attach lane has a
  place for one proof per account. Each enrolled account also has four framing slots of its
  own, because a queue is no use to a connection that can't be framed.
  `b3r_03_wrong_account_and_wrong_cgroup_peers_cannot_touch_a_victims_attach` is the report's
  PoC turned around, with L stalled and every queue the attacker can reach full, and
  `b3r_03_linux_root_*` and `b3r_linux_root_the_listener_tells_real_accounts_apart` run it
  under real accounts.

**Schema.** `instances` gains `uid` and `gid`, and allocation tables gain `instance_id`. Still
version 1, since no B3 ledger has shipped: an earlier one fails its schema audit, closed, and
needs provisioning again.

**The recheck's other PoCs.** `03-production-worker-journal-bypass.md` remains B7's gate, as the
report says: the production-disabled no-image branch must not survive enabling profiles.

**Known limits, accepted or open:**

- **Raw connections and operation slots across accounts.** An enrolled account can still fill
  the 128 shared framing slots, and the 60 normal and 4 recovery operation slots, until their
  deadlines. A daemon's attachment survives this and so does a fresh attach, because neither
  uses those operation slots, but another attached instance's Create, Inspect, List and Fence
  can be refused `resource_exhausted` while it lasts. Nothing is released and work is not
  lost, and a retry succeeds once the attacker's requests end. This used to be a same-UID
  limit; it now crosses accounts, and B7's multi-daemon test should measure it.
- **Shared node budgets.** One instance can still spend the node's capacity and its admitted
  token allowance, as the design intends.
- **Root.** Root modifying policy, enrollment or the ledger stays out of this model.

## B3 deployment corrections (November 1, 2026)

The Daybreak Blue final recheck (`reviews/2026-11-01-b3-final.md`) found the security core
sound and the deployment path broken in three ways. The decisions are made, and
`docs/setup.md` is the operator's account. Root's maintenance commands now live in one
script, `scripts/kilnd-maintenance.py`, with `scripts/add-instance.sh` and
`scripts/upgrade.sh` as its doors, and `scripts/deployment-regressions.py` runs them against
the installed services.

- **B3F-01, an enrolled ID the daemon would not use.** An instance's identity now has one
  origin: `kilnd init-state`, which root may run, because it creates only the final directory
  below a path root alone controls, hands it to the account, and gives up every privilege
  before opening anything inside. The script enrolls exactly the ID it prints, and only then
  starts the unit. `add-instance.sh` no longer takes an ID, and the default instance takes
  the same steps from `install.sh`.
- **B3F-02, socket activation racing enrollment.** The maintenance window is non-activatable.
  Stopping the socket stops every daemon through `Requires=`, so the window records what was
  running first, in `/run`, and puts back exactly that on any end, or on the next command after
  a kill. One correction to the plan we first wrote: `systemctl mask --runtime` does nothing
  to a unit installed in `/etc`, which outranks `/run/systemd/system`, so the masks go in
  `/run/systemd/system.control`, which outranks `/etc`, and each is verified by its
  `LoadState`. Another: masking a live unit discards its loaded settings, so a masked helper
  would stop with the default `KillMode` and take running sandboxes with it. The socket is
  masked first, which already makes activation impossible, and the service only once stopped.
- **B3F-03, upgrades split between stale and refused images.** Upgrades are one transaction:
  `kilnd-helper refresh-enrollments` replaces every row's image in one ledger transaction and
  can touch nothing else, `restore-enrollments` undoes it from `enrollments`' output under the
  same rule, and the images move by rename, so a rollback's old image has its old inode and
  the old rows are true again. Each running instance's new image opens its state before anything
  serves, so a failed schema upgrade reaches no client. A database goes back only if its
  schema changed, since otherwise the one in place is newer and replacing it could lose a
  reservation, and a schema that may have served is kept aside. File work in a state directory
  runs as that instance's account, so root follows nothing a hostile instance planted.

**Real attachment is now testable.** `kilnd check-attachment` attaches once from the process
that runs it, and `--hold` stays attached until signaled. No daemon attaches yet, so this is
the only way to run the real proof, the unit's cgroup, account and image, against the installed
helper. A runtime `ExecStartPre=` or `ExecStart=` drop-in gives it the unit's context.

**Known limits, accepted or open:**

- **B7: template units aren't verified by staying up.** A `kilnd@` daemon stops at startup
  reconciliation until B7, then gives up under `StartLimit`, so an upgrade can't tell a broken
  one from a correct one by its state, and neither can the window's "exactly what was running".
  The upgrade relies on init-state opening its state and on its enrollment matching the
  installed image. B7 must make `settle()` require those units to stay up, as it does the
  default instance.
- **A hostile instance can refuse an upgrade** by breaking its own state, though only until
  the operator stops it, and the refusal names it. A database it fills also costs a snapshot's
  disk, and snapshots are only taken of running instances.
- **Every maintenance command stops every instance,** because the node lock is global. Adding
  an instance takes under a second of that on the test VM; an upgrade takes a few seconds more.

## B4 implementation notes (November 2, 2026)

B4 implements section 11's B4 scope: real host allocation, the patched jailer and the
release Firecracker VMM launched by retained descriptor, supervision, Stop, Remove and
scoped Gc, against a fixed guest that listens for nothing. No semantic constraint changed.
Production stays disabled: `ManifestGate::ProductionDisabled` still refuses every catalog
profile, so no installed helper serves one, and the root tests approve their catalog only
through the `cfg(test)` gate. A boot ends at BOOTING; no reply or journal phase is READY.

**New modules** (`crates/kilnd/src/helper/firecracker/`): `cgroup.rs` (the allocation tree
from the plan's recipe, joins proven by `/proc/self/cgroup`, `cgroup.kill` and removal by
pinned inode), `storage.rs` (private work directory, preallocated backing file, loop
binding, jail tmpfs, read-only binds, hardening, teardown and the absence observation),
`supervisor.rs` (S's pipeline, records and cleanup), `monitor.rs` (stop targets M holds and
K executes) and `lifecycle.rs` (H's record handling, Stop, Remove and Gc). The jailer patch
and the static tool build are in `deploy/firecracker/` and `scripts/build-phase1b-tools.sh`.

**The launch, in order.** After C2 and PREPARING, H leases one of the two node P slots to
S, opens S's gate with the verified plan, and S:

1. sets `PR_SET_CHILD_SUBREAPER`; creates `kilnd-firecracker/<I>/fc-<H>` with its
   `control`, `relay`, `vm`, `vm/vmm` and `vm/console` children and the recipe's limits,
   and journals their inodes. H registers the `vm` node with M as a stop target before
   acknowledging, so containment never waits for a VMM PID. S then joins `control`;
2. re-opens and re-hashes `Image` and `rootfs.squashfs` through the protected bundle walk,
   with heartbeats between chunks;
3. creates the private 0700 work directory, `openat(O_CREAT|O_EXCL|O_NOFOLLOW)`s the backing
   file and journals its inode, fallocates W in full and checks `st_blocks`, then runs
   `mkfs.xfs -q -f -K -m uuid=<work_uuid> <path>` by `execveat` of the retained formatter
   descriptor, comparing the inode before and after and syncing file and directory;
4. writes the KID1 identity block and the canonical `/config.json`, journals both, and
   returns the P lease;
5. journals LOOP_INTENT (slot, backing device/inode, offset 0, size limit W), then
   `LOOP_CONFIGURE`s, verifies the binding with `LOOP_GET_STATUS64` and `BLKGETSIZE64`,
   sets the slot's `discard_max_bytes` to 0 and journals the attachment. A busy slot is a
   conflict and another free slot gets its own intent;
6. creates the jail directory, journals the jail intent (a fresh nonce: tmpfs source
   `kilnd-jail-<nonce>` and marker), builds the private tmpfs (`size=16M,nr_inodes=1024,
   mode=0700`, `nosuid`) detached with its root-only marker and jail root, attaches it onto
   the jail directory and journals its mount ID, device and the tmpfs and jail-root inodes
   (revised after the break-it review, below), bind-mounts kernel, root, config, identity
   and the retained VMM inode read-only from their descriptors' `/proc/self/fd` links,
   journals the five binds' mount IDs and inodes, and creates the `/work` node;
7. journals SPAWN_INTENT, forks the gated launch child, journals J's identity and releases
   it. The child joins `vm/vmm` (proved by `/proc/self/cgroup`), unshares an empty network
   namespace, sets core limit 0, umask 077, `/dev/null` stdin and the console pipe, then
   arranges FDs 3/4 and `execveat`s the retained jailer;
8. sends the bootstrap record; at `RDY1`, reads `/proc/<J>/exe` through the pinned process,
   journals the observed tuple, checks it and J's descriptors (exactly 0–4), and sends
   `CONT`;
9. requires J's exit status 0, adopts V only if the PID file names the single task in
   `vm/vmm` and S is its parent, pins it by pidfd, journals V's identity, observed image and
   `/proc/<V>/status` credentials, and refuses on any mask, ID or descriptor difference;
10. stops V, hardens the jail, checks the mount tree and `/firecracker`, continues V and
    journals BOOTING.

Every step heartbeats, reads every queued command first and checks the original Create
deadline. Any refusal or Revoke contains the `vm` subtree before S exits; what exists
stays charged for Remove.

**Stop, Remove and Gc.** Stop journals STOP_INTENT, revokes S in memory, has K kill the
pinned `vm` node and the recorded VMM until K proves both gone and S has exited, then
journals STOPPED. Remove does that, settles J's and V's rows, journals CLEANING, starts a
journaled cleanup-only S (in `control` while the tree exists) that unmounts, detaches the
recorded loop slots, removes the jail and work directories exactly, then K removes the
empty tree and the existing fence path observes the real namespaces and commits ABSENT.
Gc runs Remove only for this instance's named allocations that are stopped or proven dead.

**Conservative readings taken:**

- **`/work` is a node, not a bind.** S `mknod`s the loop device's block node in the jail
  tmpfs, owned U:G 0600, instead of bind-mounting the host `/dev/loopN`, whose ownership
  would otherwise change host-wide. The device and its exposure are the same.
- **P's slot for session preparation.** The two node P slots are leased to S for hashing,
  fallocate, mkfs and the private files, which run in S's `control` leaf, charged to the
  allocation, while that P process takes no other job. One preparation per allocation, at
  most two across the node.
- **The console is drained by S.** D is B5's. Until then S drains the console pipe
  continuously and keeps a 64 KiB prefix; nothing reaches logs. R is B5's too: relay leases
  are claimed at C2 and unused.
- **Stop's `expected_generation`** is the allocation's C2 generation, naming the boot. Any
  other value is refused as Unknown.
- **Every Stop revokes S.** A stopped boot is never reused, so cleanup is always a fresh,
  journaled cleanup-only S. A lost S takes the same path.
- **Hardening narrows device access.** `/dev/kvm` and `/dev/urandom` stay U:G 0600;
  `/dev/net/tun` and `/dev/userfaultfd` become root 0600, since networking and restore are out
  of scope. Any unexpected entry, link or type retires the VM.
- **An unrecorded work file** (a crash between create and its record) is owned by its fixed
  name inside the root-only 0700 work directory. A recorded one must match its inode; a
  replacement is refused, not deleted. An unrecorded loop slot backed in that directory is
  refused, never guessed.
- **No CAP_SYS_PTRACE.** `/proc/<V>/exe` and `/proc/<V>/fd` are ptrace-read checks. As B3's L
  does, S takes V's filesystem IDs for those opens and restores them at once.
- **The jailer's capabilities are scoped.** The unit adds `CAP_MKNOD`, `CAP_SYS_CHROOT` and
  `CAP_SETPCAP`. L, P, M, K and every legacy kiln child drop them from their bounding,
  effective, permitted and inheritable sets at start, so only S and its J hold them.
- **The jail base is a private bind of itself.** `/var/lib/kilnd-helper/jails` is made a
  private mount at helper start, so jail mounts never propagate to another namespace. Under
  the unit's `ProtectSystem=strict` they live in the helper's own mount namespace, which a
  helper restart replaces; a restarted helper then finds no old mounts, and loop bindings,
  which are not namespaced, are still detached by identity.
- **Real observation in production too.** `ObservationBackend::Real` replaces `Disabled` in
  the production configuration: FenceAbsent for a never-admitted token now observes the real
  owned names instead of always answering Unknown.
- **Ledger schema stays 1.** New phases (`spawn_intent`, `booting`, `cleaning`) and an
  append-only `resource_events` table with B3's guard triggers. No B3 ledger has shipped; an
  earlier one fails its schema audit, closed.
- **Test seams** are `cfg(test)` only: fault markers, a ptrace exec stop that lets S read the
  short-lived formatter's `/proc` exe (production records the formatter as inferred from its
  retained descriptor instead, below), a credential perturbation, a console dump and the
  `TestDispatchProbe` operation that exposes the dispatch fence a later Exec must consult.
  The root tests' helper image is the static test binary itself, installed in the protected
  store and executed from it, so H's self-check and every fork-only worker's image are real.

**Exit tests** (`crates/kilnd/src/helper/firecracker/tests/lifecycle.rs`, run as root in the
VM by `scripts/b4-vm-tests.sh` under exactly the helper unit's bounding set; raw output in
`reviews/2026-11-02-b4-vm/`):

| B4 exit criterion | Test | Result on November 2, 2026 |
|---|---|---|
| Real teardown at every crash boundary leaves no owned VM, loop, mount, worker or file once ABSENT is reported | `b4_linux_root_every_crash_boundary_reaches_absent_with_nothing_left` (17 step boundaries, 8 effect-before-record boundaries, 18 and 9 after the break-it corrections, S killed after BOOTING, helper killed while BOOTING and during mkfs) and `b4_linux_root_create_boots_and_remove_leaves_nothing` | Passed: each boundary stayed charged until ABSENT, and an independent host check found nothing left |
| Killing S before and after J exits, with H healthy, fences at once, contains the live VMM and admits no new dispatch; J's zero exit is not V's | `b4_linux_root_supervisor_death_before_and_after_jailer_exit_fences_and_contains` | Passed: V exited 5–11 ms after SIGKILL of S; a J released only after S died was contained before any boot; V's own death fenced |
| Real UID, GID, Groups and every capability mask; a bounding-set mismatch stops the launch | `b4_linux_root_real_credentials_and_a_bounding_mismatch_stops_the_launch` | Passed for an unequal (300101/300201) and an equal (300301/300301) pair: empty Groups, all five masks zero, NoNewPrivs 1, Seccomp 2; one bounding bit refused before BOOTING |
| VMM-credential byte, inode, socket, symlink and work-resize attacks hit the mandatory bounds without consuming journal headroom | `b4_linux_root_vmm_credential_attacks_hit_the_mandatory_bounds` | Passed: 16,732,160 bytes then ENOSPC, 952 inodes then ENOSPC, no write outside `/run`, binds read-only, `/work` stayed W with BLKDISCARD and hole punching refused (also after LOOP_SET_STATUS64), W stayed allocated, ledger filesystem unchanged |
| Stalling every blocking class and exhausting the pools leaves Capabilities, Inspect and Stop progressing | `b4_linux_root_stalled_classes_and_full_pools_keep_capabilities_inspect_and_stop` | Passed: hashing, work directory, fallocate, mkfs, private-file fsync, cgroup, mount and bind stalls; both P slots full; L stalled (bounded Unknown, VM contained anyway); inventory stalled; both K slots stuck (bounded Unknown, no K replaced) |
| Stale PID and inode tests protect unrelated resources | `b4_linux_root_stale_pids_and_inodes_protect_unrelated_resources` | Passed: a live process with another start time and a replaced cgroup were untouched; a replaced work file was refused and survived; a rebound loop slot stayed bound |
| The prelaunch charge is proved | `b4_linux_root_prelaunch_charge_is_held_from_c2_through_absent` | Passed: claim before any effect, J in `vm/vmm` before it executed, the VMM's memory charged there from launch (about 400 MiB at BOOTING under the 896 MiB limit), held through STOPPED until ABSENT |
| KR-05 races as a non-root UID and the root name swap at both launch boundaries, for J, V and the formatter, against the journal | `b4_linux_root_kr05_replacement_races_run_only_the_retained_inodes` | Passed: the attacker renamed its source tree and was denied every protected ancestor; swapping the installed jailer, Firecracker and mkfs.xfs names at their boundaries left the observed device, inode and digest equal to the journal; every fork-only worker ran the installed helper image; P, M and K held no launch capability |
| Scoped GC | `b4_linux_root_scoped_gc_removes_only_proven_dead_allocations` | Passed: only the dead allocation was removed; a live one, an unknown token and another instance's were skipped |

**Known limits, accepted or open:**

- **A static production helper is B7's.** The root tests run a `crt-static` build as the
  helper image. `scripts/install.sh` still installs the dynamic helper, because static glibc
  would lose NSS-based resolution for kiln's allowlists.
- **Instance-level directories persist.** `work/<instance>` and the
  `kilnd-firecracker/<instance>` cgroup node outlive their allocations, like the instance
  itself; nothing allocation-owned remains in them after ABSENT.
- **Exec and READY are B5's.** `TestDispatchProbe` exposes the dispatch fence; the
  interrupted-dispatch case has nothing to interrupt until Exec exists.

## B4 break-it corrections (November 2, 2026)

*Amended by the B4 recheck corrections below:* the marker and reusable tuple of item 1 are
now secondary to the journaled unique mount ID, an unjournaled bind is no longer ours by its
name, item 2's tuple is joined by the disk sequence number, item 3's fallback is root-strict,
item 4's gate moved after publishing, and item 5's record waits for exit status 0. *Amended
by the B4 recheck 2 corrections:* item 2's NotOurs for another backing file now applies only
to a slot with no journaled generation.

Daybreak Blue's B4 review (`reviews/2026-11-02-b4-breakit.md`, PoCs in `reviews/poc-b4/`)
found destructive cleanup acting on replacements, a fail-open capability path, unpinned
build inputs and mislabelled formatter evidence. All five findings are accepted and fixed
in the direction the review gave; launch and containment were not changed.

**1. Jail mount identity.** The shared `kilnd-jail` tag is gone. Each allocation's tmpfs has
the journaled identity of section 7.1: S records `jail_intent` (a fresh 128-bit nonce) before
mounting, builds the tmpfs detached with `fsopen`/`fsconfig`/`fsmount`, writes the root-only
0400 marker `.kilnd-jail` and the jail root `root/` into it, and `move_mount`s it onto the
jail directory's descriptor, then makes exactly that mount private through its own
descriptor. So the tmpfs now sits at `fc-<H>` rather than at `fc-<H>/root`. The jail root is
a directory on it, still entirely inside the 16 MiB/1024-inode bound (the marker and root
directory cost two inodes and one page), and the marker is outside the VMM's chroot, so a
pre-hardening VMM cannot remove or rewrite it. The frozen contract's `"root": "tmpfs"` and
its mount data are unchanged; the bootstrap's `jail_root_identity` is the jail root
directory's statx tuple, which the patched jailer already checks. `JailMount` records
`mount_id`, `st_dev`, the tmpfs root's `st_ino` and the jail root's `root_ino`, and the
binds are journaled as `jail_binds` (name, mount ID and the bound file's device and inode).
The ledger's `resource_events.kind` accepts `jail_intent` and `jail_binds`. Cleanup
(`storage::unmount_jail`) checks the whole tree before changing anything, and again
immediately before each unmount:

- the jail directory has exactly one mount, a tmpfs with the journaled source;
- a fresh no-follow descriptor on it has that mount ID and the recorded tuple, once recorded;
- its marker is the root-only single-link file holding exactly the journaled nonce;
- every nested mount is a contract bind name directly on that tmpfs (parent ID), read-only,
  and equal to its `jail_binds` record when there is one. A bind made before its record
  is ours by name on our verified tmpfs.

Nothing mounted is nothing to do (a restarted production helper's mounts died with its
namespace). A mount with no journaled identity, another source, a missing or foreign
marker, a changed tuple or any unknown nested mount is refused and left in place, so the
allocation stays charged; ownership is never inferred from the path. A live S holds the
mounted jail directory open, so a non-lazy unmount of it fails under its owner. New
boundaries `S.step.jail_mount` (after the intent, before the mount) and `S.after.binds`
join the crash matrix, and the stall test stalls `jail_mount`, the real mount.

**2. Loop tuple.** `LoopBinding` gains `block_size` (512, set by `LOOP_CONFIGURE`).
`verify_loop` and `detach_loop` share one comparison on one opened slot descriptor:
major/minor, backing device/inode, offset, size limit, `BLKGETSIZE64` and `BLKSSZGET`.
Detach issues `LOOP_CLR_FD` on that same descriptor only for an exact match. Another backing
file stays NotOurs, as before. Our inode with any other offset, size limit or block size is
the new `LoopOutcome::Unknown`: left bound, and cleanup refuses, so the allocation stays
charged.

**3. Capability drop.** `process::drop_firecracker_launch_capabilities` returns a Result
and checks every `prctl`, `capget` and `capset`. It reads each bounding bit, drops it
(CAP_SETPCAP last), lowers the ambient bits and clears effective/permitted/inheritable, then
re-reads every set from the kernel and fails unless CAP_MKNOD, CAP_SYS_CHROOT and CAP_SETPCAP
are absent from all five. L, P, M and K call `require_firecracker_launch_capabilities_dropped`,
which `_exit(76)`s before their loop on any error. A backend child's pre-exec hook returns the
error, so the exec never happens. One conservative reading: a process without CAP_SETPCAP in
its permitted set (an unprivileged test runner) cannot drop bounding bits at all. It holds
none of the three in any other set, so it gets `PR_SET_NO_NEW_PRIVS`, verified, which keeps a
later exec from raising them. The helper runs as root with CAP_SETPCAP, so it always takes the
strict path.

**4. Build provenance.** `scripts/build-phase1b-tools.sh` takes the mkfs sysroot from
`deploy/firecracker/mkfs-sysroot.lock`: six exact arm64 debs (util-linux 2.39.3-9ubuntu6.6,
liburcu 0.14.0-3.1build1, libinih 55-1ubuntu2), each SHA-256 pinned and fetched by file
name from Launchpad's primary-archive file store. snapshot.ubuntu.com answers 401 for
`ubuntu-ports`, so it cannot serve arm64; nothing comes from `apt-get` or host package
indexes. The patch must equal `PATCH_SHA256` whatever `--patch` names, and each output must
equal `JAILER_SHA256`/`MKFS_SHA256` before it is moved into OUT. The pinned sysroot reproduces
the approved digests, so neither changed: jailer
`42e9dea3ed1b94292464c9af0286ea0eaf09934ac0b92b439fc3e76b55e8ad11`, mkfs.xfs
`9571cecc3e015742c19d1e762fb4389b15f7ff0746f52af55fd2879c96e160ab`, patch
`e54547ff520a91a25f4b292f450163f972505a383374f23b099a4f4414b0ff5d`. Compilers stay the host's
(Rust 1.97.0 from the Firecracker tree, Ubuntu noble gcc); a compiler change that alters an
output now fails the digest check instead of producing another binary.

**5. Formatter evidence.** Production no longer records the expected mkfs.xfs tuple as
`Observed`. The formatter child gets a close-on-exec report pipe. A failed `execveat` writes
its errno and the launch is refused with no evidence recorded. Only a confirmed exec (the
pipe closes unwritten) lets S send the new `SupervisorRecord::InferredFromRetainedFd`, which L
checks under the same exact-match rule. `executable_leases.observation` says how each
observed tuple is known: `proc_exe` (read from the running image: J, V, and the formatter
under the test exec stop) or `retained_fd` (inferred from the confirmed exec of the verified
descriptor), and it cannot change once set. Recovery and Gc do not consult observed tuples;
the live checks that refuse a launch are unchanged.

**Regressions.** The PoCs are now root tests run by `scripts/b4-vm-tests.sh`:
`storage::tests::b4_linux_root_cleanup_refuses_a_replacement_jail_mount` (a replacement
tmpfs with the allocation's own source, a foreign marker, no journaled identity, a foreign
nested mount and a mismatched bind record are refused and left mounted; the genuine tree is
removed), `storage::tests::b4_linux_root_detach_refuses_the_same_inode_with_another_loop_tuple`
(offset, size limit, both, and block size), and
`process::tests::b4_linux_root_worker_capability_drop_fails_closed` (seccomp-injected
`capget`, `capset` and `prctl` failures and a `capset` that claims success without acting
each exit 76 before worker code; the strict root drop clears all five sets). The real-chain
stale-resource test adds the work file rebound with another offset or size limit and a
replacement jail tmpfs carrying the allocation's own source. The create test checks the
evidence kinds, and the unprivileged `launch_capability_drop_is_verified_in_every_set` runs
in CI.

**Results (November 2, 2026, in `kiln`, raw output in `reviews/2026-11-02-b4-fixes-vm/`).**
`scripts/b4-vm-tests.sh` ran all 13 root tests: the ten exit tests above with the new
cases and boundaries, and the three new regressions. The 13 are ten lifecycle, two storage
and one process test. Twelve passed at `a1ccd10`. The capability regression first failed
on a test defect: it read `/proc/self/status`, but capability sets are per thread and
libtest runs the child case on a worker thread. It passed at `6d84364`, which reads
`/proc/thread-self/status`; the mount-replacement test was rerun there too. The kernel
again handed the replacement tmpfs the recorded tuple (`mount_id 127, st_dev 50, st_ino
1`); cleanup refused it because the marker was not there. Each injected capability
fault exited 76 before any worker code, and the strict root drop left exactly the pre-B4
set (`0x2010eb`) in every mask. After each run the cleanup check found no owned VMM,
loop, mount, cgroup or file. With `6d84364` installed, the earlier privileged suites passed
again: `integration-test.sh`, `daemon-singleton-regressions.sh`, `state-path-regressions.sh`,
`phase0-regressions.py` (the helper's set with the jailer capabilities), `smoke.sh`,
`kilnd-maintenance-tests.py`, `deployment-regressions.py` between two builds and its
`--reboot-arm graceful`/`--reboot-verify` around a real reboot. The VM was then restored
to installed main `734e275` with its schema-7 database.

## B4 recheck corrections (November 2, 2026)

*Amended by the B4 recheck 2 corrections below:* item 2's journaled generation now makes
another backing file in its slot Unknown too, and the leftover check reads the journaled slot
itself.

Daybreak Blue's recheck of `38aee62` (`reviews/2026-11-02-b4-recheck.md`, PoCs in
`reviews/poc-b4-recheck/`) broke all five corrections with adversarial variants: a copied
marker and an unjournaled bind name authorized replacement mounts, a loop retuned between
comparison and `LOOP_CLR_FD` was detached, the build published an output swapped after its
check, a formatter that died before `execveat` produced `retained_fd` evidence, and UID 0
reached the unprivileged capability fallback. All five are accepted. The lead's fault-model
decision is recorded in section 7.1 (*Teardown fault model*): identity comes from kernel IDs
never reused within a boot, plus the boot ID; root replacing a resource before cleanup is in
scope and refused; root mutating our own resource in place during teardown is out of scope.

**1. Mounts: unique mount IDs.** `JailMount` and every `BindMount` gain `boot_id` and
`unique_id` (`STATX_MNT_ID_UNIQUE`). `storage::prepare_jail` builds the tmpfs detached and
reads both IDs from the mount descriptor; S journals `jail_mount`, then
`storage::attach_jail` attaches it and requires the path to show the journaled IDs.
`storage::prepare_bind` clones each verified descriptor with `open_tree(OPEN_TREE_CLONE)`
and sets read-only/nosuid/nodev/private with `mount_setattr` while detached; S journals
`jail_binds` for all five before `storage::attach_bind` attaches any. `unmount_jail` requires
this boot's ID on every record and, on a fresh `O_PATH` no-follow descriptor immediately
before each unmount, the journaled unique ID; the reusable tuple, source and marker are
still compared, as secondary checks. A mounted bind with no journaled record is Unknown:
nothing is unmounted and the allocation stays charged. A kernel that does not report
`STATX_MNT_ID_UNIQUE` fails `mount_identity` and so refuses the launch; there is no
fallback. New crash boundaries `S.after.jail_record`, `S.after.bind_record` and
`S.after.first_bind` cover the journaled-but-not-yet-attached states.

**2. Loops: disk sequence numbers.** `ResourceRecord::Loop` becomes
`Loop { binding, generation }`, where `LoopGeneration` is the boot ID and the
`BLKGETDISKSEQ` read on the configuring descriptor. Attachment is autoclear until that
record is durable (`storage::attach_loop`, then `storage::persist_loop`), so the window
between `LOOP_CONFIGURE` and the journal leaves no unrecorded binding behind a crash; the
new boundary `S.after.loop_record` covers the window between the record and clearing
autoclear. `detach_loop(binding, generation)` compares the full tuple and then, immediately
before `LOOP_CLR_FD` on the same descriptor, the disk sequence number. A different number is
Unknown; a generation from another boot is Free without touching the slot; an intent with no
generation is never detached. On this kernel a replacement inside cleanup's window is not
even possible: with cleanup's descriptor open, another opener's `LOOP_CLR_FD` only sets
autoclear and a rebinding `LOOP_CONFIGURE` fails `EBUSY`. `LOOP_SET_STATUS64` on our own
attachment keeps its disk sequence number and is detached, as the out-of-scope case.

**3. Build publish.** `scripts/build-phase1b-tools.sh` downloads, verifies, builds and
stages in a private `mktemp -d` directory (0700, removed on exit). It hashes each staged
output, publishes it with a rename inside OUT, then hashes the published name: that
comparison is the enforced gate, and a mismatch removes the output and exits non-zero. A
final comparison of both published names replaces the old diagnostic print. The build UID
and its processes are documented as trusted. The PoC `build-output-swap.sh` became
`scripts/build-phase1b-tools-swap-check.sh`, which swaps the staged jailer after its first
hash and passes only if the build fails at the post-publish gate with no jailer left in OUT.

**4. Formatter evidence.** S records `InferredFromRetainedFd` only after `waitpid` reports
exit status 0. The report pipe's errno still refuses a failed `execveat` with its
diagnostic, but its unwritten end of file no longer counts as proof of exec: pre-exec death
or any non-zero status records no executable evidence.

**5. Capability fallback.** `drop_firecracker_launch_capabilities` decides fallback
eligibility before changing anything: real, effective and saved UIDs all non-zero
(`getresuid`), no permitted `CAP_SETPCAP`, and none of the three launch bits in the
effective, permitted, inheritable or ambient set. Anything else that cannot drop a bounding
bit, UID 0 without `CAP_SETPCAP` included, returns an error and the worker `_exit(76)`s.

**Regressions.** The PoCs are privileged regressions that must refuse:
`storage::tests::b4_linux_root_cleanup_refuses_a_copied_marker_replacement` (was
`poc_b4_recheck_spoofed_marker_unmounts_replacement`),
`storage::tests::b4_linux_root_cleanup_refuses_an_unrecorded_or_replaced_bind` (was
`poc_b4_recheck_unrecorded_bind_replacement_is_unmounted`; also a journaled bind replaced by
another inode or by a fresh bind of the same inode),
`storage::tests::b4_linux_root_detach_refuses_a_rebound_generation` (same slot, inode and
tuple rebound before cleanup: Unknown and left bound; the in-window attempt fails `EBUSY`),
`storage::tests::b4_linux_root_detach_of_a_retuned_own_generation_is_out_of_scope` (records
that an in-place `LOOP_SET_STATUS64` keeps the generation and is detached),
`storage::tests::b4_linux_root_an_unjournaled_attachment_clears_itself`,
`tests::lifecycle::b4_linux_root_formatter_death_before_exec_records_no_evidence` (was
`poc_b4_recheck_preexec_death_falsifies_retained_fd_evidence`), the `root_without_setpcap`
case of `process::tests::b4_linux_root_worker_capability_drop_fails_closed` (was
`poc_b4_recheck_root_reaches_no_new_privs_fallback`), and the kernel-behaviour test
`storage::tests::b4_linux_root_kernel_generation_ids_are_never_reused`. The real-chain
stale-resource test adds the work file rebound with the exact journaled tuple, refused on its
disk sequence number.

**Results (November 2, 2026, in `kiln` on Linux 6.8.0-147, raw output in
`reviews/2026-11-02-b4-fixes2-vm/`).** Before any code relied on them, a standalone C probe
run as root confirmed the kernel facts: across 199 replacement tmpfs mounts the reusable
`{mount_id, st_dev, st_ino}` was reused every time and the unique mount ID never; a detached
mount's unique ID was unchanged by `move_mount`; detach plus reattach of the same slot,
inode and tuple moved the disk sequence number (16 → 18); `LOOP_SET_STATUS64` left it
unchanged. `scripts/b4-vm-tests.sh` then ran all 20 root tests at `d625179` and all passed
in 1121.7 s: the 13 existing exit tests and regressions, with the crash matrix's four new
boundaries, and the seven new ones. The copied-marker replacement reused the whole tuple and
was refused on its unique ID; a bind replaced by a fresh bind of the very same inode was
refused the same way; the real-chain work file rebound with the exact tuple was refused on
its disk sequence number (114, journaled 108) and left bound and charged; inside cleanup's
window the rebinding `LOOP_CONFIGURE` failed `EBUSY`; the in-place retune kept its sequence
number and was detached; the pre-exec formatter death recorded no evidence; and
`root_without_setpcap` exited 76. The cleanup check found no owned VMM, loop, mount, cgroup
or file. The tool build reproduced both approved digests from its private directory, and
`build-phase1b-tools-swap-check.sh` passed: the swapped jailer failed the build at the
post-publish gate and was removed. With `d625179` installed, `integration-test.sh`,
`daemon-singleton-regressions.sh`, `state-path-regressions.sh`, `phase0-regressions.py`,
`smoke.sh` and `kilnd-maintenance-tests.py` passed, as did `deployment-regressions.py`
between two builds (all 69 checks) and its `--reboot-arm graceful`/`--reboot-verify` around a
real reboot of the VM. The VM was then restored to installed main `734e275` with its schema-7
database. A station restart interrupted the first
suite run (on the uncommitted fix, after its first 12 tests, crash matrix included, had
passed); the VM came back with no mount, loop or cgroup left, and the full rerun above is
the evidence.

## B4 recheck 2 corrections (November 2, 2026)

*Amended by the B4 recheck 3 corrections below:* in the sweep, an unrecorded work file, jail
or work directory, or cgroup is no longer ours by its name but Unknown; H's stop target keeps
another boot's tree, which K's proof refuses; the VMM and every worker identity carry the boot
ID; and every kill and removal goes through section 7.1's proof types.

Daybreak Blue's second recheck of `ee79331` (`reviews/2026-11-02-b4-recheck2.md`, PoC in
`reviews/poc-b4-recheck2/`) confirmed the five earlier corrections and found one in-scope
replacement that still reached ABSENT: root detaches the journaled loop and rebinds its slot
to another backing inode. `match_slot` reported `OtherBacking` before the disk sequence
number was compared, `detach_loop` mapped that to NotOurs, cleanup accepted NotOurs, and both
the leftover check and the absence observation only scanned slots backed inside the work
directory. The finding is accepted and fixed in `8afe9c5`; the sweep it asked for found two
more journaled identities a replacement could satisfy, fixed in `4ede400`.

**1. Loops: a journaled slot holding anything else is Unknown.** With a generation journaled,
`detach_loop` returns Unknown for any occupied slot that is not exactly that generation and
tuple, whatever its backing file. NotOurs remains only for an intent-only candidate slot
bound to another backing file. `storage::recorded_loop_present` reads a recorded slot by
major and minor: free or another boot's generation is absent; with this boot's generation,
any binding is present; with only an intent, only our backing inode is. Cleanup's leftover
check and `observe_presence` use it for every journaled, unreleased slot, in addition to
`loops_backed_in`; H now loads the allocation's journal in `fence_flow` and sends its loops
with `ObserveAllocation`. Because LOOP_CTL_GET_FREE hands a freed slot to the next
allocation, cleanup journals a new `loop_released` record (resource kind `loop_released`,
accepted as evidence after the stop fence) once it detaches a generation or finds it gone; a
released slot is skipped by retries and by the observation. A crash between the detach and
that record leaves the slot Unknown if anything binds it before the retry: charged, not
guessed. The crash point is `S.after.loop_detach`.

**2. Sweep.** Every outcome that cleanup, the recovery worker K and Gc (which removes through
the same Remove path) accept as success, checked for a journaled identity replaced before
cleanup:

| Resource | Accepted outcome | Replaced before cleanup | Verdict |
|---|---|---|---|
| Loop, journaled generation | Detached: exact tuple and disk sequence number | Other diskseq or tuple on our inode: Unknown | Correct (recheck 1) |
| Loop, journaled generation | NotOurs: another backing file | Accepted, ABSENT with the replacement bound | **Fixed:** Unknown |
| Loop, journaled generation | Free: slot free or `/dev/loopN` gone | Nothing bound: gone | Correct |
| Loop, generation of another boot | Free, slot untouched | Gone by definition | Correct |
| Loop, after our `LOOP_CLR_FD` | Detached when the slot is rebound with another diskseq | Ours went by this cleanup | Correct; now journaled as `loop_released` |
| Loop, intent only | NotOurs: another backing file | May be another allocation's | Kept by design; our inode is Unknown |
| Loop leftover check and observation | Only slots backed in the work directory | A foreign-backed replacement was invisible | **Fixed:** journaled slots by major/minor |
| Jail tmpfs | Nothing mounted under the jail directory | Fresh tmpfs, copied marker, another boot's record: unique ID refused | Correct (recheck 1) |
| Read-only binds | None mounted | Unjournaled or replaced bind: refused by unique ID | Correct (recheck 1) |
| cgroup `vm` node (kill) | Absent, or Empty after `cgroup.kill` by inode | Other inode: Replaced, refused | Correct within a boot |
| cgroup, record from another boot | Inode match after a reboot | Inode numbers restart: a recreated tree could match | **Fixed:** boot ID; present means Replaced |
| cgroup children (`remove_tree`) | Parent inode only | Replaced `control`/`relay`/`vm`/`vmm`/`console` removed | **Fixed:** every recorded child |
| cgroup in H's stop target | Kill by recorded `vm` inode | Another boot's inode could name a replacement | **Fixed:** left out |
| VMM process | Not running with the recorded start time | PID reuse is another process; ours is gone | Correct |
| J, S, cleanup S, formatter | Worker records probed by PID, start time and boot ID; formatter waited by S in the charged leaf | PID reuse is another process | Correct |
| Work, identity and config files | Recorded `(st_dev, st_ino)` matches | ext4 reuses the inode number: replacement deleted as ours | **Fixed:** birth time |
| Unrecorded work file, jail and work directories | Ours by fixed name in a root-only directory, empty or owned entries only | No generation was journaled | Unchanged (intent-only analogue) |
| Absence observation | No cgroup, mount, jail or work directory, or loop | Any present name blocks ABSENT | Correct; loops fixed above |

Still outside the fault model, as before: root mutating our own resource in place during
teardown (here also moving our journaled tmpfs elsewhere with `mount --move`, or swapping a
cgroup child between `remove_tree`'s inode check and its `rmdir`), and a replacement file
created with the clock set back to our file's exact birth nanosecond.

**3. cgroup and files.** `CgroupIdentity` gains `boot_id` and the `relay` and `vm/console`
inodes. `cgroup::kill_recorded` (used by `contain`) and `cgroup::remove_tree` report a tree
recorded in another boot as Replaced when anything is at its path, and `remove_tree` compares
every recorded child before removing anything. `FileIdentity` gains `btime_sec` and
`btime_nsec` from `statx`; creation, `identity_at` and `remove_work` use it, and the
preallocation and formatting checks compare the whole generation.

**Regressions.** `tests::lifecycle::b4_linux_root_cleanup_refuses_a_foreign_backing_loop_replacement`
(the PoC on the real chain: Remove refuses, the allocation stays charged, the foreign binding
survives and the observation lists the slot; after `loop_released` a later binding of the slot
is left alone and Remove reaches ABSENT; with `S.after.loop_detach` the same later binding is
refused and charged), `storage::tests::b4_linux_root_detach_refuses_a_foreign_backing_generation`
(was `poc_b4_recheck2_foreign_loop_replacement_is_accepted`, plus the intent-only and
other-boot cases), `storage::tests::b4_linux_root_cleanup_refuses_a_work_file_reusing_the_inode`
and `cgroup::tests::b4_linux_root_cgroup_cleanup_refuses_replaced_nodes_and_other_boots`. The
stale-resource test's foreign-rebinding case, which expected ABSENT, moved into the first.

**Results (November 2, 2026, in `kiln` on Linux 6.8.0-147, raw output in
`reviews/2026-11-02-b4-fixes3-vm/`).** `scripts/b4-vm-tests.sh` ran all 24 root tests at
`4ede400` and all passed in 1167.8 s: the 20 earlier exit tests and regressions, the crash
matrix included, and the four new ones. The journaled slot rebound to a foreign inode
(disk sequence number 58, journaled 56) was refused, stayed charged and stayed bound, and the
absence observation listed it; after `loop_released`, the same slot bound again was left alone
and Remove reached ABSENT; with the crash before that record, the later binding was refused
and charged. At storage level the foreign rebinding was Unknown and present, an intent-only
slot kept NotOurs and another boot's generation was Free. ext4 gave the recreated work file
the deleted file's inode number (607456) on the first try, and the differing birth time
refused it; a replaced cgroup child and another boot's record were refused and left in place.
The cleanup check found no owned VMM, loop, mount, cgroup or file. With `4ede400` installed,
`integration-test.sh`, `daemon-singleton-regressions.sh`, `state-path-regressions.sh`,
`phase0-regressions.py`, `smoke.sh` and `kilnd-maintenance-tests.py` passed, as did
`deployment-regressions.py` between two builds and its `--reboot-arm graceful` and
`--reboot-verify` around a real reboot of the VM. Installing `4ede400` migrated the VM's dev
database from schema 7 to 10, and no schema-7 copy had been taken first. The schema-7 database
was rebuilt from it with `734e275`'s own schema: its `sandboxes` and `executions` columns are
a subset of schema 10's, and the 7-to-8 migration copies them unchanged. All 128 rows from
before this run and their 375 executions were kept, the 10 sandboxes this run's suites created
were left out, and `history_sequence` went back to 272. The schema-10 file is kept, root-only, at
`/root/kilnd-db-backups/` in the VM. `734e275` was reinstalled (`kilnd` SHA-256 `c39c3f3b…`);
`quick_check` passed, health as the `kilnd` account served, and the legacy ambiguous failure's
64 MiB/128 PID/16 MiB charge was still held.

## B4 recheck 3 corrections (November 2, 2026)

Daybreak Blue's third recheck of `eead82c` (`reviews/2026-11-02-b4-recheck3.md`, PoCs in
`reviews/poc-b4-recheck3/`) found three more destructive paths that acted before identity
was proved: a replaced `vm/vmm` child killed through its unchanged `vm` parent, cgroups and
work files created before their identity record and then deleted by deterministic name (also
reachable through Remove's stale pre-fence snapshot), and process stop targets that signalled
from PID and start time alone, with no boot ID. All three are accepted. Four rounds had each
found another such path, so the lead decided to stop patching sites and make this a single
invariant enforced by the type system. It is recorded in section 7.1 (*The
destructive-action invariant*), with the inventory of every destructive call in the helper.

**1. Proof types.** `helper/firecracker/proven.rs` is the only place the helper signals,
writes `cgroup.kill`, removes a cgroup, directory or file, unmounts or clears a loop. Each
action takes a proof that only that module's verification function can make, from the
journaled identity, the current boot ID and the live kernel object. `Unprovable` is `Gone`
(provably nothing of ours: nothing at the name, an exited process, a free slot, another
boot's record with nothing there), `Replaced` (something else holds the name; never touched)
or `Unknown` (no journaled generation, a missing or invalid boot ID, unreadable evidence;
never touched, stays charged). `storage::detach_loop`, `unmount_jail`, `remove_jail_dirs`,
`remove_work`, `cgroup::kill_recorded`, `remove_tree`, `monitor::execute` and S's own
signals now reach the kernel only through it. `cgroup::kill_node`, `CgroupTarget`,
`workers::kill_target` and `supervisor::pidfd_signal` are gone. S's formatter, its own
unreaped child, is signalled through `UnreapedChild`, which only `proven::fork_child`
makes and which never signals a reaped PID.

**2. Boot ID everywhere.** `ProcessId` gains `boot_id` (a validated `BootId`, serialized as
the kernel prints it). S identifies J and V with this boot's ID, L journals a child's
identity with the boot ID S read and refuses one without it, and `RecordWorker` and
`RecordInfrastructure` fail when the host boot ID is unreadable: `host_boot_id()` returns
an error, never `unknown`. Recovery builds each worker row's identity with its stored boot
ID; a missing or malformed one (an older row) parses to none. `RecoveryRequest::Probe` drops
its separate `boot_id` field. `proven::prove_process` opens the pidfd, then compares the
start time and the boot ID: no match is Gone; a match from another boot is Gone; a match
with no boot ID, or with the host's unreadable, is Unknown. So K's emergency stop and the VM
worker's recovery kill never signal such a process; it stays an orphan, charged, until it is
provably gone.

**3. The cgroup tree.** M's, H's and K's cgroup targets are `CgroupStopTarget`: the
allocation path and its journaled `CgroupIdentity`, or none while only the intent is
journaled. `ProvenCgroupVm` checks the boot ID and the parent's, `vm`'s, `vm/vmm`'s and
`vm/console`'s inodes and that `vm` has no other child and its leaves none, and
`kill_cgroup_vm` re-lists the children through the `vm` descriptor immediately before it
writes `cgroup.kill` there. A replacement is `NodeState::Replaced` with no signal; a tree with
no journaled generation is the new `NodeState::Unknown`. K counts only Absent or Empty as
gone. `ProvenCgroupTree` admits nothing below the parent but the five journaled nodes, and
`remove_cgroup_tree` re-reads each inode through its parent's descriptor before its `rmdir`.
A Stop whose target has only a cgroup intent and finds a tree there answers Unknown at once
instead of retrying to its deadline.

**4. No identity-free deletion.** New resource kinds `intent`, `work_dir` and `jail_dir`.
S journals `intent` before the cgroup tree, the work directory, the work file, the private
files and the jail directory; `work_dir` and `jail_dir` (the directory's device, inode and
birth time) right after each `mkdir`, before anything else is created in or on it. The work,
identity and config files are created unlinked with `O_TMPFILE`, journaled, then linked with
`linkat` through `/proc/self/fd` (no `CAP_DAC_READ_SEARCH` needed) and checked at their name,
so a crash before the record leaves no name at all; S also checks the private files it opens
for the binds are the journaled generations. Cleanup's `contain` and K's `remove_tree` with
no journaled identity return Unknown for anything present, and `remove_jail_dirs` and
`remove_work` require a `ProvenDir` and a `ProvenFile` for every entry before deleting
anything; an absent intent-only object is fine. New crash boundaries:
`S.after.cgroup_intent`, `S.after.work_link`, `S.after.private_link` (nothing left, ABSENT),
and `S.after.work_dir` and `S.after.jail_dir` (an unjournaled directory). With
`S.after.cgroup`, the latter two now leave an object that is never ours by its name: Remove
refuses, keeps the charge and leaves it in place until the operator removes it.

**5. Stale snapshot.** `remove_inner` reloads the allocation's complete journal after the
stop fence and S's settlement and builds cleanup's `RecordedResources` and K's cgroup removal
from it, so a record S committed between Remove's first read and the fence is honoured.

**6. Completeness.** The inventory in section 7.1 lists every destructive call in
`crates/kilnd/src/helper/` and the proof each takes. The three allow-listed exceptions are
the executable store's own temporary name and two signal-0 liveness probes.
`proven::tests::no_destructive_call_outside_the_gate` scans every helper source outside the
test fixtures and fails on any such call outside `proven.rs` or the allow-list; it runs in CI.

**Regressions.** The four PoCs are regressions that must refuse and leave the replacement
untouched: `cgroup::tests::b4_linux_root_a_replaced_vm_child_is_never_killed` (was
`poc_b4_recheck3_replaced_vmm_child_is_killed`; also an unexpected `vm/extra` child),
`cgroup::tests::b4_linux_root_an_unrecorded_cgroup_is_unknown_and_left` (was
`poc_b4_recheck3_unrecorded_cgroup_replacement_is_removed`),
`storage::tests::b4_linux_root_unrecorded_work_files_and_directories_are_unknown` (was
`poc_b4_recheck3_unrecorded_work_replacement_is_removed`; also an unrecorded work directory
and an unpublished unlinked file) and the unprivileged CI test
`proven::tests::a_process_target_without_this_boot_is_never_signaled` (was
`poc_b4_recheck3_process_stop_target_has_no_boot_identity`; a missing boot ID is Unknown and
unsignalled, another boot's is gone and unsignalled, this boot's is stopped). The stale
snapshot regression is
`tests::lifecycle::b4_linux_root_remove_honours_a_record_committed_before_the_fence`: S
stalls after creating its work directory, Remove reads the journal and is held, S journals
the directory and dies, and Remove reaches ABSENT with nothing left. The crash matrix covers
the new boundaries above.

**Results (November 2, 2026, in `kiln` on Linux 6.8.0-147, raw output in
`reviews/2026-11-02-b4-fixes4-vm/`).** The tool build reproduced both approved digests.
`scripts/b4-vm-tests.sh` ran all 28 root tests and all passed in 1243.0 s: the 24 earlier
exit tests and regressions, the crash matrix with its new boundaries included, and the four
new ones. That run was at the pre-commit tree of `26c2583`, which differs only in one
evidence message of `b4_linux_root_a_replaced_vm_child_is_never_killed`; that test passed
again at `26c2583`. The replaced `vm/vmm` (inode 24114, journaled 24132) and an unexpected
`vm/extra` child were Replaced with no `cgroup.kill`, and their processes survived. An
unrecorded tree, work file (ext4 generation `(64769, 786706, 1793668403, 326573925)`) and
work directory were Unknown and left in place. In the crash matrix, `S.after.cgroup`,
`S.after.work_dir` and `S.after.jail_dir` each left their object; Remove refused it
(PermitsUnsettled for the tree, ResourcesPresent for the directories) and kept the charge,
and after the operator removed the object Remove reached ABSENT. Every other boundary,
`S.after.work_file` and the new link boundaries included, reached ABSENT with nothing left.
The stale-snapshot regression reached ABSENT; with the post-fence reload removed it failed
on `the work directory is not proven ours: ... no generation was journaled`, so the reload is
what it proves. The cleanup check found no owned VMM, loop, mount, cgroup or file. With
`26c2583` installed, `integration-test.sh`, `daemon-singleton-regressions.sh`,
`state-path-regressions.sh`, `phase0-regressions.py`, `smoke.sh` and
`kilnd-maintenance-tests.py` passed, as did `deployment-regressions.py` between two builds
(all 69 checks) and its `--reboot-arm graceful` and `--reboot-verify` around a real reboot of
the VM. Before any B4 build was installed, `kilnd` was stopped and `/var/lib/kilnd/` was
copied byte-for-byte to a root-only backup (`kilnd.db` SHA-256 `aec74dc4…`, schema 7). After
the suites, that copy was restored and compared byte-for-byte (`cmp`), and main `734e275`
was reinstalled (`kilnd` SHA-256 `c39c3f3b…`, `kilnd-helper` `ccb2946f…`, `kilndctl`
`850f5392…`). Its database is schema 7 with `quick_check` ok, and health as the `kilnd`
account reports serving.

## B4 recheck 4 corrections (November 2, 2026)

Daybreak Blue's fourth recheck of `d268d8d` (`reviews/2026-11-02-b4-recheck4.md`, PoCs in
`reviews/poc-b4-recheck4/`) confirmed the three recheck-3 fixes and found two gaps in the
gate itself. Both are accepted.

**1. The executable store published and unlinked through a fixed temporary name (HIGH).**
`publish_object` created `.<role>.tmp` with `O_EXCL` and checked the copy through its
descriptor, but then called `linkat` and `unlinkat` by name, so a root replacement of that
name was published under the approved role name and its temporary link deleted. Now the copy
has no name until it is published: it is an `O_TMPFILE` inode in the root-only digest
directory, copied, hashed, made 0555 and fsynced through its one descriptor, and that exact
descriptor is linked with `linkat(AT_FDCWD, "/proc/self/fd/N", directory, role,
AT_SYMLINK_FOLLOW)`. The magic link resolves to the open file, not to a name. The name is then
re-read without following, and its device, inode and birth time must be the held
descriptor's; `verify_object` must also pass for that inode. A mismatch is an error that
leaves everything in place. `linkat` never replaces, so a collision on the approved name
fails closed with its occupant untouched. There is no `unlinkat` on any path: an unpublished
copy dies with its descriptor. The executable exception is gone from the section 7.1
inventory. The `linkat` form was chosen by measurement. On the VM's 6.8.0-147,
`linkat(fd, "", dir, name, AT_EMPTY_PATH)` fails `ENOENT` under the helper's bounding set
(`deploy/kilnd-helper.service` has no `CAP_DAC_READ_SEARCH`) and as an unprivileged user,
and succeeds only as full root; the `/proc/self/fd` form succeeds in all three
(`reviews/2026-11-02-b4-fixes5/vm/linkat-probe.log`). It is the form `storage::publish`
already used. macOS has no `O_TMPFILE`. There, a test-only `publish_object` checks the
bytes in memory, then creates the approved name with `O_EXCL`; it is not compiled into
production. Production is Linux. The other writers were audited (section 7.1): none
publishes or cleans up through a fixed temporary name.

**2. The gate was lexical (MEDIUM).** A destructive call through a local alias
(`let raw_kill = libc::kill;`) passed the substring scan, and the real `cgroup.kill` write
went through the generic `cgroup::write_control`. Now:

- *Proof-typed `cgroup.kill`.* The only `cgroup.kill` write is the private
  `proven::write_cgroup_kill`, reached only from `kill_cgroup_vm(&ProvenCgroupVm)`.
  `cgroup::write_control` is private to `cgroup.rs` and takes a `ControlFile` enum
  (`cgroup.subtree_control`, `cgroup.procs` and the five limit files) with no `cgroup.kill`
  variant. `cgroup::open_at` is now `open_dir`, which opens only directories, so no sibling
  can open a control file for writing. A recipe naming `cgroup.kill` is refused.
- *Clippy is the enforcement.* `clippy.toml` disallows every raw signal, removal, rename,
  unmount, `ioctl`, `syscall` and subprocess capability (section 7.1 lists them). Clippy
  resolves paths, so it catches a function value, a `use ... as` alias or a function-pointer
  constant as well as a call. The PoC fails clippy on 1.88 and 1.99, so no `syn` pass was
  needed. CI runs clippy with `-D warnings -D clippy::disallowed_methods` on both toolchains.
- *Typed wrappers.* The new `crate::sys` holds every remaining non-destructive use of
  `libc::syscall` and `libc::ioctl`, one fixed request per function, moved from
  `executable.rs`, `peer.rs`, `supervisor.rs`, `storage.rs`, `workers.rs` and `process.rs`.
  `pidfd_alive` takes no signal number. `move_mount` and `mount_setattr` accept only a
  `DetachedMount`, which only `fsmount` and `open_tree_clone` make. The loop wrappers cannot
  detach or reconfigure a bound slot.
- *Approved modules and their check.* Only `proven.rs`, `sys.rs`, `process::run`,
  `kiln_process::{probe, OwnedExec::spawn, OwnedExec::kill_reap}`,
  `SocketPathGuard::cleanup` and `remove_stale_socket_after_probe` carry an allow. Each has
  an `// Approved (design 7.1):` justification. Test modules and test-only files also carry
  one. `proven::tests::disallowed_allows_only_in_approved_modules` fails on any other
  allow or expect of the lint, its group (`clippy::style`, `clippy::all`) or `warnings`, and
  on a missing justification, a `[lints]` table, a `.cargo/config` or a weakened
  `clippy.toml`. `proven::tests::no_foreign_declarations_or_inline_assembly` closes the routes
  clippy cannot resolve: a local `extern` block, inline assembly, `#[link]` and `dlsym`.
  `kilnd-api` dropped its blanket `allow(clippy::all)`.
- *The lexical test* stays as defense in depth. It now squashes comments and whitespace
  and removes each allowed whole expression before matching, so an allowed fragment cannot
  hide another call on the same line. Its needles catch the alias form, `rename`,
  subprocesses, `start_kill` and raw `syscall`/`ioctl`. It covers the helper and `sys.rs`.

**Regressions.** `executable::tests::executable_publish_has_no_temporary_name_to_replace`
(unprivileged, in CI) and `b4_linux_root_executable_publish_has_no_temporary_name_to_replace`
(root, the production policy from `/`, the real store, the helper's bounding set) replace
the PoC. While the copy is blocked on a pipe, with its unnamed descriptor open, they plant
`.jailer.tmp`, `.jailer.tmp.0`, `jailer.tmp` and `#0`: `publish_object` succeeds, `jailer`
has exactly the original bytes with one link and mode 0555, and every planted name keeps the
replacement's bytes. Planting the approved name itself is refused, with the occupant
untouched. Replacing the name between the link and its re-read fails `not the held copy` and
leaves the replacement. `cgroup::tests::the_control_writer_cannot_name_cgroup_kill` covers the
enum. The gate evidence is in `reviews/2026-11-02-b4-fixes5/gate/`. With
`guard-bypass.patch` applied, clippy fails on 1.88 and 1.99, for macOS and for
`aarch64-unknown-linux-gnu`, and so does the lexical test (`guard-bypass-poc.log`).
`gate-variants.log` runs nine bypasses. Clippy stops the alias, the `use` rename, the
function-pointer constant, the raw `syscall` and the subprocess. The compiler stops
`cgroup.kill` through `write_control`, which is private and needs a `ControlFile`. The
approval test stops an unapproved allow and a `clippy::style` silencer. The foreign-declaration
test stops the local `extern` block.

**Results (November 2, 2026, `1ddd0aa`, raw output in `reviews/2026-11-02-b4-fixes5/`).**
On the Mac: `cargo test --locked --workspace` passed (1.88; the kilnd library 474 passed,
2 ignored), and clippy with `-D warnings` was clean on 1.88 and 1.99, both for macOS and
checked for `aarch64-unknown-linux-gnu`. CI passed (`41568827854`), including the new 1.99
clippy step. In `kiln` on Linux 6.8.0-147, the approved jailer and mkfs.xfs digests matched.
`scripts/b4-vm-tests.sh` ran all 29 root tests, the 28 earlier ones and
`b4_linux_root_executable_publish_has_no_temporary_name_to_replace`, and all passed in
1254.4 s, with nothing owned left. The unprivileged workspace suite passed on Linux (the
kilnd library 482 passed, 45 ignored). The shell's umask was 002, and two `b3f_01`
init-state tests correctly refuse a group-writable temporary ancestor, so the run used
umask 022. Native Linux clippy passed on 1.88 and 1.99 and failed on both with the PoC
applied (`gate/linux-native-clippy.log`). With `1ddd0aa` installed,
`integration-test.sh`, `daemon-singleton-regressions.sh`, `state-path-regressions.sh`,
`phase0-regressions.py`, `smoke.sh` and `kilnd-maintenance-tests.py` passed. So did
`deployment-regressions.py` between two builds (69 checks), and its `--reboot-arm graceful`
and `--reboot-verify` around a real reboot. Before any B4 build, `kilnd` was stopped and
`/var/lib/kilnd/` was copied byte for byte (`kilnd.db` SHA-256 `aec74dc4…`). After the
suites, main `734e275` was reinstalled (`kilnd` `c39c3f3b…`, `kilnd-helper` `ccb2946f…`,
`kilndctl` `850f5392…`), and the copy was restored and compared with `cmp`: identical.
Schema 7, `quick_check` ok, and health as `kilnd` reports serving, with the legacy
reservation still held. The empty B4 ledger directory the reboot run left under
`/var/lib/kilnd-helper` was removed. No test account, loop beyond kiln's own, mount,
cgroup, process or build output remains.

## B4 recheck 5 corrections (November 2, 2026)

Daybreak Blue's fifth recheck of `572284e` (`reviews/2026-11-02-b4-recheck5.md`, PoCs in
`reviews/poc-b4-recheck5/`) confirmed the recheck-4 executable fix and found three
destructive-boundary failures. All three are accepted. The lead added two scope statements,
now in section 7.1's *Teardown fault model*: the helper's own mount namespace, `/proc` view,
memory and descriptors are part of the trusted computing base, yet no proof may rely on a
`/proc` pathname; and the compile-time gate guards against honest developer mistakes, not
malicious source changes, with cheap checks for build scripts and generated includes.

**1. A shadowed `/proc/self/fd` made the cgroup proof kill a replacement (HIGH).**
`child_cgroups` listed a proven node by reading `/proc/self/fd/N`. Root bind-mounted a view
of empty directories there, so the final `check_vm_subtree` saw no replaced `vm/vmm`, and
`cgroup.kill` through the real `vm` descriptor killed the replacement's process. Now every
listing a proof or the hardening walk depends on is fd-native: `sys::read_dir_fd` calls
`getdents64` on an `F_DUPFD_CLOEXEC` duplicate of the retained descriptor, rewound to the
start (`proven::child_cgroups`, `storage::list`, `cgroup::allocation_names`). An entry whose
type the filesystem does not report counts as a child. `proven::unmount` no longer calls
`umount2` on `/proc/self/fd/<parent>/<name>`: on a short-lived thread with its own
filesystem context, it `fchdir`s to the held parent descriptor, re-reads the unique mount ID
at the single name and unmounts that name, which section 7.1 explains as the narrowest form
Linux 6.8 allows. The jail tmpfs's private propagation is set with `mount_setattr` on its own
descriptor. The sweep table in section 7.1 lists every `/proc/self/fd` use: only the two
publish `linkat` calls remain, because their post-link generation recheck already rejects a
redirected link. Under the lead's defense-in-depth rule, the remaining `/proc` pathname
reads (process start times, the boot ID, the VMM's status and descriptor table, the mount
table, cgroup membership, peers' process directories, the running image) moved beneath
`sys::procfs`, a private procfs instance that no mount can shadow.

**2. Socket cleanup deleted a live replacement after inode reuse (MEDIUM).**
`remove_stale_socket_after_probe` and `SocketPathGuard::cleanup` compared only device and
inode, and ext4 handed a deleted stale socket's inode number to a live replacement. Now
`sys::socket` identifies a socket by its generation (`SocketGeneration`, made only by
`socket_generation_at`): device, inode, `statx` birth time and, on Linux, the inode's file
handle from `name_to_handle_at`, all read without following through the retained
socket-directory descriptor. `remove_socket_generation` reads it again that way immediately
before `unlinkat(dir, name, 0)`. The file handle was added after the first VM run of the
regression failed (`reviews/2026-11-02-b4-fixes6/vm/b4-root-suite-ee85790.log`): inode
timestamps come from the coarse clock, so on ext4 a socket unlinked and replaced within one
tick got the same device, inode and birth time, and the cleanup unlinked the replacement.
The handle carries the inode generation number that ext4, XFS and tmpfs draw for every
allocation; in the passing runs the birth time was equal in four of six reuses and the
handle alone refused them. A filesystem that cannot export handles leaves the birth time
as the only extra field; kilnd's socket directories are on tmpfs or ext4. A different generation is left in place and
reported as changed. The bound socket's generation is recorded through the descriptor right
after `bind`. `server.rs` no longer carries an approved allow. The final read-to-unlink
interval is the decided narrow window; inode reuse before it is not.

**3. The gate admitted destructive safe wrappers (MEDIUM).** Three changes make the
destructive APIs narrow and private:

- *Opaque loop status.* `LoopInfo64`'s fields are private and only `loop_status` makes one;
  callers read `backing_device`, `backing_inode`, `offset`, `size_limit` and `autoclear`.
  There is no `LOOP_SET_STATUS64` that takes a caller's structure. The one status change,
  `loop_clear_autoclear(&ConfiguredLoop)`, takes the value `loop_configure_autoclear`
  returns for this process's own slot (it now owns the configuring descriptor), reads
  `LOOP_GET_STATUS64` itself on that descriptor, requires the configured backing device and
  inode, offset 0, size limit, autoclear set and the configured disk sequence number before
  and after that read, and changes only the flag. Two `compile_fail` doctests on Linux keep
  the PoC's forged status from being edited or submitted, with a passing control doctest.
- *Fixed tools.* `process::run` takes a `process::Tool`; the only production variant is
  `Tool::Kiln { bin: &KilnBinary, args: &KilnArgs }`. `KilnBinary::verified` checks, at
  every launch, an absolute path to a regular executable owned by root or this user and not
  group- or world-writable. `KilnArgs` has private contents and typed constructors
  (`capabilities`, `ls`, `rm`, scoped `gc`, `gc --help`, `create`) that validate sandbox IDs.
  `kiln_process::probe` and `OwnedExec::spawn` take the same types. The jailer, Firecracker
  and mkfs.xfs never went through `run`: S starts them with `execveat` of retained, verified
  descriptors.
- *A wider clippy list.* `clippy.toml` adds `File::set_len`, `File::create`,
  `OpenOptions::truncate` and `fs::write` (std and tokio), `libc::truncate`, `ftruncate`,
  `fallocate`, `fallocate64`, `posix_fallocate`, `prctl`, `ptrace`, `process_vm_writev`,
  `process_vm_readv` and `pidfd_getfd`. Neither `rustix` nor `nix` is a direct dependency.
  The legitimate uses became typed `sys` functions (`preallocate`, mode 0 only;
  `write_sysfs(SysfsControl::LoopDiscardOff)`; one `sys::prctl` function per fixed request;
  `ptrace_traceme`), `UnreapedChild::detach_trace`, one approved item
  (`ExclusiveFileLock::finish_acquire`'s own lock-file truncation) and `cfg(test)` items.
  The approval test now accepts an allow on any `#[cfg(test)]` item, not only a module
  named `tests`. Two new tests reject unapproved build scripts and generated includes, and
  `/proc/` or `cgroup.` string literals outside `sys.rs`, `cgroup.rs` and `proven.rs`
  (section 7.1).

**Regressions.** Each PoC is now a test that must refuse:

- `cgroup::tests::b4_linux_root_a_shadowed_proc_fd_view_cannot_hide_a_replaced_child`
  (root): `procfd-cgroup-proof-bypass.patch` with the view in place. The kill and the removal
  are Replaced, `vm_empty` is false, and the replacement's process survives.
- `storage::tests::b4_linux_root_a_shadowed_proc_fd_view_cannot_redirect_an_unmount` (root):
  every fake descriptor entry links to a victim directory holding another tmpfs at the same
  name, so the old `/proc/self/fd/<parent>/<name>` would have named the victim. The proven
  tmpfs is unmounted; the victim stays mounted.
- `server::tests::b4_linux_root_stale_socket_inode_reuse_is_refused` (root suite, ext4
  `/var/tmp`): `socket-inode-reuse.patch`. The stale-socket cleanup refuses the inode-reused
  live replacement, which keeps its name and accepts connections; the bound-socket guard
  leaves an inode-reused replacement at shutdown.
- `typed-ioctl-occupied-loop.patch` and `unchecked-wrappers.patch` no longer compile or pass
  clippy (`reviews/2026-11-02-b4-fixes6/gate/gate-pocs.log`, replayed by
  `run-gate-pocs.sh`). `typed-ioctl-occupied-loop.patch` no longer applies because `sys.rs`
  changed; its added module, appended verbatim, fails with four errors (private
  `lo_sizelimit` three times, and `loop_clear_autoclear` takes one `&ConfiguredLoop`).
  `unchecked-wrappers.patch` applies: macOS clippy rejects `File::set_len` (the Linux-only
  loop call is compiled out there), Linux-target clippy rejects the loop call with `E0061`,
  and, with the loop half removed, rejects `File::set_len`. `generated-include-bypass.patch`
  applies; as saved, its `build.rs` writes literal `\n` escapes that do not compile, and
  with those un-escaped `no_unapproved_build_scripts_or_generated_includes` fails on the
  build script, the `include!` and `OUT_DIR`.

**A related residual, not changed here.** `FileIdentity` (work, identity and config files and
the work and jail directories) is device, inode and birth time, so the same coarse-clock limit
applies: a replacement created within one clock tick of the journaled object's creation would
match. For that, the original inode must already be free in that tick, and S holds it open
from creation (`O_TMPFILE`, or the directory descriptor `private_dir` returns) until well
after its generation is journaled, so S would have to die within the tick and root win the
race. Adding the file handle to `FileIdentity` is a journal-schema change, left for the lead
to decide.

**Results (November 3, 2026, code `ee85790` and `09de7ab`, raw output in
`reviews/2026-11-02-b4-fixes6/`).** On the Mac: `cargo test --locked --workspace` passed on
1.88 (the kilnd library 477 passed, 2 ignored), `git diff --check` was clean, and clippy with
`-D warnings -D clippy::disallowed_methods` was clean on 1.88 and 1.99, for macOS and checked
for `aarch64-unknown-linux-gnu`. CI passed on both commits (`41579553683`, `41582288910`).
`gate/gate-pocs.log` is the gate evidence above. In `kiln` on Linux 6.8.0-147, the
Firecracker v1.17.0 archive matched its pinned digest and the rebuilt jailer and mkfs.xfs
matched theirs. `scripts/b4-vm-tests.sh` at `ee85790` passed 31 of 32 root tests: the new
socket regression failed on a same-tick birth time, which led to the file handle above. At
`09de7ab` all 32 passed in 1307.7 s (the 29 earlier ones and the three new ones), with
nothing owned left, and the socket regression passed three more runs on its own. The
unprivileged workspace suite passed on Linux (the kilnd library 485 passed, 48 ignored; the
two `compile_fail` doctests and their control passed) after a first attempt whose `rustc`
the 4 GiB VM's out-of-memory killer stopped; the rerun used two build jobs. Native Linux
clippy passed on 1.88 and 1.99. With `09de7ab` installed, `integration-test.sh`,
`daemon-singleton-regressions.sh`, `state-path-regressions.sh`, `phase0-regressions.py`,
`smoke.sh` and `kilnd-maintenance-tests.py` passed, and so did `deployment-regressions.py`
between two builds (69 checks) and its `--reboot-arm graceful` and `--reboot-verify` around a
real reboot. Before any B4 build, `kilnd` and the helper socket were stopped and
`/var/lib/kilnd/` was copied byte for byte (`kilnd.db` SHA-256 `aec74dc4…`). Afterwards main
`734e275` was reinstalled (`kilnd` `c39c3f3b…`, `kilnd-helper` `ccb2946f…`, `kilndctl`
`850f5392…`, the pre-test hashes), and the copy was restored and compared with `cmp`:
identical. Schema 7, `quick_check` ok, and health as `kilnd` reports serving with zero active
sandboxes. The empty B4 ledger directory the reboot run left under `/var/lib/kilnd-helper`
was removed. No test account, loop beyond kiln's own, mount, cgroup, process or build output
remains; the mounted checkout is back on main `b58d94a` and the VM is stopped.

## B5 implementation notes (November 3, 2026)

B5 is built in two milestones on `phase1b/b5-broker`. Milestone 1 is the direct-kiln core
extraction and the broker protocol codec; milestone 2 is the guest broker, the host relay,
console drainer, Validate and Exec, and the kiln-guest image. Milestone 2's notes, decisions
and exit evidence follow milestone 1's.

### The kilnd-exec-core move

`crates/kilnd-exec-core` holds kilnd's reviewed direct-kiln process, status, capture and
validation code, moved unchanged so the guest broker can reuse it instead of reimplementing
kiln's machine protocol (section 5.1). It has no gRPC, SQLite, helper server or receipt
types; its dependencies are `libc`, `serde`, `thiserror`, `tokio` and `tokio-util`.

*How it stays a move.* The new crate mirrors kilnd's module paths (`process`, `validation`,
`model`, `sys`, `runtime::{kiln_direct, kiln_process, kiln_protocol}`), so every moved item
keeps its `crate::` and `super::` references and every moved test keeps its name: the
workspace lists the same 541 tests (and the same 11 ignored ones) before and after, by full
path. kilnd re-exports each moved item from its old path (`kilnd::process`, `kilnd::model`,
`kilnd::runtime`, `kilnd::sys`, `crate::validation`), so the B2 and B4 interfaces, the
`Runtime` trait's signatures and every kilnd caller are unchanged. `DirectKilnRuntime` stays
in kilnd with its fields, constructors and `Runtime` impl; its moved inherent methods
delegate to the core through a borrowed view, `DirectKiln::new(&bin, &cgroup_root)`. The
methods that return kilnd-only types stay in kilnd: `create_until` and `create_result`
(`CreateFailure`, whose absence receipts are helper types), `remove_until` and `gc_until`.
kilnd's adapter tests are byte-for-byte unchanged; two `cfg(test)` fixture helpers they
import from the moved modules (`kiln_process::tests::fixture`, `kiln_protocol::tests::exit125`
and `hex`) are copied into kilnd's shim modules, because one crate's tests cannot reach
another's `cfg(test)` items.

`scripts/b5-move-audit.py` proves it mechanically against the B4 base `415d850`: it finds
each moved item in its new file and compares the two token by token, allowing only the named
rewrites below; it fails if any line deleted from a partly moved kilnd file is not part of a
moved item, an import or the delegating body; and it fails if a listed rewrite is unused.

| Old path (`crates/`) | New path (`crates/`) | Moved items |
|---|---|---|
| `kilnd/src/model.rs` | `kilnd-exec-core/src/model.rs` | `SandboxSpec`, `Network`, `SandboxDisposition`, `SandboxDisposition` impl, `CleanupEvidence`, `CleanupEvidence` impl, `Captured`, `Captured` impl, `CommandStatus`, `CommandStatus` impl, `RuntimeErrorKind`, `RuntimeStage`, `RuntimeDiagnostic`, `RuntimeDiagnostic` impl |
| `kilnd/src/sys.rs` | `kilnd-exec-core/src/sys.rs` | `sys_ret`, `CapHeader`, `CapData`, `capget`, `capset`, `cap_ambient_is_set`, `cap_ambient_lower`, `capbset_read`, `capbset_drop`, `set_no_new_privs`, `get_no_new_privs`, `set_parent_death_kill` |
| `kilnd/src/runtime/mod.rs` | `kilnd-exec-core/src/runtime/mod.rs` | `RuntimeError`, `ExecSpec`, `ExecFinish`, `ExecOutcome`, `legacy_exec_evidence`, `BackendStatus`, `BackendSandbox` |
| `kilnd/src/runtime/kiln_direct.rs` | `kilnd-exec-core/src/runtime/kiln_direct.rs` | `CLI_REQUIREMENT`, `SANDBOX_REQUIREMENT`, `CONTROL_OUTPUT`, `QUERY_TIMEOUT`, `CLEANUP_TIMEOUT`, `CLEANUP_POLL`, `call_until`, `run_control`, `capabilities`, `require_scoped_gc`, `list_until`, `wait_exec_cleanup`, `exec_direct`, `validate_sandbox`, `create_args`, `parse_ls`, `valid_kiln_id`, `check_id`, `exec_populated`, `decode_status`, `summarize` |
| `kilnd/src/process.rs` | `kilnd-exec-core/src/process.rs` | whole file: `SAFE_PATH`, `FIRECRACKER_LAUNCH_CAPABILITIES`, `drop_firecracker_launch_capabilities`, `require_firecracker_launch_capabilities_dropped`, `LAUNCH_CAPABILITY_EXIT`, `prepare_child`, `DRAIN_GRACE`, `SpawnGuard`, `spawn_guard`, `Finish`, `Outcome`, `CaptureCompletion`, `CaptureState`, `CaptureTask`, `KilnBinary`, `KilnArgs`, `kiln_id`, `Tool`, `Request`, `run`, `drain_captures`, `spawn_capture`, `capture` and its tests |
| `kilnd/src/validation.rs` | `kilnd-exec-core/src/validation.rs` | whole file: the `MAX_*` bounds, `validate_image_name`, `validate_allowlist_entry`, `validate_writable_path`, `validate_argv` and its tests |
| `kilnd/src/runtime/kiln_process.rs` | `kilnd-exec-core/src/runtime/kiln_process.rs` | whole file: `FRAME_TIMEOUT`, `SETTLEMENT_TIMEOUT`, `CLI_LIMIT`, `StreamState`, `StatusState`, `Stop`, `RawResult`, `ProbeResult`, `probe`, `OwnedExec`, `locked`, `catch_poll`, `pair`, `above_stdio`, `spawn_capture`, `capture`, `read_status` and its tests |
| `kilnd/src/runtime/kiln_protocol.rs` | `kilnd-exec-core/src/runtime/kiln_protocol.rs` | whole file: `MAX_FRAME`, `HEADER`, `FEATURE_CREATE_CERTAINTY`, `Cleanup`, `Outcome`, `Capabilities`, `u16_at`, `u32_at`, `i32_at`, `payload`, `outcome`, `capabilities` and its tests |

*The rewrites.* Crossing a crate boundary needs visibility, and nothing else changed:
`pub(crate)` became `pub` on `legacy_exec_evidence`, `valid_kiln_id`, `list_until`,
`exec_direct`, `require_firecracker_launch_capabilities_dropped`, `CaptureCompletion` and
`Outcome`'s two completion fields; `pub` was added to `check_id`, `exec_populated`,
`decode_status`, `summarize`, `CONTROL_OUTPUT`, `QUERY_TIMEOUT`, `call_until`, `run_control`,
`capabilities`, `wait_exec_cleanup` and `validate_sandbox` (the last was the `Runtime` impl's
body and is now the core's inherent method, which the impl calls); `&self.bin` became
`self.bin` three times, because the view already holds a reference; and `catch_poll` narrowed
from `pub` to `pub(crate)`, because in a now-public module clippy's `result_unit_err` would
reject exporting its `Result<_, ()>`. `sys_ret`, a five-line private helper, is in both
`sys` modules. One test-name string, `runtime::kiln_process::tests::owned_exec_recovers_descriptors_in_a_dedicated_child`,
is unchanged because the module path is.

*The gate.* The moved subprocess runner (`process::run`), kiln probe and exec owner
(`kiln_process::probe`, `OwnedExec::spawn`, `OwnedExec::kill_reap`) carry their approved allows
with them; `disallowed_allows_only_in_approved_modules` now names each approved item by crate
and file. The child setup's capability and `prctl` wrappers moved with `prepare_child`, which
issues them between fork and exec, into the core's own typed `sys` module. That is the one new
allow-list entry: a relocation of part of kilnd's approved `sys.rs`, not a new capability (the
section 7.1 table names it). `no_destructive_call_outside_the_gate` scans it with kilnd's
`sys.rs` rule (raw wrappers allowed, no destructive call), and the approved `exec/cgroup.events`
literal moved with `wait_exec_cleanup`. `scripts/b4-vm-tests.sh` now also runs the core's
library tests under the same root bounding set, since the moved
`process::tests::b4_linux_root_worker_capability_drop_fails_closed` lives there.

### Broker protocol version 1: kilnd-broker-protocol

`crates/kilnd-broker-protocol` is the strict codec of sections 5.2 and 5.3, with no `unsafe`
code (`#![forbid(unsafe_code)]`) and no I/O below its `stream` module. It depends on the core
crate for argv and writable-path validation, kiln's ID grammar and the typed runtime kinds and
stages. It is not `no_std`: tokio streams and serde JSON are the point of using it.

*Public API.* `header` (`Header::parse`/`encode`, `Kind`, `Direction`, the 36-byte `KGB1`
layout), `json` (`check`, `from_slice`, `to_vec`), `types` (`Id128`, `Hex32`, `SandboxId`,
`ExecutionId`, `BootId`, `WorkUuid`, `InnerId`, `WireText`), `message` (the sixteen messages,
`Message::decode`/`encode_payload`/`validate`, `GuestExecSpec::canonical_json`/`sha256`),
`frame` (`Frame`, `Sequence`, `encode_frame`, `FrameDecoder`), `budget` (`Budget`,
`ExecBudget`, `ExchangeBudget`, `HostBudget`), `exchange` (`HostConnection`,
`GuestConnection`) and `stream` (`FrameReader`, `FrameWriter`, `Due`). Every failure is a
`ProtocolError` variant: bad magic, unsupported version, unknown flags or kind, wrong
direction, payload over its kind's bound, premature EOF in the header or payload, sequence
mismatch or overflow, foreign request ID, unexpected kind, EOF before the terminal frame,
trailing bytes, duplicate terminal, empty data where bytes were due, non-UTF-8, JSON syntax,
depth, float and duplicate key, schema, field bound, invalid field, each cumulative budget,
stdin length, capture mismatch, a stage timeout (first byte, frame, EOF, write) and transport
I/O.

*Decisions made here, within section 5:*

- **One operation per connection.** `Hello` names its channel (`exec` or `control`); a control
  connection then carries exactly one `Initialize`, `Probe` or `Cancel` and its reply, and an
  exec connection one execution, ending with the guest's `Result` and write EOF. Each
  connection has a fresh challenge, its own sequence numbers from zero in each direction and
  its own non-exec 64 KiB/16-frame budget; the at-most-two-connections rule bounds them.
- **Order on an exec connection:** `Exec` (request ID = token), `Accepted`, the declared stdin
  in non-empty `Stdin` frames, one `StdinEnd {token, total}`; after the command settles,
  contiguous `Stdout` frames, then contiguous `Stderr` frames, then `Result`, then EOF. No
  output may precede `StdinEnd`. An `Error` is terminal anywhere; it is never success or
  absence. The host checks the `Result`'s kept lengths against the bytes actually received and
  the negotiated `max_output`.
- **Bounds checked from the header, before the body:** per frame, host-to-guest control
  384 KiB (the encoded bound, so argv within 256 KiB that escapes past it is refused at
  encode), guest-to-host control 64 KiB, data 64 KiB. Per execution, guest to host across both
  channels: 128 frames, retained stdout and stderr up to their negotiated limits (at most
  1 MiB each), other control payload 64 KiB combined, and
  `stdout + stderr + 64 KiB + 128 × 36` wire bytes. Per non-exec exchange: 16 frames and
  64 KiB. Host to guest on one connection: 1027 frames (`Hello`, `Exec`, 1024 `Stdin`,
  `StdinEnd`) and 1 MiB of stdin. A refused frame charges nothing and its body is never read.
- **Memory.** The decoder reads only the bytes the current header or payload still needs, so
  it never reads into the next frame, and grows its payload buffer only as bytes arrive. It
  holds at most a header plus the part of one checked payload received so far.
- **Strict JSON** is a full grammar pass before serde: UTF-8, integers only (`-0` refused too),
  objects and arrays nested at most 8 deep (the top-level object is depth 1), duplicate keys
  refused at every level after unescaping, lone surrogates and raw control characters refused,
  nothing after the value. Serde then maps it onto `deny_unknown_fields` types. kilnd's lenient
  `CommandStatus` shape is not used on the wire: `Termination` is its strict twin, with exit
  codes 0 to 255 and signals 1 to 64.
- **Field shapes.** IDs, challenges, nonces and digests are exact lowercase hex; sandbox and
  execution IDs are kilnd's `sb-`/`ex-` shapes; the boot ID a canonical lowercase UUID; the
  work UUID a canonical UUIDv4 (as B1 derives it); the inner ID kiln's grammar; wire
  diagnostics at most 2048 bytes. `Exec` reuses kilnd's `validate_argv` with a 256 KiB bound
  and adds stdin at most 1 MiB, `max_output` at most 1 MiB and `remaining_ms` in
  1..=3,600,000. `Initialize` carries the label-free `GuestExecSpec`, validated as B1's
  `validate_guest_exec_spec`; its canonical JSON digest matches B1's fixture
  (`24efdf3f…`, from `identity.bin`).
- **`HelloReply`** reports the vdc identity (all eight fields), the guest boot ID, the broker's
  build digest, kiln's protocol and feature bits, `/init`'s seven runtime-hardening results
  as named booleans (`cmdline`, `kernel_log_bounded`, `kaslr`, `memory_initialization`,
  `kstack_offset`, `lockdown_confidentiality`, `kexec_absent`), the work mount's UUID and
  `nosuid`/`nodev`/`noexec`/`prjquota` flags, the broker state and the inner ID if
  initialized. `Error` carries a code (`protocol`, `admission`, `incompatible`, `internal`)
  and the broker state.
- **Deadlines** are absolute instants. `Due::By` requires a whole frame by an instant;
  `Due::FirstByte` waits for the first byte until the execution deadline and then requires the
  frame within two seconds of that byte, and the caller holds every later frame and the EOF to
  the same instant, so a result transfer settles within two seconds of its start. Trickled
  bytes never move a deadline. Every write has a deadline too.

*Tests (milestone 1).* 62 in the protocol crate, all unprivileged:

- `tests/codec.rs` (41): one test per rejection: golden header bytes, bad magic (checked
  first), every unsupported version, unknown flags and kinds, every kind travelling the wrong
  way, each kind's payload bound at the limit and one past it, JSON depth (arrays, objects and
  a 100,000-deep input refused before serde), floats and `-0`, duplicate keys at every level and
  after unescaping, syntax, UTF-8, unknown, missing and mistyped fields (including inside a
  struct variant), bounded schema messages, every `Exec` bound on decode and encode, argv that
  passes 256 KiB but escapes past 384 KiB, ID shapes, wire-text narrowing, capture facts and
  termination bounds, protocol version, B1 spec validation and digest, a frame round trip of
  every message, sequence gaps, duplicates and overflow, oversized lengths allocating nothing,
  the budget charged before any payload byte, premature EOF in header and payload, each
  budget's limits, and every exchange rule on both sides (unsolicited and misaddressed
  replies, stale challenges, wrong reply kinds, cancel tokens, host send order, output order,
  totals, output after `Result`, a second `Result`, foreign tokens, stdin under- and overshoot,
  empty stdin frames, EOF before the terminal frame).
- `tests/property.rs` (8), from fixed seeds with an xorshift generator: random messages of
  every kind round-trip through random chunkings; truncation at every header byte and at
  random payload points is `PrematureEof` with the right part and counts; 10,000 oversized
  lengths are refused from the header with nothing allocated; duplicated frames break the
  sequence; 20,000 mutated headers fail typed; arbitrary bytes never panic and the decoder's
  memory stays bounded; mutated JSON never panics, and whatever still decodes is valid and
  re-encodes to itself; maximal nesting and string payloads stay bounded.
- `tests/adversary.rs` (13), over tokio duplex pipes on a paused clock, so every deadline is
  exact: no first byte (`Timeout(FirstByte)` at 2 s); a first byte only and a 100 ms trickle
  (`Timeout(Frame)` at 2 s, holding only a header); a 10 s wait then a trickle (2 s after the
  first byte); never-reading peers on both sides (`Timeout(Write)` at 2 s); endless empty
  valid frames (refused at frame 129, having read only headers); endless full 64 KiB frames
  (refused at the 1 MiB stdout limit with the refused frame's body unread); one execution
  budget spanning the exec and control channels; cumulative wire and control bytes; endless
  unsolicited replies (refused at the first); trailing bytes, a missing EOF and EOF mid-frame;
  a blocked output writer not delaying the control channel's `CancelAck`; and a healthy
  exec exchange (Hello, Exec, stdin, a 5 s command, output, Result, EOF) finishing exactly on
  time while three hostile connections beside it fail at their own bounds.

*Checks.* `cargo test --locked --workspace`, clippy with `-D warnings -D
clippy::disallowed_methods` on 1.88 and 1.99 for macOS and checked for
`aarch64-unknown-linux-gnu`, `git diff --check`, `kilnd-maintenance-tests.py` and
`scripts/b5-move-audit.py`.

### Milestone 1 break-it findings folded in

Daybreak accepted milestone 1 at `bd3f228` with no HIGH findings
(`reviews/2026-11-03-b5m1-breakit.md`) and three non-blockers, fixed in `4cd1ce6`, before every
milestone 2 exit run, each with a regression test:

- *MEDIUM, the execution budget across channels.* `SharedBudget<B>` is an `Rc<RefCell<B>>`
  borrowed only inside the synchronous `admit`, never across a read or any other await, and
  R keys it by execution token so a Cancel charges its execution. No async lock guards any
  budget. Test (`adversary.rs`): with the exec peer stalled mid-frame on the shared budget,
  the control channel's `CancelAck` is admitted at once, and both count against one budget.
- *LOW, duplicate-key checking.* An ordered set per object (the sorted-keys approach, n log n)
  replaces the quadratic scan. Test (`property.rs`): about 30,000 distinct shortest keys in
  384 KiB check in under 200 ms. Daybreak's own benchmark at the branch head: 3 ms at
  384 KiB, from 704 ms.
- *LOW, retry after timeout.* Any timeout, codec or I/O error poisons a `FrameReader` or
  `FrameWriter`: every later call returns the stored error, and every caller closes the
  connection. Test (`adversary.rs`): a read retried after a timeout, with the rest of the
  frame now available, still fails, as do a later EOF read and a write after a write
  timeout. Daybreak's retry harness now fails where it expected success, and its
  2,000,000-case decoder harness still finds no panic.

### The guest broker: kilnd-guest-broker

One binary, `/usr/local/bin/kilnd-guest-broker`, statically linked for the guest, with four
modules:

- `main.rs` (Linux only) reads `/init`'s bootstrap record from fd 3 to EOF: the 4096-byte
  `KID1` identity block, `KGH1` and the seven-bit runtime-hardening mask
  (`identity::parse_bootstrap`; the identity record must be canonical JSON, byte for byte).
  It reads the boot ID, hashes its own executable, reads the work disk's XFS superblock UUID
  from `/dev/vdb` and the work mount's flags and `prjquota` from `/proc/self/mountinfo`,
  probes kiln, then listens on AF_VSOCK port 5252 with a backlog of 4. The accept loop drops
  any peer whose CID is not 2 and any connection beyond two open ones, before reading a
  byte. Everything runs on one current-thread runtime in a `LocalSet`.
- `session.rs` is the state machine, Uninitialized → Initializing → Idle → Executing →
  Draining → Idle, with Faulted terminal; every transition is a method, so the transport
  cannot skip one. The session starts Faulted if any hardening bit is missing or the kiln
  probe failed. `Initialize` runs once: an identical repeat after success replays the same
  `Ready`; anything else, and any failure or uncertainty during initialization, faults the
  session, so a second inner sandbox is never created. `Cancel` names the active token and
  only cancels; it is acknowledged at once.
- `kiln.rs` drives only `/usr/local/bin/kiln`, through `kilnd-exec-core`'s reviewed
  `DirectKiln` (section 5.1): capabilities, `run_control(KilnArgs::create)` for the one
  persistent sandbox (no network, no labels), `valid_kiln_id`, `validate_sandbox`, then a
  smoke `true` that must finish Completed, exit 0 and leave `RuntimeDrained` evidence.
  Each execution is the core's `exec_direct`, so argv is the core's typed array with the
  caller's argv only after `--`. `result_of` turns only the core's own evidence into the
  wire `Result`.
- `server.rs` serves one operation per connection: `Hello` within two seconds of accept,
  then a control `Initialize`, `Probe` or `Cancel`, or one execution. At most one exec and
  one control connection are open at once, and they never share a writer, so `Cancel` never
  waits on the output writer. Stdin must arrive within `min(2 s, remaining)`; output goes in
  64 KiB chunks, then `Result` and EOF within two seconds. Any failure on an exec
  connection after `Accepted` faults the session.

The vdc reader is the only new codec shared with `/init`: `identity.rs` in the protocol
crate parses the block strictly (magic, length, canonical JSON, zero padding) and is tested
against B1's `identity.bin` fixture.

### Host side: the relay R, the console drainer D, Validate and Exec

S forks two more fork-only workers right after BOOTING, through the same
`proven::fork_child` as its formatter, and journals each as a `Child` record immediately:

- **R, the broker relay** (`helper/firecracker/broker.rs`), in the allocation's `relay`
  cgroup leaf, under the allocation's journaled relay UID/GID with no groups, no
  capabilities and `no_new_privs`, all three verified by `capget` after the drop. It keeps
  only a control stream and a descriptor socket to S. Per job, S connects to the exact
  recorded jail's `run/vsock.sock` as root: it walks `root` then `run` by descriptor,
  requires a socket owned by the VMM UID, connects from a scoped thread that unshared its
  filesystem context and `fchdir`ed into the held `run` directory, requires `SO_PEERCRED`
  to be the journaled VMM PID and UID, and then rechecks the socket's identity. S hands
  that connection (and for an execution the three helper-side stdio sockets) to R over
  `SCM_RIGHTS`. R does every guest-facing byte: `CONNECT 5252\n`, the `OK <port>\n` reply
  (at most 32 bytes within two seconds), Hello, the request and its budgets, stdin and
  output. It reads each connection through a token bucket (4 MiB/s after a 256 KiB burst,
  at most 64 KiB per read) within the same absolute deadlines. Its reports to S are
  bounded typed values.
- **D, the console drainer** (`helper/firecracker/console.rs`), in `vm/console` under the
  VMM's UID/GID, reads the console pipe to EOF in 64 KiB quanta, keeps the first 64 KiB and
  checked counters and discards the rest, so a full pipe never blocks the VMM. A token
  bucket (1 MiB/s, 256 KiB burst) reports a breach once (`R`), as does a counter overflow
  (`O`); S then retires the VM, and D keeps draining under its CPU cap.

S's order after the fork is: signals and parent-death checks, join the leaf by its
journaled cgroup inode, close every other descriptor, then drop credentials. (Joining
needs S's procfs descriptor, so it comes before the sweep.) Either worker's death, a
malformed or unexpected report, or a console breach ends S's steady loop and retires the
VM through the existing containment. When S ends, it closes both workers' sockets, waits
one second, then kills any still unreaped with `UnreapedChild::kill_unreaped` (section 7.1).

*Readiness.* S checks that the plan's label-free inner spec matches the journaled binding
digest, then has R send Hello and `Initialize` within the original Create deadline. Hello
must match the journaled identity, work UUID and mount flags, report every hardening bit
and not be Faulted. While the guest is still booting, the VMM answers `CONNECT` without
`OK`; only that (`Unreachable`, before any broker byte) is retried, every 50 ms. On
`Ready`, S journals a `broker` resource record (boot ID and inner ID), then `booting →
ready`, and tells H. Inspect then answers `present_ready {generation, boot_id, inner_id}`,
and List reports `ready`.

*Validate* answers `busy {token}` from the recorded state during an execution, without
touching the guest. Otherwise it requires the journaled boot and inner IDs, sends `Probe`
on a fresh control connection, and answers `ready` only for an idle broker on that boot
and inner sandbox with no active token. Any other answer, or a refusal or failure, retires
the VM; a missing answer within the deadline is `unknown`, never absence. (Since the B5
break-it corrections, a local relay refusal is `unknown` without retirement, the probe
holds the allocation's control slot until R reports, and a late breach still retires.)

*Exec* (`helper/firecracker/exec.rs`) marks the allocation busy in memory, then journals an
`exec` resource record (`intent`, with the token, execution ID and boot ID) and `ready →
exec_intent` before any byte can reach the guest. It hands the three stdio sockets to S,
which passes them to R with the vsock connection. R reads the declared stdin from kilnd
first (a failure there is `Local`, journaled `undispatched`, and the VM goes back to
`ready`; a guest protocol violation before dispatch retires it, section 5.5), then sends
`Exec`; on `Accepted` H journals `busy` and `exec_intent →
busy`. R holds the output until the `Result` is validated against it, then writes it to
kilnd within two seconds. Only a validated, delivered result with the guest's drain
evidence journals `idle` and returns to `ready` with `reusable: true`. Every other ending
after dispatch (the deadline, the caller's disconnect, a Stop, S's exit, V's death, a
protocol, transport or cleanup failure, a guest timeout or cancel) is an interruption: a
`Cancel` on a fresh control connection, two seconds to settle, then the existing stop fence
and K's kill of the `vm` subtree. The reply is `reusable: false`, and `vm_stopped` once K
has proved the subtree gone (H waits at most five seconds for that proof). The work runs on
its own task, so the caller's disconnect cannot drop it, and H polls every 50 ms for the
session ending under it.

*Journal.* The phase CHECK gains `ready`, `exec_intent` and `busy`, all three stoppable;
`resource_events` gains the `broker`, `exec` and (B5-01) `exec_history` kinds, which
recovery's `absorb` ignores (the VM itself is the resource); section 7.4 gives their
retention. The ledger keeps schema 1, as the B4 notes allow.

### Decisions made in milestone 2

- **One fresh vsock connection per operation**, matching milestone 1's one operation per
  connection: Initialize, each Probe, each Cancel and each Exec. The guest's
  two-connection cap is exactly one exec plus one control.
- **Read pacing is per connection.** Section 5.6's 4 MiB/s with a 256 KiB burst applies to
  each guest connection's read half separately, so exec output can never delay its
  Cancel's reply; with at most one exec and one control connection, R reads at most 8 MiB/s.
  A full execution's largest legal output (2 MiB of retained output plus control and
  headers) takes under half a second at that rate, inside the two-second result
  settlement. Each read takes at most 64 KiB, and the frame reader checks the deadline and
  cumulative budgets on every frame.
- **R is per allocation, not per job.** It is forked once after BOOTING and lives until S
  ends, so a job costs a connection, not a fork. Its budgets are keyed by execution token,
  so the exec connection and a Cancel share one `SharedBudget<ExecBudget>`.
- **R runs tokio after a fork.** tokio keeps a process-global signal pipe, created by H's
  runtime; the fork and descriptor sweep close it, but each new I/O driver duplicates its
  stale number and drains whatever that number names. R never handles a signal, so it moves
  its two sockets to the top 16 numbers under `min(soft limit, 1024)`, fills every free
  number below with one end of an inert socket pair while it builds a current-thread
  runtime, then closes the fill and keeps the inert peer open (an EOF would read as a
  broken signal pipe). The fork also copies H's thread-local "inside a runtime" marker, so
  the runtime runs on a fresh thread of R's own. The plain `relay_main` (no fill) serves
  tests running in a multithreaded test process.
- **`/init` supervises the broker and never restarts it.** It starts the broker as guest
  root after mounting the work disk, in a new session, with a cleared environment
  (`PATH=/usr/local/bin:/usr/bin:/usr/sbin`), `RLIMIT_CORE` 0, `RLIMIT_NOFILE` 256,
  `no_new_privs`, not dumpable, its working directory a fresh 0700 `/run/kilnd-broker`, and
  only the bootstrap pipe on fd 3. Its exit powers the VM off.
- **The pinned image.** kiln-guest's `config/pins.json` names the kilnd commit, the SHA-256
  of that commit's `git archive` (`kilnd_source_sha256`, carried into `build-lock.json`)
  and the expected broker digest and size. The build refuses an archive, lock or broker that
  does not match, unless `--allow-unpinned-broker`, which marks the bundle
  `diagnostic_only`. The manifest's provenance records the archive digest, `Cargo.lock`,
  the workspace manifest, every source file of the three crates the broker builds from
  (`kilnd-guest-broker`, `kilnd-broker-protocol`, `kilnd-exec-core`), and the exact cargo and
  compiler. The broker is built offline from vendored crates in the same verified
  toolchain as kiln, and installed at `/usr/local/bin/kilnd-guest-broker` beside
  `/usr/local/bin/kiln`.

### Exit evidence

All root evidence is from the `kiln` Lima VM (Ubuntu, kernel 6.8.0-147, 4 vCPUs, 4 GiB),
Firecracker 1.17.0 through the patched jailer, with the pinned production bundle (kiln-guest
`74f3a89`, the broker built from kilnd `fb9034d`). The B5 root suite's final run is at
`7d117af` (R's read pacing; an earlier run at `c2fc1f6`, before pacing, also passed). The
B4 and installed suites ran at `95ab9bf`; the only later host change is that pacing, which
the B5 suite covers. Logs are in `reviews/2026-11-03-b5-vm/`.

| B5 exit criterion | Evidence |
|---|---|
| Framing, cumulative wire-byte, frame-count, first-byte and never-read adversaries, including endless valid frames and trickle timing | The protocol crate's 66 tests (codec 42, property 9, adversary 15) on macOS and Linux. In the VM, under the hostile run below: a relay fed endless valid frames had 96 jobs each refused at its bound, and a silent never-reading peer had 3 jobs each ended at its two-second deadline |
| Three concurrent hostile transport and console sources leave memory flat; a healthy fourth meets its deadlines | `b5_linux_root_hostile_sources_…`: two hostile relays (endless frames, silent peer) and a 64 KiB-write console flood, each in its own capped cgroup under its own UID, beside a READY allocation doing five rounds of Inspect, Validate and Exec, then Remove. Worst cases: Inspect 3.19 ms (5 s budget), Validate 13.92 ms (5 s), Exec 55.31 ms (60 s), Remove (its stop barrier included) 118.5 ms (60 s). Hostile cgroup memory before/after: [401,408, 258,048, 151,552] → [397,312, 258,048, 151,552] bytes; helper RSS 19,656 → 20,292 KiB |
| Each offender retires | Every hostile relay job ended `Failed` at its bound; the flood was reported once (`R`), which `breach()` maps to retirement. In real VMs, killing R or D retires the VM (`b5_linux_root_a_dead_relay_or_drainer_retires_the_vm`). A real guest console flood is not exercised: the production guest has no console writer a test can drive |
| The console drains after its retained prefix | 307,625,984 bytes drained during the healthy run, after the first 64 KiB, with the flooder never blocked; one `R` report |
| Relay and console CPU charged outside H | Hostile CPU (µs) in their own cgroups: [105,445, 2,678, 104,929] → [372,802, 4,704, 378,113]. Real allocation: relay leaf 60,211 µs, `vm/console` 5,105 µs over the whole persistent-exec test (12,933 µs in the run before pacing; the increase is not yet profiled) |
| Actual persistent exec | `b5_linux_root_ready_and_persistent_execution`: READY with the journaled boot and inner IDs; Validate refuses another boot; a file one execution writes, the next reads; 1 MiB of every byte value round-trips; 3,000,000 bytes of output keep 1 MiB, total 3,000,000, truncated; exits 0, 1, 124–127 and 143 are `Exited(n)` and reusable; `kill -TERM $$` is `Signaled(15)`; a missing executable is `LaunchFailed` and reusable; stderr is separate |
| Actual cancel and kill | `b5_linux_root_timeout_cancel_and_kill_retire_the_vm`: a deadline is `TimedOut` after 3.04 s, `VmStopped`, `reusable: false`; the caller's disconnect empties the VM subtree; a Stop during an execution is `Failed(Unavailable)`, interrupted, `VmStopped` |
| Two clean-worktree builds match | kiln-guest `verify.py`: `reproducible: true`; every bundle file byte-identical (below) |
| Full guest integration | kiln-guest `tests/firecracker.py` through the jailer on the pinned bundle: the fixed test-mode suite offline and with test-only networking, every security and runtime assertion present, egress passed, installed binaries unchanged. The production boot's integration is the B5 root suite itself: the real identity drive, vsock device, broker Hello and Initialize, persistent exec, cancel and kill. A scan of the unpacked rootfs (103 files) finds no key, token or user path; Alpine's stock `/etc/shadow` has every account locked. Nothing in the image carries a credential |
| Two warmups and twenty cold boots | `b5_linux_root_boot_timings`, below |
| Legacy privileged suites | `scripts/b4-vm-tests.sh b4_linux_root` at `95ab9bf`: 31 passed (and the core's 1). Its first run at `c2fc1f6` failed one test only because a healthy neighbour now reaches READY (`PresentReady`) where it asserted `PresentBusy`; `95ab9bf` accepts both. Installed at `95ab9bf`: `install.sh`, `integration-test.sh` (with the dedicated-child admission FD/RSS, slow-client, queue and concurrent-Health stress regression), the singleton, state-path and Phase 0 regressions, `smoke.sh` and the maintenance tests all pass. `deployment-regressions.py` was not needed: B5 changes no install, upgrade or maintenance script or unit |

*Reproducible bundle* (kiln-guest `74f3a89`, both builds):

| Artifact | Bytes | SHA-256 |
|---|---|---|
| `Image` | 17,807,872 | `0015f87e136b314a164b30f5255a1589144a3937db0dce00d5eef6c0fdbf2e6a` |
| `kernel.config` | 95,549 | `f07a7ffd291f4ad821e3f4f0f2e0ab1928d3024103f3c74d71e541765cc2d4e9` |
| `kiln` | 2,376,016 | `54442ccc0ce12b9a9236c927b9073019d7d4774c2e2d82f4d55d0db491925c64` |
| `kilnd-guest-broker` | 2,245,008 | `d4eb4cacc428ce8887a396456456bcb00e2ad5c912eb3fce5393c907962a4f2d` |
| `rootfs.squashfs` | 8,396,800 | `9e1f4f750d2de73e0fc1645e735e5debaeff54207b4b4038ff18ab3a24ded1c4` |
| `manifest.json` | | `91e9291605cc5e0f895882e4b600ac48b7ca549c2e7b7b5ab6c9d976076995bf` |

*Boot timings* (2 warmups, then 20 measured cold boots, each a fresh Create of a new
allocation; milliseconds from the Create call):

| | min | p50 | p95 | max |
|---|---|---|---|---|
| BOOTING journaled | 12,751 | 12,804 | 12,849 | 12,866 |
| READY journaled | 13,221 | 13,265 | 13,288 | 13,297 |
| BOOTING → READY | 429 | 455 | 480 | 497 |
| First tool result (`true`, after READY) | 13 | 23 | 37 | 37 |

(The `c2fc1f6` run, before pacing: READY p50 13,778 ms, p95 14,512 ms; BOOTING → READY p50
456 ms.)

The guest and broker take under half a second from BOOTING to a smoke-tested inner
sandbox. The roughly 13 s before BOOTING is B4's host path in this nested VM (the work
disk, jail, jailer and VMM launch and adoption), which B5 does not change and these runs
do not break down; B7 owns that profile.

## B5 break-it corrections (November 3, 2026)

Daybreak's B5 break-it review (`reviews/2026-11-03-b5-breakit.md`, kilnd `38aefb4`,
kiln-guest `74f3a89`) found three HIGH, six MEDIUM and one LOW defect. Stephen's rule
governs every fix: any post-dispatch timeout, cancel or uncertainty terminates the VM,
and a guest that breaks the session protocol is not reusable. The attacks that held
(framing and budgets, retirement on timeout, disconnect, Stop and worker death, the
console drain, relay pacing, the terminal Faulted state, `/init`'s supervision, the
destructive-action gate, provenance) are unchanged and rerun below.

- **B5-01, unbounded execution history (HIGH).** Section 7.4: settled `exec` rows fold
  into one `exec_history` summary in the settling transaction, stop reasons and settled
  cleanup workers are capped, and L answers an oversized reply with `oversized` and a
  health fault instead of exiting. Tests: `journal::tests::b5_01_execution_history_never_grows_the_allocation_state`
  (100,000 executions; the state's frame stays about 400 bytes; Stop and Remove reach
  ABSENT), `journal::tests::b5_01_stop_reasons_and_cleanup_workers_are_bounded`,
  `workers::tests::b5_01_an_oversized_ledger_answer_is_refused_and_l_stays_up`, and in the
  VM `b5_linux_root_three_thousand_executions_keep_the_ledger_bounded`.
- **B5-02, a stalled BUSY write blocked containment (HIGH).** Section 5.5's
  containment-always-polled rule. `exec.rs` is now written against a `Host` trait so its
  decisions run against a scripted relay and ledger. Tests:
  `exec::tests::b5_02_a_stalled_busy_write_never_blocks_cancellation` (BUSY stalls
  forever; cancel, deadline expiry and the session ending each retire the VM within
  Cancel's two seconds), `b5_02_a_busy_write_past_its_bound_retires_the_vm`,
  `b5_02_an_unanswered_exec_intent_retires_without_dispatch`. The audit also bounds
  Remove's Inspect, CLEANING and cleanup-worker intent by the wire deadline. S's own
  journal records (Create's path) keep their existing acknowledgement protocol.
- **B5-03, a timed-out partial frame was delivered later (HIGH).** Section 5.6's
  all-or-nothing frames. Tests: `workers::tests::b5_03_a_timed_out_partial_frame_is_never_delivered_later`
  (Daybreak's `endpoint_resume`: frame 101 never arrives), the rewritten
  `a_given_up_write_never_tears_the_frame_stream`, `an_oversized_frame_is_refused_without_poisoning`,
  and `exec::tests::b5_03_an_uncertain_dispatch_failure_retires_the_vm`.
- **B5-04, stale health (MEDIUM).** Section 5.3's Probe health. Tests: the guest
  broker's `server::tests::b5_04_probe_reports_a_dead_inner_sandbox_as_faulted`, and in
  the VM `b5_linux_root_a_killed_inner_sandbox_is_never_ready` with the kill-inner test
  guest (`scripts/b5-test-guest.sh`, Daybreak's wrapper).
- **B5-05, concurrent Validate and Exec (MEDIUM).** Section 5.6's control slot and the
  `control_busy` Validate answer. Test: `exec::tests::b5_05_control_operations_are_serialized_per_allocation`.
- **B5-06, Result's inner ID (MEDIUM).** Test: `exec::tests::b5_06_a_result_for_another_inner_sandbox_retires_the_vm`.
- **B5-07, pre-dispatch violations restored READY (MEDIUM).** Section 5.5's
  pre-dispatch split; `RelayReport::Failed` and `Refused` carry `reach` instead of
  `dispatched`. Tests: `exec::tests::b5_07_pre_dispatch_guest_violations_retire_and_local_failures_do_not`,
  and the relay's `readiness_needs_the_journaled_identity_and_full_hardening` and
  `short_stdin_fails_before_any_exec_byte` (now `Guest` and `Local`).
- **B5-08, capture metadata (MEDIUM).** Without a validated Result both captures are
  `known: false`; when forwarding to kilnd stops part way, R reports the bytes each
  socket took and H reports them, truncated. Tests: `exec::tests::b5_08_capture_evidence_is_never_fabricated`
  and the relay's `b5_08_a_partial_delivery_reports_the_bytes_delivered`.
- **B5-09, Validate forgot a late failure (MEDIUM).** Section 5.6: the probe keeps its
  waiter and the control slot until R reports. Test: `exec::tests::b5_09_a_late_probe_failure_is_still_recorded`.
- **B5-10, digest and feature bits (LOW).** Section 5.3's identity checks. Test: the
  relay's `readiness_needs_the_journaled_identity_and_full_hardening` with the
  wrong-digest, no-features and Ready-without-features guests.

*Decisions made here.* A ledger write on the Exec path is bounded at five seconds, and a
probe may report up to ten seconds after Validate's deadline before the relay itself is
treated as broken. An EXEC_INTENT whose outcome is unknown retires the VM rather than
trying to repair the journal. A queued Validate answers the new `control_busy` rather
than queueing past its deadline. The ledger keeps schema 1 (no B5 ledger has shipped).
The real guest console flood, previously a disposable review patch, is now the VM
regression `b5_linux_root_a_real_guest_console_flood_keeps_the_drainer_flat` with its
own test guest.

### Evidence for the corrections

On the Mac: `cargo test --locked --workspace` (472 kilnd library tests, the guest
broker's 18, the protocol crate's), clippy with `-D warnings -D clippy::disallowed_methods`
on Rust 1.88 and 1.99 (and on Linux in the VM), the destructive-action gate tests, the 26
maintenance tests, the 58-move audit and `git diff --check` all pass; CI is green. All VM
evidence is from the `kiln` Lima VM (kernel 6.8, 4 vCPUs, 4 GiB) under the managed
`kiln-vm` process, with the re-pinned bundle below; logs are in
`reviews/2026-11-03-b5-fixes-vm/`.

| Run | Result |
|---|---|
| B5 real-chain suite (`b5_linux_root`, 8 tests) | All pass in 657 s. Twenty cold boots: READY p50 13.94 s, p95 13.96 s, max 13.99 s. Persistent execution, timeout, disconnect and Stop retirement, worker death as before; a timeout now reports `known: false` capture |
| 3,000 executions (B5-01) | 3,000 `true` executions in 46.4 s, each reusable; afterwards the journal holds one `exec_history` row (`settled: 3000`) and Remove reaches ABSENT |
| Killed inner sandbox (B5-04) | READY, then the guest-root wrapper kills init; Validate answers `unknown: the broker reported Faulted`, the VM subtree empties, the next Exec is not dispatched, Remove reaches ABSENT |
| Real guest console flood | About 128 KiB/s from guest root over 30 s of executions: D's cgroup memory plateaus at 155,648 bytes, its RSS stays 8,628 KiB, its CPU keeps rising (1.75 s total), every execution reusable, Validate Ready |
| Four-source fairness | Healthy worst cases under two hostile relays and a console flood: Inspect 3.42 ms, Validate 21.49 ms, Exec 50.27 ms, Remove 130.96 ms; hostile memory [659,456, 487,424, 151,552] → [393,216, 249,856, 151,552] bytes; 331,415,552 console bytes drained, one rate report |
| B4 root suite | 31 passed in 1,368 s, and the core's capability-drop test. The first attempt was cut off when the VM itself failed (Virtualization.framework `VirtualMachineStateError` at 10:49, during the scoped-GC test); the VM was restarted through its managed process and the rerun passed |
| Installed suites at `c0b303f` | `install.sh`, `integration-test.sh`, the singleton, state-path and Phase 0 regressions, `smoke.sh` and the maintenance tests all pass. `/var/lib/kilnd` was restored from its byte copy afterwards (`cmp` identical, schema 7) and kilnd `734e275` reinstalled |

*Re-pinned bundle* (kiln-guest `86fbf26`, broker from kilnd `71fe6c4`, archive
`5e23b69da19226473656c61cb4943cb17118e68e21ba529606e36d3533803b00`; two clean builds,
`verify.py` `reproducible: true`, every file byte-identical):

| Artifact | Bytes | SHA-256 |
|---|---|---|
| `Image` | 17,807,872 | `0015f87e136b314a164b30f5255a1589144a3937db0dce00d5eef6c0fdbf2e6a` |
| `kernel.config` | 95,549 | `f07a7ffd291f4ad821e3f4f0f2e0ab1928d3024103f3c74d71e541765cc2d4e9` |
| `kiln` | 2,376,016 | `54442ccc0ce12b9a9236c927b9073019d7d4774c2e2d82f4d55d0db491925c64` |
| `kilnd-guest-broker` | 2,245,008 | `35fad74f7ce0babe5f531accbdee2b19926f632603b0a55de43775d117cc3528` |
| `rootfs.squashfs` | 8,396,800 | `04ce1385409207967d71018e84dc3dc61b1dd71827b47d19b1a912b55c8a4ab8` |
| `manifest.json` | 33,056,298 | `34f53dc5f2a8df61fdfefea738732a73e1818d3809ac4eff1d3aa53010c6a474` |

The real-chain fixture now pins the bundle's own broker artifact (`c0b303f`): with B5-10
the synthetic fixture broker is refused at Hello, which the first suite run showed.

## B6 implementation notes (November 3, 2026)

B6 is built in two milestones on `phase1b/b6-lifecycle`, from B5's accepted `034136a`.
Milestone 1 wires the public `Runtime` path into B4's and B5's helper operations and runs
the first whole session through the real daemon and `kilndctl`; milestone 2 is recovery
and section 10's attacks. Stephen's decisions stand: one VM and one persistent kiln sandbox
per session, 768 MiB guests, no warm pool, the VM terminated on any post-dispatch timeout,
cancel or uncertainty, no API socket, and production Firecracker disabled behind the
manifest gate until B7.

### Milestone 1: the public runtime path

*Create follows READY.* The helper answers Create once C2 is durable (`accepted`), and S
journals READY later, after the broker's Hello and Initialize (B5). `FirecrackerRuntime`'s
`create` therefore reads the allocation back with Inspect every 100 ms within the create
deadline. `present_ready` becomes the C6 receipt: the plan's node, the instance,
allocation and plan digest, the helper generation and the boot ID, which the manager
publishes at C7 exactly as B2 built it. A booting phase keeps waiting. A stopped
allocation, a phase past READY, an incompatible answer or the deadline is a charged
ambiguous failure, which the manager settles by exact token; an absence fence is the
token's own receipt. The B3 fixtures' fake effects never reach READY, so their Create now
ends at its deadline, still ambiguous and charged.

*The boot binding.* Validate and Exec must name the journaled boot and inner sandbox. The
runtime remembers both per allocation from the READY Inspect, reads them again from the
helper's `present_ready` when it has none (after a daemon restart, for example), and
forgets them when a session retires or is removed. This is a binding, not an authority:
the helper compares both with its own journal and refuses anything else, and startup
reconciliation compares the row's durable boot ID with the helper's before a READY row
stays READY (section 8.3).

*Inspect.* `present_ready` is `Present` with a ready receipt, healthy and idle, with no
uncertain execution. `present_busy` (still booting, or executing) stays `Unknown`, so the
manager never reads it as reusable.

*Exec.* `Client::firecracker_exec` shares kiln's stdio exchange: the three opposite
endpoints, the receipt byte, stdin, then both outputs drained beside the reply. Its reply
allowance after the wire deadline is 70 s, as for kiln, because after the deadline the
helper still sends Cancel, waits two seconds for the guest and proves the `vm` subtree
empty. The reply's own evidence sets the disposition:

| Reply | Disposition | Cleanup evidence |
|---|---|---|
| `reusable: true` with `no_child_started` or `guest_cgroup_drained` | Reusable | NoChildStarted or RuntimeDrained |
| `reusable: false` with `vm_stopped` | Stopped (the row becomes LOST, `sandbox_reusable=false`) | SandboxStopped |
| anything else | Quarantined | as reported |
| no reply, or capture facts that do not match the delivered bytes | Quarantined | Unknown |

A failure to learn the session's boot before sending anything is NoChildStarted and
Quarantined; nothing reached the guest, but the session can't be named.

*Remove, the fence and Gc.* `remove` is the helper's Remove by exact token. Its receipt must
name this instance and allocation; the manager compares the plan digest with its row
before committing it. `fence_absent` now tries Remove first: for a token the helper
journaled, Remove stops the VM, removes every owned resource and persists ABSENT; for a
retired token it answers with the fence; only for a token with no journal record (Remove
refuses it and touches nothing) does `fence_absent` call FenceAbsent, which fences a
never-admitted token. The manager settles an `Unknown` observation, such as a stop still in
progress or a VM still booting, through `fence_absent`, and FenceAbsent on an admitted
token would close the token's gate and still refuse while its resources exist. `gc` maps
backend IDs to allocations, returns only individually proven receipts and reports the
skipped and failed ones.

*Never NotFound.* A malformed backend ID is `Incompatible`, and no Firecracker answer is
`NotFound`: only a receipt is absence (section 8.1).

*Health reads the node ledger.* The new `Runtime::node_totals` (no totals by default) is
read in the same shared, cached Health probe as the version. For Firecracker it is the
helper's Accounting snapshot: the node's ceilings as limits, and its committed claims,
including the once-only shared reserve, as reservations, for all seven dimensions. Health
reports them as `AUTHORITATIVE`, with the snapshot's generation and when it was read. An
unreadable authority stays `UNAVAILABLE`, degraded, with every total zero; commitments over
a lowered ceiling degrade Health. The daemon's own sum is never shown as the node's.
`kilndctl health` prints the generation.

### The isolated test deployment

`deploy/firecracker-test/` holds `deployment.json` and its README. kilnd selects the
Firecracker backend only with `--backend firecracker --firecracker-test-deployment FILE`,
and only when the file is strict JSON with exact fields, its kind is `isolated-test`, the
daemon's `--socket`, `--state-dir` and `--helper-socket` are exactly the file's, no path
in it is, contains or lies under a production path (`/run/kilnd`, `/var/lib/kilnd`,
`/run/kilnd-helper`, `/var/lib/kilnd-helper`, `/etc/kilnd`), and its account, group and
unit are its own. Either flag alone is refused. The other half of the gate is unchanged:
the installed helper loads every profile through `ManifestGate::ProductionDisabled`, and
`TestApproved` has no constructor outside test builds, so a daemon started this way against
the production helper gets a C0 refusal for every Create.
`exit1_production_gate_leaves_every_catalog_profile_refused` now checks that `main.rs`
constructs `FirecrackerRuntime` exactly once, after reading the test deployment and
checking its paths.

The privileged `b6_linux_root_a_whole_session_through_kilnd_and_kilndctl` is that
deployment. It creates the `kilnd-fctest` system account, installs the daemon image
root-owned at `/opt/kilnd/b6-session/kilnd`, runs `kilnd init-state` for the instance ID,
builds the real helper at the deployment's root and, with it stopped, enrolls that account,
unit, cgroup and image digest as `add-instance.sh` does. It starts kilnd with `systemd-run`
as the transient `kilnd-fctest.service` with every `[Service]` setting of
`deploy/kilnd@.service`, so the helper attests the real daemon by its account, its exact
unit cgroup and its image's device, inode and SHA-256, then drives the session with
`kilndctl`. `scripts/b4-vm-tests.sh` builds kilnd and kilndctl for it, and
`scripts/b4-vm-cleanup.py` removes the deployment's unit, account and directories (never
production's) and fails if any remain.

### Milestone 1 exit evidence

All in the `kiln` Lima VM (kernel 6.8.0-147, 4 vCPUs, 4 GiB) under the managed `kiln-vm`
process, with the re-pinned production bundle (kiln-guest `86fbf26`, broker `35fad74f…`),
the approved jailer `42e9dea3…`, `mkfs.xfs` `9571cecc…` and the release Firecracker
v1.17.0. Logs, the transcript and the SQLite and journal evidence are in
`reviews/2026-11-03-b6-vm/`.

| Milestone 1 criterion | Evidence |
|---|---|
| The public path is wired | `kilndctl create` reached READY in 13.8 s through Preflight, C1, the helper's C2, boot, the broker and C7; Validate ran in startup reconciliation; Exec, Remove and Health went through the helper |
| Persistent sandbox | A file one `exec` wrote, the next read; stdin appended to it; a nonzero exit and stderr kept the session reusable (`runtime_drained`, `sandbox_reusable=1`) |
| A timeout retires the VM | `exec --timeout 3s … sleep 60` exited 124 after 3.08 s; the execution is `timed_out`, `sandbox_reusable=0`, `sandbox_stopped`; the row is `lost` ("its host stop barrier passed") and refuses the next command; the journal's stop reason is "execution interrupted after dispatch"; the node still charges one slot until Delete |
| `rm` reaches ABSENT and releases | The journal's phase is `absent`, the claim's `released_generation` is set, a retired token holds the receipt, and the row is `deleted` with that receipt's `release_evidence`; Health went 0/3, 1/3 while ready, 1/3 while lost, 0/3 after `rm`; no VMM, loop, mount, cgroup or file remains |
| Real attestation | The daemon ran as `kilnd-fctest` in `/system.slice/kilnd-fctest.service` with kilnd@.service's hardening; the helper attached it by enrollment, cgroup and image digest |
