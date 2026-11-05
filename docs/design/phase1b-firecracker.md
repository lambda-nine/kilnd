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

The requested guest-contract work has arrived locally: kiln-guest `13c037a`, with `results/launch-contract/summary.json` recording a matching A/B manifest digest:

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

**Use one protected store and descriptor-based handoff for every host executable in the Firecracker helper chain.** Mirror kiln-guest `a928731`'s root-private installation, descriptor-relative ancestry walk, hashing through an open FD and retained-jailer-FD execution (`scripts/privileged_launch.py`, `tests/test_vmm_path_race.py`). Extend that rule to the VMM's final exec, formatter and every separate supervisor/worker/relay/drainer binary. This is a specification for kilnd, not a claim that kiln-guest already implements those extensions.

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

Receipts identify node, instance, allocation, plan digest, monotonically increasing helper generation and kind `AbsentFenced`. A prior candidate collision or revalidation failure with no fence returns AllocationAmbiguous and the daemon keeps its FAILED row charged while fencing is retried. A ledger failure or a stuck accepted worker forbids the receipt. Retired entries remain even when API history expires, until B7's compaction (section 16) removes them: the helper issues every token, and only rows of an absent token below its instance's durable watermark are ever deleted, so nothing is pruned by age or clock. Since B7 the ledger reserves a 128 MiB fence allowance, counted at a measured 20 KiB per retained token; stop accepting new tokens before the space needed to fence already accepted tokens would be exhausted. A quarter of that allowance is set aside for tokens the ledger never admitted, divided equally among the policy's possible instances, and each instance's quota, counted over retained rows only (a budget per lease window, RTC-12), is checked in the fence's own transaction. At its quota, FenceAbsent for a never-seen token fails closed with no row written, and the daemon keeps its charge; a token the ledger admitted is never refused by this quota. The admitted remainder is shared by reserved per-slot shares (RTC-17), so never-admitted fences and admitted tokens together always fit the allowance. Bound console retention to 64 KiB combined; its mandatory drain/rate policy is in section 5.6.

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

**The destructive-action invariant (B4 recheck 3, November 2, 2026).** No destructive action may run on a resource unless the caller holds proof that the resource's current generation equals a durable journaled generation from the current boot. A resource with no such proof is Unknown: it stays charged, nothing is done to it, and it never counts toward ABSENT. The destructive actions are signals (`pidfd_send_signal`, `kill`), writes to `cgroup.kill`, `rmdir` of a cgroup or directory, `unlink` of a file, `umount2` and `LOOP_CLR_FD`. The type system enforces it: `crates/kilnd/src/helper/firecracker/proven.rs` holds one proof type per resource kind (`ProvenProcess`, `ProvenCgroupVm` and `ProvenCgroupTree`, `ProvenFile`, `ProvenDir`, `ProvenMount`, `ProvenLoop`), none `Clone` and none constructible outside that module. Only its verification functions make them, each from the journaled identity, the current boot ID and the live kernel object, returning `Result<Proven*, Unprovable>` (`Gone`, `Replaced` or `Unknown`). Every destructive helper takes its proof, and the raw capabilities appear nowhere else: since B4 recheck 4 clippy enforces it semantically for the whole workspace (*The clippy gate* below), with the lexical test `proven::tests::no_destructive_call_outside_the_gate` kept as defense in depth. Each check stays as close to its action as the kernel allows, which is the decided residual window: a pidfd for processes, the `vm` node's descriptor for `cgroup.kill` with its children re-listed from that descriptor (`getdents64` on a fresh open file description of it, `openat(fd, ".")`, since B7) just before, the parent's descriptor with the child's inode or birth time re-read just before each `rmdir` and `unlinkat`, the loop descriptor the generation was compared on, and for mounts a fresh descriptor's unique mount ID read just before `umount2` of the single name resolved from the held parent descriptor (that descriptor must be closed first, or a non-lazy unmount is busy). No proof reads a `/proc/self/fd` pathname (B4 recheck 5).

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
| `proven::child_cgroups` (the `cgroup.kill` and removal proofs) | `read_dir("/proc/self/fd/N")` | `sys::read_dir_fd`: `getdents64` on a fresh open file description of the retained node descriptor, `openat(fd, ".", O_RDONLY\|O_DIRECTORY\|O_CLOEXEC)` (B7; until then an `F_DUPFD_CLOEXEC` duplicate rewound with `lseek(0)`, which also rewound the caller's offset) |
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

Each allow is `#[allow(clippy::disallowed_methods)]` (inner for a whole module) with an `// Approved (design 7.1):` justification immediately above it. The CI test `proven::tests::disallowed_allows_only_in_approved_modules` scans every Rust source in the workspace and fails on an `allow` or `expect` of `disallowed_methods`, `disallowed_types` or anything that would silence them (`clippy::style`, `clippy::all`, `warnings`, also inside `cfg_attr`) other than exactly these, on a `#[cfg(test)]` item, or on a test-only file (a `tests.rs` its parent declares `#[cfg(test)] mod tests;`, or an integration test); on one without the justification; on any `[lints]` table or `.cargo/config`; and on a `clippy.toml` that drops a required path. (`kilnd-api`'s generated code no longer allows `clippy::all`.) `proven::tests::no_foreign_declarations_or_inline_assembly` rejects a local `extern` block, inline assembly, `#[link]`, `link_name` or `dlsym` anywhere, which clippy cannot see through. Since B4 recheck 5, `proven::tests::no_unapproved_build_scripts_or_generated_includes` fails on any build script other than `kilnd-api/build.rs` and (since B7 milestone 2 recheck 3) the other five crates' backstop-only build scripts, a `build` key in a manifest, and any `include!`, `include_proto!` or `OUT_DIR` other than `kilnd-api`'s `tonic::include_proto!("kilnd.v1")`, since generated code is invisible to every source check; and `proven::tests::proc_and_control_paths_only_in_approved_modules` fails on a production string literal containing `/proc/` or `cgroup.` outside `sys.rs`, `cgroup.rs` and `proven.rs`, except four justified ones (the two publish `linkat` paths above, kiln's read-only `exec/cgroup.events`, and one `cfg(test)` fixture). Every helper write under `/proc` or `/sys` goes through `cgroup::write_control`'s `ControlFile` enum, `proven::write_cgroup_kill` (the two `/sys/fs/cgroup` writers) or `sys::write_sysfs` (the one `/sys/block` file); nothing writes under `/proc`. The lexical test now matches whole expressions with comments and whitespace removed, so an allowed expression cannot hide another on the same line, and its needles also catch aliases (`libc::kill` without a call), `rename`, subprocesses, `start_kill`, raw `syscall`, `ioctl`, `prctl`, `ptrace` and `fallocate` outside `sys.rs`, truncation (`set_len`, `.truncate(true)`, `File::create(`, `truncate`, `ftruncate`), `process_vm_writev`, `pidfd_getfd`, foreign declarations and inline assembly; it scans the helper and `sys.rs`, where its one `unlinkat` is allow-listed by exact expression.

Test fixtures are excluded from the gate. Outside the approved items above, nothing in the workspace calls or names any listed capability.

*The dependency gate (B7, B4 recheck 6 item 2; rebuilt after the B7 milestone 2 break-it and its three rechecks).* Clippy resolves workspace code, but it never lints a dependency's own body, so a dependency can offer a destructive operation under a name `clippy.toml` does not know, or perform one inside a method that workspace code calls under a harmless name (an extension trait on `std::fs::File` whose `reset` calls `set_len(0)`). The gate therefore fails closed on *review*, not on detection. For builds made through the supported entry point, `scripts/build.sh` with one of the reviewed build profiles, in its closed compiler environment, it guarantees exactly two things: **no unreviewed package enters the build**, and **every occurrence of a curated destructive sink identifier, and every trait impl or type alias on std's and Tokio's file and process types, in the checked-in source of the runtime subtree of a package declared non-destructive (each package's whole directory, not only its library target's) is flagged for review**. A raw `cargo build` (or `test`, `clippy`) given other feature flags or compiler flags builds what the gate has not reviewed, and is outside the guarantee; every workspace crate's build script refuses a `--cfg`, `-Z` or response-file compiler flag on any build, as a backstop. Deciding whether an API is destructive is the reviewer's job. The gate is a lexical aid to that review, not a proof, and it is built for honest mistakes, not for a dependency written to hide one. `proven::tests::dependency_gate` checks it on every `cargo test`.

*Supported builds.* `dependency-gate.json`'s `profiles` lists every supported build: `default` (no features: the release build `scripts/install.sh` installs and `scripts/upgrade.sh` takes, CI's default tests, clippy and release build, and the library tests the VM scripts build) and `firecracker-test-deployment` (`kilnd/firecracker-test-deployment`: CI's feature job and the daemon and client `scripts/b4-vm-tests.sh` builds). `scripts/build.sh [+TOOLCHAIN] [--crt-static] PROFILE build|test|clippy|check ...` reads the same list and runs `cargo COMMAND --locked`, with `--features` only for the profile's own. A profile enables only features a workspace member declares (`member/feature`), so a dependency feature a build needs is forwarded through a checked-in workspace feature. Before `--`, `build.sh` refuses every argument that selects features or another graph: `--features` and `-F` (so `dep/feature` selectors such as `tokio/full`), `--all-features`, `--no-default-features`, `--manifest-path`, `--config` and `-Z`, in every spelling cargo accepts (`--features=x`, `-Fx`, `-rF x`). The gate runs `cargo metadata --locked` once per profile with exactly those flags, and refuses a profile that names anything but a declared workspace feature, any package a profile resolves that `Cargo.lock` does not lock, and any locked package no profile resolves. The reviewed features are the union over the profiles, and kinds are judged from the union of their graphs.

*The closed compiler environment (recheck 3).* rustc's own flags can compile feature-gated code that cargo's resolver, and so `cargo metadata` and the gate, never see: `--cfg feature="x"` in `RUSTFLAGS` builds an unreviewed feature under a reviewed profile. So `build.sh` refuses a nonempty `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `CARGO_BUILD_RUSTFLAGS`, `RUSTDOCFLAGS` (and its encoded and build forms), `CARGO_TARGET_*_RUSTFLAGS`, `CARGO_TARGET_*_RUSTDOCFLAGS`, `CARGO_PROFILE_*_RUSTFLAGS`, `CARGO_HOST_RUSTFLAGS`, `RUSTC`, `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`, `CARGO_BUILD_RUSTC*`, `RUSTC_BOOTSTRAP`, `CARGO_UNSTABLE_*` and `CLIPPY_ARGS`, then sets the compiler inputs itself so no Cargo config file can supply any: empty `CARGO_ENCODED_RUSTFLAGS` and `CARGO_ENCODED_RUSTDOCFLAGS`, which take precedence over every config table (a `target.'cfg(...)'` table included, which `--config` cannot reach), `RUSTC=rustc`, empty wrappers, and `--config` resets of `build.rustflags`, `build.rustdocflags` and the `target.TRIPLE.rustflags` of the host and every `--target`. Its one compiler flag is `--crt-static`'s `-C target-feature=+crt-static`, which requires `--target` so build scripts and procedural macros stay dynamic (`scripts/b4-vm-tests.sh`'s static test helper). Clippy's arguments are `build.sh`'s own fixed list, `-D warnings -D clippy::disallowed_methods`; a caller's `--` tail is refused for `clippy` (it reaches clippy-driver and rustc), `build` and `check`, and goes to the test harness for `test`. Behind it, every workspace crate has a build script whose first act refuses a `--cfg`, `-Z` or `@response-file` entry in the `CARGO_ENCODED_RUSTFLAGS` cargo hands it, which catches a raw cargo build given such a flag by any route; `b7m2_recheck3_every_workspace_crate_refuses_compiler_cfg_flags` holds all six to the same function, and `b7m2_recheck3_workspace_build_scripts_emit_no_feature_cfg` refuses a workspace build script that emits a feature cfg (or a cfg it does not name literally).

*Every build instruction (recheck 3).* `supported_builds_use_the_build_entry_point` inspects every Markdown, shell, Python and workflow file in the workspace and fails on a raw `cargo build`, `test`, `clippy`, `check`, `run`, `rustc`, `doc` or `install` anywhere but `scripts/build.sh` itself, the gate's regression fixtures (`scripts/dependency-gate-regressions.sh`) and the Firecracker jailer build (a line naming `-p jailer` in `scripts/build-phase1b-tools.sh` and `deploy/firecracker/README.md`). `CHANGELOG.md` and this design hold records of past runs and of the guarantee's limits; each file's exact number of raw mentions is pinned, so a new one fails until someone confirms it is a record.

*Every locked package is reviewed.* `dependency-gate.json` has an entry under `packages` for every package in `Cargo.lock` outside the workspace, direct and transitive (144 today), keyed `name@version` and pinned to `Cargo.lock`'s `checksum` and to the `features` that `cargo metadata --locked` resolves for it in any supported profile (their union). A `name@version` key cannot tell two sources apart, so two packages with one name and version (two registries, or a registry and a path) are refused outright, in `Cargo.lock` and in each profile's metadata, before any review is matched; the drafter refuses them too. Each entry has a `kind`, a `capability` (`none`, or a set of `filesystem`, `process`, `signals`, `syscalls` and `network`) and a justification: its own `why`, or a `group` with a shared one. A new package, a changed version or checksum, or a changed feature set fails the test, so every lock change needs a person's review; a path or git dependency outside the workspace has no checksum and is refused. `scripts/dependency-gate-review.py --write` drafts entries for new packages, filling the checksum, features and kind and leaving the capability and justification empty, so the test fails until someone writes them. A group is allowed only for `none` packages with no raw system-call crate underneath whose source (since recheck 3 the same whole-package set the scan reads, build scripts included) names no `std::fs`, `std::process`, `std::os` fs, fd or process extension (or the Unix prelude that re-exports them), libc, or `tokio::fs`/`tokio::process` path at all, and the test checks that. Today 74 packages share `pure-computation` and 12 share `compile-time` (procedural macros and the syntax libraries only they use); the other 58 have their own justification (seven left their groups at recheck 3 because a build script or binary names a process or file path). A direct dependency's kind comes from the manifests and any other package's from the dependency graph: `runtime` if a workspace crate's normal dependencies reach it through normal edges, otherwise `build-only` or `dev-only`. A procedural macro runs in the compiler, so it and what only it reaches are build-only. A direct `build-only` or `dev-only` dependency that the runtime graph also reaches records `runtime_via` (`h2`, also `tonic`'s transport).

*Capabilities.* `Cargo.lock` can only require more, never override a reviewed decision. A raw system-call crate (`libc`, `linux-raw-sys`, `rustix`, `nix`, `syscalls`, `sc`, any `*-sys`) declares `syscalls`, and a `none` package directly over one records in `raw_use` what it uses it for (`tokio-util`: `libc::memchr`; `errno`, `cpufeatures`, `getrandom` and three Windows console crates likewise). A direct dependency with a destructive-capable category (filesystem, process, signals, syscalls) lists its `destructive` paths and `clippy.toml` disallows each one, or records in `no_destructive_api` why its API has none (only `rusqlite`, and never a raw crate). `clippy.toml` names only std and direct dependencies, and no path an entry does not list. Workspace code cannot name a transitive crate, so a transitive entry lists no paths: its API reaches the workspace only through a direct dependency, whose own review covers it. The test also refuses an unknown field, capability or group, a stale entry or exception, and a renamed dependency. Production code (every crate's `src` and build script, comments and strings ignored, `use` aliases resolved) may not name a destructive-looking function through a dependency path `clippy.toml` does not disallow, or glob-import a dependency reviewed as non-destructive.

*The subtree scan.* For every package declared `none`, `network` or `no_destructive_api` that is in the runtime graph or is a direct dependency, the test reads the checked-in source of every package in its whole runtime dependency subtree (normal edges for any target; procedural macros excluded) from the directory cargo extracted it to. Since recheck 3 that is every `.rs` file under the package root, build scripts and binaries included, except files under the package's top-level `tests/`, `benches/` and `examples/` that nothing reaches, and the test follows every literal `#[path = "..."]` (directly or in `cfg_attr`, each conditional path as well as the module's ordinary location), every ordinary out-of-line `mod name;` and every `include!("...")` edge from a scanned file, transitively and wherever it lands, so a module outside the library target's directory (`#[path = "../hidden.rs"]`) is read, and so is each ordinary child module below one, even under an otherwise unscanned `tests/` (since the integrated recheck: `tests/common/mod.rs`'s `mod reset;`). An ordinary module is resolved by both of Rust's readings, conservatively: `name.rs` and `name/mod.rs` in the declaring file's directory (a crate root, a `mod.rs` or a `#[path]` file) and, for any other file `foo.rs`, under `foo/`, beneath its inline modules (`mod a { mod b; }` is `a/b.rs`); every candidate that exists is scanned. An edge inside a macro body that the file's own directory cannot resolve is looked up from every source directory in the package. An edge that resolves outside the package root, a symbolic link or an unreadable file refuses the package outright. An edge that resolves to no file, or an `include!` of anything but a literal path or generated `OUT_DIR` code, is an `unresolved source edge` hit like any sink, so it needs a reviewed exception. Generated `OUT_DIR` code remains the documented exception. In each package of that subtree it flags four things. First, every occurrence of an identifier the curated, justified list in `METHOD_SINKS` names, wherever it is: `set_len`, `truncate`, `remove_file`, `remove_dir`, `remove_dir_all`, `rename`, `unlink*`, `copy`, `kill`, `start_kill`, `send_signal`, `persist*`, `exec`, `umount*` and `unmount*`. The identifier token is the sink, not a call shape: a method call on any receiver, a call through any qualifier or type alias (`LocalFile::set_len(self, 0)`, `<T as Tr>::set_len`), a function value, a `use` list, a definition, a field and an attribute argument all count. Second, any path `clippy.toml` disallows, however it is aliased or glob-imported (`use std::fs::*;` then `remove_file(p)`). Third, a trait impl for `std::fs::File`, `std::fs::OpenOptions`, `std::process::Child` or `Command`, or Tokio's file and process types, named directly or through a `use` or `type` alias (a bare `File` counts unless the package imports it from elsewhere or defines its own). Fourth, a `type` alias (`pub type LocalFile = File;`, an associated type's included) whose target resolves to one of those types. A hit refuses the declaration unless `sink_exceptions` records a reviewed exception for that package, version and exact feature set, naming the sinks and why. An exception does nothing outside that scope, and one that no longer matches a hit is refused as stale. Today there are 37 exceptions (30 packages): harmless identifiers that share a sink's name (`Vec`, `BytesMut` and `SmallVec` `set_len` and `truncate`, `core::ptr::copy` inside a package's own buffer, `futures::io::copy` and `tokio::io::copy` between streams, executor bindings named `exec` in hyper, hyper-util, tonic and Tokio, a `$copy` macro metavariable in serde_json, bitflags' `Flags::truncate` in its own tests), `unlink` on h2's and futures-util's own intrusive lists, libc's own declarations of the C functions (each destructive one disallowed for workspace code), Win32 binding parameters in windows-sys, mio's `FIONBIO` `ioctl` on its own pipe, writer impls for a `File` the caller passes (anstream, anstyle-wincon, tracing-subscriber, whose writer type alias is `&std::fs::File`), and Tokio's own implementation of the API its entry lists. Recheck 3's whole-package scan added ten: build scripts that run the compiler to probe it, remove their own `OUT_DIR/probe` directories or write and copy their generated code into `OUT_DIR` (anyhow, httparse, libc, libsqlite3-sys, serde, serde_core, thiserror, zmij), libsqlite3-sys's `sqlite3_api_routines.exec` field (the loadable-extension pointer to `sqlite3_exec`, in bindings only the unused `loadable_extension` feature copies), and serde_core's five docs.rs-only `cfg_attr` paths into serde's facade layout, which serde_core does not ship. Inline `#[cfg(test)]` modules are skipped; out-of-line test files are scanned.

*What the gate does not see.* A build outside `scripts/build.sh`, its closed compiler environment and the reviewed profiles (the build scripts' backstop refuses only `--cfg`, `-Z` and response files there). A destructive operation behind a name not on the list, on a receiver of unknown type and without a flagged impl or alias (for example a generic method that is only later instantiated with `File`). Code generated by build scripts (`OUT_DIR`), procedural macros or macros built from strings, and a path a macro builds rather than writes literally. C code behind FFI (SQLite's own journal files, under `rusqlite`'s `no_destructive_api`). Windows API names (`windows-sys` is reviewed, scanned and never compiled for kilnd's targets). Build-only and dev-only packages are reviewed but not scanned, since they never link into a kilnd binary.

*Completeness.* This is tested, not asserted. `every_destructive_libc_function_is_disallowed` reads every exported function of the locked `libc` (all targets, from the source cargo resolved) and requires each one matching the curated patterns (`*unlink*`, `rmdir`, `rename*`, `*truncate*`, `creat*`, `exec*`, `posix_spawn*`, `system`, `popen`, `*kill*`, `tkill`, `tgkill`, `*sigqueue*`, `pidfd_send_signal`, `umount*`, `mount`, `remove*`, `*removexattr`, `fallocate*`, `ptrace`, `process_vm_writev`, `prctl`, `syscall`, `reboot`, `swapoff`) to be disallowed: 104 in libc 0.2.190, most of them for other targets (marked `allow-invalid`). `std_and_tokio_destructive_surfaces_are_disallowed` holds `clippy.toml` to a curated, justified review of `std::fs`, `std::process` and the Unix extensions (std is not a `Cargo.lock` input, so the list is re-read at each toolchain bump), and to every public function of the locked Tokio's `fs` module, failing on any the review does not classify.

*Reviewed and not gated.* `fork`, `vfork` and `clone` duplicate the caller, and running another program needs `exec*`, which is gated. `unshare`, `setns` and `chroot` change only the caller's own view. `mknod`, `link` and `symlink` create and never replace. Descriptor writes, and `O_TRUNC` passed by flag to `open`/`openat`, are invisible to any path-based gate.

The jail base's two mounts moved into typed wrappers (`sys::bind_onto_itself`, `sys::make_private_recursive`) when `libc::mount` joined the list, and `kilnd-api/build.rs` carries the one approved allow, for `tonic-prost-build`; the other five crates' build scripts are only the compiler-flag backstop. `scripts/dependency-gate-regressions.sh` (and a CI job) replays Daybreak's PoCs on Rust 1.88 and 1.99 through the actual source loader, cargo and clippy. Its method, transitive and type-alias wrappers are vendored registry packages with `Cargo.lock` checksums. The script points the ignored `regression_fixture_gate` test (the same loader and gate) at each case's workspace with `KILND_DEPENDENCY_GATE_FIXTURE`; the authoritative `the_dependency_gate_holds` always checks the workspace its test binary was built from and reads no variable, which `the_authoritative_gate_reads_no_environment` checks in its source and the script checks by setting both variables.

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

Reserve shared infrastructure **once per node**, before any session: 128 MiB RAM, 500 CPU millis, 32 PIDs for H/L/M/K plus shared validation/control processes, and 512 MiB on durable storage for the node ledger/WAL, bounded queues/control metadata and retired fences (128 MiB of that is the fence allowance since B7; it was 64 MiB, which the frozen B1 launch contract still records). Give those shared processes their own cgroup with those ceilings outside all VM parents. Bound WAL/checkpoint growth and queues; stop new claims while retaining room for all outstanding stop/absence records. The immutable bundle store has a separate root-configured size/inode cap, initially 1 GiB, also deducted from the 16 GiB backend budget; do not sum it once per daemon. Provision actual filesystem free space for these reservations plus host-service headroom. The per-session 128 MiB disk allowance is neither license for arbitrary jail writes nor a substitute for shared journal space.

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

A durable rollback fault (RTC-14, section 16.5), set only by a helper-verified token at or above the ledger's issue pointer, is treated like ledger loss, node-wide and for every instance: the helper refuses Preflight, Create, Validate, Exec and every other forward effect, keeps bounded Inspect, List, Stop, Remove, Gc and FenceAbsent so reconciliation and Delete can drain, and stays latched across restarts until root's offline inventory and fault clear (section 16.6). Reconciliation under the latch publishes only what that cleanup proves; it never infers absence from the refusals. The latch is enforced in three places, so no single lost message reopens the node (B7 milestone 1 break-it corrections, section 16.9): H refuses forward requests at its request gate; queued work rechecks H's latch at its final effect boundary (Preflight before issuance, Create immediately before S's `OpenGate`, Exec after its EXEC_INTENT write and immediately before the descriptors and the broker Exec, retiring the VM if latched there); and L refuses every forward write (C2 admission, PREPARING, `spawn_intent`, EXEC_INTENT, issuance and a first attach) under its own latch, its fail-stop marker or any fault row, whatever H believes. Every L hands its latch state to H together with K, and H imports it before it publishes that L's channel. Since the milestone 1 recheck (section 16.10, "Recheck residuals"), no answer that could carry a fault is ever discarded: when a deadline or cancellation drops H's wait for a write, the channel hands L's eventual answer to H, which imports a `SyncFailed`, `Latched` or `FaultPending` from it, and until it arrives H holds every forward effect exactly as if latched (a boundary that can wait, waits within its own deadline; still held at the deadline, it refuses). The latch also covers the supervisor: L serves only an explicit allowlist under its latch (reads, the fault, compaction, stop, fence, settlement, cleanup and the identities of objects and processes that already exist) and refuses every record that precedes the effect it authorizes, every forward phase and S's check before each broker Initialize; H sends S's records to L only where L would take them, reads the latch again after L answers, and acknowledges only teardown (a cleanup S's `loop_released`) while latched, containing S otherwise.

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

Retain Runtime's create/exec/remove/list/gc/version/validation roles. Add preparation and allocation recovery, and make cleanup disposition explicit. Suggested Rust-domain signatures below are normative about inputs/results; ordinary borrowing/lifetimes may be chosen locally. Futures remain `Send`; the trait remains generic, not object-safe. *This listing is the B7 contract* (retired-token compaction, section 16): the helper, not the daemon, issues a Firecracker allocation token, so preparation names no allocation, and every removal of a fenced allocation carries the Store's binding.

```rust
/// Built before preparation. Names no allocation: a Firecracker token does
/// not exist until the helper issues it inside Preflight (RTC-2).
struct PrepareContext {
    instance_id: Id128,
    sandbox_id: String,
}
struct PreparedCreate {
    spec: SandboxSpec, // complete effective host spec, including labels
    host_spec_sha256: Digest,
    guest_exec_spec_sha256: Digest,
    reservation: ResourceReservation,
    plan_version: u32,
    plan_digest: Digest,
    backend_plan: Vec<u8>, // strict bounded internal codec, <=128 KiB
    runtime_profile: String,
    runtime_artifact_digest: String,
    regime: EvidenceRegime, // LegacyLocal | AbsenceFenced { node_id }
    allocation_id: Option<Id128>, // Some(helper-issued token) iff AbsenceFenced
}
impl PreparedCreate {
    /// The token the helper issued and bound into this plan's substitutions,
    /// verified by the adapter for this instance; None for kiln.
    fn allocation_id(&self) -> Option<Id128>;
}
/// Built after preparation, before C1, and stored with the row.
struct CreateContext {
    instance_id: Id128,
    allocation_id: Id128, // prepared.allocation_id(), or a legacy random ID for kiln
    sandbox_id: String,   // the PrepareContext's
}
/// What a removal names: never a backend ID alone for a fenced allocation.
enum RemoveTarget<'a> {
    /// A kiln sandbox: its backend ID, released only through the legacy tag.
    Legacy { backend_id: &'a str },
    /// A fenced allocation: the daemon Store's immutable binding, read from its row.
    Fenced { binding: &'a AllocationBinding },
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
prepare(prepare_context, spec, deadline, cancel)
    -> Result<PreparedCreate, RuntimeError>
create(create_context, prepared, deadline, cancel)
    -> Result<CreatedSandbox, CreateFailure>
inspect_allocation(create_context, prepared_digest, deadline, cancel)
    -> Result<AllocationObservation, RuntimeError>
fence_absent(create_context, prepared_digest, deadline, cancel)
    -> Result<AbsenceReceipt, RuntimeError>
exec(id, execution_context, spec, cancel) -> ExecOutcome
remove(target: RemoveTarget, deadline, cancel) -> Result<AbsenceReceipt, RuntimeError>
list(deadline, cancel) -> Result<BackendInventory, RuntimeError>
gc(targets: &[RemoveTarget], deadline, cancel) -> Result<Vec<AbsenceReceipt>, RuntimeError>
```

**Where each ID comes from.** The manager builds `PrepareContext` from the Store identity and a new sandbox ID, and calls `prepare` with it. A Firecracker `prepare` sends Preflight with no allocation ID; the helper issues the token, binds it into the plan's substitutions and returns it, and the adapter's `verify_prepared` checks its shape (32 hex digits, seq ≠ 0), that the substitutions name it, and that it is this instance's, then returns `PreparedCreate::fenced(.., token)`, whose `allocation_id()` is `Some(token)`; the issuance consumes one seq (RTC-4) but `prepare` still allocates nothing and leaves no row or charge. Kiln's `prepare` returns `PreparedCreate::legacy(..)`, whose `allocation_id()` is `None`. Immediately after `prepare` and the serving recheck, and before C1, the manager builds `CreateContext`: `allocation_id` is `prepared.allocation_id()` when present; otherwise, for kiln only, the manager generates the legacy `Id128::random()` there, which kiln never sees and which records no allocation. A fenced plan without a token, or a legacy plan with one, is refused before C1. Every later call for that row (`create`, `inspect_allocation`, `fence_absent`) uses the `CreateContext` stored with it, and the manager never invents a Firecracker token.

**Removal targets.** The fenced release path calls `remove(RemoveTarget::Fenced { binding })` with the Store row's immutable binding; legacy Delete, publication compensation and reconciliation Gc pass `RemoveTarget::Legacy { backend_id }`. The generic manager passes these to whichever runtime is active, so `Legacy` **can reach a Firecracker runtime** (a historical kiln row's Delete, for example). The Firecracker adapter refuses `Legacy` as `Incompatible` before any wire call, and checks every `Fenced` binding's node and instance against its attachment, refusing a whole `gc` vector with nothing sent if any target fails; the kiln adapters refuse `Fenced`. Historical kiln rows therefore do not drain while Firecracker is selected: they stay charged and visible, and are drained by running the database with `--backend kiln` before switching (section 16.6). A compile-time contract test instantiates every method, with both `RemoveTarget` variants, for `FakeRuntime`, `KilnRuntime`, `DirectKilnRuntime` and `FirecrackerRuntime`.

`name`, `version` and side-effect-free `validate_sandbox` remain. Add disposition and cleanup-evidence fields to `ExecOutcome`; no change to `CommandStatus`, capture truthfulness or first-wins cancellation semantics. `AllocationObservation` distinguishes Present, StoppedWithResources, AbsentFenced, Unknown and Unsupported. `BackendInventory` contains records, generation and completeness; it must not erase Unknown entries into Stale. Receipts are backend-produced typed evidence bounded to 16 KiB, matched by identity/generation and persisted; they are not caller-supplied strings or guest assertions.

`KilnRuntime.prepare` returns the unchanged spec reservation; its existing strict removal proof is wrapped in an absence receipt. It returns Unsupported for allocation-token recovery and retains its legacy ambiguous-create behavior. It reports Reusable only after the existing verified cleanup barrier, Quarantined on cleanup failure. No fabricated Firecracker-grade proof for legacy kiln. FakeRuntime implements every disposition, loss and crash boundary for manager tests.

The manager checks pre-cancel/deadline, invokes prepare **before** reserving, builds `CreateContext` from the prepared plan, then writes C1 and starts create with the exact prepared plan. After an await in preflight, recheck shutdown/serving and bind tracked ownership before committing a new create. A paused/preflight-only call cannot allocate after shutdown because an earlier serving check passed. Delete/reconcile/exec publication use typed evidence, not only `Result<()>`, enum state or NotFound. Each runtime's proof logic stays internal; the generic manager handles only reservation, ownership, lifecycle and reuse.

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

16. Reproduce kiln-guest `a928731`'s KR-05 source-parent race as an unrelated unprivileged UID: rename the old build/source tree after verification, plant a replacement, and separately try renaming each protected installation ancestor. The old source rename may succeed; protected-tree replacement must be denied or launch must refuse. Pause immediately before S executes J and between J verification and V exec; replace the Firecracker `--exec-file` name in a test-only root fault injection as well. The only allowed outcomes are refusal or execution of the retained approved inode. Assert actual `/proc/<J>/exe` and `/proc/<V>/exe` **device, inode and FD-computed digest** against their pre-exec journal records, not only path strings, configured hashes or exit codes. Repeat every race for the formatter and each separately executed S/L/P/R/D/M/K image; verify fork-only workers inherit the approved image. A test-only exec-stop fixture may hold short-lived children for `/proc` inspection; production does not acquire a ptrace dependency. Missing evidence fails the test. Check bootstrap FDs do not survive V exec, no fallback path is attempted, preflight mismatches create no session resource, and every post-C1 mismatch holds its charge until ABSENT.

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

**Retired-token compaction comes first.** Without it a node admits 12,287 sessions in its lifetime and an instance stops after 384 post-C1 refusals. B7 implements [section 16](#retired-token-compaction-pre-b7-design) (helper-issued sequence tokens and a per-instance watermark, rules RTC-1 to RTC-18, node ledger schema 2 and Firecracker group schema 2) and passes its section 16.6 acceptance criteria, including the lifetime test past 16,384 sessions, before production is enabled.

**Exit:** node-global stress across at least two daemon namespaces supports the chosen profile, accounting for all per-allocation S/P/R/D and VMM/KVM costs plus shared H/L/M/K, the full tmpfs allowance, journal/WAL/fence and bundle-store headroom. Measure peak CPU/PIDs/memory/storage and workload density; reapprove limits if 128 MiB per-session or shared allowances fail. Legacy privileged suites pass; Daybreak recheck closes the findings (or Stephen explicitly accepts any residual risk); Stephen's section 12 choices are reflected in fixtures. These tests alone do not establish hostile multi-tenant production readiness.

**B4 recheck 6 hardening follow-ups** (`reviews/2026-11-03-b4-recheck6.md`, ranked; none blocks B5):

All five are done in B7 milestone 2 (section 15, *B7 milestone 2: hardening follow-ups*), with the B6 recheck's three LOW items.

1. **Done.** *Fail closed when a socket filesystem cannot export a file handle* (MEDIUM). `name_to_handle_at` returning `EOPNOTSUPP` becomes the all-zero handle, so the API socket's generation silently falls back to device, inode and birth time; ramfs accepts Unix sockets and returns `EOPNOTSUPP`. Reject `EOPNOTSUPP`, or validate an explicit allowlist of socket filesystems that export handles (`sys.rs` socket generation).
2. **Done.** *Make the destructive-method gate dependency-aware* (LOW). Clippy's list names libc/std/tokio paths; a future system-call crate could expose an equivalent the lexical backstop misses. Reject new syscall-wrapper dependencies by manifest allowlist, or require their destructive methods to join `clippy.toml` in the same change.
3. **Done.** *Serialize initialization of the private procfs cache* (LOW). The cache publishes its mount ID and descriptor through two atomics; concurrent first callers can each create a procfs root, and the losers' descriptors leak for the process's life. Use `OnceLock` or a mutex.
4. **Done.** *Give `read_dir_fd` an independent file description* (LOW). `F_DUPFD_CLOEXEC` shares the directory offset, so its rewind also rewinds the original description. Reopen `.` beneath the held descriptor instead, preserving the fd-native property.

**B6 break-it follow-up** (`reviews/2026-11-03-b6-breakit.md`, B6-BI-03, MEDIUM; does not
block B6):

5. **Done.** *Keep idle public sockets from starving Health and cleanup.* The server takes one of
   the 64 global connection permits before it reads peer credentials and holds it for
   the connection's life, and admission has only global connection and ordinary-RPC
   budgets. Any principal the socket's filesystem gate lets in can open 64 sockets that
   never send an HTTP/2 preface, and a new Health, Get or Delete connection is then
   dropped before authorization or Health's reserved RPC lane can help (Daybreak's
   `reviews/poc-b6/public-connection-starvation.py`). An accepted, manager-owned
   detached Delete still drains. Direction: reserve ingress capacity (a connection slot
   held back for Health and cleanup RPCs), and after reading peer credentials enforce
   per-UID shares of connections and of ordinary RPCs. Add a real-daemon hostile
   public-caller test beside the existing guest/helper I/O fairness scenario.

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
- Guest: kiln-guest README, `scripts/launch_contract.py`, `dist/bundle-a/manifest.json` and `results/launch-contract/{summary,reproducibility}.json` observed at `13c037a`; current bundle digest in section 1.2. The new broker profile remains unbuilt/unapproved.
- Executable-handoff reference: kiln-guest `a928731d3015bfc49f316e0d9c5ba825bd149c32`, README validation section, `scripts/privileged_launch.py`, `tests/test_vmm_path_race.py` and `results/kr05/README.md`. It supplies protected installation/retained-jailer-inode regressions; section 3.4 explicitly extends the rule to the entire Phase 1b helper chain. Guest manifest/artifact identity did not change.
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
- **Fence headroom.** Each token was bounded at 4096 bytes (B7 measures 20 KiB and doubles
  the allowance to 128 MiB, section 16). Space for never-admitted tokens,
  including C1 rows the helper has not seen, is reserved from the allowance (see the
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
- **Never-admitted fences were a lifetime budget** (superseded by B7, section 16). Fences
  were permanent, so a quota spent stayed spent. Since B7 the quota counts retained rows
  only, and rows below the watermark are compacted, so it refills every lease window
  (RTC-12; `b7_rtc12_a_never_admitted_flood_stops_at_the_floor_and_refills_after_a_lease`).
  A policy with a lower `max_enrolled_instances` still gives each instance more.

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
`92c7acd`, the broker built from kilnd `fb9034d`). The B5 root suite's final run is at
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

*Reproducible bundle* (kiln-guest `92c7acd`, both builds):

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
kiln-guest `92c7acd`) found three HIGH, six MEDIUM and one LOW defect. Stephen's rule
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

*Re-pinned bundle* (kiln-guest `ba890f8`, broker from kilnd `71fe6c4`, archive
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
unit are its own. Either flag alone is refused. (As first built, "its own" only checked
the names in the file; since the B6 break-it corrections they are compared with what the
process observably is, and only a build with the `firecracker-test-deployment` feature
has either flag: B6-BI-01 below.) The other half of the gate is unchanged:
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
process, with the re-pinned production bundle (kiln-guest `ba890f8`, broker `35fad74f…`),
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
| Nothing regressed | B5's real-chain suite 8/8 in 668 s (at `9c88e9a`; the later commits change only `main.rs`'s backend selection, docs and lexical tests); B4's 31/31 in 1,416 s plus the core's capability-drop test, and the session again, at `b0ef982`; Mac tests and clippy on Rust 1.88 and 1.99, the gate tests, the maintenance tests and CI green |

The station restart at 19:26 UTC stopped the managed VM during the first B4 run (14 minutes of uptime, not the two-hour death below). The B5 suite had already passed; nothing non-main had been installed, `/var/lib/kilnd/kilnd.db` kept its digest, no build file was truncated, and B4 and the session were rerun. Separately, at 18:44 UTC the idle VM died at 2 h 02 m of uptime, as twice before: launchd reports the Virtualization service "exited due to exit(0), ran for 7339719ms", and the guest kernel logged nothing. That points to a host-side limit near two hours rather than nested-Firecracker load; VM phases are now kept under two hours from a fresh restart.

### Milestone 2: recovery and section 10 on the real chain

Milestone 2 runs every remaining B6 exit criterion through real daemons and `kilndctl`.
The harness in `tests/session.rs` (`Deployment`, `Daemon`) builds the isolated test
deployment for any number of daemons. Each has its own `kilnd-<name>` account, transient
unit with `kilnd@.service`'s hardening, state directory and root enrollment, all against
one real helper. `tests/recovery.rs` holds the scenarios. `scripts/firecracker-crash-matrix.py`
and `scripts/firecracker-regressions.py` run each one alone through `scripts/b4-vm-tests.sh`,
which cleans the host before and after, and collect a `B6 matrix:` line per scenario into
`matrix.json` and `matrix.md`. A scenario that is missing, fails or reports nothing fails
the script, and `b6_scenario_names_match_the_scripts` keeps the scripts' lists and the
tests in step. The scripts refuse to start past 90 minutes of VM uptime.

*Two defects the real chain found.*

- **A dropped POSIX lock let another reader unlink the daemon's live WAL.** `Store::open`
  (since `7c3cd14`, so also on main `b58d94a` and in the installed `734e275`, where
  Daybreak demonstrated the loss: B6-BI-02 below) checked the database's and its sidecars' owner,
  mode and link count by opening and closing its own descriptors, some after SQLite had
  opened them. Closing any descriptor to a file drops every POSIX lock the process holds
  on it, SQLite's included. Another process's connection, such as an operator's `sqlite3`,
  a backup or this harness's root reader, could then take the database's exclusive lock,
  believe itself the last connection, checkpoint and unlink the WAL and shared memory
  under the live daemon. Everything the daemon committed afterwards went to an unlinked
  file: it saw its own writes, nobody else did, and a crash lost them. The crash matrix
  saw a SIGKILLed daemon return without an execution row it had committed, and a
  root reader still see a row as `ready` after Delete had committed `deleting`. Fix:
  entries are only `fstatat`ed beneath the held directory with `AT_SYMLINK_NOFOLLOW`, never
  opened, and a new database is created by kilnd itself (`O_CREAT|O_EXCL|O_NOFOLLOW`,
  0600) and closed before SQLite opens it, so SQLite's sidecars inherit 0600. Test:
  `store::tests::another_process_never_unlinks_the_live_wal` reads from a separate
  process (POSIX locks belong to a process), and fails on the old code.
- **A session no supervisor owns was refused as reusable.** After a helper restart, the
  new helper adopts the old supervisor only as an orphan to watch, and Exec on that
  allocation is refused before anything is journaled or sent. B5 answered every such
  refusal `reusable: true`, so the daemon kept the row READY and kept sending commands.
  Now a refusal because the session can never run a command again (fenced, stopped,
  unsupervised, booted again, supervisor gone) is `reusable: false` with
  `no_child_started`, and the daemon quarantines the row, still charged, for Delete.
  Another execution in flight stays a transient, reusable refusal. Test:
  `exec::tests::b6_an_unsupervised_session_is_refused_and_not_reusable`.

*The B5 recheck follow-ups.*

- **B5-R1:** `fence_flow`'s Lookup, never-admitted quota check, `SettleUnstarted`,
  pending-record flush and Fence all stop waiting at the request's own deadline
  (`ledger_until`), so a stalled L ends the attempt charged and ambiguous. The detached
  task then gives its slot and any removing claim back, and a later attempt can make
  progress. The flush is cancel-safe: a record in flight when the flush is dropped goes
  back to the front of the queue, and L may then see it twice, as after any unanswered
  call. The Fence commit after a dropped wait may still land; the next attempt answers
  with that fence. Tests: `b5_r1_a_stalled_ledger_fence_gives_back_its_detached_slot`
  (the recheck's PoC as a fixture test, which fails without the bound) and, through the
  daemon, `b6_linux_root_attack_a_stalled_ledger_fence_never_holds_remove`.
- **B5-R2:** settlement compacts too, so exactly eight settled cleanup-worker rows remain,
  as section 7.4 says, even when rows settle out of order. Unsettled and node-level rows
  are never removed (`b5_01_stop_reasons_and_cleanup_workers_are_bounded`).

*Decisions made here.*

- **A capacity refusal is RESOURCE_EXHAUSTED.** A C2 refusal for capacity now carries
  that in `CreateFailure` (`exhausted`), still ambiguous and released only by its fence,
  and Create answers RESOURCE_EXHAUSTED after the fence settles (section 9.2). A Delete
  whose proof is blocked still answers INTERNAL with a "stays charged" message: the row
  and the node stay charged and the text says so, but kilnd's API has no UNAVAILABLE
  code for it yet. That mapping is left for B7.
- **A C0 refusal is an honest answer to a full node.** When the node is full, or both of
  P's node-wide slots are busy (section 6.4), Preflight refuses with no row and no
  reservation. Only a refusal after C1 needs its fence. The scenarios accept either, and
  the matrix records which one happened.
- **A helper restart never resumes a session.** The restarted helper replays every claim
  and watches the old supervisor as an orphan, but never adopts it as a supervisor. The
  daemon learns that at its next Exec (quarantine), and Delete stops and removes by exact
  token as for any allocation.
- **Recovery by allocation stays in the runtime.** Section 9.1's split holds. The manager
  inspects, removes or fences exact tokens, and `FirecrackerRuntime` decides how. Its
  `fence_absent` removes a journaled token first, because the manager reaches it for any
  Unknown observation (a stop still in progress, a boot).

*How each section 4.5 row is covered on the real chain.*

| Section 4.5 row | Scenario | Result |
|---|---|---|
| Post-C1 failure before INTENT; a queued duplicate | `crash_daemon_death_before_c2_…`: kilnd dies with its Create held before C2 | The restarted daemon fences the never-admitted token and releases the row with that fence; the held Create then finds the fence and allocates nothing |
| Capacity commits, reply lost | `crash_capacity_commit_reply_lost_…`: L dies right after the C2 commit | One claim survives L's death and a helper restart, never a second; the row stays charged until Delete's ABSENT |
| H dies (READY session) | `crash_helper_restart_keeps_every_claim` | S killed the VM when H died (the old VMM is gone); the new helper replays the one claim, its journal phase still `ready`; the next Exec is refused as not reusable and the row quarantined, never READY again; Delete reaches ABSENT |
| H or the daemon dies during BUSY | `crash_daemon_death_mid_execution_…` | The disconnect retires the VM; the helper's phase is `stop_intent` and its Inspect stays Unknown until STOPPED, so the restarted daemon publishes the execution `failed` with unknown cleanup and the row quarantined (section 8.3's "or cleanup failure/QUARANTINED"), never READY; no command replays; Delete releases |
| Daemon dies while booting | `crash_daemon_death_while_booting_…` | The restarted daemon adopts exactly that READY boot (C6); one allocation, no second VM |
| Cleanup finishes but ABSENT's sync fails | `crash_absent_sync_failure_…` | Delete errors; both ledgers stay charged; a retry commits ABSENT |
| ABSENT commits, the daemon's terminal commit is lost | `crash_absent_committed_but_publication_lost_…` | The helper's claim is released; the row stays DELETING and charged until the restarted daemon replays the receipt |
| Daemon database restored or stale; the node ledger survives | `crash_restored_stale_db_…` (two daemons) | The stale daemon blocks its own admission; the node keeps the charge; the other daemon's Health shows the node's count, and its second Create is refused |
| Daemon database lost | `crash_lost_db_…` (two daemons) | The new database is another instance, which the helper refuses; the lost daemon's claim and VM stay; the other daemon gets no slot; restoring the database restores control |

Section 10.2's other items: item 15's two-daemon race and the disk and vCPU
exhaustion (`attack_two_daemons_race_…`, `attack_disk_and_vcpu_exhaustion_…`);
section 4.1's one live holder against a byte copy of the daemon's files from the enrolled
unit's own cgroup (`attack_duplicate_instance_attachment_…`); item 13's simultaneous
hostile I/O beside real Create, Health, Get, Exec and Delete (`attack_hostile_io_…`); and
quarantine with blocked proof (`attack_quarantine_stays_deletable_…`: both K slots
stalled, a timed-out execution can't prove the VM gone, the sandbox is quarantined and
charged, Delete errors until K recovers, then reaches ABSENT).

### Milestone 2 exit evidence

All in the `kiln` Lima VM under the managed `kiln-vm` process, restarted at 21:04 UTC
for a fresh window, with the inputs of milestone 1 (the approved jailer and `mkfs.xfs`,
release Firecracker v1.17.0, kiln-guest `ba890f8`'s bundle with broker `35fad74f…`).
Matrices, transcripts and daemon and helper logs are in `reviews/2026-11-03-b6-vm/m2-final/`.

| B6 exit criterion | Evidence |
|---|---|
| Section 10 attacks on the actual chain | `firecracker-regressions.py`: 7/7 (the session, the race, exhaustion, duplicate attachment, hostile I/O, the stalled fence, quarantine) |
| Two-daemon race | Two sessions first, then the last two Creates together: exactly three allocations reach INTENT; the loser is FAILED and released by its own fence (`refused_after_c1`, receipt in `retired_tokens`); claims return to 0 after cleanup. Four simultaneous Creates instead mostly end at C0 for P's two slots, with no row |
| Full global-ledger crash matrix | `firecracker-crash-matrix.py`: 9/9 (the table above) |
| Disk and vCPU exhaustion never oversubscribe | One session per dimension's ceiling; the second is refused at C2 (`node capacity exhausted: Disk` and `VirtualCpu`), released by its fence; claims never exceed 1 |
| Duplicate attachments | A byte copy of the serving daemon's files, the enrolled account and image, from inside the enrolled unit's own cgroup and from outside it: both `another live holder has this instance`; the daemon kept serving |
| A surviving node ledger never discounts a lost daemon | Stale and lost databases: the node keeps the claim and the lost daemon's VM; the other daemon's Health shows the node's count and its next Create is refused (released by its fence) |
| B5's hostile I/O with real lifecycle requests | Two hostile relays and a console flood beside a real daemon: worst Create 14.38 s (120 s budget), Health 8.8 ms, Get 3.8 ms, Exec 76.9 ms (60 s), Delete 127 ms (60 s); hostile cgroups' memory [659,456, 487,424, 147,456] → [397,312, 258,048, 147,456] bytes; helper RSS 20,292 → 21,476 KiB; 806 endless-frame and 10 silent-peer jobs each ended at its bound; 2.9 GB of console drained with one rate report |
| No reservation freed while a VM, disk or worker may exist | Every scenario's release is checked the same way: helper phase `absent`, claim released, the retired token's receipt equal to the row's `release_evidence_id`, no host leftover; before Delete, a retired VM's disk, jail and cgroup and its claim remain |
| Quarantine controllable through Delete; honest Unknown | Both K slots stalled: a timed-out execution can't prove the VM gone, so it is `failed` with unknown cleanup and the row quarantined; Delete then errors ("the fence deadline expired; the allocation stays charged"), the row DELETING and charged; once K recovers, Delete reaches ABSENT |
| B5-R1 and B5-R2 | The stalled-fence Delete answered in 60.0 s with the detached slot and removing claim already free while L was still stalled; the next Delete reached ABSENT. The fixture test fails without the bound. Exactly eight settled worker rows |
| The gate | No new destructive call: `Store::open` now only `fstatat`s and creates; clippy with `-D clippy::disallowed_methods` on Rust 1.88 and 1.99 (macOS and Linux) and the gate tests pass |
| Nothing regressed | At `0046a8e`: B5's real-chain suite 8/8 (661 s) and B4's 31/31 (1,380 s) plus the core's capability-drop test. At the head `a2473a7`: Linux clippy, the session, the race and both exhaustion cases again (now RESOURCE_EXHAUSTED); then `install.sh` and the installed suites (`integration-test.sh` with its admission stress, the singleton, state-path and Phase 0 regressions, `smoke.sh`, the maintenance tests) all pass. The first state-path run, at `5555d16`, failed only on the symlink diagnostic's wording, restored in `a2473a7`. `/var/lib/kilnd` was byte-copied before and restored afterwards (`cmp` identical, schema 7, `quick_check` ok) under the reinstalled `734e275` |

The managed VM was restarted before each long phase (21:04 and 21:52 UTC) and never died
during milestone 2. Milestone 1's evidence records its earlier interruptions.

## B6 break-it corrections (November 3, 2026)

Daybreak Blue reviewed `phase1b/b6-lifecycle` at `1973a14`
(`reviews/2026-11-03-b6-breakit.md`, PoCs in `reviews/poc-b6/`): REJECT on one HIGH,
with a HIGH operational exposure on main and two MEDIUM follow-ups. All four are
answered here; B6-BI-03 is scheduled for B7.

*B6-BI-01 (HIGH): the isolated deployment's identity was only declared.* The daemon
compared the manifest's paths with its flags, but its account, socket group and unit only
had to look non-production. A release `kilnd` running as the developer's own login account, with
`--socket-group staff`, outside any unit, selected `FirecrackerRuntime` for a manifest
naming `kilnd-fctest-manifest-only` for all three. Two fixes, either sufficient:

- *Observed identity.* `TestDeployment::check_process`, called in `selected_deployment`
  right after the path check and before `Store::open`, the socket bind or any runtime,
  resolves the manifest account with `getpwnam` and its group with `getgrnam` (both must
  exist), then compares them with what the kernel reports: the real, effective and saved
  UIDs (`getresuid`) must all be the account's UID, which is never 0 or the production
  `kilnd` account's; the resolved CLI `--socket-group` GID must be the manifest group's,
  never the production `kilnd` group's (an empty `--socket-group` is refused); and this
  process's own `<pid>/cgroup`, read through `sys::procfs` (the private procfs instance,
  or `/proc` for an unprivileged process, as everywhere else) must be exactly one cgroup
  v2 line whose path's last component is the manifest unit (`…/kilnd-fctest.service`).
  Every mismatch is collected and named in one refusal. The comparison is a pure function
  over `Resolved` and `Observed` (`test_deployment::tests::b6_bi_01_*`). The real
  session test found that `kilnd@.service`'s `RestrictSUIDSGID=` makes systemd answer
  `openat2` with `ENOSYS` (it cannot filter the mode argument), so `sys::procfs::open`
  now falls back, for an unprivileged process and on `ENOSYS` only, to opening one
  component at a time with `O_NOFOLLOW`, each checked to be on procfs (`fstatfs`); root
  keeps `openat2` with `RESOLVE_BENEATH|NO_SYMLINKS|NO_MAGICLINKS|NO_XDEV`
  (`sys::tests::the_component_walk_reads_what_openat2_reads`).
- *Build boundary.* `kilnd`'s new cargo feature `firecracker-test-deployment` is not a
  default. Without it, `Backend` has no `Firecracker` value, `Args` has no
  `--firecracker-test-deployment` field, `selected_deployment` can select only kiln (its
  other type is `Infallible`), and `FirecrackerRuntime` is not even imported, so a
  release or installed build refuses both flags at argument parsing (clap's usage error,
  exit 2) and cannot construct the runtime. `scripts/b4-vm-tests.sh` builds the B6 test
  daemon with the feature; nothing else does. The lexical gate tests
  (`exit1_production_gate_leaves_every_catalog_profile_refused`,
  `production_stays_disabled_without_the_broker`) now also require `check_process`
  after `check_daemon`, every Firecracker name in `main.rs` behind the feature, and the
  feature absent from `default`.

Regressions: `scripts/test-deployment-gate-regressions.sh` turns Daybreak's PoC into
three modes. `release` runs the PoC command and each flag alone against a default build
and requires clap's refusal, no Firecracker selection and no state; CI runs it after
`cargo build --release`. `feature` runs the PoC against a feature build, with the PoC's
unresolvable names and again with resolvable ones (`nobody`, `nogroup`), and requires the
named refusal; CI's new `feature` job runs it with the feature's tests and clippy on both
toolchains. `root` (in the VM) creates the account `kilnd-fcgate` and runs the feature
build with `systemd-run` as that account in `kilnd-fcgate.service`: the matching identity
is selected (the control), and a wrong account, a wrong `--socket-group`, a wrong unit
and no unit at all (`setpriv`) are each refused on their own, naming only that mismatch,
before any state exists. The whole B6 session test still runs as `kilnd-fctest` in
`kilnd-fctest.service`.

*B6-BI-02 (HIGH operational exposure): the WAL lock-drop bug is on main and installed.*
The milestone-2 note above said the `Store::open` defect was never on main or installed.
That was wrong: it came with `7c3cd14` and is on main `b58d94a` and in the installed
`734e275`, and Daybreak's `reviews/poc-b6/store-wal-lock-drop.py` lost a committed row
there on Linux. `1089aab` on this branch fixes it (Daybreak assessed the fix as sound).
**Until main carries `1089aab` and the installed build is replaced, nobody opens the live
`/var/lib/kilnd/kilnd.db` with `sqlite3` (or any other SQLite client) while the daemon
runs; inspect only stopped byte copies.** Updating main is the roadmap lead's.

*B6-BI-03 (MEDIUM): idle public sockets starve ingress.* Not fixed in B6: it is B7
follow-up 5 above (a reserved ingress slot for Health and cleanup, per-UID connection and
RPC shares after peer credentials).

*B6-BI-04 (MEDIUM): two crash interleavings were missing.* The matrix now has 11
scenarios (`scripts/firecracker-crash-matrix.py`, `tests/recovery.rs`):

| Interleaving | Scenario | What it proves |
|---|---|---|
| H restarts after C2 while the public Create polls for READY | `crash_helper_restart_while_create_polls_never_publishes_ready` | Killed at BOOTING, before S journaled the broker's handshake; the old VMM is gone; the new helper replays one claim; while the Create polls the row is CREATING and charged on both ledgers; the Create fails (no READY, no broker record, one allocation); the claim is released only by the token's ABSENT receipt, which the row's `release_evidence_id` names |
| kilnd dies mid-Remove, after the helper owns it and before ABSENT | `crash_daemon_death_mid_remove_stays_charged_until_absent` | Held at `H.remove.after_state` in the helper's detached Remove; after the kill, after a restart whose reconciliation meets the removal still held, and after the old removal resumes for a daemon that is gone, the row stays DELETING and charged and the claim unreleased; the next start's reconciliation settles it from the matching ABSENT receipt |

In the first interleaving the release came from the failed Create's own settlement by
exact token, not from a later Delete: the Create waits out its 120 s deadline (the new
helper reports the orphaned boot as still `booting` without a fresh supervisor
observation), publishes FAILED and charged, and its `settle_fenced` removes the token
through the new helper and commits the ABSENT receipt. Delete then finds the row released.
The claim was charged on both ledgers for the whole polling window. In the second, the
old removal resumed for a dead daemon's epoch and did nothing (phase still `ready`), so
only the restarted daemon's reconciliation produced ABSENT.

The existing `crash_capacity_commit_reply_lost_keeps_one_claim` failed once in its first
VM run here: when H has already replaced the dead L, the failed Create's immediate
settlement can prove the never-launched allocation absent and release the row with the
token's own receipt, which the scenario had treated as a failure. That is the design's
behavior, so the scenario now accepts either path and asserts one claim, never a second,
released only by the matching receipt (it took the immediate path in 2 of 4 runs).

*Evidence (VM, November 3–4).* In the `kiln` Lima VM under the managed `kiln-vm`
process, restarted at 03:18 UTC for a fresh window, at `7474f4f`, with the approved
jailer `42e9dea3…` and `mkfs.xfs` `9571cecc…` rebuilt by `build-phase1b-tools.sh`,
release Firecracker v1.17.0 `fe726e0b…` and kiln-guest `ba890f8`'s bundle (broker
`35fad74f…`): `test-deployment-gate-regressions.sh` release, feature and root all pass,
and Daybreak's PoC no longer selects Firecracker from either build; the whole session
through kilnd and kilndctl as `kilnd-fctest` in `kilnd-fctest.service` passes;
`firecracker-crash-matrix.py` 11/11; `firecracker-regressions.py` 7/7; B5's
`b5_linux_root` 8/8 (862 s). B4's `b4_linux_root` (not required: no B4 code changed)
passed 30 of 31: `b4_linux_root_cleanup_refuses_a_foreign_backing_loop_replacement`
failed in its third phase on a Prepare's 10 s request deadline, again on a rerun at
`cc79d7b`, then passed at `cc79d7b` and at `1973a14`, so it is timing-flaky on this VM
rather than changed by these commits. `cc79d7b` after `7474f4f` only moves a test module
in `sys.rs` (the destructive-call gate stops scanning a file at its test module). Linux
clippy (`-D warnings -D clippy::disallowed_methods`, Rust 1.88 and 1.99, default and
feature builds) is clean, and CI's `check` and `feature` jobs are green. Logs, matrices
and transcripts are in `reviews/2026-11-03-b6-fixes-vm/`. Before the phase,
`/var/lib/kilnd` was byte-copied with the installed `734e275` daemon stopped; afterwards
it was restored, `cmp` found `kilnd.db` and `kilnd.lock` identical, a stopped copy is
schema 7 with `quick_check` ok, and the installed binaries' hashes are unchanged.

## B7 milestone 2: hardening follow-ups (November 4, 2026)

Milestone 2 of B7 closes section 11's five B7 follow-ups (B4 recheck 6 items 1 to 4 and
B6-BI-03) and the three LOW items of the B6 recheck (`reviews/2026-11-04-b6-recheck.md`,
B6-RC-01 to B6-RC-03), each with a regression test. Milestone 1, retired-token compaction
(section 16), is separate work on `phase1b/b7-compaction`. Production Firecracker stays
disabled.

### Ingress fairness (B6-BI-03, MEDIUM)

Daybreak's PoC held all 64 connection slots with idle sockets that never sent an HTTP/2
preface; a new Health, Get or Delete connection was closed before authorization or
Health's reserved RPC lane could help. Admission (`admission.rs`) now splits each shared
budget by the caller's kernel UID:

- *Reserved connection slots.* `--reserved-connections` (default 4) of the
  `--max-connections` slots are held back from the general pool. A connection takes a
  general slot while its UID holds fewer than `--max-connections-per-uid` (default 32,
  half the general pool), otherwise one reserved slot, at most one per UID, otherwise the
  socket is closed at accept. A reserved-slot connection carries its lane in
  `PeerIdentity` and serves only Health, GetSandbox and DeleteSandbox; Create, List, Exec
  and GetExecution on it are `RESOURCE_EXHAUSTED`. The UID comes from `SO_PEERCRED`,
  read once, before any byte, with one `getsockopt`; unavailable credentials share one
  bucket (and every RPC but Health from them is still `UNAUTHENTICATED`). There is no
  public Gc RPC: garbage collection is manager-owned, so the cleanup set is Get and
  Delete.
- *Per-UID RPC shares and a cleanup lane.* An ordinary RPC needs a global permit and room
  in its UID's `--max-concurrent-rpcs-per-uid` share (default 32 of 64). GetSandbox and
  DeleteSandbox try that lane first and, when it refuses, take one of the
  `--max-concurrent-cleanup` permits (default 4, at most one per UID). Health keeps its
  own four. Each share's check and increment happen under one lock, so concurrent
  callers of one UID never overshoot it. Health exposes the existing totals; the new
  per-lane counters are internal (`AdmissionSnapshot`), so `kilnd.v1` is unchanged.
- *Preface deadline.* `AdmittedUnixStream` fails its next read once
  `--connection-preface-timeout-ms` (default 5000, 100 to 60000) passes before the
  24-byte HTTP/2 client preface has arrived. The deadline is polled with every read, so
  a socket that sends nothing is woken for it, and the transport then closes the
  connection and drops its slot. A slow drip of 23 bytes gets the same deadline.

- *Strict invariants (B7 milestone 2 break-it, HIGH-2).* `admission::validate_ingress`
  refuses to start unless `--reserved-connections` is at least 1 and below
  `--max-connections`; `--max-connections-per-uid` is strictly below the general pool
  (`--max-connections` minus `--reserved-connections`); that share plus the UID's one
  reserved slot is strictly below `--max-connections`; `--max-concurrent-rpcs-per-uid`
  is strictly below `--max-concurrent-rpcs`; and `--max-concurrent-cleanup` is at least
  1. Equality is refused: Daybreak's accepted `33/1/32` let one UID hold all 32 general
  slots and the only reserved one.
- *Root's slot (B7 milestone 2 break-it, MEDIUM-2).* Beyond `--max-connections`, one
  connection slot only UID 0 may take, after the general and reserved slots refuse it,
  and one RPC permit only UID 0 may use for Health, GetSandbox and DeleteSandbox after
  their own lanes refuse it. A connection on it serves those three RPCs only. So the
  operator always reaches Health and cleanup.

Residual: a client that sends the preface may then idle on its slot (bounded by its UID's
share). The reserve is first-come and bounded per UID, not per caller: colluding UIDs can
hold all of it (four UIDs holding 33, 29, 1 and 1 connections at the defaults take every
slot), as the threat model accepts colluding UIDs filling shared capacity; a further
non-root UID is then refused, and root alone still gets Health, Get and Delete on its
own slot. Tests:
`admission::tests::b7_one_uid_cannot_exhaust_connections`,
`b7_rpc_shares_and_the_cleanup_lane`, `b7_shares_hold_under_concurrent_callers`;
`service::tests::b7_rpc_shares_cleanup_lane_and_reserved_connections`;
`server::tests::b7_idle_sockets_are_dropped_at_the_preface_deadline` (fails without the
deadline: the idle sockets outlive it) and `b7_a_reserved_slot_serves_health_and_cleanup_only`
on the real transport. The real-daemon regression is
`scripts/hostile-public-caller.py`, Daybreak's PoC made harder: as root it starts a
hostile caller under another UID (`nobody` with the socket's group as its one
supplementary group), which keeps 64 idle sockets open for the whole victim phase and
reconnects each one the daemon closes; while that runs, Health, GetSandbox and
DeleteSandbox as root must each succeed within 5, 5 and 60 s; afterwards every hostile
socket must have been closed by the daemon, none living past the preface deadline plus
3 s, and at least one must have held its slot until about the deadline (so the victim's
success is not a failed attack). It runs against the installed daemon and, as the new
`b7_linux_root_attack_hostile_public_caller_cannot_starve_health_or_cleanup` in
`scripts/firecracker-regressions.py`, against the Firecracker test deployment's daemon
with a READY session that the Delete then releases with its ABSENT receipt.

### Socket file handles fail closed (B4 recheck 6 item 1, MEDIUM)

`sys::socket` no longer turns `name_to_handle_at`'s `EOPNOTSUPP` into the all-zero
handle. A socket filesystem that exports no handle is refused (`ErrorKind::Unsupported`,
"cannot export file handles"), so `server::bind` fails rather than keep a socket whose
generation is device, inode and birth time alone; a zero-length or oversized handle is
an error too. The handle is read before the birth-time check, so ramfs (which lacks
both) is refused by name. Rejecting outright was chosen over a filesystem allowlist:
kilnd's socket directories are tmpfs (`/run`), ext4 or XFS, all of which export handles.
Tests: `sys::tests::b7_a_socket_filesystem_without_file_handles_is_refused` (the errno
mapping, every platform) and, as root in a private mount namespace on a real ramfs,
`b7_linux_root_sys_a_ramfs_socket_has_no_generation_and_is_refused`.

### The dependency gate (B4 recheck 6 item 2, LOW)

Section 7.1's *The dependency gate*: `dependency-gate.json`, checked against `Cargo.lock`,
the manifests and `clippy.toml` on every `cargo test` (so in CI). The B7 milestone 2
break-it replaced its Cargo.lock inference with reviewed capability decisions; see the
corrections below.

### One procfs root (B4 recheck 6 item 3, LOW)

`sys::procfs::root` now goes through `sys::RootCache`, one mutex over the cached
descriptor and its unique mount ID: the identity check and, at most once, the creation
happen under it, so concurrent first callers make exactly one private procfs instance and
none leaks. A cached descriptor whose identity no longer reads (a forked worker closed it,
or the number was reused) is replaced and never closed, as before. Workers fork only from
single-threaded processes, so no child inherits the mutex held. Test:
`sys::tests::b7_concurrent_first_callers_make_exactly_one_procfs_root` (16 callers behind
a barrier with a slowed creation: one creation, one shared answer; replacement once
stale; a failed creation caches nothing).

### Directory listings read their own file description (B4 recheck 6 item 4, LOW)

`sys::read_dir_fd` lists `openat(fd, ".", O_RDONLY|O_DIRECTORY|O_CLOEXEC)`, a fresh open
file description of the held directory, instead of an `F_DUPFD_CLOEXEC` duplicate
rewound with `lseek`. `.` resolves to the descriptor's own mount and dentry, so the
listing is still fd-native, and reading from offset 0 no longer moves the caller's
offset. Test: `sys::tests::b7_read_dir_fd_leaves_the_callers_offset_alone` (a partly read
200-entry directory keeps its offset, the listing is whole, and an `O_PATH` descriptor,
as the helper holds, lists the same).

### The B6 recheck's LOW items

- *B6-RC-01: procfs fallback redirection.* The unprivileged `ENOSYS` component walk
  (`sys::procfs::open_by_components`) now also compares every component's unique mount
  ID with the procfs root's. A bind mount of another process's `/proc/<pid>` over this
  one's is on the same procfs superblock, so `fstatfs` cannot see it, but it is a new
  mount with a new ID, so the walk is refused ("crosses a mount"), restoring
  `RESOLVE_NO_XDEV`'s meaning. Cheap (one `statx` per component, on the kernels the
  walk already requires); the attack still needs root control of the daemon's own mount
  namespace, which is in its TCB. Tests:
  `sys::tests::the_component_walk_reads_what_openat2_reads` (a wrong root ID is refused)
  and, as root, `b7_linux_root_sys_the_component_walk_refuses_a_bind_mounted_procfs_directory`
  (the PoC's bind mount in a private namespace, with an unredirected control).
- *B6-RC-02: unit basename under another slice.* The test deployment's schema is now
  `kilnd-firecracker-test-deployment/2`, which adds `kilnd.cgroup`, the unit's whole
  cgroup path (`/system.slice/kilnd-fctest.service` for the checked-in file). It must be
  absolute, normal, below a slice and end in the unit; the daemon's own cgroup must equal
  it exactly. The session harness enrolls that same path with the helper. Tests:
  `test_deployment::tests::b6_bi_01_identity_is_observed_not_declared` (the recheck's
  `/b6.slice/b6-recheck.slice/kilnd-fctest.service`, and a user service's cgroup, are
  refused), `production_paths_names_and_other_kinds_are_refused` (bad `cgroup` values and
  schema 1), and `scripts/test-deployment-gate-regressions.sh root`'s new case: the right
  unit under `b7gate.slice` is refused.
- *B6-RC-03: nondeterministic capacity coverage.* A test-only hold at H's Inspect entry
  (`H.inspect`, compiled only into the test helper) holds a failed Create's settlement
  at its first look. `b6_linux_root_crash_capacity_commit_reply_lost_keeps_one_claim` now
  runs both settle paths on every run: first H is killed and restarted while the
  settlement is held, so it fails, the row stays FAILED and charged, the restarted
  helper replays exactly one claim and only Delete's ABSENT receipt releases it; then a
  second Create's settlement is held until the census shows H's replacement L, so the
  failed Create's own settlement proves the token absent and releases the row with that
  receipt.

### Debug-build hashing

The VM runs found the test helper no longer starting within its fixtures' 30-second wait,
on main `1c107f9` as on this branch: H hashes its own image (the 71 MiB stripped debug
test binary) and every approved artifact at start, and unoptimized `sha2` (its portable
code, since the crate's `asm` feature is off) hashes about 5 MiB/s on the VM (71 MiB in
13.9 s, 0.68 s at opt-level 3). The workspace `Cargo.toml` now builds `sha2` at
opt-level 3 in dev and test profiles only (`[profile.dev.package.sha2]`); release builds,
dependencies and `Cargo.lock` are unchanged.

### Files shared with milestone 1

`helper/firecracker/mod.rs` gains only the five-line test hold above, `manager.rs` only
the five new `Limits` fields and their defaults, and the workspace `Cargo.toml` only the
`sha2` profile override. Everything else is in `sys.rs`,
`server.rs`, `service.rs`, `admission.rs`, `main.rs`, `test_deployment.rs`, the gate
(`proven.rs` tests, `dependency-gate.json`), the B6 test harness (`tests/session.rs`,
`tests/recovery.rs`), scripts and docs.

### Evidence

Branch `phase1b/b7-hardening` from main `1c107f9`: `51d1733` (the code), `0147703` (a
needless borrow clippy 1.88 found on Linux), `ddafe5d` (the `sha2` profile) and the
documentation commit after it.

- *macOS.* `cargo test --locked --workspace`, default and `firecracker-test-deployment`
  features: every test passes (kilnd lib 496 passed, 3 ignored). `cargo clippy --locked
  --all-targets -- -D warnings -D clippy::disallowed_methods` on Rust 1.88 and 1.99,
  both feature sets: clean. The gate tests, the new dependency gate included, pass;
  `git diff --check` and `scripts/kilnd-maintenance-tests.py` pass. Mutation check: with
  the preface deadline removed, `b7_idle_sockets_are_dropped_at_the_preface_deadline`
  fails ("an idle socket outlived the preface deadline").
- *CI.* Green on `0147703` (run 41958571713) and `ddafe5d` (run 41969039008): both jobs,
  tests and clippy on 1.88 and 1.99, default and feature. The first push failed only that
  needless borrow.
- *VM, Linux unit tests* (`0147703`, `umask 022`). Default and feature
  `cargo test --locked --workspace --no-fail-fast`: everything passes (kilnd lib 505
  passed, 77 ignored) except the untouched `kilnd-broker-protocol` timing test
  `wide_objects_check_in_well_under_quadratic_time`, whose 200 ms bound the VM's debug
  build misses (211 to 226 ms alone; main `1c107f9` in the same VM: 180, 180 and 200.5 ms,
  one failure in three). The new root tests (`b7_linux_root_sys_*`, run with `sudo`):
  2/2 passed.
- *VM, gate regressions.* `scripts/test-deployment-gate-regressions.sh feature` and `root`
  against a feature build: all checks passed, the new slice case refused with "runs in
  cgroup /b7gate.slice/kilnd-fcgate.service, not in unit "kilnd-fcgate.service" at
  /system.slice/kilnd-fcgate.service".
- *VM, real chain* (`ddafe5d`, with jailer and mkfs.xfs rebuilt by
  `scripts/build-phase1b-tools.sh` at their approved digests, the Firecracker v1.17.0
  release at `fe726e0b…`, and `bundle-a` rebuilt from kiln-guest `ba890f8` with broker
  `35fad74f…`). `scripts/firecracker-regressions.py`: **8/8 passed**, the whole session
  and the new hostile public caller included; under the attack the hostile UID opened and
  had closed 798,341 sockets, held 66 to the 5-second deadline (none longer than 5.003 s,
  none left open), while Health, Get and Delete answered in 3 ms, 1 ms and 116 ms and the
  Delete released the session with its ABSENT receipt. `scripts/firecracker-crash-matrix.py`:
  **11/11 passed**; the capacity scenario reported both paths, and three more runs of it
  alone each reported both again.
- *VM, installed daemon* (`ddafe5d` installed with `scripts/install.sh`): Linux clippy
  (both feature sets) clean, `scripts/integration-test.sh`,
  `scripts/daemon-singleton-regressions.sh`, `scripts/state-path-regressions.sh`,
  `sudo python3 -I scripts/phase0-regressions.py`, `scripts/smoke.sh`,
  `scripts/kilnd-maintenance-tests.py` and `scripts/hostile-public-caller.py` against
  `/run/kilnd/kilnd.sock` all passed; the hostile caller there held 66 sockets to the
  deadline (longest 5.004 s), none left, while Health, Get and Delete succeeded.
- *Installed state.* Before installing, with kilnd stopped, `/var/lib/kilnd` and the
  installed binaries were byte-copied and `cmp` found `kilnd.db`, `kilnd.lock` and the
  three binaries identical; a copy reported schema 10 and `quick_check` ok (the live
  database was never opened with `sqlite3`). Afterwards main `2a1faea` was reinstalled,
  whose rebuilt binaries `cmp` identical to the pre-phase copies, the state was restored
  and `cmp` found `kilnd.db` and `kilnd.lock` identical, and the daemon served with no
  test account, unit, mount, cgroup, VMM or path left.

Logs, matrices and transcripts are in `reviews/2026-11-04-b7-m2-vm/`. The first real-chain
attempt, before the `sha2` profile, failed every scenario at "timed out waiting: the
helper listens" on this branch and on main alike (`phase2/debug-session-main*.log`);
a `gdb` sample showed H in `sha2::sha256::soft` under `verify_self_image`.

## B7 milestone 2 break-it corrections (November 5, 2026)

Daybreak Blue's break-it review of milestone 2 at `01cc7bc`
(`reviews/2026-11-05-b7m2-breakit.md`) returned MUST-FIX with two HIGH findings, two
MEDIUM and two LOW. All six are accepted and corrected on `phase1b/b7-hardening`; none is
rejected. Daybreak's recheck of those fixes at `1d11ac9`
(`reviews/2026-11-05-b7m2-recheck.md`) found HIGH-1 only partly fixed; *HIGH-1 recheck*
below closes it. Production Firecracker stays disabled.

### HIGH-1: a wrapper around std passed the dependency gate

The gate inferred whether a dependency could wrap system calls from `Cargo.lock` (a raw
crate, or a direct dependency on one) and then *required* each entry's `syscalls` flag to
equal that inference. `fs-err`, a drop-in wrapper around `std::fs` that depends only on
`autocfg`, therefore had to be declared `syscalls: false` with no destructive paths, and
production could call `fs_err::remove_dir_all`, which clippy saw under the wrapper's name.
The gate now records a reviewed decision for every direct dependency (kind, capability,
reason) and never overrides it; `Cargo.lock` can only require more. A destructive-capable
category lists its destructive paths and `clippy.toml` disallows them. Two lexical checks
flag a mistaken `none`: a production path to a destructive-looking function that clippy
does not disallow (aliases, grouped imports and `extern crate ... as` resolved; a glob
import of such a crate refused), and a dependency whose own locked source reaches a
disallowed std, Tokio or libc path (the real `fs-err` 3.3.2 reaches thirteen). The recheck
showed these were narrower than this section first claimed; see *HIGH-1 recheck*. Tests: `proven::tests::dependency_gate::b7m2_an_fs_err_wrapper_declared_none_is_refused`
(Daybreak's PoC on a synthetic lockfile, manifest and source: unreviewed, `none`, aliased,
glob, `filesystem` without paths and with paths not disallowed are refused; listed and
disallowed passes, though `Cargo.lock` shows no raw crate), `the_lock_graph_requires_but_never_overrides`
and `the_dependency_gate_holds`; on the real crates, `scripts/dependency-gate-regressions.sh`
shows the gate refusing `fs-err` reviewed as `none` and, reviewed as `filesystem` with its
paths disallowed, clippy rejecting the call on Rust 1.88 and 1.99.

### HIGH-1 recheck: method and transitive wrappers

Daybreak's recheck (`reviews/poc-b7m2-recheck/`) showed that both lexical checks missed two
ordinary shapes. In the first, `method-wrapper`, reviewed `filesystem` with
`no_destructive_api`, implements an extension trait for `std::fs::File` whose `reset`
calls `self.set_len(0)`; production imports it `as _` and calls `file.reset()`. In the
second, `outer-wrapper`, reviewed `none`, re-exports the same trait from `inner-wrapper`,
a transitive package with no entry and no scanned source. Neither check could see a method
call: the source scan matched only rooted paths, read only direct dependencies, and cut each
file at its first `#[cfg(test)] mod`, so an out-of-line `mod tests;` near the top hid the
rest of the file (`smallvec`'s `lib.rs`, for one). Workspace clippy accepted both, because
it does not lint dependency bodies.

The gate now fails closed on review, not detection (section 7.1 has the model):

- *Every locked package is reviewed.* There are 144 entries, one per package in
  `Cargo.lock` outside the workspace, keyed `name@version` and pinned to the lock
  checksum and the resolved feature set, each with a kind, a capability and a written
  justification. Shared justifications are limited to packages the test proves name no
  file, process, libc or Tokio fs/process path: 78 under `pure-computation` and 15 under
  `compile-time`. A new package, a version or checksum change or a feature change fails
  until reviewed. `scripts/dependency-gate-review.py` drafted the initial entries and their
  mechanical fields; each capability and justification was written by hand.
- *Method-form sinks across the subtree.* For each `none`, `network` or
  `no_destructive_api` declaration, the whole runtime subtree's source is scanned for the
  curated method names (whatever the receiver), disallowed paths and trait impls on
  std's and Tokio's file and process types. The sources come from cargo's own resolve
  (`cargo metadata`), so the loader also reads transitive packages and libraries rooted
  outside `src/` (`fnv`'s is). Inline test modules are skipped by their braces, not by
  truncating the file, and out-of-line test files in the library directory are read too. Each hit
  needs a `sink_exceptions` entry scoped to package, version and feature set. The 22 today
  are listed with their reasons in `dependency-gate.json`.
- *The claim is narrowed.* Section 7.1 and `dependency-gate.json`'s `about` now promise
  only that no unreviewed package enters the build and that common destructive sinks in
  packages declared non-destructive are flagged for review. Wording that the backstops
  *catch* a mistaken capability is gone; identifying a destructive API is the reviewer's
  job.

Tests (synthetic, under `cargo test`):

- `b7m2_recheck_a_method_wrapper_is_refused`: Daybreak's direct case, reviewed
  `filesystem` with `no_destructive_api` or `none`, is refused for `.set_len(` and
  `impl for std::fs::File`, and the refusal drafts the scoped exception. So is the same
  shape through a lifetime-qualified reference, UFCS, an aliased module, a glob-imported
  `File` and glob-imported free functions, and each other sink name. A definition, a field, `write`, strings, comments, the
  package's own `File` and an imported non-std `File` are not hits.
- `b7m2_recheck_a_transitive_wrapper_is_refused`: the unreviewed inner package is refused,
  and the outer package's subtree reaches the inner `.set_len(`. Reviewing the inner package
  as `none` leaves both declarations refused, and missing source is refused.
- `b7m2_recheck_every_locked_package_is_reviewed`: a version bump (new version
  unreviewed, old entry stale), a checksum change, a feature change, a transitive kind the
  graph contradicts, a git dependency, the group purity check, an unknown group and a
  transitive `destructive` list.
- `b7m2_recheck_an_exception_holds_only_for_its_scope`: it holds at its exact scope.
  Another feature set, another version, another sink, another package, or no reason or
  features is refused.
- `b7m2_recheck_proc_macros_are_build_time`; `the_dependency_gate_holds` on the real
  workspace.

On the real crates, `scripts/dependency-gate-regressions.sh` uses the actual loader, cargo
and clippy, with the fixtures as vendored registry packages. The cases and their results
are under *Recheck corrections evidence* below.

### HIGH-2: accepted flags let one UID own every connection slot

`main.rs` refused a per-UID share only *above* the general pool, so
`--max-connections 33 --reserved-connections 1 --max-connections-per-uid 32` let one UID
hold all 32 general slots and the only reserved one with preface-complete idle sockets,
starving every other UID's fresh Health, Get and Delete. `admission::validate_ingress` now
holds the strict invariants (section *Ingress fairness* above) and kilnd refuses to start on
a violation, naming the flags. Tests: `admission::tests::b7m2_ingress_invariants` (each
invariant at equality and one below, and that 33/1/31 leaves another UID a general slot)
and `main`'s `b7m2_ingress_flags_are_refused_at_their_boundaries` (33/1/32 refused, 33/1/31,
64/4/59 and 3/1/1 accepted, 64/4/60, 2/1/1, 3/2/1, 3/3/1, a zero reserve, RPC 8/8 and a
zero cleanup lane refused).

### MEDIUM-1: the destructive lists were incomplete

`std::fs::copy` and `tokio::fs::copy` overwrite and truncate a destination by name;
`libc::creat` opens with `O_TRUNC`; `sigqueue`, `creat64`, `truncate64`, `ftruncate64`,
`execl`, `execle`, `execlp` and `popen` were missing too. All are disallowed now, with
`std::os::unix::process::CommandExt::exec` and every other locked libc function matching
the curated destructive patterns (`mount`, `removexattr`, `shm_unlink`, `pthread_kill`,
`reboot`, `swapoff` and other targets' names: 104 in libc 0.2.190). Completeness is now a
test rather than two hand-written lists agreeing: `every_destructive_libc_function_is_disallowed`
reads the pinned libc source, and `std_and_tokio_destructive_surfaces_are_disallowed` holds
`clippy.toml` to a curated std review and to every public `tokio::fs` function of the
locked Tokio. Gating `libc::mount` moved the jail base's two production mounts into the
typed `sys::bind_onto_itself` and `sys::make_private_recursive`. Daybreak's
`missing-methods` fixture is part of `scripts/dependency-gate-regressions.sh`: clippy
rejects both calls on 1.88 and 1.99.

### MEDIUM-2: four UIDs could consume the whole reserve

The design said the reserve still served up to four *other* UIDs after colluding UIDs
filled the general pool; four UIDs holding 33, 29, 1 and 1 connections take all 64 slots.
The claim is narrowed: the reserve is first-come and bounded per UID, consistent with the
threat model's acceptance of colluding UIDs. One connection slot and one Health/cleanup
RPC permit beyond the budget belong to UID 0, so the operator always reaches Health,
GetSandbox and DeleteSandbox. Tests: `admission::tests::b7m2_root_gets_its_slot_after_a_four_uid_fill`
(the exact fill at the defaults; a fifth UID and unknown credentials refused, root
admitted on its slot, once), `b7m2_root_keeps_one_health_and_cleanup_permit` and
`service::tests::b7m2_root_reaches_health_and_cleanup_with_every_lane_held`.

### LOW-1: build-only status was not enforced

Every entry now has a `kind` the manifests must agree with, and a build-only or dev-only
dependency that `Cargo.lock` reaches from the runtime dependencies is refused unless
`runtime_via` names the path (`h2`, also `tonic`'s transport). Test:
`b7m2_build_and_dev_only_kinds_are_enforced` (moving `tonic-prost-build` to a normal
dependency fails twice over; a runtime dependency pulling in a dev-only crate fails).

### LOW-2: the reserved-lane tests did not cover every ordinary RPC

`service::tests::b7_rpc_shares_cleanup_lane_and_reserved_connections` (reserved and root
lanes) and `server::tests::b7_a_reserved_slot_serves_health_and_cleanup_only` (the real
transport) now send valid Exec and GetExecution requests too, each first shown valid on a
general connection.

### Corrections evidence

Branch `phase1b/b7-hardening`: `13c3a50` (ingress: HIGH-2, MEDIUM-2, LOW-2), `5d3ab15`
(the dependency gate and destructive lists: HIGH-1, MEDIUM-1, LOW-1), `62fb76e` (the CI
job) and the documentation commit after them. The VM runs used `62fb76e`.

- *macOS.* `cargo test --locked`, default and `firecracker-test-deployment` features:
  every test passes (kilnd lib 506 passed, 3 ignored). `cargo clippy --locked
  --all-targets -- -D warnings -D clippy::disallowed_methods` on Rust 1.88 and 1.99, both
  feature sets: clean. `git diff --check` and `scripts/kilnd-maintenance-tests.py` pass.
  `scripts/dependency-gate-regressions.sh`: `fs-err` reviewed as `none` refused on 1.88
  and 1.99 (the production call and its own source); reviewed as `filesystem`, the gate
  holds and clippy rejects `fs_err::remove_dir_all` on both; `std::fs::copy` and
  `libc::creat` rejected on both.
- *CI.* Run 41995571790 on `62fb76e`: `check`, `feature` and the new `gate-regressions`
  jobs green. The first attempt's `feature` job failed only the untouched
  `kilnd-broker-protocol` timing test `wide_objects_check_in_well_under_quadratic_time`
  (229 ms against its 200 ms bound; see milestone 2's evidence); the rerun passed.
- *VM, phase 1.* Linux clippy, both feature sets, clean (so `libc::mount` is gated with
  every production use behind the typed wrappers). `cargo test --locked --workspace`:
  default all passed (kilnd lib 515 passed, 77 ignored); feature all passed except the
  same timing test, which then passed 3/3 alone. The root `b7_linux_root_sys_*` tests (the
  ramfs `EOPNOTSUPP` refusal and the procfs component walk's mount check): 2/2. The
  Linux `b7_*`, procfs and `read_dir_fd` tests: 10/10. `scripts/test-deployment-gate-regressions.sh`
  `feature` and `root`: all checks passed, the slice and no-unit cases refused.
  `scripts/dependency-gate-regressions.sh` on Linux: all passed.
- *VM, phase 2, the real chain.* `scripts/firecracker-regressions.py`: **8/8 passed**, the
  whole session and the hostile public caller included (773,153 sockets opened and closed
  by the daemon, 66 held to the 5-second deadline, longest 5.003 s, none left open, while
  Health, Get and Delete answered in 3 ms, 1 ms and 110 ms). `scripts/firecracker-crash-matrix.py`:
  **11/11 passed**.
- *VM, phase 3, the PoCs on the wire* (`ingress.py` in the evidence directory: daemons
  run as `kilnd` on private sockets against the installed helper, callers `b7m2a` to
  `b7m2e` in the `kilnd` group; **16/16 passed**). HIGH-2 at `33/1/32`: on the reviewed
  `01cc7bc`, one UID held 33 of 33 slots and another UID's fresh Health, Get and Delete
  were each closed at the transport, then served once the holder exited; this branch
  refused the flags at startup ("--max-connections-per-uid (32) must be below the general
  connection slots (--max-connections 33 - --reserved-connections 1 = 32)"). MEDIUM-2 at
  the defaults: four UIDs held exactly 33, 29, 1 and 1 on both builds and a fifth UID was
  refused on both; root was refused on `01cc7bc` and got Health, Get and Delete on this
  branch, and a non-root UID could not take root's slot. Floods on this branch, each 30 s
  over the attacker's whole share of 33 connections while another UID repeated Health,
  Get and Delete: SETTINGS 6,573 served and 0 refused, PING 7,089/0, slow headers 8,736/0
  (the daemon closed all 33 attacker connections), slow frames 8,520/0, rapid reset
  8,727/0 (all 33 closed); the daemon survived every one, and afterwards the four-UID fill
  reached exactly 33, 29, 1 and 1 again (the attacker's 34th refused), so every permit
  had been returned.
- *VM, phase 3, installed daemon* (`62fb76e` installed with `scripts/install.sh`):
  `scripts/integration-test.sh`, `daemon-singleton-regressions.sh`,
  `state-path-regressions.sh`, `sudo python3 -I scripts/phase0-regressions.py`,
  `scripts/smoke.sh`, `scripts/hostile-public-caller.py` (794,539 sockets, 66 held to the
  deadline, longest 5.002 s, none left) and `scripts/kilnd-maintenance-tests.py`: all
  passed.
- *Installed state.* Before installing, with kilnd stopped, `/var/lib/kilnd` and the three
  installed binaries were byte-copied and `cmp` found `kilnd.db`, `kilnd.lock` and the
  binaries identical; a copy reported schema 10 and `quick_check` ok (the live database
  was never opened with `sqlite3`). Afterwards `2a1faea` was reinstalled, whose binaries
  `cmp` identical to the pre-phase copies (and hash as before the phase), the state was
  restored and `cmp` found `kilnd.db` and `kilnd.lock` identical, and the daemon served
  with no test account, group, unit, mount, cgroup, VMM or temporary path left.

Logs, matrices and the PoC harness are in `reviews/2026-11-05-b7m2-fixes-vm/`.

### Recheck corrections evidence

Branch `phase1b/b7-hardening`: `a65bbe2` (the gate: every locked package reviewed,
the subtree scan, the narrowed claim), `9986dd7` (the regression script and CI job) and
the documentation commit after them. No runtime code changed, so no VM run was needed.

- *macOS, the gate.* `proven::tests::dependency_gate`: 13 passed on Rust 1.88 and 1.99,
  `the_dependency_gate_holds` included. That is 144 reviewed packages (78
  `pure-computation`, 15 `compile-time`, 51 with their own justification; 102 runtime, 40
  build-only, 2 dev-only) and 22 scoped exceptions. On a 10-core Mac the gate test reads
  48 MB of dependency source, lexes the 15 MB that could hold a hit, and takes about 7 s
  wall.
- *macOS, clippy.* `cargo clippy --locked --all-targets -- -D warnings
  -D clippy::disallowed_methods` on Rust 1.88 and 1.99, default and
  `firecracker-test-deployment` features: clean. `git diff --check` and
  `scripts/kilnd-maintenance-tests.py` pass.
- *macOS, the full suites.* `cargo test --locked --no-fail-fast`, default and
  `firecracker-test-deployment` features, ran with the Mac mini at a load average of
  3 to 12 from other work. Every test binary passed except three timing-bound tests:
  `runtime::kiln_direct`'s `late_failure_frame_settles_after_kill_and_retains_cleanup_proof`
  and `received_runtime_failure_wins_cancellation_and_timeout_while_cli_is_alive` (5 s
  fixture-marker waits), and the broker's `wide_objects_check_in_well_under_quadratic_time`
  (kilnd lib 509 passed, 2 failed, 3 ignored). The unchanged `1d11ac9`, run the same way
  under the same load, failed the same `kiln_direct` tests (503 passed, 3 failed). No
  runtime code changed, and the Linux CI below passes them.
- *`scripts/dependency-gate-regressions.sh` on Rust 1.88 and 1.99* (macOS, at
  `9986dd7`): all passed.
  - fs-err reviewed `none`: refused, for the production call and for
    `std::fs::remove_dir_all` in its source. Reviewed `filesystem` with its paths
    disallowed: the gate holds, and clippy rejects `fs_err::remove_dir_all`.
  - `method-wrapper`, reviewed `filesystem` with `no_destructive_api` or reviewed `none`:
    refused for `.set_len(` (and `impl for std::fs::File`) in its source, while clippy
    accepts the workspace.
  - `outer-wrapper` (`none`) over `inner-wrapper`: refused. With the drafter's skeleton
    entry for the inner package, it needs a reviewed capability; with no entry at all,
    it is in Cargo.lock with no reviewed entry. Both times the outer package's subtree
    reaches the inner `.set_len(`, and clippy accepts the workspace.
  - With a reviewed exception for `method-wrapper` 1.0.0 and no features, the gate holds
    and clippy accepts.
  - A lock change to 1.0.1 is refused (1.0.1 unreviewed, the 1.0.0 entry and exception
    stale), and holds once 1.0.1 is reviewed.
  - Enabling `extra` is refused: the reviewed features, the exception's scope and the
    `.set_len(` hit all fail.
  - `std::fs::copy` and `libc::creat`: clippy rejects both.
- *CI.* Run 42032865841 on `9986dd7`: `check` and `gate-regressions` green.
  `gate-regressions` ran every case above on Linux with Rust 1.88 and 1.99, all
  passed, in 25 minutes; `the_dependency_gate_holds` took 14 s on the 4-core runner. The
  first attempt's `feature` job failed only the untouched
  `exit3_second_helper_is_refused_by_the_persistent_node_lock`, which read the second
  helper's `start-error` file before its reason was written; the rerun passed.

Logs: `reviews/2026-11-05-b7m2-recheck-fixes/` (the regression script on macOS and in
CI, the full suites, and the `1d11ac9` baseline).

### Recheck 2: the build's own graph, identifiers, identities and the root

Daybreak's second recheck (`reviews/2026-11-05-b7m2-recheck2.md`, PoCs in
`reviews/poc-b7m2-recheck2/`) at `c500a6e` failed the gate on two HIGHs and raised two
MEDIUMs:

- *HIGH-1: the gate reviewed a different feature graph from the build.* The gate test ran
  its own `cargo metadata --locked --all-features`, which does not inherit a dependency
  feature the parent command selects. `cargo test --locked --all-features --features
  tokio/full` passed the gate while the build used four unreviewed Tokio features (`full`,
  `io-std`, `parking_lot`, `rt-multi-thread`) and four packages in neither `Cargo.lock` nor
  the review (`lock_api`, `parking_lot`, `parking_lot_core`, `scopeguard`). `--locked`
  left the lock byte-identical.
- *HIGH-2: a type alias plus UFCS evaded the method and impl checks.* In a package
  reviewed `none`, `pub type LocalFile = File;` and `LocalFile::set_len(self, 0)` inside an
  extension trait's impl for `LocalFile` is not a `.set_len(` call, not a rooted std path,
  and not an impl on a flagged type: the alias counted as a type the package defines.
- *MEDIUM-1: `name@version` collapsed distinct source identities.* Two local registries'
  `dupe@1.0.0` became one key in the gate and the drafter, so one review covered both and
  the unreviewed one (whose `tidy` removes a file) disappeared. The drafter reported
  `145 locked packages, 0 to review`.
- *MEDIUM-2: an ambient root override.* `KILND_DEPENDENCY_GATE_ROOT` redirected the
  authoritative test from a dirty workspace it refused to a clean copy that passed.

The corrections:

- *One supported entry point, one graph per profile* (HIGH-1). `scripts/build.sh PROFILE
  COMMAND` is the only supported way to build, test or lint, and `dependency-gate.json`'s
  `profiles` (`default`; `firecracker-test-deployment`, which enables
  `kilnd/firecracker-test-deployment`) is the one list it and the gate read. It runs
  `cargo COMMAND --locked` with only the profile's workspace features and refuses every
  argument that would select features or another graph, in every spelling cargo accepts.
  The gate resolves each profile with exactly those flags; a profile may name only a
  feature a workspace member declares, so a dependency feature goes through a checked-in
  workspace feature; every package a profile resolves must be locked and reviewed; the
  reviewed features are the union over the profiles and kinds come from the union of
  their graphs. CI's jobs, `scripts/install.sh` (and so the binaries `scripts/upgrade.sh`
  takes), `scripts/b4-vm-tests.sh`, `scripts/integration-test.sh`, `docs/setup.md` and the
  README build through it, and `supported_builds_use_the_build_entry_point` refuses a raw
  cargo build in any of them. No build needs a dependency feature today; the two profiles
  resolve the same 150 packages.
- *Identifiers, not call shapes* (HIGH-2). Every identifier matching a `METHOD_SINKS`
  pattern is a hit wherever it occurs in the scanned subtree (labelled by the identifier:
  `set_len`, not `.set_len(`). `type` aliases (any visibility, generics skipped, associated
  types included) resolve like `use` aliases in the impl check, and an alias whose target
  is one of std's or Tokio's file or process types is flagged itself (`type alias for
  std::fs::File`, or `type alias for File` through a glob import). A `type` name no longer
  counts as a type the package defines. The wider match reached harmless identifiers in 12
  packages; each was read and recorded: seven existing exceptions widened (bytes,
  futures-util, hyper, serde_json, smallvec, Tokio, tracing-subscriber) and five added
  (hyper-util and tonic executor bindings, libc's own declarations, windows-sys binding
  parameters, zmij's `ptr::copy`), 27 in all, each still scoped to package, version and
  feature set.
- *Duplicate identities refused* (MEDIUM-1). Two packages with one `name@version` in
  `Cargo.lock` fail the gate before any review is matched, naming both sources and
  checksums; two in a profile's `cargo metadata` fail the loader; the drafter refuses both.
  Multiple sources for one name and version are not supported.
- *A fixed root* (MEDIUM-2). `the_dependency_gate_holds` always checks
  `workspace_root()`, the workspace its test binary was compiled from, and reads no
  variable (`the_authoritative_gate_reads_no_environment` checks its body). The regression
  script runs the same loader and gate through `regression_fixture_gate`, a test ignored by
  default that requires `KILND_DEPENDENCY_GATE_FIXTURE`; `cargo test` and CI never run it.
- *The claim, narrowed again.* Section 7.1, the CHANGELOG and `dependency-gate.json`'s
  `about` now promise only builds made through `scripts/build.sh` and a reviewed profile,
  describe the sink check as identifier-level, and state that duplicate identities are
  refused. A raw `cargo build` with other feature flags is outside the guarantee.

Tests (synthetic, under `cargo test`):

- `b7m2_recheck2_each_profile_graph_is_reviewed`: a profile selecting `tokio/full` is no
  workspace feature; a workspace feature forwarding it resolves an unlocked
  `parking_lot` and an unreviewed `libc` feature, and reviewing the union holds; an
  undeclared feature, a `default` with features, an unknown field, an unresolved profile
  and a missing section are refused.
- `b7m2_recheck2_duplicate_identities_are_refused`: two `dupe@1.0.0` lock entries return
  only the identity error; two metadata packages fail the loader.
- `b7m2_recheck2_type_aliases_resolve`: aliases (with references and lifetimes, through
  `use` aliases and chains, glob-imported, associated) are flagged and their impls
  resolved; the package's own `File`, another crate's and target-less associated types
  are not.
- `b7m2_recheck_a_method_wrapper_is_refused` now also refuses Daybreak's alias-UFCS
  wrapper, `Handle::set_len(x, 0)`, `<Handle as Len>::set_len`, a function value, a `use`
  list, a definition and a field; strings, comments and aliases of non-std types are not
  hits.
- `supported_builds_use_the_build_entry_point`,
  `the_authoritative_gate_reads_no_environment`, and `the_dependency_gate_holds` on the
  real workspace (both profiles).

`scripts/dependency-gate-regressions.sh` keeps every earlier case and adds Daybreak's
type-alias UFCS wrapper (vendored, its source exact), feature injection through
`build.sh`, a profile's own graph, the two-registry collision and the root override.
Results are under *Recheck 2 corrections evidence*.

### Recheck 2 corrections evidence

Branch `phase1b/b7-hardening`: `aaff49b` (build profiles and `scripts/build.sh`, the
per-profile gate, identifier matching and type aliases, duplicate identities, the fixed
root, the regression cases and CI) and the documentation commit after it. No runtime code
changed, so no VM run was needed.

- *macOS, the gate.* `proven::tests::dependency_gate`: 18 passed and 1 ignored
  (`regression_fixture_gate`) on Rust 1.88 and 1.99, `the_dependency_gate_holds` included.
  That is two profiles resolving the same 150 packages, 144 reviewed packages (unchanged:
  78 `pure-computation`, 15 `compile-time`, 51 with their own justification; 102 runtime,
  40 build-only, 2 dev-only) and 27 scoped exceptions. `scripts/dependency-gate-review.py`
  reports `144 locked packages, 0 to review`.
- *macOS, clippy.* `scripts/build.sh [+1.99.0] PROFILE clippy --all-targets -- -D warnings
  -D clippy::disallowed_methods` on Rust 1.88 and 1.99, both profiles: clean. `git diff
  --check` and `scripts/kilnd-maintenance-tests.py` pass.
- *macOS, the full suites.* `scripts/build.sh +1.88.0 PROFILE test --no-fail-fast`, both
  profiles: every test binary passed (kilnd lib 516 passed, 4 ignored). The timing-bound
  `kiln_direct` tests and the broker's `wide_objects_check_in_well_under_quadratic_time`,
  which failed under load at the recheck, passed this time.
- *`scripts/dependency-gate-regressions.sh` on Rust 1.88 and 1.99* (macOS, at `aaff49b`):
  all passed. Every earlier case held its result (fs-err `none` refused and `filesystem`
  holding with clippy rejecting the call; `method-wrapper` refused as `filesystem` with
  `no_destructive_api` and as `none`; `outer-wrapper` over `inner-wrapper` refused with
  and without the inner entry; the exception holding at its scope; the 1.0.1 bump refused
  until reviewed; `extra` refused; clippy rejecting `std::fs::copy` and `libc::creat`),
  with hits now labelled `set_len` rather than `.set_len(`. The new cases:
  - Daybreak's type-alias UFCS wrapper, reviewed `none`: refused for `set_len`, `type
    alias for std::fs::File` and `impl for std::fs::File`; clippy accepts the workspace.
  - Feature injection through `build.sh`: the PoC's `--all-features --features
    tokio/full` and ten other spellings (`--features=`, `-F`, `-Fx`, `-rF`,
    `--all-features`, `--no-default-features`, `--manifest-path`, `--config`, `-Z`) are
    refused before cargo runs.
  - A profile selecting `tokio/full`: `build.sh` refuses it; the gate refuses it as no
    workspace feature and for `lock_api`, `parking_lot`, `parking_lot_core` and
    `scopeguard`, which its graph resolves and `Cargo.lock` does not lock. `Cargo.lock` is
    unchanged.
  - A workspace feature forwarding `tokio/full`, in a profile: refused for the
    unreviewed `parking_lot` (and the rest) it locks and Tokio's unreviewed features.
  - Two `dupe@1.0.0` registries: the drafter and the gate refuse the duplicate identity.
  - The root override: the dirty workspace's authoritative test refuses with both
    variables naming a clean copy; the pristine copy's holds with both naming the dirty
    one; the ignored fixture test follows its variable and refuses the dirty one.
- *CI.* Run 42051232479 on `aaff49b`: `check` and `gate-regressions` green.
  `gate-regressions` ran every case above on Linux with Rust 1.88 and 1.99, with the same
  73 outcomes as on macOS, in 25 minutes. The first attempt's `feature` job failed only
  the untouched `b3_04_startup_that_cannot_journal_never_serves_and_leaves_no_workers`,
  which read the helper's `start-error` file before its reason was written (the same race
  as the recheck's `exit3_second_helper…` flake); the rerun passed, and the run concluded
  green.

Logs: `reviews/2026-11-05-b7m2-recheck2-fixes/` (the regression script on macOS and in
CI, the full suites, and the failed `feature` attempt).

### Recheck 3: compiler cfg inputs, the whole package and every build instruction

Daybreak's third recheck (`reviews/2026-11-05-b7m2-recheck3.md`, PoCs in
`reviews/poc-b7m2-recheck3/`) at `0c4bdd5` failed the gate on two HIGHs and raised one
MEDIUM:

- *HIGH-1: compiler cfg inputs bypassed a profile's feature review.* `build.sh` refused
  cargo's feature arguments but passed the ambient compiler configuration through, and
  any Clippy arguments after `--`. `RUSTFLAGS='--cfg feature="ambient-poc"'` (and
  `CARGO_BUILD_RUSTFLAGS`, and the Clippy tail `-- --cfg 'feature="ambient-poc"'`)
  compiled a declared feature no profile selects under `scripts/build.sh default`, while
  `cargo metadata` still reported it disabled and the authoritative gate passed.
- *HIGH-2: the loader read only the library target's directory.* A vendored package
  reviewed `none` whose `src/lib.rs` declared `#[path = "../hidden.rs"] mod hidden;` kept
  its `File` alias, extension-trait impl and `LocalFile::set_len(self, 0)` in a
  package-root file the gate never read; the fixture gate and workspace Clippy passed and
  the wrapper truncated a file.
- *MEDIUM-1: raw cargo in contributor and deployment instructions.* `CLAUDE.md` and
  `deploy/firecracker-test/README.md` still prescribed raw `cargo` builds, and the
  fixed eight-file policy test read neither.

The corrections (lead decisions, made on the integrated branch `phase1b/b7-integrated`):

- *A closed compiler environment* (HIGH-1, section 7.1). `build.sh` refuses a nonempty
  `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `CARGO_BUILD_RUSTFLAGS`, `RUSTDOCFLAGS` (and its
  forms), `CARGO_TARGET_*_RUSTFLAGS`, `CARGO_PROFILE_*_RUSTFLAGS`, `RUSTC`, the wrappers,
  `CARGO_BUILD_RUSTC*`, `RUSTC_BOOTSTRAP`, `CARGO_UNSTABLE_*` and `CLIPPY_ARGS` with a
  message naming the variable, then sets the compiler inputs itself: empty encoded
  rustflags and rustdocflags (which override every Cargo config table, including a
  `target.'cfg(all())'` table no `--config` key can reach), `RUSTC=rustc`, empty
  wrappers, and `--config` resets of `build.rustflags`, `build.rustdocflags` and the host's
  and each `--target`'s table. Clippy's arguments are `build.sh`'s fixed `-D warnings -D
  clippy::disallowed_methods`; a caller's tail is refused. The one compiler flag
  `build.sh` passes is `--crt-static`'s, which `scripts/b4-vm-tests.sh` uses instead of
  exporting `RUSTFLAGS` for its static test helper, and which requires `--target`.
- *A backstop in every build script* (HIGH-1). Each of the six workspace crates (all
  ship in a kilnd binary) has a build script whose first act refuses a `--cfg`, `-Z` or
  `@` response-file entry in the `CARGO_ENCODED_RUSTFLAGS` cargo hands it, so a raw cargo
  build given such a flag fails too. Cargo reruns a build script when the flags change.
  A test holds all six to one function, called first, and another refuses a workspace
  build script that emits a feature cfg or a cfg it does not name literally.
  `no_unapproved_build_scripts_or_generated_includes` approves the five new scripts as
  backstop-only.
- *The whole package, and its source edges* (HIGH-2, section 7.1). The loader scans every
  checked-in `.rs` file under each scanned package's root, build scripts and binaries
  included, except unreached files under the top-level `tests/`, `benches/` and
  `examples/`, and follows literal `#[path]` (also through `cfg_attr`, and inside inline
  modules) and `include!` edges from every scanned file, into those directories too. An
  edge that leaves the package root, a symbolic link or an unreadable file refuses the
  package outright. An edge it cannot resolve, or a non-literal `include!` that is not
  generated `OUT_DIR` code, becomes an `unresolved source edge` hit, refused unless a
  scoped exception reviews it: the gate cannot read what it cannot find, so a person has
  to say why it is harmless. An edge in a macro body (serde's `crate_root!`, whose paths
  resolve from where the macro is invoked) is also looked up from every source directory
  in the package. Generated `OUT_DIR` code stays the documented exception.
- *New exceptions, each read before it was excepted.* The wider scan found three kinds
  of hit in the current lock, all recorded with their package, version and features:
  - Build scripts (build-time only, never linked into kilnd), eight packages: anyhow
    and thiserror run the compiler on a probe and remove their own `OUT_DIR/probe`
    (`remove_dir_all`, `Command::new`; thiserror also writes `OUT_DIR/private.rs`);
    serde and serde_core write `OUT_DIR/private.rs` and run `rustc --version`; httparse,
    libc and zmij run `rustc --version` (libc also `freebsd-version` and `emcc
    -dumpversion` on those hosts); libsqlite3-sys copies its checked-in bindings into
    `OUT_DIR` and writes bindgen output there (`copy`, `std::fs::copy`, `std::fs::write`).
  - libsqlite3-sys's `exec`: the `sqlite3_api_routines` field holding the
    loadable-extension API's pointer to `sqlite3_exec` (runs SQL), in the checked-in
    `*_ext.rs` bindings that only the `loadable_extension` feature (not enabled) uses.
  - serde_core's five `unresolved source edge`s: `crate_root!`'s docs.rs-only
    `cfg_attr(all(docsrs, if_docsrs_then_no_serde_core), path = "core/...")`, serde's
    facade layout. serde ships `src/core` and the gate follows them there; serde_core
    does not, so a build with that cfg could not compile, no supported build sets it, and
    every `.rs` file serde_core ships is scanned regardless.

  The group check reads the same whole-package source, so seven packages whose build
  script or binary names a process or file path left their groups for their own
  justifications: httparse, serde_core, zmij and pulldown-cmark (`pure-computation`),
  prettyplease, proc-macro2 and quote (`compile-time`).
- *Every build instruction* (MEDIUM-1). `CLAUDE.md` and the isolated deployment's
  README use `build.sh` profiles. The policy test inspects every Markdown, shell, Python
  and workflow file, allows raw cargo builds only in `build.sh`, the gate regressions and
  the jailer build (a line naming `-p jailer`, in its two files), and pins the number of
  raw mentions in `CHANGELOG.md` and this design, which record past runs and the
  guarantee's limits, so a new one is looked at. It now also splits words on `,` and
  brackets, so a Python argument list (`['cargo', 'test', ...]`) counts.

What this claims: a build through `build.sh` compiles only what a reviewed profile
selects, and the scan reads every checked-in source file of a scanned package that the
compiler could reach by a literal path. It does not claim more: a raw cargo build with
other `-C` flags is outside the guarantee, a path a macro assembles is not followed, and
generated `OUT_DIR` code is not read.

`scripts/dependency-gate-regressions.sh` adds case 8, Daybreak's `rustflags-feature.sh`
(`RUSTFLAGS` and `CARGO_BUILD_RUSTFLAGS` refused by name, the Clippy tail refused, a
Cargo config file's `build.rustflags`, `target.'cfg(all())'` table and `rustc-wrapper`
overridden so the feature's test is not compiled, and a raw cargo build refused by the
backstop) and case 9, `path-module-sink.sh`'s exact vendored package (refused on
`hidden.rs`'s `set_len`, alias and impl, with Clippy accepting the workspace; the same
module under `tests/`, reached only by its `#[path]`, refused; a `#[path]` outside the
package root refused as unscannable).

### Recheck 3 corrections evidence

Branch `phase1b/b7-integrated`: merge `9f63aae`, `c5cc5f5` (the stray bytecode),
`a3b3acc` (the recheck 3 corrections and regression cases), `2c5a2db` (the merge's
Linux-only fix), `8f7ff79` (this documentation, first pass), `f5c6327` (B3R-01's root
test) and `12491ac` (the CI job's time limit). Logs:
`reviews/2026-11-05-b7-integration/`.

- *macOS, the gate.* `proven::tests::dependency_gate`: 23 passed and 1 ignored
  (`regression_fixture_gate`), `the_dependency_gate_holds` included: two profiles, 144
  reviewed packages (74 `pure-computation`, 12 `compile-time`, 58 with their own
  justification) and 37 scoped exceptions on 30 packages.
  `scripts/dependency-gate-review.py` reports `144 locked packages, 0 to review`.
- *macOS and Linux, clippy.* `scripts/build.sh [+1.99.0] PROFILE clippy --all-targets`
  (`build.sh`'s fixed `-D warnings -D clippy::disallowed_methods`) on Rust 1.88 and 1.99,
  both profiles, on macOS and in the VM: clean. `git diff --check` and
  `scripts/kilnd-maintenance-tests.py` pass.
- *macOS, the full suites.* `scripts/build.sh +1.88.0 PROFILE test --no-fail-fast`, both
  profiles, at `12491ac` on a quiet machine: every test binary passed (795 passed, 15
  ignored; the kilnd library 619 passed, 6 ignored). An earlier pair of runs, made while
  the VM suites and the regression script loaded the Mac, failed only timing-bound tests
  that also fail under load on the parent branches: `kiln_direct` (up to 12),
  `wide_objects_check_in_well_under_quadratic_time`,
  `invalid_exec_claims_fail_cleanup_and_quarantine_end_to_end` and two `helper::tests`
  deadline tests.
- *`scripts/dependency-gate-regressions.sh 1.88.0 1.99.0`* (macOS, at `f5c6327`): all
  passed, 91 outcomes. Every earlier case held its result; the new ones: `RUSTFLAGS`,
  `CARGO_BUILD_RUSTFLAGS` and the Clippy tail refused by `build.sh` on both toolchains;
  a Cargo config file's `build.rustflags`, `target.'cfg(all())'` table and
  `rustc-wrapper` overridden, the `ambient-poc` test not compiled; a raw cargo build with
  the `RUSTFLAGS` refused by the build scripts' backstop; `path-module-wrapper` refused on
  `hidden.rs`'s `set_len`, alias and impl with Clippy accepting the workspace, refused
  again with the module under `tests/`, and refused as unscannable with a `#[path]`
  outside its root.
- *CI.* Run 42092695860 on `12491ac`: `check`, `feature` and `gate-regressions` green;
  `gate-regressions` ran the same 91 outcomes on Linux in 52 minutes. Run 42085264270 on
  `f5c6327` passed `check` and `feature` but hit the job's old 45-minute limit in case 9
  (cases 1 to 7 alone took 40 minutes on that runner), hence `12491ac`.
- *The VM* (Lima `kiln`, everything built through `build.sh`, at `f5c6327`; the release
  build was installed by `scripts/install.sh` after a byte copy of `/var/lib/kilnd/` taken
  with kilnd stopped):
  - `scripts/integration-test.sh`: passed (admission stress, the kiln integration
    tests and the `b3r_` root tests). The first run, at `2c5a2db`, failed
    `b3r_01_linux_root_a_prefence_from_a_real_second_account_stays_its_own`, which still
    expected the pre-B7 fence in the attacker's own namespace; under RTC-3 H refuses the
    copied token at its tag check (`f5c6327`).
  - `scripts/b4-vm-tests.sh`: 32 passed (and the direct-kiln core's 1).
  - `scripts/firecracker-crash-matrix.py`: 31/31.
  - `scripts/firecracker-regressions.py`: 26/26, the whole session (E2E) and milestone
    1's R2 (`b7_rtc_r2_01`, `b7_rtc_r2_03`) and R3 (`b7_rtc14_linux_root_*`) included. In
    the full run `b7_linux_root_attack_hostile_public_caller…` failed only because the
    run's VM-local checkout sat in a home directory `nobody` cannot traverse, and the
    script re-executes itself as `nobody`; rerun alone with the directory traversable, it
    passed.
  - B5: `scripts/b5-test-guest.sh` built both test guests and
    `scripts/b4-vm-tests.sh b5_linux_root` passed 8.
  - `scripts/deployment-regressions.py` between the install build and a second
    `build.sh` release build (line tables on, so different bytes; `build.sh` refuses the
    old `RUSTFLAGS='-C metadata=…'`): 69 PASS. `--reboot-arm graceful`, a real guest
    reboot, then `--reboot-verify`: same images, enrollments, units and state.

  A station restart hard-stopped the VM in the first full run's crash matrix (after `b4`
  had passed), and the second run filled the VM's disk with a second set of build caches
  (`b4` and the crash matrix failed with `ENOSPC`, and one `userdel` could not rewrite
  `/etc/group`; `scripts/b4-vm-cleanup.py` then removed the leftover account). The run
  above is the third, from the start, on the VM's shared caches. Afterwards the VM was
  put back: main `1c107f9`'s `install.sh` rebuilt byte-identical binaries, and
  `/var/lib/kilnd/` was restored from the copy (`cmp` identical, file for file); all three
  services active, and helper state, instances, accounts, loops, mounts, cgroups and
  processes match the pre-run state.

## B7 milestones 1 and 2 integrated (November 5, 2026)

Branch `phase1b/b7-integrated` merges milestone 2 (`phase1b/b7-hardening`, `0c4bdd5`)
into milestone 1 (`phase1b/b7-compaction`, `63beb65`) with merge commit `9f63aae`; the
recheck 3 corrections above follow it. The conflicts, each resolved keeping both sides:

- `CHANGELOG.md`: both milestones' entries.
- `helper/firecracker/mod.rs`: milestone 1's digest-bearing `Inspect { allocation_id,
  plan_digest }` with milestone 2's `H.inspect` test hold for the capacity crash scenario.
- `scripts/b4-vm-tests.sh`: milestone 2's `build.sh` entry point with milestone 1's
  optimized dependencies. `build.sh` refuses `--config`, so the override became the
  workspace's `vm-test` Cargo profile (`dev` with every dependency at opt-level 2, kilnd
  itself unoptimized with its overflow checks), which the script selects with
  `--profile vm-test`.

The merge also changed two things that did not conflict textually. Milestone 1's raw
`cargo test` for the B7 fixture scenarios in `scripts/firecracker_matrix.py` now runs
`scripts/build.sh default test`, and `b7_scenario_names_match_the_scripts` also reads
`tests/recovery.rs`, where milestone 2's `b7_linux_root_attack_hostile_public_caller…`
scenario lives (it failed on the merged tree until then). `main.rs`, `service.rs`,
`manager.rs`, `setup.md` and this design merged cleanly; milestone 1 added no dependency,
so the gate held on the merged tree unchanged. A follow-up commit drops the Python
bytecode milestone 2 had committed under `scripts/__pycache__/` and ignores it.

## B7 integrated recheck (November 5, 2026)

Daybreak Blue's recheck of the integrated branch at `f4db5b5`
(`reviews/2026-11-05-b7-integrated-recheck.md`, PoCs in `reviews/poc-b7-integrated/`)
failed it on two HIGH findings and ranked one MEDIUM; every earlier PoC was confirmed
fixed. Each is corrected on `phase1b/b7-integrated`, with the lead's decisions.

| Finding | Correction | Proving tests |
|---|---|---|
| HIGH-2 An L death released R1's lost-answer hold before the replacement's Handover imported the durable latch: a Create at its final boundary was accepted, and an Exec past EXEC_INTENT could dispatch | A fault-bearing call that ends in `Closed` (parked lost answer or not) moves its hold to a barrier keyed by the L generation it was sent to; it still counts for `is_latched` and `latched_once_answered`, and only a successful replacement Handover drains it, after importing the latch. A failed or absent replacement leaves it, and every final boundary refuses at its own deadline (section 16.10, *Integrated recheck: the transferred hold*) | `b7_crash_l_death_keeps_a_lost_fault_held_until_the_replacement_imports_the_latch` (the PoC inverted), `b7_crash_l_death_with_a_lost_benign_answer_lifts_the_hold_at_the_replacement_handover`, `b7_crash_a_failed_replacement_handover_keeps_the_transferred_hold`, real chain `b7_linux_root_crash_exec_after_intent_waits_for_the_replacement_handover`; all in the crash matrix |
| HIGH-1 The gate's source-edge traversal stopped at ordinary child modules: `src/lib.rs` reached `tests/common/mod.rs` by `#[path]`, whose `mod reset;` (`tests/common/reset.rs`, an extension trait on `File` calling `set_len(0)`) was never scanned | Every ordinary out-of-line `mod name;` is a source edge, resolved by both Rust readings (`name.rs`, `name/mod.rs`, from the file's directory and, for a non-mod-rs file, its stem's, beneath inline modules), every existing candidate scanned, transitively from every scanned file including those under `tests/`, `benches/` and `examples/`. One that resolves to nothing is an `unresolved source edge`; an edge outside the package still refuses it. A module whose `#[path]`s are all `cfg_attr` also follows its ordinary location (scanned if it exists) and each conditional path. The wider traversal needed no new exception: still 37 across 30 packages (section 7.1) | `b7int_ordinary_out_of_line_modules_are_source_edges`, `b7int_ordinary_child_modules_below_a_path_module_are_scanned` (the exact shape and two levels, through `a.rs` and `a/mod.rs`), `b7int_every_path_of_a_module_is_scanned`, `b7int_an_ordinary_child_module_to_nothing_or_outside_is_reported`; `scripts/dependency-gate-regressions.sh` case 10 on Rust 1.88 and 1.99 (the PoC's vendored fixture refused, Clippy accepting the workspace, and both two-level variants refused) |
| MEDIUM-1 A `PresentReady` answer delivered after a terminal Remove re-published its session; 32 stale allocations left 32 sessions that a complete List never pruned | The session is published only through the caller's terminal-aware `LearnClaim`, under the digest cache's lock, and a complete List prunes unlisted sessions as well as digests (section 16.10) | `stale_ready_answers_after_terminal_answers_resurrect_no_session` (the PoC inverted), `a_complete_inventory_drops_only_unclaimed_unlisted_sessions` |

**Evidence** (`reviews/2026-11-05-b7-integrated-fixes/`). Kiln VM: crash matrix 35 of 35
(B6's 11 on the real chain, B7's 23 fixture scenarios with the three new HIGH-2 ones, and
the real-chain Exec scenario, rerun after its first run's exact hold count was relaxed in
`c5065cf`: on the real chain S's own fault-bearing records to the dead L are transferred
too, and the fixture tests were relaxed the same way after a loaded macOS run showed a
refused Create's own record transferred);
attack regressions 26 of 26. The Exec scenario refused at its deadline with nothing
dispatched, the VM stopped, and Remove was ABSENT under the latch. The installed kilnd
was never replaced and `/var/lib/kilnd` was restored from its `cmp`-verified copy.

# 16. Retired-token compaction (pre-B7 design)

*Design only, November 4, 2026, against kilnd main `2a1faea`. No product code changes with
this section. B7 implements it before production Firecracker is enabled (section 11, B7).*

The node ledger keeps every allocation token that reaches ABSENT forever, so a node can
host a fixed number of sessions in its lifetime and then stops admitting. This section
measures that limit, states what any compaction must preserve, compares five designs and
recommends one: **helper-issued sequence tokens with a per-instance durable low
watermark**, in which a row always outranks the watermark, everything below the watermark
is permanently absent, and the watermark's movement is a liveness choice that no safety
rule depends on. Rules RTC-1 to RTC-18 in section 16.5 are what B7 builds and what
Daybreak should attack. Nothing here changes Stephen's settled decisions (one VM per
session, terminate on uncertainty, no API socket, offline and cold only).

*Revised the same day for Daybreak Blue's design review
(`reviews/2026-11-04-rtc-design-review.md`): every request that can meet a compacted token
now carries its plan digest, the issue pointer is persisted exactly, L alone classifies,
compaction has a guaranteed share of L, admission headroom has a guaranteed per-instance
share, and the rollback claims are corrected. Section 16.8 maps each finding to its change.*

*Revised again for Daybreak Blue's recheck (`reviews/2026-11-04-rtc-design-recheck.md`):
the rollback detector accepts only a helper-issued token whose tag verifies, and its
durable latch closes every forward effect node-wide; the issue pointer is a high-water
mark, not a delivery record; watermark checkpoints are bounded; section 9's Runtime
listing is rewritten to the B7 contract; every policy slot's share is reserved; and the
L-lane and H/L restart contracts are stated at their exact boundaries. Section 16.8 maps
these findings too.*

## 16.1 The problem, measured

**What writes permanent rows.** Every release after C1 goes through `Ledger::commit_fence`,
which writes one `retired_tokens` row (keyed by instance and allocation, with the canonical
`FencedAbsence` receipt) in the same FULL-sync transaction that marks the allocation
`absent` and releases its claim and leases. Three flows reach it:

| Flow | Ledger rows left behind, forever | Counted against |
|---|---|---|
| ABSENT for an admitted token (Remove, a fence after INTENT, Gc, settlement of a failed Create after C2) | The fence row, plus the allocation's whole history: `allocations`, `capacity_claims`, five `identity_leases`, one `executable_leases` row per role, `stop_events` (up to 16), `resource_events` (every non-execution record), `worker_intents` (up to 8 settled per mode). Only the plan bytes are deleted at the fence, and execution and worker history is compacted per allocation (section 7.4) | `fence_headroom`: one entry per `allocations` row |
| A never-admitted fence: FenceAbsent for a token the ledger never saw (daemon death before C2, helper restart before C2, a lost Create) | The fence row only | That instance's never-admitted quota |
| Refused after C1: C2 refused the token (capacity, identity collision, revalidation, deadline), then its fence | The fence row only (no allocation row was written) | That instance's never-admitted quota |

**Bytes per row.** Measured on mini-one with the real schema and write paths
(`research/retired-token-compaction/probe_rtc_bytes_per_session.rs`, appended to the journal
tests in a scratch checkout and discarded): 2,000 admitted sessions, each with a full
create-to-ABSENT history, five executions and one stop, grew the ledger by **9,785 bytes
per session** (allocations 928, capacity claim 186, identity leases 954, executable leases
1,411, worker rows 688, fence row 827 with its 400-byte receipt, stop event 102, resource
events 4,723). A never-admitted fence costs **about 700 bytes**. The ledger code assumes
`FENCE_ENTRY_BOUND = 4096` bytes for "the most space one retired token can need, across all
its rows"; the measured admitted footprint is 2.4 times that, so the 64 MiB fence allowance
would really hold about 120 MB at its count limit. The separate ledger-size guard in C2
(`ledger_bytes` against the 448 MiB left of the 512 MiB shared reservation) catches this at
about 47,000 sessions, so it never binds first, but the allowance's byte accounting is
wrong today and section 16.6 corrects it.

**The real lifetime limits** at the default policy (64 MiB allowance, `max_enrolled_instances`
8):

- **Node: 12,287 admitted sessions, ever.** Headroom is count-based: allocations ever
  admitted, plus the whole never-admitted pool reserved up front (16,384 / 4 = 4,096), plus
  one, must fit 16,384 entries. Once 12,287 allocation rows exist, every Preflight on every
  instance answers "no fence headroom is left for another token" (a C0 refusal, no row), for
  the rest of the ledger's life. The share is first come: one instance may take all of it;
  eight even instances get about 1,535 each.
- **Instance: 384 post-C1 refusals, ever.** Each instance's never-admitted quota is the pool
  over the larger of the policy maximum and the enrolled rows: 512 at the default (64 at the
  hard maximum of 64 instances). Preflight stops issuing that instance new tokens once a
  quarter of its quota remains, so after **384** never-admitted fences the instance can
  never create again; FenceAbsent keeps working up to 512 so already charged C1 rows can
  still settle. Ordinary contention spends this budget: B6's two-daemon race shows the
  loser of a C2 capacity race is released by exactly such a fence (`refused_after_c1`).
  On a busy shared node this limit arrives long before the node's 12,287.
- **Nothing else repairs it.** The only way out today is re-provisioning the ledger, which
  needs every session on the node gone first (section 4.5: never recreate a ledger over
  possibly live resources).

**What each side assumes about a token's permanence.**

| Party | Assumption today | Where |
|---|---|---|
| Daemon | It mints the allocation ID itself (`Id128::random()` before C0) and assumes it is unique forever: `release_evidence.allocation_id` is UNIQUE | `manager.rs` `create_supervised`; store schema 8 |
| Daemon | Release needs a typed `AbsentFenced` receipt binding node, instance, allocation and plan digest with a generation above the row's last published one; evidence is immutable and outlives retention prune | store triggers `release_evidence_*`, section 8.4 |
| Daemon | A lost terminal commit is repaired by asking again: the helper must still answer for the token, with a receipt, however old the token is. A restored or stale database relies on that for every token it ever held | sections 4.5, 8.3; B6 crash matrix |
| Helper | A fence row and the allocation's rows are permanent; `allocations_no_resurrection` refuses a retired token by its row | `journal.rs` schema triggers |
| Helper | Lookup is fence, then allocation, then **Unknown, which is admittable**: an unseen random ID is a fresh token | `lookup_on`, `admit_intent_authorized` |
| Helper | Preflight refuses a token that is retired or active by finding its row | `PreflightSnapshot.retired_or_active` |
| Helper | The open audit decodes every receipt and checks the generation counter against every stored generation, including fences | `Ledger::audit` |
| Helper | H's closed gates are non-durable; only ledger rows are authority | B3-03 |

The dangerous one is "Unknown is admittable". A random 128-bit token carries no age, so
deleting its fence row turns an old token back into a fresh one: a replayed Create from a
restored daemon database, a delayed Create, or a copied token would pass Preflight and C2
and allocate. Any compaction must first make an old token recognizable as old without its
row.

## 16.2 Requirements every design must keep

A token whose rows were compacted must never lead to:

- a VM, disk, jail, cgroup, loop device, worker or capacity claim being created (no INTENT,
  no C2 commit, no side effect);
- a node claim or daemon reservation being released while any resource for it might exist;
- an ABSENT receipt, a DELETED row or any other absence being published for a token that
  might still own resources;
- a false READY or any reusable answer (`PresentReady`, `PresentBusy`, Accepted, Validate
  or Exec success).

This must hold through every replay path: a stale or restored daemon database; a lost
database (another instance); a copied database or token used elsewhere; two daemons; a
delayed Create or Remove queued in H or L; a helper restart (with its orphaned supervisors);
a host reboot; a crash at every step of compaction; a clock step in either direction; and a
token presented by a different instance. A node ledger restored from an older copy, or
cloned, is root's action and stays **outside the fault model** (section 16.7). This design
does not make the node safe against it. Measured against today it is better in some cases
and worse in one: a restored ledger refuses tokens issued after its copy, and RTC-14
detects some restores, but a coordinated restore of ledger and daemon, or a cloned ledger,
re-mints identical tokens, where today's random IDs never repeat. RTC-14 is a partial
detector, not a defense; any ledger restore requires the node-wide offline inventory in
section 16.7 before the helper serves again. The detector itself must not become a
cross-instance weapon: no report an instance can make without a helper-issued token may
fault the node. It must also keep B3's
anti-flood properties (no unbounded rows, gates or helper memory from any one instance,
admitted tokens never refused a fence, quotas checked inside the fence transaction), B6's crash matrix and
terminal publication rules, crash safety and idempotence of compaction itself, and the
destructive-action gate (section 7.1): compaction is ledger SQL only, never a host action.

## 16.3 Candidate designs

### A. Helper-issued sequence tokens with a durable low watermark

**Idea.** The helper mints every Firecracker token. The 128-bit allocation ID becomes a
per-instance issue sequence (64 bits) followed by a 64-bit keyed tag. Each instance has a
durable watermark W. Lookup order is fence row, allocation row, then *below W means absent
forever*, then Unknown. W only moves up, in its own FULL-sync transaction, and compaction
then deletes rows of **absent** tokens below W. Active allocations below W keep all their
rows, so they are never mistaken for absent ("pinned").

**What proves nothing outstanding sits below W.** Nothing has to: that is the point of the
rows-first order. Every token below W is in exactly one of three states. It has rows (active
or not yet compacted), and the rows answer. It was admitted and fenced, and its rows were
compacted only after ABSENT, so it is absent. Or it was never admitted, and C2 refuses any
token below W inside the admission transaction, so it never will be: absent is true of it
from the moment W passes it. A daemon still holding such a token in a C1 row gets an
absence receipt and releases; a delayed Create gets the same receipt and allocates nothing.
Advancing W too early only turns a slow honest Create into a failed, released one. Clocks
therefore choose *when* W moves (a lease after issuance) but can never make an unsafe
answer.

**Schema and wire.** Node ledger schema 2: `token_key`, `instance_tokens` (exact issue
pointer, watermark, watermark generation, retained admitted count), `issue_seq` columns with
a hex-prefix CHECK on `allocations` and `retired_tokens`, `compaction_log`, `node_faults`,
and delete triggers that permit only compactable rows (section 16.6). Firecracker group
schema 2: Preflight stops taking an allocation ID and returns the issued one inside the
plan's substitutions; AttachInstance carries the daemon's highest recorded complete
allocation token (or none), whose tag H and L verify before it can mean anything;
Accounting gains retained and watermark fields. Every request that can meet a compacted
token carries the plan digest the daemon's Store bound at C1: Create and FenceAbsent already
do, Inspect and Remove gain a required `plan_digest`, and each Gc target becomes an
`(allocation_id, plan_digest)` pair. The Runtime calls pass the Store's immutable binding
through (`inspect_allocation` already receives it; `remove` and `gc` gain it). The daemon
database needs no schema change: it stores the helper's token where it stored its own.

**Migration.** Schema 1 has never shipped beyond test. A schema-1 ledger fails its audit,
closed, with a message to re-provision, as B3 to B5 did; the isolated test deployment is
re-provisioned with its daemons' Firecracker rows settled first. Production has no ledger.

**Replay paths** (intact node ledger; the restored-ledger case follows). Stale or restored
daemon database: each of its CREATING or DELETING rows reaches Inspect, Remove or FenceAbsent
carrying the digest from its own immutable binding. Tokens with rows answer from the rows,
and a digest that differs from the rows' is refused as Conflict, so evidence for one plan
can never release another plan's charge. Rowless tokens below W get a receipt synthesized
for that digest and release. Tokens at or above W behave as today. It cannot obtain a new
token without Preflight. Lost database: another instance, refused as in B6. Copied database
or token in another instance: the tag binds the instance, so the token is Malformed there
and never reaches the ledger. Two daemons: separate sequences and watermarks. Delayed
Create: if C2 commits first, its allocation row pins the token below W; if W's advance
commits first, the lookup inside C2 and the INSERT trigger refuse it with the synthesized
receipt (SQLite's IMMEDIATE transactions order the two). Delayed Remove, FenceAbsent or Gc:
an active, stopped, quarantined or worker-unsettled allocation keeps its rows, which outrank
W; a rowless compacted token gets a receipt and causes no host action, because Remove and
Gc act only on journaled resources. Helper restart: the watermark and the exact issue
pointer are durable, no request depends on a digest the helper remembered, and no advance
happens for one lease. Host reboot: the same; `CLOCK_BOOTTIME` restarts, which only delays
W. Suspend: `CLOCK_BOOTTIME` counts it, so a resumed, long-delayed honest Create can fail
released; it cannot bypass C2 or hide an active row. Crash during compaction: the advance
and each delete batch are separate atomic transactions, so rows present after an advance
answer from rows, and rows gone after a delete commit passed RTC-10. Clock steps: change
only when W moves.

**Restored or cloned node ledger** (outside the fault model, section 16.7). A copy restored
under a current daemon refuses as NotIssued every token issued after the copy, and RTC-14
latches every forward effect node-wide when the daemon has recorded such a token. It cannot see a token that was
issued before the copy but admitted, retired and compacted after it: the restored ledger
has no row for it and an older W, so it is Unknown and C2 could admit its replay. A restore
of both the ledger and the daemon database together, or two helpers running copies of one
ledger, re-mint the identical next token. Only the node-wide offline inventory in
section 16.7 covers these.

**Quota, recovery and the ceiling.** Never-admitted rows below W are compacted, so each
instance's quota becomes a budget per lease window instead of per lifetime; fences below W
cost no row at all. Admitted tokens are still never refused a fence. B6 recovery and
terminal publication are unchanged except that a token's receipt may be a synthesized one
(still `AbsentFenced`, still bound to node, instance, allocation and plan digest, with a
generation above anything published for it). The lifetime ceiling disappears: rows retained
are the active allocations plus what was issued within one lease, bounded by the
allowance, of which every policy slot has a reserved share (RTC-17); the sequence is about
2^63 per instance.

**Operator repair and observability.** No manual compaction or force flag exists. Accounting
and `kilnd-helper ledger-stats` (root, read-only) show per instance the issue pointer, W,
retained admitted and never-admitted rows, pinned active allocations below W, and the last
compaction's generation and lag; Health degrades on low retained headroom or compaction lag.
A stuck compaction (a row a trigger refuses) is a health fault naming the token, not a
deletion.

**Cost.** Moderate: about 800 to 1,200 lines in `journal.rs`, `workers.rs` (L requests and
the compactor), `mod.rs` (issuance, classification before gates), `runtime/firecracker.rs`
and `manager.rs` (token from Preflight, digests to Inspect, Remove and Gc), plus tests. One
HMAC over `sha2` (no new dependency). Steady-state cost is one FULL-sync write per issued
token (the exact pointer, section 16.6 measures it at about 0.2 ms) and one small
transaction per compaction batch.

### B. Instance epochs, bumped by re-enrollment or rotation

**Idea.** Each instance row carries an epoch. Tokens embed it (for example a 32-bit epoch
and 96 random bits, still daemon-minted). Rotation, done by root's maintenance command with
the helper stopped, bumps the epoch; older-epoch tokens without rows are refused wholesale
with a synthesized absence receipt, and absent older-epoch rows are compacted. Remaining
charged older-epoch allocations either keep their rows (pinned, as in A) or must be drained
first.

**Schema and wire.** `instances.epoch`, an epoch CHECK on token columns, AttachInstance
returning the epoch the daemon must mint under; Preflight unchanged. **Migration** as in A.

**Replay paths.** The same rows-first argument holds per epoch, so safety is as strong as
A's. Delayed Creates cannot span a rotation, because rotation stops the helper and every
connection epoch with it.

**Quota, ceiling, operations.** The lifetime limits become per-epoch limits: 12,287 admitted
and 384 refusals per instance between rotations. Something must still notice the approaching
limit and schedule a rotation, which is a maintenance window: the node lock means every
maintenance command stops every instance (B3 deployment corrections). Draining instead of
pinning would need all sessions on the instance deleted. An online variant that rotates
while attached needs the daemon to learn the new epoch per Preflight, at which point it is
design A with a coarser counter.

**Cost.** Small code (about 300 lines plus maintenance-script work), but it turns a
capacity property into a recurring operator outage and keeps a hard cap between rotations.

### C. Self-describing MAC'd tokens, refused by age without rows

**Idea.** The helper issues issue_time ‖ nonce ‖ MAC tokens. Unknown tokens older than T
are refused without rows, and fences older than T are deleted.

**Why it is not enough on its own.** A MAC proves the helper issued a token; it cannot say
whether an issued token is old enough to have been compacted unless freshness is measured
against something that never goes backwards. With wall-clock or boot-clock time it does go
backwards: an NTP step, an RTC reset, a VM restore of the host, or simply a new boot makes
an expired, compacted token look fresh, it is then Unknown, and C2 admits it. That is
resurrection from a clock. Making freshness a durable monotonic ledger value turns C into
A (a sequence and a watermark) or B (an epoch). The MAC itself is worth keeping, and A uses
it: it lets H refuse forged or foreign tokens before any ledger call, with no per-token
state.

### D. Bloom filter or other summary of retired tokens

**Idea.** Replace fence rows with a durable Bloom filter keyed by (instance, allocation).
A member is treated as retired forever; there are no false negatives, so a retired token is
always refused, and a false positive is a fresh token treated as absent.

**Why rejected.** It does not remove the limit, it moves it: a plain filter cannot delete,
its false-positive rate climbs with every insertion, and at a few percent it fails honest
Creates at random (each spurious refusal is itself a post-C1 failure for the daemon to
fence). Stable or rotating filters can retire old entries, but keeping them free of false
negatives across deletion needs generations or epochs (B or A again), and saturation stays
a lifetime concern. It does nothing for the 9.8 KB of allocation history per session, which is most of
the space. It must be keyed (the daemon chooses IDs today) and rewritten inside the fence's
FULL-sync transaction. Operators and Daybreak cannot enumerate or audit what it contains,
and every safety argument becomes probabilistic. An exact summary of random IDs is the
fence table itself; an exact summary of structured IDs is a watermark (A).

### E. Delete a fence once the daemon acknowledges its receipt

**Idea.** Keep random IDs; the daemon acknowledges durable publication of each receipt and
the helper then deletes the fence.

**Why rejected.** It makes the daemon database part of the release authority, which section
4.1 forbids. A restored or stale database never saw the acknowledgement it is replaying
around: its CREATING or DELETING row for an old token would reach Preflight's lookup as
Unknown and C2 could admit the replayed token. B6's `crash_restored_stale_db_*` and
`crash_lost_db_*` scenarios exist precisely because daemon state is not trusted to be
current.

### Comparison

| | A. Sequence and watermark | B. Epochs | C. MAC'd, aged | D. Bloom | E. Daemon ack |
|---|---|---|---|---|---|
| Removes the lifetime cap | Yes | No: per epoch | Only with a monotonic counter (then A or B) | No: moves it | Yes |
| Safety independent of clocks | Yes | Yes | No | Yes | Yes |
| Safe for restored or stale daemon DB | Yes | Yes | Only if clocks are honest | Yes | **No** |
| Operator action needed | None | Scheduled outage | None | None | None |
| Bounds allocation history (9.8 KB/session) | Yes | Yes, per rotation | Yes | No | Yes |
| Wire change | Preflight returns the token; digests on Inspect, Remove, Gc | Attach returns epoch | Token issuance | None | Ack message |
| Code size | Moderate | Small | Moderate | Moderate | Small |

## 16.4 Recommendation

Build **A**, with C's keyed tag as its token check. It is the only design that removes the
cap without an outage, does not lean on any clock or on daemon state for safety, and keeps
every existing release rule: the only new answer is "absent" for tokens that provably can
never be admitted. Its cost is concentrated in the ledger, which already owns these rules,
plus one change to where the daemon gets its token.

Defaults: lease 15 minutes (well over four times Preflight's 30 s plus Create's 120 s), a
compaction pass every 60 s on its own one-slot L lane, which also takes the pass's
watermark checkpoint (at most 17 per instance), at most 256 tokens per delete
transaction, an exact high-water issue pointer persisted with each issuance, a per-token
space bound set from a measured worst case (section 16.6), and a 128 MiB fence allowance
(8,192 entries at 16 KiB; a quarter, 2,048, is the never-admitted pool, 256 per instance
per window at the default 8 instances; of the remaining 6,143 admitted entries each of the
8 policy slots reserves 767, whether or not an instance is enrolled in it, and only the
7-entry remainder can be borrowed). All are root policy, never daemon input.

*As built in B7 milestone 1 (section 16.9):* the measured worst case is about 18.0 KB per
token, so the bound is 20 KiB and the 128 MiB allowance holds 6,553 entries: a pool of
1,638 (204 per instance per window at 8 instances, Preflight's floor at 153), 4,914
admitted entries, a reserved share of 614 per slot and a 2-entry remainder, so a ceiling of
616 retained admitted rows per instance at the default policy. A full 256-token delete
transaction took 310 to 580 ms, so the batch is 16 tokens (RTC-18's 100 ms cap). The
lease, pass and allowance are root policy fields (`compaction_lease_seconds`,
`compaction_pass_seconds`, `fence_allowance_bytes`).

## 16.5 Rules for B7 (RTC-1 to RTC-18)

1. **RTC-1 Token form and key.** A Firecracker allocation ID is seq ‖ tag: `seq` is the
   instance's issue sequence as 8 big-endian bytes, 1 ≤ seq ≤ 2^63 − 2; `tag` is the first 8
   bytes of HMAC-SHA-256(K, `"kilnd-fc-token-v1"` ‖ node_id ‖ instance_id ‖ seq). K is 32
   bytes from the OS CSPRNG (`getrandom`), written in the schema-provisioning transaction
   with a check value, the first 16 bytes of HMAC-SHA-256(K, `"kilnd-fc-key-check-v1"` ‖
   node_id). Triggers refuse every UPDATE, DELETE and INSERT OR REPLACE of it. K lives only
   in the node ledger (so every copy of the ledger carries it) and in H's and L's memory.
   It crosses exactly one boundary, the private L-to-H channel (RTC-3), and never appears
   in a public or wire reply (anything a daemon or other client can receive), log, error or
   Accounting field. Open never generates a
   replacement: a missing, truncated or substituted K fails the open audit and closes the
   Firecracker group. K never rotates: changing it invalidates every outstanding token, so
   loss or compromise is recovered by node-wide drain, verified absence and re-provisioning
   (section 16.7). The text form stays 32 lowercase hex digits, so `backend_id`, jail names
   and every 128-bit field keep their shape.
2. **RTC-2 Only the helper mints.** Tokens are issued only by Preflight, only to the live
   holder of the instance (section 4.1), only when headroom allows. The daemon never mints a
   Firecracker token; it uses the one bound into the verified plan.
3. **RTC-3 H checks the tag; L classifies.** Before any gate, quota or L call, H performs
   only a constant-time check of the tag in the caller's authenticated instance and of
   seq ≠ 0 (each L hands H the key over its own private channel, published to H together
   with that channel; section 16.6, "H and L replacement"). A failure is
   **Malformed**: refused as `Incompatible` with no gate, L call, row, generation or receipt,
   and the daemon's charge stays. Another instance's token is Malformed here. H holds no
   issue pointer, watermark or row state and never classifies further: it never infers
   Compacted from seq < W, because a pinned active allocation can sit below W and rows win.
   L classifies authoritatively inside the transaction that reads the token: it repeats the
   tag check, answers **NotIssued** for seq at or above the durable issue pointer it reads in
   that transaction, then applies RTC-6. H acts on L's answer alone (RTC-15).
4. **RTC-4 Issuance is an exact, durable high-water pointer.** Each instance has a durable
   exclusive issue pointer `issue_next`. Issuing seq = `issue_next` raises it by exactly one
   in the same FULL-sync IMMEDIATE transaction that takes Preflight's identity and headroom
   snapshot, committed before the token leaves L. On start, L reads the pointer as
   committed. The pointer records what was **issued**, not what was **delivered**: no seq
   is ever issued twice or reused, but a committed seq may be abandoned before any daemon
   holds it (L dies before its private reply, H dies or loses the public reply, the daemon
   dies before C1, or P refuses the preflight after issuance). Abandoned seqs are safe
   under the classifier and need no record: a rowless seq below the pointer is Unknown
   until W passes it and Compacted afterwards, and it is never re-issued. A token that
   never left the helper cannot be presented at all, since nobody outside it can compute
   the tag; one that reached a daemon process but no C1 row is an ordinary issued rowless
   token, which C2 may admit only while it is at or above W. B7
   does not add a delivery acknowledgement; the compaction proof does not need one.
   Besides issuance, only the root offline fault clear (RTC-14) moves the pointer, and
   only upward. At `issue_next` = 2^63 − 1 Preflight refuses with a health fault and never
   wraps.
5. **RTC-5 The watermark.** Each instance has a durable W with 1 ≤ W ≤ `issue_next`. W only
   increases, in a FULL-sync transaction that takes a fresh generation G_W. No other path
   writes W.
6. **RTC-6 Rows outrank the watermark, and the digest binds.** Every token read follows:
   fence row (its original receipt, or Conflict on another plan digest), then allocation row
   (as today, or Conflict when its plan digest is not the caller's), then seq < W
   (Compacted), then Unknown. A Conflict changes nothing and the daemon's charge stays.
7. **RTC-7 Nothing below W is admitted or newly fenced.** C2 commits INTENT only for
   seq ≥ W, checked by the lookup in the admission transaction and by an INSERT trigger on
   `allocations`. A fence row for seq < W is written only for a token that has an allocation
   row (a pinned active allocation reaching ABSENT).
8. **RTC-8 Compacted means absent, and nothing else.** Every request that can reach a token
   lookup carries the plan digest from the daemon Store's immutable binding: Create and
   FenceAbsent today, and in group schema 2 Inspect and Remove (a required `plan_digest`)
   and each Gc target (an `(allocation_id, plan_digest)` pair). For a Compacted token those
   five answer `AbsentFenced` with a synthesized receipt: helper generation G_W; receipt ID
   the first 16 bytes of SHA-256(`"kilnd-fc-compacted-v1"` ‖ node ‖ instance ‖ allocation ‖
   plan digest ‖ G_W); the request's plan digest; observations
   `compacted;watermark=<W>;issue_seq=<seq>`. The digest comes from the request and nowhere
   else: no cache, row or reply supplies it, so the answer is the same after any helper
   restart. Binding the caller's digest is truthful, because a compacted token owns nothing
   under any plan, and the receipt can release only a Store row whose own immutable binding
   names that digest (the daemon's `receipt.matches(binding)` and the Store's identity
   triggers, unchanged). The answer writes nothing and touches no host resource. No Ready,
   Busy, Present, Stopped, Accepted or reusable answer is ever given for it, and Remove,
   Stop and Gc never act on a token with no rows.
9. **RTC-9 Synthesized receipts are never stale.** A token's rows are compacted only when
   its fence generation is below G_W (RTC-10), so G_W exceeds every generation the helper
   ever reported for a token that answers Compacted; a never-admitted token below W was
   issued before W passed it, and the advance took a new generation. When a pinned
   allocation is fenced after the last advance, the compactor refreshes G_W (a new
   generation, W unchanged) before compacting it. The daemon's `release_evidence_not_stale`
   trigger and C1's `last_helper_generation = 0` therefore accept it, and only for a row
   whose identity it matches. A later G_W gives a later, different receipt for the same
   token; evidence the daemon already published stays authoritative and immutable, and a
   charged row accepts only a generation newer than its own last publication.
10. **RTC-10 Only absent rows are compacted.** A token's rows may be deleted only when
    seq < W, its fence row exists with a helper generation below G_W, and, if it was
    admitted, its allocation is `absent` with the claim and every identity and executable
    lease released and every worker row settled. Children go first, then the allocation,
    then the fence row last, in one transaction. SQL triggers enforce each condition,
    including the child order itself: the allocation and fence delete guards check with
    explicit `NOT EXISTS` that no plan, claim, identity or executable lease, worker intent,
    stop event or resource event of the token remains, so the order holds even on a
    connection with `foreign_keys` off. Active, stopped, quarantined or ambiguous
    allocations are never deleted, whatever their seq.
11. **RTC-11 Crash-safe and idempotent.** Advancing W and deleting rows are separate atomic
    transactions; any crash leaves a state where RTC-6 to RTC-8 give the same answers, and a
    rerun deletes nothing more than the rule allows. Compaction runs only in L, performs no
    host action and calls nothing in `proven.rs` or `sys.rs`.
12. **RTC-12 Quotas per window.** The never-admitted quota counts only retained
    never-admitted fence rows (seq ≥ W or not yet compacted), checked inside the fence
    transaction as today. Admitted tokens are never refused a fence. Headroom counts retained
    allocation rows plus the reserved pool plus one, at an honest per-token bound, and is
    shared under RTC-17.
13. **RTC-13 Advance policy is liveness only, with bounded checkpoints.** Issuance records
    nothing in memory. Each compaction pass for an instance (RTC-18) first snapshots that
    instance's current exclusive pointer as a checkpoint (`issue_next`, now), when the
    pointer has moved since the instance's newest checkpoint and that checkpoint is at least
    one pass (60 s) old; otherwise it records nothing, however many passes run. L keeps at
    most LEASE / PASS + 2 checkpoints per instance (17 at the defaults: one per pass until
    it matures, plus the restart point and the newest, tail point); if the bound is ever
    reached, the newest point is overwritten with (pointer, now), which only delays
    maturity. L advances W to the highest checkpoint at least one lease old by
    `CLOCK_BOOTTIME` and then prunes every checkpoint whose pointer is at or below W. After
    any L start the only checkpoint is (`issue_next`, now), so nothing advances for one
    lease. Checkpoint memory is therefore a fixed bound, instances × 17 points of 16 bytes
    (about 17 KiB at the hard maximum of 64 instances), independent of the request rate or
    of how many Preflights succeed, fail or lose their replies; and every token, including
    the last one issued, is below a matured checkpoint within one lease plus two passes.
    No wall clock is read. A test that steps any clock must find no unsafe answer.
14. **RTC-14 Rollback detection needs a verified token, and latches forward effects.**
    - *Report.* AttachInstance carries `highest_token`: the complete allocation token (seq ‖
      tag) with the highest seq among the daemon's Firecracker rows and its permanent
      release evidence, or none. Group schema 2 has no bare-sequence field.
    - *Verification.* H checks the reported token exactly as RTC-3 checks any token, in the
      caller's authenticated instance; L repeats the check inside the attach transaction,
      and only then compares the decoded seq with `issue_next`. A malformed, foreign
      (another instance's valid token), bit-flipped or bad-tag report fails **that
      attachment alone**, as `Incompatible`: no `node_faults` row, no latch, no write, no
      effect on any other instance. The daemon stays unattached until it reports none or a
      token that verifies; a daemon whose own Store holds a corrupt high token therefore
      fails closed for its own instance only. A verified token below `issue_next` is the
      normal case.
    - *Detection.* Only a verified token with seq ≥ `issue_next` proves a rollback: under an
      intact ledger every tag that verifies was computed by L after it committed the pointer
      past that seq, and no caller can compute one without K. L then inserts a `node_faults`
      row (kind `rollback`, the instance, the token, the pointer, a fresh generation) in a
      FULL-sync transaction, and the attachment fails.
    - *Latch scope.* While any `node_faults` row exists, or H's or L's in-memory latch is
      set, the helper refuses node-wide, before any gate, L write or host action, every
      operation that starts work: Preflight (so nothing is issued), Create, Validate, Exec,
      and any other forward effect, including an instance's first attachment binding. It
      keeps bounded Inspect, List, Stop, Remove, Gc and FenceAbsent, plus Health,
      Capabilities, Accounting and the reattachment of an already-bound instance (which
      writes nothing), so cleanup drains. This is section 8.3's rule for ledger loss (deny
      Create and Exec, keep read and authorized cleanup). FenceAbsent may stay because its
      proof inspects every derived host resource of the token, not only rows (section 4.1);
      Remove and Gc act only on journaled resources; none of them creates anything.
      Under the latch L serves only `workers::allowed_under_latch`'s explicit list and the
      supervisor gets no further authority: its resource intents, the records that precede
      a loop configuration, a mount attachment, a link or readiness, the `spawn_intent`,
      `booting` and readiness phases and the check S makes before each guest-broker
      Initialize are refused; the identities of a cgroup tree, directory, VMM or child that
      already exists are journaled for cleanup but never acknowledged; only a cleanup S's
      `loop_released` is (recheck R2, section 16.10). A lost answer to any request whose
      answer could carry a fault holds forward effects until H has consumed it (recheck R1).
    - *Uncertain commit.* H and L each set their in-memory latch before L attempts the fault
      commit. If that commit fails or its outcome is unknown, the latch stays closed: L
      treats it as a ledger sync failure and exits (section 4.5); H keeps its latch for the
      rest of its process life and hands the pending fault to every replacement L, which
      commits it (idempotently, keyed by instance and token) before it serves any request.
      After an H process restart a committed row latches again at open; an uncommitted one
      is found again at the reporting daemon's next attachment, which cannot succeed before
      then.
    - *Clearing.* Only the root offline clear in section 16.6 ("Clearing a rollback fault")
      removes a fault row: root only, helper stopped, node lock held, after the mandatory
      offline inventory. It is the single exception to `node_faults` being insert-only.
      Nothing online clears a fault or raises the pointer to match.
    - *Coverage.* It detects a ledger restored to before any token the daemon has recorded.
      It does not detect a restore to a point after the daemon's last recorded token (a
      token issued before the copy and admitted, retired and compacted after it then answers
      Unknown), a coordinated restore of the ledger and the daemon database together, or two
      helpers running clones of one ledger. It is evidence, never authority, and its silence
      proves nothing.
15. **RTC-15 Gates follow L.** While a flow waits for L it holds only B3-03's per-token
    serialization entry, which leaves with the flow. H closes or retains a gate only on L's
    answer. A token that fails H's tag check, or that L answers NotIssued or Compacted,
    creates and retains no closed gate and never counts toward the instance's gate quota
    (B3-03).
16. **RTC-16 Audit and observability.** The open audit checks K's presence, length and
    check value; every stored seq's hex prefix and tag; W ≤ `issue_next`; every stored
    seq < `issue_next`; no allocation below W that is absent without its fence row; each
    instance's retained-admitted counter against its rows; and includes G_W, `node_faults`
    `compaction_log` and `node_fault_clears` in the generation rollback check; and checks
    that every cleared fault is covered by a clear row and every other fault row is still
    present. Accounting reports, for the caller's own instance only, W, `issue_next`,
    retained admitted and never-admitted rows, its reserved share, pinned allocations below
    W, checkpoint count and compaction lag, plus node retained totals and the share
    shortfall, if any (RTC-17). Health degrades below 25% retained headroom or past two
    leases of lag, and fails on any `node_faults` row or a set in-memory latch, naming only
    the fault kind to instances other than the one whose token detected it.
17. **RTC-17 A reserved share of admitted headroom for every policy slot.** Let E be the
    admitted entries (the allowance's entries, less the never-admitted pool, less one),
    slots = max(policy `max_enrolled_instances`, enrolled instances) and
    share = floor(E / slots) (767 at the defaults). Every slot reserves its unused share,
    max(0, share − retained admitted rows), and a slot no instance is enrolled in has no
    rows, so it reserves its whole share. Equivalently, the ledger keeps
    Σ over slots of max(retained_admitted(J), share) ≤ E. An instance below its share
    always fits; above its share it may take an entry only while free − 1 still covers every
    other slot's reserve, enrolled or not. Unenrolled shares are never borrowed, and an
    enrolled peer's unused share is its own reservation, so borrowing comes only from space
    no slot reserves: the remainder E − slots × share (7 at the defaults), less what other
    borrowers already hold. Enrolling an instance within the policy maximum turns an
    unenrolled slot's reservation into that instance's own, so its whole share is
    available at once, whatever the existing instances hold, and **an instance below its
    share is never refused for admitted headroom**. The cost is stated plainly: one
    instance can no longer borrow the shares of slots nobody is enrolled in, so a node
    running a single instance at the default policy holds at most 774 retained admitted
    rows (its 767 plus the 7-entry remainder) instead of 6,143. Root sizes
    `max_enrolled_instances` to the instances it will really run; a value of 1 gives that
    instance all 6,143. Preflight checks this before issuance and C2 rechecks it inside the
    admission transaction (section 16.6). The one exception is a root policy change that
    shrinks the share (a larger `max_enrolled_instances` or a smaller allowance) while
    instances hold rows above the new share: the open audit reports the shortfall in
    Health, and the guarantee holds again once those rows drain.
18. **RTC-18 Compaction has reserved capacity in L, bounded at the queue.** H keeps one L
    permit for compaction on its own lane, separate from the normal (28), reserved (4) and
    attach (64) lanes, and submits a due batch without waiting for the normal lane to go
    idle. L serves the frames of its single stream one at a time in arrival order. Once a
    batch's frame is enqueued, at most 96 frames (28 + 4 + 64) are ahead of it; once any
    other frame is enqueued behind a batch, it waits for at most that one batch, because H
    sends the next batch only after the previous reply. Both bounds start at enqueue: a
    caller that holds a permit but has not yet enqueued its frame can be passed by the next
    batch, so each batch is capped at 100 ms (B7 lowers the 256-token batch if a full one
    exceeds that). The lanes preserve reserved **capacity**, not scheduling priority:
    compaction never takes a reserved permit, so cleanup and recovery keep their permits as
    today, but their frames are served in arrival order like every other frame.

## 16.6 B7 implementation and test plan

**Node ledger schema 2** (`journal.rs`; schema 1 refuses to open with "re-provision"):

```text
token_key(id = 1, key BLOB length 32, check BLOB length 16,
          created_generation)                                      written once at provisioning;
                                                                   UPDATE, DELETE, REPLACE refused
instance_tokens(instance_id PK -> instances, issue_next >= 1,
                watermark >= 1, watermark_generation >= 1,
                retained_admitted >= 0,
                CHECK watermark <= issue_next,
                CHECK issue_next <= 9223372036854775807)           issue_next and watermark only
                                                                   increase (issue_next by
                                                                   issuance or the offline
                                                                   fault clear); no delete;
                                                                   row written by enroll
allocations.issue_seq, retired_tokens.issue_seq  INTEGER NOT NULL,
    CHECK (issue_seq BETWEEN 1 AND 9223372036854775806
           AND substr(allocation_id, 1, 16) = printf('%016x', issue_seq))
INDEX (instance_id, issue_seq) on both
compaction_log(id, instance_id, from_w, to_w, generation UNIQUE,
               tokens_deleted, rows_deleted)                       newest 64 per instance kept
node_faults(id, generation UNIQUE, kind, instance_id,
            token, issue_next_seen, detail)                        insert only, except the
                                                                   offline clear; UPDATE refused
node_fault_clears(generation UNIQUE, cleared_through_generation,
                  inventory_sha256, raised_pointers)               insert only; written only by
                                                                   the offline clear
DELETE trigger on node_faults: refused unless a node_fault_clears row with
  generation = the ledger's current highest generation (this transaction's) has
  cleared_through_generation >= the fault's generation
INSERT triggers: allocations refused for issue_seq < W or >= issue_next;
                 retired_tokens refused for issue_seq >= issue_next, or < W with no
                 allocation row
COUNTER triggers: allocations INSERT / DELETE adjust instance_tokens.retained_admitted
DELETE triggers (replacing the "permanent" ones): a child row only if its token is
  compactable and the row is released or settled; an allocation only if absent and
  compactable; a fence row only if issue_seq < W and no allocation row remains.
  B5-01's execution and worker compaction rules stay as they are.
compactable(I, A) := EXISTS fence row (I, A) with issue_seq < W(I)
                       AND helper_generation < watermark_generation(I)
```

`FENCE_ENTRY_BOUND` becomes a measured worst case: a new test fills every bounded
per-allocation table to its cap (16 stop events, 8 settled workers per mode with B5-01's
settled-worker retention applied, every resource kind, the largest receipt) and asserts the
bound; 16 KiB is the expected value against the 9.8 KB typical footprint. The fence allowance
becomes 128 MiB of the 512 MiB shared storage reservation, and the ledger-size guard measures
live pages, (page_count − freelist_count) × page_size, since SQLite reuses freed pages
without shrinking the file.

**Messages** (Firecracker group schema 2; old daemons are refused at capability preflight):

| Message | Change |
|---|---|
| Preflight | Request drops `allocation_id`; reply's plan substitutions carry the issued token, and the reply names it. `verify_prepared` binds substitutions to the reply's token and the caller's instance |
| AttachInstance | Adds `highest_token: Option<AllocationId>`: the complete token (seq ‖ tag) with the highest seq among the instance's Firecracker rows and release evidence, or none. No bare sequence is accepted. H and L verify its tag for the authenticated instance before comparing its seq (RTC-14); a token that fails is `Incompatible` for this attachment only |
| Accounting | Adds the RTC-16 fields (`AccountingSnapshot` is `deny_unknown_fields`, hence the schema bump) |
| Create, FenceAbsent | Shapes unchanged; both already carry `plan_digest`. Compacted answers `AbsentFenced` synthesized for that digest; Malformed and NotIssued answer `Incompatible` |
| Inspect | `Inspect { allocation_id, plan_digest }`, digest required. Rows answer when the digest matches and Conflict when it does not; Compacted answers `AbsentFenced` synthesized for that digest |
| Remove | `Remove { allocation_id, plan_digest }`, digest required. Same lookup; it acts only on the journaled resources of a row whose digest matches |
| Gc | `Gc { targets: Vec<GcTarget> }` with `GcTarget { allocation_id, plan_digest }`, today's length bound, duplicate IDs refused. **Validation is all-or-nothing:** H checks every target's tag in the authenticated instance before any lookup, and one Malformed target (another instance's token among them) refuses the whole request with no L call and no action. After validation each target is answered as Remove would answer it; a Compacted target contributes its synthesized receipt. Partial progress is possible only from a later per-target cleanup failure, which stays discoverable and charged (section 8.2) |
| Stop, Validate, Exec | Unchanged. None is a release; a rowless token is refused with no action. Validate and Exec are refused while the RTC-14 latch is set; Stop is kept |
| L protocol | `PreflightSnapshot` becomes `IssueAndSnapshot { instance }`; `Inspect { instance, allocation, plan_digest }`; new `Compact { instance, max_tokens }` and `CompactReply` on the new compaction lane (each pass also takes its checkpoint, RTC-13); the attach request carries the H-checked `highest_token`, and a pending fault travels to a replacement L in its startup handshake; `TokenLookup` gains `Compacted { receipt }`, `Malformed`, `NotIssued`. H sends L no classification of its own |
| Daemon | `prepare` takes a `PrepareContext` that names no allocation; `CreateContext` is built after `prepare`, from `PreparedCreate::allocation_id()` (Firecracker) or a legacy `Id128::random()` (kiln, which records no allocation), as section 9.1 specifies. No store schema change |

*Rejected: "Compacted, then FenceAbsent".* The review's alternative, in which Inspect, Remove
and Gc return a non-releasing `Compacted` and the daemon then calls the digest-bearing
FenceAbsent, is not taken: it costs a second round trip on every compacted recovery and
opens a window between the two calls in which state can change and must be re-proved.
Carrying the digest answers in one transaction.

**Daemon and Runtime changes.** The Runtime trait stays backend-neutral. Its normative
listing is section 9.1, rewritten for B7: `PrepareContext`, `PreparedCreate::allocation_id()`,
`CreateContext` built after `prepare`, and `RemoveTarget` for `remove` and `gc`.

- **Firecracker adapter** (`runtime/firecracker.rs`): `prepare` sends Preflight without an
  allocation ID, and `verify_prepared` checks that the reply's token passes the tag-free
  shape checks, equals the plan substitutions' token, and belongs to the attached
  instance; the result is `PreparedCreate::fenced(.., token)`. `inspect_allocation` sends
  `prepared_digest` as `Inspect.plan_digest` instead of discarding it. `remove` and `gc`
  send `binding.allocation_id` and `binding.plan_digest`, after checking every binding's
  node and instance against the attached identity; `gc` checks the whole vector (no
  `Legacy`, no foreign binding, no duplicate, the length bound) before the first wire
  frame, so one bad target refuses the call with nothing sent. A `Legacy` target is
  refused as `RuntimeError::Incompatible` before any wire call, so no Firecracker request
  can leave without a digest. `Legacy` **is reachable** here: the generic manager's legacy
  Delete (`remove_legacy`), its publication compensation and its reconciliation Gc pass
  `Legacy` to whichever runtime is active. The refusal, not unreachability, is what keeps
  it safe.
- **kiln adapters** (`KilnRuntime`, `DirectKilnRuntime`) accept only `Legacy` targets and
  refuse `Fenced` as `Incompatible` before any kiln call; their behavior is otherwise
  unchanged.
- **Manager** (`manager.rs`): the fenced release path calls
  `remove(RemoveTarget::Fenced { binding })` with the binding from `fenced_binding(sandbox)`,
  and `remove_legacy` calls `remove(RemoveTarget::Legacy { backend_id })`. Reconciliation's
  Gc list becomes `Vec<RemoveTarget>`. Today it sends only legacy rows (`stale_owned`
  excludes fenced rows, which recover through Inspect, Remove and FenceAbsent), and B7 keeps
  that, but any fenced row sent to Gc carries its Store binding, and every fenced receipt
  goes through `commit_absence`, which already requires `receipt.matches(binding)`. A
  binding comes only from the Store row: never from List inventory, a helper reply or a
  cache.
- **Historical kiln rows when Firecracker is selected.** A daemon database may hold kiln
  rows (backend `kiln`, legacy regime) when it is restarted with `--backend firecracker`.
  They do not drain under Firecracker, and nothing releases them by guesswork:
  reconciliation skips every row whose backend is not the active runtime's name (as
  today), so it neither Gcs nor marks them lost; a Delete of such a row moves it to
  DELETING and reaches `remove(Legacy)` on the Firecracker adapter, which refuses before
  any wire call, so the row stays DELETING and charged with the refusal as its reason, and
  it is listed as such. The drain procedure is operational and documented with B7's
  deployment notes: before selecting Firecracker for a database, run it with
  `--backend kiln` and delete every kiln row until none is charged (`kilndctl list`), then
  switch. B7's Firecracker startup counts charged rows of another backend and degrades
  Health naming that count, so a skipped drain is visible rather than silent. Each further
  Firecracker instance gets a fresh database under its own account (section 4.1), so this
  arises only for the default `kilnd` instance's existing database.
- **Helper** (`helper/firecracker/mod.rs`, `workers.rs`, `journal.rs`): `Ledger::inspect`
  takes the digest; the Remove and Gc handlers pass each request digest to the lookup;
  an allocation row whose plan digest differs answers Conflict, as a fence row already does.

**Transaction order** (all IMMEDIATE, FULL-sync, in L):

```text
latch_gate(op):                             -- H before any gate; L again in its tx
  if op starts work (Preflight, Create, Validate, Exec, a first attach binding, ...)
     and (the in-memory latch is set or any node_faults row exists):
       refuse, no gate, no L write, no host action
  -- kept: Inspect, List, Stop, Remove, Gc, FenceAbsent, Health, Capabilities,
  --       Accounting, reattachment of a bound instance (RTC-14)

issue(tx, I):                               -- IssueAndSnapshot, one transaction
  n = issue_next(I)                         -- durable, exclusive high-water pointer
  require n <= 2^63 - 2                     -- else refuse, health fault, no write
  require headroom(tx, I) and the never-admitted issuance floor (RTC-12)
  snapshot = claimed identities
  UPDATE instance_tokens SET issue_next = n + 1
    WHERE instance_id = I AND issue_next = n;  commit
  return be64(n) || hmac(K, node, I, n)[0..8], snapshot
  -- no memory written; from here n may be abandoned (RTC-4), never reused

attach(tx, I, highest_token):               -- AttachInstance, after H's tag check
  if highest_token is none: proceed
  tag_check(I, highest_token)?              -- Malformed: this attach fails, no write
  seq = be64(highest_token[0..8])
  if seq < issue_next(I): proceed           -- normal
  latch_in_memory(I, highest_token)         -- H and L, before the commit
  INSERT node_faults(next_generation(), 'rollback', I, highest_token,
                     issue_next(I), ...);  commit
    -- commit fails or is uncertain: L exits as a sync failure; H keeps the latch and
    -- hands the pending fault to every replacement L, which commits it before serving
  fail this attach

tag_check(I, A):                            -- H before any gate or call; L again in lookup
  seq = be64(A[0..8])
  if seq == 0 or not ct_eq(A[8..16], hmac(K, node, I, seq)[0..8]): Malformed

lookup(tx, I, A, digest):                   -- L only, inside every tx that reads a token
  tag_check(I, A)?
  if seq >= issue_next(I) (read in tx): NotIssued
  fence row (I, A)        -> digest == row's ? Fenced(original) : Conflict
  allocation row (I, A)   -> digest == row's ? Active(...)      : Conflict
  seq < W(I)              -> Compacted(synth(I, A, digest, W, G_W))
  otherwise               -> Unknown

headroom(tx, I):                            -- RTC-17, at issue and again in C2
  E = entries - pool - 1;  slots = max(policy_max_instances, enrolled)
  share = E / slots
  free = E - sum(retained_admitted)
  reserve = sum over enrolled J != I of max(0, share - retained_admitted(J))
          + (slots - enrolled) * share     -- unenrolled slots reserve their whole share
  return free >= 1 and (retained_admitted(I) < share or free - 1 >= reserve)

admit (C2): lookup; Compacted -> AdmitOutcome::Fenced(synth); Unknown -> headroom and
            today's checks, insert allocation with issue_seq (trigger rechecks
            W <= seq < issue_next)
commit_fence: lookup; Compacted -> Absent(synth, replay = true);
              Unknown -> quota over retained never-admitted rows -> insert fence with issue_seq
inspect / remove / gc target: lookup with the request's digest; Compacted -> synth;
              Conflict, NotIssued, Malformed -> refuse, no action; Active -> as today

snapshot(I):                                -- first step of each Compact pass (RTC-13)
  p = issue_next(I);  newest = last checkpoint of I
  if p > newest.pointer and now - newest.time >= PASS:
    if count(I) == LEASE / PASS + 2: replace newest with (p, now)
    else: append (p, now)

advance(I):                                 -- compactor, after snapshot(I)
  target = max(W, min(highest checkpoint pointer older than LEASE, issue_next(I)))
  tx: if target == W and no fence row of I has issue_seq < W
                      and helper_generation >= G_W: done
      G = next_generation()                 -- also refreshes G_W for late pinned fences
      UPDATE instance_tokens SET watermark = target, watermark_generation = G
        WHERE instance_id = I AND watermark = W
      INSERT compaction_log(I, W, target, G, 0, 0);  commit
  drop every checkpoint of I with pointer <= W   -- the bound in RTC-13

compact_batch(I, 256):
  tx: for A in fence rows of I with issue_seq < W and helper_generation < G_W
          ORDER BY issue_seq LIMIT 256:
        if allocation row (I, A):
           require absent, claim released, leases released, workers settled
             (else: health fault naming the token, skip it; never delete)
           DELETE resource_events, stop_events, worker_intents, executable_leases,
                  identity_leases, capacity_claims (I, A); DELETE allocations (I, A)
        DELETE retired_tokens (I, A)
      UPDATE compaction_log counts;  commit

compactor (H, RTC-18):
  due(I) := 60 s since I's last pass, or I's last batch deleted max_tokens, or advance
            moved W with compactable rows left
  loop: for I in round-robin order with due(I):
          Compact { instance: I, max_tokens: 256 } on the compaction lane (one permit),
          awaiting each reply before the next
```

The headroom check keeps one invariant over every policy slot, enrolled or not:
Σ max(retained_admitted(J), share) ≤ E, which is free ≥ reserve with unenrolled slots
counted at their whole share. An admission below its share uses one entry of its own
reservation; an admission above it is allowed only if the invariant still holds afterwards;
compaction frees an entry for every row it deletes. So an instance below its share always
finds an entry. Enrollment (a root maintenance action with the helper stopped) within the
policy maximum changes neither `slots` nor `share`: it only gives an already reserved slot
an owner, so a new instance's whole share is free at once even while every existing
instance keeps live rows (the recheck model's counterexample, E = 7 with two slots, now
refuses the first instance's fifth row instead of the second instance's first;
`research/retired-token-compaction/model_rtc17_reserved_slots.py` exhausts small states,
15,522 admissions and 1,124 enrollments with live rows, and finds no refusal below share).
The price is borrowing: only the floor remainder is borrowable, so at the default policy
(128 MiB allowance, 6,143 admitted entries, 8 slots) every instance's ceiling is 774
retained admitted rows, including a lone instance on its node, where the earlier rule let
it take all 6,143. That still does not limit throughput. RTC-13 guarantees maturity within
one lease plus two passes, 17 minutes at the defaults (RTC-R2-04), so the conservative
sustainable rate is 774 / 17, about 45 completed sessions a minute per instance (51 is the
ideal lease-only figure). With B7's measured bound the ceiling is 616 (section 16.9), so
616 / 17 is about 36 a minute. Either is several times what a node can boot: three VM
slots at about 14 s per boot on mini-one is at most 12.9 new boots a minute, about 219
retained completions over 17 minutes plus three active sessions, 36% of 616. A node that
will only ever run one instance sets `max_enrolled_instances` to 1. The implementation cost is one counter column
kept by triggers and a sum over at most 64 instance rows per check.

**Clearing a rollback fault** (`kilnd-helper clear-node-faults`, new in B7). Root only,
over no socket, with the helper stopped: it takes the node lock exactly as `enroll` does,
so no H or L can run. It refuses to start without the report of the mandatory offline
inventory (section 16.7), produced by `kilnd-helper offline-inventory` under the same
conditions: every jail, cgroup, loop device, work file and VMM process walked against the
ledger, everything the ledger does not own settled or destroyed by root, and each enrolled
instance's daemon database read (read-only) for its Firecracker tokens. The walk is one
node-wide pass over six families, each listed from its owned base and mapped back only
through `host_name(instance, allocation)` of an active ledger allocation (and, where the path
names one, the same instance): jail directories (`jails/` and `jails/firecracker/`), jail
mounts (every mountinfo entry at or below the jail or work base, or with a `kilnd-jail-`
source, read through the private procfs), loop devices (every `/sys/block/loop*` whose
backing file, deleted or not, lies under either base), VMM and supervisor processes (every
process in the Firecracker cgroup tree, by its allocation subtree, and any `firecracker` or
`jailer` outside it), cgroups (instance and allocation directories) and work files. Anything
else under an owned base is an orphan, never adopted for looking like `fc-*`; any orphan in
any family, and any listing that cannot be read completely and within its bound, makes the
verdict `unexplained`, which the clear refuses. The report records
the ledger's highest generation at the end of the inventory, the fault rows it saw, for each
instance the highest token in its daemon database whose tag verifies, the digest of the
report itself and a verdict, `explained` only when no resource is left unaccounted for. The
clear is one IMMEDIATE FULL-sync transaction:

```text
clear(report):
  open audit passes (K and its check value, schema, counters)
  require report.verdict == explained
  require report.ledger_generation == highest generation in the ledger  -- nothing moved
  require report.faults == the node_faults rows present
  G = next_generation()
  for each instance I in report:
    UPDATE instance_tokens SET issue_next = max(issue_next, report.highest_seq(I) + 1)
      WHERE instance_id = I            -- never lowered; W untouched
  INSERT node_fault_clears(G, cleared_through = max fault generation,
                           sha256(report), the raised pointers)
  DELETE FROM node_faults WHERE generation <= cleared_through   -- trigger: needs row G
  commit
```

Raising each pointer past the daemon's highest verified token is what lets the helper start
and every daemon reattach immediately without faulting again, and it guarantees that no
token a daemon has recorded is ever issued a second time. The seqs between the old and the
raised pointer belong to the discarded future: rowless, they are Unknown until the restart
checkpoint matures and W passes them, then Compacted, exactly like abandoned issuance
(RTC-4), and the inventory has already proved that nothing owns them. A non-root caller,
a running helper, a missing, stale (`ledger_generation` behind) or unexplained report, or
any plain-SQL DELETE or UPDATE of `node_faults` is refused, and the attempt changes nothing.

**H and L replacement.** Three boundaries, each with its own contract and test:

- *L replaced while H's process lives.* The replacement L opens and audits the committed
  ledger, rereads K and verifies its check value, settles its predecessor (waits for the
  old L's exit and reaps it, so no two L processes ever hold the ledger) and journals
  itself as a node-level worker. Only then does H publish, in one atomic swap, the new
  channel together with the K that L sent over it. A request is bound to the channel it was
  sent on: a late reply on the old channel is discarded, never matched to a request on the
  new one, and its flow fails as ambiguous through the normal deadline path. H holds no
  pointer, watermark or row cache, so every later answer comes from the new L's committed
  state. Any pending RTC-14 fault is committed by the new L before it serves. K comes
  only in L's `Handover` reply, which always carries L's latch state (its `node_faults`
  kinds, the fail-stop marker and its in-memory latch); H imports that state, latching if
  any part is set, before it publishes the channel, so no channel is served whose handover
  omitted it. This is what keeps a fail-stop latched when L wrote the marker and died before
  H received its `SyncFailed`: H never saw the failure, but the replacement's handover
  carries the marker.
- *H's request-serving task or channel restarted while L lives.* The replacement task
  receives K over the private channel before it checks any tag, and accepts no reply that
  was addressed to the old task's channel.
- *H's process dies.* L's private worker socket closes, and L exits; nothing survives to
  be handed over. The whole helper restarts: a new H spawns a new L, which opens and
  audits as above. In-memory latches and checkpoints are gone, the durable fault rows and
  the exact pointer are not, and nothing advances for one lease.

**What exact issuance costs.** Today's Preflight writes nothing to the ledger
(`PreflightSnapshot` is a read), and the 424c74c design committed only every 64th issuance,
so persisting the exact pointer adds one FULL-sync commit per issued token. Measured on
mini-one with `research/retired-token-compaction/probe_issue_commit_cost.py` (WAL,
synchronous=FULL, one conditional single-row UPDATE per IMMEDIATE transaction, 2,000
commits): median 53 µs (p99 217 µs) with plain fsync, and median 168 µs (p99 443 µs) with
F_FULLFSYNC, which is the closer analogue of a real Linux flush. The Linux ledger in the
kiln VM (ext4 on the Lima virtio disk) was not measured here; the lifetime test records it.
An admitted session's modeled lifecycle already makes about 50 ledger write transactions
(the byte probe's sequence), so this is about 2% more ledger writes and nothing measurable
next to a 14 s boot. L serializes every transaction, so even at 1 ms per commit issuance is
limited to about 1,000 tokens a second, far above anything capacity admits. A Preflight
refused for headroom, quota or exhaustion aborts before the UPDATE and writes nothing, and
Preflight floods remain bounded by B3's per-instance limits and P's two slots, and since
issuance writes no memory and checkpoints are bounded (RTC-13), a flood of successful,
refused or reply-lost Preflights grows nothing in L. In return the pointer is exact across
restarts and never moves back: no seq is issued twice (some may be abandoned, RTC-4), and a
valid-tag seq at or above the pointer is NotIssued before and after restart.

**Crash points** to add to `firecracker-crash-matrix.py` (each a `b7_linux_root_crash_*`
scenario in `tests/recovery.rs`, run alone under the VM lock with the 90-minute uptime rule):

| Scenario | Fault point | Required outcome |
|---|---|---|
| Issuance before commit | `L.issue.before_commit` | Pointer unchanged; no token exists; the next Preflight issues the same seq, which is not a reuse because none was issued |
| Issuance: commit before the private reply | `L.issue.after_commit_before_reply` (L killed) | Pointer is n + 1 and seq n is **abandoned**: no daemon holds it, it is never reissued, and its token, computed by the harness from K, answers Unknown while W ≤ n and Compacted once W passes it; never NotIssued. No row, gate or claim |
| Issuance: private reply before the public reply | `H.preflight.after_l_reply_before_public` (H task killed, and separately the public reply dropped) | As above: abandoned, never reused, Unknown then Compacted; the daemon's Preflight fails with no row or charge (C0) |
| Issuance: public reply before C1 | `daemon.after_preflight_before_c1` (daemon killed) | As above; the restarted daemon has no row for it and never presents it |
| Issuance then P refusal | P refuses the manifest, spec or artifact after `IssueAndSnapshot` committed | Seq consumed and abandoned; Preflight answers its refusal with no token; the next Preflight gets n + 1; no fence row and no never-admitted quota spent |
| L replaced while H lives | Kill L mid-churn; separately, stall the replacement before and after its self-journal commit, and before and after H publishes its channel | H publishes the new channel and K together, only after the replacement settled its predecessor and journaled itself; nothing is served before that; a late reply on the old channel is discarded and its flow fails ambiguous; every answer comes from the committed ledger; open serialization entries settle with their flows; a pending RTC-14 fault is committed first |
| H task or channel restart while L lives | Restart H's request-serving task mid-churn | The new task receives K before any tag check and accepts no old-channel reply; L, the pointer and every row unchanged |
| H process death | Kill H's process mid-churn | L's private socket closes and L exits (asserted); the restarted helper opens and audits; durable faults latch again; no seq reused; no advance for one lease |
| Watermark advance | `L.compact.advance.before_commit`, `.after_commit` | Before: W unchanged. After: W durable, rows still present answer from rows, a Create below W gets the synthesized receipt and allocates nothing |
| G_W refresh for a late pinned fence | Advance W past a READY allocation, fence it at a generation at or above the old G_W, crash before and after the W-unchanged refresh and before and after its delete; restore the old READY daemon DB | Only a fresh synthesized receipt for the matching digest is accepted; nothing is compacted before the refresh commits |
| Delete batch, every boundary | `L.compact.delete.after_<family>` for each child family, `.after_allocation`, `.after_fence`, `.after_commit_before_reply`, `L.compact.sync_fail` | Every uncommitted batch rolls back whole and stays charged; after commit, a lost reply changes nothing; the rerun is idempotent |
| Non-compactable rows in a batch | A STOPPED, a QUARANTINED, a failed-cleanup, an unreleased-lease, an unsettled-worker and a root-replaced-resource allocation below W | Each is skipped with a health fault naming it and never deleted; the rest of the batch proceeds |
| Create racing compaction | Create held at `L.admit` while W passes its seq, and a delayed C2 released immediately before and immediately after W's commit | Fenced with the synthesized receipt or admitted and pinned, by commit order; zero claims in the fenced case; the daemon publishes FAILED released by that receipt |
| Remove racing compaction | Remove held at `H.remove.after_state` while its token is compacted | Impossible by RTC-10 (the token is not absent yet); the scenario proves the batch skips it and the Remove completes with its own receipt |
| Restored stale DB after compaction | Restore a daemon DB copied before 200 sessions, after compaction passed them, with H and L restarted | Every compacted row released by a synthesized receipt for its own Store digest; no VM, disk or claim; B6 admission blocking rules unchanged for active tokens |
| Helper restart resets checkpoints | Restart H and L mid-churn, with checkpoints at their bound | Issue pointer is exactly the committed one, a single restart checkpoint, no advance for one lease, no seq reused |
| Rollback fault commit | `L.fault.before_commit`, `L.fault.after_commit_before_reply`, `L.fault.sync_fail`, then a replacement L, then an H process restart | Forward effects refused from the moment of detection in every case; the replacement L commits the pending fault before serving; after the H restart the committed row latches at open, and an uncommitted fault is found again at the detecting daemon's next attach; Inspect, Stop, Remove, Gc and FenceAbsent keep working throughout |
| Offline fault clear | Kill the clear before and after its commit; run it with a stale report and with the helper running | Before commit: every fault row, the latch and the pointers unchanged. After: rows gone, a `node_fault_clears` row, raised pointers; the helper starts and every daemon reattaches at once with no new fault. Stale report or running helper: refused, nothing changed |

**Real-wire digest tests** (RTC-DR-01). `b7_linux_root_digest_*_after_restart`, one each for
Inspect (through reconciliation), Remove (through Delete) and Gc (through a direct
`FirecrackerRuntime::gc` call with typed targets), plus Create and FenceAbsent: finish a
session, compact all its rows, restart H and L, restore a charged daemon snapshot in which
the row is CREATING or DELETING, and drive the request through the real manager, adapter,
listener, H and L. Each must return `AbsentFenced` synthesized for the Store's digest, which
the daemon accepts through `commit_absence`. To prove no cache supplies the digest, the same
request sent with another digest must yield a receipt for that other digest, which the
daemon's match refuses, so the row stays charged; and while rows still exist, a mismatched
digest must answer Conflict with no action.

**Attack regressions** (`firecracker-regressions.py` and `tests/control_plane.rs`):

- **Replay a compacted token.** Capture tokens from finished sessions, wait for compaction,
  then replay Create (with the original plan), FenceAbsent, Remove, Inspect and Gc from the
  enrolled daemon's own unit: every answer is the synthesized `AbsentFenced`, with no row,
  claim, VM, disk, jail or worker, and Accounting unchanged.
- **Forged, foreign and unissued tokens.** Random IDs (the old format), a valid token with
  one tag bit flipped, seq 0, and another instance's valid token are refused by H with no L
  call and no gate (instrumented counters prove both). A valid-tag seq at and beyond the
  pointer reaches L and is NotIssued, before and after an L restart. Nothing is written
  (B3-03's PoC turned around).
- **Gates.** Fill an instance's gate table with closed gates, then present its pinned active
  token below W: L answers from rows. Reorder two concurrent issuance replies: both tokens
  work, since H holds no pointer.
- **Never-admitted flood.** Fence issued tokens until the window quota refuses, then advance
  the test clock one pass (a checkpoint) and one lease and prove the quota refills. The never-admitted quota is per
  instance, so other instances' isolation is proven by the two starvation tests below, not
  by this one.
- **Compactor starvation.** Keep the normal lane continuously nonempty from two instances for
  several leases while a third needs its quota refilled: compaction still runs at its
  RTC-18 share, W keeps pace, and the third instance's quota refills within a lease plus two
  passes.
- **Headroom hog.** One instance repeatedly takes every freed admitted entry while a victim
  below its share waits: the victim is never refused for headroom (RTC-17), and the hog is
  refused exactly when it holds its share plus the unreserved remainder, whatever the
  enrolled and unenrolled slots hold.
- **Rollback detector cannot be spoofed (RTC-14).** Instance A, attached on a node with an
  intact ledger, while instance B runs sessions: A attaches reporting the all-zero token,
  a token whose seq is A's current pointer with a guessed tag, seq 2^63 − 2 with a guessed
  tag, B's valid token, and A's own valid token with one tag bit flipped; a frame carrying
  the old bare `highest_issue_seq` is refused by the strict codec. Each fails A's
  attachment alone: no `node_faults` row, no latch, no write; B's Preflight, Create,
  Validate and Exec keep succeeding throughout and B's Health is unchanged; A then
  reattaches with its honest highest token and works.
- **A real rollback sets the latch.** Copy the ledger with the helper stopped, issue a
  token to A and let A record it, then restore the copy and start: A's attachment reports
  that valid token at or above the restored pointer and a `node_faults` row is written.
  Then, on A, on B and on a newly enrolled C: Preflight, Create, Validate, Exec and C's
  first binding are refused with no effect; Inspect, List, Stop, Remove, Gc and FenceAbsent
  on B's existing session succeed and drain it. The latch survives H and L restarts and a
  host reboot. `clear-node-faults` is refused for a non-root caller, with the helper
  running, and with a stale or unexplained report; after the offline inventory the clear
  commits, the helper starts, A, B and C reattach at once with no new fault, and A's next
  token is above the one it recorded (nothing reissued).
- **Checkpoint memory bound (RTC-13).** For five leases, two instances flood at the most
  B3's limits allow: Preflights abandoned before C1, Preflights P refuses after issuance,
  Preflights whose public reply is dropped, C0 refusals, and successful sessions. The
  instrumented checkpoint count never exceeds 17 per instance, L's RSS stays within a fixed
  bound after the first lease, and once the flood stops W reaches the final pointer within a
  lease plus two passes.
- **Enrollment while borrowers keep live rows (RTC-17).** A test policy with E = 7 and two
  slots (share 3): A holds four READY sessions (its share plus the remainder) and keeps
  them; B is enrolled with the helper stopped, and after start B's first three admissions
  succeed at once while A's fifth is refused. Repeated at the default policy with seven
  instances each holding live rows at their ceiling before the eighth is enrolled. At the
  ordinary boundary, fill all admitted space across instances, race Preflight against C2
  from every instance, and prove every already admitted token still fences (its Remove gets
  its receipt; no admitted token is refused a fence).
- **Exact L queues (RTC-18).** Hold 28 normal, 4 reserved and 64 attach frames enqueued, then
  make a compaction due: L's instrumented frame order shows at most 96 frames served before
  the batch, and a reserved recovery call enqueued behind a full 256-token batch waits for
  that one batch only. The test records p50 and p99 of a full batch and fails above 100 ms
  until the batch size is lowered.
- **Typed Runtime boundary (section 9.1).** `FirecrackerRuntime` refuses
  `RemoveTarget::Legacy` in `remove` and in `gc` with zero frames written (wire counter),
  through a direct call and through the manager's Delete of a historical kiln row, which
  stays DELETING and charged while Health reports the count. A Gc vector mixing another
  node's binding, another instance's binding, a duplicate or a `Legacy` target is refused
  whole with nothing sent. Over the real wire, a hand-built Gc frame that puts another
  instance's token among valid ones is refused whole by H with no L call and no action. A
  mismatched digest while rows exist answers Conflict with no action; an arbitrary digest
  for a rowless token below W gets a receipt for that digest, which the daemon's match
  refuses. A compile-time contract, one generic `fn runtime_contract<R: Runtime>()`
  instantiated for `FakeRuntime`, `KilnRuntime`, `DirectKilnRuntime` and
  `FirecrackerRuntime`, calls every section 9.1 method with both `RemoveTarget` variants
  and `PreparedCreate::allocation_id()`, so any signature drift fails the build; behavior
  tests show the kiln adapters refuse `Fenced` and `FakeRuntime` models both regimes.
- **Pinned active session.** Keep one session READY while 5,000 others churn past it; it
  still validates and executes, is never compacted, and its eventual Remove returns its own
  receipt before it is compacted in turn.
- **Synthesized receipt changes.** Publish synthetic receipt R1, advance G_W, then receive
  the matching R2: an already-released row keeps R1 and stays idempotently released; a
  charged stale row accepts R2 only when its generation is newer than the row's own last
  publication.
- **Clock lifecycle.** On the injected boot clock: step forward a day and back a day (W jumps
  or stops, in-flight Creates fail released, nothing below W is admitted); suspend and
  resume (BOOTTIME advances while no process runs); reboot (BOOTTIME resets; the restart
  checkpoint waits a lease); helper-only restart.
- **Key lifecycle.** Missing, truncated and same-length substituted K (with and without rows
  left to check against; the check value catches the rowless case); UPDATE, DELETE and
  REPLACE of `token_key` refused through standard SQL; a crash during provisioning leaves no
  half-provisioned ledger; open never regenerates K; K appears in no public or wire reply,
  log or error (scanned) and crosses only the private L-to-H channel; drain and
  re-provision documented for loss or compromise.
- **Rollback boundaries, with expected limits marked.** Same-block restore (a ledger copy
  taken before a token the daemon then records): RTC-14 detects it from a verified token and
  latches every forward effect node-wide (the latch regression above). Restore after issuance but before C2, restore of both databases, a ledger
  cloned into two helpers, and retention of a live resource from the discarded future:
  **expected limitation**, the test asserts that the outcome is the documented one (no
  detection, or a re-minted token) and that the section 16.7 offline inventory finds the
  live resource. A ledger with a different K: the open audit fails closed.
- **Bounds.** `issue_next` at 2^63 − 1 refuses Preflight with a fault and never wraps; W and
  the pointer cannot be lowered; every bounded row family at its true maximum fits the
  measured per-token bound, including B5-01's settled-worker retention.
- **Trigger matrix.** Extend `exit6_every_unique_key_and_conflict_algorithm_is_guarded`: every
  delete of a non-compactable row, every lowering of W or the pointer, every insert below W
  or at or above the pointer, every write to `token_key`, every UPDATE of `node_faults` and
  every DELETE of it without this transaction's covering `node_fault_clears` row, every
  write to `node_fault_clears` outside the clear, and every counter drift fails through
  standard SQL with triggers on.

**The lifetime test past 16,384 issuances per instance.** `b7_lifetime_past_16384_sessions`
runs the real H and L processes behind the real listener, with a real FULL-sync ledger and
B3's fake host effects, two attached instances under the default policy (8 slots, so a
ceiling of 774 retained admitted rows each), and lease 60 s on the injected clock. After
every 500 admitted sessions per instance the test advances the clock one pass (each
instance's compaction pass takes a checkpoint) and then one lease (the next pass advances
W and compacts), so retained admitted rows stay near 500 and below the ceiling. **Each
instance** drives **14,000 admitted sessions** (create, three executions, Remove) plus
**2,500 post-C1 refusals**: 16,500 issuances per instance, 33,000 in total. The refusals are
interleaved on a fixed schedule, one after roughly every 5.6 admitted sessions (at most 90
per 500-session window), never in a run: 500 consecutive refusals would exceed the
256-per-window quota and its 192 issuance floor. Per instance it asserts the issue pointer
past 16,385, retained never-admitted rows at most 192 at every window boundary, no
LedgerSpace, headroom or quota refusal ever, and every session released by a receipt the
daemon accepted. Separately, for the node,
it asserts 28,000 admitted sessions (past the old 12,287-session limit and the old
16,384-entry count), retained rows never above the allowance, the ledger's live bytes flat
after the first lease, and open-audit time flat. Finally it issues one token on one instance
and goes idle for two leases: W reaches the exclusive pointer, that last token is compacted,
and the instance retains no rows (RTC-DR-06). It runs on macOS and in CI and records its
duration and the per-commit cost (about 1.4 million ledger transactions; if CI cannot
afford it, it moves to the nightly job rather than shrinking the counts). On the real chain
(boot to READY is about 14 s on mini-one's nested KVM, so 16,384 real boots would take about
a day), the companion `b7_linux_root_compaction_cycles` uses a test policy of a 64-entry
allowance, `max_enrolled_instances` 1 (so its one instance's share is all 47 admitted
entries, RTC-17) and a 3-minute lease and runs 300 real sessions, crossing the old count limit
about five times over and many compaction cycles, inside one VM window.

**B7 acceptance criteria.**

1. RTC-1 to RTC-18 hold, each named by at least one failing-without-the-rule test.
2. The lifetime test passes with more than 16,384 issuances on each instance and no
   admission refusal for ledger space, and the real-chain cycle test passes at more than
   five times the configured entry count.
3. B6's eleven crash scenarios and seven regressions still pass, plus the eighteen B7
   crash scenarios, the real-wire digest tests and the attack regressions above.
4. The fence allowance's per-token bound is the measured worst case, not an estimate.
5. Daybreak attacks this design and its implementation and finds no path to a VM, disk,
   claim release, absence, DELETED row or READY for a compacted token (or Stephen accepts a
   named residual risk).
6. Section 4.1's "never prune fences by age" and B3's lifetime-budget limit are rewritten
   to point here (section 9.1's Runtime listing already is), and the operator docs describe
   the new Health fields, the restore and fault-clear procedure in sections 16.6 and 16.7,
   and the kiln-row drain before selecting Firecracker.

## 16.7 Residual risks and open decisions

- **Restored or cloned node ledger: outside the fault model.** Restoring or copying
  `node.db` is root's action. RTC-14 detects only a ledger older than every token its
  daemons have recorded. These are not detected, and the design does not claim otherwise:
  a ledger restored to a point after the daemon's last recorded token, whose tokens issued
  before the copy but compacted after it become Unknown and C2-admittable; a coordinated
  restore of the ledger and the daemon database together, after which the next Preflight
  re-mints the identical token (and its jail and work names, which may still exist from the
  discarded future); and two helpers running clones of one ledger, which mint identical
  tokens (the node lock excludes two helpers on one node, not a copy on another host or VM).
  Because K is inside the ledger, every copy carries it; there is no "ledger restored but
  key kept" state. Closing these would need rollback-resistant authority outside the
  ledger and daemon pair, such as a TPM monotonic counter or a remote witness, which is not
  in Phase 1b. **Operator procedure:** any restore, copy-back or suspected clone of
  `node.db` is treated as ledger loss (section 8.3): stop every instance's daemon and the
  helper, take a mandatory node-wide offline inventory of every jail, cgroup, loop device,
  work file and VMM process against the ledger, settle or destroy everything the ledger
  does not own, and only then let the helper serve; if any resource cannot be explained,
  re-provision after verified absence. The same applies after an RTC-14 fault.
- **Key loss or compromise.** K never rotates. Recovery is node-wide drain, verified absence
  and re-provisioning, as for any ledger loss. A substituted K with every old row already
  compacted may not be visible from rows (the check value is root-writable like the rest of
  the ledger); old tokens then fail as Malformed and stay charged, which is safe.
- **Admission share.** RTC-17 reserves a share for every policy slot, enrolled or not,
  in place of the earlier "shared, first come" allowance: an instance below its share is
  never refused for headroom, and a newly enrolled instance's share is free at once. The
  cost is borrowing: only the floor remainder can be borrowed, so at the default policy
  every instance, a lone one included, holds at most 774 retained admitted rows instead of
  up to 6,143. At the defaults that is still several times what a node can boot; a node
  that runs fewer instances lowers `max_enrolled_instances`. A policy change that shrinks
  the share while instances hold more is reported, and the guarantee returns as those rows
  drain. Recommendation: keep it; measure at B7.
- **Compaction share.** RTC-18 bounds a batch's wait to the frames already enqueued (at
  most 96) and every frame enqueued behind a batch to that one batch. It preserves reserved
  capacity, not priority, and its bounds start at enqueue. B7 measures a full 256-token
  batch's duration and lowers the batch size if it exceeds 100 ms.
- **Rollback latch.** A genuine RTC-14 detection stops new work on every instance until root
  runs the offline inventory and the fault clear; that is the intended cost of a node whose
  ledger is provably behind a token it issued. No instance can cause it without a
  helper-issued token for which the ledger's pointer is behind. *Chosen resolution of
  RTC-R2-01 (lead decision, November 4): fail-stop.* L writes a durable fail-stop marker
  (`failstop`, beside the ledger) the moment it detects a verified future token, before it
  answers H or attempts the fault commit, and on any failed or uncertain ledger commit. A
  helper that finds the marker latched at start refuses every forward effect, whatever the
  fault row's fate, until root's offline inventory and clear-node-faults reset it. The
  window the recheck named (a lost fault commit followed by a whole-helper restart) is
  closed: `b7_crash_rollback_fault_commit_at_every_boundary_keeps_forward_effects_refused`
  kills the whole helper after a commit that never landed and finds it still latched. What
  remains is a marker write that itself fails while H dies before any replacement L can
  commit the pending fault: the node then reopens until the detecting daemon reattaches.
  The cost of fail-stop on every sync failure is stated plainly: one transient fsync error
  on the node ledger stops new work node-wide until root intervenes; cleanup and reads keep
  working.
  *Corrected after the milestone 1 break-it review:* the marker alone was not enough while H
  lived, because H latched only when its own request received `SyncFailed`; an L killed
  between writing the marker and replying left H unlatched, and the replacement L admitted a
  prepared token. Every L's handover now carries its latch with K and H imports it before
  publishing the channel, and L refuses forward writes under its own latch whatever H
  sends. The remaining residual is unchanged: a marker write that itself fails.
- **Abandoned issuance.** Some issued seqs are never delivered (RTC-4). They cost nothing
  but a number; Accounting's `issue_next` therefore counts issuances, not sessions.
- **Daemon-side growth.** `release_evidence` rows (about 1 KB each with indexes) stay
  permanent in each daemon database. That is disk, not a ceiling, and nothing refuses
  admission on it. Pruning evidence together with its retention-pruned sandbox row is safe
  once tokens are helper-issued, except that it lowers RTC-14's recorded maximum, so a
  follow-up after B7 must keep the highest complete token as its own permanent value.
- **Daemon digest cache.** The daemon keeps each allocation's Store plan digest in memory
  only from Create (after C1) to the allocation's terminal answer, so Validate and Exec can
  read the boot after a restart. A hard cap of 5,120 entries (the 1,024-allocation complete
  listing bound plus the 4,096 node-wide token gates) is a backstop, never an eviction:
  at the cap Preflight is refused `RESOURCE_EXHAUSTED` before any seq is issued. One benign
  race remains: a reconciliation Inspect answered live just before a concurrent Remove
  finishes can re-learn one entry after the Remove forgot it; the cap bounds it.
- **What the offline inventory cannot see.** It reads the mount namespace and cgroup
  namespace it runs in, so root runs it from the host's initial namespaces. The helper unit
  runs in its own mount namespace (`ProtectSystem=strict`), so with the helper stopped its
  jail mounts survive only through a surviving jailer or VMM process, which the process
  family reports; a mount namespace kept alive some other way (a bind-mounted nsfs file) is
  not walked. That is root's own action and outside the fault model, like a ledger restore.
- **Synthesized receipts differ from originals.** A daemon that lost its terminal commit
  after compaction gets a different, equally valid receipt, and a later G_W gives yet
  another. Section 8.3's "replay the same receipt" becomes "replay a matching receipt"; B6's
  assertion that `release_evidence_id` equals the fence's receipt holds whenever the fence
  row still exists.
- **Node-level worker rows** (infrastructure workers recorded at each helper start) remain
  permanent; they grow with helper restarts, not sessions, and are out of this scope.

## 16.8 Design review and recheck corrections (November 4, 2026)

Daybreak Blue's design review of `424c74c` (`reviews/2026-11-04-rtc-design-review.md`,
models in `reviews/poc-rtc-design/`) rejected the design as written for one HIGH and found
the rows-first core sound. Every finding is accepted; none is rejected.

| Finding | Change |
|---|---|
| RTC-DR-01 (HIGH) Synthesized receipts need a digest that Inspect, Remove and Gc did not carry | Inspect and Remove gain a required `plan_digest`; Gc targets become `(allocation_id, plan_digest)` pairs; `remove` and `gc` take a typed `RemoveTarget` carrying the Store's immutable binding, and the adapter sends the digest `inspect_allocation` already receives. Rows win and a mismatched digest is Conflict; below W with no rows the receipt is synthesized for the caller's digest. "Compacted, then FenceAbsent" rejected (second round trip, race window). RTC-6, RTC-8, message table, Runtime signatures, replay analysis, real-wire tests after helper restart |
| RTC-DR-02 (MEDIUM) RTC-14 misses same-block, coordinated and cloned-ledger rollback | Ledger restore stated as outside the fault model and RTC-14 as a partial detector (RTC-14, sections 16.2, 16.3, 16.7, the brief). Blocks of 64 replaced by the exact pointer, persisted with each issuance in Preflight's issuance transaction (measured: about 0.17 ms per commit, about 2% more ledger writes per session), which closes the same-block case. Undetected cases listed; detection now closes admission node-wide with a durable fault; mandatory node-wide offline inventory after any restore |
| RTC-DR-03 (MEDIUM) Idle-only compaction can starve; "at most one lease" unproven | RTC-18: compaction on its own one-permit lane, waiting behind at most 96 queued requests, never taking cleanup or recovery permits. RTC-17: a guaranteed per-instance share of admitted headroom with borrowing, which replaces the "at most one lease" claim with "never refused below its share". Starvation and headroom-hog tests |
| RTC-DR-04 (MEDIUM) H's classification state underspecified | Contract (1): H checks only tag and seq ≠ 0; L classifies NotIssued, rows, Compacted and Unknown inside its transaction; H keeps no pointer and never infers Compacted; gates follow L's answer. RTC-3, RTC-15, pseudocode, H/L split-restart crash scenario |
| RTC-DR-05 (MEDIUM) Lifetime arithmetic could not reach 16,384 on both instances | Per-instance counts: 14,000 admitted plus 2,500 refusals each (16,500 issuances per instance), node-lifetime property asserted separately |
| RTC-DR-06 (LOW) Checkpointing seq keeps the last token | Checkpoints record the exclusive pointer (`issue_next`); the lifetime test's idle tail proves the last token compacts |
| B7 test-plan gaps 1 to 12 | 1: real-wire digest tests. 2: G_W refresh crash scenario. 3: every delete boundary and the non-compactable-row scenario. 4: synthesized receipt changes. 5: issuance oracle corrected (an issued rowless token is Unknown, not NotIssued) plus H/L split restart. 6: tag-check instrumentation, NotIssued before and after restart, reordered replies, pinned token with a full gate table. 7: rollback boundaries with expected limits marked. 8: compactor starvation and headroom hog. 9: clock lifecycle. 10: key lifecycle (and RTC-1's key rules). 11: per-instance lifetime counts and the idle tail. 12: overflow and true-maximum bounds |
| Rejected alternatives | Unchanged verdicts; D's "a filter cannot delete" narrowed to plain filters, with rotating filters needing generations or epochs |
| Key handling | RTC-1: CSPRNG key in the provisioning transaction, check value, immutable by trigger, never regenerated or logged, no rotation; drain and re-provision on loss (section 16.7) |

### Design recheck corrections (November 4, 2026)

Daybreak Blue's recheck of `01daf61` (`reviews/2026-11-04-rtc-design-recheck.md`, model in
`reviews/poc-rtc-design-recheck/rtc_recheck_model.py`) closed RTC-DR-01 and RTC-DR-04 to
RTC-DR-06, closed RTC-DR-02 and RTC-DR-03 with residuals, and rejected the revision for one
new HIGH. Every finding is accepted.

| Finding | Change |
|---|---|
| RTC-RC-01 (HIGH) An instance could durably fault every other instance with a bare `highest_issue_seq` | AttachInstance carries `highest_token`, a complete token or none; H and L verify its tag for the authenticated instance before comparing its seq. A malformed, foreign, bit-flipped or bad-tag report fails only that attachment, with no fault row. Only a verified token at or above the pointer sets the durable latch, which refuses Preflight, Create, Validate, Exec and every other forward effect node-wide (section 8.3's ledger-loss rule) and keeps Inspect, List, Stop, Remove, Gc and FenceAbsent. An uncertain fault commit keeps the latch closed in memory and is handed to every replacement L. New root clear (`clear-node-faults`, helper stopped, node lock, after the offline inventory; raises pointers past the daemons' verified tokens, never W), the single exception to insert-only `node_faults`, enforced by trigger. RTC-14, RTC-16, schema, message table, pseudocode, spoof and real-rollback regressions, fault-commit and clear crash scenarios, trigger matrix |
| RTC-RC-02 (MEDIUM) `issue_next` is exact, but delivery is not gap-free | RTC-4 restated as an exact durable high-water pointer: never reused, possibly abandoned before delivery, safe under the classifier (Unknown, then Compacted; an unescaped tag cannot be computed). No delivery acknowledgement added. Crash table split into commit-before-private-reply, private-before-public reply, public reply before C1 and P refusal after issuance; "delivered" wording removed |
| RTC-RC-03 (MEDIUM) Per-issuance checkpoints were unbounded | Issuance writes no memory. Each compaction pass snapshots the exclusive pointer, at most one point per pass until it matures plus the restart and tail point (17 per instance at the defaults), pruned at or below W; overflow overwrites the newest point. Maturity is now within a lease plus two passes. RTC-13, pseudocode, checkpoint-flood regression with a fixed memory bound |
| RTC-RC-04 (MEDIUM) Section 9's normative Runtime listing contradicted B7 | Section 9.1 rewritten: `PrepareContext` before `prepare`, `PreparedCreate::allocation_id()` (helper token for Firecracker, `None` for kiln), the legacy ID generated after `prepare` and before C1, `CreateContext` after `prepare`, `RemoveTarget { Legacy, Fenced { binding } }` for `remove` and `gc`. `Legacy` stated as reachable on Firecracker through legacy Delete, compensation and Gc, refused before any wire call; historical kiln-row drain documented; all-or-nothing Gc validation; compile-time contract tests for FakeRuntime, kiln, DirectKiln and Firecracker. "Section 8's listing" corrected to section 9 |
| RTC-RC-05 (MEDIUM) A newly enrolled instance's share could stay borrowed indefinitely | Every policy slot reserves its share, enrolled or not; unenrolled shares are never borrowed, and only the floor remainder is borrowable, so enrollment finds its share free and "never refused below its share" holds. Stated cost: a single instance at the defaults holds at most 774 retained admitted rows (767 + 7) instead of 6,143; `max_enrolled_instances` 1 restores 6,143. Policy changes that shrink the share are the reported exception. Model `research/retired-token-compaction/model_rtc17_reserved_slots.py`; enrollment-with-live-rows regression |
| RTC-RC-06 (LOW) RTC-18's service wording was stronger than its mechanism | RTC-18 phrased at the queue boundary (bounds start at enqueue) and as reserved capacity, not priority; 100 ms batch cap kept. Test saturates all three other lanes and measures the 96-frame wait and a full 256-token batch |
| RTC-RC-07 (LOW) H/L restart tests needed exact process boundaries | Three cases: L replaced while H lives (new channel and verified K published atomically only after the replacement settled its predecessor and journaled itself; stale replies stay bound to the old channel), H task or channel restart while L lives, and H process death (L exits). RTC-1 now says K never appears in a public or wire reply |
| Test-plan sufficiency 1 to 8 | 1: spoof set, real rollback, fault-commit loss, restart persistence, every forward operation denied, cleanup kept, non-root and running-helper clear refused, offline clear with immediate reattach. 2: the four issuance boundaries, no reuse, documented gap, Unknown then Compacted. 3: checkpoint flood over five leases with a fixed count and RSS bound and final maturity. 4: enrollment with live borrower rows, plus the full-space Preflight/C2 race proving admitted tokens fence. 5: exact L queues. 6: Legacy refusal before the wire, mixed-node and mixed-instance Gc, mismatched digest with rows, arbitrary digest without rows, compile-time contract. 7: replacement handover at each boundary. 8: lifetime refusals interleaved at most 90 per window, under the quota and its issuance floor |

## 16.9 B7 milestone 1: retired-token compaction as built (November 4, 2026)

Branch `phase1b/b7-compaction` from main `1c107f9`. Everything in section 16.6 is built:
helper-issued tokens and the key, node ledger schema 2, the classifier, compaction and its
lane, the RTC-17 shares, the RTC-14 latch with root's offline commands, group schema 2 and
the section 9.1 Runtime contract. Production Firecracker stays disabled (milestone 3).

### Where it lives

| Piece | Code |
|---|---|
| Token form, HMAC-SHA-256 over `sha2`, the key, its check value and its private transfer form | `helper/firecracker/token.rs` |
| Schema 2 tables and triggers, issuance, classification, admission and fence changes, watermark advance, compaction batch, RTC-17 shares, fault commit and offline clear, the open audit | `helper/firecracker/journal.rs` |
| L's checkpoints, boot clock and fail-stop marker | `helper/firecracker/compaction.rs` |
| L's protocol (`IssueAndSnapshot`, `Handover` (K with the latch), `CommitFault`, `Compact`, `FaultPending`, `SyncFailed`, `Latched`), its in-memory latch and its forward-write refusal | `helper/firecracker/workers.rs` |
| H: tag checks before any gate, the latch gate, issuing Preflight, digests on Inspect, Remove and Gc, the compactor task, key handover with each L | `helper/firecracker/mod.rs`, `lifecycle.rs` |
| Root's `offline-inventory`, `clear-node-faults` and `ledger-stats` | `helper/firecracker/offline.rs`, `bin/kilnd-helper.rs` |
| Group schema 2 wire | `helper/protocol.rs` |
| `PrepareContext`, `PreparedCreate::allocation_id`, `RemoveTarget` | `runtime/mod.rs`, every adapter, `manager.rs` |
| The daemon's highest recorded token | `store.rs` (`highest_fenced_token`), `runtime/firecracker.rs` |

### Lead decisions on the recheck's notes

- **RTC-R2-01, fail-stop** (section 16.7). L writes the `failstop` marker at detection and on
  any failed commit; every later helper latches at start until the offline clear resets
  it. Tests: `b7_rtc_r2_01_an_uncertain_fault_commit_fails_stop_across_every_restart`,
  `b7_crash_rollback_fault_commit_at_every_boundary_keeps_forward_effects_refused` (its
  fourth case kills the whole helper after a commit that never landed).
- **RTC-R2-02.** An empty checkpoint list takes `(issue_next, now)` at the next pass
  (`Compactor::snapshot`). Tests: `rtc_r2_02_an_empty_list_takes_the_next_pointer_at_once`,
  `rtc13_nothing_advances_for_a_lease_after_start_and_an_idle_tail_compacts` (drain, idle,
  issue one: compacted within a lease plus two passes), and the lifetime test's idle tail.
- **RTC-R2-03.** L answers `FaultPending` having latched and written nothing; H latches
  atomically and only then sends `CommitFault`. Queued work rechecks the latch at its last
  boundary: Preflight before issuance, Create after C2 and before any host effect, Validate
  and Exec at dispatch. Test:
  `b7_rtc_r2_03_h_latches_before_the_commit_and_queued_work_starts_nothing` holds H between
  its latch and the commit, proves no fault row exists yet, and releases a Create held after
  C2: it answers `latched` with no supervisor and no host effect.
- **RTC-R2-04.** The capacity arithmetic uses the 17-minute worst case (section 16.6).

### Changes from the design, and why

- **The per-token bound is 20 KiB, not 16.** `b7_fence_entry_bound_is_the_measured_worst_case`
  fills every bounded family of one allocation to its cap (sixteen stop reasons of the
  longest length, eight settled workers in each real mode, every resource kind with every
  field at its widest, an execution left in flight, a long receipt) and measures about
  18.0 KB per token. The defaults therefore become 6,553 entries, a pool of 1,638, a share
  of 614 and a ceiling of 616 (section 16.4). The lifetime schedule still fits: 500 sessions
  per window under 616, and at most 90 refusals per window under the 153 issuance floor.
- **The delete batch is 16 tokens.** A full 256-token batch of admitted sessions took 310
  to 580 ms on mini-one, and 32 about 40 ms idle but up to 195 ms on a loaded host; 16 keeps
  the measured batch under RTC-18's 100 ms
  (`b7_rtc18_compaction_has_its_own_lane_and_a_full_batch_stays_under_100_ms`).
- **The frozen B1 launch contract still says 64 MiB.** Its `shared.fence_allowance_bytes`
  is pinned into every guest bundle through `contract_sha256`. The allowance is helper-only
  ledger accounting that no guest or plan consumes, so B7 changes the helper's default and
  leaves the contract; reconciling the contract's value needs a bundle rebuild.
- **Preflight takes its preparation slot before issuing.** A busy node refuses without
  consuming a seq, instead of abandoning one for every refused Preflight.
- **Fail-stop on any failed commit** (lead decision). Earlier tests that injected a sync
  failure and then created again now expect the latch.
- **The crash scenarios run through the B3 fixture.** Each `b7_crash_` test in
  `tests/compaction.rs` uses the real H, L, listener and adapter (and, for the restored
  database, the real manager and Store) with fake host effects and a FULL-sync ledger, at an
  exact fault point. They run on macOS and in CI, and in the kiln VM through
  `scripts/firecracker-crash-matrix.py` (the attack regressions likewise through
  `scripts/firecracker-regressions.py`), whose runner gives these unprivileged scenarios to
  `cargo test` as the calling user: the fixture enrolls the test process's own account, and
  an instance account is never root. Real VMs add nothing at these boundaries, which are
  ledger and process boundaries; `b7_linux_root_compaction_cycles` and the B4 to B6 suites
  cover the real chain.
- **"H task or channel restart while L lives" is not a reachable boundary here.** H owns
  exactly one channel per L process; the only swap is an L replacement, which publishes the
  new channel and its K together (`b7_crash_ledger_replaced_while_h_lives_serves_nothing_before_publication`).
- **The lifetime test cannot execute.** B3's fake effects have no broker, so each fake
  session is Preflight, Create and Remove; the real-chain test runs one execution per
  session.
- **First attachment is no longer refused for space.** RTC-17 reserves every policy slot's
  share, so `AttachOutcome::NoSpace` is gone; enrollment past the policy maximum is refused
  when it would leave a slot short of its share, and a policy whose allowance cannot give
  every slot a never-admitted window (fewer than four entries per slot) is refused.
- **A B4 adoption race, found by the real-chain run.** J exits once it has cloned V and
  written the PID file, which can be before V has dropped to the VMM's IDs and exec'd.
  Until then the ptrace-read check on `/proc/<V>/exe` refuses S, which takes the VMM's
  filesystem IDs for it, so on a loaded host a few launches in a hundred were refused
  `at adopt: Permission denied`. S now waits out exactly that refusal, within five seconds
  and while V lives, and still checks the observed image against the journal. Refusal
  reasons now name the launch step they came from.
- **The VM test build optimizes dependencies.** `scripts/b4-vm-tests.sh` builds kilnd's
  own code as before (debug, with overflow checks) but its dependencies at `opt-level=2`:
  a real helper hashes its image and parses the bundle's 33 MB manifest at start and in
  every Preflight, which unoptimized `sha2` and `serde_json` made slower than the wire
  deadlines. The faster helper start exposed a test race in B6's capacity scenario (the
  Delete became the daemon's first call to the restarted helper, while Health answered
  from its 5 s cache); the scenario now lets a fresh Health probe reattach first.
- **The offline inventory reports and destroys nothing.** Root settles whatever it names
  and runs it again; the clear accepts only an `explained`, canonical report, read through
  a protected walk, whose digest, ledger generation, fault set, fail-stop state and instance
  set all match the stopped node.

### Rules to code and proving tests

| Rule | Code | Tests (those that fail without the rule) |
|---|---|---|
| RTC-1 key and token form | `token.rs`; `Ledger::provision`, `audit_token_key`; `token_key` triggers | `rtc1_*` in `token.rs` and `journal/b7_tests.rs`; `rtc16_accounting_reports_only_the_callers_token_figures` (no K in replies) |
| RTC-2 only the helper mints | `Node::preflight`, `issue_and_snapshot`; `verify_prepared`; manager's context after `prepare` | `exit1_prepared_wire_is_reconstructed_and_verified_field_by_field`, `b7_runtime_contract_compiles_for_every_backend` |
| RTC-3 H checks the tag, L classifies | `Node::check_token`; `Ledger::lookup_on` | `b7_rtc3_forged_foreign_and_seq_zero_tokens_never_reach_a_gate_or_l`, `b7_rtc3_a_valid_tag_at_the_pointer_reaches_l_and_is_not_issued_across_restarts`, `rtc3_rtc6_l_classifies_*` |
| RTC-4 exact pointer | `issue_and_snapshot`; `instance_tokens_monotonic` | `rtc4_*`, the four `b7_crash_issuance_*` scenarios |
| RTC-5 watermark | `advance_watermark`; triggers | `rtc4_the_pointer_never_wraps_and_never_moves_back`, `b7_crash_watermark_advance_before_and_after_its_commit` |
| RTC-6 rows outrank W, digest binds | `lookup_on`; `remove_inner`, `gc_flow` | `rtc3_rtc6_*`, `b7_rtc8_real_wire_digests_after_compaction_and_a_helper_restart` |
| RTC-7 nothing admitted below W | lookup in C2; `allocations_issued_above_watermark`, `retired_tokens_issued` | `rtc7_nothing_below_w_is_admitted_or_newly_fenced_even_by_raw_sql`, `b7_crash_a_create_racing_compaction_is_fenced_or_pinned_by_commit_order` |
| RTC-8 compacted means absent | `compacted_receipt`; every flow's `Compacted` arm | `rtc8_compacted_receipts_bind_the_callers_digest_generation_and_write_nothing`, `b7_rtc8_real_wire_*`, `b7_crash_a_restored_stale_daemon_db_after_compaction_releases_by_synthesized_receipts` |
| RTC-9 never stale | G_W refresh in `advance_watermark` | `rtc9_a_late_pinned_fence_refreshes_g_w_before_anything_is_compacted`, `b7_crash_g_w_refresh_*`, `b7_crash_a_remove_racing_compaction_*` |
| RTC-10 only absent rows | `compact_batch`; delete triggers, child order by explicit `NOT EXISTS` | `rtc10_*` (trigger matrix, stuck rows, `rtc10_child_order_triggers_hold_with_foreign_keys_off`), `b7_crash_non_compactable_allocations_below_w_are_never_deleted` |
| RTC-11 crash-safe, idempotent | separate transactions; fault points | `rtc11_*`, `b7_crash_delete_batch_rolls_back_whole_at_every_boundary` |
| RTC-12 quotas per window | `never_admitted_fences` over retained rows; issuance floor | `rtc12_*`, `b7_rtc12_*`, `b7_crash_issuance_then_a_preparation_refusal_*` |
| RTC-13 bounded checkpoints, bounded daemon cache | `Compactor`; `FirecrackerRuntime::digests` (`DigestCache`, `LearnClaim`), `MAX_DIGESTS` | `rtc13_*` (unit and ledger), `b7_rtc13_a_five_lease_flood_*`, `b7_crash_a_helper_restart_resets_checkpoints_*`, `b7_crash_h_process_death_*`, `b7_rtc13_completed_sessions_leave_no_digest_entries`, `prepare_at_the_digest_cap_is_exhausted_before_any_helper_call`, `b7_rtc13_stale_inspects_racing_removes_never_fill_the_digest_cap`, `stale_learns_after_terminal_answers_never_fill_the_digest_cap`, `a_complete_inventory_drops_only_unclaimed_unlisted_digests` |
| RTC-14 verified rollback, latch | `attach_instance`; `Node::rollback_detected`, `set_latch`, `fetch_key` (latch with K); `workers::allowed_under_latch`, `LedgerRequest::fault_bearing`, `Channel::call_owned` and `LostAnswers` (lost answers), `on_record`'s latch checks; `commit_fault`; `offline.rs`, `inventory::observe_offline` | `rtc14_*`, `b7_rtc14_*`, `b7_rtc_r2_0*`, `b7_crash_rollback_fault_commit_*`, `b7_crash_the_offline_clear_*`, `b7_crash_a_lost_syncfailed_then_a_replaced_l_keeps_forward_effects_latched`, `offline_walk_*`, `b7_offline_inventory_walks_every_host_family_before_the_clear`, `b7_crash_a_timed_out_*`, `rtc14_r2_*`, `b7_rtc14_linux_root_*`, `offline_walk_fails_closed_without_a_mandatory_enumeration_root` |
| RTC-15 gates follow L | `create_flow`, `fence_flow` classification arms | `b7_rtc3_forged_*` (no gate), `b7_rtc3_a_valid_tag_*` (no gate for NotIssued) |
| RTC-16 audit and observability | `audit_tokens`; `accounting`; Health | `rtc16_*`, `b7_a_historical_kiln_row_stays_deleting_and_charged_under_a_fenced_backend` |
| RTC-17 reserved shares | `Shares` | `rtc17_*`, `b7_rtc17_an_instance_enrolled_beside_a_borrower_finds_its_share_at_once` |
| RTC-18 compaction lane | `Lane::Compaction`; `Node::compactor`; `COMPACTION_BATCH` | `b7_rtc18_*` |

### Evidence

- **Lifetime, macOS** (`b7_lifetime_past_16384_sessions`, release test binary, real H and
  L, FULL-sync ledger): 28,000 admitted sessions and 5,000 never-admitted fences across two
  instances (16,500 issuances each) in 1,241 s. Live ledger bytes were 225,280 at every one
  of the 28 window boundaries; the open audit took 68 ms after the second window and 43 ms
  at the end; the idle tail compacted the last token and left the instance no rows. No
  headroom, quota or ledger-space refusal occurred (any would have failed the test).
  Rerun at `fe82b55`, the code as shipped: the same 28,000 and 5,000 in 851 s, live bytes
  225,280 at all 28 boundaries, retained admitted rows peaking at 1,181 of the two shares'
  1,228, and the open audit 15 ms.
- **Batches, macOS:** 16-token full batches well under 100 ms; 256 tokens 310 to 580 ms.
- **Real chain, kiln VM** (`b7_linux_root_compaction_cycles`, real jailer, Firecracker and
  guest, three concurrent lanes against a 64-entry allowance, 3-minute lease and 30 s pass):
  300 sessions, each booted to READY, executed once and removed, in 1,304 s, four times the
  allowance. The watermark reached 281 of 325 issued; retained admitted rows peaked at 47,
  exactly the share, and never above it; 1,322 headroom or preparation-slot refusals were
  waited out and retried; 37 compaction records were kept.
- **Crash matrix, kiln VM:** 28 of 28 (B6's 11 on the real chain, B7's 17) at `fe82b55`.
  In one earlier run B6's "daemon death while booting" saw its allocation stop before READY
  (stop reason not captured then; the scenario now prints it); it passed in the 13 runs
  since, including the full matrix.
- **Attack regressions, kiln VM:** 19 of 19 at `fe82b55`, including B6's whole session
  through kilnd and kilndctl and B7's 12.
- **B5 suite** 8 of 8 (with both B5 test guests), **B4 suite** 31 of 31, and all 61 B7
  fixture tests on Linux, each in its own phase.
- **The installed kilnd** (main `2a1faea`, schema 10) was never replaced; its database is
  byte-identical to the backup taken before the VM phases (`cmp`, SHA-256 `ef02941f…`).

## 16.10 B7 milestone 1 break-it corrections (November 5, 2026)

Daybreak Blue's break-it review of `179837c` (`reviews/2026-11-05-b7m1-breakit.md`) found no
compacted-token replay and no digest-binding break, one HIGH and four lower findings. Each
is corrected on `phase1b/b7-compaction`; the lead's decisions are recorded here.

| Finding | Correction | Proving tests |
|---|---|---|
| 1 (HIGH) A replacement L bypassed a durable fail-stop marker: L wrote it and died before H received `SyncFailed`, the replacement's handover carried only K, and L's Admit ignored its own latch | **Handover:** K now comes only in L's `Handover` reply, which always carries `LatchState` (the `node_faults` kinds, the fail-stop marker, L's in-memory latch); H imports it, latching if any part is set, before it publishes the channel, at startup and at every replacement. **L enforces:** a new L starts latched from any fault row as well as the marker, and under its latch refuses every forward write whoever sends it (C2 `Admit`, PREPARING, `spawn_intent`, EXEC_INTENT and its exec intent record; issuance and a first attach already refused in their own transactions), answering `Latched`, on which H latches too. Inspect, List, Stop, Remove, Gc, FenceAbsent, settlement and evidence records stay | `b7_crash_a_lost_syncfailed_then_a_replaced_l_keeps_forward_effects_latched` (the review's PoC as a regression: L killed at `L.reply` after the marker, H held after importing the latch and before publication, then the prepared token's Create and a Preflight refused with no L call, no C2 row, no effect, and the fence still working); `rtc14_l_refuses_forward_writes_under_its_own_latch_whatever_h_believes` (L-level: an Admit with a current authority, as an unlatched H would send it, and every other forward write refused with nothing written, under the latch and under the marker; reads and the never-admitted fence allowed; the handover carries the latch) |
| 2 (MEDIUM) Queued Create and Exec could cross their final effect boundary after H latched | Create rechecks the node latch last, immediately before `OpenGate` (`AmbiguousClass::Latched`; the C2 claim stays for an exact fence). Exec rechecks it after its EXEC_INTENT write and immediately before the descriptors and the broker Exec; latched there, it dispatches nothing and retires the VM by the stop fence and K, since the journal says EXEC_INTENT | `b7_rtc14_a_latch_during_create_setup_is_rechecked_before_open_gate` (held at `H.create.before_open_gate`, latched by a real rollback, released: `Latched`, no gate, no effect); `b7_rtc14_a_latch_during_exec_intent_dispatches_nothing_and_retires_the_vm` (EXEC_INTENT held, latched, released: no descriptor, no broker Exec, no BUSY, VM retired) and its unlatched control |
| 3 (MEDIUM) The offline inventory listed only work and cgroup directories | `ObservationBackend::observe_offline`: one node-wide walk over jail directories, jail mounts (mountinfo through the private procfs), loop devices, VMM and supervisor processes, cgroups and work files (section 16.6), over injectable `HostRoots`; any orphan or incomplete listing makes the report `unexplained` | `offline_walk_*` in `inventory.rs` (one fixture per family, an all-explained host, a vanished process, unreadable sources); `b7_offline_inventory_walks_every_host_family_before_the_clear` (the real walk over a planted tree feeds the report: an orphan jail directory alone, then an orphan VMM process alone, each refused by the clear; explained, it clears); `b7_linux_root_offline_walk_names_an_orphan_in_every_real_family` (root, real host: one planted orphan per family found, none before or after) |
| 4 (MEDIUM) The daemon digest cache grew for its lifetime | Learned at Create (after C1), not at Preflight, so a plan refused or abandoned before C1 leaves nothing; forgotten on every terminal answer (Remove, each released Gc result, FenceAbsent, Create's or Inspect's absence); kept across a non-reusable Exec or an incompatible Validate, which may be READY again. Hard cap `MAX_DIGESTS` = 1,024 + 4,096 = 5,120, never evicting: at the cap `prepare` returns the new `RuntimeError::Exhausted` before any helper call, which the manager answers `RESOURCE_EXHAUSTED` | `b7_rtc13_completed_sessions_leave_no_digest_entries` (the review's PoC as a regression: eight sessions and a dropped Preflight leave none); `b7_digest_cap_is_the_listed_bound_plus_the_token_gates`; `prepare_at_the_digest_cap_is_exhausted_before_any_helper_call`; `c0_rejection_leaves_no_row_no_charge_and_no_fence` |
| 5 (LOW) RTC-10's child order depended on `foreign_keys` | `allocations_no_delete` and `retired_tokens_no_delete` check with explicit `NOT EXISTS` that none of the token's seven child tables has a row left. Schema 2 is unreleased, so its triggers changed in place; a schema-2 development ledger provisioned before this change refuses to open ("ledger schema differs") and is re-provisioned | `rtc10_child_order_triggers_hold_with_foreign_keys_off` (the review's SQL PoC with `PRAGMA foreign_keys=OFF`: both deletes refused for each child table; the honest order still compacts) |

**PoC results.** `reviews/poc-b7m1/run-failstop-replacement.sh` at `179837c` still passes
(the bypass). Its test, appended unchanged to the corrected tree, fails at its first
assertion: H is latched when the replacement L is published. The digest PoC's count is now
zero (`b7_rtc13_completed_sessions_leave_no_digest_entries`).

**Validate.** It journals no intent, so there is nothing for L to refuse; H refuses it at
its request gate under the latch, as before.

**Evidence** (`reviews/2026-11-05-b7m1-fixes-vm/`). Kiln VM, each suite in its own phase:
crash matrix 29 of 29 (B6's 11 on the real chain, B7's 18 with the lost-`SyncFailed`
replacement); attack regressions 21 of 21, B6's whole session through kilnd and kilndctl
included (201.7 s), with the OpenGate recheck and the digest regression; the real-host
offline walk as root found exactly one orphan in each of the six families and none after;
B4 31 of 31 and the capability-drop test. B5: 5 of 8 in the full run; the killed-inner and
timeout/cancel/kill tests (the latter refused once at adopt, "VMM credentials differ:
Seccomp") passed on rerun, and the console-flood guest, freshly built from the current
`bundle-a`, fails its readiness check ("kiln protocol is not 1") identically at the reviewed
`179837c`, so it is a test-guest fixture problem, not these changes. macOS: workspace tests
pass on both feature sets except `runtime::kiln_direct`'s fake-kiln timing tests, untouched
here, which time out under host load on the base commit too; CI is green. The installed
kilnd (main `2a1faea`, schema 10) was never replaced; `/var/lib/kilnd` was restored from its
`cmp`-verified copy (`kilnd.db` SHA-256 `ef02941f…`).

### Recheck residuals (November 5, 2026)

Daybreak Blue's recheck of `d7f7b44` (`reviews/2026-11-05-b7m1-recheck.md`) accepted
milestone 1 (no HIGH finding) and ranked four MEDIUM residuals and one LOW gap, with
review-only PoCs in `reviews/poc-b7m1-recheck/`. Each is corrected before milestone 1
merges; the lead's decisions are recorded with them.

| Residual | Correction | Proving tests |
|---|---|---|
| R1 (MEDIUM) A request deadline dropped H's wait for L's `SyncFailed` or `FaultPending`; the reader discarded the answer while the same L lived, and H stayed unlatched | No fault-bearing answer is ever discarded. `LedgerRequest::fault_bearing` classifies every request exhaustively (only the eight reads may be lost freely). When a fault-bearing call's waiter is dropped after the request was sent, `Channel::call_owned` parks H's `LostAnswers` owner on the pending call, under the lock the reader sends under, and the reader hands it the answer (or the worker's death) when it comes; H imports `SyncFailed`, `Latched` or `FaultPending` from it, and an unreadable answer while L lives fails stop. From the moment the wait is dropped until the answer is consumed, H holds every forward effect exactly as the latch does; the boundaries that can wait (the request gate, Preflight before issuance, Create after C2 and before `OpenGate`, Exec after EXEC_INTENT, S's records) wait within their own deadline, and a hold still unresolved there refuses. `register_infrastructure` now goes through the same call | `b7_crash_a_timed_out_syncfailed_latches_h_while_the_same_l_lives` (the PoC as a regression: the queued Create waits during the hold, L's `SyncFailed` is consumed with nobody waiting, H latches `fail_stop` with the same L, the Create answers `Latched` with no gate or effect, Preflight is refused); `b7_crash_a_timed_out_benign_answer_holds_forward_effects_only_until_it_arrives` (the control: a fence's deadline lapses inside L, the queued Create waits, L answers the fence, the hold lifts unlatched and the Create is accepted) |
| R2 (MEDIUM) S's resource intents, their acknowledgements and the broker Initialize could gain or use forward authority after H and L latched | L's `forward_effect` blocklist became `allowed_under_latch`, an exhaustive allowlist: reads, attach and issuance (refused in their own transactions), the fault commit, compaction, stop, fence, settlement, a cleanup S's intent, worker and child identities and observations, H's teardown phases (`stopped`, `cleaning`), an execution's acceptance and settlement (`exec_intent` to `busy`, either to `ready`), and the identities of a cgroup tree, work or jail directory or VMM that already exists. Everything else is refused: C2, PREPARING, every resource intent, `loop_intent`, the loop generation, the jail intent, mount and binds, the work and private files, the broker identity, an Exec intent, `spawn_intent`, `booting`, readiness from `booting` and the new `AuthorizeInitialize` (otherwise answered only for a `booting` allocation). H does not send a record L would refuse, reads the latch again after L answers, and acknowledges only `loop_released` while latched, containing S otherwise. S asks (`SupervisorRecord::Initialize`) before each Initialize it submits, retries included | `rtc14_r2_l_refuses_every_supervisor_forward_record_and_initialize_under_its_latch` (the PoC as a regression, every refused record and phase under the latch and the marker, nothing written; the allowed identities journaled; the phase allowlist exactly); `rtc14_r2_initialize_is_authorized_only_while_booting`; real chain: `b7_rtc14_linux_root_a_latch_while_s_waits_grants_no_resource_authority` (S held before its cgroup intent, latched by a real failed commit: no intent, no tree, S contained, Remove ABSENT), `b7_rtc14_linux_root_a_latch_while_h_awaits_l_refuses_the_acknowledgement` (H held between L's journaled intent and its acknowledgement while the node latches: refused, no tree), `b7_rtc14_linux_root_a_latch_before_initialize_sends_none` (BOOTING, S held before readiness: no Initialize, never READY, VMM contained, Remove ABSENT) |
| R3 (MEDIUM) A stale Inspect continuation relearned a digest after a terminal Remove forgot it; enough races filled one runtime's 5,120-entry cap and denied its Preflights | `DigestCache` tracks learning calls in flight: Create and Inspect take a `LearnClaim`, a terminal answer marks any live claim, and a marked claim's learn is refused, so a reply begun before a terminal answer never reinserts the key. A refused Inspect (`Incompatible`) forgets the digest; an error or a deadline learns nothing. Reconciliation recovers the cap: a complete List drops every digest known before it was asked whose allocation it omits (retired or absent), never one a claim holds | `b7_rtc13_stale_inspects_racing_removes_never_fill_the_digest_cap` (real adapter and helper: an Inspect answer held in H after its lookup while Remove completes, twice with the cap at two; no entry survives, Preflight is served, a complete List drops a retired token's seeded digest); `stale_learns_after_terminal_answers_never_fill_the_digest_cap` (the PoC's sequence); `a_complete_inventory_drops_only_unclaimed_unlisted_digests` |
| R4 (MEDIUM) Adoption read `/proc/<V>/status` once after the image became visible, which can precede Firecracker's own seccomp filter, falsely refusing a healthy VMM | Within the existing five-second adoption bound S re-samples only `storage::vmm_seccomp_pending`'s state: `Seccomp` 0 where the contract expects 2, with every other field already as the contract says. Any other sample (another `Seccomp` value, a wrong UID, GID, group, capability or no-new-privs) is taken as it is and refused at once; a filter never observed is refused as `Seccomp` when the bound ends. Requiring Firecracker's own filter beyond the inherited service filters was not adopted: it would delay the jail hardening, which runs with V stopped right after adoption, until after the VMM had built its VM | `vmm_seccomp_pending_is_only_the_filter_not_yet_installed`; real chain: `b4_linux_root_a_late_vmm_seccomp_filter_is_waited_out_and_a_wrong_one_refused` (three late samples waited out to BOOTING; strict mode refused within four seconds of adoption; a filter never seen refused after the bound; each contained and charged until ABSENT) |
| R5 (LOW) A missing `/sys/block` made the offline walk's loop family an empty listing | `inventory::list_mandatory` for the kernel enumeration roots (`/sys/block`, and the fixture's process table): missing or unreadable is an error, so the report is `unknown` and the clear refuses it. Owned bases that were never created stay empty listings | `offline_walk_fails_closed_without_a_mandatory_enumeration_root` (the PoC as a regression; also an unreadable `/sys/block` when unprivileged, a missing process table, and the empty-base control) |
| Harness: the console-flood guest failed readiness ("kiln protocol is not 1") | Not a product defect. The wrapper's flood child started before the real broker's one-shot two-second capability probe and could starve it. It now waits for the persistent inner sandbox's `init.pid`, which exists only after Initialize, and so after the probe and Hello, then marks the console (`B5_TEST_FLOOD_START`) and floods; kill-inner shares the wait. The probe is not made to tolerate a flood: a guest that cannot prove its capability is correctly refused | `b5_linux_root_a_real_guest_console_flood_keeps_the_drainer_flat` with a guest rebuilt by `scripts/b5-test-guest.sh` |

**R1, the decision as built.** The lead's decision was that a timeout, cancellation or
dropped reply after a fault-bearing request latches H fail-stop, recoverable only through
the offline inventory and clear. Built literally, that made the fail-stop
client-triggerable: the request deadline is the caller's, so one request whose deadline
lapses before L answers (a millisecond deadline, or any attach queued behind a slow
fsync) would have stopped every instance on the node until root's offline clear. The full
macOS suite showed it: `b3r_03_wrong_account_and_wrong_cgroup_peers_cannot_touch_a_victims_attach`
latched the node through one wrong-cgroup attach whose five-second deadline lapsed while
L was held. The correction keeps the decision's fail-closed rule without that coupling:
from the lost wait H is held exactly as latched, and the latch becomes permanent (and
needs the offline clear) precisely when the answer carried a fault. L writes the
fail-stop marker before it answers `SyncFailed` or `FaultPending`, and answers `Latched`
only from a fault row, the marker or its own in-memory latch, so if L dies instead, its
replacement's handover imports that state before publication. A caller that lets its own deadline lapse therefore
delays other work by at most L's queue and never fail-stops the node.

**PoC results.** `reviews/poc-b7m1-recheck/run-residuals.sh` targets `d7f7b44` and still
passes there. Each of its four claims is inverted by a regression above: H latches on the
consumed `SyncFailed` and the queued Create is refused; the latched L answers the cgroup
intent `Latched` and writes nothing; no stale digest survives and Preflight is served; a
missing `/sys/block` is `unknown`.

**Evidence** (`reviews/2026-11-05-b7m1-residuals/`). Kiln VM at `3c33774` (the R2
real-chain tests again at `b8c0a31`, which only corrects their own assertions and matrix
line), each suite in its own phase: crash matrix 31 of 31 (B6's 11 on the real chain, B7's
20 with both R1 scenarios); attack regressions 22 of 22 for the existing scenarios, B6's
whole session through kilnd and kilndctl included, with the R3 race; the three R2
real-chain tests 3 of 3; B5 8 of 8 with both test guests rebuilt from the current
`bundle-a`, the console flood included; B4 32 of 32, the R4 seccomp test included (strict
mode refused 60 ms after adoption, a filter never seen refused after 5.1 s), and the
capability-drop test; the real-host offline walk as root. macOS: the workspace tests pass on
both feature sets except `runtime::kiln_direct`'s fake-kiln timing tests and
`manager::fenced_tests::invalid_exec_claims_fail_cleanup_and_quarantine_end_to_end`, which
fail identically at the unchanged `d7f7b44`; clippy is clean on 1.88 and 1.99. The VM's
mounted checkout was returned to main `1c107f9` and `/var/lib/kilnd` restored from its
copy, every file `cmp`-identical (`kilnd.db` SHA-256 `ef02941f…`).

### Integrated recheck: the transferred hold (November 5, 2026)

Daybreak Blue's integrated recheck of `f4db5b5` (`reviews/2026-11-05-b7-integrated-recheck.md`,
HIGH-2) found the gap R1 left at an L death. `LostAnswers` treated the dead worker's
`Closed` as the end of a lost fault-bearing answer and lifted the hold, on the premise that
the replacement's Handover would import whatever L had made durable. Between that `Closed`
and the Handover, H was neither held nor latched: a Create waiting at its final boundary
sent `OpenGate` and was accepted, and an Exec past EXEC_INTENT could hand over its
descriptors and dispatch, before the replacement imported the fail-stop marker.

**Correction: the replacement-generation barrier.** H counts the ledger slot's
publications (`ledger_generation`, read with the channel under the slot's lock), and every
fault-bearing call carries the generation of the L it was sent to. When such a call ends in
`Closed`, whether its waiter was dropped and the answer parked (`LostAnswers` with
`parked`), the waiter was dropped as `Closed` arrived, or the waiter itself received
`Closed`, the hold is not lifted. It moves to a barrier keyed by that generation
(`TransferredHolds`) and keeps counting in `lost_answers`, so `is_latched` and
`latched_once_answered`, and with them every forward boundary (the request gate, Preflight,
Create before `OpenGate`, Exec after EXEC_INTENT, S's records), see it. Only
`handover_ledger` drains it: after the replacement's Handover reply has been imported (any
pending fault committed first, then `fetch_key` latches H from L's `LatchState`), and before
the channel is published, every hold of a generation up to the replaced one lifts. A
`Closed` that arrives after a Handover already imported a later generation's state lifts at
once, since that import followed this L's death. A failed Handover (the replacement dies,
answers wrongly or misses `REPLACEMENT_LEDGER_REPLY`) or no replacement at all leaves the
hold in place, so each waiting boundary refuses at its own deadline (`Latched` for Create;
an undispatched, retired VM for Exec), and the next replacement whose Handover succeeds
drains it. Health reports `transferred_holds` beside `lost_answers`.

| Test | What it shows |
|---|---|
| `b7_crash_l_death_keeps_a_lost_fault_held_until_the_replacement_imports_the_latch` | The review's PoC inverted: a FenceAbsent's answer is lost after L wrote the marker, L is killed, the replacement is held before Handover. The hold is transferred (`transferred_holds` at least 1 and equal to `lost_answers`, unlatched); the queued Create waits at its final boundary and is refused `Latched` at its deadline with no gate and no effect; after the Handover H is latched `fail_stop`, the hold has lifted and Preflight is refused |
| `b7_crash_l_death_with_a_lost_benign_answer_lifts_the_hold_at_the_replacement_handover` | The control: L killed inside a benign fence; the Create waits during the stall, the Handover imports no latch, the hold lifts, the Create and a later one are accepted |
| `b7_crash_a_failed_replacement_handover_keeps_the_transferred_hold` | The replacement dies inside Handover (`L.handover.panic`): nothing imported, the hold stays, the Create is refused at its deadline; a later replacement's Handover latches H and lifts it |
| `b7_linux_root_crash_exec_after_intent_waits_for_the_replacement_handover` | Real chain: an Exec held after EXEC_INTENT, the same L death; released, it hands over no descriptors and dispatches nothing (`dispatched: false`, empty output), refused at its deadline with the VM retired; after the Handover H is latched |

All four are in `scripts/firecracker-crash-matrix.py`. With the old release (a transferred
hold lifted at once), the first and third fail at the census after the replacement is held.
The tests check at least one transferred hold, not exactly one: any other fault-bearing
call that reaches the dead L (S's own records on the real chain, a refused Create's record)
is transferred with it, as it should be.

**Stale sessions (integrated recheck MEDIUM-1).** R3's claim guarded only the digest:
`inspect_raw` remembered a `PresentReady` session unconditionally, so an answer produced
before a terminal Remove and delivered after it brought the session back (32 stale
allocations left 32 sessions, and a complete List pruned none). The session is now
published only through the caller's `LearnClaim` (`publish_session`), under the digest
cache's lock and only if the claim was not forgotten; `forget_allocation` takes the same
lock first and removes the session under it, so the check and the insert cannot straddle a
terminal answer. Every `inspect_raw` caller holds a claim: Create's READY poll, the
reconciliation Inspect and the session lookup before Validate and Exec (claimed before it
reads the digest). A complete List now drops the sessions as well as the digests of
allocations known before it was asked that it omits, never one a claim holds. Tests:
`stale_ready_answers_after_terminal_answers_resurrect_no_session` (the PoC inverted, 32
allocations, zero sessions and digests) and
`a_complete_inventory_drops_only_unclaimed_unlisted_sessions`.
