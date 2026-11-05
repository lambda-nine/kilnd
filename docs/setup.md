# Setting up kilnd

kilnd runs where kiln runs: Linux 6.8+ with cgroups v2. The daemon runs
as the unprivileged `kilnd` system account; only `kilnd-helper` runs as root. On a Mac
that means kiln's Lima VM (Ubuntu 24.04, aarch64). These steps take a fresh
Mac to a working kilnd; they were run on the Mac mini (Estradas-Mac-mini)
on 2026-10-13, with the Phase 0 service split revalidated on 2026-10-30.

## 1. Mac prerequisites

```sh
brew install lima protobuf          # protoc is only needed to build on macOS
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
gh auth login                        # both repositories are private
mkdir -p ~/Projects/lambda-nine
gh repo clone lambda-nine/kiln  ~/Projects/lambda-nine/kiln
gh repo clone lambda-nine/kilnd ~/Projects/lambda-nine/kilnd
```

Both checkouts must be at these paths: kiln's `lima.yaml` mounts
`~/Projects/lambda-nine/kiln` and `~/Projects/lambda-nine/kilnd` into the VM
at the same paths. kilnd's mount is the only change kiln needed for this.

## 2. The VM and kiln

Follow kiln's README "Dev setup (macOS)". The part kilnd needs:

```sh
cd ~/Projects/lambda-nine/kiln
git fetch origin
git checkout --detach 00d61c546db7aa67ad283d10c2ca6165ca5f8166  # tested Phase 0 companion
limactl create --name=kiln lima.yaml && limactl start kiln
limactl shell --workdir "$PWD" kiln
sudo scripts/fetch-alpine.sh        # the "alpine" image
sudo scripts/setup-storage.sh       # XFS project quotas for --disk
unset CARGO_TARGET_DIR              # kiln's installer uses target/release
scripts/install.sh                  # /usr/local/bin/kiln, kiln-dns, kiln-metrics
```

kilnd requires persistent-exec protocol v1, scoped `gc ID...` and
persistent-create certainty (capability feature `0x10`). The minimum kiln
revision providing all three is `e48f0e785ad484d0b2947897f6d48d0756059d7e`. Older revisions are refused,
including `40d9aa5003205d4c171e1b3eca61e9868064e98b` and
`46d84bdfe13e331f047e70e38848f7d74bcd2872`, which lack `0x10`: upgrade kiln
before kilnd, or kilnd refuses to start. Sandboxes those revisions already
started keep working; only the installed CLI needs the new feature.
The tested Phase 0 companion is `00d61c546db7aa67ad283d10c2ca6165ca5f8166`: install, integration, smoke and every
kilnd regression script passed against that immutable pin.
Install a compatible artifact, then check `kiln capabilities --protocol=1`
(binary output) and `kiln gc --help` (usage must advertise `[ID]...`). kilnd
checks both interfaces before reconciliation and workload launch rather than
trusting `--version`; it never falls back to global garbage collection.
Existing sandboxes need compatible PID 1 instances too; an old instance
requires explicit recreation. An incompatible replacement CLI degrades Health
and is rejected before workload launch.

## 3. kilnd in the VM

```sh
limactl shell --workdir ~/Projects/lambda-nine/kilnd kiln
sudo apt-get install -y protobuf-compiler sqlite3
# Keep Linux build output off the shared checkout, where macOS builds go.
echo 'export CARGO_TARGET_DIR=$HOME/.cache/kilnd-target' >> ~/.profile && . ~/.profile
scripts/install.sh
```

`scripts/install.sh` builds and installs `kilnd`, `kilnd-helper` and
`kilndctl`, creates the non-login `kilnd` account/group, and installs the
hardened daemon/helper services, the helper socket and tmpfiles config, and the boot guard
for interrupted maintenance.
It stops the daemon before validating and transferring old root-owned state
and API runtime-directory entries to the service account. Unsafe links,
ownership, modes or unexpected entries abort the transfer; originals are
never copied into a broader directory. The installer requires root through
sudo; the installed daemon refuses to run as root. `--helper-socket` replaces
the old daemon `--kiln` flag. The helper alone has a root-controlled `--kiln`
path, defaulting to the pinned `/usr/local/bin/kiln`.

The API socket is `kilnd:kilnd 0660` under `/run/kilnd` (0750). The helper is
`root:kilnd-helper 0660` under `/run/kilnd-helper` (0750) and checks the exact service
UID, rejecting other group members and root; `kilnd-helper` exists only to reach it. Do not grant callers access to
the `kilnd` account itself. See [helper protocol and trust](helper-protocol.md). To use the socket without sudo:
`sudo usermod -aG kilnd $USER`, then open a new shell.

Check it:

```sh
sudo kilndctl health
systemctl status kilnd kilnd-helper kilnd-helper.socket
journalctl -u kilnd -u kilnd-helper -o cat -f        # one JSON object per line
# Use the API for live inspection; stop kilnd before opening its SQLite DB.
sudo kilndctl ls --all
```

## 4. Tests

```sh
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
scripts/integration-test.sh          # dedicated admission stress, root + real kiln, FD-exec properties
scripts/daemon-singleton-regressions.sh # duplicate starts preserve active work
scripts/state-path-regressions.sh    # ownership, mode, type, link and symlink defenses
sudo python3 -I scripts/phase0-regressions.py # real peer UIDs, helper, privilege, retention
# install, add-instance and every way an upgrade can fail, between two builds, under a
# hostile account's connections; see the script for what it needs
sudo python3 -I scripts/deployment-regressions.py --bin-a DIR --bin-b DIR
# recovery from a reboot at each step, or from a failed restore, with systemd faked; runs anywhere
python3 -I scripts/kilnd-maintenance-tests.py
scripts/smoke.sh                     # through the installed service
```

The smoke test restarts and kills kilnd, so don't run it on a node with
sandboxes you care about.

### Firecracker B4 regressions (real VMs, test approval only)

These launch real Firecracker microVMs in the VM under the shared VM lock. They need
nested KVM, the release Firecracker v1.17.0 binary and a kiln-guest bundle's `Image` and
`rootfs.squashfs` (the schema-1 guest, which listens for nothing, so a boot ends at
BOOTING). Production is untouched: the catalog is approved only by a `cfg(test)` gate.

```sh
# Once: the patched jailer and a static mkfs.xfs, both SHA-256 pinned (no sudo).
scripts/build-phase1b-tools.sh --out "$HOME/b4-build/out"
# The privileged suite; B4_TOOLS, B4_VMM and B4_GUEST override the inputs.
scripts/b4-vm-tests.sh                 # every b4_linux_root test, or pass a name filter
```

`b4-vm-tests.sh` builds the library tests statically (`crt-static`), because that binary
is installed in the protected store as the helper image and the contract approves static
ELFs only. It installs under `/opt/kilnd`, uses `/var/lib/kilnd-helper/{jails,work}` and
`/sys/fs/cgroup/kilnd-firecracker`, and its `scripts/b4-vm-cleanup.py` removes all of it
and fails if any owned VMM, loop device, mount, cgroup or file is left. Its output is
under `CARGO_TARGET_DIR` (default `~/.cache/kilnd-target-static`).

## Firecracker group (disabled by default)

`scripts/install.sh` leaves this off: no policy, no ledger and no VM launch. It only
creates `/var/lib/kilnd-helper/firecracker` as root 0700. The helper unit's bounding set
includes the jailer's `CAP_MKNOD`, `CAP_SYS_CHROOT` and `CAP_SETPCAP` from B4, but only a
Firecracker supervisor keeps them: every other helper worker and kiln child drops them.

B3 infrastructure can be exercised with a root-owned policy file, mode 0644 or
tighter, whose whole path is root-owned and not writable by anyone else:

```json
{"schema":"kilnd-firecracker-node-policy-v1",
 "node_id":"<32 lowercase hex digits>",
 "ledger_dir":"/var/lib/kilnd-helper/firecracker",
 "ceilings":{"slots":3,"memory_bytes":3221225472,"disk_bytes":17179869184,
             "host_cpu_millis":3500,"virtual_cpu_slots":3,"pids":2048,"host_pids":128},
 "uid_range":{"first":300000,"last":365535},
 "gid_range":{"first":300000,"last":365535},
 "cid_range":{"first":3,"last":65535},
 "profiles":[]}
```

```sh
sudo kilnd-helper --firecracker-policy /etc/kilnd/firecracker-node.json --firecracker-init-ledger
# Then add the same --firecracker-policy to ExecStart in a drop-in and restart.
```

The first command creates the ledger, once, and refuses if any ledger file exists; do
not delete a ledger to recover from an error, because that discards every claim.

Each kilnd instance is then enrolled by root under the ID its own state holds. Rerun
`scripts/install.sh` once the helper has the policy, and the default instance is enrolled
under the `kilnd` account. Every further instance gets its own account and group, its
`kilnd@<name>` unit and its enrollment, in one command, with no ID to supply:

```sh
scripts/add-instance.sh <name>
```

Both take the same steps. `kilnd init-state --state-dir <dir> --account <account>` creates the
private state as that account and prints its durable instance ID, root enrolls exactly that
ID, and only then does the unit start. Repeating a step is harmless: init-state answers with
the same ID.

Enrollment needs the node lock, and any enrolled account can connect to the helper's socket,
so the helper would just come back if only its service were stopped. These commands mask
`kilnd-helper.socket`, stop it along with the helper and every daemon that requires it, then
mask the service, so nothing can start any of them. A running sandbox keeps running. When the
work is done, by success, failure or signal, the same command unmasks them and starts
exactly what was running. This is brief, but it stops every instance on the node. If the
command is killed outright, activation stays unavailable until `scripts/upgrade.sh --recover`,
or until the next maintenance command, either of which finishes the job. The masks live in
`/run/systemd/system.control`, because `systemctl mask --runtime` has no effect on a unit
installed in `/etc`.

A reboot clears those masks, so they only hold within one boot. Across a reboot the fence is
`kilnd-maintenance-guard.service`, which `scripts/install.sh`, or any maintenance command, puts
in place first, and which the helper socket, the helper and every kilnd unit `Requires=` and
are ordered after. Before anything changes, each maintenance command writes and fsyncs a marker,
`/var/lib/kilnd-helper/maintenance.json`, which also records what was running. The marker goes
last, after every restore and start, or after a commit, is durable.

At boot, while the marker says work may be half done, the guard runs `upgrade.sh --recover --boot`
from its own copy in `/usr/local/libexec/kilnd`, and everything behind it waits:

- **It succeeds:** the images, unit files, enrollments and state are back, and boot starts what's
  enabled. `kilnd-maintenance-finish.service` then starts anything else recorded as running, and
  removes the marker. A reboot does not count as restored until that has happened.
- **It fails:** the socket and every daemon stay down, and `systemctl start` on any of them fails,
  for as long as it keeps failing. `journalctl -u kilnd-maintenance-guard` says why. Fix that and run
  `scripts/upgrade.sh --recover`, which opens activation once it succeeds.

Any maintenance command exits with status 3 when something could not be put back, including a
unit that would not start again. It keeps its record, and an upgrade its journal and stage, and
`scripts/upgrade.sh --recover` tries again without stopping what did come back. The next
maintenance command does the same first, and refuses to go on until that succeeds.

Enrollment refuses an account another instance holds, root, the helper's own account and
anything in the policy's VM identity ranges, and the helper refuses a ledger that breaks
those rules. That separation needs no Yama setting. Each instance's state directory and
database are its own account's, mode 0700. `kilnd@<name>` is for instances on the Firecracker
backend: the helper refuses an enrolled account's kiln requests, so until B7 can select that
backend such a daemon stops at startup reconciliation.

An enrollment names the installed image, so replacing `/usr/local/bin/kilnd` by hand leaves
every instance unable to attach. On a node with a policy or further instances,
`scripts/install.sh` runs the whole replacement as one transaction, `scripts/upgrade.sh`:

```sh
scripts/install.sh                  # builds, then upgrades in place
scripts/upgrade.sh <directory>      # the same with kilnd, kilnd-helper, kilndctl already built
scripts/upgrade.sh --recover        # finishes an upgrade killed partway
```

1. **Before stopping anything,** it refuses new images that don't run.
2. It discovers every instance (`kilnd.service` and `kilnd@*`), records which are running,
   and stops them all, with activation unavailable as above.
3. **Before replacing anything,** it refuses if the ledger can't be read or refreshed, if an
   enrollment isn't a standard unit bound to its current account, or if it can't keep a copy of
   a running instance's database.
4. It moves the old images aside by rename, keeping their inodes, installs the new images and
   units, and refreshes every enrollment's image in one ledger transaction. An instance's ID,
   account and unit can't change, and an instance that isn't running is refreshed too.
5. With everything still down, the new image opens each running instance's state, which
   performs any schema upgrade before a client or a reconciliation can see it. The ID it
   finds must be the enrolled one.
6. It starts exactly what was running. The default instance must stay up and answer Health.

Any failure or signal at any point puts back the old images, under their old inodes, the
enrollments and the units, and starts what was running. A database is put back only if its
schema changed, since the old image couldn't open it; otherwise the one in place is the newer
truth, and replacing it could forget a reservation. If a daemon may have served on a schema
that goes back, what it held is kept under `/var/lib/kilnd-helper/failed-upgrades`, and the
command says so. A kill leaves `/var/lib/kilnd-helper/upgrade` for `--recover` or the next
maintenance command to undo. A reboot leaves it for the boot guard, which undoes the upgrade
before anything can start, or keeps it all down if it can't. Once the upgrade has committed, a
reboot keeps the new images, and only the cleanup remains.

A hostile instance can make its own state unusable and so make the upgrade refuse. The message
names that instance. Stop it (`systemctl disable --now kilnd@<name>`) and upgrade the rest: its
enrollment is refreshed, and its state is left alone.

`--cgroup` names the unit's cgroup if it isn't `/system.slice/<unit>`, and the unit
must not set `Delegate=`. A policy's `max_enrolled_instances` limits the total (default 8).
This needs Linux 6.5 or later. Ledgers from earlier B3 builds fail their audit and must be
provisioned again.

Startup problems leave kiln running and the group disabled or Unavailable. Every
profile is refused by the disabled gate until a reviewed release (B7). Do not expect a
sandbox from this: Capabilities reports `launch_enabled: false`.

## Operating notes

The daemon's admission flags and defaults are:

| Flags | Defaults |
|-------|----------|
| `--max-connections`, `--max-streams-per-connection` | 64, 8 |
| `--reserved-connections`, `--max-connections-per-uid` | 4 (one per UID), 32 |
| `--connection-preface-timeout-ms` | 5000 |
| `--max-concurrent-rpcs`, `--max-concurrent-health` | 64, 4 |
| `--max-concurrent-rpcs-per-uid`, `--max-concurrent-cleanup` | 32, 4 (one per UID) |
| `--max-concurrent-execs`, `--max-queued-execs-per-sandbox` | 32, 8 (plus one running) |
| `--max-queued-exec-stdin-bytes` | 16777216 (16 MiB) |
| `--max-request-bytes`, `--max-response-bytes` | 2097152, 4194304 |
| `--max-list-page-size`, `--max-list-response-bytes` | 200, 1048576 |
| `--max-sandboxes` | 32 retained reservations |
| `--max-node-memory-bytes` | 3221225472 (3 GiB) |
| `--max-node-pids` | 2048 |
| `--max-node-disk-bytes` | 17179869184 (16 GiB) |
| `--max-node-host-cpu-millis`, `--max-node-virtual-cpu-slots`, `--max-node-host-pids` | 3000, 3, 96 (kiln reserves none) |
| `--health-probe-timeout-secs` | 2 |
| `--health-success-cache-secs`, `--health-failure-cache-secs` | 5, 1 |

Limits are validated before state/socket creation. Required values must be
nonzero except `--max-queued-execs-per-sandbox`, which may be zero. The reserved
connections must leave at least one general slot, one UID's connection share must
fit in the general slots, its RPC share in `--max-concurrent-rpcs`, and the
preface deadline is 100 to 60000 ms. Counts
used by semaphores and stream counts must fit `u32`; the per-sandbox queue
plus one must fit too. Request bytes must cover stdin + argv + 64 KiB, and
response bytes must cover twice `--max-output-bytes`, maximum argv, and 64 KiB.
List response bytes cannot exceed response bytes, and pages cannot exceed 1000
items.
Each node budget must admit at least the default 512 MiB memory, 128 PIDs and
1 GiB disk sandbox. The 16 GiB disk default intentionally leaves substantial
headroom on the 40 GB development VM; deployments should set all four durable
reservation limits for their own host capacity. CPU is intentionally
schedulable and may be overcommitted rather than reserved. Timeouts must be
nonzero, the default cannot exceed the maximum, and the
maximum in milliseconds must fit `u32`. Invalid limits fail before opening
SQLite or binding the socket.

The fixed 256 KiB argv limit counts UTF-8 bytes plus one separator per
argument. The daemon also checks kiln's encoded persistent-exec body
(four-byte argc plus a four-byte length per argument) against its fixed 1 MiB
cap. At 4096 arguments the largest accepted API argv therefore encodes to at
most 274436 bytes. See the [validation contract](validation.md) for field
grammars.

Health reports admission maxima, current use and cumulative rejection totals
since daemon startup, plus durable sandbox count/memory/PID/disk reservations
and node-budget-rejected creates since startup;
backend probes are shared and cached, with a 2-second timeout. Ordinary and
Health handlers have separate budgets. Full handler/Exec/stdin budgets return
`RESOURCE_EXHAUSTED`; a full connection budget closes the socket without a
guaranteed gRPC status. tonic message-size cap failures use `OUT_OF_RANGE`.
Messages decode before handler admission under connection/stream/message
caps. Phase 1b B7 split the connection and RPC budgets by the caller's kernel UID
(B6-BI-03): reserved slots for Health and cleanup, per-UID shares and a cleanup RPC
lane, and the HTTP/2 preface deadline; the [architecture](architecture.md) has the
rules. One UID can still fill its own share with slow clients, and synchronous
SQLite/filesystem operations are not hard real time.
`sudo python3 -I scripts/hostile-public-caller.py --socket SOCKET --kilndctl KILNDCTL`
runs the hostile public caller against a running daemon in the VM. Terminal history is bounded by age/count retention; charged and
unfinished rows stay. See [history retention](../README.md#history-retention).

An Exec timeout includes queueing. Expiry before row insertion returns
`DEADLINE_EXCEEDED`; expiry afterwards returns a successful terminal
`TIMED_OUT` execution once cleanup/finalization finishes, potentially later
than the deadline. Tickets remain held while finalization retries.

`kilndctl ls` follows pages and prints incrementally. Other clients should set
`page_size` (present zero means the server default, normally 100) and pass the
bounded `next_page_token` until empty, keeping `include_deleted` and the calling
uid unchanged. Tokens do not survive the schema 7 upgrade: restart the listing.
Omitting `page_size` preserves complete-list behavior but now fails
`RESOURCE_EXHAUSTED` when the result exceeds the configured count or byte
bounds. Every older schema upgrades in order through v9. Schema 5 introduced
typed termination and runtime diagnostics together with output, terminal state,
truncation facts and whether each byte total is exact, plus each sandbox's
create certainty. Historical records retain unknown typed values and unknown
output-total certainty, and every existing no-ID `FAILED` row stays ambiguous and
charged, even one whose text describes a missing image. Older binaries refuse
the current schema, so keep a backup before upgrading.
Store migration may occur before startup capability validation fails;
installing an older daemon is not a database downgrade path.

Schema 7 records each sandbox's owner and assigns every existing row to root.
After upgrading, non-root callers no longer see sandboxes they created earlier;
use root to inspect or delete them. Older binaries refuse schema 7.

Schema 8 rebuilds the sandbox and execution tables in one transaction, so the first
start needs free disk for a second copy of retained output. It preserves every charge
exactly, gives this database a durable UUID and instance ID, and refuses to migrate a
row whose stored spec cannot be decoded, leaving the old schema intact. A kiln sandbox
whose execution cleanup cannot be confirmed now becomes `quarantined` rather than
staying `ready`; delete it. Older binaries refuse schema 8.

Schema 9 hardens conflict handling independently of per-connection pragmas and
requires canonical, identity-matching typed absence receipts at the SQL boundary.
A schema-8 database containing invalid receipts is refused atomically; preserve it
for investigation rather than deleting evidence. Independent SQLite connections
without the registered receipt validator cannot insert release evidence. Older
binaries refuse schema 9.

- **Upgrade:** rerun `scripts/install.sh`. Sandboxes keep running across the
  restart. On a Firecracker node this is a transaction; see above.
- **State path:** `--state-dir` must be absolute. Its real ancestors must be
  trusted and non-writable, and every nested symlink alias must be owned by
  root or the service UID (a trusted sticky temporary directory is allowed).
  The final directory must be `kilnd`-owned 0700, and existing
  `kilnd.db`, WAL, SHM or journal entries must be `kilnd`-owned regular 0600 files
  with one link. Do not move a database into place with permissive ownership,
  use a symlink, or hard-link it; kilnd fails before reconciliation. systemd's
  `StateDirectory=kilnd` and `StateDirectoryMode=0700` provide the supported
  default path. The socket parent must resolve to a different directory inode;
  `..`, symlink and platform aliases cannot be used to overlap it with state.
- **Ownership locks:** `kilnd.lock` and `.kilnd.socket.lock` are persistent
  inode anchors, not stale PID files. Never remove them to fix contention;
  stop the owning daemon and inspect its logs. A crash releases the kernel
  locks automatically even though the files remain. Linux then recovers an
  unchanged stale socket after a bounded refusal probe; ambiguous platforms
  preserve it and require operator inspection.
- **After a reboot,** sandboxes are gone (kiln's state is in tmpfs and
  cgroups). kilnd marks them `lost` at startup; delete them to clear the
  records.
- **Node budget cleanup:** a create that kiln proves failed before allocating
  anything, such as a missing image, is charged nothing once it is `FAILED`;
  delete it to clear the record. `LOST` and every other `FAILED` create with no
  backend ID keep their durable reservation. Known-ID deletion requires a negative exact-ID
  probe, a complete list omitting the ID and absent cgroup. Delete refuses a
  no-ID ambiguous `FAILED` row even after stray resources have been removed:
  ordinary listings cannot account for hidden resources, and authoritative
  no-ID reconciliation is not yet supported. Do not release capacity by editing
  SQLite.
  Lowering configured budgets below surviving reservations degrades Health and
  rejects new creates, but Get/List/Delete and reconciliation remain available
  so the node can be brought back within budget.
- **Output history:** `--output-storage=metadata` is recommended; `full` is
  the compatibility default, while `none` drops output evidence as well.
  Use `systemctl edit kilnd` with an empty `ExecStart=` followed by the full
  replacement command to change flags. Execution history defaults to 7 days /
  10,000 rows; deleted and uncharged failed sandbox history to 7 days / 1,000
  rows. Startup and periodic pruning apply both age and count limits. Zero
  age/count expires all eligible rows, never charged/unfinished rows. Mode
  changes affect future writes only; pruning is not secure erasure of SQLite
  pages, WAL or backups. Argv, labels and diagnostics may still contain secrets.
- **Logs:** `--log-format json` in the unit; `KILND_LOG=debug` for more.
- **Stray kiln sandboxes** kilnd didn't create are logged at startup as
  unmanaged and left alone. Remove live ones with `sudo kiln rm ID`; remove
  stale ones explicitly with `sudo kiln gc ID`.
- **Reservation boundary:** budgets cover promises made through kilnd. Trusted
  root or direct `kiln` use can bypass them and must be included in deployment
  headroom and operator accounting.
- **Bare-metal Linux** works the same way: install kiln and kilnd, then
  enable both services and the helper socket. Only the Lima VM has been tested.
