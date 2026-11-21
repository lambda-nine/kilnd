# Setting up kilnd

kilnd runs where kiln runs: Linux 6.8+ with cgroups v2. The daemon runs
as the unprivileged `kilnd` system account; only `kilnd-helper` runs as root. On a Mac
that means kiln's Lima VM (Ubuntu 24.04, aarch64). These steps take a fresh
Mac to a working kilnd; they were run on an Apple silicon Mac mini
on 2026-10-13, with the Phase 0 service split revalidated on 2026-10-30.

## 1. Mac prerequisites

```sh
brew install lima protobuf          # protoc is only needed to build on macOS
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
mkdir -p ~/Projects/lambda-nine
git clone https://github.com/lambda-nine/kiln  ~/Projects/lambda-nine/kiln
git clone https://github.com/lambda-nine/kilnd ~/Projects/lambda-nine/kilnd
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
kilnd regression script passed against that immutable pin. Exec cwd and env
(`ExecRequest.cwd` and `env`, `CreateSandboxRequest.default_env`) also need kiln's exec
options, capability bit `0x20`, first in `5cada841edd0bbe112550816fad221dfb1db6a47`, the
tested companion for them: install that revision instead to use them. With an older
kiln, kilnd works as before and Health lists no `EXEC_CWD`, `EXEC_ENV` or
`SANDBOX_DEFAULT_ENV`; sandboxes created before the upgrade keep refusing options
(`sandbox_unsupported`), because their PID 1 predates them.
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
scripts/build.sh default test
scripts/build.sh default clippy --all-targets
scripts/build.sh firecracker-test-deployment test
scripts/build.sh firecracker-test-deployment clippy --all-targets
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
scripts/expiry-regressions.sh        # real idle and lifetime expiry, grace, renew and restart
scripts/idempotent-create-regressions.sh # keyed retries, release and a kill mid-create
```

The smoke test restarts and kills kilnd, so don't run it on a node with
sandboxes you care about.

### Firecracker B4 regressions (real VMs, test approval only)

These launch real Firecracker microVMs in the VM under the shared VM lock. They need
nested KVM, the release Firecracker v1.17.0 binary and a kiln-guest bundle with `Image`,
`rootfs.squashfs` and `kilnd-guest-broker`: since B5 the production bundle (default
`$HOME/kiln-guest-build/bundle-a`), whose broker answers the host, so a boot reaches READY
(the earlier schema-1 guest listens for nothing, so its boot ends at BOOTING). Production
is untouched: the catalog is approved only by a `cfg(test)` gate.

```sh
# Once: the patched jailer and a static mkfs.xfs, both SHA-256 pinned (no sudo).
scripts/build-phase1b-tools.sh --out "$HOME/b4-build/out"
# The privileged suite; B4_TOOLS, B4_VMM and B4_GUEST override the inputs.
scripts/b4-vm-tests.sh                 # every b4_linux_root test, or pass a name filter
scripts/b4-vm-tests.sh b5_linux_root   # B5's broker and console tests; two need B5's test
                                       # guests from scripts/b5-test-guest.sh
B6_EVIDENCE=$HOME/b6-evidence scripts/b4-vm-tests.sh b6_linux_root # a whole session
                                       # through kilnd and kilndctl (deploy/firecracker-test/)
```

`b4-vm-tests.sh` builds the library tests statically (`crt-static`), because that binary
is installed in the protected store as the helper image and the contract approves static
ELFs only. It installs under `/opt/kilnd`, uses `/var/lib/kilnd-helper/{jails,work}` and
`/sys/fs/cgroup/kilnd-firecracker`, and its `scripts/b4-vm-cleanup.py` removes all of it
and fails if any owned VMM, loop device, mount, cgroup or file is left. It first builds
`kilnd` (with the `firecracker-test-deployment` feature) and `kilndctl` as ordinary
release binaries for B6's session test, under `B6_TARGET_DIR` (default
`~/.cache/kilnd-target-b6`); the static test binary goes under `B4_TARGET_DIR` (default
`~/.cache/kilnd-target-static`), and an ambient `CARGO_TARGET_DIR` is ignored.

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
maintenance command does the same first, and refuses to go on until that succeeds. A rollback
that finds the checkpoint artifacts changed also exits 3 and keeps every unit down, the boot
guard included, until `kilnd-maintenance.py accept-artifacts`; see
[checkpoints.md](checkpoints.md#upgrade-and-rollback).

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
   enrollment isn't a standard unit bound to its current account, if a process of an
   instance's account outlived its unit, if it can't keep a copy of a running instance's
   database, or if any configured or enrolled instance, running or not, or any standard state
   directory nothing names any more, has a checkpoint in flight.
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

### Retired-token compaction (B7)

The node ledger is schema 2: the helper issues every Firecracker allocation token, and a
compactor removes the rows of absent tokens once they fall below their instance's
watermark, so a node no longer stops admitting after a fixed number of sessions. A schema 1
ledger fails its audit with a message to re-provision: settle every Firecracker session on
the node, stop the helper, move the old ledger aside and provision again. Root policy may
set `fence_allowance_bytes` (whole 20 KiB entries, at least four per enrolled instance,
default 128 MiB), `compaction_lease_seconds` (default 900) and `compaction_pass_seconds`
(default 60). Size `max_enrolled_instances` to the instances the node will really run:
every policy slot reserves a share of admitted headroom whether or not it is enrolled
(614 retained sessions per slot at the defaults, all 4,914 with a limit of 1).

What Health and Accounting show: the instance's issue pointer, watermark, retained admitted
and never-admitted rows, its reserved share, rows pinned below the watermark, checkpoints and
compaction lag; Health is degraded below 25% retained headroom, past two leases of lag, for a
token that cannot be compacted, or after a policy change shrank the shares, and fails on a
node fault. `kilnd-helper ledger-stats` (root, helper stopped) prints the same per instance.

**A node fault latches every forward effect, node-wide.** It comes from a daemon reporting a
verified token the ledger has not issued, which only a restored or copied ledger produces,
or from any failed ledger commit. New sessions and executions are refused on every instance;
Inspect, List, Stop, Delete and reconciliation keep draining. Any restore, copy-back or
suspected clone of `node.db` is treated the same way. To recover:

```sh
sudo systemctl stop 'kilnd*' kilnd-helper.service kilnd-helper.socket
sudo kilnd-helper offline-inventory --report /root/inventory.json \
    --daemon-db <instance>=/var/lib/kilnd/kilnd.db ...   # one per enrolled instance
# settle or destroy whatever the report lists as unexplained, then run it again
sudo kilnd-helper clear-node-faults --report /root/inventory.json
sudo systemctl start kilnd-helper.socket kilnd.service
```

The inventory reads each daemon database read-only and destroys nothing. The clear refuses a
running helper, a report that is stale (the ledger moved), unexplained, altered or not
root-owned, and raises each issue pointer past the highest token its daemon recorded, so no
recorded token is ever issued again. If anything cannot be explained, re-provision after
proving every resource absent.

**Selecting Firecracker for a database that holds kiln rows.** Historical kiln rows do not
drain under `--backend firecracker`: their Delete is refused before any helper call and the
row stays DELETING and charged, and Health names the count. Before switching, run the
database with `--backend kiln` and delete every kiln row until `kilndctl ls` shows none
charged. Each further Firecracker instance has a fresh database, so this arises only for
the default instance.

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
nonzero except `--max-queued-execs-per-sandbox`, which may be zero. The ingress
flags must keep every UID's share strictly below what it shares (B7 milestone 2):
at least one reserved connection, fewer than `--max-connections`; one UID's
connection share strictly below the general slots (`--max-connections` minus
`--reserved-connections`), and that share plus its one reserved slot strictly below
`--max-connections`; its RPC share strictly below `--max-concurrent-rpcs`; and at
least one cleanup permit. So `--max-connections 33 --reserved-connections 1
--max-connections-per-uid 32` is refused, and 31 is the most one UID may hold there.
The preface deadline is 100 to 60000 ms. Beyond these limits, UID 0 keeps one
connection slot and one Health/cleanup RPC permit of its own. Counts
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
bounds. Every older schema upgrades in order through the current one (16). Schemas 3 to 5
added, alongside output, terminal state and truncation facts, typed termination and
runtime diagnostics (schema 3), whether each byte total is exact (schema 4) and each
sandbox's create certainty (schema 5). Historical records retain unknown typed values and unknown
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

Schema 15 adds the workspace checkpoint store (checkpoint milestone C4; see
[architecture.md](architecture.md#workspace-checkpoint-store-schema-15)). The feature is
off, so the tables stay empty and every total is unchanged. The upgrade audits the
schema 14 reservation membership first and refuses (leaving schema 14 intact) if it does
not match. Older binaries refuse schema 15. **Rollback never lowers `user_version`:**
it restores a database backup taken before the upgrade, together with the checkpoint
artifacts that match it (`/var/lib/kiln/runs/.checkpoints/<instance>/`), with the
daemon and helper stopped. While the feature is off there are no artifacts, so the
database backup alone is the matching set, which is what `kilnd-maintenance.py` restores
when an upgrade fails. Once checkpoints exist, a database restored without its artifacts,
or artifacts without their rows, leaves unexplained artifacts that block new disk
allocation until reconciled; they are never adopted or swept as free space.

Schema 16 adds one table, the checkpoint barrier's durable marker (see
[architecture.md](architecture.md#workspace-checkpoint-engine-milestone-c5a)); schema 15
rows are unchanged and older binaries refuse schema 16. Rollback is the same database
backup restore.

`--enable-workspace-checkpoints` (default off) serves the checkpoint RPCs and creates from
a checkpoint. **It is off by default and a supported opt-in** on a node that passes the
rollout gate's per-node criteria 9 and 10
([checkpoint-rollout-gate.md](checkpoint-rollout-gate.md)). Health lists
`workspace_checkpoint` only while the root helper's checkpoint checks pass (see
[architecture.md](architecture.md#checkpoint-discovery-and-capacity-milestone-c5b-2)),
and every capture and create from a checkpoint must leave `--checkpoint-headroom-bytes`
(default 1 GiB) free on kiln's runs filesystem and on its loop device's backing
filesystem. Operating a node with checkpoints (cleanup, backup, upgrade and rollback) is
in [checkpoints.md](checkpoints.md).

To opt a node in:

1. **Check criterion 10 on the kiln the helper runs:** the helper's `--kiln` path,
   `/usr/local/bin/kiln` unless its command line (step 2) names another. All three must
   hold:
   - **(a)** That binary's `--version` (`/usr/local/bin/kiln --version` by default)
     prints exactly `kiln 0.1.0 (git 87359079834c, clean)`: commit `8735907`, the kiln
     the gate was measured on. `dirty`, `(git unknown)` or any other form fails.
   - **(b)** That binary was built from a clean checkout of exactly that commit with
     `KILN_BUILD_COMMIT` unset, as kiln's `RELEASING.md` at that commit describes:
     section 1's `git status --porcelain` prints nothing, and section 4 runs the locked
     release build under `env -u KILN_BUILD_COMMIT`.
   - **(c)** A build record proves (b): the commit (`git rev-parse HEAD`), the empty
     `git status --porcelain`, the unset `KILN_BUILD_COMMIT` and the built binary's
     sha256. The installed binary's `sha256sum` must equal the recorded one.

   The version line alone proves nothing. kiln's build script takes `KILN_BUILD_COMMIT`
   first in every build, inside a git checkout or not, and for any value of at least 12
   hex digits not ending in `-dirty` reports that commit and `clean` without looking at
   the source (kiln `runtime/build.rs:24-42` at `8735907`). Any source built with it set
   can print the gated line. A later commit qualifies only if (a) to (c) hold for it, with
   `(git <its first 12 digits>, clean)`, and a gate record shows criteria 2-4 rerun on
   that exact commit with a binary built and recorded the same way. Any other kiln: leave
   the flag off.
2. **Start the helper with checkpoints on, and check it, before kilnd.** Add
   `--enable-checkpoints` to the helper's `ExecStart` (the shipped
   `deploy/kilnd-helper.service` runs `/usr/local/bin/kilnd-helper` with no flags), run
   `systemctl daemon-reload` and restart `kilnd-helper`. Then check the running process,
   not the unit file: `systemctl show -p MainPID --value kilnd-helper` gives its PID,
   and `tr '\0' ' ' < /proc/<pid>/cmdline` must contain `--enable-checkpoints` (and no
   `--kiln` other than the binary checked in step 1). `systemctl show -p ExecStart
   kilnd-helper` shows what the loaded unit runs, which a missed restart leaves different
   from the running process. Then check that the helper's journal since that restart
   (`journalctl -u kilnd-helper --since "<restart time>"`) has no
   `kilnd-helper: checkpoint group disabled` line. The helper prints that line only when
   it was given the flag and the group failed to start; started without the flag, it
   leaves the group off silently, so the journal alone does not show a missed
   `daemon-reload`, a wrong drop-in or the wrong unit. Only then restart kilnd
   with `--enable-workspace-checkpoints` (and `--checkpoint-headroom-bytes` if 1 GiB is
   not right for the node). The flag makes every kilnd startup reconcile checkpoints, and
   reconciliation needs the helper's checkpoint group and a kiln that lists format 1 and
   checks generations on removal. If the helper answers ordinary kiln operations but
   cannot give kilnd a checkpoint maintenance session (its group off, or a kiln without
   format 1 or generation-checked removal) when kilnd starts, the checkpoint barrier
   stays set: Health is DEGRADED, every new sandbox create is refused, and captures and
   forks get the allocation barrier's `FAILED_PRECONDITION` refusal (not one of the typed
   checkpoint reasons below). kilnd retries on its own; the barrier clears once the
   helper's group and a compatible kiln are back and a reconciliation completes cleanly.
   If the helper cannot be reached at all, kilnd's startup reconciliation fails before
   it serves anything, and kilnd exits with a `startup reconciliation` error.
3. **Check criterion 9.** `kilndctl health` must report SERVING, list
   `workspace_checkpoint` under `features` and print a `checkpoint limits:` line. If it
   is SERVING without the feature, the node is not eligible as it stands. This is also
   how a node that started cleanly behaves when a later discovery probe fails: Health
   stays SERVING, without the feature, with `workspace checkpoints withdrawn: <why>` in
   its `detail` and no limits line. Every new capture and create from a checkpoint asks
   the helper again (never the cached Health answer) and is refused with a typed reason:
   `UNIMPLEMENTED backend_unsupported:workspace_checkpoint` while the helper's group is
   disabled, `FAILED_PRECONDITION sandbox_unsupported:workspace_checkpoint` when the
   installed kiln or host fails a check (leases, format 1, generation-checked removal, XFS
   with project quotas, trusted image registry) or the helper writes another checkpoint
   format, and `UNAVAILABLE checkpoint_io` when the helper cannot be reached or free space
   on runs or its loop backing is unknown. Get, List and Delete stay served. A later probe
   that passes lists the feature again. A Firecracker node never lists it and refuses
   captures and forks `backend_unsupported`. `kilndctl create --from-checkpoint` itself
   refuses unless Health is SERVING and lists the feature. DEGRADED alone does not say
   why (a failed backend probe, retrying finalization writes, degraded accounting,
   over-budget reservations and other allocation blocks also cause it; its `detail` names
   them). If Health is DEGRADED and kilnd's journal (`journalctl -u kilnd`) has
   `checkpoint reconciliation could not reach the helper; allocation blocked`, startup
   reconciliation could not get a checkpoint session from the helper (step 2; the
   warning reads the same when the helper answers but its group is off or kiln fails the
   removal checks), and kilnd's retry logs it again on each pass that fails that way.
4. **To turn it back off,** restart kilnd without `--enable-workspace-checkpoints`;
   nothing is deleted. With no checkpoint state on disk, every checkpoint RPC is refused
   `UNIMPLEMENTED backend_unsupported:workspace_checkpoint`. With any row, capture key or
   barrier marker present, kilnd keeps serving Get, List and Delete, answers keyed capture
   retries from their records, keeps running expiry, removal and startup reconciliation,
   and keeps reporting Health's checkpoint stats when it can read them (without the
   limits line); only new captures and forks are refused `backend_unsupported`. Charges
   stay counted until each artifact's removal is proved.

   **Keep the helper's checkpoint group on, and a kiln that lists format 1 and checks
   generations on removal installed, until no checkpoint state is left at all,** not just
   no live checkpoints. A deleted or failed checkpoint stays as a history row, and a keyed
   capture's request record stays, after its artifact is gone: a record is automatically
   retained for at least `--create-request-retention-secs` (default one day, counted again
   from a host reboot) unless released early with
   `kilndctl checkpoint rm --release-request-id`, and the row until it is older than
   `--deleted-sandbox-max-age-secs` (default 7 days, at least one day) and its record is
   gone. A quarantined checkpoint stays until it is deleted, and no checkpoint row or
   capture key is pruned while the checkpoint barrier is blocked. Once the last of them
   may go, the next prune (every `--prune-interval-secs`, default 60) removes it.

   **The exit condition** is kilnd's own checkpoint gate. With kilnd's flag off, ask the
   kilnd instance being turned off (`--socket`, default `/run/kilnd/kilnd.sock`):

   ```sh
   sudo kilndctl checkpoint ls --page-size 1
   ```

   It is done only when that is refused with gRPC `UNIMPLEMENTED` and reason
   `backend_unsupported:workspace_checkpoint`: kilndctl prints the list's header line,
   then exits 1 with this on standard error:

   ```text
   kilndctl: unimplemented: backend_unsupported:workspace_checkpoint: workspace checkpoints are not enabled
   ```

   kilnd checks that gate before reading any row, and refuses this way only while it
   maintains no checkpoint state: flag off, no checkpoint row, capture key or barrier
   marker, and the barrier not blocked. Anything else is not done: a list that succeeds,
   even an empty one, means kilnd still maintains checkpoint state, and any other error
   tells nothing. Keep the helper's group and kiln as they are and check again later.
   Health's `checkpoints:` block is informational only: kilnd leaves it out when reading
   the statistics fails (logging `read checkpoint counts`), so its absence proves
   nothing. Only after that refusal turn off the helper's group or install an older
   kiln.

   If the helper's group goes off, or an older kiln goes in, while any of that remains,
   removal cannot run (rows stay DELETING and charged), and the next kilnd start must
   reconcile that state without a helper session it can get: the barrier stays set,
   Health is DEGRADED and every new sandbox create is refused, even with no checkpoint
   visible. One DELETED history row is enough (the test
   `manager::checkpoint::tests::fix::feature_off_settled_history_blocks_on_a_failed_session_until_inventory_is_clean`
   shows it). To recover, reinstall a compatible kiln, restart the helper with
   `--enable-checkpoints`, and leave both up: kilnd's retry clears the barrier once a
   reconciliation completes cleanly
   ([checkpoints.md](checkpoints.md#turning-it-on-and-off)).

Known limits, measured on one test machine
([checkpoint-performance.md](checkpoint-performance.md); no latency is promised):

- **The per-checkpoint cap is in effect an entry cap.** Each manifest entry (the root
  and directories included) is charged a 16 KiB allowance toward the 1 GiB
  per-checkpoint cap whatever its real size, so a checkpoint holds roughly 60,000 small
  files at most (50,000 entries were charged 987 MiB against 208 MiB of physical use).
- **Large captures take tens of seconds.** A 50,000-file capture took about 28 s warm and
  37 s (p50) cold, against kilnd's 120 s checkpoint operation timeout. `kilndctl` sets no
  gRPC deadline of its own; a client that sets one must allow for this.

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
  stale ones explicitly with `sudo kiln gc ID`. A kilnd sandbox whose kiln shim
  died (kiln lists its run `stale`) needs no root step: Delete collects exactly
  that run by ID and proves it absent.
- **Reservation boundary:** budgets cover promises made through kilnd. Trusted
  root or direct `kiln` use can bypass them and must be included in deployment
  headroom and operator accounting.
- **Bare-metal Linux** works the same way: install kiln and kilnd, then
  enable both services and the helper socket. Only the Lima VM has been tested.
