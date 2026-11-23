# Operating workspace checkpoints

Workspace checkpoints capture a sandbox's writes over its image and create new sandboxes
from them (design in [architecture.md](architecture.md#workspace-checkpoint-api-milestone-c5b-1)).
**They are off by default and a supported opt-in** on a node that passes the rollout
gate's per-node criteria 9 and 10 ([checkpoint-rollout-gate.md](checkpoint-rollout-gate.md));
[setup.md](setup.md) has the opt-in steps.
This page is what an operator needs once checkpoints exist on a node: turning the feature on
and off, cleaning up, backing up, upgrading and rolling back.

## Turning it on and off

Two switches, both off by default:

- `kilnd --enable-workspace-checkpoints` serves the checkpoint RPCs and creates from a
  checkpoint, with the design's limits: 1 GiB per checkpoint; 32 checkpoints and 4 GiB per
  uid; 128 and 8 GiB per node; 24 h lifetime and 1 h idle by default, at most 7 days and
  24 h; two capture and restore workers per node, one per uid.
  `--checkpoint-headroom-bytes` (default 1 GiB) is the free space every capture and fork must
  leave on kiln's runs filesystem and on its loop device's backing filesystem.
- `kilnd-helper --enable-checkpoints` serves the root helper's checkpoint group. Without it
  the group answers Disabled and kilnd advertises nothing.

**Turn the helper's group on first.** kilnd's flag makes every kilnd startup reconcile
checkpoints, which needs the helper's group and a kiln that lists format 1 and checks
generations on removal. Add `--enable-checkpoints` to the helper's `ExecStart` (the shipped
unit has no flags), run `systemctl daemon-reload` and restart `kilnd-helper`. Then check
the running process: `tr '\0' ' ' < /proc/<pid>/cmdline`, with the PID from
`systemctl show -p MainPID --value kilnd-helper`, must contain `--enable-checkpoints`, and
its journal since that restart (`journalctl -u kilnd-helper --since "<restart time>"`)
must have the line `kilnd-helper: checkpoint group: enabled`. The helper logs exactly one
such line at each start: `enabled`, `off (flag)` without the flag, or `failed: <why>` when
the flag was given and the group could not start; a helper that can't write the line exits
without serving. Only then restart kilnd with its flag.
If kilnd starts while the helper answers ordinary kiln operations but cannot give it a
checkpoint maintenance session, the checkpoint barrier stays set: Health is DEGRADED (its
`detail` says `a checkpoint barrier is pending`), every new sandbox create is refused,
kilnd's journal has `checkpoint reconciliation could not reach the helper; allocation
blocked`, and captures and forks get
the allocation barrier's `FAILED_PRECONDITION` refusal, until the helper's group and a
compatible kiln are back and a reconciliation completes cleanly. If the helper cannot be
reached at all, kilnd's startup reconciliation fails and kilnd exits before serving.

`kilndctl health` lists `workspace_checkpoint` only while every probe passes: the helper's
group is enabled, kiln grants leases, lists checkpoint format 1 and checks generations on
removal, runs is XFS with project quotas, kiln's image registry is trusted, and free space
on runs and its backing is known. After a clean startup, when a later probe fails, Health
stays SERVING with `workspace checkpoints withdrawn: <why>` in its detail, and new captures
and forks are refused with a typed reason until a later probe passes. Firecracker never
lists the feature.

**Turning it off keeps what exists.** With the flag off and checkpoint state on disk (any
row, capture key or barrier marker), kilnd still serves Get, List and Delete, answers
keyed retries from their records, runs expiry and removal, and reconciles at startup. Only
new captures and forks are refused (`UNIMPLEMENTED backend_unsupported:workspace_checkpoint`).
Charges stay counted until each artifact's removal is proved.

**The helper's group goes off last, after all checkpoint state is gone,** not just the
live checkpoints. Turn kilnd's flag off first, let the checkpoints expire or delete them,
and keep the helper's group on and a kiln that lists format 1 and checks generations on
removal installed until, with the flag off, `kilndctl checkpoint ls --page-size 1` against
that kilnd is refused with gRPC `UNIMPLEMENTED` and reason
`backend_unsupported:workspace_checkpoint`. kilndctl then prints the list's header line
and exits 1 with
`kilndctl: unimplemented: backend_unsupported:workspace_checkpoint: workspace checkpoints are not enabled`
on standard error. kilnd checks that gate before reading any row, and refuses this way only
while no checkpoint row, capture key or barrier marker exists and the barrier is not
blocked. Anything else is not done: a successful list, even an empty one, any other error,
or Health without its `checkpoints:` block (which is informational and also missing when
reading the statistics fails: kilnd logs `read checkpoint counts`, and Health is DEGRADED
with `checkpoint counts unreadable: <why>` in its `detail`). Keep the helper and
kiln as they are and check again later. A deleted or failed checkpoint's history row stays
until it is older than `--deleted-sandbox-max-age-secs` (default 7 days, at least one day)
and its capture record is gone; a capture record is automatically retained for at least
`--create-request-retention-secs` (default one day, counted again from a host reboot)
unless released early with `kilndctl checkpoint rm --release-request-id`; a quarantined
checkpoint stays until it is deleted; and no checkpoint row or capture key is pruned while
the checkpoint barrier is blocked. Once the last of them may go, the next prune (every
`--prune-interval-secs`, default 60) removes it.

Turning the helper's group off, or installing an older kiln, while any of that remains
makes removal impossible (rows stay DELETING and charged, and kilnd retries) and, at the
next kilnd start, leaves the barrier set: Health is DEGRADED and every new sandbox create
is refused, even when no checkpoint is visible. One DELETED history row is enough
(the test `manager::checkpoint::tests::fix::feature_off_settled_history_blocks_on_a_failed_session_until_inventory_is_clean`). To
recover, reinstall a compatible kiln, restart the helper with `--enable-checkpoints` and
leave both up; kilnd's retry clears the barrier once a reconciliation completes cleanly.

## What the states mean

| State | Meaning | Operator action |
|---|---|---|
| `capturing` | a capture is running; its R bytes are charged | none; it settles to `ready` or `failed` |
| `ready` | an immutable artifact, charged its sealed size S | none; it expires on lifetime or idle |
| `failed` | the capture failed (its typed reason is on the row); nothing is charged once its storage is proved absent | `kilndctl checkpoint rm` to drop the row |
| `deleting` | removal is in progress or being retried; still charged | none; kilnd retries until the helper proves the artifact absent |
| `quarantined` | a `ready` checkpoint whose artifact was found missing or corrupt; forks are refused, its charge kept | `kilndctl checkpoint rm` (owner or root) |
| `deleted` | removed, charge released | none; retention prunes it |

**The checkpoint barrier.** At every startup, and after certain removal verdicts, kilnd
blocks new disk allocation (sandbox creates, captures and forks) until a complete inventory
of this instance's artifacts matches its rows; meanwhile those requests are refused and
Get, List and Delete keep working. It clears on its own
once interrupted captures fail, pending removals prove absence, and nothing unexplained is
left. It stays blocked while the helper is unreachable, the inventory is incomplete, or an
artifact exists that no row explains.

**Never delete files under `/var/lib/kiln/runs/.checkpoints/` to free space or clear a
block.** kilnd releases a charge only on the helper's proof that the exact artifact is gone;
a file removed behind its back leaves the charge in place and the row quarantined or blocked.

## Cleaning up

- `kilndctl checkpoint ls` lists your checkpoints, newest first (root sees every uid's).
- `kilndctl checkpoint rm <id>` deletes one. Delete is idempotent; a `deleting` row that
  answers `checkpoint_busy`, `checkpoint_io` or `checkpoint_corrupt` stays charged and kilnd
  keeps retrying.
- Expiry removes every checkpoint by its lifetime (counted from READY, never extended) or
  idle timeout (refreshed by Get and by an accepted fork, paused while a fork is restoring).
- Completed forks survive their checkpoint's deletion; a fork still restoring when its
  checkpoint is deleted fails with a typed reason.

**Artifacts no row explains** (for example after restoring a database without its matching
artifacts) keep the barrier blocked. kilnd never adopts them into an owner and never sweeps
them as free space. Put back the database and artifacts that belong together (below). If an
artifact is known to be unwanted and no row references it, remove it with kiln itself, with
kilnd and kilnd-helper stopped: `kiln checkpoint rm --instance <instance> --checkpoint <id>`.
The next startup's inventory then clears the barrier.

## Backup and restore

A checkpoint is two things that must match: its row in kilnd's database
(`<state-dir>/kilnd.db`) and its artifact under `/var/lib/kiln/runs/.checkpoints/<instance>/`,
where `<instance>` is the 32-hex instance ID.

A coherent backup:

1. Stop kilnd and kilnd-helper, so no capture, fork or removal is running.
2. Sync (`sync`).
3. Copy the database files and the instance's `.checkpoints/<instance>/` directory together,
   preserving ownership, modes and extended attributes.
4. Start kilnd-helper, then kilnd.

Restore the same pair together, with both services stopped. A database restored alone, or
artifacts restored alone, is safe but not usable as-is: rows whose artifacts are missing are
quarantined when used (their charges kept until deleted), and artifacts with no row block new
disk allocation as above.

## Upgrade and rollback

Schema 15 added the checkpoint store and schema 16 the barrier marker; older binaries refuse
newer schemas, and **rollback never lowers `user_version`**: it restores a database backup
taken before the upgrade. `scripts/upgrade.sh` (`kilnd-maintenance.py upgrade`) does this
for every running instance as one transaction. With checkpoints it also:

- **Refuses to start while a checkpoint is in flight** (exit 2, nothing changed): any
  checkpoint `capturing` or `deleting`, or one with a fork still restoring from it, in
  **any** configured or enrolled instance, running or stopped, and in any standard state
  directory (`/var/lib/kilnd`, `/var/lib/kilnd-<name>`) that no unit or enrollment names
  any more. Such a directory whose account is gone can't be inspected as that account, so
  if its database header says schema 15 or later, or it has a non-empty WAL, the upgrade
  refuses: restore the account or move the directory aside. Only the running instances
  are then snapshotted, migrated and started again. The daemons were stopped to take the
  snapshot, so they are started again; let those checkpoints settle (`kilndctl checkpoint
  ls`), then retry.
- **Requires the instance's account to be quiet.** The units stop with `KillMode=process`,
  so before each copy the upgrade refuses (exit 2) if any process still runs with the
  account's UID as its real, effective, saved or filesystem UID, or if `/proc` can't be
  read. It scans every inspected instance's account again, running or stopped, just before
  replacing the images (exit 2, nothing replaced) and just before starting the units (rolled
  back, exit 1).
  These scans are a guard against what `KillMode=process` leaves, not a fence: nothing
  stops an account starting a process after a scan.
- **Never migrates over a busy checkpoint.** That invariant is enforced atomically by
  `kilnd init-state --refuse-busy-checkpoints`, which only the upgrade passes. It applies
  the same busy predicate inside the schema migration's own IMMEDIATE transaction (one
  transaction for every step), or, at the current schema, in an IMMEDIATE transaction of
  its own while it reads the instance ID, so a row committed before the check is seen
  and one written after it can only be written after the migration committed. On a busy
  row it commits nothing and exits 75 with a `busy <id> <kind>` line per checkpoint; the
  upgrade then rolls back like any other failure after the replacement (exit 1). Without
  the flag (`add-instance`, a daemon's own start) init-state is unchanged. A stopped
  instance isn't migrated, so the upgrade keeps it in its journal and, with the new images
  installed and just before starting the units, takes a fresh snapshot and inspects it
  again: a busy row, or an ID other than its enrollment's, rolls the upgrade back (exit 1).
  That last inspection is the decisive check for a stopped instance. A write after it is
  the same as a write to a stopped instance at any time after an upgrade: ordinary state
  the new image will open, not state the upgrade upgraded over. A stopped instance's state
  is never restored, because the upgrade never changed it.
- **Reads one coherent snapshot, not the live state.** The instance's own account takes one
  SQLite backup of its database, which reads the database and its WAL in one read
  transaction, so a checkpoint of the WAL during the copy can't hide a row; the snapshot is
  that single `kilnd.db`. The account then runs the query, unprivileged, on a copy of that
  snapshot that only root can change. When the instance is enrolled, the snapshot's
  instance ID must be the enrollment's (exit 2 otherwise), and that ID is what the journal
  records. The ID never comes from the live state: a running instance whose snapshot
  records none is refused (exit 2) if it has checkpoint state (schema 15 or later with a
  checkpoint table); start kilnd once so it records one. Older state with no ID has no
  checkpoints and is journaled without an inventory.
- **Restores a snapshot all or nothing, across crashes.** Before a rollback touches an
  instance's live state it records, durably in its journal, that the restore has begun
  (after setting aside what a newer schema that may have served held). The account stages
  and syncs every snapshot file first, removes the live `-wal`, `-shm` and `-journal` the
  snapshot doesn't hold (the `-shm` always), renames the database and then its WAL in, and
  syncs the directory; only then is the mark cleared. A retry that finds the mark redoes the
  whole restore from the snapshot, whatever schema the live file shows, so an old journal's
  snapshot with a WAL can't end up beside the failed upgrade's WAL.
- **Records the instance's artifact inventory** beside its database snapshot: the name,
  type and inode of each entry at the top of `.checkpoints/<instance>/`. Root walks from
  `/`, opening every component without following a link, and refuses (exit 2) unless `/`
  and every ancestor of the registry are root's and not group- or other-writable, the
  registry and instance directories are root's alone (`0700`) and neither is a mount
  point, and every ancestor that is a mount point, any number of them, is either the mount
  root of a whole filesystem (its mount source root is `/`, and its device is the one the
  walk opened) or a Btrfs subvolume mounted by itself, never a bind mount of a subtree. A
  Btrfs subvolume's mountinfo root is its `subvol=` path (`/@var` for `/var` on a common
  layout), and `stat` gives each subvolume a device of its own rather than mountinfo's, so
  such a mount is accepted only when its type is `btrfs`, its root equals exactly the
  `subvol=` path in its superblock options (or, if those have none, its mount options),
  and the directory the walk opened is a subvolume root (inode 256). Btrfs prints
  `subvol=` after every other option and escapes only space, tab, newline and backslash in
  it, so the path is the decoded text from the first `subvol=` to the end of the field,
  commas included (`subvol=/@var,archive` is the subvolume `/@var,archive`). A Btrfs mount
  rooted below its subvolume (`/@var/sub` with `subvol=/@var`), or any other filesystem
  with a root other than `/`, is a bind mount and refused. An ancestor that is no mount
  point but has a device other than its parent's is accepted only as a Btrfs subvolume
  nested in its parent's: inode 256, opened on the same mount as its parent (the mount
  IDs in `/proc/self/fdinfo`), and that mount's type in mountinfo is `btrfs`. Any other
  change of filesystem on the way is refused, and so is a
  `/proc/self/mountinfo` the upgrade can't read or parse. An absent instance directory and an
  empty one are the same inventory, and a changed modification time alone is not a
  difference.
- **Checks the inventory after a rollback, and fails closed on a difference.** Artifacts
  are immutable, so the snapshot plus the artifacts on disk are a matching set unless the
  new daemon changed them before the upgrade failed (it may have run and served requests).
  If they differ, the rollback still restores the binaries, unit files, enrollments and
  databases, but **does not start kilnd again**: it keeps its record (the journal, with
  the listing) and exits 3. While that record exists, `recover`, every other command and
  the boot guard exit 3 with the listing, so every unit stays down, across reboots too.
  Reconcile the listed artifacts as in "Cleaning up", then run
  `sudo python3 -I scripts/kilnd-maintenance.py accept-artifacts`. It prints the listing,
  clears the record and starts what was running. A journal from before inventories has
  nothing to compare and recovers as before.

The messages, each prefixed `kilnd-maintenance: `:

| Exit | Message |
|---|---|
| 2 | `refused, nothing changed: <unit> has <n> busy checkpoints: <id> (capturing), <id> (deleting), <id> (fork pin); start kilnd, let those checkpoints settle (kilndctl checkpoint ls), and retry` (at most five IDs) |
| 2 | `refused, nothing changed: cannot inspect the checkpoints of <unit>: <error>` |
| 2 | `refused, nothing changed: <state> holds kilnd state of schema 15 or later, but account <account> is gone, so it cannot be inspected safely; restore the account or move the directory aside, and retry` |
| 2 | `refused, nothing changed: <unit> is stopped, but <n> processes still run as <account>: pids <pid>, …; stop them and retry` (at most ten PIDs) |
| 2 | `refused, nothing changed: cannot list processes in /proc: <error>` |
| 2 | `refused, nothing changed: <unit> is stopped, but <n> processes started as <account> during the upgrade: pids <pid>, …; stop them and retry` (the scan before replacing) |
| 1 | `the upgrade failed and was undone: <unit> is stopped, but <n> processes started as <account> during the upgrade: pids <pid>, …; stop them and retry` (the scan before starting) |
| 1 | `the upgrade failed and was undone: <unit> has <n> busy checkpoints, so its state was not upgraded: <id> (<kind>), …` (init-state's refusal; at most five IDs) |
| 1 | `the upgrade failed and was undone: <unit> has <n> busy checkpoints: <id> (<kind>), …; start kilnd, let those checkpoints settle (kilndctl checkpoint ls), and retry` (a stopped instance's last inspection; at most five IDs) |
| 1 | `the upgrade failed and was undone: <unit> is enrolled as <id>, but its state says <id>` (a stopped instance's last inspection) |
| 2 | `refused, nothing changed: <unit> is enrolled as <id>, but its state says <id>` |
| 2 | `refused, nothing changed: <unit> is enrolled as <id>, but its state records no instance ID; start kilnd once and retry` |
| 2 | `refused, nothing changed: <unit> has checkpoint state but records no instance ID; start kilnd once so it records one, then retry` |
| 2 | `refused, nothing changed: <unit> has an invalid checkpoint instance ID` |
| 2 | `refused, nothing changed: cannot inventory the checkpoint artifacts of <unit>: <error>` |
| 3 | `rolled back, but the checkpoint artifacts of <unit> changed during the window: added '<name>', missing '<name>', changed '<name>'`, then `recovery required: kilnd stays stopped until the checkpoint artifacts are reconciled; then run kilnd-maintenance.py accept-artifacts (docs/checkpoints.md)` |
| 2 | `refused, nothing changed: no checkpoint artifact difference is recorded` (from `accept-artifacts`) |

A step of the rollback that cannot read the inventory logs `rollback: check the checkpoint
artifacts of <unit>: <error>` and leaves the rollback incomplete (exit 3 with its record
kept, as for any other step; `recover` retries it).

## Disk

A capture is admitted only if its reservation R, the lesser of the source's disk limit and
1 GiB rounded down to 512 bytes, fits the uid and node budgets and the headroom. R is charged
until the capture seals; then the checkpoint is charged its sealed size S. A fork is charged
like any sandbox of its disk size and needs the checkpoint's S free beyond the headroom while
it restores. Charged bytes are logical: S includes a 16 KiB allowance per entry, so many
small files cost more than their data. Health's `checkpoint_reserved_disk_bytes` is the
node's checkpoint charge, already inside `reserved_disk_bytes`.

Measured on one test machine ([checkpoint-performance.md](checkpoint-performance.md)), the
allowance is most of the charge for small files: 50,000 small files charged 987 MiB for
208 MiB on disk, and the 1 GiB cap holds about 60,000 of them. Sparse files are charged by
their logical size. Capture time grows with the number of entries (about 0.57 ms each
there, two device flushes per entry), so a client's deadline for a large workspace must
allow tens of seconds; kilnd's own bound is the operation timeout Health reports.
