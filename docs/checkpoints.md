# Operating workspace checkpoints

Workspace checkpoints capture a sandbox's writes over its image and create new sandboxes
from them (design in [architecture.md](architecture.md#workspace-checkpoint-api-milestone-c5b-1)).
**They are for tests and explicit staging only** until the rollout gate
([checkpoint-rollout-gate.md](checkpoint-rollout-gate.md)) passes and the default is decided.
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

`kilndctl health` lists `workspace_checkpoint` only while every probe passes: the helper's
group is enabled, kiln grants leases, lists checkpoint format 1 and checks generations on
removal, runs is XFS with project quotas, kiln's image registry is trusted, and free space
on runs and its backing is known. When a probe fails, Health stays SERVING with
`workspace checkpoints withdrawn: <why>` in its detail, and new captures and forks are
refused with a typed reason until a later probe passes. Firecracker never lists the feature.

**Turning it off keeps what exists.** With the flag off and checkpoint state on disk (any
row, capture key or barrier marker), kilnd still serves Get, List and Delete, answers
keyed retries from their records, runs expiry and removal, and reconciles at startup. Only
new captures and forks are refused (`UNIMPLEMENTED backend_unsupported:workspace_checkpoint`).
Charges stay counted until each artifact's removal is proved. Turning the helper's group off
instead makes removal impossible: the rows stay DELETING and charged, and kilnd retries.
Turn kilnd's flag off first, let the checkpoints expire or delete them, and only then turn
off the helper's group.

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
  checkpoint `capturing` or `deleting`, or one with a fork still restoring from it. The
  daemons were stopped to take the snapshot, so they are started again; let those
  checkpoints settle (`kilndctl checkpoint ls`), then retry.
- **Records the instance's artifact inventory** beside its database snapshot.
- **Checks the inventory after a rollback.** Artifacts are immutable, so the snapshot plus
  the artifacts on disk are a matching set unless the new daemon changed them before the
  upgrade failed (it may have run and served requests). If they differ, the rollback still
  finishes (binaries, unit files, enrollments and databases are back and the units
  restarted) and the command exits 3, listing the artifacts added, missing or changed.
  kilnd then keeps new disk work blocked, or quarantines the rows, as above. Nothing is
  left for `recover` in this case: reconcile the listed artifacts as in "Cleaning up".
  A rollback finished at boot only logs the difference; the first `recover` (or other
  command) after it reports it the same way and exits 3, once.

The messages, each prefixed `kilnd-maintenance: `:

| Exit | Message |
|---|---|
| 2 | `refused, nothing changed: <unit> has <n> busy checkpoints: <id> (capturing), <id> (deleting), <id> (fork pin); start kilnd, let those checkpoints settle (kilndctl checkpoint ls), and retry` (at most five IDs) |
| 2 | `refused, nothing changed: cannot inspect the checkpoints of <unit>: <error>` |
| 2 | `refused, nothing changed: <unit> has an invalid checkpoint instance ID` |
| 2 | `refused, nothing changed: cannot inventory the checkpoint artifacts of <unit>: <error>` |
| 3 | `rolled back, but the checkpoint artifacts of <unit> changed during the window: added '<name>', missing '<name>', changed '<name>'; kilnd blocks new disk work or quarantines rows until they are reconciled; see docs/checkpoints.md` |

A step of the rollback that cannot read the inventory logs `rollback: check the checkpoint
artifacts of <unit>: <error>` and leaves the rollback incomplete (exit 3 with its record
kept, as for any other step; `recover` retries it). `changed '<directory>'` means the
instance's artifact directory appeared or vanished as a whole.

## Disk

A capture is admitted only if its reservation R, the lesser of the source's disk limit and
1 GiB rounded down to 512 bytes, fits the uid and node budgets and the headroom. R is charged
until the capture seals; then the checkpoint is charged its sealed size S. A fork is charged
like any sandbox of its disk size and needs the checkpoint's S free beyond the headroom while
it restores. Charged bytes are logical: S includes a 16 KiB allowance per entry, so many
small files cost more than their data. Health's `checkpoint_reserved_disk_bytes` is the
node's checkpoint charge, already inside `reserved_disk_bytes`.
