# Workspace checkpoint performance (milestone C6b)

**These are measurements of one test machine under the conditions below, not a promise.**
kilnd makes no latency commitment for capture or fork (checkpoint design, decision 1). The
feature stays off by default and is for testing only.

## Conditions

Every VM number below was measured under all of these; a node that differs in any of them
should measure for itself.

| Item | Value |
|---|---|
| Host | Apple M4 Mac mini, macOS, running the guest under Lima's `vz` driver |
| Guest | Ubuntu, kernel `6.8.0-149-generic`, 4 vCPUs, 3.9 GiB RAM, virtio disk backed by APFS |
| kiln | `8735907` (runtime identical to `c55d8bb`); copy path, no reflinks |
| kilnd | branch `checkpoint-c6b-vm-acceptance` (the commit is in each run's raw record) |
| Runs filesystem | XFS with `prjquota` on `loop0`, backed by `/var/lib/kiln/storage.xfs` on the guest's ext4 root |
| Durability | as shipped: kiln syncs every object, directory, manifest and completion marker |
| Daemon and helper | a private daemon (`Manager` over the helper client, gRPC on a private socket) and a private root helper, both children of the test binary, one capture or restore worker per uid, two per node |
| Other load | none: the shared VM lock held, the node's own kilnd and kilnd-helper running and idle (not stopped, not used) |
| Measured | each call's round trip inside a client process, around the one gRPC call (process start excluded) |
| Cache | warm: the source was written just before; cold: `sync; echo 3 > /proc/sys/vm/drop_caches` before each run |

A cell is a source sandbox holding *MiB* of random data spread over *entries* files (one
`split` of `/dev/urandom`, topped up with empty files). Each run captures it, forks the
checkpoint into a new sandbox, then deletes both; 20 runs per cell unless noted.

## Capture and fork, warm cache

| MiB × entries | Runs | Capture p50 / p95 ms | Fork p50 / p95 ms | Charged S MiB | Artifact physical MiB |
|---|---|---|---|---|---|
| 10 × 100 | 20 | 535 / 713 | 130 / 146 | 11.8 | 10.2 |
| 10 × 10,000 | 20 | 5,867 / 6,202 | 1,475 / 1,497 | 197 | 41.5 |
| 10 × 50,000 | 20 | 28,447 / 35,409 | 7,017 / 7,081 | 987 | 207 |
| 50 × 100 | 20 | 268 / 276 | 373 / 380 | 51.6 | 50.0 |
| 50 × 10,000 | 20 | 5,904 / 5,985 | 1,785 / 1,801 | 237 | 80.6 |
| 50 × 50,000 | 20 | 28,630 / 29,953 | 7,282 / 7,344 | 987 | 208 |
| 100 × 100 | 20 | 446 / 459 | 680 / 692 | 102 | 100 |
| 100 × 10,000 | 20 | 6,142 / 6,234 | 2,087 / 2,105 | 276 | 120 |
| 100 × 50,000 | **n=8** | 28,991 / 30,480 | 7,520 / 7,559 | 987 | 208 |

The 100 × 50,000 cell has 8 runs, not 20: its window's time ran out.

What the grid shows, under these conditions only:

- **Entry count, not bytes, sets the time.** A capture costs about 0.57 ms per entry. Each
  entry costs about two device flushes on `loop0` (kiln syncs each object and directory):
  about 209 flushes for 100 entries, 20,000 for 10,000 and 100,000 for 50,000, each
  interval's count including whatever else the guest flushed then.
- **The charge is mostly the per-entry allowance.** At 50,000 entries the sealed charge S
  is 987 MiB of the 1 GiB per-checkpoint cap, nearly all of it the 16 KiB-per-entry
  allowance, while the artifact uses 208 MiB on disk (about 4.3 KiB and one inode per
  entry). So the allowance, not the data, is what limits how many entries a checkpoint can
  hold under the default cap (see [checkpoints.md](checkpoints.md)): the 65,536-entry
  bound cannot be reached separately under it.
- **A fork's upper is a full copy** (no reflinks): the fork's raw upper used 10.2, 39.4,
  197, 50.0, 78.5, 197, 100, 118 and 197 MiB for the nine cells.
- **The worker's footprint** stayed under the 64 MiB worker budget: peak RSS 3.5 MiB at 100
  entries, 7.3 MiB at 10,000 and 23 MiB at 50,000. Its system CPU was about 0.8 s per
  10,000 entries.
- **The digest is a small share.** On this guest `sha256sum` hashes 100 MiB in 0.03 s of
  user CPU, so hashing is at most about 7% of the fastest 100 MiB capture.

## Cold cache, sparse files, metadata and concurrency

Cold: `sync; echo 3 > /proc/sys/vm/drop_caches` before each run, 10 runs per cell.

| MiB × entries | Capture p50 / p95 ms | Fork p50 / p95 ms |
|---|---|---|
| 10 × 100 | 1,194 / 1,636 | 150 / 168 |
| 50 × 10,000 | 7,611 / 30,544 | 1,765 / 1,868 |
| 100 × 50,000 | 37,520 / 48,217 | 7,539 / 7,637 |

The cold 50 × 10,000 p95 is one slow run in ten; with 10 runs per cell, the p95 is the
slowest run or close to it.

| Case | Runs | Capture p50 / p95 ms | Fork p50 ms | Charged S | Physical |
|---|---|---|---|---|---|
| One 960 MiB sparse file (3 bytes written at its end) | 10 | 2,522 / 2,529 | 5,027 | 960 MiB | 16 KiB |
| 50,000 empty files, one user xattr each | 10 | 16,500 / 16,650 | 1,352 | 793 MiB | 13.3 MiB |

- **Sparse files are charged by logical size.** Holes stay holes in the artifact and the
  fork (the fork's upper used 4 KiB), but they count as zeros in the digest and in the
  charge, so a sparse file uses its whole logical size of the cap.
- **Empty files with an xattr** cost about 0.33 ms each, about 60% of a small data file's, and
  still two device flushes each.

Two workers at once, 50 MiB × 10,000, two uids, 20 runs each:

| Measure | p50 / p95 ms |
|---|---|
| One capture alone | 5,856 / 5,963 |
| Two captures at once (each) | 7,728 / 8,078 |
| A capture with a fork at once: the capture | 6,558 / 6,674 |
| A capture with a fork at once: the fork | 1,833 / 1,876 |

Two simultaneous captures each took about 1.3 times as long as one alone.

## Admission and discovery costs

| Measure | Runs | p50 / p95 ms |
|---|---|---|
| The helper's checkpoint `Capabilities`, called directly over its socket | 200 | 6.6 / 6.9 |
| Health with the feature on | 200 | 8.0 / 8.3 |
| Health with the feature off | 200 | 0.94 / 1.08 |

Each capture and fork's admission includes one `Capabilities` call, so the first row is
also the added latency per admission. Health with the feature on asked the helper 3 times
in 200 calls (its probe results are cached); its cost over the flag-off Health is the
probes' own statvfs and checks.

## What this means for clients (observations, not tuning)

- **Deadlines.** Capture time grows about 0.57 ms per entry, so a 50,000-entry workspace
  took about 28 s warm and 37 s (p50) to 48 s (p95) cold. kilnd's own bound is the
  checkpoint operation timeout, 120 s by default (Health's
  `ApiLimits.checkpoint.operation_timeout_ms`), within the helper's 300 s ceiling: under
  these conditions the largest admissible workspace (65,536 entries) would take about 37 s
  warm, inside it. `kilndctl` sets no gRPC deadline of its own. A client that sets one must
  allow for this; kiln-harness's capture deadline should be at least the operation timeout.
- **The per-entry allowance dominates the charge.** At 50,000 entries the charge is about
  4.7 times the physical use (987 MiB against 208 MiB), so the 1 GiB per-checkpoint cap is
  in effect an entry cap of about 60,000 entries for small files. Whether 16 KiB per entry is
  the right allowance is a tuning question for enablement; C6b changes no limit.

## Daemon overhead on the fake runtime (Mac, not a VM number)

On the Mac, with the fake runtime (no files, no workers), a debug test build and SQLite in a
temporary directory, 1,000 calls each through the gRPC service in-process: capture p50
5.2 ms / p95 5.6 ms, fork 7.1 / 7.8 ms, checkpoint delete 4.9 / 5.1 ms, sandbox delete
5.2 / 5.4 ms (`c6b_fake_daemon_overhead`). This is the daemon's own store and admission
path in an unoptimized build, an upper bound on kilnd's share, not a node latency.

## Raw records

Every run's row (latencies, helper and worker CPU, worker peak RSS, R, S, logical and
allocated bytes, entries, artifact and fork physical bytes and inodes, device flushes) is
kept with the test records of milestone C6b, outside this repository. The harness is
`crates/kilnd/src/manager/tests/checkpoint_vm_perf.rs`, run by
`scripts/checkpoint-crash-matrix.py --set perf`.
