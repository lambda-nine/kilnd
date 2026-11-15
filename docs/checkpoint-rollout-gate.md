# Workspace checkpoint rollout gate

**Status: draft (milestone C6a).** The criteria are fixed here; the evidence slots marked
*pending* are filled by milestone C6b. Until every criterion holds, and the default is
decided, `--enable-workspace-checkpoints` stays off by default and documented as testing
only. Passing the gate does not by itself turn the feature on anywhere.

Each criterion is checkable: a test, a run with recorded conditions, or a document.

| # | Criterion | Evidence | Status |
|---|---|---|---|
| 1 | Every crash point of the design's recovery table, every required-test case and every adversarial-review finding of milestones C3–C5b is named in the acceptance ledger with a passing test, a planned VM scenario, or an explicit accepted disposition | `crates/kilnd/tests/data/checkpoint-acceptance-matrix.json`; `checkpoint_acceptance_matrix` tests and build.sh compiled-registry check in CI | C6a |
| 2 | The VM crash matrix passes on the pinned kiln and kernel, with the host check clean before and after every scenario: real process death of the daemon, the root helper and kiln's copy and restore workers at each capture, removal and fork boundary; a reboot; a stale database backup; a corrupt artifact; a kill during the startup barrier | `scripts/checkpoint-crash-matrix.py` run log | *pending (C6b)* |
| 3 | Hostile workspace content (links, special files, ACLs, file capabilities, xattrs, names, depth, entry count, sparse and inode-heavy trees, protected paths) is refused before allocation or round-trips exactly, through kilnd's capture and fork on the pinned kiln, with host and other users' sandboxes unchanged; hostile callers (two real uids) get only their own checkpoints and budgets | VM run log | *pending (C6b)* |
| 4 | The rewind, best-of-N and eval-reset client fixtures pass on the fake runtime (CI) and on real kiln (VM), the latter checking workspace content byte for byte | `manager::checkpoint::tests::api::clients` in CI; VM run log | Mac: C6a; VM: *pending (C6b)* |
| 5 | The harness contract goldens are unchanged: fixture request and response shapes, every typed refusal's code and `kilnd-reason` token, and Health with the flag on; flag-off Health bytes unchanged | `crates/kilnd/tests/data/checkpoint-contract.json`; `flag_off_health_bytes_are_unchanged` | C6a |
| 6 | A performance report is published with its conditions (hardware, kernel, kiln, filesystem and backing, cache state, concurrency, runs per cell, p50 and p95). No latency is promised | `docs/checkpoint-performance.md` | *pending (C6b)* |
| 7 | Operator documentation covers enabling and disabling, cleanup, backup, upgrade and rollback with checkpoints present; the maintenance upgrade refuses while a checkpoint is in flight and checks the artifact inventory on rollback, with tests | [checkpoints.md](checkpoints.md); `scripts/kilnd-maintenance-tests.py`; `maintenance_busy_query_matches_the_schema` | C6a |
| 8 | No HIGH or MEDIUM finding of the C6 adversarial reviews is open | review records | *pending* |
| 9 | On the node itself, every discovery probe passes (Health lists `workspace_checkpoint`): helper group enabled, leases, format 1, generation-checked removal, XFS with project quotas on runs, trusted image registry, free space known; headroom configured | `kilndctl health` on the node | per node |
| 10 | The node runs the kiln commit the gate was measured on, or a later one on which criteria 2–4 were rerun | `kiln --version` against the gate record | per node |

Full-suite `scripts/build.sh PROFILE test` pins the ordered crash, case and finding IDs,
then checks ledger test references against Cargo's compiled libtest registry after the
suite passes. Mac references must be compiled and non-ignored in that profile. VM
references must be compiled and ignored on Linux; elsewhere they may be absent but
must be ignored if compiled. A filtered test run does not perform this registry gate.
Names start with the test binary's crate name, followed by its libtest path; binary
unit-test targets add `::bin` and doctests add `::doc` to distinguish them from a
same-named library. Duplicate binary identities and unparsed listing lines fail closed.

## Gate record

| Item | Value |
|---|---|
| kilnd commit | *pending* |
| kiln commit | `8735907` (runtime identical to `c55d8bb`) |
| Kernel | `6.8.0-149-generic` |
| Filesystem | XFS with `prjquota` on a loop device, in a Lima `vz` guest on Apple silicon |
| Date | *pending* |
