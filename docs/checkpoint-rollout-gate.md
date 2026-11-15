# Workspace checkpoint rollout gate

**Status: evidence filled in (milestone C6b); criterion 8 waits for C6b's adversarial
review.** The criteria were fixed in C6a. Until every criterion holds, and the default is
decided, `--enable-workspace-checkpoints` stays off by default and documented as testing
only. Passing the gate does not by itself turn the feature on anywhere.

Each criterion is checkable: a test, a run with recorded conditions, or a document.

| # | Criterion | Evidence | Status |
|---|---|---|---|
| 1 | Every crash point of the design's recovery table, every required-test case and every adversarial-review finding of milestones C3–C5b is named in the acceptance ledger with a passing test, a VM scenario, or an explicit accepted disposition | `crates/kilnd/tests/data/checkpoint-acceptance-matrix.json`; `checkpoint_acceptance_matrix` tests and build.sh compiled-registry check in CI | **Met.** No planned slot is left. Recorded gaps: the kiln-side cases and C3 findings that only kiln's own tests drive (each names the kiln test, or says there is none), the Firecracker half of legacy behavior (contract tests only, no VM run), V14's lack of partial staging across the real reboot, and two accepted LOWs (C3-r1-L2, C5a-r7-J2). C6b's own finding (C6b-V16) is fixed with its regressions |
| 2 | The VM crash matrix passes on the pinned kiln and kernel, with the host check clean before and after every scenario: real process death of the daemon, the root helper and kiln's copy and restore workers at each capture, removal and fork boundary; a reboot; a stale database backup; a corrupt artifact; a kill during the startup barrier | `scripts/checkpoint-crash-matrix.py --set crash`, `v14-arm` and `v14-verify` run logs | **Met.** V1–V13, V15–V17 pass with clean host checks; V14 passes across a real guest reboot (two boot IDs); V16 passes after the C6b-V16 fix. V9, V11 and V13 hold the C5a-2 pin rule: an undispatched or ambiguous reader's pin is released only by its checkpoint's ABSENT |
| 3 | Hostile workspace content (links, special files, ACLs, file capabilities, xattrs, names, depth, entry count, sparse and inode-heavy trees, protected paths) is refused before allocation or round-trips exactly, through kilnd's capture and fork on the pinned kiln, with host and other users' sandboxes unchanged; hostile callers (two real uids) get only their own checkpoints and budgets | `--set hostile` run logs | **Met,** with two notes. Walk-time refusals (special files, xattrs, depth, size) create the FAILED row and its charge first and release it with ABSENT evidence; refusals before C1 allocate nothing. The 65,536-entry bound cannot be reached separately under the 1 GiB cap: the 16 KiB-per-entry allowance refuses first (`checkpoint_size_limit`) |
| 4 | The rewind, best-of-N and eval-reset client fixtures pass on the fake runtime (CI) and on real kiln (VM), the latter checking workspace content byte for byte | `manager::checkpoint::tests::api::clients` in CI; `--set clients` run logs | **Met.** F1–F3 pass on real kiln byte for byte; F3's seed ends by lifetime on the VM. The alpine image has no `git`, so no `git status` check |
| 5 | The harness contract goldens are unchanged: fixture request and response shapes, every typed refusal's code and `kilnd-reason` token, and Health with the flag on; flag-off Health bytes unchanged | `crates/kilnd/tests/data/checkpoint-contract.json`; `flag_off_health_bytes_are_unchanged` | C6a |
| 6 | A performance report is published with its conditions (hardware, kernel, kiln, filesystem and backing, cache state, concurrency, runs per cell, p50 and p95). No latency is promised | [checkpoint-performance.md](checkpoint-performance.md) | **Met** (one warm cell at n=8, labeled). Open tuning questions it raises, not changed: the per-entry allowance makes the 1 GiB cap an entry cap of about 60,000; a 50,000-entry capture takes about 28 s warm, inside the 120 s operation timeout |
| 7 | Operator documentation covers enabling and disabling, cleanup, backup, upgrade and rollback with checkpoints present; the maintenance upgrade refuses while a checkpoint is in flight and checks the artifact inventory on rollback, with tests | [checkpoints.md](checkpoints.md); `scripts/kilnd-maintenance-tests.py`; `maintenance_busy_query_matches_the_schema` | C6a |
| 8 | No HIGH or MEDIUM finding of the C6 adversarial reviews is open | review records | *pending: C6b's adversarial review* |
| 9 | On the node itself, every discovery probe passes (Health lists `workspace_checkpoint`): helper group enabled, leases, format 1, generation-checked removal, XFS with project quotas on runs, trusted image registry, free space known; headroom configured | `kilndctl health` on the node | per node |
| 10 | The node runs the kiln commit the gate was measured on, or a later one on which criteria 2–4 were rerun | `kiln --version` against the gate record | per node |

Full-suite `scripts/build.sh PROFILE test` pins the ordered crash, case and finding IDs,
runs the suite once with libtest's per-test output kept, then checks the ledger's test
references against that run and Cargo's compiled libtest registry. Every compiled test
must appear in the run, `ok` or, if the registry lists it ignored, `ignored`; a test
listed but not run, run but not listed, or filtered out fails, and every group's counts
must match its lines. Mac references must have run `ok` in that profile. VM references
must be compiled and ignored on Linux; elsewhere they may be absent but must be ignored
if compiled. A filtered test run does not perform this gate. Names start with the test
binary's crate name, followed by its libtest path; binary unit-test targets add `::bin`
and doctests add `::doc` to distinguish them from a same-named library. Duplicate binary
identities and unparsed listing or run lines fail closed.

The run is only as honest as what runs it, so `build.sh` closes Cargo's configuration
before cargo starts (C6a recheck 1): it refuses a `.cargo/config` or `.cargo/config.toml`
in the workspace or any parent directory other than `$CARGO_HOME`'s own, a `$CARGO_HOME`
config with any top-level key but `http`, `net`, `registry`, `registries`, `term`,
`cargo-new` and `source` (an allowlist: `include`, `alias`, `env`, `build`, `target`,
`profile`, `unstable` and any key a later Cargo adds are refused, C6a recheck 3; reading
one needs Python 3.11's `tomllib`, and without it the config is refused unread), a
`$CARGO_HOME/credentials` or `credentials.toml`, which Cargo can merge as configuration, with
anything but `token`, `credential-provider`, `secret-key` and `secret-key-subject` under
`[registry]` and `[registries.NAME]` (C6a recheck 4, read the same way), and any
`CARGO_TARGET_*_RUNNER`, `CARGO_TARGET_*_LINKER`, `CARGO_BUILD_*`, `CARGO_ENV_*`,
`CARGO_ALIAS_*` or `CARGO_PROFILE_*` variable, and it passes a pass-through runner for every
target. Registry and source replacement settings stay allowed: like the toolchain's own
binaries and the crates they fetch, they are inside the trusted toolchain, not something
`build.sh` proves. It
checks the directories cargo will read (C6a recheck 2): it changes to the repository
before any check, resolves `CARGO_HOME` (or `$HOME/.cargo`), `RUSTUP_HOME`, a path-valued
`RUSTUP_TOOLCHAIN` or `+TOOLCHAIN`, `CARGO` and `CARGO_TARGET_DIR` to absolute paths and
exports them, and refuses a relative `HOME`, a `CARGO_HOME` it can't resolve, and a set
`RUSTDOC` or `CLIPPY_CONF_DIR`. `scripts/build-config-regressions.sh` holds it to that.

The contract and wire goldens (`checkpoint-contract.json`, `checkpoint-wire.json`) are
only ever compared by the suite. The one writer is the ignored test
`bless_checkpoint_contract`, run locally, by name, with `--ignored` and
`KILND_BLESS_CHECKPOINT_CONTRACT=1`, outside `build.sh` (its doc comment and the goldens'
notes have the exact command). `build.sh` refuses that variable outright and never
passes `--ignored`, and the test refuses while `CI` is set; review the golden diff it
leaves. The checkpoint messages' field numbers, types and labels, the checkpoint
fields of shared messages and the checkpoint enums are also pinned by a table written by
hand (`checkpoint_field_numbers_match_the_pinned_table`), which nothing blesses.

## Gate record

| Item | Value |
|---|---|
| kilnd commit | branch `checkpoint-c6b-vm-acceptance` (C6b); each VM run records its commit |
| kiln commit | `8735907` (runtime identical to `c55d8bb`) |
| Kernel | `6.8.0-149-generic` |
| Filesystem | XFS with `prjquota` on a loop device, in a Lima `vz` guest on Apple silicon |
| Date | 2026-11-15 |
| VM evidence | crash matrix, hostile set, client fixtures, the reboot and the performance runs, each with the shared VM gate passed before and after |
