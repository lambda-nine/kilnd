# The isolated Firecracker test deployment (Phase 1b B6)

This is the only way to run kilnd on the Firecracker backend before B7. It exists so
B6 can drive whole sessions through the real daemon and `kilndctl` on the dev VM. It is
**not** a production configuration, and nothing in it can turn production Firecracker on.

## What it is

[`deployment.json`](deployment.json) names one isolated test deployment:

| Field | Value | Meaning |
|---|---|---|
| `schema` | `kilnd-firecracker-test-deployment/1` | The only schema this build reads |
| `deployment` | `isolated-test` | The only kind before B7 |
| `profile` | `offline-768-v1` | The one Phase 1b guest profile (768 MiB, one vCPU, offline) |
| `kilnd.socket` | `/run/kilnd-fctest/kilnd.sock` | The test daemon's API socket |
| `kilnd.socket_group`, `kilnd.account` | `kilnd-fctest` | Its own account and group, never `kilnd` |
| `kilnd.state_dir` | `/var/lib/kilnd-fctest` | Its own database, never `/var/lib/kilnd` |
| `kilnd.unit` | `kilnd-fctest.service` | Its own unit, so its own cgroup to enroll |
| `helper.root`, `helper.socket` | `/run/kilnd-fctest-helper`, `…/helper.sock` | The test helper's private root (ledger, logs) and socket, never `/run/kilnd-helper` |

The daemon side is `kilnd --backend firecracker --firecracker-test-deployment <file>`, and
both flags exist only in a kilnd built with the non-default `firecracker-test-deployment`
cargo feature (`cargo build -p kilnd --features firecracker-test-deployment`). A default
build, which is what `cargo build --release`, `scripts/install.sh` and CI's release step
make, refuses both at argument parsing. A feature build reads the file strictly (exact
fields, no duplicate keys, at most 64 KiB) and, before it opens any state, refuses to
start unless:

- its `--socket`, `--state-dir` and `--helper-socket` are exactly the file's;
- no path in the file is, contains or lies under a production path (`/run/kilnd`,
  `/var/lib/kilnd`, `/run/kilnd-helper`, `/var/lib/kilnd-helper`, `/etc/kilnd`);
- the account, group and unit are named as its own, not `kilnd`, `root` or
  `kilnd.service`;
- and they are what the process observably is (B6-BI-01): its real, effective and saved
  UIDs are the UID `getpwnam` gives the file's account (which must exist, and is never 0
  or the production `kilnd` account's), the GID of the CLI's `--socket-group` is the
  file's group's (never the production `kilnd` group's), and its own cgroup, read from
  its procfs entry beneath kilnd's private procfs instance, ends in exactly
  `/<unit>`. Every mismatch is named in the refusal.

`--backend firecracker` without the file is refused, and so is the file with the default
`kiln` backend. The installed units never pass either flag.
`scripts/test-deployment-gate-regressions.sh` checks all of this: `release` mode against a
default build, `feature` mode against a feature build unprivileged, and `root` mode (in
the VM) with a real account and transient unit, where each wrong account, group or unit
is refused on its own and the matching identity is selected.

## Why production stays off

The gate has two halves, and B6 changes neither's production behavior:

1. **The helper.** The installed `kilnd-helper` loads every catalog profile through
   `ManifestGate::ProductionDisabled`, which refuses every manifest. The only other gate,
   `ManifestGate::TestApproved`, has no constructor outside `cfg(test)`, no CLI flag and
   no policy spelling. So the production helper serves no Firecracker profile: every
   Preflight is a C0 refusal with zero session effects, even for a daemon started with
   this file. `exit1_production_gate_leaves_every_catalog_profile_refused` checks both.
2. **The daemon.** Only a feature build has the backend at all, and only this file
   selects it, at these non-production paths and as this account, group and unit
   (`test_deployment::tests`, `scripts/test-deployment-gate-regressions.sh`).

The helper that does serve the test profile is the real node code (H and its L/P/S/M/K
workers, R and D, the patched jailer, the release Firecracker VMM and the pinned
production guest bundle) running from the test binary's protected installed image under
the test gate, exactly as the B4 and B5 real-chain suites run it.

## Running it

In the kiln Lima VM, under the shared VM lock, after `scripts/build-phase1b-tools.sh`
and with the B5 production bundle at `$HOME/kiln-guest-build/bundle-a`:

```sh
B6_EVIDENCE=$HOME/b6-evidence scripts/b4-vm-tests.sh b6_linux_root
```

The script builds `kilnd` (with the `firecracker-test-deployment` feature) and `kilndctl`
(ordinary dynamic release binaries, in `$HOME/.cache/kilnd-target-b6`) and the static test binary, then runs
`b6_linux_root_a_whole_session_through_kilnd_and_kilndctl`, which:

1. creates the `kilnd-fctest` system account, installs the daemon image root-owned at
   `/opt/kilnd/b6-session/kilnd` with this file beside it, and runs
   `kilnd init-state` for the instance ID;
2. builds the test helper at `helper.root`, and, with the helper stopped, enrolls that
   instance's account, unit, cgroup (`/system.slice/kilnd-fctest.service`) and image
   digest in its node ledger, as `scripts/add-instance.sh` does in production;
3. starts the daemon with `systemd-run` as the transient `kilnd-fctest.service`, with
   every `[Service]` setting of `deploy/kilnd@.service` (the account, state and runtime
   directories, `ProtectSystem=strict`, `PrivateTmp`, `ProtectProc=invisible`,
   `RestrictAddressFamilies=AF_UNIX` and the rest). The helper attests it for real: its
   account, its exact unit cgroup and its image's device, inode and SHA-256;
4. drives the session with `kilndctl` and checks the SQLite and journal evidence (below);
5. stops the daemon. `scripts/b4-vm-cleanup.py`, which the script runs on exit, removes
   the unit, the account, the state directory, the helper root and every owned VM
   resource, and fails if anything is left.

With `B6_EVIDENCE` set, the test writes `transcript.txt` (every `kilndctl` command, its
output and exit code), `kilnd-db.json` (the sandbox row, its executions and its release
evidence), `helper-journal.json` (the node ledger's allocation, claim, leases, stop and
resource events and retired token), `kilnd.log` and `helper.log` there.

## The crash matrix and the attacks (B6 milestone 2)

The same deployment, with a second daemon `fctest2` (account `kilnd-fctest2`, unit
`kilnd-fctest2.service`, socket `/run/kilnd-fctest2/kilnd.sock`, state
`/var/lib/kilnd-fctest2`, the same helper) where a scenario needs two, runs the
global-ledger crash matrix and section 10's attacks:

```sh
python3 -I scripts/firecracker-crash-matrix.py --evidence $HOME/b6/crash
python3 -I scripts/firecracker-regressions.py --evidence $HOME/b6/attacks
```

Each scenario is one privileged test in
`crates/kilnd/src/helper/firecracker/tests/recovery.rs`, run alone through
`scripts/b4-vm-tests.sh` with a clean host before and after. Each script writes the
transcripts, daemon and helper logs, `tests.log`, `matrix.json` and `matrix.md`, and
fails if any scenario is missing or failed. Byte copies of daemon state for the database
scenarios live under `/var/lib/kilnd-b6-copies`, which the cleanup script removes too.
Both scripts refuse to start past 90 minutes of VM uptime, because the kiln VM freezes
at about two hours.

## What the session proves

- `kilndctl create --net none` reaches READY through C0 to C7: Preflight, the C1 row, the
  helper's C2 claim, boot, the broker's handshake and the published READY receipt.
- Successive `kilndctl exec` calls share one persistent kiln sandbox: a file one writes,
  the next reads; stdin, stderr and a nonzero exit keep the session reusable.
- `kilndctl exec --timeout 3s … sleep 60` exits 124; the helper retires the VM (cancel,
  then the host stop barrier); the execution is `timed_out` with `sandbox_reusable=0` and
  `sandbox_stopped` cleanup evidence; the sandbox is `lost` and refuses the next command.
  Its disk, jail, cgroup and node claim stay charged until Delete.
- `kilndctl rm` removes everything by exact token and reaches ABSENT: the helper's claim is
  released, the daemon's row is `deleted` with its matching `release_evidence` receipt, and
  no VMM, loop device, mount, cgroup or file remains.
