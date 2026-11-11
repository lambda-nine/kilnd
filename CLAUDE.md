# kilnd: notes for agents

kilnd is the per-node control daemon for kiln sandboxes: gRPC (`kilnd.v1`)
on `/run/kilnd/kilnd.sock`, state in SQLite at `/var/lib/kilnd`, kiln driven
through its CLI. Read [README.md](README.md),
[docs/architecture.md](docs/architecture.md) and
[docs/threat-model.md](docs/threat-model.md) before changing anything.

## Working here

- **The Mac mini is the development machine.** kilnd builds and unit-tests on
  macOS, but runs only in kiln's Lima VM (`limactl shell --workdir "$PWD"
  kiln`), which mounts this checkout at the same path. In the VM,
  `CARGO_TARGET_DIR=$HOME/.cache/kilnd-target` keeps Linux builds out of
  `target/`.
- **Checks before every commit:** `scripts/build.sh default test`,
  `scripts/build.sh default clippy --all-targets` (it supplies `-D warnings -D
  clippy::disallowed_methods`), the same two with the `firecracker-test-deployment`
  profile, `git diff --check` and `python3 -I scripts/kilnd-maintenance-tests.py`.
  CI runs them with Rust 1.88 (the MSRV), and clippy again with 1.99.
- **Every build goes through `scripts/build.sh PROFILE`** (design section 7.1's
  dependency gate): a profile from `dependency-gate.json` is the build's only feature
  input, and build.sh refuses feature flags, `--config`, `-Z`, a clippy tail, and an
  ambient `RUSTFLAGS`, `RUSTC_WRAPPER` and the like. Never run raw `cargo` builds in
  scripts, CI or instructions.
- **Crates:** `kilnd` (daemon, helper, store), `kilnd-api` (generated gRPC), `kilndctl`,
  `kilnd-exec-core` (the direct-kiln process/status/capture/validation core, shared with the
  guest broker; kilnd re-exports it from the old paths) and `kilnd-broker-protocol` (the
  strict broker protocol v1 codec, design section 5.2).
- **The destructive-action gate is clippy.** `clippy.toml` disallows raw signals,
  removals, renames, unmounts, `libc::syscall`, `libc::ioctl` and subprocesses. Use the
  proof-taking functions in `helper/firecracker/proven.rs` or the typed wrappers in
  `src/sys.rs`; never add `#[allow(clippy::disallowed_methods)]` outside the approved list
  in `proven::tests::disallowed_allows_only_in_approved_modules` (design section 7.1).
- **Privileged checks** for anything touching the runtime adapter, process
  handling, reconciliation, the socket or shutdown, in the VM after
  `scripts/install.sh`: `scripts/integration-test.sh`,
  `scripts/daemon-singleton-regressions.sh`,
  `scripts/state-path-regressions.sh`,
  `sudo python3 -I scripts/phase0-regressions.py`, `scripts/smoke.sh` and, for
  anything touching expiry, the manager's delete path or the clocks,
  `scripts/expiry-regressions.sh`, and for anything touching create, request
  records or retention, `scripts/idempotent-create-regressions.sh`. Exec cwd and env
  need a kiln with exec options (bit `0x20`, kiln `5cada84` or later) installed for the
  integration, smoke and phase 0 checks to run their positive cases. Changes to
  `install.sh`, `add-instance.sh`, `upgrade.sh`, `kilnd-maintenance.py` or the units also run
  `sudo python3 -I scripts/deployment-regressions.py` between two builds, and its
  `--reboot-arm` and `--reboot-verify` around a real reboot of the VM.
  The integration script also runs the dedicated-child admission FD/RSS,
  slow-client, queue and concurrent-Health stress regression.
- **kiln stays in its own repository** (`~/Projects/lambda-nine/kiln`). Never
  copy its runtime code here. If kilnd exposes a kiln defect, fix it there,
  with its own test and commit.
- **No LLM or product code here.** The agent loop, providers, memory and tool
  registry come later as a separate layer over the API (docs/roadmap.md).
  Downstream products consume the harness; nothing specific to them belongs here.
- **The API is backend-neutral.** Don't add kiln-only fields to
  `proto/kilnd/v1`; within v1, only add fields and RPCs.
- **Keep the docs in step,** and add a line to CHANGELOG.md.
- **Commits are attributed to Stephen only** (Stephen Estrada
  <stcrestrada@gmail.com>). No `Co-Authored-By` trailers of any kind.
- **Releases need Stephen's explicit approval.** The repositories are public;
  never push secrets, private notes or `reviews/` material.
- **Security wording:** kiln is experimental shared-kernel isolation, not a
  boundary for hostile multi-tenant workloads.

## Privilege boundary

Production kilnd refuses root and runs as the non-login `kilnd` account, or a
`kilnd-<name>` account of its own for each further Firecracker instance, with no
capabilities. Only `kilnd-helper` runs root, using its typed private socket
protocol (`docs/helper-protocol.md`). Keep helper validators, fd constraints,
deadlines, peer UID checks and shared process/cleanup evidence fail-closed.
`KilnRuntime` is a helper client; `DirectKilnRuntime` is for the helper and
privileged adapter tests. API callers must never supply host executable paths,
flags or environment to the helper. Future backends get separate validated
enum variants; the Runtime trait stays backend-neutral.
