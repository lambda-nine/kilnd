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
- **Checks before every commit:** `cargo test --locked`,
  `cargo clippy --locked --all-targets -- -D warnings`, `git diff --check`.
  CI runs them with Rust 1.88 (the MSRV).
- **Privileged checks** for anything touching the runtime adapter, process
  handling, reconciliation, the socket or shutdown, in the VM after
  `scripts/install.sh`: `scripts/integration-test.sh`,
  `scripts/daemon-singleton-regressions.sh`,
  `scripts/state-path-regressions.sh`,
  `sudo python3 -I scripts/phase0-regressions.py` and `scripts/smoke.sh`.
  The integration script also runs the dedicated-child admission FD/RSS,
  slow-client, queue and concurrent-Health stress regression.
- **kiln stays in its own repository** (`~/Projects/lambda-nine/kiln`). Never
  copy its runtime code here. If kilnd exposes a kiln defect, fix it there,
  with its own test and commit.
- **No LLM or product code here.** The agent loop, providers, memory and tool
  registry come later as a separate layer over the API (docs/roadmap.md).
  Idea Marathon consumes the harness; nothing specific to it belongs here.
- **The API is backend-neutral.** Don't add kiln-only fields to
  `proto/kilnd/v1`; within v1, only add fields and RPCs.
- **Keep the docs in step,** and add a line to CHANGELOG.md.
- **Commits are attributed to Stephen only** (Stephen Estrada
  <stcrestrada@gmail.com>). No `Co-Authored-By` trailers of any kind.
- **Both repositories stay private.** Making either public, or publishing a
  release, needs Stephen's explicit approval.
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
