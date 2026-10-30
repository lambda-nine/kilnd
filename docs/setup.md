# Setting up kilnd

kilnd runs where kiln runs: Linux 6.8+ with cgroups v2, as root. On a Mac
that means kiln's Lima VM (Ubuntu 24.04, aarch64). These steps take a fresh
Mac to a working kilnd; they were run on the Mac mini (Estradas-Mac-mini)
on 2026-10-13.

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
git checkout --detach 46d84bdfe13e331f047e70e38848f7d74bcd2872  # tested companion
limactl create --name=kiln lima.yaml && limactl start kiln
limactl shell --workdir "$PWD" kiln
sudo scripts/fetch-alpine.sh        # the "alpine" image
sudo scripts/setup-storage.sh       # XFS project quotas for --disk
unset CARGO_TARGET_DIR              # kiln's installer uses target/release
scripts/install.sh                  # /usr/local/bin/kiln, kiln-dns, kiln-metrics
```

kilnd requires persistent-exec protocol v1 and scoped `gc ID...`. The minimum
kiln revision providing both is `40d9aa5003205d4c171e1b3eca61e9868064e98b`.
`711440db3167` has the exec protocol but lacks scoped GC and is refused.
The tested companion is `46d84bdfe13e331f047e70e38848f7d74bcd2872` on
`review/breakit-fixes`: install, integration, smoke and every kilnd regression
script passed against that immutable pin on 2026-10-30.
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

`scripts/install.sh` builds release binaries, installs `/usr/local/bin/kilnd`
and `/usr/local/bin/kilndctl`, creates the `kilnd` system group, installs and
starts `kilnd.service`. To use the socket without sudo:
`sudo usermod -aG kilnd $USER`, then open a new shell.

Check it:

```sh
sudo kilndctl health
systemctl status kilnd
journalctl -u kilnd -o cat -f        # one JSON object per line
sudo sqlite3 /var/lib/kilnd/kilnd.db 'SELECT id, state, backend_id FROM sandboxes'
```

## 4. Tests

```sh
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
scripts/integration-test.sh          # dedicated admission stress, then root + real kiln
scripts/daemon-singleton-regressions.sh # duplicate starts preserve active work
scripts/state-path-regressions.sh    # ownership, mode, type, link and symlink defenses
scripts/smoke.sh                     # through the installed service
```

The smoke test restarts and kills kilnd, so don't run it on a node with
sandboxes you care about.

## Operating notes

The daemon's admission flags and defaults are:

| Flags | Defaults |
|-------|----------|
| `--max-connections`, `--max-streams-per-connection` | 64, 8 |
| `--max-concurrent-rpcs`, `--max-concurrent-health` | 64, 4 |
| `--max-concurrent-execs`, `--max-queued-execs-per-sandbox` | 32, 8 (plus one running) |
| `--max-queued-exec-stdin-bytes` | 16777216 (16 MiB) |
| `--max-request-bytes`, `--max-response-bytes` | 2097152, 4194304 |
| `--max-list-page-size`, `--max-list-response-bytes` | 200, 1048576 |
| `--max-sandboxes` | 32 retained reservations |
| `--max-node-memory-bytes` | 3221225472 (3 GiB) |
| `--max-node-pids` | 2048 |
| `--max-node-disk-bytes` | 17179869184 (16 GiB) |
| `--health-probe-timeout-secs` | 2 |
| `--health-success-cache-secs`, `--health-failure-cache-secs` | 5, 1 |

Limits are validated before state/socket creation. Required values must be
nonzero except `--max-queued-execs-per-sandbox`, which may be zero. Counts
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
caps. Slow authorized clients can monopolize those bounded slots; there is no
tenant fairness, and synchronous SQLite/filesystem operations are not hard
real time. History still grows without retention.

An Exec timeout includes queueing. Expiry before row insertion returns
`DEADLINE_EXCEEDED`; expiry afterwards returns a successful terminal
`TIMED_OUT` execution once cleanup/finalization finishes, potentially later
than the deadline. Tickets remain held while finalization retries.

`kilndctl ls` follows pages and prints incrementally. Other clients should set
`page_size` (present zero means the server default, normally 100) and pass the
opaque `next_page_token` until empty, keeping `include_deleted` unchanged.
Omitting `page_size` preserves complete-list behavior but now fails
`RESOURCE_EXHAUSTED` when the result exceeds the configured count or byte
bounds. Schema v1 upgrades through v2 and v3 to v4; v2/v3 also upgrade to v4.
Schema 4 stores typed termination and runtime diagnostics together with output,
terminal state, truncation facts and whether each byte total is exact.
Historical records retain unknown typed values and unknown output-total
certainty. Older binaries refuse schema 4, so keep a backup before upgrading.
Store migration may occur before startup capability validation fails;
installing an older daemon is not a database downgrade path.

- **Upgrade:** rerun `scripts/install.sh`. Sandboxes keep running across the
  restart.
- **State path:** `--state-dir` must be absolute. Its real ancestors must be
  trusted and non-writable, and every nested symlink alias must be owned by
  root (a root-owned sticky temporary directory is allowed). The final
  directory must be root-owned 0700, and existing
  `kilnd.db`, WAL, SHM or journal entries must be root-owned regular 0600 files
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
- **Node budget cleanup:** `LOST` and a `FAILED` create with no backend ID keep
  their durable reservation. Known-ID deletion requires a negative exact-ID
  probe, a complete list omitting the ID and absent cgroup. Delete refuses a
  no-ID ambiguous `FAILED` row even after stray resources have been removed:
  ordinary listings cannot account for hidden resources, and authoritative
  no-ID reconciliation is not yet supported. Do not release capacity by editing
  SQLite.
  Lowering configured budgets below surviving reservations degrades Health and
  rejects new creates, but Get/List/Delete and reconciliation remain available
  so the node can be brought back within budget.
- **Logs:** `--log-format json` in the unit; `KILND_LOG=debug` for more.
- **Stray kiln sandboxes** kilnd didn't create are logged at startup as
  unmanaged and left alone. Remove live ones with `sudo kiln rm ID`; remove
  stale ones explicitly with `sudo kiln gc ID`.
- **Reservation boundary:** budgets cover promises made through kilnd. Trusted
  root or direct `kiln` use can bypass them and must be included in deployment
  headroom and operator accounting.
- **Bare-metal Linux** works the same way: install kiln and kilnd, then
  enable the unit. Only the Lima VM has been tested.
