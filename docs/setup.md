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
limactl create --name=kiln lima.yaml && limactl start kiln
limactl shell --workdir "$PWD" kiln
sudo scripts/fetch-alpine.sh        # the "alpine" image
sudo scripts/setup-storage.sh       # XFS project quotas for --disk
scripts/install.sh                  # /usr/local/bin/kiln, kiln-dns, kiln-metrics
```

kilnd requires persistent-exec protocol v1, first supplied by kiln commit
`f3da4b5319566de4912ed617caf81d4eb8e50b6f`, with follow-up
`711440db3167cdf3a90d3aad44623ce56c2d01b1`, based on baseline `3b42552`.
Install that exact compatible artifact, then check
`kiln capabilities --protocol=1` (binary output). kilnd validates capabilities,
rather than trusting `--version`. Existing sandboxes need compatible PID 1
instances too; an old instance requires explicit recreation. An incompatible
replacement CLI degrades Health and is rejected before workload launch.

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
| `--health-probe-timeout-secs` | 2 |
| `--health-success-cache-secs`, `--health-failure-cache-secs` | 5, 1 |

Limits are validated before state/socket creation. Required values must be
nonzero except `--max-queued-execs-per-sandbox`, which may be zero. Counts
used by semaphores and stream counts must fit `u32`; the per-sandbox queue
plus one must fit too. Request bytes must cover stdin + argv + 64 KiB, and
response bytes must cover twice `--max-output-bytes`, maximum argv, and 64 KiB.
List response bytes cannot exceed response bytes, and pages cannot exceed 1000
items.
Timeouts must be nonzero, the default cannot exceed the maximum, and the
maximum in milliseconds must fit `u32`. Invalid limits fail before opening
SQLite or binding the socket.

Health reports admission maxima, current use and cumulative rejection totals;
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
bounds. Schema v1 upgrades through v2 to v3; v2 upgrades to v3. Schema 3 stores
typed termination and runtime diagnostics together with output and terminal
state, while historical records retain unknown typed values. Schema-1/2
binaries refuse schema 3, so keep a backup before upgrading. Store migration
may occur before startup capability validation fails; installing an older
daemon is not a database downgrade path.

- **Upgrade:** rerun `scripts/install.sh`. Sandboxes keep running across the
  restart.
- **Ownership locks:** `kilnd.lock` and `.kilnd.socket.lock` are persistent
  inode anchors, not stale PID files. Never remove them to fix contention;
  stop the owning daemon and inspect its logs. A crash releases the kernel
  locks automatically even though the files remain. Linux then recovers an
  unchanged stale socket after a bounded refusal probe; ambiguous platforms
  preserve it and require operator inspection.
- **After a reboot,** sandboxes are gone (kiln's state is in tmpfs and
  cgroups). kilnd marks them `lost` at startup; delete them to clear the
  records.
- **Logs:** `--log-format json` in the unit; `KILND_LOG=debug` for more.
- **Stray kiln sandboxes** kilnd didn't create are logged at startup as
  unmanaged and left alone. Remove them with `sudo kiln rm ID`.
- **Bare-metal Linux** works the same way: install kiln and kilnd, then
  enable the unit. Only the Lima VM has been tested.
