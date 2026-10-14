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

kilnd needs kiln at or after commit `3736329` (exec cancellation and exit
code 125).

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
scripts/integration-test.sh          # root, real kiln, temporary database
scripts/smoke.sh                     # through the installed service
```

The smoke test restarts and kills kilnd, so don't run it on a node with
sandboxes you care about.

## Operating notes

- **Upgrade:** rerun `scripts/install.sh`. Sandboxes keep running across the
  restart.
- **After a reboot,** sandboxes are gone (kiln's state is in tmpfs and
  cgroups). kilnd marks them `lost` at startup; delete them to clear the
  records.
- **Logs:** `--log-format json` in the unit; `KILND_LOG=debug` for more.
- **Stray kiln sandboxes** kilnd didn't create are logged at startup as
  unmanaged and left alone. Remove them with `sudo kiln rm ID`.
- **Bare-metal Linux** works the same way: install kiln and kilnd, then
  enable the unit. Only the Lima VM has been tested.
