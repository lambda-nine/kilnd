#!/bin/sh
# Builds kilnd and kilndctl, installs them in /usr/local/bin, creates the
# kilnd group (allowed to use the API socket) and starts the kilnd service.
# Needs kiln installed first (kiln's scripts/install.sh). Run inside the VM
# as your user:
#   scripts/install.sh
set -eu
cd "$(dirname "$0")/.."
target=${CARGO_TARGET_DIR:-target}

[ -x /usr/local/bin/kiln ] || { echo "install kiln first: kiln/scripts/install.sh" >&2; exit 1; }
cargo build --release --locked
sudo install -m 755 "$target/release/kilnd" /usr/local/bin/kilnd
sudo install -m 755 "$target/release/kilndctl" /usr/local/bin/kilndctl
getent group kilnd >/dev/null || sudo groupadd --system kilnd
sudo install -m 644 deploy/kilnd.service /etc/systemd/system/kilnd.service
sudo systemctl daemon-reload
sudo systemctl enable kilnd
sudo systemctl restart kilnd
systemctl --no-pager --lines=5 status kilnd
