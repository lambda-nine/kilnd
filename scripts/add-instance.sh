#!/bin/sh
# Adds one more kilnd instance on this node, under its own Unix account and group, with the
# ID its own state holds. Needs scripts/install.sh and a provisioned Firecracker node policy
# (docs/setup.md). Enrollment takes the node lock, so every instance stops briefly, with the
# helper unable to start, and exactly what was running starts again:
#   scripts/add-instance.sh <name>
set -eu
cd "$(dirname "$0")/.."
[ "$#" -eq 1 ] || { echo "usage: $0 <name>" >&2; exit 2; }
root=
[ "$(id -u)" -eq 0 ] || root=sudo
$root python3 -I scripts/kilnd-maintenance.py add-instance "$1"
systemctl --no-pager --lines=5 status "kilnd@$1.service" || true
