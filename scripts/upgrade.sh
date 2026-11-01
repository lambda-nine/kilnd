#!/bin/sh
# Replaces kilnd, kilnd-helper and kilndctl on a node with enrolled instances, as one
# transaction: scripts/kilnd-maintenance.py documents it, docs/setup.md explains it.
#   scripts/upgrade.sh <directory holding the new binaries>
#   scripts/upgrade.sh --recover      finishes whatever a killed upgrade or a reboot left
# Exit status 3 means something could not be put back: fix what it reported, and --recover again.
set -eu
maintenance=$(cd "$(dirname "$0")" && pwd)/kilnd-maintenance.py
root=
[ "$(id -u)" -eq 0 ] || root=sudo
case ${1:-} in
    --recover) shift; exec $root python3 -I "$maintenance" recover "$@" ;;
    '' | -*) echo "usage: $0 <directory holding the new binaries> | --recover" >&2; exit 2 ;;
esac
exec $root python3 -I "$maintenance" upgrade --bin-dir "$1"
