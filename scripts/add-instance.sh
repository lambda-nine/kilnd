#!/bin/sh
# Adds one more kilnd instance on this node, under its own Unix account and group.
# Needs scripts/install.sh and a provisioned Firecracker node policy (docs/setup.md).
# It stops the helper briefly, because enrollment takes the node lock:
#   scripts/add-instance.sh <name> <32 hex digit instance ID>
set -eu
cd "$(dirname "$0")/.."
[ "$#" -eq 2 ] || { echo "usage: $0 <name> <instance ID>" >&2; exit 2; }
name=$1
instance=$2
case $name in
    '' | *[!a-z0-9]*) echo "the name must be lowercase letters and digits" >&2; exit 2 ;;
esac
[ "${#name}" -le 16 ] || { echo "the name must be at most 16 characters" >&2; exit 2; }
getent group kilnd-helper >/dev/null || { echo "run scripts/install.sh first" >&2; exit 1; }
user=kilnd-$name
unit=kilnd@$name.service
getent group "$user" >/dev/null || sudo groupadd --system "$user"
getent passwd "$user" >/dev/null ||
    sudo useradd --system --gid "$user" --home-dir /nonexistent --shell /usr/sbin/nologin "$user"
sudo usermod -a -G kilnd-helper "$user"
sudo install -m 644 deploy/kilnd@.service /etc/systemd/system/kilnd@.service
sudo systemctl daemon-reload
sudo systemctl stop kilnd-helper.service
# Whatever enrollment answers, the helper comes back for the instances it already serves.
status=0
# A template instance's cgroup sits in the slice systemd makes for that template.
sudo kilnd-helper enroll --instance "$instance" --unit "$unit" --user "$user" \
    --cgroup "/system.slice/system-kilnd.slice/$unit" || status=$?
sudo systemctl start kilnd-helper.service
[ "$status" -eq 0 ] || exit "$status"
sudo systemctl enable --now "$unit"
systemctl --no-pager --lines=5 status "$unit"
