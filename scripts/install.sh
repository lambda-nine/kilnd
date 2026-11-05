#!/bin/sh
# Builds kilnd and kilndctl, installs them in /usr/local/bin, creates the
# kilnd group (allowed to use the API socket) and the kilnd-helper group (allowed to
# reach the helper socket, whose own check is the peer's UID), and starts the kilnd
# service. A node with a Firecracker policy or further instances upgrades as one
# transaction (scripts/upgrade.sh). Further instances: scripts/add-instance.sh.
# Needs kiln installed first (kiln's scripts/install.sh). Run inside the VM
# as your user:
#   scripts/install.sh
set -eu
cd "$(dirname "$0")/.."
target=${CARGO_TARGET_DIR:-target}

[ -x /usr/local/bin/kiln ] || { echo "install kiln first: kiln/scripts/install.sh" >&2; exit 1; }
scripts/build.sh default build --release
getent group kilnd >/dev/null || sudo groupadd --system kilnd
getent passwd kilnd >/dev/null || sudo useradd --system --gid kilnd --home-dir /nonexistent --shell /usr/sbin/nologin kilnd
getent group kilnd-helper >/dev/null || sudo groupadd --system kilnd-helper
sudo usermod -a -G kilnd-helper kilnd
status=0
sudo python3 -I scripts/kilnd-maintenance.py needs-transaction || status=$?
case $status in
    0)
        # Enrollment names the image, so replacing it has to be one step with every enrolled
        # instance. The default instance is enrolled here too if it isn't yet.
        sudo python3 -I scripts/kilnd-maintenance.py upgrade --bin-dir "$target/release" --enroll-default
        systemctl --no-pager --lines=5 status kilnd || true
        exit 0
        ;;
    1) ;;
    *) exit "$status" ;;
esac
# Stop the old daemon before transferring its private state. No live SQLite
# files or ownership locks are moved under a running process.
sudo systemctl stop kilnd.service 2>/dev/null || true
sudo systemctl stop kilnd-helper.service 2>/dev/null || true
# Picks up the socket's group, for an install older than the kilnd-helper group.
sudo systemctl stop kilnd-helper.socket 2>/dev/null || true
sudo install -m 755 "$target/release/kilnd-helper" /usr/local/bin/kilnd-helper
sudo install -m 755 "$target/release/kilnd" /usr/local/bin/kilnd
sudo install -m 755 "$target/release/kilndctl" /usr/local/bin/kilndctl
# Refuse links/nonregular or broadly writable state before migration. chown
# never follows symlinks and only known state entries are transferred.
if sudo test -d /var/lib/kilnd; then
    sudo python3 -I - <<'PYTHON'
import os, pwd, stat
root = '/var/lib/kilnd'
uid = pwd.getpwnam('kilnd').pw_uid
gid = pwd.getpwnam('kilnd').pw_gid
metadata = os.lstat(root)
assert stat.S_ISDIR(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o700 and metadata.st_uid in (0, uid), 'unsafe kilnd state directory'
for name in os.listdir(root):
    assert name in ('kilnd.db', 'kilnd.db-wal', 'kilnd.db-shm', 'kilnd.db-journal', 'kilnd.lock'), 'unexpected state entry: ' + name
    path = os.path.join(root, name)
    m = os.lstat(path)
    assert stat.S_ISREG(m.st_mode) and m.st_nlink == 1 and stat.S_IMODE(m.st_mode) == 0o600 and m.st_uid in (0, uid), 'unsafe state entry: ' + name
for name in os.listdir(root):
    os.chown(os.path.join(root, name), uid, gid, follow_symlinks=False)
os.chown(root, uid, gid, follow_symlinks=False)
# The ownership transfer above supports the legacy root daemon. Installation
# must finish with the same private boundary that Store::open requires.
m = os.lstat(root)
assert m.st_uid == uid and stat.S_IMODE(m.st_mode) == 0o700, 'state directory must be kilnd-owned 0700'
for name in os.listdir(root):
    m = os.lstat(os.path.join(root, name))
    assert m.st_uid == uid and stat.S_ISREG(m.st_mode) and m.st_nlink == 1 and stat.S_IMODE(m.st_mode) == 0o600, 'state file must be kilnd-owned 0600: ' + name
PYTHON
fi
# Old API runtime directory is root-owned. It contains only the endpoint and
# the persistent socket lock; transfer both after stopping its owner.
if sudo test -d /run/kilnd; then
    sudo python3 -I - <<'PYTHON'
import os, pwd, stat
root = '/run/kilnd'
uid = pwd.getpwnam('kilnd').pw_uid
gid = pwd.getpwnam('kilnd').pw_gid
m = os.lstat(root)
assert stat.S_ISDIR(m.st_mode) and m.st_uid in (0, uid) and not m.st_mode & 0o022, 'unsafe runtime directory'
for name in os.listdir(root):
    path = os.path.join(root, name)
    m = os.lstat(path)
    assert m.st_uid in (0, uid), 'foreign runtime entry'
    assert (name == 'kilnd.sock' and stat.S_ISSOCK(m.st_mode)) or (name == '.kilnd.socket.lock' and stat.S_ISREG(m.st_mode) and m.st_nlink == 1 and stat.S_IMODE(m.st_mode) == 0o600), 'unexpected runtime entry'
    os.chown(path, uid, gid, follow_symlinks=False)
os.chown(root, uid, gid, follow_symlinks=False)
PYTHON
fi
# Also creates the Firecracker ledger's private parents. No node policy or ledger is
# installed, so that group stays disabled; see docs/setup.md before configuring one.
sudo install -m 644 deploy/kilnd-helper.conf /etc/tmpfiles.d/kilnd-helper.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/kilnd-helper.conf
sudo install -m 644 deploy/kilnd-helper.socket /etc/systemd/system/kilnd-helper.socket
sudo install -m 644 deploy/kilnd-helper.service /etc/systemd/system/kilnd-helper.service
sudo install -m 644 deploy/kilnd.service /etc/systemd/system/kilnd.service
sudo install -m 644 deploy/kilnd@.service /etc/systemd/system/kilnd@.service
# Every unit above requires the boot guard.
sudo python3 -I scripts/kilnd-maintenance.py install-fence
sudo systemctl daemon-reload
sudo systemctl enable --now kilnd-helper.socket
sudo systemctl enable --now kilnd-helper.service
# The same first step every instance takes: its private state and its durable ID exist
# before its unit starts. Nothing is enrolled here until a node policy is installed.
echo "default instance: $(sudo kilnd init-state --state-dir /var/lib/kilnd --account kilnd)"
sudo systemctl enable kilnd
sudo systemctl restart kilnd
systemctl --no-pager --lines=5 status kilnd
