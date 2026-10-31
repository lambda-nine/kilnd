#!/bin/sh
# Privileged state-path regression. Run inside kiln's VM after installing this
# checkout. Every rejected fixture must fail before socket bind or kiln spawn.
set -eu

scratch=$(mktemp -d /tmp/kilnd-state-path.XXXXXX)
fixture=$scratch.root
case "$scratch" in
    /tmp/kilnd-state-path.*) ;;
    *) echo "unexpected temporary path: $scratch" >&2; exit 1 ;;
esac
sudo install -d -o kilnd -g kilnd -m 700 "$fixture"
marker=$scratch/backend-called
fake=$scratch/fake-kiln
pivot=/tmp/kilnd-state-pivot.$$
case "$pivot" in
    /tmp/kilnd-state-pivot.*) ;;
    *) echo "unexpected pivot path: $pivot" >&2; exit 1 ;;
esac
[ ! -e "$pivot" ] && [ ! -L "$pivot" ] || { echo "pivot path already exists: $pivot" >&2; exit 1; }
printf '#!/bin/sh\ntouch %s\nexit 1\n' "$marker" >"$fake"
chmod 700 "$fake"

fail() { echo "FAIL: $*" >&2; exit 1; }
owned_mkdir() { mode=$1; shift; sudo install -d -o kilnd -g kilnd -m "$mode" "$@"; }
owned_touch() { sudo touch "$@"; sudo chown kilnd:kilnd "$@"; }
cleanup() {
    rm -f "$pivot" >/dev/null 2>&1 || true
    sudo find "$fixture" -depth -delete >/dev/null 2>&1 || true
    sudo find "$scratch" -depth -delete >/dev/null 2>&1 || true
}

run_separation_rejected() {
    name=$1
    state=$2
    socket=$3
    log=$scratch/$name.log
    sudo rm -f "$marker"
    set +e
    sudo -u kilnd timeout 5 /usr/local/bin/kilnd \
        --state-dir "$state" \
        --socket "$socket" \
        --socket-group kilnd \
        --helper-socket "$fake" >"$log" 2>&1
    rc=$?
    set -e
    [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ] || fail "$name did not fail promptly"
    grep -q 'socket directory and --state-dir must be different' "$log" \
        || fail "$name gave the wrong diagnostic: $(cat "$log")"
    [ "$(sudo stat -c '%a' "$state")" = 700 ] || fail "$name widened state permissions"
    [ ! -e "$socket" ] || fail "$name bound a socket"
    [ ! -e "$marker" ] || fail "$name invoked the backend"
}
trap cleanup EXIT INT TERM

run_rejected() {
    name=$1
    state=$2
    diagnostic=$3
    socket_dir=$fixture/socket-$name
    log=$scratch/$name.log
    owned_mkdir 700 "$socket_dir"
    sudo rm -f "$marker"
    set +e
    sudo -u kilnd timeout 5 /usr/local/bin/kilnd \
        --state-dir "$state" \
        --socket "$socket_dir/kilnd.sock" \
        --socket-group '' \
        --helper-socket "$fake" >"$log" 2>&1
    rc=$?
    set -e
    [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ] || fail "$name did not fail promptly"
    grep -q "$diagnostic" "$log" || fail "$name gave the wrong diagnostic: $(cat "$log")"
    [ ! -e "$socket_dir/kilnd.sock" ] || fail "$name bound a socket"
    [ ! -e "$marker" ] || fail "$name invoked the backend"
}

echo "1. An attacker-owned 0700 ancestor is rejected"
owned_mkdir 700 "$fixture/attacker"
sudo chown "$(id -u):$(id -g)" "$fixture/attacker"
owned_mkdir 700 "$fixture/attacker/state"
run_rejected ancestor "$fixture/attacker/state" 'state path ancestor.*must be owned\|Permission denied'
[ ! -e "$fixture/attacker/state/kilnd.db" ] || fail "ancestor case created a database"

echo "2. Every nested symlink hop must be trusted"
owned_mkdir 700 "$fixture/safe-parent" "$fixture/safe-parent/state"
ln -s "$fixture/safe-parent" "$pivot"
sudo ln -s "$pivot" "$fixture/trusted-alias"
run_rejected nested-symlink "$fixture/trusted-alias/state" 'state path symlink.*must be owned'
[ ! -e "$fixture/safe-parent/state/kilnd.db" ] || fail "nested symlink case created a database"

echo "3. A service-owned 0755 final directory is rejected"
owned_mkdir 755 "$fixture/mode-state"
run_rejected mode "$fixture/mode-state" 'must have mode 0700'
[ ! -e "$fixture/mode-state/kilnd.db" ] || fail "mode case created a database"

echo "4. Main database and sidecar symlinks are rejected"
owned_mkdir 700 "$fixture/symlink-state"
owned_touch "$fixture/forged.db"
sudo chmod 600 "$fixture/forged.db"
sudo ln -s "$fixture/forged.db" "$fixture/symlink-state/kilnd.db"
run_rejected symlink "$fixture/symlink-state" 'kilnd.db.*without following symlinks'
[ "$(sudo sqlite3 "$fixture/forged.db" 'PRAGMA user_version;')" -eq 0 ] \
    || fail "database symlink target was modified"

owned_mkdir 700 "$fixture/sidecar-state"
owned_touch "$fixture/sidecar-state/kilnd.db" "$fixture/forged-wal"
sudo chmod 600 "$fixture/sidecar-state/kilnd.db" "$fixture/forged-wal"
sudo ln -s "$fixture/forged-wal" "$fixture/sidecar-state/kilnd.db-wal"
run_rejected sidecar "$fixture/sidecar-state" 'kilnd.db-wal.*without following symlinks'

echo "5. Foreign, broad-mode, non-regular, and hard-linked databases are rejected"
owned_mkdir 700 "$fixture/foreign-state"
# This deliberately untrusted database must be refused before opening or
# migrating its rows. Use an independent synthetic schema, so the fixture never
# copies a live WAL database or depends on the installed schema revision.
sudo sqlite3 "$fixture/foreign-state/kilnd.db" \
    "CREATE TABLE sandboxes (id TEXT PRIMARY KEY,backend TEXT,backend_id TEXT,state TEXT,spec TEXT,created_at_ms INTEGER,updated_at_ms INTEGER,list_seq INTEGER);
     INSERT INTO sandboxes VALUES ('sb-0000000000000000','kiln','forged-backend','deleting','{}',1,1,9223372036854775807);"
sudo chown "$(id -u):$(id -g)" "$fixture/foreign-state/kilnd.db"
sudo chmod 600 "$fixture/foreign-state/kilnd.db"
run_rejected foreign "$fixture/foreign-state" "kilnd.db must be owned by uid $(id -u kilnd)\|Permission denied"

owned_mkdir 700 "$fixture/public-state"
owned_touch "$fixture/public-state/kilnd.db"
sudo chmod 644 "$fixture/public-state/kilnd.db"
run_rejected public "$fixture/public-state" 'kilnd.db must have mode 0600'

owned_mkdir 700 "$fixture/directory-state" "$fixture/directory-state/kilnd.db"
run_rejected directory "$fixture/directory-state" 'kilnd.db must be a regular file'

owned_mkdir 700 "$fixture/hardlink-state"
owned_touch "$fixture/hardlink-target"
sudo chmod 600 "$fixture/hardlink-target"
sudo ln "$fixture/hardlink-target" "$fixture/hardlink-state/kilnd.db"
run_rejected hardlink "$fixture/hardlink-state" 'kilnd.db must have exactly one link'

echo "6. Socket path aliases cannot widen state-directory permissions"
owned_mkdir 700 "$fixture/separation-state"
run_separation_rejected dotdot-separation "$fixture/separation-state" \
    "$fixture/separation-state/../separation-state/kilnd.sock"
sudo ln -s "$fixture" "$fixture/separation-alias"
run_separation_rejected symlink-separation "$fixture/separation-state" \
    "$fixture/separation-alias/separation-state/kilnd.sock"

echo "7. systemd StateDirectory remains the trusted production path"
[ "$(systemctl is-active kilnd)" = active ] || fail "kilnd service is not active"
sudo kilndctl health >/dev/null || fail "kilnd health failed"
[ "$(sudo stat -c '%U:%G %a %F' /var/lib/kilnd)" = 'kilnd:kilnd 700 directory' ] \
    || fail "unexpected /var/lib/kilnd metadata"
[ "$(sudo stat -c '%U:%G %a %F %h' /var/lib/kilnd/kilnd.db)" = 'kilnd:kilnd 600 regular file 1' ] \
    || fail "unexpected kilnd.db metadata"
[ ! -L /var/lib/kilnd/kilnd.db ] || fail "kilnd.db is a symlink"

echo "PASS"
