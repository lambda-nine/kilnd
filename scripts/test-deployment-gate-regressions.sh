#!/bin/sh
# B6-BI-01's regressions: the isolated Firecracker test deployment is selected only by a
# kilnd built with the non-default `firecracker-test-deployment` feature, and only when
# the deployment's account, socket group and systemd unit are what the process observably
# is. The break-it PoC (reviews/poc-b6/test-deployment-identity-gate.sh) selected
# Firecracker from an ordinary release binary with all three wrong.
#
#   scripts/test-deployment-gate-regressions.sh release BINARY
#       A default-feature build (cargo build --release) refuses --backend firecracker
#       and --firecracker-test-deployment at argument parsing, the PoC's whole command
#       included, and touches no state. Unprivileged; any OS. CI runs it.
#   scripts/test-deployment-gate-regressions.sh feature BINARY
#       A feature build refuses the PoC's mismatched identity, with names that do not
#       exist and with names that do, and touches no state. Unprivileged, on Linux. CI
#       runs it.
#   sudo scripts/test-deployment-gate-regressions.sh root BINARY
#       A feature build as a real test account in a real transient unit: with everything
#       matching it selects the deployment (the control); a wrong account, a wrong socket
#       group, a wrong unit, the right unit under another slice (B6-RC-02, B7) and no
#       unit at all are each refused on their own, before any state is opened. Root, in
#       the kiln VM. It creates the account and group kilnd-fcgate, the units
#       kilnd-fcgate.service and kilnd-fcgate-other.service and the slice b7gate.slice,
#       and removes them on exit.
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 release|feature|root BINARY" >&2
    exit 2
fi
mode=$1
binary=$2
[ -x "$binary" ] || { echo "not an executable: $binary" >&2; exit 2; }

failures=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }
SERVING="serving the isolated Firecracker test deployment"

# manifest FILE ROOT ACCOUNT GROUP UNIT: the unit's cgroup is /system.slice/UNIT.
manifest() {
    cat >"$1" <<EOF
{
  "schema": "kilnd-firecracker-test-deployment/2",
  "deployment": "isolated-test",
  "profile": "offline-768-v1",
  "kilnd": {
    "socket": "$2/socket/kilnd.sock",
    "socket_group": "$4",
    "state_dir": "$2/state-parent/state",
    "account": "$3",
    "unit": "$5",
    "cgroup": "/system.slice/$5"
  },
  "helper": {
    "root": "$2/helper",
    "socket": "$2/helper/helper.sock"
  }
}
EOF
}

# expect_refused NAME LOG STATUS ROOT NEEDLE [ABSENT...]: refused, with NEEDLE in the log,
# none of ABSENT, no Firecracker selection and no state directory.
expect_refused() {
    name=$1 log=$2 status=$3 root=$4 needle=$5
    shift 5
    ok=1
    [ "$status" -ne 0 ] || { fail "$name: exited 0"; ok=0; }
    if grep -q "$SERVING" "$log"; then fail "$name: selected Firecracker"; ok=0; fi
    if ! grep -q -- "$needle" "$log"; then fail "$name: no \"$needle\" in the refusal"; ok=0; fi
    for absent in "$@"; do
        if grep -q -- "$absent" "$log"; then fail "$name: also refused for \"$absent\""; ok=0; fi
    done
    if [ -e "$root/state-parent/state" ]; then fail "$name: state was opened"; ok=0; fi
    if [ "$ok" -eq 1 ]; then
        pass "$name"
        sed -n '1,4p' "$log" | sed 's/^/    /'
    else
        sed -n '1,40p' "$log" >&2
    fi
}

case $mode in
release)
    run=$(mktemp -d "${TMPDIR:-/tmp}/kilnd-gate.XXXXXX")
    trap 'rm -rf -- "$run"' EXIT HUP INT TERM
    mkdir -m 700 "$run/socket" "$run/helper" "$run/state-parent"
    manifest "$run/deployment.json" "$run" kilnd-fctest-manifest-only \
        kilnd-fctest-manifest-only kilnd-fctest-manifest-only.service
    group=$(id -gn)
    # The break-it PoC command, verbatim but for its paths.
    status=0
    "$binary" --backend firecracker --firecracker-test-deployment "$run/deployment.json" \
        --socket "$run/socket/kilnd.sock" --socket-group "$group" \
        --state-dir "$run/state-parent/state" --helper-socket "$run/helper/helper.sock" \
        >"$run/poc.log" 2>&1 || status=$?
    expect_refused "release build refuses the PoC command" "$run/poc.log" "$status" "$run" \
        "unexpected argument '--firecracker-test-deployment'"
    [ "$status" -eq 2 ] || fail "the PoC command exited $status, not clap's usage error 2"
    status=0
    "$binary" --firecracker-test-deployment "$run/deployment.json" \
        --state-dir "$run/state-parent/state" >"$run/file.log" 2>&1 || status=$?
    expect_refused "release build has no --firecracker-test-deployment" "$run/file.log" \
        "$status" "$run" "unexpected argument '--firecracker-test-deployment'"
    [ "$status" -eq 2 ] || fail "--firecracker-test-deployment exited $status, not 2"
    status=0
    "$binary" --backend firecracker --state-dir "$run/state-parent/state" \
        >"$run/backend.log" 2>&1 || status=$?
    expect_refused "release build has no --backend firecracker" "$run/backend.log" \
        "$status" "$run" "invalid value 'firecracker'"
    "$binary" --help >"$run/help.txt"
    if grep -q -- "--firecracker-test-deployment <" "$run/help.txt" \
        || ! grep -q "\[possible values: kiln\]" "$run/help.txt"; then
        fail "release build's --help offers a Firecracker flag or backend value"
    else
        pass "release build's --help offers no Firecracker flag, and kiln as the only backend"
    fi
    ;;
feature)
    run=$(mktemp -d "${TMPDIR:-/tmp}/kilnd-gate.XXXXXX")
    trap 'rm -rf -- "$run"' EXIT HUP INT TERM
    mkdir -m 700 "$run/socket" "$run/helper" "$run/state-parent"
    group=$(id -gn)
    # The break-it PoC: names that exist nowhere. Refused when they do not resolve.
    manifest "$run/poc.json" "$run" kilnd-fctest-manifest-only \
        kilnd-fctest-manifest-only kilnd-fctest-manifest-only.service
    status=0
    "$binary" --backend firecracker --firecracker-test-deployment "$run/poc.json" \
        --socket "$run/socket/kilnd.sock" --socket-group "$group" \
        --state-dir "$run/state-parent/state" --helper-socket "$run/helper/helper.sock" \
        >"$run/poc.log" 2>&1 || status=$?
    expect_refused "feature build refuses the PoC's unresolvable identity" "$run/poc.log" \
        "$status" "$run" "account \"kilnd-fctest-manifest-only\" does not exist"
    # The same three mismatches with names that resolve (nobody, nogroup), so the
    # comparison itself refuses, naming all three.
    other_group=nogroup
    getent group nogroup >/dev/null 2>&1 || other_group=nobody
    manifest "$run/resolved.json" "$run" nobody "$other_group" kilnd-fcgate-manifest-only.service
    status=0
    "$binary" --backend firecracker --firecracker-test-deployment "$run/resolved.json" \
        --socket "$run/socket/kilnd.sock" --socket-group "$group" \
        --state-dir "$run/state-parent/state" --helper-socket "$run/helper/helper.sock" \
        >"$run/resolved.log" 2>&1 || status=$?
    expect_refused "feature build refuses all three observed mismatches" "$run/resolved.log" \
        "$status" "$run" "not account \"nobody\""
    for needle in "--socket-group resolves to GID" "not in unit \"kilnd-fcgate-manifest-only.service\""; do
        grep -q -- "$needle" "$run/resolved.log" || fail "the refusal does not name: $needle"
    done
    ;;
root)
    [ "$(id -u)" -eq 0 ] || { echo "root mode runs as root" >&2; exit 2; }
    account=kilnd-fcgate
    unit=$account.service
    other_unit=$account-other.service
    other_slice=b7gate.slice
    run=$(mktemp -d /var/tmp/kilnd-fcgate.XXXXXX)
    created=0
    cleanup() {
        for u in "$unit" "$other_unit" "$other_slice"; do
            systemctl stop "$u" >/dev/null 2>&1 || true
            systemctl reset-failed "$u" >/dev/null 2>&1 || true
        done
        rm -rf -- "$run"
        if [ "$created" -eq 1 ]; then
            userdel "$account" >/dev/null 2>&1 || true
            groupdel "$account" >/dev/null 2>&1 || true
        fi
    }
    trap cleanup EXIT HUP INT TERM
    if id "$account" >/dev/null 2>&1; then
        echo "account $account exists: remove it first" >&2
        exit 1
    fi
    useradd --system --user-group --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin "$account"
    created=1
    chmod 0755 "$run"
    install -m 0755 -o root -g root "$binary" "$run/kilnd"
    other_group=nogroup
    getent group nogroup >/dev/null 2>&1 || other_group=nobody

    # case NAME UNIT ACCOUNT-IN-FILE GROUP-ON-CLI [systemd|setpriv] [SLICE]: a fresh root
    # and file, then the daemon as $account, in UNIT (under SLICE, default system.slice)
    # or outside any unit.
    attempt() {
        name=$1 in_unit=$2 file_account=$3 cli_group=$4 how=$5 slice=${6:-system.slice}
        root=$run/$name
        mkdir -m 0755 "$root"
        install -d -m 0700 -o "$account" -g "$account" "$root/socket" "$root/state-parent" "$root/helper"
        manifest "$root/deployment.json" "$root" "$file_account" "$account" "$unit"
        chmod 0444 "$root/deployment.json"
        set -- "$run/kilnd" --backend firecracker --firecracker-test-deployment "$root/deployment.json" \
            --socket "$root/socket/kilnd.sock" --socket-group "$cli_group" \
            --state-dir "$root/state-parent/state" --helper-socket "$root/helper/helper.sock"
        status=0
        if [ "$how" = systemd ]; then
            systemctl reset-failed "$in_unit" >/dev/null 2>&1 || true
            timeout 60 systemd-run --quiet --wait --pipe --collect --unit "$in_unit" \
                --slice "$slice" \
                --property=User="$account" --property=Group="$account" -- "$@" \
                >"$root/kilnd.log" 2>&1 </dev/null || status=$?
        else
            timeout 60 setpriv --reuid "$account" --regid "$account" --clear-groups -- "$@" \
                >"$root/kilnd.log" 2>&1 </dev/null || status=$?
        fi
    }

    # The control: everything matches, so the deployment is selected (the daemon then
    # stops at startup reconciliation: there is no helper at this socket).
    attempt control "$unit" "$account" "$account" systemd
    if grep -q "$SERVING" "$run/control/kilnd.log" && [ -e "$run/control/state-parent/state" ]; then
        pass "control: the matching account, group and unit select the deployment"
        grep "$SERVING" "$run/control/kilnd.log" | sed 's/^/    /'
    else
        fail "control: the matching identity was not selected"
        sed -n '1,40p' "$run/control/kilnd.log" >&2
    fi

    attempt account "$unit" nobody "$account" systemd
    expect_refused "a wrong account alone is refused" "$run/account/kilnd.log" "$status" \
        "$run/account" "not account \"nobody\"" "--socket-group" "not in unit"

    # The file names the right group; the CLI passes another.
    attempt group "$unit" "$account" "$other_group" systemd
    expect_refused "a wrong --socket-group alone is refused" "$run/group/kilnd.log" "$status" \
        "$run/group" "--socket-group resolves to GID" "UIDs" "not in unit"

    attempt unit "$other_unit" "$account" "$account" systemd
    expect_refused "a wrong unit alone is refused" "$run/unit/kilnd.log" "$status" \
        "$run/unit" "not in unit \"$unit\"" "UIDs" "--socket-group"

    # B6-RC-02: the right unit name, but under another slice, so not the enrolled cgroup.
    attempt slice "$unit" "$account" "$account" systemd "$other_slice"
    expect_refused "the right unit under another slice is refused" "$run/slice/kilnd.log" \
        "$status" "$run/slice" "runs in cgroup /$other_slice/$unit, not in unit \"$unit\"" \
        "UIDs" "--socket-group"

    attempt nounit - "$account" "$account" setpriv
    expect_refused "the right account outside any unit is refused" "$run/nounit/kilnd.log" \
        "$status" "$run/nounit" "not in unit \"$unit\"" "UIDs" "--socket-group"
    ;;
*)
    echo "usage: $0 release|feature|root BINARY" >&2
    exit 2
    ;;
esac

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed" >&2
    exit 1
fi
echo "all $mode checks passed"
