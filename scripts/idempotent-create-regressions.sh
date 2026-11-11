#!/bin/bash
# Idempotent create under the installed daemon (API additions M2): a keyed create's
# retries return the same real kiln sandbox, a different request under the key is
# refused, records survive a daemon restart, release frees a key only from DELETED,
# and a daemon killed mid-create leaves a record every retry answers and none
# recreates. To kill kilnd exactly between the reservation commit and the backend
# create, the root helper is paused (SIGSTOP) for that step and always resumed. On
# legacy kiln that crashed create is an ambiguous FAILED, still charged (design 3.1);
# the run removes any kiln sandbox it orphaned, as an operator would. It restarts kilnd twice and takes about a minute. Run inside the VM as your
# user after scripts/install.sh:
#   scripts/idempotent-create-regressions.sh
set -euo pipefail

ctl() { sudo kilndctl "$@"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
small=(--memory 64M --disk 16M)
run=idem-$$-$(date +%s)
created=()
create_client=
helper_paused=
out=$(mktemp -d)
baseline_kiln=$(sudo kiln ls | awk 'NR > 1 { print $1 }' | sort)
resume_helper() {
    sudo systemctl kill --kill-whom=main --signal=SIGCONT kilnd-helper.service
    helper_paused=
}
cleanup() {
    if [ -n "$helper_paused" ]; then resume_helper || true; fi
    if [ -n "$create_client" ]; then
        kill "$create_client" 2>/dev/null || true
        wait "$create_client" 2>/dev/null || true
    fi
    # The background keyed create may have finished without its ID being recorded.
    if [ -n "${killed_key:-}" ]; then
        for s in $(sudo sqlite3 -readonly /var/lib/kilnd/kilnd.db \
            "SELECT sandbox_id FROM create_requests WHERE request_id GLOB '$run/*'" 2>/dev/null); do
            created+=("$s")
        done
    fi
    for s in "${created[@]}"; do ctl rm --release-request-id "$s" >/dev/null 2>&1 || true; done
    # A kiln sandbox the killed create left behind belongs to no row: an operator's.
    for b in $(comm -13 <(echo "$baseline_kiln") <(sudo kiln ls | awk 'NR > 1 { print $1 }' | sort)); do
        if ! ctl ls --all | awk '{ print $4 }' | grep -qx "$b"; then
            echo "removing kiln sandbox $b orphaned by the killed create"
            sudo kiln rm "$b" >/dev/null 2>&1 || true
        fi
    done
    rm -f "$out"/*
    rmdir "$out"
}
trap cleanup EXIT

wait_ready() {
    for _ in $(seq 100); do
        ctl health >/dev/null 2>&1 && return 0
        sleep 0.2
    done
    fail "kilnd did not come back"
}
restart_kilnd() {
    sudo systemctl reset-failed kilnd
    sudo systemctl restart kilnd
    wait_ready
}
# Runs in this shell, never in a command substitution, so EXIT cleanup sees the ID.
created_id=
create() {
    [ "$BASHPID" = "$$" ] || fail "create ran in a subshell; its ID would escape EXIT cleanup"
    created_id=
    ctl create "${small[@]}" "$@" >"$out/created"
    created_id=$(cat "$out/created")
    [ -n "$created_id" ] || fail "create printed no ID"
    case " ${created[*]} " in *" $created_id "*) ;; *) created+=("$created_id") ;; esac
}
state_of() { ctl get "$1" | awk '/^state:/ { print $2 }'; }
request_of() { ctl get "$1" | awk '/^request id:/ { print $3, $4 }'; }
kiln_count() { sudo kiln ls | awk 'NR > 1' | wc -l; }

wait_ready
echo "1. Health lists both request-ID features and the record counts"
health=$(ctl health)
grep -q '^features: .*idempotent_create' <<<"$health" || fail "no idempotent_create: $health"
grep -q '^features: .*request_id_release' <<<"$health" || fail "no request_id_release"
grep -q '^create requests: *node [0-9]*/32768, yours [0-9]*/4096' <<<"$health" \
    || fail "no create request counts: $health"

echo "2. A bad request ID is refused before anything is created"
before=$(kiln_count)
for bad in "has space" "$(printf 'x%.0s' $(seq 65))"; do
    if ctl create "${small[@]}" --request-id "$bad" >"$out/refused" 2>&1; then
        created+=("$(cat "$out/refused")")
        fail "create --request-id '$bad' succeeded"
    fi
    grep -q '^Error: invalidargument: \|invalidargument: ' "$out/refused" || fail "bad id: $(cat "$out/refused")"
done
[ "$(kiln_count)" = "$before" ] || fail "a refused create reached the backend"

echo "3. Retries return the same sandbox; a different request is refused"
key=$run/a
create --request-id "$key" --label run="$run"
first=$created_id
[ "$(state_of "$first")" = ready ] || fail "keyed create is $(state_of "$first")"
[ "$(request_of "$first")" = "$key " ] || fail "request id shown as '$(request_of "$first")'"
before=$(kiln_count)
for _ in 1 2 3; do
    create --request-id "$key" --label run="$run"
    [ "$created_id" = "$first" ] || fail "a retry created $created_id"
done
[ "$(kiln_count)" = "$before" ] || fail "a retry reached the backend"
if ctl create "${small[@]}" --request-id "$key" --label run=other >"$out/refused" 2>&1; then
    fail "a conflicting create succeeded"
fi
grep -q 'alreadyexists: request_id_conflict: ' "$out/refused" || fail "untyped conflict: $(cat "$out/refused")"
# Without --request-id nothing changes: every create is a new sandbox.
create --label run="$run"
plain1=$created_id
create --label run="$run"
[ "$created_id" != "$plain1" ] || fail "an unkeyed create was deduplicated"
ctl get "$plain1" | grep -q '^request id:' && fail "an unkeyed sandbox shows a request id"

echo "4. A daemon restart keeps the record"
restart_kilnd
create --request-id "$key" --label run="$run"
[ "$created_id" = "$first" ] || fail "after restart a retry created $created_id"

echo "5. Release frees the key only once the sandbox is DELETED"
ctl rm --release-request-id "$first" >/dev/null
[ "$(state_of "$first")" = deleted ] || fail "released sandbox is $(state_of "$first")"
[ "$(request_of "$first")" = "$key (released)" ] || fail "release not shown: '$(request_of "$first")'"
create --request-id "$key" --label run="$run"
second=$created_id
[ "$second" != "$first" ] || fail "a released key returned the old sandbox"
# Delete without the flag keeps the record: a retry returns the DELETED row.
ctl rm "$second" >/dev/null
create --request-id "$key" --label run="$run"
[ "$created_id" = "$second" ] || fail "a retry after delete created $created_id"
[ "$(state_of "$second")" = deleted ] || fail "the retried row is $(state_of "$second")"
# A repeated release is a no-op that still reads as released.
ctl rm --release-request-id "$second" >/dev/null
ctl rm --release-request-id "$second" >/dev/null
[ "$(request_of "$second")" = "$key (released)" ] || fail "repeat release: '$(request_of "$second")'"

echo "6. A daemon killed mid-create leaves a record that every retry answers"
killed_key=$run/killed
# kilndctl's feature check reads Health, which probes the helper: warm its 5 s cache.
ctl health >/dev/null
helper_paused=1
sudo systemctl kill --kill-whom=main --signal=SIGSTOP kilnd-helper.service
sudo -n kilndctl create "${small[@]}" --request-id "$killed_key" >"$out/killed.out" 2>"$out/killed.err" &
create_client=$!
creating=
for _ in $(seq 100); do
    creating=$(ctl ls | awk '$2 == "creating" { print $1; exit }')
    [ -n "$creating" ] && break
    sleep 0.05
done
[ -n "$creating" ] || fail "never saw the create's CREATING row: $(cat "$out/killed.err")"
created+=("$creating")
# The row and its record are committed; the backend create waits on the paused helper.
sudo systemctl kill --signal=KILL kilnd
resume_helper
wait "$create_client" && fail "the killed create's client succeeded" || true
create_client=
restart_kilnd
before=$(kiln_count)
create --request-id "$killed_key"
[ "$created_id" = "$creating" ] || fail "the retry after the kill created $created_id, not $creating"
state=$(state_of "$creating")
case "$state" in
    failed | ready) ;;
    *) fail "the killed create settled $state" ;;
esac
echo "   settled $state (legacy kiln: an ambiguous FAILED stays charged)"
create --request-id "$killed_key"
[ "$created_id" = "$creating" ] || fail "a second retry created $created_id"
[ "$(kiln_count)" = "$before" ] || fail "a retry of the killed create reached the backend"
if [ "$state" = failed ]; then
    # Delete refuses the ambiguous reservation, exactly as for an unkeyed create.
    if ctl rm "$creating" >"$out/refused" 2>&1; then fail "deleted an ambiguous reservation"; fi
fi
health=$(ctl health)
grep -q 'retries answered' <<<"$health" || fail "no retry stats: $health"
echo "PASS"
