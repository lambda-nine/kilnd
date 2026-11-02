#!/bin/sh
# B4 recheck finding 3, as a check: a jailer replaced after its private pre-publish hash
# must fail the build, and no wrong jailer may be left published. (Was the break-it PoC
# reviews/poc-b4-recheck/build-output-swap.sh, which demonstrated an exit-zero build.)
#
# A sha256sum wrapper on PATH is the deterministic synchronization: it runs the real hash
# over the staged jailer, then replaces that file with /bin/true before the script
# publishes it. The actor runs as the build UID, which the script documents as trusted;
# the post-publish comparison still refuses what it published.
#
# Run as the normal user in the aarch64 kiln VM; it performs a full jailer build in a
# temporary directory, removed afterwards:
#   scripts/build-phase1b-tools-swap-check.sh
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
scratch=$(mktemp -d /tmp/b4-build-swap.XXXXXX)
trap 'rm -rf "$scratch"' EXIT INT TERM

out=$scratch/out
wrapper_dir=$scratch/bin
replacement=$scratch/replacement
real_sha=$(command -v sha256sum)
mkdir -p "$wrapper_dir"
cp /bin/true "$replacement"

cat >"$wrapper_dir/sha256sum" <<'EOF'
#!/bin/sh
set -eu
case "$#:${1:-}" in
    1:*/b4-tools.*/stage/jailer)
        "$POC_REAL_SHA" "$@"
        cp "$POC_REPLACEMENT" "$1"
        echo "swap-check: replaced $1 after its hash" >&2
        exit 0
        ;;
esac
exec "$POC_REAL_SHA" "$@"
EOF
chmod 0755 "$wrapper_dir/sha256sum"

status=0
POC_REAL_SHA=$real_sha \
POC_REPLACEMENT=$replacement \
PATH="$wrapper_dir:$PATH" \
    "$repo/scripts/build-phase1b-tools.sh" --out "$out" >"$scratch/build.log" 2>&1 || status=$?

tail -n 3 "$scratch/build.log"
grep -q "swap-check: replaced" "$scratch/build.log" || {
    echo "FAILED: the swap never happened; the check proved nothing" >&2
    exit 1
}
[ "$status" -ne 0 ] || {
    echo "FAILED: the build exited 0 after its staged jailer was replaced" >&2
    exit 1
}
if [ -e "$out/jailer" ]; then
    echo "FAILED: a jailer is still published: $($real_sha "$out/jailer")" >&2
    exit 1
fi
grep -q "published jailer SHA-256 is .*; removed it" "$scratch/build.log" || {
    echo "FAILED: the build did not fail at the post-publish gate" >&2
    exit 1
}
echo "PASS: the replaced jailer failed the build (exit $status) at the post-publish gate and was removed"
