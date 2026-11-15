#!/bin/sh
# C6a recheck 1 HIGH 5 and 6: scripts/build.sh's closed Cargo configuration. Every case is
# refused before cargo runs, so this is offline and quick:
#
#   scripts/build-config-regressions.sh [TOOLCHAIN]
#
# In a disposable copy of HEAD, build.sh refuses:
#  a. the recheck's PoC: a workspace `.cargo/config.toml` whose `cfg(unix)` runner skips a
#     ledger test on ordinary runs but passes `--list` through, and whose `[env]` forces
#     CI empty and KILND_BLESS_CHECKPOINT_CONTRACT=1; the wire golden stays unchanged;
#  b. a workspace `.cargo/config` and a parent directory's `.cargo/config.toml`;
#  c. a $CARGO_HOME config with `[env]`, a target runner or linker, or a build key build.sh
#     does not override (`build.jobs`);
#  d. CARGO_TARGET_<host>_RUNNER, CARGO_TARGET_<host>_LINKER, CARGO_BUILD_JOBS and
#     CARGO_ENV_CI set, even empty, and KILND_BLESS_CHECKPOINT_CONTRACT set to 1 or empty.
# dependency-gate-regressions.sh runs it for each toolchain.
set -eu
toolchain=${1:-}
repo=$(git -C "$(dirname -- "$0")" rev-parse --show-toplevel)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/kilnd-build-config.XXXXXX")
trap 'rm -rf "$scratch"' EXIT HUP INT TERM
failed=0
fail() {
    echo "FAIL: $*" >&2
    failed=1
}
copy=$scratch/parent/repo
mkdir -p "$copy"
git -C "$repo" archive HEAD | tar -x -C "$copy"
cd "$copy"
host=$(rustc ${toolchain:+"+$toolchain"} -vV | sed -n 's/^host: //p')
host_var=$(printf '%s' "$host" | tr 'a-z-' 'A-Z_')
build() {
    sh scripts/build.sh ${toolchain:+"+$toolchain"} "$@"
}
refused() { # what message command...
    what=$1 message=$2
    shift 2
    if "$@" >"$scratch/build.log" 2>&1; then
        cat "$scratch/build.log" >&2
        fail "build.sh ran cargo with $what"
    elif grep -qF -- "scripts/build.sh: refused: $message" "$scratch/build.log"; then
        echo "build.sh refuses: $what"
    else
        cat "$scratch/build.log" >&2
        fail "build.sh failed for another reason with $what"
    fi
}
golden=crates/kilnd/tests/data/checkpoint-wire.json
before=$(cksum <"$golden")
here=$(pwd -P)

# a. The recheck's PoC.
mkdir .cargo
cat >.cargo/config.toml <<'CONFIG'
[target.'cfg(unix)']
runner = "./poc-runner.sh"

[env]
KILND_BLESS_CHECKPOINT_CONTRACT = "1"
CI = { value = "", force = true }
CONFIG
cat >poc-runner.sh <<'RUNNER'
#!/bin/sh
case " $* " in
    *" --list "*) exec "$@" ;;
esac
exec "$@" --skip manager::checkpoint::tests::crash_after_c1_before_the_helper_settles_failed_with_no_recapture
RUNNER
chmod +x poc-runner.sh
refused "the recheck's runner and [env] PoC" "$here/.cargo/config.toml is a Cargo configuration file" \
    env CI=true sh scripts/build.sh ${toolchain:+"+$toolchain"} default test
[ "$(cksum <"$golden")" = "$before" ] || fail "the wire golden changed"

# b. Other spellings and places.
mv .cargo/config.toml .cargo/config
refused "a workspace .cargo/config" "$here/.cargo/config is a Cargo configuration file" build default check
rm -r .cargo poc-runner.sh
mkdir "$scratch/parent/.cargo"
printf '[env]\nCI = ""\n' >"$scratch/parent/.cargo/config.toml"
refused "a parent directory's config" "$(cd "$scratch/parent" && pwd -P)/.cargo/config.toml is a Cargo configuration file" \
    build default check
rm -r "$scratch/parent/.cargo"

# c. $CARGO_HOME's own config: checked (with Python 3.11's tomllib, else refused unread).
home=$scratch/cargo-home
mkdir "$home"
for body in '[env]\nCI = ""' "[target.'cfg(unix)']\nrunner = \"./poc-runner.sh\"" \
    "[target.$host]\nlinker = \"/bin/true\"" '[build]\njobs = 2'; do
    printf "$body\n" >"$home/config.toml"
    refused "a \$CARGO_HOME config with $(head -n 2 "$home/config.toml" | tr '\n' ' ')" \
        "$(cd "$home" && pwd -P)/config.toml " env CARGO_HOME="$home" sh scripts/build.sh \
        ${toolchain:+"+$toolchain"} default check
done

# d. The variables.
for assignment in "CARGO_TARGET_${host_var}_RUNNER=./poc-runner.sh" "CARGO_TARGET_${host_var}_LINKER=" \
    CARGO_BUILD_JOBS=2 CARGO_ENV_CI=; do
    refused "$assignment" "${assignment%%=*} is set; build.sh runs cargo in a closed configuration" \
        env "$assignment" sh scripts/build.sh ${toolchain:+"+$toolchain"} default test
done
for value in 1 ''; do
    refused "KILND_BLESS_CHECKPOINT_CONTRACT='$value'" "KILND_BLESS_CHECKPOINT_CONTRACT is set; build.sh never blesses goldens" \
        env KILND_BLESS_CHECKPOINT_CONTRACT="$value" sh scripts/build.sh ${toolchain:+"+$toolchain"} default test \
        -p kilnd --lib bless_checkpoint_contract -- --ignored
done
[ "$(cksum <"$golden")" = "$before" ] || fail "the wire golden changed"

if [ "$failed" -ne 0 ]; then
    echo "closed Cargo configuration regressions: FAILED" >&2
    exit 1
fi
echo "closed Cargo configuration regressions: all passed"
