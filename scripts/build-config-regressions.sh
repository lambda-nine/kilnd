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
#  c. a $CARGO_HOME config with `[env]`, a target runner or linker, or a `build` key;
#  d. CARGO_TARGET_<host>_RUNNER, CARGO_TARGET_<host>_LINKER, CARGO_BUILD_JOBS and
#     CARGO_ENV_CI set, even empty, KILND_BLESS_CHECKPOINT_CONTRACT set to 1 or empty, and
#     RUSTDOC or CLIPPY_CONF_DIR set;
#  e. C6a recheck 2 HIGH 3: a relative CARGO_HOME whose config's `[env]` forces blessing,
#     with build.sh run by its absolute path from another directory (the wire golden's
#     SHA-256 stays unchanged); a relative CARGO_HOME only the caller's directory has; and a
#     relative HOME;
#  f. C6a recheck 3: a $CARGO_HOME config whose `include` brings in a blessing `[env]` (the
#     wire golden's SHA-256 stays unchanged), and ones with `alias`, `profile` or a key no
#     Cargo knows; CARGO_ALIAS_CLIPPY replacing clippy. A config of only allowed keys gets
#     past the check (to the profile check, with Python 3.11 or later; refused unread
#     before that).
#  g. C6a recheck 4: a $CARGO_HOME credentials.toml, and separately a credentials, with a
#     target runner, `[env]`, `include`, `[alias]`, a non-credential key in
#     `[registries.NAME]` or a non-table `registry`; CARGO_PROFILE_DEV_DEBUG_ASSERTIONS set.
#     Credentials of tokens only get past the check (as in f).
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
for assignment in RUSTDOC=/bin/false CLIPPY_CONF_DIR="$scratch"; do
    refused "$assignment" "${assignment%%=*} is set; build.sh runs cargo in a closed compiler environment" \
        env "$assignment" sh scripts/build.sh ${toolchain:+"+$toolchain"} default check
done
[ "$(cksum <"$golden")" = "$before" ] || fail "the wire golden changed"

# e. Paths resolved from the repository, as cargo resolves them.
sha256() {
    python3 -I -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$1"
}
golden_sha=$(sha256 "$golden")
mkdir relative-cargo-home "$scratch/elsewhere" "$scratch/elsewhere/caller-only-home"
cat >relative-cargo-home/config.toml <<'CONFIG'
[target.'cfg(unix)']
runner = "/bin/false"

[env]
KILND_BLESS_CHECKPOINT_CONTRACT = "1"
CI = { value = "", force = true }
CONFIG
from_elsewhere() { # CARGO_HOME build.sh-argument...
    (cd "$scratch/elsewhere" && CI=true CARGO_HOME=$1 && shift && export CI CARGO_HOME &&
        exec "$here/scripts/build.sh" ${toolchain:+"+$toolchain"} "$@")
}
refused "a relative CARGO_HOME with a blessing [env], from another directory" \
    "$here/relative-cargo-home/config.toml " from_elsewhere relative-cargo-home default test \
    -p kilnd --lib bless_checkpoint_contract -- --ignored --nocapture
[ "$(sha256 "$golden")" = "$golden_sha" ] || fail "the wire golden's SHA-256 changed"
refused "a CARGO_HOME relative to the caller's directory only" \
    "CARGO_HOME=caller-only-home is not a directory build.sh can resolve" \
    from_elsewhere caller-only-home default check
refused "a relative HOME, with CARGO_HOME unset" "HOME=relative-home is not absolute" \
    env -u CARGO_HOME HOME=relative-home sh scripts/build.sh ${toolchain:+"+$toolchain"} default check
[ "$(sha256 "$golden")" = "$golden_sha" ] || fail "the wire golden's SHA-256 changed"

# f. An allowlist of top-level keys, and no aliases.
include_home=$scratch/include-cargo-home
mkdir "$include_home"
ln -s "${CARGO_HOME:-$HOME/.cargo}/registry" "$include_home/registry"
printf 'include = ["bless.toml"]\n' >"$include_home/config.toml"
printf '[env]\nKILND_BLESS_CHECKPOINT_CONTRACT = "1"\nCI = { value = "", force = true }\n' \
    >"$include_home/bless.toml"
refused "a \$CARGO_HOME config whose include blesses" "$(cd "$include_home" && pwd -P)/config.toml " \
    env CI=true CARGO_HOME="$include_home" sh scripts/build.sh ${toolchain:+"+$toolchain"} default test \
    -p kilnd --lib bless_checkpoint_contract -- --ignored --nocapture
[ "$(sha256 "$golden")" = "$golden_sha" ] || fail "the wire golden's SHA-256 changed"
rm "$include_home/bless.toml"
for body in '[alias]\nclippy = "test --no-run"' '[profile.dev]\ndebug-assertions = false' \
    'future-key = true'; do
    printf "$body\n" >"$include_home/config.toml"
    refused "a \$CARGO_HOME config with $(head -n 2 "$include_home/config.toml" | tr '\n' ' ')" \
        "$(cd "$include_home" && pwd -P)/config.toml " env CARGO_HOME="$include_home" sh scripts/build.sh \
        ${toolchain:+"+$toolchain"} default check
done
refused "CARGO_ALIAS_CLIPPY='test --no-run'" "CARGO_ALIAS_CLIPPY is set; build.sh runs cargo in a closed configuration" \
    env CARGO_ALIAS_CLIPPY='test --no-run' sh scripts/build.sh ${toolchain:+"+$toolchain"} default clippy --all-targets
cat >"$include_home/config.toml" <<'CONFIG'
[http]
timeout = 30
[net]
retry = 3
[registry]
default = "crates-io"
[registries.example]
index = "sparse+https://example.invalid/index/"
[term]
color = "never"
[cargo-new]
vcs = "none"
[source.example-mirror]
registry = "sparse+https://example.invalid/mirror/"
CONFIG
if python3 -I -c 'import tomllib' 2>/dev/null; then
    allowed_message="no-such-profile is not a profile in dependency-gate.json"
else
    allowed_message="$(cd "$include_home" && pwd -P)/config.toml cannot be checked without Python 3.11"
fi
refused "a \$CARGO_HOME config of allowed keys only (past the config check)" "$allowed_message" \
    env CARGO_HOME="$include_home" sh scripts/build.sh ${toolchain:+"+$toolchain"} no-such-profile check
[ "$(sha256 "$golden")" = "$golden_sha" ] || fail "the wire golden's SHA-256 changed"

# g. The credentials files hold registry credentials only, and no profile variables.
credentials_home=$scratch/credentials-cargo-home
mkdir "$credentials_home"
ln -s "${CARGO_HOME:-$HOME/.cargo}/registry" "$credentials_home/registry"
credentials_dir=$(cd "$credentials_home" && pwd -P)
for name in credentials.toml credentials; do
    for body in "[registry]\ntoken = \"x\"\n[target.$host]\nrunner = \"$scratch/runner.sh\"" \
        '[registry]\ntoken = "x"\n[env]\nKILND_BLESS_CHECKPOINT_CONTRACT = "1"' \
        'include = ["bless.toml"]' '[alias]\nclippy = "test --no-run"' \
        '[registries.foo]\ntoken = "y"\nindex = "sparse+https://example.invalid/index/"' \
        'registry = "x"'; do
        printf "$body\n" >"$credentials_home/$name"
        refused "a \$CARGO_HOME $name with $(tr '\n' ' ' <"$credentials_home/$name")" \
            "$credentials_dir/$name " env CARGO_HOME="$credentials_home" sh scripts/build.sh \
            ${toolchain:+"+$toolchain"} default check
    done
    rm "$credentials_home/$name"
done
refused "CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false" \
    "CARGO_PROFILE_DEV_DEBUG_ASSERTIONS is set; build.sh runs cargo in a closed configuration" \
    env CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false sh scripts/build.sh ${toolchain:+"+$toolchain"} default test
printf '[registry]\ntoken = "x"\n[registries.foo]\ntoken = "y"\n' >"$credentials_home/credentials.toml"
if python3 -I -c 'import tomllib' 2>/dev/null; then
    allowed_message="no-such-profile is not a profile in dependency-gate.json"
else
    allowed_message="$credentials_dir/credentials.toml cannot be checked without Python 3.11"
fi
refused "a \$CARGO_HOME credentials.toml of tokens only (past the credentials check)" "$allowed_message" \
    env CARGO_HOME="$credentials_home" sh scripts/build.sh ${toolchain:+"+$toolchain"} no-such-profile check
[ "$(sha256 "$golden")" = "$golden_sha" ] || fail "the wire golden's SHA-256 changed"

if [ "$failed" -ne 0 ]; then
    echo "closed Cargo configuration regressions: FAILED" >&2
    exit 1
fi
echo "closed Cargo configuration regressions: all passed"
