#!/usr/bin/env python3
"""Phase 1b B5: proves the kilnd-exec-core extraction is a move.

For every item moved out of kilnd at the B4 base commit, finds it in its new file and
compares the two texts token by token. The only differences allowed are the listed
visibility widenings and rewrites, each named below; anything else fails. Run from the
repository root, at the commit that made the move (later edits to the core crate are
not moves): python3 -I scripts/b5-move-audit.py [BASE] (default 415d850).
"""
import difflib
import re
import subprocess
import sys

BASE = sys.argv[1] if len(sys.argv) > 1 else "415d850"
K = "crates/kilnd/src/"
C = "crates/kilnd-exec-core/src/"

# (old file at BASE, new file, item headers). An item is its doc comments and
# attributes, its header line and everything to the matching closing brace (or `;`).
ITEMS = [
    (K + "model.rs", C + "model.rs", [
        "pub struct SandboxSpec {", "pub enum Network {", "pub enum SandboxDisposition {",
        "impl SandboxDisposition {", "pub enum CleanupEvidence {", "impl CleanupEvidence {",
        "pub struct Captured {", "impl Captured {", "pub enum CommandStatus {",
        "impl CommandStatus {", "pub enum RuntimeErrorKind {", "pub enum RuntimeStage {",
        "pub struct RuntimeDiagnostic {", "impl RuntimeDiagnostic {"]),
    (K + "sys.rs", C + "sys.rs", [
        "    fn sys_ret(", "    pub struct CapHeader {", "    pub struct CapData {",
        "    pub fn capget(", "    pub fn capset(", "        pub fn cap_ambient_is_set(",
        "        pub fn cap_ambient_lower(", "        pub fn capbset_read(",
        "        pub fn capbset_drop(", "        pub fn set_no_new_privs(",
        "        pub fn get_no_new_privs(", "        pub fn set_parent_death_kill("]),
    (K + "runtime/mod.rs", C + "runtime/mod.rs", [
        "pub enum RuntimeError {", "pub struct ExecSpec<'a> {", "pub enum ExecFinish {",
        "pub struct ExecOutcome {", "pub(crate) fn legacy_exec_evidence(",
        "pub enum BackendStatus {", "pub struct BackendSandbox {"]),
    (K + "runtime/kiln_direct.rs", C + "runtime/kiln_direct.rs", [
        "const CLI_REQUIREMENT: &str =", "const SANDBOX_REQUIREMENT: &str",
        "const CONTROL_OUTPUT: usize", "const QUERY_TIMEOUT: Duration",
        "const CLEANUP_TIMEOUT: Duration", "const CLEANUP_POLL: Duration",
        "    async fn call_until(", "    async fn run_control(", "    async fn capabilities(",
        "    async fn require_scoped_gc(", "    pub(crate) async fn list_until(",
        "    async fn wait_exec_cleanup(", "    pub(crate) async fn exec_direct(",
        "    async fn validate_sandbox(", "pub fn create_args(", "pub fn parse_ls(",
        "pub(crate) fn valid_kiln_id(", "fn check_id(", "fn exec_populated(",
        "fn decode_status(", "fn summarize("]),
]
WHOLE = [
    (K + "process.rs", C + "process.rs"),
    (K + "validation.rs", C + "validation.rs"),
    (K + "runtime/kiln_process.rs", C + "runtime/kiln_process.rs"),
    (K + "runtime/kiln_protocol.rs", C + "runtime/kiln_protocol.rs"),
]
# Allowed token rewrites (old -> new), and why. Applied to the old text only.
REWRITES = [
    ("pub(crate) fn legacy_exec_evidence", "pub fn legacy_exec_evidence",
     "kilnd's re-export needs it public across the crate boundary"),
    ("pub(crate) fn valid_kiln_id", "pub fn valid_kiln_id", "re-exported to kilnd's helper protocol"),
    ("fn check_id", "pub fn check_id", "kilnd's rm/gc still call it"),
    ("fn exec_populated", "pub fn exec_populated", "core free function"),
    ("fn decode_status", "pub fn decode_status", "core free function"),
    ("fn summarize", "pub fn summarize", "kilnd's create/rm/gc errors still call it"),
    ("const CONTROL_OUTPUT", "pub const CONTROL_OUTPUT", "kilnd's adapter tests name it"),
    ("const QUERY_TIMEOUT", "pub const QUERY_TIMEOUT", "kilnd's rm/gc/create still use it"),
    ("async fn call_until", "pub async fn call_until", "DirectKilnRuntime delegates"),
    ("async fn run_control", "pub async fn run_control", "DirectKilnRuntime delegates"),
    ("async fn capabilities", "pub async fn capabilities", "DirectKilnRuntime delegates"),
    ("pub(crate) async fn list_until", "pub async fn list_until", "DirectKilnRuntime delegates"),
    ("async fn wait_exec_cleanup", "pub async fn wait_exec_cleanup", "the broker reuses it"),
    ("pub(crate) async fn exec_direct", "pub async fn exec_direct", "DirectKilnRuntime delegates"),
    ("async fn validate_sandbox", "pub async fn validate_sandbox",
     "was the Runtime impl's body; now the core's inherent method, the impl delegates"),
    ("&self.bin", "self.bin", "the core holds `&KilnBinary`, so the borrow is already a reference"),
    ("pub(crate) fn require_firecracker_launch_capabilities_dropped",
     "pub fn require_firecracker_launch_capabilities_dropped", "kilnd's helper workers call it"),
    ("pub(crate) stdout_completion", "pub stdout_completion", "kilnd's create_result reads it"),
    ("pub(crate) stderr_completion", "pub stderr_completion", "kilnd's create_result reads it"),
    ("pub(crate) enum CaptureCompletion", "pub enum CaptureCompletion", "kilnd's create_result reads it"),
    ("pub async fn catch_poll", "pub(crate) async fn catch_poll",
     "narrowed: a now-public module would export a Result<_, ()> (clippy::result_unit_err)"),
]


def show(path, rev=None):
    if rev:
        return subprocess.run(["git", "show", f"{rev}:{path}"], check=True,
                              capture_output=True, text=True).stdout
    return open(path).read()


def item(text, header):
    lines = text.split("\n")
    starts = [i for i, l in enumerate(lines) if l.startswith(header)]
    if len(starts) != 1:
        raise SystemExit(f"{header!r}: {len(starts)} matches")
    s = a = starts[0]
    while a > 0 and lines[a - 1].strip().startswith(("///", "#[", "// ")):
        a -= 1
    depth, seen = 0, False
    for i in range(s, len(lines)):
        code = re.sub(r'"(\\.|[^"\\])*"', '""', lines[i].split("//")[0])
        for c in code:
            if c in "{(":
                depth += 1
                seen = True
            elif c in "})":
                depth -= 1
        if (seen and depth == 0) or (not seen and lines[i].rstrip().endswith(";")):
            if lines[i].rstrip().endswith(("{", ",")) and depth > 0:
                continue
            return "\n".join(lines[a:i + 1])
    raise SystemExit(f"{header!r}: unterminated")


def tokens(text):
    return re.findall(r'"(?:\\.|[^"\\])*"|[A-Za-z0-9_]+|\S', text)


def rewrite(toks, before, after):
    """Replaces the token sequence `before` with `after`, except where `after` is
    already present (a rewrite that adds a prefix is not applied twice)."""
    b, a = tokens(before), tokens(after)
    out, i, n = [], 0, 0
    while i < len(toks):
        if toks[i:i + len(b)] == b:
            k = len(a) - len(b)
            already = k > 0 and a[k:] == b and out[len(out) - k:] == a[:k]
            if not already:
                out.extend(a)
                i += len(b)
                n += 1
                continue
        out.append(toks[i])
        i += 1
    return out, n


def compare(label, old, new, used):
    a = tokens(old)
    for before, after, _ in REWRITES:
        a, n = rewrite(a, before, after)
        used[before] = used.get(before, 0) + n
    b = tokens(new)
    if a != b:
        i = next(i for i in range(min(len(a), len(b)) + 1)
                 if i == min(len(a), len(b)) or a[i] != b[i])
        raise SystemExit(f"{label}: differs at token {i}: {' '.join(a[i:i+12])!r} vs "
                         f"{' '.join(b[i:i+12])!r}")


def main():
    used = {}
    count = 0
    for old_path, new_path, headers in ITEMS:
        old_text, new_text = show(old_path, BASE), show(new_path)
        for header in headers:
            new_header = header
            for before, after, _ in REWRITES:
                if header.strip().startswith(before):
                    new_header = header.replace(before, after)
            new_header = new_header.replace("pub(crate) fn", "pub fn")
            compare(f"{old_path} {header.strip()}", item(old_text, header),
                    item(new_text, new_header if new_header.strip() in new_text else header), used)
            print(f"moved  {old_path} `{header.strip()}` -> {new_path}")
            count += 1
    for old_path, new_path in WHOLE:
        compare(old_path, show(old_path, BASE), show(new_path), used)
        print(f"moved  {old_path} (whole file) -> {new_path}")
        count += 1
    # Nothing else left kilnd: every line deleted from a partly moved file belongs to a
    # moved item, or is an import, a module declaration or the delegated body.
    for old_path, new_path, headers in ITEMS:
        before = show(old_path, BASE)
        moved = "\n".join(item(before, h) for h in headers)
        after = show(old_path)
        for line in difflib.ndiff(before.split("\n"), after.split("\n")):
            if not line.startswith("- "):
                continue
            text = line[2:]
            if not text.strip() or text in moved.split("\n"):
                continue
            if re.match(r"\s*(use |pub use |\}|[A-Za-z0-9_:, {}]+,$|[A-Za-z0-9_:, {}]+$|//)", text):
                continue
            raise SystemExit(f"{old_path}: deleted line is not part of a moved item: {text!r}")
    unused = [b for b, _, _ in REWRITES if not used.get(b)]
    if unused:
        raise SystemExit(f"rewrites never applied (remove them): {unused}")
    print(f"{count} moves verified; {len(REWRITES)} named rewrites:")
    for before, after, why in REWRITES:
        print(f"  {before} -> {after}: {why} (x{used[before]})")


main()
