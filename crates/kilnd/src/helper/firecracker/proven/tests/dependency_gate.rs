//! Design section 7.1's dependency gate, rebuilt for the B7 milestone 2 break-it
//! (HIGH-1, MEDIUM-1 and LOW-1) and its recheck (HIGH-1's method and transitive
//! wrappers).
//!
//! The gate fails closed on *review*, not on detection. What it guarantees:
//!
//! - **No unreviewed package enters the build.** `dependency-gate.json` has an entry for
//!   every package in Cargo.lock outside the workspace, direct and transitive, keyed by
//!   `name@version` and pinned to Cargo.lock's checksum and to the features cargo resolves
//!   for it: its `kind` (runtime, build-only or dev-only), its `capability` (`none` or a
//!   set of `filesystem`, `process`, `signals`, `syscalls`, `network`) and why. A new
//!   package, a changed version or checksum, or a changed feature set fails until a person
//!   reviews it.
//! - **Common destructive sinks in packages declared non-destructive are flagged for
//!   review.** For every package declared `none`, `network` or `no_destructive_api` (in the
//!   runtime graph, or a direct dependency), the source of its whole runtime dependency
//!   subtree is scanned for curated destructive method names whatever their receiver
//!   (`.set_len(`, `.remove_file(`, `.kill(` …), for std, Tokio and libc paths clippy.toml
//!   disallows, and for trait impls on std's and Tokio's file and process types. A hit
//!   refuses the declaration unless `sink_exceptions` records a reviewed exception scoped to
//!   the package, version and feature set it is in.
//!
//! The gate is not a proof. Deciding whether an API is destructive is the reviewer's job;
//! the scan is lexical and catches the common shapes of an honest mistake, not a dependency
//! built to hide one.
//!
//! The clippy gate (`clippy.toml`) is the semantic one for workspace code. A direct
//! dependency with a destructive-capable category (filesystem, process, signals, syscalls)
//! lists its destructive paths, and clippy.toml disallows each of them. Production code
//! that names a destructive-looking function through a dependency's path clippy does not
//! disallow is refused.
//!
//! The completeness tests check the clippy list itself: every exported libc function
//! matching the curated destructive patterns, every `tokio::fs` function, and the
//! curated std surface.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::{production_part, rust_files};

/// Crates that are raw system-call bindings themselves. A package that is one, is a
/// `*-sys` crate (native code) or depends directly on either can wrap system calls.
const RAW_SYSCALL_CRATES: [&str; 6] = ["libc", "linux-raw-sys", "rustix", "nix", "syscalls", "sc"];

fn raw_or_native(name: &str) -> bool {
    RAW_SYSCALL_CRATES.contains(&name) || name.ends_with("-sys")
}

const CAPABILITIES: [&str; 6] = [
    "none",
    "filesystem",
    "process",
    "signals",
    "syscalls",
    "network",
];
/// The categories that can destroy: a direct dependency with any of them lists its
/// destructive paths, and clippy.toml disallows each one.
const DESTRUCTIVE_CAPABILITIES: [&str; 4] = ["filesystem", "process", "signals", "syscalls"];
const KINDS: [&str; 3] = ["runtime", "build-only", "dev-only"];
const SECTIONS: [&str; 4] = ["about", "groups", "packages", "sink_exceptions"];
const ENTRY_FIELDS: [&str; 10] = [
    "checksum",
    "features",
    "kind",
    "runtime_via",
    "capability",
    "destructive",
    "no_destructive_api",
    "raw_use",
    "why",
    "group",
];
const EXCEPTION_FIELDS: [&str; 5] = ["package", "version", "features", "sinks", "why"];

/// MEDIUM-1's curated destructive name patterns: `*x*` contains, `x*` prefix, `*x`
/// suffix, otherwise exact. The libc completeness test requires every exported libc
/// function matching one to be disallowed in clippy.toml. The design's list, with the
/// review's additions: every `unlink` (`shm_unlink`, `mq_unlink`, `sem_unlink`), every
/// `kill` and `sigqueue` (`pthread_kill`, `pthread_sigqueue`), the extended-attribute
/// removals, `reboot` and `swapoff`.
pub(super) const DESTRUCTIVE_NAMES: [&str; 25] = [
    "*unlink*",
    "rmdir",
    "rename*",
    "*truncate*",
    "creat*",
    "exec*",
    "posix_spawn*",
    "system",
    "popen",
    "*kill*",
    "tkill",
    "tgkill",
    "*sigqueue*",
    "pidfd_send_signal",
    "umount*",
    "mount",
    "remove*",
    "*removexattr",
    "fallocate*",
    "ptrace",
    "process_vm_writev",
    "prctl",
    "syscall",
    "reboot",
    "swapoff",
];

/// Names a wrapper crate gives std's and Tokio's destructive file operations, beyond
/// the libc patterns: `copy` and `write` overwrite a destination by name, `set_len`
/// truncates, and `persist` replaces a name.
const WRAPPER_NAMES: [&str; 4] = ["copy", "write", "set_len", "persist*"];

/// The B7 milestone 2 recheck's method-form sinks: a call `.name(` (or `.name::<`) with
/// one of these names is flagged in a non-destructive declaration's subtree whatever its
/// receiver, since a lexical scan cannot resolve the receiver's type (an extension trait
/// on `std::fs::File` hides `File::set_len` behind any name; its body still calls it).
/// Same patterns as above. Each is a std or Tokio destructive method, or the method form
/// a handle-based wrapper gives one; several share a name with harmless methods
/// (`Vec::truncate`, `Vec::set_len`), which is what `sink_exceptions` is for.
pub(super) const METHOD_SINKS: [(&str, &str); 15] = [
    (
        "set_len",
        "File::set_len (std, Tokio) truncates or extends an open file",
    ),
    (
        "truncate",
        "OpenOptions::truncate (std, Tokio) empties a file as it opens",
    ),
    (
        "remove_file",
        "a handle-relative removal (a directory handle's remove_file)",
    ),
    (
        "remove_dir",
        "a handle-relative removal (a directory handle's remove_dir)",
    ),
    ("remove_dir_all", "a recursive handle-relative removal"),
    (
        "rename",
        "a handle-relative rename replaces the target name",
    ),
    (
        "unlink*",
        "unlink, unlink_at, unlinkat on a directory or socket handle",
    ),
    ("copy", "a handle-relative copy overwrites its destination"),
    ("kill", "Child::kill (std, Tokio) signals a process"),
    ("start_kill", "tokio::process::Child::start_kill"),
    ("send_signal", "a process or pidfd handle's signal"),
    ("persist*", "tempfile-style persist replaces a name"),
    (
        "exec",
        "CommandExt::exec replaces the process image with another program",
    ),
    ("umount*", "a mount handle's umount"),
    ("unmount*", "a mount handle's unmount"),
];

/// std's and Tokio's file and process types: a trait impl for one in a non-destructive
/// declaration's subtree is flagged (an extension trait is how a method wrapper reaches
/// `File::set_len` or `Child::kill`).
const FLAGGED_IMPL_TYPES: [&str; 8] = [
    "std::fs::File",
    "std::fs::OpenOptions",
    "std::process::Child",
    "std::process::Command",
    "tokio::fs::File",
    "tokio::fs::OpenOptions",
    "tokio::process::Child",
    "tokio::process::Command",
];

/// Paths that keep a package out of a shared justification (`groups`): a grouped package
/// names none of them, anywhere in its library source.
const IMPURE_PREFIXES: [&str; 11] = [
    "std::fs",
    "std::process",
    "std::os::unix::fs",
    "std::os::unix::process",
    "std::os::unix::prelude",
    "std::os::linux::fs",
    "std::os::linux::process",
    "std::os::fd",
    "libc",
    "tokio::fs",
    "tokio::process",
];

fn matches_pattern(name: &str, pattern: &str) -> bool {
    if let Some(rest) = pattern.strip_prefix('*') {
        match rest.strip_suffix('*') {
            Some(middle) => name.contains(middle),
            None => name.ends_with(rest),
        }
    } else if let Some(prefix) = pattern.strip_suffix('*') {
        name.starts_with(prefix)
    } else {
        name == pattern
    }
}

/// Whether a path segment names a destructive-looking function (lower-case: constants
/// such as `SYS_kill` and types are not functions). `wrapper` adds the std-wrapper
/// names; libc's own `write` and `copy`-like names are descriptor operations, and
/// libc is held to the pattern list by its completeness test.
fn destructive_name(segment: &str, wrapper: bool) -> Option<&'static str> {
    if !segment.starts_with(|c: char| c.is_ascii_lowercase() || c == '_') {
        return None;
    }
    DESTRUCTIVE_NAMES
        .iter()
        .chain(WRAPPER_NAMES.iter().filter(|_| wrapper))
        .find(|pattern| matches_pattern(segment, pattern))
        .copied()
}

fn method_sink(name: &str) -> bool {
    // A quick rejection first (every pattern is exact or a prefix): this runs on every
    // word of every scanned file.
    let first = name.as_bytes().first().copied();
    METHOD_SINKS.iter().any(|(pattern, _)| {
        pattern.as_bytes().first().copied() == first && matches_pattern(name, pattern)
    })
}

// ---------------------------------------------------------------------------------
// Cargo.lock, cargo metadata, manifests and clippy.toml.

/// One `[[package]]` of Cargo.lock.
#[derive(Clone, Debug)]
struct LockEntry {
    name: String,
    version: String,
    /// Workspace members have no `source`.
    source: Option<String>,
    checksum: Option<String>,
    /// Direct dependencies as Cargo.lock writes them: `name` or `name version`.
    dependencies: Vec<String>,
}

impl LockEntry {
    fn key(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }
}

fn lock_entries(lock: &str) -> Vec<LockEntry> {
    let mut out = Vec::new();
    for block in lock.split("[[package]]").skip(1) {
        let (mut name, mut version, mut source, mut checksum) = (None, None, None, None);
        let mut dependencies = Vec::new();
        let mut in_dependencies = false;
        let value = |line: &str| line.split('"').nth(1).unwrap_or("").to_string();
        for line in block.lines() {
            let line = line.trim();
            if in_dependencies {
                if line == "]" {
                    in_dependencies = false;
                } else if let Some(entry) = line.strip_prefix('"') {
                    let entry = entry.trim_end_matches(',').trim_end_matches('"');
                    // `name version (source)`: the source is redundant for the key.
                    let mut words = entry.split(' ');
                    let name = words.next().unwrap_or("");
                    dependencies.push(match words.next() {
                        Some(version) if !version.starts_with('(') => {
                            format!("{name} {version}")
                        }
                        _ => name.to_string(),
                    });
                }
            } else if line.starts_with("name = ") {
                name = Some(value(line));
            } else if line.starts_with("version = ") {
                version = Some(value(line));
            } else if line.starts_with("source = ") {
                source = Some(value(line));
            } else if line.starts_with("checksum = ") {
                checksum = Some(value(line));
            } else if line == "dependencies = [" {
                in_dependencies = true;
            }
        }
        out.push(LockEntry {
            name: name.expect("a package without a name"),
            version: version.expect("a package without a version"),
            source,
            checksum,
            dependencies,
        });
    }
    out
}

/// Cargo.lock's versions of each package name (the completeness tests read the locked
/// libc and Tokio).
fn locked_versions(lock: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for entry in lock_entries(lock) {
        out.entry(entry.name).or_default().insert(entry.version);
    }
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum DependencyKind {
    Normal,
    Build,
    Dev,
}

/// One resolved package, from `cargo metadata`.
#[derive(Clone, Debug, Default)]
pub(super) struct Resolved {
    member: bool,
    proc_macro: bool,
    features: BTreeSet<String>,
    /// Direct dependencies by `name@version`, with every kind of edge (any target).
    deps: BTreeMap<String, BTreeSet<DependencyKind>>,
    /// The directory of the library target's root file, and the files of the package's
    /// other targets (build script, binaries) that may sit under it.
    library: Option<(PathBuf, BTreeSet<PathBuf>)>,
    /// The package's own directory (where its Cargo.toml is).
    root: Option<PathBuf>,
}

/// The resolve `cargo metadata --locked --all-features` reports, by `name@version`:
/// every target's edges, every workspace feature enabled, so the reviewed features are
/// the union any supported build can enable.
#[derive(Clone, Debug, Default)]
pub(super) struct Resolve {
    packages: BTreeMap<String, Resolved>,
}

fn parse_metadata(metadata: &serde_json::Value) -> Result<Resolve, String> {
    let mut keys = BTreeMap::new();
    let mut resolve = Resolve::default();
    let members: BTreeSet<&str> = metadata["workspace_members"]
        .as_array()
        .ok_or("cargo metadata has no workspace_members")?
        .iter()
        .filter_map(|id| id.as_str())
        .collect();
    for package in metadata["packages"]
        .as_array()
        .ok_or("cargo metadata has no packages")?
    {
        let id = package["id"].as_str().ok_or("a package without an id")?;
        let key = format!(
            "{}@{}",
            package["name"].as_str().ok_or("a package without a name")?,
            package["version"]
                .as_str()
                .ok_or("a package without a version")?
        );
        let mut resolved = Resolved {
            member: members.contains(id),
            root: package["manifest_path"]
                .as_str()
                .and_then(|m| Path::new(m).parent())
                .map(Path::to_path_buf),
            ..Resolved::default()
        };
        let mut others = BTreeSet::new();
        for target in package["targets"].as_array().into_iter().flatten() {
            let kinds: Vec<&str> = target["kind"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|k| k.as_str())
                .collect();
            let path = PathBuf::from(target["src_path"].as_str().unwrap_or(""));
            if kinds.contains(&"proc-macro") {
                resolved.proc_macro = true;
            }
            if kinds
                .iter()
                .any(|k| ["lib", "rlib", "dylib", "proc-macro"].contains(k))
            {
                resolved.library = path
                    .parent()
                    .map(|dir| (dir.to_path_buf(), BTreeSet::new()));
            } else {
                others.insert(path);
            }
        }
        if let Some((_, other)) = resolved.library.as_mut() {
            *other = others;
        }
        keys.insert(id.to_string(), key.clone());
        resolve.packages.insert(key, resolved);
    }
    for node in metadata["resolve"]["nodes"]
        .as_array()
        .ok_or("cargo metadata has no resolve (was it run with --no-deps?)")?
    {
        let key = &keys[node["id"].as_str().ok_or("a node without an id")?];
        let mut features = BTreeSet::new();
        for feature in node["features"].as_array().into_iter().flatten() {
            features.insert(feature.as_str().unwrap_or("").to_string());
        }
        let mut deps: BTreeMap<String, BTreeSet<DependencyKind>> = BTreeMap::new();
        for dep in node["deps"].as_array().into_iter().flatten() {
            let target = &keys[dep["pkg"].as_str().ok_or("an edge without a package")?];
            for kind in dep["dep_kinds"].as_array().into_iter().flatten() {
                deps.entry(target.clone())
                    .or_default()
                    .insert(match kind["kind"].as_str() {
                        Some("build") => DependencyKind::Build,
                        Some("dev") => DependencyKind::Dev,
                        _ => DependencyKind::Normal,
                    });
            }
        }
        let resolved = resolve.packages.get_mut(key).unwrap();
        resolved.features = features;
        resolved.deps = deps;
    }
    Ok(resolve)
}

/// The graph's kind for every package: `runtime` if a workspace crate's normal
/// dependencies reach it through normal edges (a proc macro runs in the compiler, so it
/// and what only it reaches are build-time), `build-only` if only build edges (or a proc
/// macro) reach it, `dev-only` if only dev edges do. Also each runtime package's runtime
/// parents.
struct GraphKinds {
    kinds: BTreeMap<String, &'static str>,
    runtime_parents: BTreeMap<String, BTreeSet<String>>,
}

fn graph_kinds(resolve: &Resolve) -> GraphKinds {
    let (mut runtime, mut build, mut dev) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    let mut runtime_parents: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let proc_macro = |key: &String| resolve.packages.get(key).is_some_and(|p| p.proc_macro);
    let member = |key: &String| resolve.packages.get(key).is_some_and(|p| p.member);
    for (key, package) in resolve.packages.iter().filter(|(_, p)| p.member) {
        for (dep, kinds) in &package.deps {
            if member(dep) {
                continue;
            }
            if kinds.contains(&DependencyKind::Normal) {
                if proc_macro(dep) {
                    build.insert(dep.clone());
                } else {
                    runtime.insert(dep.clone());
                    runtime_parents
                        .entry(dep.clone())
                        .or_default()
                        .insert(key.clone());
                }
            }
            if kinds.contains(&DependencyKind::Build) {
                build.insert(dep.clone());
            }
            if kinds.contains(&DependencyKind::Dev) {
                dev.insert(dep.clone());
            }
        }
    }
    loop {
        let edges = |parents: &BTreeMap<String, BTreeSet<String>>| -> usize {
            parents.values().map(BTreeSet::len).sum()
        };
        let before = (
            runtime.len(),
            build.len(),
            dev.len(),
            edges(&runtime_parents),
        );
        for key in runtime.clone() {
            for (dep, kinds) in &resolve.packages[&key].deps {
                if kinds.contains(&DependencyKind::Normal) {
                    if proc_macro(dep) {
                        build.insert(dep.clone());
                    } else {
                        runtime.insert(dep.clone());
                        runtime_parents
                            .entry(dep.clone())
                            .or_default()
                            .insert(key.clone());
                    }
                }
                if kinds.contains(&DependencyKind::Build) {
                    build.insert(dep.clone());
                }
            }
        }
        for set in [&mut build, &mut dev] {
            for key in set.clone() {
                for dep in resolve.packages[&key].deps.keys() {
                    set.insert(dep.clone());
                }
            }
        }
        if (
            runtime.len(),
            build.len(),
            dev.len(),
            edges(&runtime_parents),
        ) == before
        {
            break;
        }
    }
    let mut kinds = BTreeMap::new();
    for key in resolve.packages.keys() {
        if runtime.contains(key) {
            kinds.insert(key.clone(), "runtime");
        } else if build.contains(key) {
            kinds.insert(key.clone(), "build-only");
        } else if dev.contains(key) {
            kinds.insert(key.clone(), "dev-only");
        }
    }
    GraphKinds {
        kinds,
        runtime_parents,
    }
}

/// One workspace manifest's dependency names and kinds, every target included. A
/// renamed dependency (`package = ...`) is refused: the gate matches by name.
fn manifest_dependencies(manifest: &str) -> Result<Vec<(String, DependencyKind)>, String> {
    fn kind(section: &str) -> Option<DependencyKind> {
        match section.rsplit('.').next().unwrap() {
            "dependencies" => Some(DependencyKind::Normal),
            "build-dependencies" => Some(DependencyKind::Build),
            "dev-dependencies" => Some(DependencyKind::Dev),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut current = None;
    for line in manifest.lines() {
        let line = line.split('#').next().unwrap().trim();
        if line.is_empty() {
            continue;
        }
        if let Some(header) = line.strip_prefix('[') {
            let header = header.trim_end_matches(']').trim();
            current = kind(header);
            if current.is_none() {
                // `[dependencies.name]`, `[target.x.dev-dependencies.name]` and the like.
                for (marker, k) in [
                    ("dev-dependencies.", DependencyKind::Dev),
                    ("build-dependencies.", DependencyKind::Build),
                    ("dependencies.", DependencyKind::Normal),
                ] {
                    if let Some(at) = header.find(marker)
                        && (at == 0 || header[..at].ends_with('.'))
                    {
                        out.push((header[at + marker.len()..].to_string(), k));
                        break;
                    }
                }
            }
            continue;
        }
        if let Some(k) = current {
            if line.starts_with("package") || line.contains("package =") {
                return Err(format!("renamed dependency: {line}"));
            }
            let name = line
                .split(['.', ' ', '='])
                .next()
                .unwrap()
                .trim_matches('"')
                .to_string();
            out.push((name, k));
        }
    }
    Ok(out)
}

/// clippy.toml's disallowed paths.
fn clippy_paths(clippy: &str) -> BTreeSet<String> {
    clippy
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter_map(|line| line.split("path = \"").nth(1))
        .map(|rest| rest.split('"').next().unwrap().to_string())
        .collect()
}

// ---------------------------------------------------------------------------------
// A small Rust lexer: identifiers and `::`, with comments, strings and character
// literals removed, so a path is seen however it is spaced or commented.

/// Identifiers borrow from the source text: the scan lexes megabytes of dependency
/// source in debug test builds, so it allocates nothing per token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Token<'a> {
    Ident(&'a str),
    PathSep,
    Punct(char),
}

fn tokens(text: &str) -> Vec<Token<'_>> {
    let chars: Vec<char> = text.chars().collect();
    // Each char's byte offset, and the text's end.
    let offsets: Vec<usize> = text
        .char_indices()
        .map(|(at, _)| at)
        .chain(std::iter::once(text.len()))
        .collect();
    let slice = |start: usize, end: usize| &text[offsets[start]..offsets[end]];
    let ident_char = |c: char| c.is_alphanumeric() || c == '_';
    let mut out = Vec::new();
    let mut i = 0;
    // Skips a (raw) string literal whose opening quote or `#` is at `i`.
    let skip_string = |mut i: usize, raw: bool| -> usize {
        let mut hashes = 0;
        if raw {
            while chars.get(i) == Some(&'#') {
                hashes += 1;
                i += 1;
            }
        }
        i += 1; // the opening quote
        while i < chars.len() {
            if !raw && chars[i] == '\\' {
                i += 2;
                continue;
            }
            if chars[i] == '"' && (0..hashes).all(|h| chars.get(i + 1 + h) == Some(&'#')) {
                return i + 1 + hashes;
            }
            i += 1;
        }
        i
    };
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && chars.get(i + 1) == Some(&'*') {
            let mut depth = 0;
            while i < chars.len() {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
        } else if c == '"' {
            i = skip_string(i, false);
        } else if c == '\'' {
            if chars.get(i + 1) == Some(&'\\') {
                i += 2;
                while i < chars.len() && chars[i] != '\'' {
                    i += 1;
                }
                i += 1;
            } else if chars.get(i + 2) == Some(&'\'') {
                i += 3;
            } else {
                i += 1; // a lifetime
            }
        } else if c.is_ascii_digit() {
            while i < chars.len() && ident_char(chars[i]) {
                i += 1;
            }
        } else if ident_char(c) {
            let start = i;
            while i < chars.len() && ident_char(chars[i]) {
                i += 1;
            }
            let word = slice(start, i);
            // A raw identifier, `r#type`.
            if word == "r"
                && chars.get(i) == Some(&'#')
                && chars
                    .get(i + 1)
                    .is_some_and(|c| c.is_alphabetic() || *c == '_')
            {
                let start = i + 1;
                i = start;
                while i < chars.len() && ident_char(chars[i]) {
                    i += 1;
                }
                out.push(Token::Ident(slice(start, i)));
                continue;
            }
            match (word, chars.get(i)) {
                ("b" | "c", Some('"')) => i = skip_string(i, false),
                ("r" | "br" | "cr", Some('"' | '#')) => i = skip_string(i, true),
                ("b", Some('\'')) => {
                    i += 1;
                    while i < chars.len() && chars[i] != '\'' {
                        if chars[i] == '\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                    i += 1;
                }
                _ => out.push(Token::Ident(word)),
            }
        } else if c == ':' && chars.get(i + 1) == Some(&':') {
            out.push(Token::PathSep);
            i += 2;
        } else {
            out.push(Token::Punct(c));
            i += 1;
        }
    }
    out
}

/// One name a `use` brings in: its full path and the name it is known by, or a glob.
#[derive(Debug)]
struct UseItem {
    path: Vec<String>,
    alias: Option<String>,
}

/// Expands one use tree (the tokens between `use` and `;`).
fn expand_use(tokens: &[Token], prefix: &[String], out: &mut Vec<UseItem>) {
    let mut path = prefix.to_vec();
    let mut i = 0;
    while i < tokens.len() {
        match &tokens[i] {
            Token::Ident(word) if *word == "as" => {
                // `as _` (a trait for its methods) brings in no name.
                if let Some(Token::Ident(alias)) = tokens.get(i + 1)
                    && *alias != "_"
                {
                    out.push(UseItem {
                        path: path.clone(),
                        alias: Some(alias.to_string()),
                    });
                }
                return;
            }
            Token::Ident(word) if *word == "self" && !path.is_empty() => {}
            Token::Ident(word) => path.push(word.to_string()),
            Token::PathSep => {}
            Token::Punct('*') => {
                out.push(UseItem { path, alias: None });
                return;
            }
            Token::Punct('{') => {
                // Each comma-separated subtree at depth one.
                let mut depth = 0;
                let mut start = i + 1;
                for (j, token) in tokens.iter().enumerate().skip(i) {
                    match token {
                        Token::Punct('{') => depth += 1,
                        Token::Punct('}') => {
                            depth -= 1;
                            if depth == 0 {
                                if start < j {
                                    expand_use(&tokens[start..j], &path, out);
                                }
                                break;
                            }
                        }
                        Token::Punct(',') if depth == 1 => {
                            if start < j {
                                expand_use(&tokens[start..j], &path, out);
                            }
                            start = j + 1;
                        }
                        _ => {}
                    }
                }
                return;
            }
            _ => {}
        }
        i += 1;
    }
    if let Some(last) = path.last().cloned() {
        out.push(UseItem {
            path,
            alias: Some(last),
        });
    }
}

/// A file's `use` items (and `extern crate ... as ...`) and every other path in it.
fn uses_and_paths(tokens: &[Token]) -> (Vec<UseItem>, Vec<Vec<String>>) {
    let mut uses = Vec::new();
    let mut paths = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let is =
            |at: usize, word: &str| matches!(tokens.get(at), Some(Token::Ident(w)) if *w == word);
        if is(i, "use") {
            let end = (i..tokens.len())
                .find(|&j| tokens[j] == Token::Punct(';'))
                .unwrap_or(tokens.len());
            let tree: Vec<Token> = tokens[i + 1..end]
                .iter()
                .skip_while(|t| **t == Token::PathSep)
                .cloned()
                .collect();
            expand_use(&tree, &[], &mut uses);
            i = end + 1;
            continue;
        }
        if is(i, "extern") && is(i + 1, "crate") {
            if let Some(Token::Ident(name)) = tokens.get(i + 2) {
                let alias = match (tokens.get(i + 3), tokens.get(i + 4)) {
                    (Some(Token::Ident(as_)), Some(Token::Ident(alias))) if *as_ == "as" => {
                        alias.to_string()
                    }
                    _ => name.to_string(),
                };
                uses.push(UseItem {
                    path: vec![name.to_string()],
                    alias: Some(alias),
                });
            }
            i += 3;
            continue;
        }
        if let Token::Ident(first) = &tokens[i]
            && tokens.get(i + 1) == Some(&Token::PathSep)
            && !matches!(i.checked_sub(1).map(|p| &tokens[p]), Some(Token::PathSep))
        {
            let mut path = vec![first.to_string()];
            let mut j = i + 1;
            while tokens.get(j) == Some(&Token::PathSep) {
                match tokens.get(j + 1) {
                    Some(Token::Ident(next)) => {
                        path.push(next.to_string());
                        j += 2;
                    }
                    _ => break,
                }
            }
            paths.push(path);
            i = j;
            continue;
        }
        i += 1;
    }
    (uses, paths)
}

/// A file's `use` aliases whose path resolves under one of `roots`, to a fixed point:
/// aliases may build on each other (`use tokio::fs; use fs::File;`).
fn alias_map(uses: &[UseItem], roots: &BTreeSet<String>) -> BTreeMap<String, Vec<String>> {
    let mut aliases: BTreeMap<String, Vec<String>> = BTreeMap::new();
    loop {
        let mut changed = false;
        for item in uses {
            // First resolution wins, so the loop ends (a self-referencing import cannot
            // grow an alias forever).
            if let (Some(alias), Some(full)) =
                (&item.alias, resolve_path(&aliases, roots, &item.path))
                && !aliases.contains_key(alias)
            {
                aliases.insert(alias.clone(), full);
                changed = true;
            }
        }
        if !changed {
            return aliases;
        }
    }
}

fn resolve_path(
    aliases: &BTreeMap<String, Vec<String>>,
    roots: &BTreeSet<String>,
    path: &[String],
) -> Option<Vec<String>> {
    let first = path.first()?;
    if roots.contains(first) {
        return Some(path.to_vec());
    }
    let mut full = aliases.get(first)?.clone();
    full.extend_from_slice(&path[1..]);
    Some(full)
}

/// Every path a file names whose root is one of `roots` (crate names in their
/// underscore form), with `use` aliases resolved: `use fs_err as fs;` then
/// `fs::remove_dir_all` is `fs_err::remove_dir_all`. Glob imports of a root come back
/// as a path ending in `*`.
fn rooted_paths(text: &str, roots: &BTreeSet<String>) -> Vec<Vec<String>> {
    rooted_paths_in(&tokens(text), roots)
}

fn rooted_paths_in(tokens: &[Token], roots: &BTreeSet<String>) -> Vec<Vec<String>> {
    let (uses, paths) = uses_and_paths(tokens);
    let aliases = alias_map(&uses, roots);
    let mut out = Vec::new();
    for item in &uses {
        if let Some(mut full) = resolve_path(&aliases, roots, &item.path) {
            if item.alias.is_none() {
                full.push("*".into());
            }
            out.push(full);
        }
    }
    for path in &paths {
        if let Some(full) = resolve_path(&aliases, roots, path) {
            out.push(full);
        }
    }
    out
}

/// `core::` and `alloc::` paths are std's.
fn as_std(path: &str) -> String {
    path.replacen("core::", "std::", 1)
        .replacen("alloc::", "std::", 1)
}

/// Non-ASCII bytes count as word bytes, so a word never splits a character.
fn word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b >= 0x80
}

/// A text's identifier-like words with their byte offsets, comments and strings
/// included (a superset of its identifiers), without allocating.
fn word_spans(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let bytes = text.as_bytes();
    let mut at = 0;
    std::iter::from_fn(move || {
        while at < bytes.len() && !word_byte(bytes[at]) {
            at += 1;
        }
        if at == bytes.len() {
            return None;
        }
        let start = at;
        while at < bytes.len() && word_byte(bytes[at]) {
            at += 1;
        }
        Some((start, &text[start..at]))
    })
}

fn words(text: &str) -> impl Iterator<Item = &str> {
    word_spans(text).map(|(_, word)| word)
}

/// Whether a `.` could come before the word at `at`, with only whitespace (or a comment,
/// which might hide one) between them.
fn dot_before(bytes: &[u8], at: usize) -> bool {
    let mut i = at;
    let mut crossed_line = false;
    while i > 0 && bytes[i - 1].is_ascii_whitespace() {
        crossed_line |= bytes[i - 1] == b'\n';
        i -= 1;
    }
    if i == 0 {
        return false;
    }
    match bytes[i - 1] {
        b'.' => true,
        // The end of a block comment.
        b'/' => true,
        _ if crossed_line => {
            // The line before may end in a `//` comment after a `.`.
            let line_start = bytes[..i]
                .iter()
                .rposition(|b| *b == b'\n')
                .map_or(0, |n| n + 1);
            bytes[line_start..i].windows(2).any(|w| w == b"//")
        }
        _ => false,
    }
}

/// The word after `at`, past whitespace; `Some("/")` when a comment intervenes, so the
/// caller treats it as possible.
fn word_after(bytes: &[u8], mut at: usize) -> Option<&str> {
    while at < bytes.len() && bytes[at].is_ascii_whitespace() {
        at += 1;
    }
    if bytes.get(at) == Some(&b'/') {
        return Some("as");
    }
    let start = at;
    while at < bytes.len() && word_byte(bytes[at]) {
        at += 1;
    }
    std::str::from_utf8(&bytes[start..at]).ok()
}

/// Whether a flagged type's name could be the type after the `for` ending at `at`:
/// past whitespace, `&`, `mut`, `dyn`, lifetimes and `path::` segments. A comment in
/// between counts as possible.
fn flagged_type_after(text: &str, mut at: usize) -> bool {
    let bytes = text.as_bytes();
    loop {
        while at < bytes.len() && (bytes[at].is_ascii_whitespace() || bytes[at] == b'&') {
            at += 1;
        }
        match bytes.get(at) {
            Some(b'/') => return true,
            Some(b'\'') => {
                at += 1;
                while at < bytes.len() && word_byte(bytes[at]) {
                    at += 1;
                }
                continue;
            }
            Some(b':') => {
                at += 1;
                continue;
            }
            _ => {}
        }
        let start = at;
        while at < bytes.len() && word_byte(bytes[at]) {
            at += 1;
        }
        let word = &text[start..at];
        if word.is_empty() {
            return false;
        }
        if FLAGGED_NAMES.contains(&word) {
            return true;
        }
        // Another segment of a path, or a qualifier: keep going only if one follows.
        let mut next = at;
        while next < bytes.len() && bytes[next].is_ascii_whitespace() {
            next += 1;
        }
        let qualifier = ["mut", "dyn", "const"].contains(&word);
        if !(qualifier || bytes.get(next) == Some(&b':')) {
            return false;
        }
    }
}

/// A file's tokens without its inline `#[cfg(test)]` modules (`#[cfg(test)] mod x { … }`,
/// with any further attributes and visibility). Only inline test modules go: an
/// out-of-line `#[cfg(test)] mod x;` names a file the scan reads like any other, so a
/// test file is scanned unless it is `tests.rs` or under `tests/`.
fn without_test_modules(toks: Vec<Token<'_>>) -> Vec<Token<'_>> {
    let ident = |t: Option<&Token>, w: &str| matches!(t, Some(Token::Ident(x)) if *x == w);
    let punct = |t: Option<&Token>, c: char| t == Some(&Token::Punct(c));
    let mut out = Vec::with_capacity(toks.len());
    let mut i = 0;
    while i < toks.len() {
        // `# [ cfg ( test ) ]`
        let cfg_test = punct(toks.get(i), '#')
            && punct(toks.get(i + 1), '[')
            && ident(toks.get(i + 2), "cfg")
            && punct(toks.get(i + 3), '(')
            && ident(toks.get(i + 4), "test")
            && punct(toks.get(i + 5), ')')
            && punct(toks.get(i + 6), ']');
        if cfg_test {
            // Further attributes, then visibility, then `mod name {`.
            let mut j = i + 7;
            while punct(toks.get(j), '#') && punct(toks.get(j + 1), '[') {
                let mut depth = 0;
                j += 1;
                while j < toks.len() {
                    match toks[j] {
                        Token::Punct('[') => depth += 1,
                        Token::Punct(']') => {
                            depth -= 1;
                            if depth == 0 {
                                j += 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
            }
            if ident(toks.get(j), "pub") {
                j += 1;
                if punct(toks.get(j), '(') {
                    while j < toks.len() && !punct(toks.get(j), ')') {
                        j += 1;
                    }
                    j += 1;
                }
            }
            if ident(toks.get(j), "mod") && punct(toks.get(j + 2), '{') {
                let mut depth = 0;
                let mut k = j + 2;
                while k < toks.len() {
                    match toks[k] {
                        Token::Punct('{') => depth += 1,
                        Token::Punct('}') => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    k += 1;
                }
                i = k + 1;
                continue;
            }
        }
        out.push(toks[i]);
        i += 1;
    }
    out
}

/// The types a file defines itself (`struct`, `enum`, `union`, `type` and `trait`
/// names), so a trait impl for a package's own `File` or `Command` is not mistaken for
/// std's.
fn defined_types(toks: &[Token<'_>]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for pair in toks.windows(2) {
        if let [Token::Ident(keyword), Token::Ident(name)] = pair
            && ["struct", "enum", "union", "type", "trait"].contains(keyword)
        {
            out.insert(name.to_string());
        }
    }
    out
}

/// The self type of each trait impl in a file (`impl ... for <path>`), with references,
/// `mut`, `dyn` and lifetimes removed.
fn impl_self_types(toks: &[Token]) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for (start, token) in toks.iter().enumerate() {
        if *token != Token::Ident("impl") {
            continue;
        }
        // The first `for` outside angle brackets, before the body or a where clause.
        let mut depth = 0i32;
        let mut at = None;
        for j in start + 1..toks.len() {
            match &toks[j] {
                Token::Punct('<') => depth += 1,
                Token::Punct('>') if toks[j - 1] != Token::Punct('-') => depth -= 1,
                Token::Punct('{') | Token::Punct(';') if depth <= 0 => break,
                Token::Ident("where") if depth <= 0 => break,
                Token::Ident("for") if depth <= 0 => {
                    at = Some(j + 1);
                    break;
                }
                _ => {}
            }
        }
        let Some(mut j) = at else { continue };
        let mut referenced = false;
        loop {
            match toks.get(j) {
                Some(Token::Punct('&')) => referenced = true,
                Some(Token::Punct('*')) | Some(Token::PathSep) => {}
                Some(Token::Ident(word)) if ["mut", "dyn", "const"].contains(word) => {}
                // `&'a File`: the lexer leaves a lifetime's name as an identifier.
                Some(Token::Ident(_))
                    if referenced && matches!(toks.get(j + 1), Some(Token::Ident(_))) => {}
                _ => break,
            }
            j += 1;
        }
        let mut path = Vec::new();
        while let Some(Token::Ident(segment)) = toks.get(j) {
            path.push(segment.to_string());
            if toks.get(j + 1) != Some(&Token::PathSep) {
                break;
            }
            j += 2;
        }
        if !path.is_empty() {
            out.push(path);
        }
    }
    out
}

/// One file's scan: its sink labels, the bare flagged type names it implements a trait
/// for (`impl X for File`, unresolved by any `use`), and the types it defines.
#[derive(Default)]
struct FileScan {
    sinks: BTreeSet<String>,
    bare_impls: BTreeSet<String>,
    defined: BTreeSet<String>,
}

/// What a dependency's own library source reaches that a non-destructive declaration
/// must account for, by sink label:
///
/// - `.name(`: a method call whose name is a [`METHOD_SINKS`] pattern, whatever the
///   receiver;
/// - a std, Tokio or libc (or other reviewed crate's) path clippy.toml disallows, named
///   through any `use` alias;
/// - `impl for std::fs::File` and the like: a trait impl for a [`FLAGGED_IMPL_TYPES`]
///   type, or `impl for File` (and `OpenOptions`, `Child`, `Command`) when the bare name
///   is neither imported by a `use` nor a type the package defines (a glob import).
struct SinkScanner<'a> {
    disallowed: &'a BTreeSet<String>,
    /// Every proper prefix of a disallowed path, so a path is followed only as far as it
    /// could still name one.
    prefixes: BTreeSet<String>,
    /// Each disallowed path's segments, its crate first.
    segments: Vec<Vec<&'a str>>,
    needed: Vec<&'a str>,
    /// The first byte of any word worth a closer look.
    initial: [bool; 256],
    /// `needed` by first byte, with each word's index: a set lookup per word is too
    /// slow in a debug build.
    needed_by_initial: Vec<Vec<(&'a str, usize)>>,
    roots: BTreeSet<String>,
    impl_roots: BTreeSet<String>,
}

const FLAGGED_NAMES: [&str; 4] = ["File", "OpenOptions", "Child", "Command"];

impl<'a> SinkScanner<'a> {
    fn new(disallowed: &'a BTreeSet<String>) -> Self {
        let prefixes = disallowed
            .iter()
            .flat_map(|path| {
                let segments: Vec<&str> = path.split("::").collect();
                (1..segments.len()).map(move |n| segments[..n].join("::"))
            })
            .collect();
        let segments: Vec<Vec<&str>> = disallowed
            .iter()
            .map(|path| path.split("::").collect())
            .collect();
        let mut needed: BTreeSet<&str> = segments.iter().flatten().copied().collect();
        // A std path may be written through core or alloc.
        needed.extend(["core", "alloc"]);
        let mut initial = [false; 256];
        for word in needed
            .iter()
            .copied()
            .chain(METHOD_SINKS.iter().map(|(p, _)| p.trim_matches('*')))
            .chain(FLAGGED_NAMES)
            .chain(["for"])
        {
            initial[word.as_bytes()[0] as usize] = true;
        }
        let needed: Vec<&str> = needed.into_iter().collect();
        let mut needed_by_initial: Vec<Vec<(&str, usize)>> = vec![Vec::new(); 256];
        for (index, word) in needed.iter().enumerate() {
            needed_by_initial[word.as_bytes()[0] as usize].push((word, index));
        }
        let impl_roots: BTreeSet<String> = ["std", "core", "alloc", "tokio"]
            .into_iter()
            .map(String::from)
            .collect();
        let mut roots = impl_roots.clone();
        roots.extend(
            disallowed
                .iter()
                .map(|p| p.split("::").next().unwrap().to_string()),
        );
        SinkScanner {
            disallowed,
            prefixes,
            segments,
            needed,
            initial,
            needed_by_initial,
            roots,
            impl_roots,
        }
    }

    /// Whether a file could make a hit, from its raw text. Each hit is built from the
    /// file's own tokens, so a file passes only if it has one of:
    ///
    /// - a method-sink name with a `.` before it (whitespace, or a comment that might
    ///   hide one, between them);
    /// - a flagged type's name after `for` (references, `mut`, `dyn`, lifetimes and path
    ///   segments between them) or before `as` (an aliasing `use`);
    /// - every segment of some disallowed path, its crate included (`core` or `alloc`
    ///   for std).
    ///
    /// Strings and comments only add words, so the test is a superset of the scan's own;
    /// skipping a file only saves time (windows-sys alone is 18 MB).
    fn worth_lexing(&self, text: &str) -> bool {
        let bytes = text.as_bytes();
        let mut seen = vec![false; self.needed.len()];
        let mut at = 0;
        while at < bytes.len() {
            // The next word, by hand: this loop runs over every scanned byte.
            if !word_byte(bytes[at]) {
                at += 1;
                continue;
            }
            let start = at;
            while at < bytes.len() && word_byte(bytes[at]) {
                at += 1;
            }
            let first = bytes[start] as usize;
            if !self.initial[first] {
                continue;
            }
            let word = &text[start..at];
            let at = start;
            if method_sink(word) && dot_before(bytes, at) {
                return true;
            }
            if FLAGGED_NAMES.contains(&word) && word_after(bytes, at + word.len()) == Some("as") {
                return true;
            }
            if word == "for" && flagged_type_after(text, at + 3) {
                return true;
            }
            if let Some((_, index)) = self.needed_by_initial[first]
                .iter()
                .find(|(w, _)| *w == word)
            {
                seen[*index] = true;
            }
        }
        let seen = |word: &str| {
            self.needed
                .iter()
                .position(|w| *w == word)
                .is_some_and(|index| seen[index])
        };
        self.segments.iter().any(|path| {
            let root = match path[0] {
                "std" => ["std", "core", "alloc"].iter().any(|r| seen(r)),
                root => seen(root),
            };
            root && path[1..].iter().all(|segment| seen(segment))
        })
    }

    fn scan_file(&self, text: &str) -> FileScan {
        let mut out = FileScan::default();
        if !self.worth_lexing(text) {
            return out;
        }
        let toks = without_test_modules(tokens(text));
        out.defined = defined_types(&toks);
        // Method-form sinks.
        for (at, token) in toks.iter().enumerate() {
            if *token == Token::Punct('.')
                && let Some(Token::Ident(name)) = toks.get(at + 1)
                && matches!(toks.get(at + 2), Some(Token::Punct('(') | Token::PathSep))
                && method_sink(name)
            {
                out.sinks.insert(format!(".{name}("));
            }
        }
        // Disallowed paths.
        for path in rooted_paths_in(&toks, &self.roots) {
            let mut candidate = match path[0].as_str() {
                "core" | "alloc" => "std".to_string(),
                first => first.to_string(),
            };
            for segment in &path[1..] {
                if !self.prefixes.contains(&candidate) {
                    break;
                }
                candidate.push_str("::");
                candidate.push_str(segment);
                if self.disallowed.contains(&candidate) {
                    out.sinks.insert(candidate.clone());
                }
            }
        }
        // A glob import of a disallowed path's parent: `use std::fs::*;` then
        // `remove_file(p)` or `File::create(p)`. The name alone is enough to flag it.
        let (uses, paths) = uses_and_paths(&toks);
        let rooted = alias_map(&uses, &self.roots);
        let idents: BTreeSet<&str> = toks
            .iter()
            .filter_map(|t| match t {
                Token::Ident(word) => Some(*word),
                _ => None,
            })
            .collect();
        let named: BTreeSet<String> = paths.iter().map(|p| p.join("::")).collect();
        for glob in uses.iter().filter(|u| u.alias.is_none()) {
            let Some(parent) = resolve_path(&rooted, &self.roots, &glob.path) else {
                continue;
            };
            let parent = as_std(&parent.join("::"));
            for path in self.disallowed {
                let Some(rest) = path.strip_prefix(&format!("{parent}::")) else {
                    continue;
                };
                if idents.contains(rest) || named.contains(rest) {
                    out.sinks.insert(path.clone());
                }
            }
        }
        // Trait impls for std's and Tokio's file and process types.
        let aliases = alias_map(&uses, &self.impl_roots);
        for path in impl_self_types(&toks) {
            match resolve_path(&aliases, &self.impl_roots, &path).map(|p| as_std(&p.join("::"))) {
                Some(full) if FLAGGED_IMPL_TYPES.contains(&full.as_str()) => {
                    out.sinks.insert(format!("impl for {full}"));
                }
                None if path.len() == 1
                    && FLAGGED_NAMES.contains(&path[0].as_str())
                    && !uses
                        .iter()
                        .any(|u| u.alias.as_deref() == Some(path[0].as_str())) =>
                {
                    out.bare_impls.insert(path[0].clone());
                }
                _ => {}
            }
        }
        out
    }
}

/// One package's sinks, by label, with the files each is in, from its files' scans: a
/// bare `impl for File` counts unless the package defines its own `File`.
fn package_sinks(
    files: &[(String, String)],
    scans: &[&FileScan],
) -> BTreeMap<String, BTreeSet<String>> {
    let defined: BTreeSet<&String> = scans.iter().flat_map(|s| &s.defined).collect();
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for ((file, _), scan) in files.iter().zip(scans) {
        for sink in &scan.sinks {
            out.entry(sink.clone()).or_default().insert(file.clone());
        }
        for name in scan.bare_impls.iter().filter(|n| !defined.contains(n)) {
            out.entry(format!("impl for {name}"))
                .or_default()
                .insert(file.clone());
        }
    }
    out
}

/// Runs `f` over `items` on half the cores (the scan reads tens of megabytes of
/// dependency source in a debug test build; the other half stays with the suite's
/// timing-sensitive tests), keeping the order.
fn parallel_map<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let workers = (std::thread::available_parallelism().map_or(2, |n| n.get()) / 2)
        .clamp(1, items.len().max(1));
    let next = std::sync::atomic::AtomicUsize::new(0);
    let results: Vec<std::sync::Mutex<Option<R>>> =
        items.iter().map(|_| std::sync::Mutex::new(None)).collect();
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let at = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(item) = items.get(at) else { break };
                    *results[at].lock().unwrap() = Some(f(item));
                }
            });
        }
    });
    results
        .into_iter()
        .map(|r| r.into_inner().unwrap().unwrap())
        .collect()
}

/// The paths in [`IMPURE_PREFIXES`] a package's library source names, with the file.
fn impure_paths(files: &[(String, String)]) -> BTreeSet<String> {
    let roots: BTreeSet<String> = ["std", "core", "alloc", "libc", "tokio"]
        .into_iter()
        .map(String::from)
        .collect();
    let mut out = BTreeSet::new();
    for (file, text) in files {
        // Each prefix ends in one of these words, which a path to it must spell out.
        if !words(text).any(|w| ["fs", "process", "fd", "prelude", "libc"].contains(&w)) {
            continue;
        }
        for path in rooted_paths(text, &roots) {
            let full = as_std(&path.join("::"));
            if IMPURE_PREFIXES
                .iter()
                .any(|p| full == *p || full.starts_with(&format!("{p}::")))
            {
                out.insert(format!("{full} ({file})"));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------------
// The gate.

/// What the gate reads. `sources` is the workspace's production source (path label,
/// text); `package_sources` each locked package's own library source by `name@version`;
/// `resolve` what `cargo metadata` resolves (features, edge kinds, proc macros).
pub(super) struct Inputs {
    pub lock: String,
    pub manifests: Vec<(String, String)>,
    pub resolve: Resolve,
    pub sources: Vec<(String, String)>,
    pub package_sources: BTreeMap<String, Vec<(String, String)>>,
    pub gate: serde_json::Value,
    pub clippy: String,
}

fn strings(value: &serde_json::Value) -> Option<Vec<String>> {
    match value {
        serde_json::Value::String(s) => Some(vec![s.clone()]),
        serde_json::Value::Array(items) => items
            .iter()
            .map(|item| item.as_str().map(String::from))
            .collect(),
        _ => None,
    }
}

fn list(set: &BTreeSet<String>) -> String {
    serde_json::to_string(&set.iter().collect::<Vec<_>>()).unwrap()
}

fn text(value: &serde_json::Value) -> Option<&str> {
    value.as_str().filter(|s| !s.trim().is_empty())
}

/// A reviewed exception: hits of `sinks` in `package` at `version` with exactly
/// `features` do not refuse a declaration.
struct Exception {
    key: String,
    features: BTreeSet<String>,
    sinks: BTreeSet<String>,
}

/// Every violation of the gate, in words; none means it holds.
pub(super) fn violations(inputs: &Inputs) -> Vec<String> {
    let mut wrong = Vec::new();
    let lock = lock_entries(&inputs.lock);
    let resolve = &inputs.resolve;
    let graph = graph_kinds(resolve);
    let disallowed = clippy_paths(&inputs.clippy);
    let empty = BTreeSet::new();
    let features_of = |key: &str| resolve.packages.get(key).map_or(&empty, |p| &p.features);

    // The packages to review: everything in Cargo.lock outside the workspace.
    let member = |key: &str| resolve.packages.get(key).is_some_and(|p| p.member);
    let workspace_names: BTreeSet<&String> = lock
        .iter()
        .filter(|entry| member(&entry.key()))
        .map(|entry| &entry.name)
        .collect();
    let locked: BTreeMap<String, &LockEntry> = lock
        .iter()
        .filter(|entry| !member(&entry.key()))
        .map(|entry| (entry.key(), entry))
        .collect();
    let mut by_name: BTreeMap<&str, Vec<&String>> = BTreeMap::new();
    for (key, entry) in &locked {
        by_name.entry(entry.name.as_str()).or_default().push(key);
    }
    let raw_underneath = |key: &str| {
        let name = key.split('@').next().unwrap();
        raw_or_native(name)
            || resolve.packages.get(key).is_some_and(|p| {
                p.deps
                    .keys()
                    .any(|d| raw_or_native(d.split('@').next().unwrap()))
            })
            || locked.get(key).is_some_and(|entry| {
                entry
                    .dependencies
                    .iter()
                    .any(|d| raw_or_native(d.split(' ').next().unwrap()))
            })
    };

    // The manifests' direct dependencies and the kind each one has.
    let mut manifest_kinds: BTreeMap<String, BTreeSet<DependencyKind>> = BTreeMap::new();
    for (crate_name, manifest) in &inputs.manifests {
        match manifest_dependencies(manifest) {
            Ok(dependencies) => {
                for (name, kind) in dependencies {
                    if !workspace_names.contains(&name) {
                        manifest_kinds.entry(name).or_default().insert(kind);
                    }
                }
            }
            Err(error) => wrong.push(format!("{crate_name}/Cargo.toml: {error}")),
        }
    }
    let manifest_kind = |name: &str| {
        manifest_kinds.get(name).map(|kinds| {
            if kinds.contains(&DependencyKind::Normal) {
                "runtime"
            } else if kinds.contains(&DependencyKind::Build) {
                "build-only"
            } else {
                "dev-only"
            }
        })
    };
    // Each direct dependency's key: the gate maps paths to crates by name, so a direct
    // dependency is locked at one version.
    let mut direct: BTreeMap<String, String> = BTreeMap::new();
    for name in manifest_kinds.keys() {
        match by_name.get(name.as_str()).map(Vec::as_slice) {
            Some([key]) => {
                direct.insert(name.clone(), (*key).clone());
            }
            Some(keys) => wrong.push(format!(
                "{name} is a direct dependency locked at {} versions ({}); the gate maps paths to crates by name, so lock one",
                keys.len(),
                keys.iter().map(|k| k.as_str()).collect::<Vec<_>>().join(", ")
            )),
            None => wrong.push(format!(
                "{name} is a direct dependency of the workspace that Cargo.lock does not lock"
            )),
        }
    }
    let direct_keys: BTreeSet<&String> = direct.values().collect();

    // The file's shape.
    if let Some(object) = inputs.gate.as_object() {
        for key in object.keys() {
            if !SECTIONS.contains(&key.as_str()) {
                wrong.push(format!(
                    "dependency-gate.json has an unknown section {key:?}"
                ));
            }
        }
    } else {
        wrong.push("dependency-gate.json is not an object".into());
    }
    let section = |key: &str| -> BTreeMap<String, serde_json::Value> {
        inputs.gate[key]
            .as_object()
            .map(|o| o.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default()
    };
    let (groups, entries) = (section("groups"), section("packages"));
    for (group, why) in &groups {
        if text(why).is_none() {
            wrong.push(format!("group {group} gives no shared justification"));
        }
    }

    // Every locked package is reviewed at its exact version, checksum and features.
    for (key, entry) in &locked {
        if entry
            .source
            .as_deref()
            .is_none_or(|s| !s.starts_with("registry+"))
            || entry.checksum.is_none()
        {
            wrong.push(format!(
                "{key} is not a registry package with a Cargo.lock checksum: the gate pins each review to a checksum, so path and git dependencies outside the workspace are refused"
            ));
        }
        if !resolve.packages.contains_key(key) {
            wrong.push(format!(
                "{key} is in Cargo.lock but cargo metadata did not resolve it"
            ));
        }
        if !entries.contains_key(key) {
            wrong.push(format!(
                "{key} is in Cargo.lock with no reviewed entry under `packages` in dependency-gate.json: review it (scripts/dependency-gate-review.py drafts the entry; its capability and justification are a person's)"
            ));
        }
    }

    // Each decision: complete, consistent with the lock, the resolve and the manifests.
    let mut capabilities: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut quiet: BTreeSet<String> = BTreeSet::new();
    for (key, entry) in &entries {
        let Some(object) = entry.as_object() else {
            wrong.push(format!("`packages` entry {key} is not an object"));
            continue;
        };
        for field in object.keys() {
            if !ENTRY_FIELDS.contains(&field.as_str()) {
                wrong.push(format!("{key} has an unknown field {field:?}"));
            }
        }
        let Some(locked_entry) = locked.get(key) else {
            wrong.push(format!(
                "`packages` entry {key} is not in Cargo.lock; drop it (a new version needs its own review)"
            ));
            continue;
        };
        let name = locked_entry.name.as_str();
        let is_direct = direct_keys.contains(key);
        match (entry["checksum"].as_str(), &locked_entry.checksum) {
            (Some(reviewed), Some(actual)) if reviewed == actual => {}
            (reviewed, actual) => wrong.push(format!(
                "{key}'s reviewed checksum {} is not Cargo.lock's {}: review the new source",
                reviewed.unwrap_or("(none)"),
                actual.as_deref().unwrap_or("(none)")
            )),
        }
        let actual = features_of(key);
        match strings(&entry["features"]) {
            Some(reviewed) if entry["features"].is_array() => {
                let reviewed: BTreeSet<String> = reviewed.into_iter().collect();
                if &reviewed != actual {
                    wrong.push(format!(
                        "{key}'s reviewed features {} are not the resolved features {}: review the change",
                        list(&reviewed),
                        list(actual)
                    ));
                }
            }
            _ => wrong.push(format!(
                "{key} needs `features`, the list cargo resolves for it: {}",
                list(actual)
            )),
        }
        match (text(&entry["why"]), entry["group"].as_str()) {
            (Some(_), None) => {}
            (None, Some(group)) if groups.contains_key(group) => {}
            (None, Some(group)) => wrong.push(format!("{key} names an unknown group {group:?}")),
            (Some(_), Some(_)) => wrong.push(format!(
                "{key} gives both its own reason and a group; keep one"
            )),
            (None, None) => wrong.push(format!(
                "{key} gives no reason (`why`, or a `group` with a shared one)"
            )),
        }
        let derived = if is_direct {
            manifest_kind(name)
        } else {
            graph.kinds.get(key).copied()
        };
        match (entry["kind"].as_str(), derived) {
            (Some(kind), Some(derived)) if KINDS.contains(&kind) => {
                if kind != derived {
                    wrong.push(format!(
                        "{key} is declared {kind}, but the {} it {derived}",
                        if is_direct {
                            "workspace manifests make"
                        } else {
                            "dependency graph makes"
                        }
                    ));
                }
            }
            (_, None) => wrong.push(format!("{key} is not reachable from any workspace crate")),
            _ => wrong.push(format!(
                "{key} needs a `kind`: one of runtime, build-only or dev-only"
            )),
        }
        let declared: BTreeSet<String> = match strings(&entry["capability"]) {
            Some(list) if !list.is_empty() => list.into_iter().collect(),
            _ => {
                wrong.push(format!(
                    "{key} needs a reviewed `capability`: none, or a set of {}",
                    CAPABILITIES[1..].join(", ")
                ));
                continue;
            }
        };
        for capability in &declared {
            if !CAPABILITIES.contains(&capability.as_str()) {
                wrong.push(format!(
                    "{key} declares an unknown capability {capability:?}"
                ));
            }
        }
        if declared.contains("none") && declared.len() > 1 {
            wrong.push(format!(
                "{key} declares `none` together with other capabilities"
            ));
        }
        let none = declared.iter().all(|c| c == "none");
        let destructive_capable = declared
            .iter()
            .any(|c| DESTRUCTIVE_CAPABILITIES.contains(&c.as_str()));
        // Cargo.lock may require more, never less.
        if raw_or_native(name) && !declared.contains("syscalls") {
            wrong.push(format!(
                "{key} is a raw system-call crate: its capability must include `syscalls`"
            ));
        }
        let raw_use = text(&entry["raw_use"]);
        if raw_underneath(key) && !raw_or_native(name) && none && raw_use.is_none() {
            wrong.push(format!(
                "Cargo.lock shows a raw system-call crate under {key}: declare a non-`none` capability, or record in `raw_use` what it uses the raw crate for"
            ));
        }
        if !entry["raw_use"].is_null() && (!raw_underneath(key) || raw_or_native(name) || !none) {
            wrong.push(format!(
                "{key}'s `raw_use` applies only to a `none` package over a raw system-call crate; drop it"
            ));
        }
        if let Some(group) = entry["group"].as_str()
            && (!none || raw_underneath(key) || !entry["raw_use"].is_null())
        {
            wrong.push(format!(
                "{key} is grouped under {group:?}, but a group is only for `none` packages with no raw system-call crate underneath; give it its own justification"
            ));
        }
        // Destructive paths: only a direct dependency can be named by the workspace, so
        // only one lists them.
        let listed: BTreeSet<String> = match &entry["destructive"] {
            serde_json::Value::Null => BTreeSet::new(),
            value => match strings(value) {
                Some(list) if value.is_array() => list.into_iter().collect(),
                _ => {
                    wrong.push(format!("{key}'s `destructive` is not a list of paths"));
                    BTreeSet::new()
                }
            },
        };
        let no_destructive_api = text(&entry["no_destructive_api"]);
        let root = name.replace('-', "_");
        if !is_direct && !entry["destructive"].is_null() {
            wrong.push(format!(
                "{key} is not a direct dependency: the workspace cannot name its paths, so it lists none (a direct dependency that re-exports them lists them under its own name)"
            ));
        }
        if destructive_capable {
            if is_direct
                && listed.is_empty()
                && (no_destructive_api.is_none() || raw_or_native(name))
            {
                wrong.push(format!(
                    "{name} declares {}: list its destructive paths (and disallow them in clippy.toml){}",
                    declared.iter().cloned().collect::<Vec<_>>().join(", "),
                    if raw_or_native(name) {
                        ""
                    } else {
                        ", or record in `no_destructive_api` why its API has none"
                    }
                ));
            }
            if !listed.is_empty() && !entry["no_destructive_api"].is_null() {
                wrong.push(format!(
                    "{name} lists destructive paths and claims `no_destructive_api`"
                ));
            }
            if raw_or_native(name) && !entry["no_destructive_api"].is_null() {
                wrong.push(format!(
                    "{key} is a raw system-call crate and cannot claim `no_destructive_api`"
                ));
            }
        } else {
            if !listed.is_empty() {
                wrong.push(format!(
                    "{name} lists destructive paths but declares no destructive-capable category"
                ));
            }
            if !entry["no_destructive_api"].is_null() {
                wrong.push(format!(
                    "{key}'s `no_destructive_api` applies only to a destructive-capable category; drop it"
                ));
            }
        }
        if is_direct {
            for path in &listed {
                if !path.starts_with(&format!("{root}::")) {
                    wrong.push(format!(
                        "{name}'s destructive {path} is not a path in {root}"
                    ));
                }
                if !disallowed.contains(path) {
                    wrong.push(format!(
                        "{name}'s destructive {path} is not disallowed in clippy.toml"
                    ));
                }
            }
            for path in disallowed
                .iter()
                .filter(|p| p.starts_with(&format!("{root}::")))
            {
                if !listed.contains(path) {
                    wrong.push(format!(
                        "clippy.toml disallows {path}, which {name}'s entry does not list"
                    ));
                }
            }
        }
        // LOW-1: a direct build-only or dev-only dependency the runtime graph also
        // reaches (h2 under tonic) records `runtime_via`, and its review is a runtime one.
        let parents = graph.runtime_parents.get(key);
        let via = entry["runtime_via"].as_str();
        match entry["kind"].as_str() {
            Some(kind @ ("build-only" | "dev-only")) if is_direct => {
                if let Some(parents) = parents
                    && !via.is_some_and(|via| parents.iter().any(|p| p.split('@').next() == Some(via)))
                {
                    wrong.push(format!(
                        "{name} is declared {kind}, but Cargo.lock reaches it from the runtime dependencies (through {}); record `runtime_via` if that is intended",
                        parents.iter().map(|p| p.split('@').next().unwrap()).collect::<Vec<_>>().join(", ")
                    ));
                } else if parents.is_none() && via.is_some() {
                    wrong.push(format!(
                        "{name}'s `runtime_via` is stale: Cargo.lock does not reach it from the runtime dependencies"
                    ));
                }
            }
            _ if !entry["runtime_via"].is_null() => wrong.push(format!(
                "{key}'s `runtime_via` applies only to a direct build-only or dev-only dependency; drop it"
            )),
            _ => {}
        }
        if !destructive_capable || no_destructive_api.is_some() {
            quiet.insert(key.clone());
        }
        capabilities.insert(key.clone(), declared);
    }
    // clippy.toml names only std and reviewed direct dependencies.
    for path in &disallowed {
        let krate = path.split("::").next().unwrap();
        if !["std", "core", "alloc"].contains(&krate)
            && !direct.keys().any(|name| name.replace('-', "_") == krate)
        {
            wrong.push(format!(
                "clippy.toml disallows {path}, but {krate} is not a reviewed direct dependency"
            ));
        }
    }

    // Production names no destructive-looking function through a direct dependency's
    // path that clippy.toml does not disallow (clippy resolves methods; this catches a
    // free function or associated function under a name clippy does not know).
    let roots: BTreeMap<String, String> = direct
        .iter()
        .map(|(name, key)| (name.replace('-', "_"), key.clone()))
        .collect();
    let root_set: BTreeSet<String> = roots.keys().cloned().collect();
    for (label, source) in &inputs.sources {
        for path in rooted_paths(source, &root_set) {
            let key = &roots[&path[0]];
            let name = key.split('@').next().unwrap();
            let declared = capabilities.get(key);
            if path.last().is_some_and(|s| s == "*") && quiet.contains(key) {
                wrong.push(format!(
                    "{label}: a glob import of {} hides its names from the gate; import them by name",
                    path[..path.len() - 1].join("::")
                ));
                continue;
            }
            for k in 1..path.len() {
                if let Some(pattern) = destructive_name(&path[k], name != "libc") {
                    let candidate = path[..=k].join("::");
                    if !disallowed.contains(&candidate) {
                        wrong.push(format!(
                            "{label}: production names {candidate}, which looks destructive (`{pattern}`) but clippy.toml does not disallow it; {name} is declared `{}`: review its capability and list its destructive paths",
                            declared
                                .map(|c| c.iter().cloned().collect::<Vec<_>>().join(", "))
                                .unwrap_or_default()
                        ));
                    }
                    break;
                }
            }
        }
    }

    // Reviewed exceptions, each scoped to one package, version and feature set.
    let mut exceptions = Vec::new();
    match &inputs.gate["sink_exceptions"] {
        serde_json::Value::Null => {}
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                let Some(object) = item.as_object() else {
                    wrong.push(format!("sink exception {index} is not an object"));
                    continue;
                };
                for field in object.keys() {
                    if !EXCEPTION_FIELDS.contains(&field.as_str()) {
                        wrong.push(format!(
                            "sink exception {index} has an unknown field {field:?}"
                        ));
                    }
                }
                let (Some(package), Some(version)) =
                    (item["package"].as_str(), item["version"].as_str())
                else {
                    wrong.push(format!(
                        "sink exception {index} needs its `package` and `version`"
                    ));
                    continue;
                };
                let key = format!("{package}@{version}");
                let features: Option<BTreeSet<String>> = strings(&item["features"])
                    .filter(|_| item["features"].is_array())
                    .map(|f| f.into_iter().collect());
                let sinks: BTreeSet<String> = strings(&item["sinks"])
                    .filter(|_| item["sinks"].is_array())
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                if text(&item["why"]).is_none() {
                    wrong.push(format!("the sink exception for {key} gives no reason"));
                }
                if sinks.is_empty() {
                    wrong.push(format!("the sink exception for {key} names no `sinks`"));
                }
                if !locked.contains_key(&key) {
                    wrong.push(format!(
                        "the sink exception for {key} is stale: Cargo.lock does not lock {key}; drop it"
                    ));
                    continue;
                }
                let Some(features) = features else {
                    wrong.push(format!(
                        "the sink exception for {key} needs `features`, the exact set it was reviewed with"
                    ));
                    continue;
                };
                if &features != features_of(&key) {
                    wrong.push(format!(
                        "the sink exception for {key} is scoped to features {}, but cargo resolves {}: it does not apply until it is re-reviewed",
                        list(&features),
                        list(features_of(&key))
                    ));
                }
                exceptions.push(Exception {
                    key,
                    features,
                    sinks,
                });
            }
        }
        _ => wrong.push("`sink_exceptions` is not a list".into()),
    }

    // The B7 milestone 2 recheck: a package declared `none`, `network` or
    // `no_destructive_api` (in the runtime graph, or a direct dependency) holds for its
    // whole runtime dependency subtree. Every package in it is scanned for method-form
    // sinks, disallowed paths and trait impls on std's and Tokio's file and process types.
    let scoped: Vec<&String> = quiet
        .iter()
        .filter(|key| graph.kinds.get(*key) == Some(&"runtime") || direct_keys.contains(key))
        .collect();
    let mut subtrees: BTreeMap<&String, BTreeSet<String>> = BTreeMap::new();
    for key in &scoped {
        let mut seen = BTreeSet::from([(*key).clone()]);
        let mut stack = vec![(*key).clone()];
        while let Some(at) = stack.pop() {
            let Some(package) = resolve.packages.get(&at) else {
                continue;
            };
            for (dep, kinds) in &package.deps {
                let skip = resolve
                    .packages
                    .get(dep)
                    .is_none_or(|p| p.member || p.proc_macro);
                if kinds.contains(&DependencyKind::Normal) && !skip && seen.insert(dep.clone()) {
                    stack.push(dep.clone());
                }
            }
        }
        subtrees.insert(key, seen);
    }
    let scanned: BTreeSet<&String> = subtrees.values().flatten().collect();
    let mut used = vec![BTreeSet::<String>::new(); exceptions.len()];
    // (package, sink) → files, for hits no exception covers.
    let mut open: BTreeMap<&String, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new();
    let scanner = SinkScanner::new(&disallowed);
    let mut work: Vec<(&String, usize, usize)> = Vec::new();
    for key in &scanned {
        match inputs.package_sources.get(*key) {
            Some(files) => work.extend(
                files
                    .iter()
                    .enumerate()
                    .map(|(at, (_, text))| (*key, at, text.len())),
            ),
            None => wrong.push(format!("{key}'s locked source was not available to scan")),
        }
    }
    // Largest files first, for an even spread across cores.
    work.sort_by_key(|(_, _, size)| std::cmp::Reverse(*size));
    let scans = parallel_map(&work, |(key, at, _)| {
        scanner.scan_file(&inputs.package_sources[*key][*at].1)
    });
    let mut by_package: BTreeMap<&String, Vec<(usize, &FileScan)>> = BTreeMap::new();
    for ((key, at, _), scan) in work.iter().zip(&scans) {
        by_package.entry(*key).or_default().push((*at, scan));
    }
    for (key, mut file_scans) in by_package {
        file_scans.sort_by_key(|(at, _)| *at);
        let files = &inputs.package_sources[key];
        let scans: Vec<&FileScan> = file_scans.iter().map(|(_, scan)| *scan).collect();
        for (sink, files) in package_sinks(files, &scans) {
            let covered = exceptions.iter().position(|e| {
                &e.key == key && &e.features == features_of(key) && e.sinks.contains(&sink)
            });
            match covered {
                Some(at) => {
                    used[at].insert(sink);
                }
                None => {
                    open.entry(key).or_default().insert(sink, files);
                }
            }
        }
    }
    for (index, exception) in exceptions.iter().enumerate() {
        if !scanned.contains(&exception.key) {
            if locked.contains_key(&exception.key) {
                wrong.push(format!(
                    "the sink exception for {} is stale: no non-destructive declaration's runtime subtree includes it; drop it",
                    exception.key
                ));
            }
            continue;
        }
        for sink in exception.sinks.difference(&used[index]) {
            if &exception.features == features_of(&exception.key) {
                wrong.push(format!(
                    "the sink exception for {} names {sink}, which its source does not reach; drop it",
                    exception.key
                ));
            }
        }
    }
    for key in &scoped {
        let mut reached = Vec::new();
        for package in &subtrees[key] {
            if let Some(hits) = open.get(package) {
                for (sink, files) in hits {
                    reached.push(format!(
                        "`{sink}` in {package} ({})",
                        files.iter().cloned().collect::<Vec<_>>().join(", ")
                    ));
                }
            }
        }
        if reached.is_empty() {
            continue;
        }
        let entry = &entries[*key];
        wrong.push(format!(
            "{key} is declared `{}`{}, but its runtime subtree reaches {}: declare its capability, or record each reviewed exception in `sink_exceptions` ({})",
            capabilities[*key].iter().cloned().collect::<Vec<_>>().join(", "),
            if entry["no_destructive_api"].is_null() {
                ""
            } else {
                " with no destructive API"
            },
            reached.join("; "),
            open.iter()
                .filter(|(package, _)| subtrees[key].contains(**package))
                .map(|(package, hits)| {
                    let (name, version) = package.split_once('@').unwrap();
                    serde_json::json!({
                        "package": name,
                        "version": version,
                        "features": features_of(package),
                        "sinks": hits.keys().collect::<Vec<_>>(),
                    })
                    .to_string()
                })
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    // A shared justification holds only for packages that name no file, process or raw
    // system-call path at all.
    let grouped: Vec<(&String, &str)> = entries
        .iter()
        .filter_map(|(key, entry)| Some((key, entry["group"].as_str()?)))
        .collect();
    let purity = parallel_map(&grouped, |(key, _)| {
        inputs
            .package_sources
            .get(*key)
            .map(|files| impure_paths(files))
    });
    for ((key, group), impure) in grouped.iter().zip(purity) {
        match impure {
            Some(impure) if !impure.is_empty() => wrong.push(format!(
                "{key} is grouped under {group:?}, but its source names {}: give it its own justification",
                impure.into_iter().collect::<Vec<_>>().join(", ")
            )),
            Some(_) => {}
            None => wrong.push(format!(
                "{key}'s locked source was not available to check its group"
            )),
        }
    }
    wrong
}

// ---------------------------------------------------------------------------------
// The workspace as it is: the actual source loader.

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The workspace the gate test checks: this one, unless `KILND_DEPENDENCY_GATE_ROOT`
/// names another. Only `scripts/dependency-gate-regressions.sh` sets it, to run this same
/// test binary, and so this same loader, against its fixture copies of the workspace.
fn gate_root() -> PathBuf {
    std::env::var_os("KILND_DEPENDENCY_GATE_ROOT").map_or_else(workspace_root, PathBuf::from)
}

#[cfg(test)]
// Approved (design 7.1): the dependency gate asks cargo itself for the resolved
// features, edge kinds and each package's extracted source; `cargo metadata` reads and
// downloads, and changes nothing outside cargo's own cache.
#[allow(clippy::disallowed_methods)]
fn cargo_metadata(root: &Path) -> Result<serde_json::Value, String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    // From the workspace itself, so its own `.cargo/config.toml` (a vendored source, in
    // the regression script's fixtures) applies.
    let output = std::process::Command::new(cargo)
        .current_dir(root)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--all-features",
        ])
        .arg("--manifest-path")
        .arg(root.join("Cargo.toml"))
        .output()
        .map_err(|e| format!("cargo metadata: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|e| format!("cargo metadata: {e}"))
}

/// This workspace's resolve, once per test binary.
fn workspace_resolve() -> &'static Resolve {
    static RESOLVE: std::sync::OnceLock<Resolve> = std::sync::OnceLock::new();
    RESOLVE.get_or_init(|| parse_metadata(&cargo_metadata(&workspace_root()).unwrap()).unwrap())
}

/// The extracted source directory of each locked version of `name` (cargo verified it
/// against Cargo.lock's checksum when it downloaded it).
fn locked_source(name: &str) -> Vec<(String, PathBuf)> {
    workspace_resolve()
        .packages
        .iter()
        .filter(|(key, _)| key.split('@').next() == Some(name))
        .filter_map(|(key, package)| {
            Some((key.split('@').nth(1)?.to_string(), package.root.clone()?))
        })
        .collect()
}

/// A package's own library source files: every `.rs` file under its library target's
/// directory, except the package's `tests`, `examples`, `benches` and `src/bin`
/// directories and the root file of any other target (a build script beside a
/// root-level `lib.rs`). Test files inside the library directory are read: only inline
/// `#[cfg(test)]` modules are skipped, by the scan itself.
fn library_files(dir: &Path, package: Option<&Path>, others: &BTreeSet<PathBuf>) -> Vec<PathBuf> {
    let skip: Vec<PathBuf> = package
        .map(|root| {
            ["tests", "examples", "benches", "target", "src/bin"]
                .iter()
                .map(|d| root.join(d))
                .collect()
        })
        .unwrap_or_default();
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(directory) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if !skip.contains(&path) {
                    stack.push(path);
                }
            } else if path.extension().is_some_and(|e| e == "rs") && !others.contains(&path) {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The workspace's production source: each crate's `src` (test modules and test files
/// excluded) and build script.
fn workspace_sources(root: &Path) -> Vec<(String, String)> {
    let mut sources = Vec::new();
    for krate in std::fs::read_dir(root.join("crates")).unwrap() {
        let krate = krate.unwrap().path();
        let name = krate.file_name().unwrap().to_string_lossy().into_owned();
        let mut files = rust_files(&krate.join("src"), true);
        if krate.join("build.rs").is_file() {
            files.push(krate.join("build.rs"));
        }
        for path in files {
            let relative = path
                .strip_prefix(&krate)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            sources.push((
                format!("{name}/{relative}"),
                production_part(&read(&path)).to_string(),
            ));
        }
    }
    sources
}

/// Everything the gate reads, for the workspace at `root`: its manifests, Cargo.lock,
/// dependency-gate.json, clippy.toml and production source, cargo's resolve, and the
/// library source of every locked package outside the workspace.
fn inputs_at(root: &Path) -> Inputs {
    let mut manifests = Vec::new();
    for krate in std::fs::read_dir(root.join("crates")).unwrap() {
        let krate = krate.unwrap().path();
        if let Ok(text) = std::fs::read_to_string(krate.join("Cargo.toml")) {
            manifests.push((
                krate.file_name().unwrap().to_string_lossy().into_owned(),
                text,
            ));
        }
    }
    assert!(
        manifests.len() >= 6,
        "the workspace's crates were not found"
    );
    let resolve = if root == workspace_root() {
        workspace_resolve().clone()
    } else {
        parse_metadata(&cargo_metadata(root).unwrap()).unwrap()
    };
    let mut package_sources = BTreeMap::new();
    for (key, package) in resolve.packages.iter().filter(|(_, p)| !p.member) {
        let Some((dir, others)) = &package.library else {
            continue;
        };
        let files: Vec<(String, String)> = library_files(dir, package.root.as_deref(), others)
            .into_iter()
            .map(|path| {
                let base = package
                    .root
                    .as_deref()
                    .filter(|r| path.starts_with(r))
                    .unwrap_or(dir);
                let label = format!(
                    "{}/{}",
                    key.replace('@', "-"),
                    path.strip_prefix(base).unwrap().display()
                );
                let text = std::fs::read(&path)
                    .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                    .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
                (label, text)
            })
            .collect();
        if !files.is_empty() {
            package_sources.insert(key.clone(), files);
        }
    }
    Inputs {
        lock: read(&root.join("Cargo.lock")),
        manifests,
        resolve,
        sources: workspace_sources(root),
        package_sources,
        gate: serde_json::from_str(&read(&root.join("dependency-gate.json")))
            .expect("dependency-gate.json is not JSON"),
        clippy: read(&root.join("clippy.toml")),
    }
}

/// HIGH-1: the gate holds for the workspace as it is.
#[test]
fn the_dependency_gate_holds() {
    let root = gate_root();
    let wrong = violations(&inputs_at(&root));
    assert!(
        wrong.is_empty(),
        "the dependency gate fails for {}:\n{}",
        root.display(),
        wrong.join("\n")
    );
}

// ---------------------------------------------------------------------------------
// MEDIUM-1: the destructive lists are complete.

/// The locked libc's exported functions (`pub fn`, in any target's module), from the
/// registry source of the version Cargo.lock pins.
fn locked_libc_functions() -> BTreeSet<String> {
    let lock = read(&workspace_root().join("Cargo.lock"));
    assert!(
        locked_versions(&lock).contains_key("libc"),
        "libc is not locked"
    );
    let mut names = BTreeSet::new();
    for (_, source) in locked_source("libc") {
        for path in rust_files(&source.join("src"), false) {
            let text = read(&path);
            let toks = tokens(&text);
            for (index, token) in toks.iter().enumerate() {
                if *token == Token::Ident("fn")
                    && let Some(Token::Ident(name)) = toks.get(index + 1)
                {
                    // `pub fn`, `pub unsafe fn`, `pub const fn`, `pub safe fn` and the like.
                    let public =
                        toks[index.saturating_sub(4)..index].contains(&Token::Ident("pub"));
                    if public {
                        names.insert(name.to_string());
                    }
                }
            }
        }
    }
    assert!(
        names.len() > 1000,
        "libc's functions were not found: {}",
        names.len()
    );
    names
}

/// MEDIUM-1: every locked libc function matching a destructive pattern is disallowed.
/// libc exports thousands of functions across targets; equality of two hand-written
/// lists is not completeness, so this reads them from the pinned source.
#[test]
fn every_destructive_libc_function_is_disallowed() {
    let disallowed = clippy_paths(&read(&workspace_root().join("clippy.toml")));
    let functions = locked_libc_functions();
    for known in [
        "kill", "unlinkat", "creat", "execl", "popen", "sigqueue", "mount",
    ] {
        assert!(functions.contains(known), "libc's {known} was not found");
    }
    let missing: Vec<String> = functions
        .iter()
        .filter(|name| DESTRUCTIVE_NAMES.iter().any(|p| matches_pattern(name, p)))
        .map(|name| format!("libc::{name}"))
        .filter(|path| !disallowed.contains(path))
        .collect();
    assert!(
        missing.is_empty(),
        "destructive libc functions missing from clippy.toml (and libc's dependency-gate.json list):\n{}",
        missing.join("\n")
    );
}

/// Whether a path of std's or Tokio's surface is destructive: gated by clippy.toml, or
/// reviewed and not gated, with why.
enum Review {
    Destructive,
    Safe(&'static str),
}
use Review::{Destructive, Safe};

const CREATES_ONLY: &str = "creates a new name, fails if it exists or replaces nothing";
const READS: &str = "reads only";
const METADATA: &str =
    "changes metadata of a descriptor or name it was given, never contents or names";

/// MEDIUM-1's curated std surface. std's source is not a Cargo.lock input, so this list
/// is the reviewed record, re-read at each toolchain bump: every public function of
/// `std::fs` and `std::process`, and the Unix extensions that delete, replace or run.
const STD_SURFACE: [(&str, Review); 47] = [
    ("std::fs::canonicalize", Safe(READS)),
    ("std::fs::copy", Destructive),
    ("std::fs::create_dir", Safe(CREATES_ONLY)),
    ("std::fs::create_dir_all", Safe(CREATES_ONLY)),
    ("std::fs::exists", Safe(READS)),
    ("std::fs::hard_link", Safe(CREATES_ONLY)),
    ("std::fs::metadata", Safe(READS)),
    ("std::fs::read", Safe(READS)),
    ("std::fs::read_dir", Safe(READS)),
    ("std::fs::read_link", Safe(READS)),
    ("std::fs::read_to_string", Safe(READS)),
    ("std::fs::remove_dir", Destructive),
    ("std::fs::remove_dir_all", Destructive),
    ("std::fs::remove_file", Destructive),
    ("std::fs::rename", Destructive),
    ("std::fs::set_permissions", Safe(METADATA)),
    ("std::fs::soft_link", Safe(CREATES_ONLY)),
    ("std::fs::symlink_metadata", Safe(READS)),
    ("std::fs::write", Destructive),
    ("std::fs::File::create", Destructive),
    ("std::fs::File::create_new", Safe(CREATES_ONLY)),
    (
        "std::fs::File::open",
        Safe("opens; writing needs OpenOptions, whose truncate is gated"),
    ),
    ("std::fs::File::options", Safe("an OpenOptions builder")),
    ("std::fs::File::set_len", Destructive),
    ("std::fs::File::set_permissions", Safe(METADATA)),
    ("std::fs::File::set_times", Safe(METADATA)),
    ("std::fs::File::set_modified", Safe(METADATA)),
    ("std::fs::File::sync_all", Safe("flushes")),
    ("std::fs::File::lock", Safe("an advisory lock")),
    ("std::fs::OpenOptions::truncate", Destructive),
    (
        "std::fs::OpenOptions::create",
        Safe("O_CREAT without truncation"),
    ),
    ("std::fs::OpenOptions::create_new", Safe(CREATES_ONLY)),
    (
        "std::fs::OpenOptions::write",
        Safe("in-place writes to a file the caller opened; truncation and replacement are gated"),
    ),
    ("std::fs::OpenOptions::append", Safe("appends only")),
    ("std::fs::DirBuilder::create", Safe(CREATES_ONLY)),
    ("std::os::unix::fs::symlink", Safe(CREATES_ONLY)),
    ("std::os::unix::fs::chown", Safe(METADATA)),
    ("std::os::unix::fs::lchown", Safe(METADATA)),
    ("std::os::unix::fs::fchown", Safe(METADATA)),
    ("std::os::unix::fs::chroot", Safe("this process's own root")),
    ("std::process::Command::new", Destructive),
    ("std::process::Child::kill", Destructive),
    ("std::os::unix::process::CommandExt::exec", Destructive),
    (
        "std::process::exit",
        Safe("ends this process only; never another"),
    ),
    (
        "std::process::abort",
        Safe("ends this process only; never another"),
    ),
    ("std::process::id", Safe(READS)),
    (
        "std::process::Child::wait",
        Safe("every other Child and Command method needs a Command, gated at Command::new"),
    ),
];

/// MEDIUM-1's `tokio::fs` review: each public function of the locked Tokio's `fs`
/// module, by (file, name). The test reads the locked source and fails on a function
/// this table does not classify.
const TOKIO_FS: [(&str, &str, &str, Review); 46] = [
    (
        "canonicalize.rs",
        "canonicalize",
        "tokio::fs::canonicalize",
        Safe(READS),
    ),
    ("copy.rs", "copy", "tokio::fs::copy", Destructive),
    (
        "create_dir.rs",
        "create_dir",
        "tokio::fs::create_dir",
        Safe(CREATES_ONLY),
    ),
    (
        "create_dir_all.rs",
        "create_dir_all",
        "tokio::fs::create_dir_all",
        Safe(CREATES_ONLY),
    ),
    (
        "dir_builder.rs",
        "new",
        "tokio::fs::DirBuilder::new",
        Safe("a builder"),
    ),
    (
        "dir_builder.rs",
        "recursive",
        "tokio::fs::DirBuilder::recursive",
        Safe("a builder"),
    ),
    (
        "dir_builder.rs",
        "mode",
        "tokio::fs::DirBuilder::mode",
        Safe("a builder"),
    ),
    (
        "dir_builder.rs",
        "create",
        "tokio::fs::DirBuilder::create",
        Safe(CREATES_ONLY),
    ),
    ("file.rs", "create", "tokio::fs::File::create", Destructive),
    (
        "file.rs",
        "create_new",
        "tokio::fs::File::create_new",
        Safe(CREATES_ONLY),
    ),
    (
        "file.rs",
        "open",
        "tokio::fs::File::open",
        Safe("opens; truncation is gated"),
    ),
    (
        "file.rs",
        "options",
        "tokio::fs::File::options",
        Safe("an OpenOptions builder"),
    ),
    (
        "file.rs",
        "from_std",
        "tokio::fs::File::from_std",
        Safe("wraps a descriptor"),
    ),
    (
        "file.rs",
        "into_std",
        "tokio::fs::File::into_std",
        Safe("unwraps a descriptor"),
    ),
    (
        "file.rs",
        "try_into_std",
        "tokio::fs::File::try_into_std",
        Safe("unwraps a descriptor"),
    ),
    (
        "file.rs",
        "metadata",
        "tokio::fs::File::metadata",
        Safe(READS),
    ),
    (
        "file.rs",
        "set_len",
        "tokio::fs::File::set_len",
        Destructive,
    ),
    (
        "file.rs",
        "set_permissions",
        "tokio::fs::File::set_permissions",
        Safe(METADATA),
    ),
    (
        "file.rs",
        "sync_all",
        "tokio::fs::File::sync_all",
        Safe("flushes"),
    ),
    (
        "file.rs",
        "sync_data",
        "tokio::fs::File::sync_data",
        Safe("flushes"),
    ),
    (
        "file.rs",
        "try_clone",
        "tokio::fs::File::try_clone",
        Safe("duplicates a descriptor"),
    ),
    (
        "file.rs",
        "max_buf_size",
        "tokio::fs::File::max_buf_size",
        Safe("buffering"),
    ),
    (
        "file.rs",
        "set_max_buf_size",
        "tokio::fs::File::set_max_buf_size",
        Safe("buffering"),
    ),
    (
        "hard_link.rs",
        "hard_link",
        "tokio::fs::hard_link",
        Safe(CREATES_ONLY),
    ),
    (
        "metadata.rs",
        "metadata",
        "tokio::fs::metadata",
        Safe(READS),
    ),
    (
        "open_options.rs",
        "new",
        "tokio::fs::OpenOptions::new",
        Safe("a builder"),
    ),
    (
        "open_options.rs",
        "read",
        "tokio::fs::OpenOptions::read",
        Safe("a builder"),
    ),
    (
        "open_options.rs",
        "write",
        "tokio::fs::OpenOptions::write",
        Safe("in-place writes to a file the caller opened; truncation and replacement are gated"),
    ),
    (
        "open_options.rs",
        "append",
        "tokio::fs::OpenOptions::append",
        Safe("appends only"),
    ),
    (
        "open_options.rs",
        "truncate",
        "tokio::fs::OpenOptions::truncate",
        Destructive,
    ),
    (
        "open_options.rs",
        "create",
        "tokio::fs::OpenOptions::create",
        Safe("O_CREAT without truncation"),
    ),
    (
        "open_options.rs",
        "create_new",
        "tokio::fs::OpenOptions::create_new",
        Safe(CREATES_ONLY),
    ),
    (
        "open_options.rs",
        "open",
        "tokio::fs::OpenOptions::open",
        Safe("opens with the flags above"),
    ),
    (
        "open_options.rs",
        "mode",
        "tokio::fs::OpenOptions::mode",
        Safe("a builder"),
    ),
    (
        "open_options.rs",
        "custom_flags",
        "tokio::fs::OpenOptions::custom_flags",
        Safe("a builder; O_TRUNC by flag is outside every gate (design 7.1)"),
    ),
    ("read.rs", "read", "tokio::fs::read", Safe(READS)),
    (
        "read_dir.rs",
        "read_dir",
        "tokio::fs::read_dir",
        Safe(READS),
    ),
    (
        "read_link.rs",
        "read_link",
        "tokio::fs::read_link",
        Safe(READS),
    ),
    (
        "read_to_string.rs",
        "read_to_string",
        "tokio::fs::read_to_string",
        Safe(READS),
    ),
    (
        "remove_dir.rs",
        "remove_dir",
        "tokio::fs::remove_dir",
        Destructive,
    ),
    (
        "remove_dir_all.rs",
        "remove_dir_all",
        "tokio::fs::remove_dir_all",
        Destructive,
    ),
    (
        "remove_file.rs",
        "remove_file",
        "tokio::fs::remove_file",
        Destructive,
    ),
    ("rename.rs", "rename", "tokio::fs::rename", Destructive),
    (
        "set_permissions.rs",
        "set_permissions",
        "tokio::fs::set_permissions",
        Safe(METADATA),
    ),
    (
        "symlink_metadata.rs",
        "symlink_metadata",
        "tokio::fs::symlink_metadata",
        Safe(READS),
    ),
    ("write.rs", "write", "tokio::fs::write", Destructive),
];

/// Functions of `tokio::fs` that need no review: read-only directory-entry accessors,
/// Windows-only builders, and Tokio's own test mocks.
fn tokio_fs_unreviewed(file: &str, name: &str) -> bool {
    file == "read_dir.rs"
        && [
            "file_name",
            "file_type",
            "ino",
            "metadata",
            "next_entry",
            "path",
            "poll_next_entry",
        ]
        .contains(&name)
        || file == "open_options.rs"
            && [
                "access_mode",
                "attributes",
                "security_qos_flags",
                "share_mode",
            ]
            .contains(&name)
        || [
            "symlink.rs",
            "symlink_dir.rs",
            "symlink_file.rs",
            "try_exists.rs",
        ]
        .contains(&file)
            && ["symlink", "symlink_dir", "symlink_file", "try_exists"].contains(&name)
        || file == "file.rs" && name == "sync_data"
        || file.starts_with("mocks")
        || file.contains("mock_")
        || file.ends_with("tests.rs")
}

/// MEDIUM-1: std's and Tokio's destructive surface is disallowed. std is the curated
/// list above; `tokio::fs` is read from the locked source, and a function the review
/// has not classified fails the test.
#[test]
fn std_and_tokio_destructive_surfaces_are_disallowed() {
    let disallowed = clippy_paths(&read(&workspace_root().join("clippy.toml")));
    let mut wrong = Vec::new();
    for (path, review) in &STD_SURFACE {
        match review {
            Destructive if !disallowed.contains(*path) => {
                wrong.push(format!("{path} is destructive but not disallowed"));
            }
            Safe(why) if disallowed.contains(*path) || why.is_empty() => {
                wrong.push(format!("{path} is reviewed as safe but disallowed"));
            }
            _ => {}
        }
    }
    // Every std path clippy.toml names is in the review.
    for path in disallowed.iter().filter(|p| p.starts_with("std::")) {
        if !STD_SURFACE
            .iter()
            .any(|(p, r)| p == path && matches!(r, Destructive))
        {
            wrong.push(format!(
                "clippy.toml disallows {path}, which the std review does not list"
            ));
        }
    }
    // tokio::fs, from the locked source.
    let lock = read(&workspace_root().join("Cargo.lock"));
    assert!(
        locked_versions(&lock).contains_key("tokio"),
        "tokio is not locked"
    );
    let mut seen = 0;
    for (version, source) in locked_source("tokio") {
        let fs = source.join("src/fs");
        for path in rust_files(&fs, false) {
            let file = path
                .strip_prefix(&fs)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let text = read(&path);
            let toks = tokens(&text);
            for (index, token) in toks.iter().enumerate() {
                if *token != Token::Ident("fn") {
                    continue;
                }
                let Some(Token::Ident(name)) = toks.get(index + 1) else {
                    continue;
                };
                let public = toks[index.saturating_sub(3)..index].contains(&Token::Ident("pub"));
                if !public || tokio_fs_unreviewed(&file, name) {
                    continue;
                }
                seen += 1;
                match TOKIO_FS.iter().find(|(f, n, _, _)| *f == file && n == name) {
                    None => wrong.push(format!(
                        "tokio {version}'s fs/{file} exports `{name}`, which the tokio::fs review does not classify"
                    )),
                    Some((_, _, path, Destructive)) if !disallowed.contains(*path) => {
                        wrong.push(format!("{path} is destructive but not disallowed"));
                    }
                    _ => {}
                }
            }
        }
    }
    assert!(seen >= 40, "tokio::fs was not found ({seen} functions)");
    for (_, _, path, review) in &TOKIO_FS {
        if matches!(review, Destructive) && !disallowed.contains(*path) {
            wrong.push(format!("{path} is destructive but not disallowed"));
        }
    }
    for path in disallowed.iter().filter(|p| p.starts_with("tokio::fs::")) {
        if !TOKIO_FS
            .iter()
            .any(|(_, _, p, r)| p == path && matches!(r, Destructive))
        {
            wrong.push(format!(
                "clippy.toml disallows {path}, which the tokio::fs review does not list"
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

// ---------------------------------------------------------------------------------
// Synthetic regressions. (`scripts/dependency-gate-regressions.sh` runs the same cases
// through the actual source loader, cargo and clippy.)

const REGISTRY: &str = "source = \"registry+https://github.com/rust-lang/crates.io-index\"";

fn checksum(name: &str, version: &str) -> String {
    format!("{name}-{version}-checksum")
}

fn package_at(name: &str, version: &str, deps: &[&str]) -> String {
    let deps: String = deps.iter().map(|d| format!(" \"{d}\",\n")).collect();
    format!(
        "[[package]]\nname = \"{name}\"\nversion = \"{version}\"\n{REGISTRY}\nchecksum = \"{}\"\ndependencies = [\n{deps}]\n\n",
        checksum(name, version)
    )
}

fn package(name: &str, deps: &[&str]) -> String {
    package_at(name, "1.0.0", deps)
}

/// The resolve cargo would report for a synthetic workspace: members (no `source`) take
/// each edge's kind from their manifest, registry packages have normal edges.
fn synthetic_resolve(lock: &str, manifests: &[(String, String)]) -> Resolve {
    let entries = lock_entries(lock);
    let mut kinds: BTreeMap<String, BTreeSet<DependencyKind>> = BTreeMap::new();
    for (_, manifest) in manifests {
        for (name, kind) in manifest_dependencies(manifest).unwrap_or_default() {
            kinds.entry(name).or_default().insert(kind);
        }
    }
    let key_of = |dependency: &str| -> String {
        match dependency.split_once(' ') {
            Some((name, version)) => format!("{name}@{version}"),
            None => entries
                .iter()
                .find(|e| e.name == dependency)
                .map_or_else(|| format!("{dependency}@?"), LockEntry::key),
        }
    };
    let mut resolve = Resolve::default();
    for entry in &entries {
        let member = entry.source.is_none();
        let mut deps = BTreeMap::new();
        for dependency in &entry.dependencies {
            let name = dependency.split(' ').next().unwrap();
            let edge = if member {
                kinds
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| BTreeSet::from([DependencyKind::Normal]))
            } else {
                BTreeSet::from([DependencyKind::Normal])
            };
            deps.insert(key_of(dependency), edge);
        }
        resolve.packages.insert(
            entry.key(),
            Resolved {
                member,
                deps,
                ..Resolved::default()
            },
        );
    }
    resolve
}

/// A one-crate workspace: `demo` depends on libc (normal) and tempfile (dev, over
/// rustix); the gate reviews all three, and clippy disallows libc::kill and tempfile's
/// persist.
fn demo(extra_lock: &str, extra_dependencies: &str, extra_workspace: &[&str]) -> Inputs {
    let workspace_deps: String = ["libc", "tempfile"]
        .iter()
        .chain(extra_workspace)
        .map(|d| format!(" \"{d}\",\n"))
        .collect();
    let mut inputs = Inputs {
        lock: format!(
            "version = 4\n\n[[package]]\nname = \"demo\"\nversion = \"0.1.0\"\ndependencies = [\n{workspace_deps}]\n\n{}{}{}{extra_lock}",
            package("libc", &[]),
            package("tempfile", &["rustix"]),
            package("rustix", &["libc"]),
        ),
        manifests: vec![(
            "demo".to_string(),
            format!(
                "[package]\nname = \"demo\"\n\n[dependencies]\nlibc.workspace = true\n{extra_dependencies}\n[dev-dependencies]\ntempfile = \"3\"\n"
            ),
        )],
        resolve: Resolve::default(),
        sources: vec![("demo/src/lib.rs".into(), "pub fn f() {}\n".into())],
        package_sources: BTreeMap::new(),
        gate: serde_json::json!({"packages": {}, "sink_exceptions": []}),
        clippy: "disallowed-methods = [\n  { path = \"libc::kill\", reason = \"x\" },\n  { path = \"tempfile::NamedTempFile::persist\", reason = \"x\" },\n]\n".into(),
    };
    review(
        &mut inputs,
        "libc",
        serde_json::json!({"kind": "runtime", "capability": ["signals", "syscalls"], "destructive": ["libc::kill"], "why": "x"}),
    );
    review(
        &mut inputs,
        "tempfile",
        serde_json::json!({"kind": "dev-only", "capability": "filesystem", "destructive": ["tempfile::NamedTempFile::persist"], "why": "x"}),
    );
    review(
        &mut inputs,
        "rustix",
        serde_json::json!({"kind": "dev-only", "capability": ["filesystem", "syscalls"], "why": "x"}),
    );
    inputs
}

/// Records a reviewed entry for `name` (at 1.0.0, or `name@version`), pinned to the
/// synthetic checksum and, unless the entry says otherwise, no features.
fn review(inputs: &mut Inputs, name: &str, mut entry: serde_json::Value) {
    let key = if name.contains('@') {
        name.to_string()
    } else {
        format!("{name}@1.0.0")
    };
    let (n, v) = key.split_once('@').unwrap();
    if entry["checksum"].is_null() {
        entry["checksum"] = checksum(n, v).into();
    }
    if entry["features"].is_null() {
        entry["features"] = serde_json::json!([]);
    }
    inputs.gate["packages"][key] = entry;
}

/// Gives `name@1.0.0` one library file.
fn source(inputs: &mut Inputs, name: &str, text: &str) {
    inputs.package_sources.insert(
        format!("{name}@1.0.0"),
        vec![(format!("{name}-1.0.0/src/lib.rs"), text.into())],
    );
}

/// Runs the gate on a synthetic workspace: the resolve is derived from its lock and
/// manifests, with any features the test set in `inputs.resolve`.
fn check(inputs: &Inputs) -> String {
    let mut resolve = synthetic_resolve(&inputs.lock, &inputs.manifests);
    for (key, package) in &inputs.resolve.packages {
        if let Some(resolved) = resolve.packages.get_mut(key) {
            resolved.features = package.features.clone();
            resolved.proc_macro = package.proc_macro;
        }
    }
    let inputs = Inputs {
        lock: inputs.lock.clone(),
        manifests: inputs.manifests.clone(),
        resolve,
        sources: inputs.sources.clone(),
        package_sources: inputs.package_sources.clone(),
        gate: inputs.gate.clone(),
        clippy: inputs.clippy.clone(),
    };
    violations(&inputs).join("\n")
}

fn set_features(inputs: &mut Inputs, key: &str, features: &[&str]) {
    inputs
        .resolve
        .packages
        .entry(key.to_string())
        .or_default()
        .features = features.iter().map(|f| f.to_string()).collect();
}

#[test]
fn the_synthetic_workspace_passes() {
    assert_eq!(check(&demo("", "", &[])), "");
}

/// B7 milestone 2 HIGH-1, Daybreak's `fs-err` PoC as a regression: an honest-looking
/// `std::fs` wrapper whose lock record shows no raw system-call crate.
#[test]
fn b7m2_an_fs_err_wrapper_declared_none_is_refused() {
    let fs_err_source = "use std::fs;\nuse std::path::Path;\n\
        pub fn remove_dir_all<P: AsRef<Path>>(path: P) -> std::io::Result<()> {\n    \
        fs::remove_dir_all(path.as_ref())\n}\n";
    let production = "use std::path::Path;\n\
        /// Removes a caller-selected tree.\n\
        pub fn remove_tree(path: &Path) -> std::io::Result<()> {\n    fs_err::remove_dir_all(path)\n}\n";
    let with = |entry: serde_json::Value, clippy_extra: &str, production: &str| {
        let mut inputs = demo(
            &package("fs-err", &[]),
            "fs-err.workspace = true\n",
            &["fs-err"],
        );
        review(&mut inputs, "fs-err", entry);
        inputs.clippy = inputs.clippy.replace("]\n", &format!("{clippy_extra}]\n"));
        // clippy.toml's std list, as the real file has it.
        inputs.clippy = inputs.clippy.replace(
            "disallowed-methods = [\n",
            "disallowed-methods = [\n  { path = \"std::fs::remove_dir_all\", reason = \"x\" },\n",
        );
        inputs.sources = vec![("demo/src/gate_bypass_poc.rs".into(), production.into())];
        source(&mut inputs, "fs-err", fs_err_source);
        inputs
    };

    // Unreviewed: refused.
    let mut unreviewed = with(serde_json::json!({}), "", production);
    unreviewed.gate["packages"]
        .as_object_mut()
        .unwrap()
        .remove("fs-err@1.0.0");
    let wrong = check(&unreviewed);
    assert!(
        wrong.contains("fs-err@1.0.0 is in Cargo.lock with no reviewed entry"),
        "{wrong}"
    );

    // Daybreak's declaration (`none`, nothing destructive): refused twice over, by the
    // production call and by fs-err's own source.
    let none = serde_json::json!({"kind": "runtime", "capability": "none", "why": "std::fs wrappers with path-rich errors"});
    let wrong = check(&with(none.clone(), "", production));
    assert!(
        wrong.contains("demo/src/gate_bypass_poc.rs: production names fs_err::remove_dir_all, which looks destructive"),
        "{wrong}"
    );
    assert!(
        wrong.contains(
            "fs-err@1.0.0 is declared `none`, but its runtime subtree reaches `std::fs::remove_dir_all` in fs-err@1.0.0"
        ),
        "{wrong}"
    );
    // The same through an alias, a grouped import or a crate rename.
    for production in [
        "use fs_err as fs;\npub fn f(p: &std::path::Path) { let _ = fs::remove_dir_all(p); }\n",
        "use fs_err::{self, remove_dir_all as tidy};\npub fn f(p: &std::path::Path) { let _ = tidy(p); }\n",
        "extern crate fs_err as files;\npub fn f(p: &std::path::Path) { let _ = files :: /* x */ remove_dir_all(p); }\n",
    ] {
        let wrong = check(&with(none.clone(), "", production));
        assert!(
            wrong.contains("production names fs_err::remove_dir_all"),
            "{production}\n{wrong}"
        );
    }
    // A glob import of a `none` crate is refused outright.
    let wrong = check(&with(none.clone(), "", "use fs_err::*;\npub fn f() {}\n"));
    assert!(
        wrong.contains("a glob import of fs_err hides its names"),
        "{wrong}"
    );

    // `filesystem` with no destructive paths: refused.
    let honest = serde_json::json!({"kind": "runtime", "capability": "filesystem", "destructive": [], "why": "std::fs wrappers"});
    let wrong = check(&with(honest, "", production));
    assert!(
        wrong.contains("fs-err declares filesystem: list its destructive paths"),
        "{wrong}"
    );
    // Listed, but not disallowed: refused.
    let listed = serde_json::json!({"kind": "runtime", "capability": "filesystem", "destructive": ["fs_err::remove_dir_all"], "why": "std::fs wrappers"});
    let wrong = check(&with(listed.clone(), "", production));
    assert!(
        wrong.contains(
            "fs-err's destructive fs_err::remove_dir_all is not disallowed in clippy.toml"
        ),
        "{wrong}"
    );
    // Listed and disallowed: the gate holds, and the honest declaration is accepted even
    // though Cargo.lock shows no raw system-call crate under fs-err (no override).
    let gated = "  { path = \"fs_err::remove_dir_all\", reason = \"x\" },\n";
    assert_eq!(check(&with(listed, gated, production)), "");
}

/// The B7 milestone 2 recheck's HIGH-1 PoC (reviews/poc-b7m2-recheck): an extension
/// trait on `std::fs::File` whose method calls `File::set_len`, imported as `_` and
/// called as `file.reset()`, directly and re-exported through a transitive package.
const WRAPPER: &str = "use std::fs::File;\n\
    pub trait Reset { fn reset(&self) -> std::io::Result<()>; }\n\
    impl Reset for File {\n\
        fn reset(&self) -> std::io::Result<()> { self.set_len(0) }\n\
    }\n";
const RESET_PRODUCTION: &str = "use method_wrapper::Reset as _;\n\
    pub fn reset(file: &std::fs::File) -> std::io::Result<()> { file.reset() }\n";

fn method_wrapper(entry: serde_json::Value) -> Inputs {
    let mut inputs = demo(
        &package("method-wrapper", &[]),
        "method-wrapper = \"1\"\n",
        &["method-wrapper"],
    );
    review(&mut inputs, "method-wrapper", entry);
    inputs.clippy = inputs.clippy.replace(
        "]\n",
        concat!(
            "  { path = \"std::fs::File::set_len\", reason = \"x\" },\n",
            "  { path = \"std::fs::File::create\", reason = \"x\" },\n",
            "  { path = \"std::fs::remove_file\", reason = \"x\" },\n",
            "  { path = \"std::fs::remove_dir_all\", reason = \"x\" },\n]\n",
        ),
    );
    inputs.sources = vec![("demo/src/lib.rs".into(), RESET_PRODUCTION.into())];
    source(&mut inputs, "method-wrapper", WRAPPER);
    inputs
}

fn no_destructive_api() -> serde_json::Value {
    serde_json::json!({
        "kind": "runtime",
        "capability": "filesystem",
        "no_destructive_api": "only extends File with a reset helper",
        "why": "file convenience traits",
    })
}

fn transitive_wrapper() -> Inputs {
    let lock = package("outer-wrapper", &["inner-wrapper"]) + &package("inner-wrapper", &[]);
    let mut inputs = demo(&lock, "outer-wrapper = \"1\"\n", &["outer-wrapper"]);
    review(
        &mut inputs,
        "outer-wrapper",
        serde_json::json!({"kind": "runtime", "capability": "none", "why": "re-exports a convenience trait"}),
    );
    inputs.clippy = inputs.clippy.replace(
        "]\n",
        "  { path = \"std::fs::File::set_len\", reason = \"x\" },\n]\n",
    );
    inputs.sources = vec![(
        "demo/src/lib.rs".into(),
        "use outer_wrapper::Reset as _;\n\
         pub fn reset(file: &std::fs::File) -> std::io::Result<()> { file.reset() }\n"
            .into(),
    )];
    source(
        &mut inputs,
        "outer-wrapper",
        "pub use inner_wrapper::Reset;\n",
    );
    source(&mut inputs, "inner-wrapper", WRAPPER);
    inputs
}

#[test]
fn b7m2_recheck_a_method_wrapper_is_refused() {
    // Daybreak's direct case: `filesystem` with `no_destructive_api`.
    let wrong = check(&method_wrapper(no_destructive_api()));
    assert!(
        wrong.contains("method-wrapper@1.0.0 is declared `filesystem` with no destructive API, but its runtime subtree reaches `.set_len(` in method-wrapper@1.0.0 (method-wrapper-1.0.0/src/lib.rs)"),
        "{wrong}"
    );
    assert!(
        wrong.contains("`impl for std::fs::File` in method-wrapper@1.0.0"),
        "{wrong}"
    );
    assert!(
        wrong.contains(r#"{"features":[],"package":"method-wrapper","sinks":[".set_len(","impl for std::fs::File"],"version":"1.0.0"}"#),
        "the refusal drafts the exception: {wrong}"
    );
    // And `none`.
    let wrong = check(&method_wrapper(
        serde_json::json!({"kind": "runtime", "capability": "none", "why": "x"}),
    ));
    assert!(
        wrong.contains(
            "method-wrapper@1.0.0 is declared `none`, but its runtime subtree reaches `.set_len(`"
        ),
        "{wrong}"
    );
    // The same shape however the wrapper writes it: a named import, a reference self
    // type with a lifetime, UFCS, a turbofish-free path through an alias, a glob-imported
    // `File`, other sink names.
    for wrapper in [
        "pub trait Reset { fn reset(&self); }\nimpl<'a> Reset for &'a std::fs::File { fn reset(&self) { let _ = std::fs::File::set_len(self, 0); } }\n",
        "use std::fs as f;\npub trait Reset { fn reset(&self); }\nimpl Reset for f::File { fn reset(&self) { let _ = f::File::set_len(self, 0); } }\n",
        "use std::fs::*;\npub trait Reset { fn reset(&self); }\nimpl Reset for File { fn reset(&self) {} }\n",
        "pub fn tidy(dir: &Dir) { let _ = dir . remove_file (\"x\"); }\n",
        "pub fn stop(child: &mut std::process::Child) { let _ = child.kill(); }\n",
        "pub fn stop(child: &mut Handle) { let _ = child.start_kill(); }\n",
        "pub fn drop_it(d: &Dir) { let _ = d.unlink_at(\"x\"); }\n",
        "pub fn keep(t: Temp) { let _ = t.persist(\"x\"); }\n",
        "pub fn go(c: &mut Cmd) { let _ = c.exec(); }\n",
        "pub fn off(m: Mount) { let _ = m.unmount(); }\n",
        "pub fn mv(d: &Dir) { let _ = d.rename(\"a\", \"b\"); }\n",
        "pub fn open(o: &mut Opts) { o.truncate(true); }\n",
        "pub fn dup(d: &Dir) { let _ = d.copy(\"a\", \"b\"); }\n",
        "use std::fs::*;\npub fn tidy(p: &std::path::Path) { let _ = remove_file(p); }\n",
        "use std::fs::*;\npub fn fresh(p: &std::path::Path) { let _ = File::create(p); }\n",
        "use std::{fs::*, io};\npub fn tidy(p: &std::path::Path) -> io::Result<()> { remove_dir_all(p) }\n",
    ] {
        let mut inputs = method_wrapper(no_destructive_api());
        source(&mut inputs, "method-wrapper", wrapper);
        let wrong = check(&inputs);
        assert!(
            wrong.contains("method-wrapper@1.0.0 is declared `filesystem` with no destructive API, but its runtime subtree reaches"),
            "{wrapper}\n{wrong}"
        );
    }
    // Not sinks: a definition, a field, other methods, strings and comments, a trait impl
    // for the package's own `File`, or for a `File` it imports from elsewhere.
    for wrapper in [
        "pub trait SetLen { fn set_len(&self, n: u64); }\n",
        "pub fn f(s: &S) { s.exec.run(); s.write(b\"x\"); let _ = \".set_len(0)\"; } // .kill()\n",
        "pub struct File;\npub trait Reset {}\nimpl Reset for File {}\n",
        "use crate::fs::File;\npub trait Reset {}\nimpl Reset for File {}\n",
        "pub trait Reset {}\nimpl<T: Fn() -> u8> Reset for T where T: Copy {}\n",
        "use std::fs::*;\npub fn look(p: &std::path::Path) { let _ = read(p); let _ = metadata(p); }\n",
    ] {
        let mut inputs = method_wrapper(no_destructive_api());
        source(&mut inputs, "method-wrapper", wrapper);
        assert_eq!(check(&inputs), "", "{wrapper}");
    }
}

#[test]
fn b7m2_recheck_a_transitive_wrapper_is_refused() {
    // Daybreak's transitive case: the inner package is unreviewed, and the `none` outer
    // package's subtree scan reaches the inner package's `.set_len(`.
    let wrong = check(&transitive_wrapper());
    assert!(
        wrong.contains("inner-wrapper@1.0.0 is in Cargo.lock with no reviewed entry"),
        "{wrong}"
    );
    assert!(
        wrong.contains("outer-wrapper@1.0.0 is declared `none`, but its runtime subtree reaches `.set_len(` in inner-wrapper@1.0.0"),
        "{wrong}"
    );
    // Reviewing the inner package as `none` too does not help: both declarations fail.
    let mut inputs = transitive_wrapper();
    review(
        &mut inputs,
        "inner-wrapper",
        serde_json::json!({"kind": "runtime", "capability": "none", "why": "x"}),
    );
    let wrong = check(&inputs);
    assert!(!wrong.contains("no reviewed entry"), "{wrong}");
    assert!(
        wrong.contains(
            "inner-wrapper@1.0.0 is declared `none`, but its runtime subtree reaches `.set_len(`"
        ),
        "{wrong}"
    );
    assert!(
        wrong.contains("outer-wrapper@1.0.0 is declared `none`, but its runtime subtree reaches `.set_len(` in inner-wrapper@1.0.0"),
        "{wrong}"
    );
    // Its source must be there to scan.
    inputs.package_sources.remove("inner-wrapper@1.0.0");
    assert!(
        check(&inputs).contains("inner-wrapper@1.0.0's locked source was not available to scan")
    );
}

#[test]
fn b7m2_recheck_every_locked_package_is_reviewed() {
    // A version bump: the new version is unreviewed and the old entry is stale.
    let bumped = |inputs: &mut Inputs| {
        inputs.lock = inputs.lock.replace(
            &package("rustix", &["libc"]),
            &package_at("rustix", "1.0.1", &["libc"]),
        );
    };
    let mut inputs = demo("", "", &[]);
    bumped(&mut inputs);
    let wrong = check(&inputs);
    assert!(
        wrong.contains("rustix@1.0.1 is in Cargo.lock with no reviewed entry"),
        "{wrong}"
    );
    assert!(
        wrong.contains("`packages` entry rustix@1.0.0 is not in Cargo.lock"),
        "{wrong}"
    );
    // A new checksum for the same version.
    let mut inputs = demo("", "", &[]);
    inputs.gate["packages"]["rustix@1.0.0"]["checksum"] = "0000".into();
    let wrong = check(&inputs);
    assert!(
        wrong.contains(
            "rustix@1.0.0's reviewed checksum 0000 is not Cargo.lock's rustix-1.0.0-checksum"
        ),
        "{wrong}"
    );
    // A changed feature set.
    let mut inputs = demo("", "", &[]);
    set_features(&mut inputs, "libc@1.0.0", &["extra_traits"]);
    let wrong = check(&inputs);
    assert!(
        wrong.contains(
            r#"libc@1.0.0's reviewed features [] are not the resolved features ["extra_traits"]"#
        ),
        "{wrong}"
    );
    inputs.gate["packages"]["libc@1.0.0"]["features"] = serde_json::json!(["extra_traits"]);
    assert_eq!(check(&inputs), "");
    // A transitive package's kind comes from the graph.
    let mut inputs = demo("", "", &[]);
    inputs.gate["packages"]["rustix@1.0.0"]["kind"] = "runtime".into();
    let wrong = check(&inputs);
    assert!(
        wrong.contains(
            "rustix@1.0.0 is declared runtime, but the dependency graph makes it dev-only"
        ),
        "{wrong}"
    );
    // A git dependency has no checksum to pin a review to.
    let git = "[[package]]\nname = \"gitdep\"\nversion = \"1.0.0\"\nsource = \"git+https://example.com/gitdep#abc\"\n\n";
    let mut inputs = demo(git, "gitdep = \"1\"\n", &["gitdep"]);
    review(
        &mut inputs,
        "gitdep",
        serde_json::json!({"kind": "runtime", "capability": "none", "why": "x"}),
    );
    source(&mut inputs, "gitdep", "");
    let wrong = check(&inputs);
    assert!(
        wrong.contains("gitdep@1.0.0 is not a registry package with a Cargo.lock checksum"),
        "{wrong}"
    );
    // A shared justification: only for `none` packages that name no file, process or raw
    // path; an unknown group or a missing reason is refused.
    let lock = package("pure", &[]);
    let grouped = |text: &str, capability: &str, group: &str| {
        let mut inputs = demo(&lock, "pure = \"1\"\n", &["pure"]);
        inputs.gate["groups"] = serde_json::json!({"pure-computation": "computes; no I/O"});
        review(
            &mut inputs,
            "pure",
            serde_json::json!({"kind": "runtime", "capability": capability, "group": group}),
        );
        source(&mut inputs, "pure", text);
        check(&inputs)
    };
    assert_eq!(
        grouped(
            "pub fn add(a: u8, b: u8) -> u8 { a + b }\n",
            "none",
            "pure-computation"
        ),
        ""
    );
    for text in [
        "use std::fs;\n",
        "use std::{io, process::Command};\n",
        "pub fn f() { let _ = core::fs::read(\"x\"); }\n",
        "extern crate libc;\n",
        "use tokio::fs::File;\n",
        "use std::os::unix::fs::PermissionsExt;\n",
        "use std::os::unix::prelude::*;\n",
    ] {
        let wrong = grouped(text, "none", "pure-computation");
        assert!(
            wrong
                .contains("pure@1.0.0 is grouped under \"pure-computation\", but its source names"),
            "{text}\n{wrong}"
        );
    }
    assert!(
        grouped("", "network", "pure-computation").contains("a group is only for `none` packages")
    );
    assert!(grouped("", "none", "pure").contains("pure@1.0.0 names an unknown group \"pure\""));
    let mut inputs = demo("", "", &[]);
    inputs.gate["packages"]["rustix@1.0.0"]["why"] = "".into();
    assert!(check(&inputs).contains("rustix@1.0.0 gives no reason"));
    // Only a direct dependency lists destructive paths.
    let mut inputs = demo("", "", &[]);
    inputs.gate["packages"]["rustix@1.0.0"]["destructive"] =
        serde_json::json!(["rustix::fs::unlink"]);
    assert!(
        check(&inputs).contains(
            "rustix@1.0.0 is not a direct dependency: the workspace cannot name its paths"
        )
    );
}

#[test]
fn b7m2_recheck_an_exception_holds_only_for_its_scope() {
    let exception = || {
        serde_json::json!({
            "package": "method-wrapper",
            "version": "1.0.0",
            "features": [],
            "sinks": [".set_len(", "impl for std::fs::File"],
            "why": "fixture: reviewed",
        })
    };
    let reviewed = |exception: serde_json::Value| {
        let mut inputs = method_wrapper(no_destructive_api());
        inputs.gate["sink_exceptions"] = serde_json::json!([exception]);
        inputs
    };
    // Exactly scoped: the gate holds.
    assert_eq!(check(&reviewed(exception())), "");
    // Another feature set: the exception does not apply.
    let mut inputs = reviewed(exception());
    set_features(&mut inputs, "method-wrapper@1.0.0", &["extra"]);
    inputs.gate["packages"]["method-wrapper@1.0.0"]["features"] = serde_json::json!(["extra"]);
    let wrong = check(&inputs);
    assert!(
        wrong.contains(r#"the sink exception for method-wrapper@1.0.0 is scoped to features [], but cargo resolves ["extra"]"#),
        "{wrong}"
    );
    assert!(
        wrong.contains("but its runtime subtree reaches `.set_len(` in method-wrapper@1.0.0"),
        "{wrong}"
    );
    // Another version: stale, and the new version is unreviewed and unexcepted.
    let mut inputs = reviewed(exception());
    inputs.lock = inputs.lock.replace(
        &package("method-wrapper", &[]),
        &package_at("method-wrapper", "1.0.1", &[]),
    );
    let wrong = check(&inputs);
    assert!(
        wrong.contains("the sink exception for method-wrapper@1.0.0 is stale"),
        "{wrong}"
    );
    assert!(
        wrong.contains("method-wrapper@1.0.1 is in Cargo.lock with no reviewed entry"),
        "{wrong}"
    );
    // Another sink: the uncovered one still refuses, and the unused one is stale.
    let mut other = exception();
    other["sinks"] = serde_json::json!([".kill(", "impl for std::fs::File"]);
    let wrong = check(&reviewed(other));
    assert!(
        wrong.contains("reaches `.set_len(` in method-wrapper@1.0.0"),
        "{wrong}"
    );
    assert!(
        wrong.contains("the sink exception for method-wrapper@1.0.0 names .kill(, which its source does not reach"),
        "{wrong}"
    );
    // Another package: the exception covers only the package the hit is in.
    let mut inputs = transitive_wrapper();
    review(
        &mut inputs,
        "inner-wrapper",
        serde_json::json!({"kind": "runtime", "capability": "none", "why": "x"}),
    );
    let mut outer = exception();
    outer["package"] = "outer-wrapper".into();
    inputs.gate["sink_exceptions"] = serde_json::json!([outer]);
    let wrong = check(&inputs);
    assert!(
        wrong.contains("reaches `.set_len(` in inner-wrapper@1.0.0"),
        "{wrong}"
    );
    // No reason, no features: refused.
    let mut bare = exception();
    bare.as_object_mut().unwrap().remove("why");
    bare.as_object_mut().unwrap().remove("features");
    let wrong = check(&reviewed(bare));
    assert!(
        wrong.contains("the sink exception for method-wrapper@1.0.0 gives no reason"),
        "{wrong}"
    );
    assert!(wrong.contains("needs `features`"), "{wrong}");
}

/// HIGH-1: Cargo.lock may require a capability, never forbid one; and every decision
/// is complete.
#[test]
fn the_lock_graph_requires_but_never_overrides() {
    // A `none` dependency directly over libc needs a recorded reason, or a capability.
    let lock = package("tokio-util", &["libc"]);
    let mut inputs = demo(&lock, "tokio-util = \"0.7\"\n", &["tokio-util"]);
    review(
        &mut inputs,
        "tokio-util",
        serde_json::json!({"kind": "runtime", "capability": "none", "why": "x"}),
    );
    source(&mut inputs, "tokio-util", "");
    source(&mut inputs, "libc", "");
    let wrong = check(&inputs);
    assert!(
        wrong.contains("Cargo.lock shows a raw system-call crate under tokio-util@1.0.0"),
        "{wrong}"
    );
    inputs.gate["packages"]["tokio-util@1.0.0"]["raw_use"] = serde_json::json!("libc::memchr only");
    assert_eq!(check(&inputs), "");
    review(
        &mut inputs,
        "tokio-util",
        serde_json::json!({"kind": "runtime", "capability": "network", "why": "x"}),
    );
    assert_eq!(check(&inputs), "");
    // A raw crate itself must say `syscalls`, and cannot claim no destructive API.
    let mut inputs = demo("", "", &[]);
    inputs.gate["packages"]["libc@1.0.0"]["capability"] = serde_json::json!("filesystem");
    let wrong = check(&inputs);
    assert!(
        wrong.contains(
            "libc@1.0.0 is a raw system-call crate: its capability must include `syscalls`"
        ),
        "{wrong}"
    );
    let mut inputs = demo("", "", &[]);
    inputs.gate["packages"]["libc@1.0.0"]["destructive"] = serde_json::json!([]);
    inputs.gate["packages"]["libc@1.0.0"]["no_destructive_api"] = serde_json::json!("x");
    inputs.clippy = "disallowed-methods = [\n  { path = \"tempfile::NamedTempFile::persist\", reason = \"x\" },\n]\n".into();
    let wrong = check(&inputs);
    assert!(
        wrong.contains("libc declares signals, syscalls: list its destructive paths"),
        "{wrong}"
    );
    // Incomplete or unknown fields.
    let mut inputs = demo("", "", &[]);
    inputs.gate["packages"]["libc@1.0.0"]["capability"] = serde_json::json!([]);
    inputs.gate["packages"]["tempfile@1.0.0"]["destrutive"] = serde_json::json!([]);
    inputs.gate["packages"]["tempfile@1.0.0"]["kind"] = serde_json::json!("test");
    inputs.gate["packages"]["tempfile@1.0.0"]
        .as_object_mut()
        .unwrap()
        .remove("features");
    let wrong = check(&inputs);
    assert!(
        wrong.contains("libc@1.0.0 needs a reviewed `capability`"),
        "{wrong}"
    );
    assert!(
        wrong.contains("tempfile@1.0.0 has an unknown field \"destrutive\""),
        "{wrong}"
    );
    assert!(wrong.contains("tempfile@1.0.0 needs a `kind`"), "{wrong}");
    assert!(wrong.contains("tempfile@1.0.0 needs `features`"), "{wrong}");
    // `none` with destructive paths, or a capability outside the list.
    let mut inputs = demo("", "", &[]);
    inputs.gate["packages"]["tempfile@1.0.0"]["capability"] = serde_json::json!(["none", "disk"]);
    let wrong = check(&inputs);
    assert!(
        wrong.contains("tempfile@1.0.0 declares an unknown capability \"disk\""),
        "{wrong}"
    );
    assert!(
        wrong.contains("tempfile@1.0.0 declares `none` together with other capabilities"),
        "{wrong}"
    );
    // clippy.toml gating a path the entry does not list, or an unreviewed crate.
    let mut inputs = demo("", "", &[]);
    inputs.clippy = inputs.clippy.replace(
        "]\n",
        "  { path = \"libc::rmdir\", reason = \"x\" },\n  { path = \"rustix::fs::unlink\", reason = \"x\" },\n]\n",
    );
    let wrong = check(&inputs);
    assert!(
        wrong.contains("clippy.toml disallows libc::rmdir, which libc's entry does not list"),
        "{wrong}"
    );
    assert!(
        wrong.contains("rustix is not a reviewed direct dependency"),
        "{wrong}"
    );
    // A new raw crate, unreviewed, and its transitive raw dependency.
    let lock = package("nix", &["libc", "memmap2"]) + &package("memmap2", &["libc"]);
    let wrong = check(&demo(&lock, "nix = \"0.29\"\n", &["nix"]));
    assert!(
        wrong.contains("nix@1.0.0 is in Cargo.lock with no reviewed entry"),
        "{wrong}"
    );
    assert!(
        wrong.contains("memmap2@1.0.0 is in Cargo.lock with no reviewed entry"),
        "{wrong}"
    );
    // A stale entry and a renamed dependency.
    let mut inputs = demo(
        "",
        "libc2 = { package = \"libc\", version = \"0.2\" }\n",
        &[],
    );
    review(
        &mut inputs,
        "gone",
        serde_json::json!({"kind": "runtime", "capability": "none", "why": "x"}),
    );
    let wrong = check(&inputs);
    assert!(
        wrong.contains("`packages` entry gone@1.0.0 is not in Cargo.lock"),
        "{wrong}"
    );
    assert!(wrong.contains("renamed dependency"), "{wrong}");
}

/// B7 milestone 2 LOW-1: kinds are enforced from the manifests and the lock graph.
/// Moving `tonic-prost-build` (which runs protoc and writes files) from a build to a
/// normal dependency fails, as does a dev-only crate a runtime dependency pulls in.
#[test]
fn b7m2_build_and_dev_only_kinds_are_enforced() {
    let lock = package("tonic-prost-build", &["tempfile"]);
    let entry = serde_json::json!({
        "kind": "build-only",
        "capability": ["filesystem", "process"],
        "destructive": ["tonic_prost_build::compile_protos"],
        "why": "generates the gRPC stubs on the build host",
    });
    let gated = "  { path = \"tonic_prost_build::compile_protos\", reason = \"x\" },\n";
    let as_kind = |section: &str| {
        let manifest = format!("[{section}]\ntonic-prost-build.workspace = true\n");
        let mut inputs = demo(&lock, "", &["tonic-prost-build"]);
        inputs.manifests[0].1.push_str(&manifest);
        review(&mut inputs, "tonic-prost-build", entry.clone());
        // tempfile's rustix is now reached by a build edge first.
        inputs.gate["packages"]["rustix@1.0.0"]["kind"] = "build-only".into();
        inputs.clippy = inputs.clippy.replace("]\n", &format!("{gated}]\n"));
        inputs
    };
    assert_eq!(check(&as_kind("build-dependencies")), "");
    let wrong = check(&as_kind("dependencies"));
    assert!(
        wrong.contains(
            "tonic-prost-build@1.0.0 is declared build-only, but the workspace manifests make it runtime"
        ),
        "{wrong}"
    );
    assert!(
        wrong.contains("tonic-prost-build is declared build-only, but Cargo.lock reaches it from the runtime dependencies"),
        "{wrong}"
    );
    // tempfile is dev-only, but a runtime dependency that pulls it in puts it in the
    // runtime graph; `runtime_via` must then name a runtime parent.
    let lock = package("cache", &["tempfile"]);
    let mut inputs = demo(&lock, "cache = \"1\"\n", &["cache"]);
    review(
        &mut inputs,
        "cache",
        serde_json::json!({"kind": "runtime", "capability": "none", "why": "x"}),
    );
    source(&mut inputs, "cache", "");
    let wrong = check(&inputs);
    assert!(
        wrong.contains("tempfile is declared dev-only, but Cargo.lock reaches it from the runtime dependencies (through cache)"),
        "{wrong}"
    );
    inputs.gate["packages"]["tempfile@1.0.0"]["runtime_via"] = "cache".into();
    source(&mut inputs, "tempfile", "");
    source(&mut inputs, "rustix", "");
    source(&mut inputs, "libc", "");
    assert!(
        !check(&inputs).contains("Cargo.lock reaches it"),
        "{}",
        check(&inputs)
    );
}

/// The graph's kinds: a proc macro and what only it reaches are build-time, even under
/// a runtime dependency's normal edge.
#[test]
fn b7m2_recheck_proc_macros_are_build_time() {
    let lock = package("serde", &["serde_derive"])
        + &package("serde_derive", &["syn"])
        + &package("syn", &[]);
    let mut inputs = demo(&lock, "serde = \"1\"\n", &["serde"]);
    inputs
        .resolve
        .packages
        .entry("serde_derive@1.0.0".into())
        .or_default()
        .proc_macro = true;
    for (name, kind) in [
        ("serde", "runtime"),
        ("serde_derive", "build-only"),
        ("syn", "build-only"),
    ] {
        review(
            &mut inputs,
            name,
            serde_json::json!({"kind": kind, "capability": "none", "why": "x"}),
        );
    }
    source(&mut inputs, "serde", "");
    assert_eq!(check(&inputs), "");
    inputs.resolve.packages.clear();
    let wrong = check(&inputs);
    assert!(
        wrong.contains(
            "serde_derive@1.0.0 is declared build-only, but the dependency graph makes it runtime"
        ),
        "{wrong}"
    );
}

/// The lexer sees paths however they are spaced or commented, and nothing in strings,
/// comments or character literals.
#[test]
fn the_path_scanner_sees_code_not_strings() {
    let roots: BTreeSet<String> = ["fs_err".to_string()].into();
    let text = "let a = \"fs_err::remove_file\"; // fs_err::rename\n/* fs_err::copy /* nested */ */\n\
        let b = r#\"fs_err::write\"#; let c = '\"'; fn d<'a>(_: &'a str) {}\n\
        let e = fs_err :: File :: create(p); let r#type = r#fs_err::rename(q);";
    let paths: Vec<String> = rooted_paths(text, &roots)
        .iter()
        .map(|p| p.join("::"))
        .collect();
    assert_eq!(paths, ["fs_err::File::create", "fs_err::rename"]);
    assert_eq!(destructive_name("create", true), Some("creat*"));
    assert_eq!(destructive_name("SYS_kill", true), None);
    assert_eq!(destructive_name("pthread_kill", false), Some("*kill*"));
    assert_eq!(destructive_name("read", true), None);
    assert_eq!(destructive_name("write", true), Some("write"));
    assert_eq!(destructive_name("write", false), None);
}
