//! Design section 7.1's dependency gate, rebuilt for the B7 milestone 2 break-it
//! (HIGH-1, MEDIUM-1 and LOW-1).
//!
//! `dependency-gate.json` records a reviewed decision for every direct dependency of
//! every workspace crate: its `kind` (runtime, build-only or dev-only), its
//! `capability` (`none` or a set of `filesystem`, `process`, `signals`, `syscalls`,
//! `network`) and why. The gate checks those decisions against Cargo.lock, the
//! workspace manifests, clippy.toml, the workspace's production source and each
//! dependency's own locked source. It never overrides an honest declaration: Cargo.lock
//! can only *require* more (a raw system-call crate underneath needs a non-`none`
//! capability or a recorded reason), never forbid a capability a reviewer declared.
//!
//! The clippy gate (`clippy.toml`) is the semantic one. A dependency with a
//! destructive-capable category (filesystem, process, signals, syscalls) lists its
//! destructive paths, and clippy.toml disallows each of them. Two lexical backstops
//! catch a mistaken `none`: production code that names a destructive-looking function
//! through a dependency's path clippy does not disallow, and a dependency whose own
//! locked source reaches a std, Tokio or libc path clippy disallows.
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
/// The categories that can destroy: an entry with any of them lists its destructive
/// paths, and clippy.toml disallows each one.
const DESTRUCTIVE_CAPABILITIES: [&str; 4] = ["filesystem", "process", "signals", "syscalls"];
const KINDS: [&str; 3] = ["runtime", "build-only", "dev-only"];
const ENTRY_FIELDS: [&str; 7] = [
    "kind",
    "runtime_via",
    "capability",
    "destructive",
    "no_destructive_api",
    "raw_use",
    "why",
];

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

// ---------------------------------------------------------------------------------
// Cargo.lock, manifests and clippy.toml.

#[derive(Default)]
struct LockPackage {
    versions: BTreeSet<String>,
    dependencies: BTreeSet<String>,
    registry: bool,
}

/// Cargo.lock's packages by name: their versions, direct dependency names (normal and
/// build, every target) and whether any version comes from a registry (workspace
/// members have no `source`).
fn lock_packages(lock: &str) -> BTreeMap<String, LockPackage> {
    let mut packages = BTreeMap::<String, LockPackage>::new();
    for block in lock.split("[[package]]").skip(1) {
        let (mut name, mut version) = (None, None);
        let mut package = LockPackage::default();
        let mut in_dependencies = false;
        for line in block.lines() {
            let line = line.trim();
            if in_dependencies {
                if line == "]" {
                    in_dependencies = false;
                } else if let Some(entry) = line.strip_prefix('"') {
                    let entry = entry.trim_end_matches(',').trim_end_matches('"');
                    package
                        .dependencies
                        .insert(entry.split(' ').next().unwrap().to_string());
                }
            } else if let Some(value) = line.strip_prefix("name = \"") {
                name = Some(value.trim_end_matches('"').to_string());
            } else if let Some(value) = line.strip_prefix("version = \"") {
                version = Some(value.trim_end_matches('"').to_string());
            } else if line.starts_with("source = ") {
                package.registry = true;
            } else if line == "dependencies = [" {
                in_dependencies = true;
            }
        }
        let entry = packages
            .entry(name.expect("a package without a name"))
            .or_default();
        entry.versions.extend(version);
        entry.dependencies.extend(package.dependencies);
        entry.registry |= package.registry;
    }
    packages
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum DependencyKind {
    Normal,
    Build,
    Dev,
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

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Ident(String),
    PathSep,
    Punct(char),
}

fn tokens(text: &str) -> Vec<Token> {
    let chars: Vec<char> = text.chars().collect();
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
            let word: String = chars[start..i].iter().collect();
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
                out.push(Token::Ident(chars[start..i].iter().collect()));
                continue;
            }
            match (word.as_str(), chars.get(i)) {
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
            Token::Ident(word) if word == "as" => {
                // `as _` (a trait for its methods) brings in no name.
                if let Some(Token::Ident(alias)) = tokens.get(i + 1)
                    && alias != "_"
                {
                    out.push(UseItem {
                        path: path.clone(),
                        alias: Some(alias.clone()),
                    });
                }
                return;
            }
            Token::Ident(word) if word == "self" && !path.is_empty() => {}
            Token::Ident(word) => path.push(word.clone()),
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
            |at: usize, word: &str| matches!(tokens.get(at), Some(Token::Ident(w)) if w == word);
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
                    (Some(Token::Ident(as_)), Some(Token::Ident(alias))) if as_ == "as" => {
                        alias.clone()
                    }
                    _ => name.clone(),
                };
                uses.push(UseItem {
                    path: vec![name.clone()],
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
            let mut path = vec![first.clone()];
            let mut j = i + 1;
            while tokens.get(j) == Some(&Token::PathSep) {
                match tokens.get(j + 1) {
                    Some(Token::Ident(next)) => {
                        path.push(next.clone());
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

/// Every path a file names whose root is one of `roots` (crate names in their
/// underscore form), with `use` aliases resolved: `use fs_err as fs;` then
/// `fs::remove_dir_all` is `fs_err::remove_dir_all`. Glob imports of a root come back
/// as a path ending in `*`.
fn rooted_paths(text: &str, roots: &BTreeSet<String>) -> Vec<Vec<String>> {
    let tokens = tokens(text);
    let (uses, paths) = uses_and_paths(&tokens);
    let mut aliases: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let resolve =
        |aliases: &BTreeMap<String, Vec<String>>, path: &[String]| -> Option<Vec<String>> {
            let first = path.first()?;
            if roots.contains(first) {
                return Some(path.to_vec());
            }
            let mut full = aliases.get(first)?.clone();
            full.extend_from_slice(&path[1..]);
            Some(full)
        };
    // Aliases may build on each other (`use tokio::fs; use fs::File;`): to a fixed point.
    loop {
        let mut changed = false;
        for item in &uses {
            // First resolution wins, so the loop ends (a self-referencing import cannot
            // grow an alias forever).
            if let (Some(alias), Some(full)) = (&item.alias, resolve(&aliases, &item.path))
                && !aliases.contains_key(alias)
            {
                aliases.insert(alias.clone(), full);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut out = Vec::new();
    for item in &uses {
        if let Some(mut full) = resolve(&aliases, &item.path) {
            if item.alias.is_none() {
                full.push("*".into());
            }
            out.push(full);
        }
    }
    for path in &paths {
        if let Some(full) = resolve(&aliases, path) {
            out.push(full);
        }
    }
    out
}

/// A dependency's production text: everything before its first `#[cfg(test)]` module.
fn dependency_production(text: &str) -> &str {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let mut offset = 0;
    for (index, line) in lines.iter().enumerate() {
        if line.trim() == "#[cfg(test)]"
            && lines[index + 1..]
                .iter()
                .map(|l| l.trim())
                .find(|l| !l.starts_with("//") && !l.starts_with("#["))
                .is_some_and(|l| {
                    l.starts_with("mod ")
                        || l.starts_with("pub mod ")
                        || l.starts_with("pub(crate) mod ")
                })
        {
            return &text[..offset];
        }
        offset += line.len();
    }
    text
}

// ---------------------------------------------------------------------------------
// The gate.

/// What the gate reads. `sources` is the workspace's production source (path label,
/// text), `dependency_sources` each dependency's own locked source by package name.
pub(super) struct Inputs {
    pub lock: String,
    pub manifests: Vec<(String, String)>,
    pub sources: Vec<(String, String)>,
    pub dependency_sources: BTreeMap<String, Vec<(String, String)>>,
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

/// Every violation of the gate, in words; none means it holds.
pub(super) fn violations(inputs: &Inputs) -> Vec<String> {
    let mut wrong = Vec::new();
    let packages = lock_packages(&inputs.lock);
    let registry = |name: &str| packages.get(name).is_some_and(|p| p.registry);
    let workspace: BTreeSet<&String> = packages
        .iter()
        .filter(|(_, package)| !package.registry)
        .map(|(name, _)| name)
        .collect();
    let raw_underneath = |name: &str| {
        raw_or_native(name)
            || packages
                .get(name)
                .is_some_and(|p| p.dependencies.iter().any(|d| raw_or_native(d)))
    };
    let disallowed = clippy_paths(&inputs.clippy);

    // The manifests' direct dependencies and the kind each one has.
    let mut manifest_kinds: BTreeMap<String, BTreeSet<DependencyKind>> = BTreeMap::new();
    for (crate_name, manifest) in &inputs.manifests {
        match manifest_dependencies(manifest) {
            Ok(dependencies) => {
                for (name, kind) in dependencies {
                    if !workspace.contains(&name) {
                        manifest_kinds.entry(name).or_default().insert(kind);
                    }
                }
            }
            Err(error) => wrong.push(format!("{crate_name}/Cargo.toml: {error}")),
        }
    }
    let derived_kind = |name: &str| {
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

    if let Some(object) = inputs.gate.as_object() {
        for key in object.keys() {
            if !["about", "dependencies", "transitive"].contains(&key.as_str()) {
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
    let (dependencies, transitive) = (section("dependencies"), section("transitive"));

    // Every direct dependency has a reviewed decision.
    for name in manifest_kinds.keys() {
        if !dependencies.contains_key(name) {
            wrong.push(format!(
                "{name} is a direct {} dependency of the workspace with no reviewed entry under `dependencies` in dependency-gate.json",
                derived_kind(name).unwrap()
            ));
        }
    }

    // Each decision: complete, consistent with the lock and manifests, and gated.
    let mut capabilities: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (name, entry) in &dependencies {
        let Some(object) = entry.as_object() else {
            wrong.push(format!("`dependencies` entry {name} is not an object"));
            continue;
        };
        for field in object.keys() {
            if !ENTRY_FIELDS.contains(&field.as_str()) {
                wrong.push(format!("{name} has an unknown field {field:?}"));
            }
        }
        if !registry(name) {
            wrong.push(format!(
                "`dependencies` entry {name} is not a registry package in Cargo.lock"
            ));
            continue;
        }
        let Some(derived) = derived_kind(name) else {
            wrong.push(format!(
                "`dependencies` entry {name} is not a direct dependency of any workspace crate; drop it"
            ));
            continue;
        };
        if entry["why"]
            .as_str()
            .is_none_or(|why| why.trim().is_empty())
        {
            wrong.push(format!("{name} gives no reason (`why`)"));
        }
        match entry["kind"].as_str() {
            Some(kind) if KINDS.contains(&kind) => {
                if kind != derived {
                    wrong.push(format!(
                        "{name} is declared {kind}, but the workspace manifests make it {derived}"
                    ));
                }
            }
            _ => wrong.push(format!(
                "{name} needs a `kind`: one of runtime, build-only or dev-only"
            )),
        }
        let declared: BTreeSet<String> = match strings(&entry["capability"]) {
            Some(list) if !list.is_empty() => list.into_iter().collect(),
            _ => {
                wrong.push(format!(
                    "{name} needs a reviewed `capability`: none, or a set of {}",
                    CAPABILITIES[1..].join(", ")
                ));
                continue;
            }
        };
        for capability in &declared {
            if !CAPABILITIES.contains(&capability.as_str()) {
                wrong.push(format!(
                    "{name} declares an unknown capability {capability:?}"
                ));
            }
        }
        if declared.contains("none") && declared.len() > 1 {
            wrong.push(format!(
                "{name} declares `none` together with other capabilities"
            ));
        }
        let none = declared.iter().all(|c| c == "none");
        let destructive_capable = declared
            .iter()
            .any(|c| DESTRUCTIVE_CAPABILITIES.contains(&c.as_str()));
        // Cargo.lock may require more, never less.
        if raw_or_native(name) && !declared.contains("syscalls") {
            wrong.push(format!(
                "{name} is a raw system-call crate: its capability must include `syscalls`"
            ));
        }
        let raw_use = entry["raw_use"].as_str().filter(|s| !s.trim().is_empty());
        if raw_underneath(name) && none && raw_use.is_none() {
            wrong.push(format!(
                "Cargo.lock shows a raw system-call crate under {name}: declare a non-`none` capability, or record in `raw_use` what it uses the raw crate for"
            ));
        }
        if !entry["raw_use"].is_null() && (!raw_underneath(name) || !none) {
            wrong.push(format!(
                "{name}'s `raw_use` applies only to a `none` dependency over a raw system-call crate; drop it"
            ));
        }
        // Destructive paths.
        let listed: BTreeSet<String> = match &entry["destructive"] {
            serde_json::Value::Null => BTreeSet::new(),
            value => match strings(value) {
                Some(list) if value.is_array() => list.into_iter().collect(),
                _ => {
                    wrong.push(format!("{name}'s `destructive` is not a list of paths"));
                    BTreeSet::new()
                }
            },
        };
        let no_destructive_api = entry["no_destructive_api"]
            .as_str()
            .filter(|s| !s.trim().is_empty());
        let root = name.replace('-', "_");
        if destructive_capable {
            if listed.is_empty() && (no_destructive_api.is_none() || raw_or_native(name)) {
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
        } else {
            if !listed.is_empty() {
                wrong.push(format!(
                    "{name} lists destructive paths but declares no destructive-capable category"
                ));
            }
            if !entry["no_destructive_api"].is_null() {
                wrong.push(format!(
                    "{name}'s `no_destructive_api` applies only to a destructive-capable category; drop it"
                ));
            }
        }
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
        capabilities.insert(name.clone(), declared);
    }
    // clippy.toml names only std and reviewed dependencies.
    for path in &disallowed {
        let krate = path.split("::").next().unwrap();
        if !["std", "core", "alloc"].contains(&krate)
            && !dependencies
                .keys()
                .any(|name| name.replace('-', "_") == krate)
        {
            wrong.push(format!(
                "clippy.toml disallows {path}, but {krate} is not a reviewed dependency"
            ));
        }
    }

    // LOW-1: a build-only or dev-only dependency is never in the runtime graph.
    let mut parent: BTreeMap<String, String> = BTreeMap::new();
    let mut queue: Vec<String> = Vec::new();
    for (name, kinds) in &manifest_kinds {
        if kinds.contains(&DependencyKind::Normal) {
            parent.insert(name.clone(), "a workspace crate's [dependencies]".into());
            queue.push(name.clone());
        }
    }
    while let Some(name) = queue.pop() {
        if let Some(package) = packages.get(&name).filter(|p| p.registry) {
            for dependency in &package.dependencies {
                if !parent.contains_key(dependency) {
                    parent.insert(dependency.clone(), name.clone());
                    queue.push(dependency.clone());
                }
            }
        }
    }
    // A crate the workspace names only for tests or builds may still be linked through
    // another dependency (h2 under tonic): then `runtime_via` must say so, and its
    // review is a runtime one.
    for (name, entry) in &dependencies {
        let via = parent.get(name);
        match (entry["kind"].as_str(), via) {
            (Some(kind @ ("build-only" | "dev-only")), Some(via))
                if entry["runtime_via"].as_str() != Some(via.as_str()) =>
            {
                wrong.push(format!(
                    "{name} is declared {kind}, but Cargo.lock reaches it from the runtime dependencies (through {via}); record `runtime_via` if that is intended"
                ));
            }
            (_, None) if !entry["runtime_via"].is_null() => wrong.push(format!(
                "{name}'s `runtime_via` is stale: Cargo.lock does not reach it from the runtime dependencies"
            )),
            (Some("runtime"), _) if !entry["runtime_via"].is_null() => wrong.push(format!(
                "{name} is runtime; drop `runtime_via`"
            )),
            _ => {}
        }
    }

    // Packages that can wrap system calls and are not direct are named under `transitive`.
    for (name, package) in &packages {
        if package.registry
            && raw_underneath(name)
            && !dependencies.contains_key(name)
            && !transitive.contains_key(name)
        {
            wrong.push(format!(
                "{name} can wrap system calls (Cargo.lock) but dependency-gate.json does not list it"
            ));
        }
    }
    for (name, entry) in &transitive {
        if !registry(name) {
            wrong.push(format!(
                "`transitive` entry {name} is not a package in Cargo.lock"
            ));
            continue;
        }
        if manifest_kinds.contains_key(name) {
            wrong.push(format!(
                "{name} is a direct dependency, listed under `transitive`: give it a `dependencies` entry"
            ));
        }
        if !raw_underneath(name) {
            wrong.push(format!(
                "`transitive` entry {name} cannot wrap system calls; drop it"
            ));
        }
        if entry["why"]
            .as_str()
            .is_none_or(|why| why.trim().is_empty())
        {
            wrong.push(format!("`transitive` entry {name} gives no reason"));
        }
    }

    // Backstop 1: production names no destructive-looking function through a
    // dependency's path that clippy.toml does not disallow.
    let roots: BTreeMap<String, String> = dependencies
        .keys()
        .map(|name| (name.replace('-', "_"), name.clone()))
        .collect();
    let root_set: BTreeSet<String> = roots.keys().cloned().collect();
    for (label, text) in &inputs.sources {
        for path in rooted_paths(text, &root_set) {
            let name = &roots[&path[0]];
            let quiet = capabilities.get(name).is_some_and(|c| {
                !c.iter()
                    .any(|c| DESTRUCTIVE_CAPABILITIES.contains(&c.as_str()))
            }) || !dependencies[name]["no_destructive_api"].is_null();
            if path.last().is_some_and(|s| s == "*") && quiet {
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
                        let declared = capabilities
                            .get(name)
                            .map(|c| c.iter().cloned().collect::<Vec<_>>().join(", "))
                            .unwrap_or_default();
                        wrong.push(format!(
                            "{label}: production names {candidate}, which looks destructive (`{pattern}`) but clippy.toml does not disallow it; {name} is declared `{declared}`: review its capability and list its destructive paths"
                        ));
                    }
                    break;
                }
            }
        }
    }

    // Backstop 2: a dependency reviewed as having no destructive API, or declared without
    // a destructive-capable category, does not reach std's, Tokio's or libc's
    // destructive paths in its own locked source.
    let std_roots: BTreeSet<String> = ["std", "core", "alloc", "tokio", "libc"]
        .into_iter()
        .map(String::from)
        .collect();
    for (name, entry) in &dependencies {
        let Some(declared) = capabilities.get(name) else {
            continue;
        };
        let quiet = !declared
            .iter()
            .any(|c| DESTRUCTIVE_CAPABILITIES.contains(&c.as_str()))
            || !entry["no_destructive_api"].is_null();
        if !quiet {
            continue;
        }
        let Some(files) = inputs.dependency_sources.get(name) else {
            wrong.push(format!("{name}'s locked source was not available to scan"));
            continue;
        };
        let mut reached = BTreeSet::new();
        for (file, text) in files {
            for path in rooted_paths(dependency_production(text), &std_roots) {
                let mut candidate = path[0].clone();
                for segment in &path[1..] {
                    candidate = format!("{candidate}::{segment}");
                    let as_std = candidate
                        .replacen("core::", "std::", 1)
                        .replacen("alloc::", "std::", 1);
                    if disallowed.contains(&as_std) {
                        reached.insert(format!("{as_std} ({file})"));
                    }
                }
            }
        }
        if !reached.is_empty() {
            wrong.push(format!(
                "{name} is declared `{}`{}, but its locked source reaches {}: declare its capability and list its destructive paths",
                declared.iter().cloned().collect::<Vec<_>>().join(", "),
                if entry["no_destructive_api"].is_null() { "" } else { " with no destructive API" },
                reached.into_iter().collect::<Vec<_>>().join(", ")
            ));
        }
    }
    wrong
}

// ---------------------------------------------------------------------------------
// The workspace as it is.

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The registry source cargo extracted for `name` at `version` (cargo checked its
/// archive against Cargo.lock's checksum when it downloaded it).
fn registry_source(name: &str, version: &str) -> Result<PathBuf, String> {
    let home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .ok_or("neither CARGO_HOME nor HOME is set")?;
    let src = home.join("registry/src");
    let indexes = std::fs::read_dir(&src).map_err(|e| format!("{}: {e}", src.display()))?;
    for index in indexes {
        let candidate = index
            .map_err(|e| e.to_string())?
            .path()
            .join(format!("{name}-{version}"));
        if candidate.join("Cargo.toml").is_file() {
            return Ok(candidate);
        }
    }
    Err(format!(
        "no registry source for {name} {version} under {} (run `cargo fetch --locked`)",
        src.display()
    ))
}

/// A dependency's own library source files: `src/`, without `src/bin`, examples,
/// benches or test files.
fn library_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![root.join("src")];
    while let Some(directory) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() {
                if !["bin", "tests", "examples", "benches"].contains(&name.as_str()) {
                    stack.push(path);
                }
            } else if name.ends_with(".rs") && name != "tests.rs" {
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

fn workspace_inputs() -> Inputs {
    let root = workspace_root();
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
    let lock = read(&root.join("Cargo.lock"));
    let gate: serde_json::Value = serde_json::from_str(&read(&root.join("dependency-gate.json")))
        .expect("dependency-gate.json is not JSON");
    let packages = lock_packages(&lock);
    let mut dependency_sources = BTreeMap::new();
    if let Some(entries) = gate["dependencies"].as_object() {
        for name in entries.keys() {
            let Some(package) = packages.get(name) else {
                continue;
            };
            let mut files = Vec::new();
            for version in &package.versions {
                let Ok(source) = registry_source(name, version) else {
                    continue;
                };
                for path in library_files(&source) {
                    let label = format!(
                        "{name}-{version}/{}",
                        path.strip_prefix(&source).unwrap().display()
                    );
                    files.push((label, read(&path)));
                }
            }
            if !files.is_empty() {
                dependency_sources.insert(name.clone(), files);
            }
        }
    }
    Inputs {
        lock,
        manifests,
        sources: workspace_sources(&root),
        dependency_sources,
        gate,
        clippy: read(&root.join("clippy.toml")),
    }
}

/// HIGH-1: the gate holds for the workspace as it is.
#[test]
fn the_dependency_gate_holds() {
    let wrong = violations(&workspace_inputs());
    assert!(
        wrong.is_empty(),
        "the dependency gate fails:\n{}",
        wrong.join("\n")
    );
}

// ---------------------------------------------------------------------------------
// MEDIUM-1: the destructive lists are complete.

/// The locked libc's exported functions (`pub fn`, in any target's module), from the
/// registry source of the version Cargo.lock pins.
fn locked_libc_functions() -> BTreeSet<String> {
    let lock = read(&workspace_root().join("Cargo.lock"));
    let packages = lock_packages(&lock);
    let libc = &packages["libc"];
    let mut names = BTreeSet::new();
    for version in &libc.versions {
        let source = registry_source("libc", version).unwrap();
        for path in rust_files(&source.join("src"), false) {
            let toks = tokens(&read(&path));
            for (index, token) in toks.iter().enumerate() {
                if *token == Token::Ident("fn".into())
                    && let Some(Token::Ident(name)) = toks.get(index + 1)
                {
                    // `pub fn`, `pub unsafe fn`, `pub const fn`, `pub safe fn` and the like.
                    let public = toks[index.saturating_sub(4)..index]
                        .iter()
                        .any(|t| *t == Token::Ident("pub".into()));
                    if public {
                        names.insert(name.clone());
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
    let packages = lock_packages(&lock);
    let mut seen = 0;
    for version in &packages["tokio"].versions {
        let source = registry_source("tokio", version).unwrap();
        let fs = source.join("src/fs");
        for path in rust_files(&fs, false) {
            let file = path
                .strip_prefix(&fs)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let toks = tokens(&read(&path));
            for (index, token) in toks.iter().enumerate() {
                if *token != Token::Ident("fn".into()) {
                    continue;
                }
                let Some(Token::Ident(name)) = toks.get(index + 1) else {
                    continue;
                };
                let public = toks[index.saturating_sub(3)..index]
                    .iter()
                    .any(|t| *t == Token::Ident("pub".into()));
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
// Synthetic regressions.

const REGISTRY: &str = "source = \"registry+https://github.com/rust-lang/crates.io-index\"";

fn package(name: &str, deps: &[&str]) -> String {
    let deps: String = deps.iter().map(|d| format!(" \"{d}\",\n")).collect();
    format!(
        "[[package]]\nname = \"{name}\"\nversion = \"1.0.0\"\n{REGISTRY}\ndependencies = [\n{deps}]\n\n"
    )
}

/// A one-crate workspace: `demo` depends on libc (normal) and tempfile (dev), the
/// gate reviews both, and clippy disallows libc::kill and tempfile's persist.
fn demo(extra_lock: &str, extra_dependencies: &str, extra_workspace: &[&str]) -> Inputs {
    let workspace_deps: String = ["libc", "tempfile"]
        .iter()
        .chain(extra_workspace)
        .map(|d| format!(" \"{d}\",\n"))
        .collect();
    Inputs {
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
        sources: vec![("demo/src/lib.rs".into(), "pub fn f() {}\n".into())],
        dependency_sources: BTreeMap::new(),
        gate: serde_json::json!({
            "dependencies": {
                "libc": {"kind": "runtime", "capability": ["signals", "syscalls"], "destructive": ["libc::kill"], "why": "x"},
                "tempfile": {"kind": "dev-only", "capability": "filesystem", "destructive": ["tempfile::NamedTempFile::persist"], "why": "x"},
            },
            "transitive": {"rustix": {"why": "x"}},
        }),
        clippy: "disallowed-methods = [\n  { path = \"libc::kill\", reason = \"x\" },\n  { path = \"tempfile::NamedTempFile::persist\", reason = \"x\" },\n]\n".into(),
    }
}

fn check(inputs: &Inputs) -> String {
    violations(inputs).join("\n")
}

#[test]
fn the_synthetic_workspace_passes() {
    assert_eq!(check(&demo("", "", &[])), "");
}

/// B7 milestone 2 HIGH-1, Daybreak's `fs-err` PoC as a regression: an honest-looking
/// `std::fs` wrapper whose lock record shows no raw system-call crate.
#[test]
fn b7m2_an_fs_err_wrapper_declared_none_is_refused() {
    let fs_err_lock = package("fs-err", &["autocfg"]) + &package("autocfg", &[]);
    let fs_err_source = "use std::fs;\nuse std::path::Path;\n\
        pub fn remove_dir_all<P: AsRef<Path>>(path: P) -> std::io::Result<()> {\n    \
        fs::remove_dir_all(path.as_ref())\n}\n";
    let production = "use std::path::Path;\n\
        /// Removes a caller-selected tree.\n\
        pub fn remove_tree(path: &Path) -> std::io::Result<()> {\n    fs_err::remove_dir_all(path)\n}\n";
    let with = |entry: serde_json::Value, clippy_extra: &str, production: &str| {
        let mut inputs = demo(&fs_err_lock, "fs-err.workspace = true\n", &["fs-err"]);
        inputs.gate["dependencies"]["fs-err"] = entry;
        inputs.clippy = inputs.clippy.replace("]\n", &format!("{clippy_extra}]\n"));
        inputs.clippy = format!(
            "{}\n{}",
            inputs.clippy, "  { path = \"std::fs::remove_dir_all\", reason = \"x\" },\n"
        );
        // clippy.toml's std list, as the real file has it.
        inputs.clippy = inputs.clippy.replace(
            "disallowed-methods = [\n",
            "disallowed-methods = [\n  { path = \"std::fs::remove_dir_all\", reason = \"x\" },\n",
        );
        inputs.sources = vec![("demo/src/gate_bypass_poc.rs".into(), production.into())];
        inputs.dependency_sources.insert(
            "fs-err".into(),
            vec![("fs-err/src/lib.rs".into(), fs_err_source.into())],
        );
        inputs
    };

    // Unreviewed: refused.
    let mut unreviewed = with(serde_json::json!(null), "", production);
    unreviewed.gate["dependencies"]
        .as_object_mut()
        .unwrap()
        .remove("fs-err");
    let wrong = check(&unreviewed);
    assert!(
        wrong.contains(
            "fs-err is a direct runtime dependency of the workspace with no reviewed entry"
        ),
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
            "fs-err is declared `none`, but its locked source reaches std::fs::remove_dir_all"
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

/// HIGH-1: Cargo.lock may require a capability, never forbid one; and every decision
/// is complete.
#[test]
fn the_lock_graph_requires_but_never_overrides() {
    // A `none` dependency directly over libc needs a recorded reason, or a capability.
    let lock = package("tokio-util", &["libc"]);
    let mut inputs = demo(&lock, "tokio-util = \"0.7\"\n", &["tokio-util"]);
    inputs.gate["dependencies"]["tokio-util"] =
        serde_json::json!({"kind": "runtime", "capability": "none", "why": "x"});
    inputs
        .dependency_sources
        .insert("tokio-util".into(), vec![]);
    let wrong = check(&inputs);
    assert!(
        wrong.contains("Cargo.lock shows a raw system-call crate under tokio-util"),
        "{wrong}"
    );
    inputs.gate["dependencies"]["tokio-util"]["raw_use"] = serde_json::json!("libc::memchr only");
    assert_eq!(check(&inputs), "");
    inputs.gate["dependencies"]["tokio-util"] =
        serde_json::json!({"kind": "runtime", "capability": "network", "why": "x"});
    assert_eq!(check(&inputs), "");
    // A raw crate itself must say `syscalls`, and cannot claim no destructive API.
    let mut inputs = demo("", "", &[]);
    inputs.gate["dependencies"]["libc"]["capability"] = serde_json::json!("filesystem");
    let wrong = check(&inputs);
    assert!(
        wrong.contains("libc is a raw system-call crate: its capability must include `syscalls`"),
        "{wrong}"
    );
    let mut inputs = demo("", "", &[]);
    inputs.gate["dependencies"]["libc"]["destructive"] = serde_json::json!([]);
    inputs.gate["dependencies"]["libc"]["no_destructive_api"] = serde_json::json!("x");
    inputs.clippy = "disallowed-methods = [\n  { path = \"tempfile::NamedTempFile::persist\", reason = \"x\" },\n]\n".into();
    let wrong = check(&inputs);
    assert!(
        wrong.contains("libc declares signals, syscalls: list its destructive paths"),
        "{wrong}"
    );
    // Incomplete or unknown fields.
    let mut inputs = demo("", "", &[]);
    inputs.gate["dependencies"]["libc"]["capability"] = serde_json::json!([]);
    inputs.gate["dependencies"]["tempfile"]["destrutive"] = serde_json::json!([]);
    inputs.gate["dependencies"]["tempfile"]["kind"] = serde_json::json!("test");
    let wrong = check(&inputs);
    assert!(
        wrong.contains("libc needs a reviewed `capability`"),
        "{wrong}"
    );
    assert!(
        wrong.contains("tempfile has an unknown field \"destrutive\""),
        "{wrong}"
    );
    assert!(wrong.contains("tempfile needs a `kind`"), "{wrong}");
    // `none` with destructive paths, or a capability outside the list.
    let mut inputs = demo("", "", &[]);
    inputs.gate["dependencies"]["tempfile"]["capability"] = serde_json::json!(["none", "disk"]);
    let wrong = check(&inputs);
    assert!(
        wrong.contains("tempfile declares an unknown capability \"disk\""),
        "{wrong}"
    );
    assert!(
        wrong.contains("tempfile declares `none` together with other capabilities"),
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
        wrong.contains("rustix is not a reviewed dependency"),
        "{wrong}"
    );
    // A new raw crate, unreviewed, and its transitive raw dependency.
    let lock = package("nix", &["libc", "memmap2"]) + &package("memmap2", &["libc"]);
    let wrong = check(&demo(&lock, "nix = \"0.29\"\n", &["nix"]));
    assert!(
        wrong
            .contains("nix is a direct runtime dependency of the workspace with no reviewed entry"),
        "{wrong}"
    );
    assert!(wrong.contains("memmap2 can wrap system calls"), "{wrong}");
    // A stale entry and a renamed dependency.
    let mut inputs = demo(
        "",
        "libc2 = { package = \"libc\", version = \"0.2\" }\n",
        &[],
    );
    inputs.gate["transitive"]["gone"] = serde_json::json!({"why": "x"});
    let wrong = check(&inputs);
    assert!(
        wrong.contains("`transitive` entry gone is not a package"),
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
        inputs.gate["dependencies"]["tonic-prost-build"] = entry.clone();
        inputs.clippy = inputs.clippy.replace("]\n", &format!("{gated}]\n"));
        inputs
    };
    assert_eq!(check(&as_kind("build-dependencies")), "");
    let wrong = check(&as_kind("dependencies"));
    assert!(
        wrong.contains(
            "tonic-prost-build is declared build-only, but the workspace manifests make it runtime"
        ),
        "{wrong}"
    );
    assert!(
        wrong.contains("tonic-prost-build is declared build-only, but Cargo.lock reaches it from the runtime dependencies"),
        "{wrong}"
    );
    // tempfile is dev-only, but a runtime dependency that pulls it in puts it in the
    // runtime graph.
    let lock = package("tonic-prost-build", &["tempfile"]) + &package("cache", &["tempfile"]);
    let mut inputs = demo(&lock, "cache = \"1\"\n", &["cache"]);
    inputs.gate["dependencies"]["cache"] =
        serde_json::json!({"kind": "runtime", "capability": "none", "why": "x"});
    inputs.dependency_sources.insert("cache".into(), vec![]);
    let wrong = check(&inputs);
    assert!(
        wrong.contains("tempfile is declared dev-only, but Cargo.lock reaches it from the runtime dependencies (through cache)"),
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
