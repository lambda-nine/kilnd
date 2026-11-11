//! Exec options (API additions design, section 4): one command's working directory and
//! environment overrides, their validation, the merge with a sandbox's defaults, and
//! kiln's options frame (operation 5, `docs/exec-protocol-v1.md` in kiln).
//!
//! Values are caller data that may be sensitive. Nothing here formats a value: the
//! `Debug` of [`EnvVar`] and [`ExecOptions`] redacts it, and every validation error names
//! an entry by its position, never by its contents.

use serde::{Deserialize, Serialize};

/// kiln capability bit 5: PID 1 accepts operation 5 and the CLI `--exec-options-fd`.
pub const FEATURE_EXEC_OPTIONS: u32 = 0x20;
/// The longest cwd, in bytes. A code ceiling: flags may only lower it.
pub const MAX_CWD_BYTES: usize = 4096;
pub const MAX_ENV_ENTRIES: usize = 64;
pub const MAX_ENV_NAME_BYTES: usize = 128;
pub const MAX_ENV_VALUE_BYTES: usize = 4096;
/// The sum of `len(name) + len(value) + 2` over one list.
pub const MAX_ENV_TOTAL_BYTES: usize = 32_768;
/// kiln's read bound for an options memfd. Every frame within the bounds above is at
/// most 37,272 bytes, so this only bounds reads.
pub const MAX_FRAME_BYTES: usize = 40 * 1024;
const FRAME_MAGIC: &[u8; 8] = b"KILNOPT\0";
const FRAME_HEADER: usize = 24;

/// One environment override. Its `Debug` shows the name and the value's length only.
/// On the helper wire it is the two-element array `[name, value]`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "(String, String)", into = "(String, String)")]
pub struct EnvVar {
    pub name: String,
    pub value: String,
}

impl EnvVar {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

impl std::fmt::Debug for EnvVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EnvVar {{ name: {:?}, value: <redacted {} bytes> }}",
            self.name,
            self.value.len()
        )
    }
}

impl From<(String, String)> for EnvVar {
    fn from((name, value): (String, String)) -> Self {
        Self { name, value }
    }
}

impl From<EnvVar> for (String, String) {
    fn from(v: EnvVar) -> Self {
        (v.name, v.value)
    }
}

/// The options one execution runs with: `None` and empty select kiln's operation 4,
/// exactly as before exec options existed. `env` holds the effective overrides
/// (sandbox defaults overlaid by the request), strictly ascending by name bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecOptions {
    pub cwd: Option<String>,
    pub env: Vec<EnvVar>,
}

impl ExecOptions {
    /// No options: today's operation 4.
    pub const EMPTY: ExecOptions = ExecOptions {
        cwd: None,
        env: Vec::new(),
    };

    pub fn is_empty(&self) -> bool {
        self.cwd.is_none() && self.env.is_empty()
    }

    /// The helper's and kiln's strict form: a valid cwd if any, and env strictly
    /// ascending by name bytes (so no duplicates) within `limits`. There is exactly one
    /// accepted encoding of each option set.
    pub fn validate_strict(&self, limits: &EnvLimits, max_cwd: usize) -> Result<(), String> {
        if let Some(cwd) = &self.cwd {
            validate_cwd(cwd, max_cwd)?;
        }
        validate_env(&self.env, limits, "env")?;
        if self
            .env
            .windows(2)
            .any(|pair| pair[0].name.as_bytes() >= pair[1].name.as_bytes())
        {
            return Err("env entries must be strictly ascending by name".into());
        }
        Ok(())
    }

    /// kiln's options frame for these (already validated) options, little endian:
    /// `KILNOPT\0`, version 1, reserved 0, total length, cwd length, entry count, the cwd
    /// bytes, then each entry as `u32 len, name, u32 len, value`.
    pub fn encode_frame(&self) -> Vec<u8> {
        let cwd = self.cwd.as_deref().unwrap_or("").as_bytes();
        let body: usize = self
            .env
            .iter()
            .map(|e| 8 + e.name.len() + e.value.len())
            .sum();
        let total = FRAME_HEADER + cwd.len() + body;
        let mut frame = Vec::with_capacity(total);
        frame.extend_from_slice(FRAME_MAGIC);
        frame.extend_from_slice(&1u16.to_le_bytes());
        frame.extend_from_slice(&0u16.to_le_bytes());
        frame.extend_from_slice(&(total as u32).to_le_bytes());
        frame.extend_from_slice(&(cwd.len() as u32).to_le_bytes());
        frame.extend_from_slice(&(self.env.len() as u32).to_le_bytes());
        frame.extend_from_slice(cwd);
        for entry in &self.env {
            frame.extend_from_slice(&(entry.name.len() as u32).to_le_bytes());
            frame.extend_from_slice(entry.name.as_bytes());
            frame.extend_from_slice(&(entry.value.len() as u32).to_le_bytes());
            frame.extend_from_slice(entry.value.as_bytes());
        }
        frame
    }
}

/// The environment bounds of one list: the request's, a sandbox's defaults or their
/// merge. Flags may lower each below its code ceiling, never raise it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnvLimits {
    pub max_entries: usize,
    pub max_name_bytes: usize,
    pub max_value_bytes: usize,
    pub max_total_bytes: usize,
}

impl EnvLimits {
    /// The code ceilings, which are also the helper's.
    pub const CEILINGS: EnvLimits = EnvLimits {
        max_entries: MAX_ENV_ENTRIES,
        max_name_bytes: MAX_ENV_NAME_BYTES,
        max_value_bytes: MAX_ENV_VALUE_BYTES,
        max_total_bytes: MAX_ENV_TOTAL_BYTES,
    };

    /// Whether every bound is within its ceiling and nonzero.
    pub fn within_ceilings(&self) -> bool {
        (1..=MAX_ENV_ENTRIES).contains(&self.max_entries)
            && (1..=MAX_ENV_NAME_BYTES).contains(&self.max_name_bytes)
            && self.max_value_bytes <= MAX_ENV_VALUE_BYTES
            && (1..=MAX_ENV_TOTAL_BYTES).contains(&self.max_total_bytes)
    }
}

impl Default for EnvLimits {
    fn default() -> Self {
        Self::CEILINGS
    }
}

/// A cwd: starts with `/`, at most `max` bytes, no NUL. Not normalized: `..` and
/// symlinks resolve inside the sandbox's own root. Empty is not a cwd; callers map an
/// empty API field to `None` first.
pub fn validate_cwd(cwd: &str, max: usize) -> Result<(), String> {
    if !cwd.starts_with('/') {
        return Err("cwd must be an absolute path starting with '/'".into());
    }
    if cwd.len() > max {
        return Err(format!("cwd is {} bytes; the limit is {max}", cwd.len()));
    }
    if cwd.contains('\0') {
        return Err("cwd must not contain NUL".into());
    }
    Ok(())
}

/// Whether `name` matches `[A-Za-z_][A-Za-z0-9_]*`.
pub fn valid_env_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes
        .first()
        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

/// One environment list (`what` names it in errors: `env` or `default_env`). Entries
/// may come in any order; a name given twice is refused, not resolved. Errors name an
/// entry by position and never quote a name or value.
pub fn validate_env(env: &[EnvVar], limits: &EnvLimits, what: &str) -> Result<(), String> {
    if env.len() > limits.max_entries {
        return Err(format!(
            "{what} has {} entries; the limit is {}",
            env.len(),
            limits.max_entries
        ));
    }
    let mut total = 0usize;
    let mut seen = std::collections::HashSet::with_capacity(env.len());
    for (i, entry) in env.iter().enumerate() {
        if !valid_env_name(&entry.name) {
            return Err(format!(
                "{what}[{i}]: the name must match [A-Za-z_][A-Za-z0-9_]*"
            ));
        }
        if entry.name.len() > limits.max_name_bytes {
            return Err(format!(
                "{what}[{i}]: the name is {} bytes; the limit is {}",
                entry.name.len(),
                limits.max_name_bytes
            ));
        }
        if entry.value.len() > limits.max_value_bytes {
            return Err(format!(
                "{what}[{i}]: the value is {} bytes; the limit is {}",
                entry.value.len(),
                limits.max_value_bytes
            ));
        }
        if entry.value.contains('\0') {
            return Err(format!("{what}[{i}]: the value must not contain NUL"));
        }
        if !seen.insert(entry.name.as_str()) {
            return Err(format!(
                "{what}[{i}]: the name repeats an earlier entry; give each name once"
            ));
        }
        total += entry.name.len() + entry.value.len() + 2;
    }
    if total > limits.max_total_bytes {
        return Err(format!(
            "{what} totals {total} bytes (name + value + 2 per entry); the limit is {}",
            limits.max_total_bytes
        ));
    }
    Ok(())
}

/// The effective overrides: `defaults` overlaid by `request`, the request winning by
/// name, sorted by name bytes. Each input must already be valid (no repeated names).
pub fn merge_env(defaults: &[EnvVar], request: &[EnvVar]) -> Vec<EnvVar> {
    let mut merged: std::collections::BTreeMap<&[u8], &EnvVar> =
        defaults.iter().map(|e| (e.name.as_bytes(), e)).collect();
    for entry in request {
        merged.insert(entry.name.as_bytes(), entry);
    }
    merged.into_values().cloned().collect()
}

/// `env` sorted by name bytes, for the digests and the frame.
pub fn sorted_env(env: &[EnvVar]) -> Vec<EnvVar> {
    let mut sorted = env.to_vec();
    sorted.sort_by(|a, b| {
        a.name
            .as_bytes()
            .cmp(b.name.as_bytes())
            .then_with(|| a.value.as_bytes().cmp(b.value.as_bytes()))
    });
    sorted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn frames_match_kilns_goldens() {
        // kiln docs/exec-protocol-v1.md, "Exec options (operation 5)".
        assert_eq!(
            ExecOptions::EMPTY.encode_frame(),
            hex("4b494c4e4f505400 0100 0000 18000000 00000000 00000000")
        );
        let options = ExecOptions {
            cwd: Some("/w".into()),
            env: vec![EnvVar::new("A", ""), EnvVar::new("B", "2")],
        };
        options
            .validate_strict(&EnvLimits::CEILINGS, MAX_CWD_BYTES)
            .unwrap();
        assert_eq!(
            options.encode_frame(),
            hex("4b494c4e4f505400 0100 0000 2d000000 02000000 02000000 2f77
                 01000000 41 00000000  01000000 42 01000000 32")
        );
    }

    #[test]
    fn the_largest_valid_frame_fits_kilns_read_bound() {
        // 64 entries of 128-byte names and values filling the total exactly.
        let name = |i: usize| format!("{}{:03}", "N".repeat(125), i);
        let per = MAX_ENV_TOTAL_BYTES / MAX_ENV_ENTRIES;
        let env: Vec<_> = (0..MAX_ENV_ENTRIES)
            .map(|i| EnvVar::new(name(i), "v".repeat(per - 128 - 2)))
            .collect();
        let options = ExecOptions {
            cwd: Some(format!("/{}", "c".repeat(MAX_CWD_BYTES - 1))),
            env,
        };
        options
            .validate_strict(&EnvLimits::CEILINGS, MAX_CWD_BYTES)
            .unwrap();
        let frame = options.encode_frame();
        assert_eq!(frame.len(), 37_272);
        assert!(frame.len() <= MAX_FRAME_BYTES);
    }

    #[test]
    fn every_bound_and_one_past_it() {
        let limits = EnvLimits::CEILINGS;
        validate_cwd(
            &format!("/{}", "a".repeat(MAX_CWD_BYTES - 1)),
            MAX_CWD_BYTES,
        )
        .unwrap();
        assert!(validate_cwd(&format!("/{}", "a".repeat(MAX_CWD_BYTES)), MAX_CWD_BYTES).is_err());
        for bad in ["", "relative", "./x", "/a\0b"] {
            assert!(validate_cwd(bad, MAX_CWD_BYTES).is_err(), "{bad:?}");
        }
        for good in ["/", "/a/../b", "/./x", "//x", "/雪"] {
            validate_cwd(good, MAX_CWD_BYTES).unwrap();
        }
        let entries = |n: usize| {
            (0..n)
                .map(|i| EnvVar::new(format!("V{i}"), ""))
                .collect::<Vec<_>>()
        };
        validate_env(&entries(64), &limits, "env").unwrap();
        assert!(validate_env(&entries(65), &limits, "env").is_err());
        let one = |name: String, value: String| vec![EnvVar::new(name, value)];
        validate_env(&one("N".repeat(128), String::new()), &limits, "env").unwrap();
        assert!(validate_env(&one("N".repeat(129), String::new()), &limits, "env").is_err());
        validate_env(&one("N".into(), "v".repeat(4096)), &limits, "env").unwrap();
        assert!(validate_env(&one("N".into(), "v".repeat(4097)), &limits, "env").is_err());
        // The total counts name + value + 2: eight 4,093-byte values with 1-byte
        // names fill 32,768 exactly.
        let full: Vec<_> = (0..8)
            .map(|i| EnvVar::new(((b'A' + i) as char).to_string(), "v".repeat(4093)))
            .collect();
        validate_env(&full, &limits, "env").unwrap();
        let mut over = full.clone();
        over[0].value.push('v');
        assert!(validate_env(&over, &limits, "env").is_err());
        for name in ["", "1A", "A-B", "A B", "A=B", "雪", "A\0"] {
            assert!(
                validate_env(&one(name.into(), String::new()), &limits, "env").is_err(),
                "{name:?}"
            );
        }
        for name in ["_", "a", "A_1", "_9"] {
            validate_env(&one(name.into(), String::new()), &limits, "env").unwrap();
        }
        assert!(validate_env(&one("A".into(), "a\0b".into()), &limits, "env").is_err());
        let duplicate = vec![EnvVar::new("A", "1"), EnvVar::new("A", "1")];
        assert!(validate_env(&duplicate, &limits, "env").is_err());
        // Lowered flags bind too.
        let lowered = EnvLimits {
            max_entries: 1,
            max_name_bytes: 2,
            max_value_bytes: 3,
            max_total_bytes: 7,
        };
        validate_env(&one("AB".into(), "abc".into()), &lowered, "env").unwrap();
        assert!(validate_env(&one("ABC".into(), "a".into()), &lowered, "env").is_err());
        assert!(validate_env(&one("A".into(), "abcd".into()), &lowered, "env").is_err());
        assert!(validate_env(&entries(2), &lowered, "env").is_err());
    }

    #[test]
    fn errors_never_quote_names_or_values() {
        let secret = "CANARY_s3cr3t_value";
        let cases = [
            vec![EnvVar::new(format!("{secret}=x"), secret)],
            vec![EnvVar::new("A", format!("{secret}\0"))],
            vec![EnvVar::new("A", secret.repeat(300))],
            vec![EnvVar::new(secret, secret), EnvVar::new(secret, secret)],
        ];
        for env in cases {
            let error = validate_env(&env, &EnvLimits::CEILINGS, "env").unwrap_err();
            assert!(!error.contains("CANARY"), "{error}");
        }
        let options = ExecOptions {
            cwd: None,
            env: vec![EnvVar::new("B", secret), EnvVar::new("A", secret)],
        };
        let error = options
            .validate_strict(&EnvLimits::CEILINGS, MAX_CWD_BYTES)
            .unwrap_err();
        assert!(!error.contains("CANARY"), "{error}");
        let debug = format!("{options:?} {:?}", options.env[0]);
        assert!(!debug.contains("s3cr3t"), "{debug}");
        assert!(debug.contains("<redacted 19 bytes>"), "{debug}");
    }

    #[test]
    fn merge_overlays_the_request_by_name_and_sorts_by_bytes() {
        let defaults = vec![
            EnvVar::new("PATH", "/d"),
            EnvVar::new("A0", "d"),
            EnvVar::new("Z", "z"),
        ];
        let request = vec![EnvVar::new("PATH", "/r"), EnvVar::new("A", "")];
        let merged = merge_env(&defaults, &request);
        let pairs: Vec<_> = merged
            .iter()
            .map(|e| (e.name.as_str(), e.value.as_str()))
            .collect();
        assert_eq!(pairs, [("A", ""), ("A0", "d"), ("PATH", "/r"), ("Z", "z")]);
        assert!(merge_env(&[], &[]).is_empty());
        // Byte order, not locale: "_" (0x5f) after "Z" (0x5a), before "a".
        let merged = merge_env(
            &[
                EnvVar::new("a", ""),
                EnvVar::new("_", ""),
                EnvVar::new("Z", ""),
            ],
            &[],
        );
        let names: Vec<_> = merged.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["Z", "_", "a"]);
    }

    #[test]
    fn strict_form_refuses_unsorted_and_duplicate_entries() {
        let limits = EnvLimits::CEILINGS;
        let sorted = ExecOptions {
            cwd: None,
            env: vec![EnvVar::new("A", ""), EnvVar::new("A0", "")],
        };
        sorted.validate_strict(&limits, MAX_CWD_BYTES).unwrap();
        for env in [
            vec![EnvVar::new("A0", ""), EnvVar::new("A", "")],
            vec![EnvVar::new("A", ""), EnvVar::new("A", "")],
        ] {
            assert!(
                ExecOptions { cwd: None, env }
                    .validate_strict(&limits, MAX_CWD_BYTES)
                    .is_err()
            );
        }
        assert!(
            ExecOptions {
                cwd: Some(String::new()),
                env: vec![]
            }
            .validate_strict(&limits, MAX_CWD_BYTES)
            .is_err()
        );
    }

    #[test]
    fn env_vars_cross_the_helper_wire_as_pairs() {
        let env = vec![EnvVar::new("A", "1")];
        assert_eq!(serde_json::to_string(&env).unwrap(), r#"[["A","1"]]"#);
        let back: Vec<EnvVar> = serde_json::from_str(r#"[["A","1"]]"#).unwrap();
        assert_eq!(back, env);
        assert!(serde_json::from_str::<Vec<EnvVar>>(r#"[["A"]]"#).is_err());
        assert!(serde_json::from_str::<Vec<EnvVar>>(r#"[{"name":"A","value":"1"}]"#).is_err());
    }
}
