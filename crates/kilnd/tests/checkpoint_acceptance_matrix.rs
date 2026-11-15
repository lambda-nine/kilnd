//! Structural guard for the checkpoint acceptance ledger. Referencing a real test is
//! not a claim that it ran, or that it alone proves the whole acceptance scenario.
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const MATRIX: &str = include_str!("data/checkpoint-acceptance-matrix.json");
const SECTIONS: [&str; 3] = ["crash_points", "cases", "findings"];
const CRASH_IDS: [&str; 12] = [
    "before-c1",
    "after-c1-before-helper",
    "mid-copy",
    "c3-complete-c4-missing",
    "c4-committed-reply-lost",
    "fork-pin-not-dispatched",
    "mid-restore",
    "restored-ready-missing",
    "d1-interrupted",
    "d2-complete-d3-missing",
    "ready-artifact-corrupt",
    "unexplained-files",
];

fn matrix() -> Value {
    serde_json::from_str(MATRIX).expect("checkpoint acceptance matrix must be valid JSON")
}

fn entries<'a>(matrix: &'a Value, section: &str) -> &'a [Value] {
    matrix[section]
        .as_array()
        .unwrap_or_else(|| panic!("{section}: expected an entry array"))
}

fn id(entry: &Value) -> &str {
    entry["id"]
        .as_str()
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| panic!("entry without an id: {entry}"))
}

fn text(value: &Value) -> bool {
    value.as_str().is_some_and(|s| !s.trim().is_empty())
}

fn mac(entry: &Value) -> &[Value] {
    entry["mac"]
        .as_array()
        .unwrap_or_else(|| panic!("{}: mac must be an array", id(entry)))
}

fn has_vm(entry: &Value) -> bool {
    match &entry["vm"] {
        Value::Null => false,
        Value::Array(names) => !names.is_empty(),
        Value::String(slot) => slot.starts_with("planned:C6b:") && slot.len() > 12,
        _ => panic!("{}: invalid vm reference", id(entry)),
    }
}

#[derive(Debug)]
struct Definition {
    path: PathBuf,
    line: usize,
    ignored: bool,
    test: bool,
}

// Definitions in this workspace put the identifier on the same line as `fn`.
// Restrict the prefix so prose and string literals mentioning functions do not
// manufacture definitions. Generics and an optional space before `(` are accepted.
fn function_name(line: &str) -> Option<&str> {
    let mut line = line.trim_start();
    if let Some(rest) = line.strip_prefix("pub") {
        if let Some(visibility) = rest.strip_prefix('(') {
            line = visibility.split_once(')')?.1.trim_start();
        } else if rest.starts_with(char::is_whitespace) {
            line = rest.trim_start();
        } else {
            return None;
        }
    }
    for modifier in ["const ", "async ", "unsafe "] {
        if let Some(rest) = line.strip_prefix(modifier) {
            line = rest.trim_start();
        }
    }
    let rest = line.strip_prefix("fn ")?.trim_start();
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    let name = &rest[..end];
    if name.is_empty() || name.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    matches!(rest[end..].trim_start().chars().next(), Some('(' | '<')).then_some(name)
}

fn collect_definitions(dir: &Path, definitions: &mut BTreeMap<String, Vec<Definition>>) {
    let mut paths: Vec<_> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|entry| entry.expect("read crate directory entry").path())
        .collect();
    paths.sort();
    for path in paths {
        if path.file_name().is_some_and(|name| name == "target") {
            continue;
        }
        // Do not follow symlinks out of the source tree.
        let kind = fs::symlink_metadata(&path).expect("stat source path");
        if kind.is_dir() {
            collect_definitions(&path, definitions);
        } else if kind.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
            let source = fs::read_to_string(&path).expect("read Rust source");
            let lines: Vec<_> = source.lines().collect();
            for (index, line) in lines.iter().enumerate() {
                if let Some(name) = function_name(line) {
                    let attrs = &lines[index.saturating_sub(3)..index];
                    definitions
                        .entry(name.to_owned())
                        .or_default()
                        .push(Definition {
                            path: path.clone(),
                            line: index + 1,
                            ignored: attrs.iter().any(|s| s.trim_start().starts_with("#[ignore")),
                            test: attrs.iter().any(|s| {
                                let attr = s.trim_start();
                                attr.starts_with("#[test]") || attr.starts_with("#[tokio::test")
                            }),
                        });
                }
            }
        }
    }
}

fn check_name(
    entry: &Value,
    name: &Value,
    vm: bool,
    definitions: &BTreeMap<String, Vec<Definition>>,
) {
    let entry_id = id(entry);
    let name = name
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| panic!("{entry_id}: test name must be a nonempty string"));
    let found = definitions
        .get(name)
        .unwrap_or_else(|| panic!("{entry_id}: no function named {name} under crates/"));
    assert!(
        found.iter().any(|d| d.test && d.ignored == vm),
        "{entry_id}: {name} must name {} test; definitions: {}",
        if vm {
            "an #[ignore] VM"
        } else {
            "a non-ignored Mac/CI"
        },
        found
            .iter()
            .map(|d| format!(
                "{}:{} (test={}, ignored={})",
                d.path.display(),
                d.line,
                d.test,
                d.ignored
            ))
            .collect::<Vec<_>>()
            .join(", ")
    );
}

#[test]
fn acceptance_matrix_names_only_real_tests() {
    let matrix = matrix();
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("kilnd is a workspace crate");
    let mut definitions = BTreeMap::new();
    collect_definitions(crates, &mut definitions);
    for section in SECTIONS {
        for entry in entries(&matrix, section) {
            for name in mac(entry) {
                check_name(entry, name, false, &definitions);
            }
            match &entry["vm"] {
                Value::Null => {}
                Value::String(slot) => assert!(
                    slot.starts_with("planned:C6b:") && slot.len() > 12,
                    "{}: vm string must name a planned C6b slot",
                    id(entry)
                ),
                Value::Array(names) => {
                    for name in names {
                        check_name(entry, name, true, &definitions);
                    }
                }
                _ => panic!(
                    "{}: vm must be null, a planned slot or a test array",
                    id(entry)
                ),
            }
        }
    }
}

#[test]
fn acceptance_matrix_covers_every_design_crash_point() {
    let matrix = matrix();
    let rows = entries(&matrix, "crash_points");
    assert_eq!(rows.len(), CRASH_IDS.len(), "design crash point count");
    for (row, expected) in rows.iter().zip(CRASH_IDS) {
        assert_eq!(id(row), expected, "{expected}: wrong crash point or order");
        assert!(
            !mac(row).is_empty() || has_vm(row),
            "{expected}: crash point has neither Mac nor VM coverage"
        );
    }
}

fn public_text(entry_id: &str, value: &Value) {
    let lower = value.to_string().to_lowercase();
    for forbidden in ["/users/", "/home/", "~/"] {
        assert!(
            !lower.contains(forbidden),
            "{entry_id}: non-public text in acceptance matrix"
        );
    }
}

#[test]
fn acceptance_matrix_entries_are_complete() {
    let matrix = matrix();
    assert_eq!(matrix["format"], 1, "matrix: unsupported format");
    public_text("matrix notes", &matrix["notes"]);
    let mut ids = BTreeSet::new();
    for section in SECTIONS {
        for entry in entries(&matrix, section) {
            let entry_id = id(entry);
            assert!(ids.insert(entry_id), "{entry_id}: duplicate id");
            public_text(entry_id, entry);
            let covered = !mac(entry).is_empty() || has_vm(entry);
            let accepted = entry["disposition"].as_str() == Some("accepted");
            if accepted {
                assert!(
                    text(&entry["reason"]),
                    "{entry_id}: accepted entry needs a reason"
                );
            }
            if entry.get("gap").is_some() {
                assert!(
                    text(&entry["gap"]),
                    "{entry_id}: gap must explain missing coverage"
                );
            }
            assert!(
                covered || text(&entry["gap"]) || accepted,
                "{entry_id}: entry needs Mac/VM coverage, an explicit gap or accepted disposition"
            );
            if section == "findings" {
                assert!(
                    matches!(entry["severity"].as_str(), Some("HIGH" | "MEDIUM" | "LOW")),
                    "{entry_id}: invalid finding severity"
                );
                assert!(text(&entry["review"]), "{entry_id}: missing review label");
                assert!(
                    text(&entry["summary"]),
                    "{entry_id}: missing finding summary"
                );
            } else {
                assert!(
                    text(&entry["design"]),
                    "{entry_id}: missing design reference"
                );
            }
        }
    }
    public_text("matrix", &matrix);
}
