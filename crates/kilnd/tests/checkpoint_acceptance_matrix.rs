//! Structural guard for the checkpoint acceptance ledger. Referencing a real test is
//! not a claim that it alone proves the whole acceptance scenario. Compiled registry
//! membership and ignored status are checked by build.sh after every full test suite.
use serde_json::Value;
use std::collections::BTreeSet;

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

const CASE_IDS: [&str; 102] = [
    "11.2.1-round-trips",
    "11.2.2-acl",
    "11.2.2-file-capabilities",
    "11.2.2-socket",
    "11.2.2-fifo",
    "11.2.2-device",
    "11.2.2-unknown-xattrs",
    "11.2.2-redirect",
    "11.2.2-metacopy",
    "11.2.2-index",
    "11.2.2-protected-tree",
    "11.2.2-overlapping-writable-paths",
    "11.2.2-old-shims",
    "11.2.2-wrong-image-generation",
    "11.2.2-incompatible-spec",
    "11.2.2-destination-disk",
    "11.2.2-disabled-helper",
    "11.2.2-disabled-feature",
    "11.2.3-symlink-parents",
    "11.2.3-absolute-link-targets",
    "11.2.3-dot-dot-link-targets",
    "11.2.3-hardlink-chains",
    "11.2.3-hardlink-cycles",
    "11.2.3-hardlink-outside",
    "11.2.3-duplicate-paths",
    "11.2.3-root-replacement",
    "11.2.3-forged-type",
    "11.2.3-forged-size",
    "11.2.3-mount-crossing",
    "11.2.3-malformed-base64",
    "11.2.3-malformed-json",
    "11.2.3-depth",
    "11.2.3-count",
    "11.2.3-sparse",
    "11.2.3-inode-bombs",
    "11.2.3-sentinels",
    "11.2.3-fuzz-parsing",
    "11.2.3-fuzz-materialization",
    "11.2.3-arbitrary-device",
    "11.2.3-external-fd",
    "11.2.4-queued-exec",
    "11.2.4-queued-exec-stream",
    "11.2.4-direct-kiln-exec",
    "11.2.4-two-captures",
    "11.2.4-source-delete",
    "11.2.4-source-idle-expiry",
    "11.2.4-source-lifetime-expiry",
    "11.2.4-fork-delete",
    "11.2.4-fork-get",
    "11.2.4-fork-idle-expiry",
    "11.2.4-fork-lifetime-expiry",
    "11.2.4-fork-fan-out",
    "11.2.4-disconnect-helper",
    "11.2.4-downgrade-helper",
    "11.2.4-kill-worker",
    "11.2.4-kill-pid1",
    "11.2.4-output-queue",
    "11.2.4-control-queue",
    "11.2.4-deadline",
    "11.2.4-shutdown",
    "11.2.5-uid-caps",
    "11.2.5-node-caps",
    "11.2.5-lowered-budgets",
    "11.2.5-sparse-physical",
    "11.2.5-reflink-divergence",
    "11.2.5-metadata-exhaustion",
    "11.2.5-inode-exhaustion",
    "11.2.5-small-project-quota",
    "11.2.5-enospc-fsync",
    "11.2.5-enospc-rename",
    "11.2.5-worker-fd-absence",
    "11.2.5-sql-triggers",
    "11.2.5-membership-audit",
    "11.2.6-capture-boundaries",
    "11.2.6-delete-boundaries",
    "11.2.6-fork-pin-dispatch",
    "11.2.6-restore-publication",
    "11.2.6-reboot",
    "11.2.6-mismatched-backups",
    "11.2.6-stale-helper-epochs",
    "11.2.6-unknown-objects",
    "11.2.6-barrier-interruption",
    "11.2.7-foreign-ids",
    "11.2.7-foreign-filters",
    "11.2.7-root-on-behalf",
    "11.2.7-pagination-insert",
    "11.2.7-pagination-delete",
    "11.2.7-digest-v1",
    "11.2.7-digest-v2",
    "11.2.7-key-reuse",
    "11.2.7-key-conflict",
    "11.2.7-key-release",
    "11.2.7-retry-after-source-deletion",
    "11.2.7-retry-after-checkpoint-deletion",
    "11.2.7-record-caps",
    "11.2.7-wall-clock-jumps",
    "11.2.7-suspend",
    "11.2.7-reboot",
    "11.2.7-list-no-refresh",
    "11.2.7-get-bounded-refresh",
    "11.2.8-preallocation-refusal",
    "11.2.8-legacy-behavior",
];

const FINDING_IDS: [&str; 63] = [
    "C3-H1",
    "C3-M1",
    "C3-r1-H1",
    "C3-r1-L1",
    "C3-r1-L2",
    "C3-r2-L1",
    "C3-r2-L2",
    "C3-r2-L3",
    "C4-H1",
    "C5a-H1",
    "C5a-H2",
    "C5a-H3",
    "C5a-H4",
    "C5a-H5",
    "C5a-H6",
    "C5a-H7",
    "C5a-H8",
    "C5a-M1",
    "C5a-r1-H1",
    "C5a-r1-H2",
    "C5a-r1-H3",
    "C5a-r2-H1",
    "C5a-r2-H2",
    "C5a-r2-M1",
    "C5a-r3-H1",
    "C5a-r3-N1",
    "C5a-r3-N2",
    "C5a-r3-N3",
    "C5a-r4-H1",
    "C5a-r5-H1",
    "C5a-r5-H2",
    "C5a-r6-H1",
    "C5a-r6-N1",
    "C5a-r7-H1",
    "C5a-r7-J1",
    "C5a-r7-J2",
    "C5a-r7-VM-gap",
    "C5a-r8-H1",
    "C5a-ruling-G1",
    "C5a-ruling-G2",
    "C5a-r9-N1",
    "C5a2-H1",
    "C5a2-H2",
    "C5a2-H3",
    "C5a2-M1",
    "C5a2-M2",
    "C5a2-r1-H1",
    "C5a2-r1-M1",
    "C5a2-r1-M2",
    "C5a2-r1-M3",
    "C5a2-r1-L1",
    "C5a2-r2-M1",
    "C5a2-r2-M2",
    "C5a2-r2-L1",
    "C5a2-r2-L2",
    "C5b1-M1",
    "C5b1-M2",
    "C5b1-L1",
    "C5b2-H1",
    "C5b2-M1",
    "C5b2-L1",
    "C5b2-r1-M1",
    "C6b-V16",
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

fn check_name(entry: &Value, name: &Value) {
    let name = name
        .as_str()
        .unwrap_or_else(|| panic!("{}: test name must be a string", id(entry)));
    let segments: Vec<_> = name.split("::").collect();
    assert!(
        segments.len() >= 2
            && segments.iter().all(|s| {
                s.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                    && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            }),
        "{}: {name} must be a fully qualified test path",
        id(entry)
    );
}

#[test]
fn acceptance_matrix_names_are_fully_qualified() {
    let matrix = matrix();
    for section in SECTIONS {
        for entry in entries(&matrix, section) {
            for name in mac(entry) {
                check_name(entry, name);
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
                        check_name(entry, name);
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
fn acceptance_matrix_pins_every_case_and_finding() {
    let matrix = matrix();
    for (section, expected) in [
        ("cases", CASE_IDS.as_slice()),
        ("findings", FINDING_IDS.as_slice()),
    ] {
        let actual: Vec<_> = entries(&matrix, section).iter().map(id).collect();
        assert_eq!(actual, expected, "{section}: wrong required IDs or order");
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
