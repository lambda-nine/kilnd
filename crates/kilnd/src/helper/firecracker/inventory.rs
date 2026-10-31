//! Section 8.2's observations. An inventory is complete only when every namespace,
//! process and resource observation in it is fresh and bounded. A missing record is
//! never absence, an empty listing is never proof, and another instance's identities
//! never appear: node totals come from `Accounting` alone.
use super::journal::{InventoryRecord, InventorySnapshot};
use crate::helper::protocol::{ListRecord, ListStatus};
use crate::model::Id128;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The most encoded bytes one complete list may take.
pub const MAX_LIST_BYTES: usize = 1 << 20;

/// What a worker saw of one exact allocation's derived names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NamespaceObservation {
    /// The owned namespace was read and holds nothing for this allocation.
    Absent,
    Present {
        names: Vec<String>,
    },
    /// No fresh answer. Never interpreted as either of the above.
    Unknown {
        reason: String,
    },
}

/// One namespace's derived allocation directories, as actually observed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeObservation {
    Observed { allocations: BTreeSet<Id128> },
    Unknown { reason: String },
}

/// Where namespace evidence comes from. B3 has no real resources: production cannot
/// observe any, so it never reports absence. B4 adds the real owned namespaces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservationBackend {
    Disabled,
    /// A private directory of fake resources, injected only by internal tests.
    #[cfg(test)]
    FakeDirectory(std::path::PathBuf),
}

impl ObservationBackend {
    pub fn observe_allocation(&self, instance: Id128, allocation: Id128) -> NamespaceObservation {
        let _ = (instance, allocation);
        match self {
            Self::Disabled => NamespaceObservation::Unknown {
                reason: "resource observation is disabled before B4".into(),
            },
            #[cfg(test)]
            Self::FakeDirectory(root) => fake::observe_allocation(root, instance, allocation),
        }
    }

    pub fn observe_node(&self, instance: Id128) -> NodeObservation {
        let _ = instance;
        match self {
            Self::Disabled => NodeObservation::Unknown {
                reason: "resource observation is disabled before B4".into(),
            },
            #[cfg(test)]
            Self::FakeDirectory(root) => fake::observe_node(root, instance),
        }
    }
}

/// The fake namespace: `<root>/<instance>/fc-<allocation>/<resource>` files. Real
/// directory reads run in workers, so stalling them exercises the real process model.
#[cfg(test)]
pub(super) mod fake {
    use super::*;
    use std::path::{Path, PathBuf};

    pub fn allocation_dir(root: &Path, instance: Id128, allocation: Id128) -> PathBuf {
        root.join(instance.to_string())
            .join(super::super::identity::backend_id(allocation))
    }

    pub fn observe_allocation(
        root: &Path,
        instance: Id128,
        allocation: Id128,
    ) -> NamespaceObservation {
        let directory = allocation_dir(root, instance, allocation);
        match std::fs::read_dir(&directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                NamespaceObservation::Absent
            }
            Err(error) => NamespaceObservation::Unknown {
                reason: error.to_string(),
            },
            Ok(entries) => {
                let mut names = Vec::new();
                for entry in entries {
                    match entry {
                        Ok(entry) => names.push(entry.file_name().to_string_lossy().into_owned()),
                        Err(error) => {
                            return NamespaceObservation::Unknown {
                                reason: error.to_string(),
                            };
                        }
                    }
                }
                if names.is_empty() {
                    // The directory itself is an owned resource.
                    names.push(".".into());
                }
                names.sort();
                NamespaceObservation::Present { names }
            }
        }
    }

    pub fn observe_node(root: &Path, instance: Id128) -> NodeObservation {
        let directory = root.join(instance.to_string());
        let entries = match std::fs::read_dir(&directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return NodeObservation::Observed {
                    allocations: BTreeSet::new(),
                };
            }
            Err(error) => {
                return NodeObservation::Unknown {
                    reason: error.to_string(),
                };
            }
            Ok(entries) => entries,
        };
        let mut allocations = BTreeSet::new();
        for entry in entries {
            let Ok(entry) = entry else {
                return NodeObservation::Unknown {
                    reason: "unreadable namespace entry".into(),
                };
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            let parsed = name
                .strip_prefix("fc-")
                .and_then(|id| Id128::parse(id).ok());
            match parsed {
                Some(id) => {
                    allocations.insert(id);
                }
                // Never adopt or ignore a name that merely looks plausible.
                None => {
                    return NodeObservation::Unknown {
                        reason: format!("unrecognized namespace entry {name}"),
                    };
                }
            }
            if allocations.len() > super::super::journal::MAX_ACTIVE_LISTED {
                return NodeObservation::Unknown {
                    reason: "namespace exceeds the listing bound".into(),
                };
            }
        }
        NodeObservation::Observed { allocations }
    }
}

/// Freshness inputs for one allocation, from H's own worker table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WorkerFreshness {
    pub stop_fenced: bool,
    pub supervisor_stalled: bool,
    pub supervisor_missing: bool,
}

/// One complete-or-inconclusive answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssembledInventory {
    pub generation: u64,
    pub records: Vec<ListRecord>,
    pub complete: bool,
    pub incomplete_reason: Option<String>,
}

fn status_of(record: &InventoryRecord, freshness: &WorkerFreshness) -> ListStatus {
    if freshness.stop_fenced {
        return ListStatus::Quarantined;
    }
    if freshness.supervisor_stalled || freshness.supervisor_missing {
        return ListStatus::Unknown;
    }
    match record.phase.as_str() {
        "intent" | "preparing" => ListStatus::Busy,
        "stop_intent" | "quarantined" => ListStatus::Quarantined,
        "stopped" => ListStatus::StoppedWithResources,
        _ => ListStatus::Unknown,
    }
}

/// Combines the root journal, the owned namespace and process freshness. Any stale
/// source, an unexplained resource or an oversize result makes it incomplete; records
/// stay, marked Unknown where they cannot be established, and never read as absent.
pub fn assemble(
    journal: &InventorySnapshot,
    namespace: &NodeObservation,
    monitor_healthy: bool,
    freshness: &dyn Fn(Id128) -> WorkerFreshness,
) -> AssembledInventory {
    let mut incomplete: Option<String> = None;
    let mut note = |reason: String| {
        incomplete.get_or_insert(reason);
    };
    if journal.overflow {
        note("active allocations exceed the listing bound".into());
    }
    if !monitor_healthy {
        note("process monitor is not healthy".into());
    }
    let mut records = Vec::with_capacity(journal.records.len());
    let mut journaled = BTreeSet::new();
    for record in &journal.records {
        journaled.insert(record.allocation_id);
        let fresh = freshness(record.allocation_id);
        let status = status_of(record, &fresh);
        if status == ListStatus::Unknown {
            note(format!(
                "allocation {} has no fresh process observation",
                record.allocation_id
            ));
        }
        records.push(ListRecord {
            allocation_id: record.allocation_id,
            plan_digest: record.plan_digest,
            generation: record.generation,
            status,
        });
    }
    match namespace {
        NodeObservation::Unknown { reason } => {
            note(format!("namespace observation unavailable: {reason}"));
        }
        NodeObservation::Observed { allocations } => {
            if let Some(unexplained) = allocations.iter().find(|id| !journaled.contains(id)) {
                // A resource with no journal record is reported, never adopted or
                // deleted, and it blocks a complete answer.
                note(format!("unexplained resources for fc-{unexplained}"));
            }
        }
    }
    let encoded = serde_json::to_vec(&records)
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX);
    if encoded > MAX_LIST_BYTES {
        note("inventory exceeds its encoded bound".into());
    }
    AssembledInventory {
        generation: journal.generation,
        complete: incomplete.is_none(),
        incomplete_reason: incomplete,
        records,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Digest;

    fn record(byte: u8, phase: &str) -> InventoryRecord {
        InventoryRecord {
            allocation_id: Id128::from_bytes([byte; 16]),
            plan_digest: Digest::of(&[byte]),
            phase: phase.into(),
            generation: 7,
            unsettled_workers: 0,
        }
    }

    fn healthy(_: Id128) -> WorkerFreshness {
        WorkerFreshness::default()
    }

    fn snapshot(records: Vec<InventoryRecord>) -> InventorySnapshot {
        InventorySnapshot {
            generation: 9,
            records,
            overflow: false,
        }
    }

    #[test]
    fn complete_only_when_every_source_is_fresh_and_explained() {
        let a = record(1, "preparing");
        let namespace = NodeObservation::Observed {
            allocations: [a.allocation_id].into(),
        };
        let done = assemble(&snapshot(vec![a.clone()]), &namespace, true, &healthy);
        assert!(done.complete, "{:?}", done.incomplete_reason);
        assert_eq!(done.records[0].status, ListStatus::Busy);
        assert_eq!(done.generation, 9);
    }

    #[test]
    fn a_missing_record_is_never_absence_and_an_empty_stale_list_is_not_complete() {
        // Unknown namespace with no journal records: not "nothing exists".
        let unknown = NodeObservation::Unknown {
            reason: "worker shortage".into(),
        };
        let listed = assemble(&snapshot(vec![]), &unknown, true, &healthy);
        assert!(!listed.complete);
        assert!(listed.records.is_empty());
        assert!(
            listed
                .incomplete_reason
                .unwrap()
                .contains("worker shortage")
        );
        // A real resource with no journal record blocks completeness.
        let stray = Id128::from_bytes([3; 16]);
        let observed = NodeObservation::Observed {
            allocations: [stray].into(),
        };
        let listed = assemble(&snapshot(vec![]), &observed, true, &healthy);
        assert!(!listed.complete);
        assert!(
            listed
                .incomplete_reason
                .unwrap()
                .contains(&stray.to_string())
        );
    }

    #[test]
    fn stale_processes_or_monitor_make_records_unknown_and_incomplete() {
        let a = record(1, "preparing");
        let namespace = NodeObservation::Observed {
            allocations: [a.allocation_id].into(),
        };
        let stalled = |_: Id128| WorkerFreshness {
            supervisor_stalled: true,
            ..WorkerFreshness::default()
        };
        let listed = assemble(&snapshot(vec![a.clone()]), &namespace, true, &stalled);
        assert!(!listed.complete);
        assert_eq!(listed.records[0].status, ListStatus::Unknown);
        let listed = assemble(&snapshot(vec![a.clone()]), &namespace, false, &healthy);
        assert!(!listed.complete);
        let fenced = |_: Id128| WorkerFreshness {
            stop_fenced: true,
            ..WorkerFreshness::default()
        };
        let listed = assemble(&snapshot(vec![a]), &namespace, true, &fenced);
        assert_eq!(listed.records[0].status, ListStatus::Quarantined);
    }

    #[test]
    fn overflow_is_an_error_not_a_truncated_complete_list() {
        let journal = InventorySnapshot {
            generation: 1,
            records: vec![],
            overflow: true,
        };
        let namespace = NodeObservation::Observed {
            allocations: BTreeSet::new(),
        };
        assert!(!assemble(&journal, &namespace, true, &healthy).complete);
    }

    #[test]
    fn production_observation_never_reports_absence() {
        let backend = ObservationBackend::Disabled;
        let (i, a) = (Id128::from_bytes([1; 16]), Id128::from_bytes([2; 16]));
        assert!(matches!(
            backend.observe_allocation(i, a),
            NamespaceObservation::Unknown { .. }
        ));
        assert!(matches!(
            backend.observe_node(i),
            NodeObservation::Unknown { .. }
        ));
    }

    #[test]
    fn fake_directory_distinguishes_absent_present_and_unexplained_names() {
        let temp = tempfile::tempdir().unwrap();
        let (i, a) = (Id128::from_bytes([1; 16]), Id128::from_bytes([2; 16]));
        let backend = ObservationBackend::FakeDirectory(temp.path().to_path_buf());
        assert_eq!(
            backend.observe_allocation(i, a),
            NamespaceObservation::Absent
        );
        let directory = fake::allocation_dir(temp.path(), i, a);
        std::fs::create_dir_all(&directory).unwrap();
        assert_eq!(
            backend.observe_allocation(i, a),
            NamespaceObservation::Present {
                names: vec![".".into()]
            }
        );
        std::fs::write(directory.join("work.xfs"), b"").unwrap();
        assert_eq!(
            backend.observe_allocation(i, a),
            NamespaceObservation::Present {
                names: vec!["work.xfs".into()]
            }
        );
        assert_eq!(
            backend.observe_node(i),
            NodeObservation::Observed {
                allocations: [a].into()
            }
        );
        std::fs::create_dir(temp.path().join(i.to_string()).join("looks-like-mine")).unwrap();
        assert!(matches!(
            backend.observe_node(i),
            NodeObservation::Unknown { .. }
        ));
    }
}
