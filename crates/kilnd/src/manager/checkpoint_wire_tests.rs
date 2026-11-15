//! The checkpoint contract on the wire (C6a adversarial review H7). The contract golden
//! records Debug values of types generated from the same proto the service uses, so a
//! renumbered field moves both sides together. Here:
//!
//! - `checkpoint_wire_golden_matches` pins the encoded bytes of fixed checkpoint messages,
//!   every field a distinct nonzero value, and the checkpoint enums' numbers, in
//!   `tests/data/checkpoint-wire.json`;
//! - `a_previous_client_reads_and_writes_every_checkpoint_field` decodes them with
//!   `prior`, structs whose tags are written out here by hand, as a client built from the
//!   published v1 proto, and the reverse.
//!
//! - `checkpoint_field_numbers_match_the_pinned_table` checks every field of every
//!   checkpoint message, the checkpoint fields of the shared ones and the checkpoint
//!   enums against a table written here by hand, never blessed, read from the proto the
//!   code is generated from (C6a recheck 1 HIGH 7).
//!
//! A renumbered, retyped or removed field fails all three. Values are distinct within
//! each message, the booleans included across the two checkpoints, so swapped tags
//! change the bytes; the previous-client expectations are literals, not copies.

use std::collections::{BTreeMap, BTreeSet};

use prost::Message;

use super::*;

pub(super) const WIRE: &str = "checkpoint-wire.json";

/// 2026-01-15T08:00:00Z, so times read as times; the offsets name their field numbers.
const T: i64 = 1_768_464_000_000;

fn policy(lifetime: u64, idle: u64) -> Option<pb::ExpiryPolicy> {
    Some(pb::ExpiryPolicy {
        max_lifetime_ms: lifetime,
        idle_timeout_ms: idle,
    })
}

/// Every field set, each to its own value.
fn checkpoint() -> pb::Checkpoint {
    pb::Checkpoint {
        id: "cp-0123456789abcdef0123456789abcdef".into(),
        state: pb::CheckpointState::Ready.into(),
        owner_uid: 1003,
        sandbox_id: "sb-0123456789abcd04".into(),
        created_at_unix_ms: T + 5,
        ready_at_unix_ms: T + 6,
        size_bytes: 7_007,
        logical_bytes: 8_008,
        allocated_bytes: 9_009,
        content_sha256: "a0".repeat(32),
        image: "image-11".into(),
        image_content_sha256: "c1".repeat(32),
        read_only_root: true,
        writable_paths: vec!["/w14".into(), "/w14/b".into()],
        excluded_paths: vec!["/x15".into(), "/x15/b".into()],
        scope: pb::CheckpointScope::PersistentOverlay.into(),
        expiry: Some(pb::CheckpointExpiryStatus {
            effective: policy(17_101, 17_102),
            lifetime_expires_at_unix_ms: T + 17_002,
            idle_expires_at_unix_ms: T + 17_003,
            last_activity_at_unix_ms: T + 17_004,
            idle_paused: true,
        }),
        failure_reason: "reason-18".into(),
        deletion_reason: pb::DeletionReason::ExpiredLifetime.into(),
        request_id: "key-20".into(),
        request_id_released: true,
        format_version: 22,
        max_size_bytes: 23_023,
    }
}

/// A second, DELETED row for the list page.
fn deleted_checkpoint() -> pb::Checkpoint {
    pb::Checkpoint {
        id: "cp-fedcba9876543210fedcba9876543210".into(),
        state: pb::CheckpointState::Deleted.into(),
        deletion_reason: pb::DeletionReason::ExpiredIdle.into(),
        // Unlike checkpoint(): equal booleans would hide swapped tags 13 and 21.
        read_only_root: false,
        request_id_released: true,
        expiry: Some(pb::CheckpointExpiryStatus {
            effective: policy(60_000, 30_000),
            ..Default::default()
        }),
        ..checkpoint()
    }
}

fn capture_request() -> pb::CheckpointSandboxRequest {
    pb::CheckpointSandboxRequest {
        sandbox_id: "sb-0123456789abcd01".into(),
        request_id: "key-2".into(),
        expiry: policy(3_001, 3_002),
        max_size_bytes: 4_004,
    }
}

fn list_request() -> pb::ListCheckpointsRequest {
    pb::ListCheckpointsRequest {
        sandbox_id: "sb-0123456789abcd01".into(),
        page_size: 2,
        page_token: "page-3".into(),
    }
}

fn list_response() -> pb::ListCheckpointsResponse {
    pb::ListCheckpointsResponse {
        checkpoints: vec![checkpoint(), deleted_checkpoint()],
        next_page_token: "page-2".into(),
    }
}

fn delete_request() -> pb::DeleteCheckpointRequest {
    pb::DeleteCheckpointRequest {
        id: "cp-0123456789abcdef0123456789abcdef".into(),
        release_request_id: true,
    }
}

fn fork_request() -> pb::CreateSandboxRequest {
    pb::CreateSandboxRequest {
        spec: Some(pb::SandboxSpec {
            image: "image-1".into(),
            limits: Some(pb::ResourceLimits {
                memory_bytes: 536_870_912,
                cpu_millis: 1_000,
                pids: 128,
                disk_bytes: 1_073_741_824,
            }),
            read_only_root: true,
            writable_paths: vec!["/w".into()],
            ..Default::default()
        }),
        request_id: "key-2".into(),
        expiry: policy(3_001, 3_002),
        default_env: vec![pb::EnvVar {
            name: "NAME_4".into(),
            value: "value-4".into(),
        }],
        from_checkpoint: "cp-0123456789abcdef0123456789abcdef".into(),
    }
}

/// A fork's provenance fields (the rest of Sandbox is not checkpoint's).
fn fork() -> pb::Sandbox {
    pb::Sandbox {
        id: "sb-0123456789abcd01".into(),
        state: pb::SandboxState::Ready.into(),
        request_id: "key-16".into(),
        from_checkpoint: "cp-0123456789abcdef0123456789abcdef".into(),
        checkpoint_content_sha256: "a0".repeat(32),
        ..Default::default()
    }
}

/// Flag-on Health's checkpoint parts: the boolean, the feature and the limits.
fn capabilities() -> pb::RuntimeCapabilities {
    pb::RuntimeCapabilities {
        checkpoint: true,
        features: vec![pb::Feature::WorkspaceCheckpoint.into()],
        limits: Some(pb::ApiLimits {
            checkpoint: Some(pb::CheckpointLimits {
                max_size_bytes: 1_001,
                max_entries: 1_002,
                max_manifest_bytes: 1_003,
                max_path_bytes: 1_004,
                max_directory_depth: 1_005,
                max_link_target_bytes: 1_006,
                max_xattrs_per_entry: 1_007,
                max_xattr_bytes_per_entry: 1_008,
                default_lifetime_ms: 1_009,
                max_lifetime_ms: 1_010,
                default_idle_ms: 1_011,
                max_idle_ms: 1_012,
                min_lifetime_ms: 1_013,
                min_idle_ms: 1_014,
                operation_timeout_ms: 1_015,
                helper_timeout_ceiling_ms: 1_016,
                max_fork_depth: 1_017,
                worker_memory_bytes: 1_018,
                worker_max_fds: 1_019,
                request_retention_ms: 1_020,
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Flag-on Health's checkpoint use.
fn admission() -> pb::AdmissionStats {
    pb::AdmissionStats {
        checkpoints: Some(pb::CheckpointStats {
            max_count: 2_001,
            current_count: 2_002,
            max_count_per_uid: 2_003,
            caller_count: 2_004,
            max_bytes: 2_005,
            reserved_bytes: 2_006,
            max_bytes_per_uid: 2_007,
            caller_reserved_bytes: 2_008,
            max_workers: 2_009,
            current_workers: 2_010,
            max_workers_per_uid: 2_011,
            caller_workers: 2_012,
            pending_deletes: 2_013,
            rejected_captures: 2_014,
            rejected_forks: 2_015,
            max_records: 2_016,
            current_records: 2_017,
            max_records_per_uid: 2_018,
            caller_records: 2_019,
            max_request_records: 2_020,
            request_records: 2_021,
            max_request_records_per_uid: 2_022,
            caller_request_records: 2_023,
            max_cleanup_workers: 2_024,
            current_cleanup_workers: 2_025,
            expired: 2_026,
        }),
        ..Default::default()
    }
}

/// Health's node budgets, checkpoint_reserved_disk_bytes among them.
fn node_resources() -> pb::NodeResourceStats {
    pb::NodeResourceStats {
        max_sandboxes: 3_001,
        reserved_sandboxes: 3_002,
        max_memory_bytes: 3_003,
        reserved_memory_bytes: 3_004,
        max_pids: 3_005,
        reserved_pids: 3_006,
        max_disk_bytes: 3_007,
        reserved_disk_bytes: 3_008,
        rejected_creates: 3_009,
        max_host_cpu_millis: 3_010,
        reserved_host_cpu_millis: 3_011,
        max_virtual_cpu_slots: 3_012,
        reserved_virtual_cpu_slots: 3_013,
        max_host_pids: 3_014,
        reserved_host_pids: 3_015,
        accounting_status: pb::NodeAccountingStatus::Authoritative.into(),
        accounting_generation: 3_017,
        accounting_observed_at_unix_ms: T + 18,
        checkpoint_reserved_disk_bytes: 3_019,
    }
}

fn hex(bytes: &[u8]) -> J {
    J::S(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// An enum's values 0 to 63 by name.
fn numbers(name: fn(i32) -> Option<&'static str>) -> J {
    J::O(
        (0..64)
            .filter_map(|n| name(n).map(|s| (s.to_string(), J::N(n as u64))))
            .collect(),
    )
}

pub(super) fn wire() -> J {
    let messages: Vec<(&str, Vec<u8>)> = vec![
        ("Checkpoint", checkpoint().encode_to_vec()),
        (
            "CheckpointSandboxRequest",
            capture_request().encode_to_vec(),
        ),
        (
            "CheckpointSandboxResponse",
            pb::CheckpointSandboxResponse {
                checkpoint: Some(checkpoint()),
            }
            .encode_to_vec(),
        ),
        (
            "GetCheckpointRequest",
            pb::GetCheckpointRequest {
                id: checkpoint().id,
            }
            .encode_to_vec(),
        ),
        (
            "GetCheckpointResponse",
            pb::GetCheckpointResponse {
                checkpoint: Some(checkpoint()),
            }
            .encode_to_vec(),
        ),
        ("ListCheckpointsRequest", list_request().encode_to_vec()),
        ("ListCheckpointsResponse", list_response().encode_to_vec()),
        ("DeleteCheckpointRequest", delete_request().encode_to_vec()),
        (
            "DeleteCheckpointResponse",
            pb::DeleteCheckpointResponse {
                checkpoint: Some(deleted_checkpoint()),
            }
            .encode_to_vec(),
        ),
        (
            "CreateSandboxRequest (fork)",
            fork_request().encode_to_vec(),
        ),
        (
            "CreateSandboxResponse (fork)",
            pb::CreateSandboxResponse {
                sandbox: Some(fork()),
            }
            .encode_to_vec(),
        ),
        ("RuntimeCapabilities", capabilities().encode_to_vec()),
        ("AdmissionStats", admission().encode_to_vec()),
        ("NodeResourceStats", node_resources().encode_to_vec()),
    ];
    let name = |n: i32| pb::Feature::try_from(n).ok().map(|f| f.as_str_name());
    let feature = (0..64)
        .find(|n| name(*n) == Some("FEATURE_WORKSPACE_CHECKPOINT"))
        .expect("the checkpoint feature");
    obj([
        ("format", J::N(1)),
        (
            "notes",
            J::A(
                [
                    "Encoded protobuf bytes (lowercase hex) of fixed checkpoint messages, each field a distinct nonzero value, so a renumbered, retyped or removed field changes them; and the checkpoint enums' numbers.",
                    "a_previous_client_reads_and_writes_every_checkpoint_field decodes the same messages with hand-written tags, as a client of the published v1 proto.",
                    "Regenerate with KILND_BLESS_CHECKPOINT_CONTRACT=1 cargo test --locked -p kilnd --lib bless_checkpoint_contract -- --ignored, locally (scripts/build.sh refuses the variable; refused when CI is set). Within v1 only additions are compatible: review that no existing byte changed. Field numbers are pinned by hand in checkpoint_field_numbers_match_the_pinned_table, not here.",
                ]
                .iter()
                .map(|n| J::S(n.to_string()))
                .collect(),
            ),
        ),
        (
            "messages",
            J::O(
                messages
                    .iter()
                    .map(|(name, bytes)| (name.to_string(), hex(bytes)))
                    .collect(),
            ),
        ),
        (
            "enums",
            obj([
                (
                    "CheckpointState",
                    numbers(|n| {
                        pb::CheckpointState::try_from(n)
                            .ok()
                            .map(|v| v.as_str_name())
                    }),
                ),
                (
                    "CheckpointScope",
                    numbers(|n| {
                        pb::CheckpointScope::try_from(n)
                            .ok()
                            .map(|v| v.as_str_name())
                    }),
                ),
                (
                    "DeletionReason",
                    numbers(|n| pb::DeletionReason::try_from(n).ok().map(|v| v.as_str_name())),
                ),
                (
                    "Feature",
                    obj([("FEATURE_WORKSPACE_CHECKPOINT", J::N(feature as u64))]),
                ),
            ]),
        ),
    ])
}

#[test]
fn checkpoint_wire_golden_matches() {
    check_golden(WIRE, &wire());
}

/// A client built from the published v1 proto: the tags are written here, not taken
/// from generated code. Enums are their numbers; a fork request's spec is its own
/// encoded message (not checkpoint's), and a fork lists only its provenance.
mod prior {
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct ExpiryPolicy {
        #[prost(uint64, tag = "1")]
        pub max_lifetime_ms: u64,
        #[prost(uint64, tag = "2")]
        pub idle_timeout_ms: u64,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct CheckpointExpiryStatus {
        #[prost(message, optional, tag = "1")]
        pub effective: Option<ExpiryPolicy>,
        #[prost(int64, tag = "2")]
        pub lifetime_expires_at_unix_ms: i64,
        #[prost(int64, tag = "3")]
        pub idle_expires_at_unix_ms: i64,
        #[prost(int64, tag = "4")]
        pub last_activity_at_unix_ms: i64,
        #[prost(bool, tag = "5")]
        pub idle_paused: bool,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Checkpoint {
        #[prost(string, tag = "1")]
        pub id: String,
        #[prost(int32, tag = "2")]
        pub state: i32,
        #[prost(uint32, tag = "3")]
        pub owner_uid: u32,
        #[prost(string, tag = "4")]
        pub sandbox_id: String,
        #[prost(int64, tag = "5")]
        pub created_at_unix_ms: i64,
        #[prost(int64, tag = "6")]
        pub ready_at_unix_ms: i64,
        #[prost(uint64, tag = "7")]
        pub size_bytes: u64,
        #[prost(uint64, tag = "8")]
        pub logical_bytes: u64,
        #[prost(uint64, tag = "9")]
        pub allocated_bytes: u64,
        #[prost(string, tag = "10")]
        pub content_sha256: String,
        #[prost(string, tag = "11")]
        pub image: String,
        #[prost(string, tag = "12")]
        pub image_content_sha256: String,
        #[prost(bool, tag = "13")]
        pub read_only_root: bool,
        #[prost(string, repeated, tag = "14")]
        pub writable_paths: Vec<String>,
        #[prost(string, repeated, tag = "15")]
        pub excluded_paths: Vec<String>,
        #[prost(int32, tag = "16")]
        pub scope: i32,
        #[prost(message, optional, tag = "17")]
        pub expiry: Option<CheckpointExpiryStatus>,
        #[prost(string, tag = "18")]
        pub failure_reason: String,
        #[prost(int32, tag = "19")]
        pub deletion_reason: i32,
        #[prost(string, tag = "20")]
        pub request_id: String,
        #[prost(bool, tag = "21")]
        pub request_id_released: bool,
        #[prost(uint32, tag = "22")]
        pub format_version: u32,
        #[prost(uint64, tag = "23")]
        pub max_size_bytes: u64,
    }

    /// CheckpointSandboxResponse, GetCheckpointResponse and DeleteCheckpointResponse.
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct CheckpointResponse {
        #[prost(message, optional, tag = "1")]
        pub checkpoint: Option<Checkpoint>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct CheckpointSandboxRequest {
        #[prost(string, tag = "1")]
        pub sandbox_id: String,
        #[prost(string, tag = "2")]
        pub request_id: String,
        #[prost(message, optional, tag = "3")]
        pub expiry: Option<ExpiryPolicy>,
        #[prost(uint64, tag = "4")]
        pub max_size_bytes: u64,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct GetCheckpointRequest {
        #[prost(string, tag = "1")]
        pub id: String,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct ListCheckpointsRequest {
        #[prost(string, tag = "1")]
        pub sandbox_id: String,
        #[prost(uint32, tag = "2")]
        pub page_size: u32,
        #[prost(string, tag = "3")]
        pub page_token: String,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct ListCheckpointsResponse {
        #[prost(message, repeated, tag = "1")]
        pub checkpoints: Vec<Checkpoint>,
        #[prost(string, tag = "2")]
        pub next_page_token: String,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct DeleteCheckpointRequest {
        #[prost(string, tag = "1")]
        pub id: String,
        #[prost(bool, tag = "2")]
        pub release_request_id: bool,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct EnvVar {
        #[prost(string, tag = "1")]
        pub name: String,
        #[prost(string, tag = "2")]
        pub value: String,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct CreateSandboxRequest {
        #[prost(bytes = "vec", optional, tag = "1")]
        pub spec: Option<Vec<u8>>,
        #[prost(string, tag = "2")]
        pub request_id: String,
        #[prost(message, optional, tag = "3")]
        pub expiry: Option<ExpiryPolicy>,
        #[prost(message, repeated, tag = "4")]
        pub default_env: Vec<EnvVar>,
        #[prost(string, tag = "5")]
        pub from_checkpoint: String,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Fork {
        #[prost(string, tag = "1")]
        pub id: String,
        #[prost(string, tag = "16")]
        pub request_id: String,
        #[prost(string, tag = "20")]
        pub from_checkpoint: String,
        #[prost(string, tag = "21")]
        pub checkpoint_content_sha256: String,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct CreateSandboxResponse {
        #[prost(message, optional, tag = "1")]
        pub sandbox: Option<Fork>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct CheckpointLimits {
        #[prost(uint64, tag = "1")]
        pub max_size_bytes: u64,
        #[prost(uint32, tag = "2")]
        pub max_entries: u32,
        #[prost(uint64, tag = "3")]
        pub max_manifest_bytes: u64,
        #[prost(uint32, tag = "4")]
        pub max_path_bytes: u32,
        #[prost(uint32, tag = "5")]
        pub max_directory_depth: u32,
        #[prost(uint32, tag = "6")]
        pub max_link_target_bytes: u32,
        #[prost(uint32, tag = "7")]
        pub max_xattrs_per_entry: u32,
        #[prost(uint32, tag = "8")]
        pub max_xattr_bytes_per_entry: u32,
        #[prost(uint64, tag = "9")]
        pub default_lifetime_ms: u64,
        #[prost(uint64, tag = "10")]
        pub max_lifetime_ms: u64,
        #[prost(uint64, tag = "11")]
        pub default_idle_ms: u64,
        #[prost(uint64, tag = "12")]
        pub max_idle_ms: u64,
        #[prost(uint64, tag = "13")]
        pub min_lifetime_ms: u64,
        #[prost(uint64, tag = "14")]
        pub min_idle_ms: u64,
        #[prost(uint64, tag = "15")]
        pub operation_timeout_ms: u64,
        #[prost(uint64, tag = "16")]
        pub helper_timeout_ceiling_ms: u64,
        #[prost(uint32, tag = "17")]
        pub max_fork_depth: u32,
        #[prost(uint64, tag = "18")]
        pub worker_memory_bytes: u64,
        #[prost(uint32, tag = "19")]
        pub worker_max_fds: u32,
        #[prost(uint64, tag = "20")]
        pub request_retention_ms: u64,
    }

    /// ApiLimits' checkpoint field.
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct ApiLimits {
        #[prost(message, optional, tag = "20")]
        pub checkpoint: Option<CheckpointLimits>,
    }

    /// RuntimeCapabilities' checkpoint fields.
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct RuntimeCapabilities {
        #[prost(bool, tag = "3")]
        pub checkpoint: bool,
        #[prost(int32, repeated, tag = "4")]
        pub features: Vec<i32>,
        #[prost(message, optional, tag = "5")]
        pub limits: Option<ApiLimits>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct CheckpointStats {
        #[prost(uint64, tag = "1")]
        pub max_count: u64,
        #[prost(uint64, tag = "2")]
        pub current_count: u64,
        #[prost(uint64, tag = "3")]
        pub max_count_per_uid: u64,
        #[prost(uint64, tag = "4")]
        pub caller_count: u64,
        #[prost(uint64, tag = "5")]
        pub max_bytes: u64,
        #[prost(uint64, tag = "6")]
        pub reserved_bytes: u64,
        #[prost(uint64, tag = "7")]
        pub max_bytes_per_uid: u64,
        #[prost(uint64, tag = "8")]
        pub caller_reserved_bytes: u64,
        #[prost(uint64, tag = "9")]
        pub max_workers: u64,
        #[prost(uint64, tag = "10")]
        pub current_workers: u64,
        #[prost(uint64, tag = "11")]
        pub max_workers_per_uid: u64,
        #[prost(uint64, tag = "12")]
        pub caller_workers: u64,
        #[prost(uint64, tag = "13")]
        pub pending_deletes: u64,
        #[prost(uint64, tag = "14")]
        pub rejected_captures: u64,
        #[prost(uint64, tag = "15")]
        pub rejected_forks: u64,
        #[prost(uint64, tag = "16")]
        pub max_records: u64,
        #[prost(uint64, tag = "17")]
        pub current_records: u64,
        #[prost(uint64, tag = "18")]
        pub max_records_per_uid: u64,
        #[prost(uint64, tag = "19")]
        pub caller_records: u64,
        #[prost(uint64, tag = "20")]
        pub max_request_records: u64,
        #[prost(uint64, tag = "21")]
        pub request_records: u64,
        #[prost(uint64, tag = "22")]
        pub max_request_records_per_uid: u64,
        #[prost(uint64, tag = "23")]
        pub caller_request_records: u64,
        #[prost(uint64, tag = "24")]
        pub max_cleanup_workers: u64,
        #[prost(uint64, tag = "25")]
        pub current_cleanup_workers: u64,
        #[prost(uint64, tag = "26")]
        pub expired: u64,
    }

    /// AdmissionStats' checkpoint field.
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct AdmissionStats {
        #[prost(message, optional, tag = "26")]
        pub checkpoints: Option<CheckpointStats>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct NodeResourceStats {
        #[prost(uint64, tag = "1")]
        pub max_sandboxes: u64,
        #[prost(uint64, tag = "2")]
        pub reserved_sandboxes: u64,
        #[prost(uint64, tag = "3")]
        pub max_memory_bytes: u64,
        #[prost(uint64, tag = "4")]
        pub reserved_memory_bytes: u64,
        #[prost(uint64, tag = "5")]
        pub max_pids: u64,
        #[prost(uint64, tag = "6")]
        pub reserved_pids: u64,
        #[prost(uint64, tag = "7")]
        pub max_disk_bytes: u64,
        #[prost(uint64, tag = "8")]
        pub reserved_disk_bytes: u64,
        #[prost(uint64, tag = "9")]
        pub rejected_creates: u64,
        #[prost(uint64, tag = "10")]
        pub max_host_cpu_millis: u64,
        #[prost(uint64, tag = "11")]
        pub reserved_host_cpu_millis: u64,
        #[prost(uint64, tag = "12")]
        pub max_virtual_cpu_slots: u64,
        #[prost(uint64, tag = "13")]
        pub reserved_virtual_cpu_slots: u64,
        #[prost(uint64, tag = "14")]
        pub max_host_pids: u64,
        #[prost(uint64, tag = "15")]
        pub reserved_host_pids: u64,
        #[prost(int32, tag = "16")]
        pub accounting_status: i32,
        #[prost(uint64, tag = "17")]
        pub accounting_generation: u64,
        #[prost(int64, tag = "18")]
        pub accounting_observed_at_unix_ms: i64,
        #[prost(uint64, tag = "19")]
        pub checkpoint_reserved_disk_bytes: u64,
    }
}

fn prior_policy(max_lifetime_ms: u64, idle_timeout_ms: u64) -> Option<prior::ExpiryPolicy> {
    Some(prior::ExpiryPolicy {
        max_lifetime_ms,
        idle_timeout_ms,
    })
}

/// checkpoint() as a previous client reads it, written out (never copied by name).
fn prior_ready() -> prior::Checkpoint {
    prior::Checkpoint {
        id: "cp-0123456789abcdef0123456789abcdef".into(),
        state: 2,
        owner_uid: 1003,
        sandbox_id: "sb-0123456789abcd04".into(),
        created_at_unix_ms: 1_768_464_000_005,
        ready_at_unix_ms: 1_768_464_000_006,
        size_bytes: 7_007,
        logical_bytes: 8_008,
        allocated_bytes: 9_009,
        content_sha256: "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0".into(),
        image: "image-11".into(),
        image_content_sha256: "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1"
            .into(),
        read_only_root: true,
        writable_paths: vec!["/w14".into(), "/w14/b".into()],
        excluded_paths: vec!["/x15".into(), "/x15/b".into()],
        scope: 1,
        expiry: Some(prior::CheckpointExpiryStatus {
            effective: prior_policy(17_101, 17_102),
            lifetime_expires_at_unix_ms: 1_768_464_017_002,
            idle_expires_at_unix_ms: 1_768_464_017_003,
            last_activity_at_unix_ms: 1_768_464_017_004,
            idle_paused: true,
        }),
        failure_reason: "reason-18".into(),
        deletion_reason: 3,
        request_id: "key-20".into(),
        request_id_released: true,
        format_version: 22,
        max_size_bytes: 23_023,
    }
}

/// deleted_checkpoint() as a previous client reads it.
fn prior_deleted() -> prior::Checkpoint {
    prior::Checkpoint {
        id: "cp-fedcba9876543210fedcba9876543210".into(),
        state: 4,
        deletion_reason: 2,
        read_only_root: false,
        request_id_released: true,
        expiry: Some(prior::CheckpointExpiryStatus {
            effective: prior_policy(60_000, 30_000),
            ..Default::default()
        }),
        ..prior_ready()
    }
}

/// A previous client decodes `current`'s encoding to `prior` exactly; `prior` encodes to
/// the same bytes (so it lost no field); and the current types decode that back to
/// `current`.
#[track_caller]
fn same_on_the_wire<G, P>(what: &str, current: &G, prior: &P)
where
    G: Message + Default + PartialEq + Debug,
    P: Message + Default + PartialEq + Debug,
{
    let wire = current.encode_to_vec();
    assert_eq!(
        &P::decode(wire.as_slice()).unwrap(),
        prior,
        "{what}: a previous client's decode of the current encoding"
    );
    let theirs = prior.encode_to_vec();
    assert_eq!(theirs, wire, "{what}: a previous client's encoding");
    assert_eq!(
        &G::decode(theirs.as_slice()).unwrap(),
        current,
        "{what}: the current decode of a previous client's encoding"
    );
}

#[test]
fn a_previous_client_reads_and_writes_every_checkpoint_field() {
    let c = checkpoint();
    same_on_the_wire("Checkpoint", &c, &prior_ready());
    let d = deleted_checkpoint();
    same_on_the_wire("a DELETED Checkpoint", &d, &prior_deleted());
    let one = |c: prior::Checkpoint| prior::CheckpointResponse {
        checkpoint: Some(c),
    };
    let capture = pb::CheckpointSandboxResponse {
        checkpoint: Some(c.clone()),
    };
    same_on_the_wire("CheckpointSandboxResponse", &capture, &one(prior_ready()));
    let get = pb::GetCheckpointResponse {
        checkpoint: Some(c.clone()),
    };
    same_on_the_wire("GetCheckpointResponse", &get, &one(prior_ready()));
    let delete = pb::DeleteCheckpointResponse {
        checkpoint: Some(d.clone()),
    };
    same_on_the_wire("DeleteCheckpointResponse", &delete, &one(prior_deleted()));

    same_on_the_wire(
        "CheckpointSandboxRequest",
        &capture_request(),
        &prior::CheckpointSandboxRequest {
            sandbox_id: "sb-0123456789abcd01".into(),
            request_id: "key-2".into(),
            expiry: prior_policy(3_001, 3_002),
            max_size_bytes: 4_004,
        },
    );
    same_on_the_wire(
        "GetCheckpointRequest",
        &pb::GetCheckpointRequest { id: c.id.clone() },
        &prior::GetCheckpointRequest {
            id: "cp-0123456789abcdef0123456789abcdef".into(),
        },
    );
    same_on_the_wire(
        "ListCheckpointsRequest",
        &list_request(),
        &prior::ListCheckpointsRequest {
            sandbox_id: "sb-0123456789abcd01".into(),
            page_size: 2,
            page_token: "page-3".into(),
        },
    );
    same_on_the_wire(
        "ListCheckpointsResponse",
        &list_response(),
        &prior::ListCheckpointsResponse {
            checkpoints: vec![prior_ready(), prior_deleted()],
            next_page_token: "page-2".into(),
        },
    );
    same_on_the_wire(
        "DeleteCheckpointRequest",
        &delete_request(),
        &prior::DeleteCheckpointRequest {
            id: "cp-0123456789abcdef0123456789abcdef".into(),
            release_request_id: true,
        },
    );

    // The fork request, both ways. Its spec is not checkpoint's: its own bytes.
    let q = fork_request();
    same_on_the_wire(
        "CreateSandboxRequest (fork)",
        &q,
        &prior::CreateSandboxRequest {
            spec: q.spec.as_ref().map(Message::encode_to_vec),
            request_id: "key-2".into(),
            expiry: prior_policy(3_001, 3_002),
            default_env: vec![prior::EnvVar {
                name: "NAME_4".into(),
                value: "value-4".into(),
            }],
            from_checkpoint: "cp-0123456789abcdef0123456789abcdef".into(),
        },
    );
    // A fork's provenance, as a previous client reads it.
    let read = prior::CreateSandboxResponse::decode(
        pb::CreateSandboxResponse {
            sandbox: Some(fork()),
        }
        .encode_to_vec()
        .as_slice(),
    )
    .unwrap();
    assert_eq!(
        read.sandbox,
        Some(prior::Fork {
            id: "sb-0123456789abcd01".into(),
            request_id: "key-16".into(),
            from_checkpoint: "cp-0123456789abcdef0123456789abcdef".into(),
            checkpoint_content_sha256:
                "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0".into(),
        })
    );

    // Health's checkpoint parts.
    same_on_the_wire(
        "RuntimeCapabilities",
        &capabilities(),
        &prior::RuntimeCapabilities {
            checkpoint: true,
            features: vec![9],
            limits: Some(prior::ApiLimits {
                checkpoint: Some(prior::CheckpointLimits {
                    max_size_bytes: 1_001,
                    max_entries: 1_002,
                    max_manifest_bytes: 1_003,
                    max_path_bytes: 1_004,
                    max_directory_depth: 1_005,
                    max_link_target_bytes: 1_006,
                    max_xattrs_per_entry: 1_007,
                    max_xattr_bytes_per_entry: 1_008,
                    default_lifetime_ms: 1_009,
                    max_lifetime_ms: 1_010,
                    default_idle_ms: 1_011,
                    max_idle_ms: 1_012,
                    min_lifetime_ms: 1_013,
                    min_idle_ms: 1_014,
                    operation_timeout_ms: 1_015,
                    helper_timeout_ceiling_ms: 1_016,
                    max_fork_depth: 1_017,
                    worker_memory_bytes: 1_018,
                    worker_max_fds: 1_019,
                    request_retention_ms: 1_020,
                }),
            }),
        },
    );
    same_on_the_wire(
        "AdmissionStats",
        &admission(),
        &prior::AdmissionStats {
            checkpoints: Some(prior::CheckpointStats {
                max_count: 2_001,
                current_count: 2_002,
                max_count_per_uid: 2_003,
                caller_count: 2_004,
                max_bytes: 2_005,
                reserved_bytes: 2_006,
                max_bytes_per_uid: 2_007,
                caller_reserved_bytes: 2_008,
                max_workers: 2_009,
                current_workers: 2_010,
                max_workers_per_uid: 2_011,
                caller_workers: 2_012,
                pending_deletes: 2_013,
                rejected_captures: 2_014,
                rejected_forks: 2_015,
                max_records: 2_016,
                current_records: 2_017,
                max_records_per_uid: 2_018,
                caller_records: 2_019,
                max_request_records: 2_020,
                request_records: 2_021,
                max_request_records_per_uid: 2_022,
                caller_request_records: 2_023,
                max_cleanup_workers: 2_024,
                current_cleanup_workers: 2_025,
                expired: 2_026,
            }),
        },
    );
    same_on_the_wire(
        "NodeResourceStats",
        &node_resources(),
        &prior::NodeResourceStats {
            max_sandboxes: 3_001,
            reserved_sandboxes: 3_002,
            max_memory_bytes: 3_003,
            reserved_memory_bytes: 3_004,
            max_pids: 3_005,
            reserved_pids: 3_006,
            max_disk_bytes: 3_007,
            reserved_disk_bytes: 3_008,
            rejected_creates: 3_009,
            max_host_cpu_millis: 3_010,
            reserved_host_cpu_millis: 3_011,
            max_virtual_cpu_slots: 3_012,
            reserved_virtual_cpu_slots: 3_013,
            max_host_pids: 3_014,
            reserved_host_pids: 3_015,
            accounting_status: 2,
            accounting_generation: 3_017,
            accounting_observed_at_unix_ms: 1_768_464_000_018,
            checkpoint_reserved_disk_bytes: 3_019,
        },
    );
}

// --- The pinned field table (C6a recheck 1 HIGH 7) -------------------------------------

/// Every message here is pinned whole: exactly these fields.
const WHOLE: &[&str] = &[
    "ExpiryPolicy",
    "CheckpointExpiryStatus",
    "Checkpoint",
    "CheckpointSandboxRequest",
    "CheckpointSandboxResponse",
    "GetCheckpointRequest",
    "GetCheckpointResponse",
    "ListCheckpointsRequest",
    "ListCheckpointsResponse",
    "DeleteCheckpointRequest",
    "DeleteCheckpointResponse",
    "CheckpointLimits",
    "CheckpointStats",
    "NodeResourceStats",
    "CheckpointState",
    "CheckpointScope",
    "DeletionReason",
];

/// (message or enum, field or value, number, type, label), written by hand from the
/// published v1 contract and never generated or blessed. A message or enum not in
/// WHOLE is pinned only for the rows listed: the checkpoint fields of shared messages.
/// An enum value's type and label are empty.
#[rustfmt::skip]
const PINNED: &[(&str, &str, u32, &str, &str)] = &[
    ("ExpiryPolicy", "max_lifetime_ms", 1, "uint64", ""),
    ("ExpiryPolicy", "idle_timeout_ms", 2, "uint64", ""),
    ("CheckpointExpiryStatus", "effective", 1, "ExpiryPolicy", ""),
    ("CheckpointExpiryStatus", "lifetime_expires_at_unix_ms", 2, "int64", ""),
    ("CheckpointExpiryStatus", "idle_expires_at_unix_ms", 3, "int64", ""),
    ("CheckpointExpiryStatus", "last_activity_at_unix_ms", 4, "int64", ""),
    ("CheckpointExpiryStatus", "idle_paused", 5, "bool", ""),
    ("Checkpoint", "id", 1, "string", ""),
    ("Checkpoint", "state", 2, "CheckpointState", ""),
    ("Checkpoint", "owner_uid", 3, "uint32", ""),
    ("Checkpoint", "sandbox_id", 4, "string", ""),
    ("Checkpoint", "created_at_unix_ms", 5, "int64", ""),
    ("Checkpoint", "ready_at_unix_ms", 6, "int64", ""),
    ("Checkpoint", "size_bytes", 7, "uint64", ""),
    ("Checkpoint", "logical_bytes", 8, "uint64", ""),
    ("Checkpoint", "allocated_bytes", 9, "uint64", ""),
    ("Checkpoint", "content_sha256", 10, "string", ""),
    ("Checkpoint", "image", 11, "string", ""),
    ("Checkpoint", "image_content_sha256", 12, "string", ""),
    ("Checkpoint", "read_only_root", 13, "bool", ""),
    ("Checkpoint", "writable_paths", 14, "string", "repeated"),
    ("Checkpoint", "excluded_paths", 15, "string", "repeated"),
    ("Checkpoint", "scope", 16, "CheckpointScope", ""),
    ("Checkpoint", "expiry", 17, "CheckpointExpiryStatus", ""),
    ("Checkpoint", "failure_reason", 18, "string", ""),
    ("Checkpoint", "deletion_reason", 19, "DeletionReason", ""),
    ("Checkpoint", "request_id", 20, "string", ""),
    ("Checkpoint", "request_id_released", 21, "bool", ""),
    ("Checkpoint", "format_version", 22, "uint32", ""),
    ("Checkpoint", "max_size_bytes", 23, "uint64", ""),
    ("CheckpointSandboxRequest", "sandbox_id", 1, "string", ""),
    ("CheckpointSandboxRequest", "request_id", 2, "string", ""),
    ("CheckpointSandboxRequest", "expiry", 3, "ExpiryPolicy", ""),
    ("CheckpointSandboxRequest", "max_size_bytes", 4, "uint64", ""),
    ("CheckpointSandboxResponse", "checkpoint", 1, "Checkpoint", ""),
    ("GetCheckpointRequest", "id", 1, "string", ""),
    ("GetCheckpointResponse", "checkpoint", 1, "Checkpoint", ""),
    ("ListCheckpointsRequest", "sandbox_id", 1, "string", ""),
    ("ListCheckpointsRequest", "page_size", 2, "uint32", ""),
    ("ListCheckpointsRequest", "page_token", 3, "string", ""),
    ("ListCheckpointsResponse", "checkpoints", 1, "Checkpoint", "repeated"),
    ("ListCheckpointsResponse", "next_page_token", 2, "string", ""),
    ("DeleteCheckpointRequest", "id", 1, "string", ""),
    ("DeleteCheckpointRequest", "release_request_id", 2, "bool", ""),
    ("DeleteCheckpointResponse", "checkpoint", 1, "Checkpoint", ""),
    ("CheckpointLimits", "max_size_bytes", 1, "uint64", ""),
    ("CheckpointLimits", "max_entries", 2, "uint32", ""),
    ("CheckpointLimits", "max_manifest_bytes", 3, "uint64", ""),
    ("CheckpointLimits", "max_path_bytes", 4, "uint32", ""),
    ("CheckpointLimits", "max_directory_depth", 5, "uint32", ""),
    ("CheckpointLimits", "max_link_target_bytes", 6, "uint32", ""),
    ("CheckpointLimits", "max_xattrs_per_entry", 7, "uint32", ""),
    ("CheckpointLimits", "max_xattr_bytes_per_entry", 8, "uint32", ""),
    ("CheckpointLimits", "default_lifetime_ms", 9, "uint64", ""),
    ("CheckpointLimits", "max_lifetime_ms", 10, "uint64", ""),
    ("CheckpointLimits", "default_idle_ms", 11, "uint64", ""),
    ("CheckpointLimits", "max_idle_ms", 12, "uint64", ""),
    ("CheckpointLimits", "min_lifetime_ms", 13, "uint64", ""),
    ("CheckpointLimits", "min_idle_ms", 14, "uint64", ""),
    ("CheckpointLimits", "operation_timeout_ms", 15, "uint64", ""),
    ("CheckpointLimits", "helper_timeout_ceiling_ms", 16, "uint64", ""),
    ("CheckpointLimits", "max_fork_depth", 17, "uint32", ""),
    ("CheckpointLimits", "worker_memory_bytes", 18, "uint64", ""),
    ("CheckpointLimits", "worker_max_fds", 19, "uint32", ""),
    ("CheckpointLimits", "request_retention_ms", 20, "uint64", ""),
    ("CheckpointStats", "max_count", 1, "uint64", ""),
    ("CheckpointStats", "current_count", 2, "uint64", ""),
    ("CheckpointStats", "max_count_per_uid", 3, "uint64", ""),
    ("CheckpointStats", "caller_count", 4, "uint64", ""),
    ("CheckpointStats", "max_bytes", 5, "uint64", ""),
    ("CheckpointStats", "reserved_bytes", 6, "uint64", ""),
    ("CheckpointStats", "max_bytes_per_uid", 7, "uint64", ""),
    ("CheckpointStats", "caller_reserved_bytes", 8, "uint64", ""),
    ("CheckpointStats", "max_workers", 9, "uint64", ""),
    ("CheckpointStats", "current_workers", 10, "uint64", ""),
    ("CheckpointStats", "max_workers_per_uid", 11, "uint64", ""),
    ("CheckpointStats", "caller_workers", 12, "uint64", ""),
    ("CheckpointStats", "pending_deletes", 13, "uint64", ""),
    ("CheckpointStats", "rejected_captures", 14, "uint64", ""),
    ("CheckpointStats", "rejected_forks", 15, "uint64", ""),
    ("CheckpointStats", "max_records", 16, "uint64", ""),
    ("CheckpointStats", "current_records", 17, "uint64", ""),
    ("CheckpointStats", "max_records_per_uid", 18, "uint64", ""),
    ("CheckpointStats", "caller_records", 19, "uint64", ""),
    ("CheckpointStats", "max_request_records", 20, "uint64", ""),
    ("CheckpointStats", "request_records", 21, "uint64", ""),
    ("CheckpointStats", "max_request_records_per_uid", 22, "uint64", ""),
    ("CheckpointStats", "caller_request_records", 23, "uint64", ""),
    ("CheckpointStats", "max_cleanup_workers", 24, "uint64", ""),
    ("CheckpointStats", "current_cleanup_workers", 25, "uint64", ""),
    ("CheckpointStats", "expired", 26, "uint64", ""),
    ("NodeResourceStats", "max_sandboxes", 1, "uint64", ""),
    ("NodeResourceStats", "reserved_sandboxes", 2, "uint64", ""),
    ("NodeResourceStats", "max_memory_bytes", 3, "uint64", ""),
    ("NodeResourceStats", "reserved_memory_bytes", 4, "uint64", ""),
    ("NodeResourceStats", "max_pids", 5, "uint64", ""),
    ("NodeResourceStats", "reserved_pids", 6, "uint64", ""),
    ("NodeResourceStats", "max_disk_bytes", 7, "uint64", ""),
    ("NodeResourceStats", "reserved_disk_bytes", 8, "uint64", ""),
    ("NodeResourceStats", "rejected_creates", 9, "uint64", ""),
    ("NodeResourceStats", "max_host_cpu_millis", 10, "uint64", ""),
    ("NodeResourceStats", "reserved_host_cpu_millis", 11, "uint64", ""),
    ("NodeResourceStats", "max_virtual_cpu_slots", 12, "uint64", ""),
    ("NodeResourceStats", "reserved_virtual_cpu_slots", 13, "uint64", ""),
    ("NodeResourceStats", "max_host_pids", 14, "uint64", ""),
    ("NodeResourceStats", "reserved_host_pids", 15, "uint64", ""),
    ("NodeResourceStats", "accounting_status", 16, "NodeAccountingStatus", ""),
    ("NodeResourceStats", "accounting_generation", 17, "uint64", ""),
    ("NodeResourceStats", "accounting_observed_at_unix_ms", 18, "int64", ""),
    ("NodeResourceStats", "checkpoint_reserved_disk_bytes", 19, "uint64", ""),
    ("RuntimeCapabilities", "checkpoint", 3, "bool", ""),
    ("RuntimeCapabilities", "features", 4, "Feature", "repeated"),
    ("RuntimeCapabilities", "limits", 5, "ApiLimits", ""),
    ("ApiLimits", "checkpoint", 20, "CheckpointLimits", ""),
    ("AdmissionStats", "checkpoints", 26, "CheckpointStats", ""),
    ("Sandbox", "from_checkpoint", 20, "string", ""),
    ("Sandbox", "checkpoint_content_sha256", 21, "string", ""),
    ("CreateSandboxRequest", "from_checkpoint", 5, "string", ""),
    ("Feature", "FEATURE_WORKSPACE_CHECKPOINT", 9, "", ""),
    ("CheckpointState", "CHECKPOINT_STATE_UNSPECIFIED", 0, "", ""),
    ("CheckpointState", "CHECKPOINT_STATE_CAPTURING", 1, "", ""),
    ("CheckpointState", "CHECKPOINT_STATE_READY", 2, "", ""),
    ("CheckpointState", "CHECKPOINT_STATE_DELETING", 3, "", ""),
    ("CheckpointState", "CHECKPOINT_STATE_DELETED", 4, "", ""),
    ("CheckpointState", "CHECKPOINT_STATE_FAILED", 5, "", ""),
    ("CheckpointState", "CHECKPOINT_STATE_QUARANTINED", 6, "", ""),
    ("CheckpointScope", "CHECKPOINT_SCOPE_UNSPECIFIED", 0, "", ""),
    ("CheckpointScope", "CHECKPOINT_SCOPE_PERSISTENT_OVERLAY", 1, "", ""),
    ("DeletionReason", "DELETION_REASON_UNSPECIFIED", 0, "", ""),
    ("DeletionReason", "DELETION_REASON_REQUESTED", 1, "", ""),
    ("DeletionReason", "DELETION_REASON_EXPIRED_IDLE", 2, "", ""),
    ("DeletionReason", "DELETION_REASON_EXPIRED_LIFETIME", 3, "", ""),
];

type Row = (String, u32, String, String);

/// The fields or values of each named top-level message or enum in `proto`, as rows.
/// Fails on anything in those blocks that is not a plain `[repeated] TYPE name = N;` or
/// `NAME = N;` line: an option, a reservation, a oneof, a map, a nested type, a block
/// comment, two statements on a line.
fn proto_rows(proto: &str, wanted: &BTreeSet<&str>) -> Result<BTreeMap<String, Vec<Row>>, String> {
    if proto.contains("/*") {
        return Err("a block comment".into());
    }
    let mut found = BTreeMap::new();
    let mut open: Option<(String, bool)> = None; // (name, is a message)
    let mut depth = 0usize; // outside the open block
    for (number, raw) in proto.lines().enumerate() {
        let line = raw.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let err = |what: &str| format!("kilnd.proto:{}: {what}: {raw:?}", number + 1);
        match open.clone() {
            None => {
                let words: Vec<&str> = line.split_whitespace().collect();
                if let (0, [kind @ ("message" | "enum"), name, "{"]) = (depth, &words[..]) {
                    if wanted.contains(name) {
                        if found.contains_key(*name) {
                            return Err(err("defined twice"));
                        }
                        found.insert(name.to_string(), Vec::new());
                        open = Some((name.to_string(), *kind == "message"));
                        continue;
                    }
                }
                depth += line.matches('{').count();
                depth = depth
                    .checked_sub(line.matches('}').count())
                    .ok_or_else(|| err("unbalanced"))?;
            }
            Some((name, message)) => {
                if line == "}" {
                    open = None;
                    continue;
                }
                let words: Vec<&str> = line
                    .strip_suffix(';')
                    .ok_or_else(|| err("not one statement"))?
                    .split_whitespace()
                    .collect();
                let plain = |w: &str| {
                    !w.is_empty()
                        && w.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
                };
                let row = match (message, &words[..]) {
                    (true, [ty, field, "=", n]) => (field, n, *ty, ""),
                    (true, ["repeated", ty, field, "=", n]) => (field, n, *ty, "repeated"),
                    (false, [value, "=", n]) => (value, n, "", ""),
                    _ => return Err(err("unexpected")),
                };
                let (field, n, ty, label) = row;
                if !plain(field) || !(ty.is_empty() || plain(ty)) || ["map", "oneof", "option", "reserved", "optional", "extensions", "message", "enum"].contains(&ty) {
                    return Err(err("unexpected"));
                }
                let n: u32 = n.parse().map_err(|_| err("not a number"))?;
                found
                    .get_mut(&name)
                    .expect("open block")
                    .push((field.to_string(), n, ty.to_string(), label.to_string()));
            }
        }
    }
    if open.is_some() {
        return Err("an unclosed block".into());
    }
    Ok(found)
}

/// Where `proto` differs from PINNED, or None.
fn pinned_mismatch(proto: &str) -> Option<String> {
    let names: BTreeSet<&str> = PINNED.iter().map(|r| r.0).collect();
    let found = match proto_rows(proto, &names) {
        Ok(found) => found,
        Err(e) => return Some(e),
    };
    for name in &names {
        let Some(rows) = found.get(*name) else {
            return Some(format!("{name} is missing"));
        };
        let pinned: Vec<Row> = PINNED
            .iter()
            .filter(|r| r.0 == *name)
            .map(|r| (r.1.to_string(), r.2, r.3.to_string(), r.4.to_string()))
            .collect();
        for row in &pinned {
            if !rows.contains(row) {
                let now = rows.iter().find(|r| r.0 == row.0);
                return Some(format!("{name}.{}: pinned {row:?}, the proto has {now:?}", row.0));
            }
        }
        if WHOLE.contains(name) && rows.len() != pinned.len() {
            let extra: Vec<_> = rows.iter().filter(|r| !pinned.contains(r)).collect();
            return Some(format!("{name} has fields the table does not pin: {extra:?}"));
        }
    }
    None
}

fn proto_text() -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../proto/kilnd/v1/kilnd.proto"),
    )
    .unwrap()
}

#[test]
fn checkpoint_field_numbers_match_the_pinned_table() {
    let names: BTreeSet<&str> = PINNED.iter().map(|r| r.0).collect();
    assert!(WHOLE.iter().all(|w| names.contains(w)));
    if let Some(what) = pinned_mismatch(&proto_text()) {
        panic!("the checkpoint wire contract changed: {what}");
    }
}

/// The adversarial recheck's two mutations, and what the parser refuses to read past.
#[test]
fn the_pinned_table_catches_swaps_renumbers_and_unreadable_blocks() {
    let proto = proto_text();
    let edit = |from: &str, to: &str| {
        assert_eq!(proto.matches(from).count(), 1, "{from}");
        proto.replace(from, to)
    };
    let swapped = edit("bool read_only_root = 13;", "bool read_only_root = 21;")
        .replace("bool request_id_released = 21;", "bool request_id_released = 13;");
    let what = pinned_mismatch(&swapped).expect("swapped tags 13 and 21");
    assert!(what.contains("Checkpoint.read_only_root"), "{what}");
    let moved = edit(
        "uint64 checkpoint_reserved_disk_bytes = 19;",
        "uint64 checkpoint_reserved_disk_bytes = 99;",
    );
    let what = pinned_mismatch(&moved).expect("19 to 99");
    assert!(what.contains("NodeResourceStats.checkpoint_reserved_disk_bytes"), "{what}");
    for (from, to, why) in [
        ("uint64 max_size_bytes = 1;", "uint64 max_size_bytes = 99;", "CheckpointLimits"),
        ("uint32 owner_uid = 3;", "int32 owner_uid = 3;", "Checkpoint.owner_uid"),
        ("repeated string excluded_paths = 15;", "string excluded_paths = 15;", "excluded_paths"),
        ("CHECKPOINT_STATE_READY = 2;", "CHECKPOINT_STATE_READY = 7;", "CHECKPOINT_STATE_READY"),
        ("FEATURE_WORKSPACE_CHECKPOINT = 9;", "FEATURE_WORKSPACE_CHECKPOINT = 10;", "Feature"),
        ("string from_checkpoint = 20;", "string from_checkpoint = 22;", "Sandbox.from_checkpoint"),
        ("uint64 expired = 26;", "uint64 expired = 26;\n  uint64 extra = 27;", "does not pin"),
        ("uint64 expired = 26;", "uint64 expired = 26 [deprecated = true];", "unexpected"),
        ("uint64 expired = 26;", "uint64 expired = 26;\n  reserved 30;", "unexpected"),
        ("uint64 expired = 26;", "uint64 expired = 26; uint64 more = 28;", "unexpected"),
        ("uint64 expired = 26;", "oneof x {\n  uint64 expired = 26;\n  }", "not one statement"),
        ("uint64 expired = 26;", "/* */ uint64 expired = 26;", "block comment"),
    ] {
        let what = pinned_mismatch(&edit(from, to)).unwrap_or_else(|| panic!("{from} -> {to}"));
        assert!(what.contains(why), "{from} -> {to}: {what}");
    }
}
