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
//! A renumbered, retyped or removed field fails both.

use prost::Message;

use super::*;

const WIRE: &str = "checkpoint-wire.json";

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

fn wire() -> J {
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
                    "Regenerate with KILND_BLESS_CHECKPOINT_CONTRACT=1 scripts/build.sh default test -p kilnd --lib checkpoint_wire_golden_matches (refused when CI is set). Within v1 only additions are compatible: review that no existing byte changed.",
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
}

fn prior_policy(p: &Option<pb::ExpiryPolicy>) -> Option<prior::ExpiryPolicy> {
    p.map(|p| prior::ExpiryPolicy {
        max_lifetime_ms: p.max_lifetime_ms,
        idle_timeout_ms: p.idle_timeout_ms,
    })
}

/// The same checkpoint, field by field by name.
fn prior_checkpoint(c: &pb::Checkpoint) -> prior::Checkpoint {
    prior::Checkpoint {
        id: c.id.clone(),
        state: c.state,
        owner_uid: c.owner_uid,
        sandbox_id: c.sandbox_id.clone(),
        created_at_unix_ms: c.created_at_unix_ms,
        ready_at_unix_ms: c.ready_at_unix_ms,
        size_bytes: c.size_bytes,
        logical_bytes: c.logical_bytes,
        allocated_bytes: c.allocated_bytes,
        content_sha256: c.content_sha256.clone(),
        image: c.image.clone(),
        image_content_sha256: c.image_content_sha256.clone(),
        read_only_root: c.read_only_root,
        writable_paths: c.writable_paths.clone(),
        excluded_paths: c.excluded_paths.clone(),
        scope: c.scope,
        expiry: c.expiry.map(|x| prior::CheckpointExpiryStatus {
            effective: prior_policy(&x.effective),
            lifetime_expires_at_unix_ms: x.lifetime_expires_at_unix_ms,
            idle_expires_at_unix_ms: x.idle_expires_at_unix_ms,
            last_activity_at_unix_ms: x.last_activity_at_unix_ms,
            idle_paused: x.idle_paused,
        }),
        failure_reason: c.failure_reason.clone(),
        deletion_reason: c.deletion_reason,
        request_id: c.request_id.clone(),
        request_id_released: c.request_id_released,
        format_version: c.format_version,
        max_size_bytes: c.max_size_bytes,
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
    same_on_the_wire("Checkpoint", &c, &prior_checkpoint(&c));
    let d = deleted_checkpoint();
    same_on_the_wire("a DELETED Checkpoint", &d, &prior_checkpoint(&d));
    let one = |c: &pb::Checkpoint| prior::CheckpointResponse {
        checkpoint: Some(prior_checkpoint(c)),
    };
    let capture = pb::CheckpointSandboxResponse {
        checkpoint: Some(c.clone()),
    };
    same_on_the_wire("CheckpointSandboxResponse", &capture, &one(&c));
    let get = pb::GetCheckpointResponse {
        checkpoint: Some(c.clone()),
    };
    same_on_the_wire("GetCheckpointResponse", &get, &one(&c));
    let delete = pb::DeleteCheckpointResponse {
        checkpoint: Some(d.clone()),
    };
    same_on_the_wire("DeleteCheckpointResponse", &delete, &one(&d));

    let q = capture_request();
    same_on_the_wire(
        "CheckpointSandboxRequest",
        &q,
        &prior::CheckpointSandboxRequest {
            sandbox_id: q.sandbox_id.clone(),
            request_id: q.request_id.clone(),
            expiry: prior_policy(&q.expiry),
            max_size_bytes: q.max_size_bytes,
        },
    );
    let q = pb::GetCheckpointRequest { id: c.id.clone() };
    same_on_the_wire(
        "GetCheckpointRequest",
        &q,
        &prior::GetCheckpointRequest { id: q.id.clone() },
    );
    let q = list_request();
    same_on_the_wire(
        "ListCheckpointsRequest",
        &q,
        &prior::ListCheckpointsRequest {
            sandbox_id: q.sandbox_id.clone(),
            page_size: q.page_size,
            page_token: q.page_token.clone(),
        },
    );
    let a = list_response();
    same_on_the_wire(
        "ListCheckpointsResponse",
        &a,
        &prior::ListCheckpointsResponse {
            checkpoints: a.checkpoints.iter().map(prior_checkpoint).collect(),
            next_page_token: a.next_page_token.clone(),
        },
    );
    let q = delete_request();
    same_on_the_wire(
        "DeleteCheckpointRequest",
        &q,
        &prior::DeleteCheckpointRequest {
            id: q.id.clone(),
            release_request_id: q.release_request_id,
        },
    );

    // The fork request, both ways.
    let q = fork_request();
    same_on_the_wire(
        "CreateSandboxRequest (fork)",
        &q,
        &prior::CreateSandboxRequest {
            spec: q.spec.as_ref().map(Message::encode_to_vec),
            request_id: q.request_id.clone(),
            expiry: prior_policy(&q.expiry),
            default_env: q
                .default_env
                .iter()
                .map(|e| prior::EnvVar {
                    name: e.name.clone(),
                    value: e.value.clone(),
                })
                .collect(),
            from_checkpoint: q.from_checkpoint.clone(),
        },
    );
    // A fork's provenance, as a previous client reads it.
    let f = fork();
    let read = prior::CreateSandboxResponse::decode(
        pb::CreateSandboxResponse {
            sandbox: Some(f.clone()),
        }
        .encode_to_vec()
        .as_slice(),
    )
    .unwrap();
    assert_eq!(
        read.sandbox,
        Some(prior::Fork {
            id: f.id,
            request_id: f.request_id,
            from_checkpoint: f.from_checkpoint,
            checkpoint_content_sha256: f.checkpoint_content_sha256,
        })
    );
}
