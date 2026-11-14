//! The workspace checkpoint RPCs (design `kilnd-checkpoint-fork` 7 and Appendix A;
//! milestone C5b): `CheckpointSandbox`, `GetCheckpoint`, `ListCheckpoints` and
//! `DeleteCheckpoint`, over the C5a engine. The engine owns ownership, keys, admission,
//! supervision and every typed reason; this layer converts messages, computes the
//! capture key's digest, pages and bounds lists, and refuses everything before any
//! store query while checkpoints are off with nothing durable to maintain.

use super::*;
use crate::manager::{CaptureKey, CaptureRequest, CheckpointExpiryView};
use crate::store::{Checkpoint, CheckpointState};

impl<R: Runtime> Service<R> {
    /// CheckpointSandbox: an Ordinary RPC, as CreateSandbox. A keyed capture's deadline
    /// is the caller's `grpc-timeout`, as for a keyed create; an admitted capture
    /// outlives a dropped or timed-out waiter (the engine's supervisor).
    pub(super) async fn checkpoint_sandbox_rpc(
        &self,
        req: Request<pb::CheckpointSandboxRequest>,
    ) -> Result<Response<pb::CheckpointSandboxResponse>, Status> {
        let headers = req.extensions().get::<HeadersReceived>().copied();
        let uid = caller_uid(&req)?;
        let deadline = rpc_deadline(&req, headers);
        let _permit = self.rpc_permit(&req, RpcClass::Ordinary, uid)?;
        self.manager.checkpoint_rpc_gate().map_err(status)?;
        let req = req.into_inner();
        let capture = CaptureRequest {
            sandbox_id: req.sandbox_id,
            expiry: req.expiry.map(|e| crate::expiry::RequestedExpiry {
                max_lifetime_ms: e.max_lifetime_ms,
                idle_timeout_ms: e.idle_timeout_ms,
            }),
            max_size_bytes: req.max_size_bytes,
        };
        let key = if req.request_id.is_empty() {
            None
        } else {
            crate::idempotency::validate_request_id(&req.request_id)
                .map_err(Status::invalid_argument)?;
            Some(CaptureKey {
                sha256: crate::idempotency::capture_request_digest(&capture),
                request_id: req.request_id,
            })
        };
        let checkpoint = self
            .manager
            .capture_checkpoint(capture, uid, key, deadline)
            .await
            .map_err(status)?;
        Ok(Response::new(pb::CheckpointSandboxResponse {
            checkpoint: Some(self.checkpoint_out(checkpoint)?),
        }))
    }

    /// GetCheckpoint: a cleanup-class RPC, as GetSandbox, so a reserved connection can
    /// still inspect what it is deleting.
    pub(super) async fn get_checkpoint_rpc(
        &self,
        req: Request<pb::GetCheckpointRequest>,
    ) -> Result<Response<pb::GetCheckpointResponse>, Status> {
        let uid = caller_uid(&req)?;
        let _permit = self.rpc_permit(&req, RpcClass::Cleanup, uid)?;
        self.manager.checkpoint_rpc_gate().map_err(status)?;
        let id = req.into_inner().id;
        let checkpoint = self.manager.get_checkpoint(&id, uid).map_err(status)?;
        Ok(Response::new(pb::GetCheckpointResponse {
            checkpoint: Some(self.checkpoint_out(checkpoint)?),
        }))
    }

    /// ListCheckpoints: newest first by creation sequence, filtered by owner (unless
    /// root) and source before paging, within ListSandboxes' count and byte bounds.
    /// `page_size` 0 is the legacy complete list or `RESOURCE_EXHAUSTED`. A
    /// continuation names the last row returned, so a later capture (a higher
    /// sequence) never shifts a page.
    pub(super) async fn list_checkpoints_rpc(
        &self,
        req: Request<pb::ListCheckpointsRequest>,
    ) -> Result<Response<pb::ListCheckpointsResponse>, Status> {
        let uid = caller_uid(&req)?;
        let _permit = self.rpc_permit(&req, RpcClass::Ordinary, uid)?;
        self.manager.checkpoint_rpc_gate().map_err(status)?;
        let req = req.into_inner();
        let limits = self.manager.limits();
        let paginated = req.page_size != 0;
        if !paginated && !req.page_token.is_empty() {
            return Err(Status::invalid_argument("page_token requires page_size"));
        }
        if !req.sandbox_id.is_empty() && !crate::model::valid_id("sb", &req.sandbox_id) {
            return Err(Status::invalid_argument(
                "sandbox_id must be sb- and 16 lowercase hexadecimal digits",
            ));
        }
        let count = match req.page_size {
            0 => limits.max_list_page_size,
            n if n <= limits.max_list_page_size => n,
            _ => return Err(Status::invalid_argument("page_size exceeds server maximum")),
        };
        let before = if req.page_token.is_empty() {
            None
        } else {
            Some(parse_checkpoint_token(&req.page_token, uid, &req.sandbox_id)?)
        };
        let source = (!req.sandbox_id.is_empty()).then_some(req.sandbox_id.as_str());
        let page = self
            .manager
            .list_checkpoints(uid, source, before, count)
            .map_err(status)?;
        if !paginated && page.has_more {
            return Err(pagination_required());
        }
        let mut response = pb::ListCheckpointsResponse::default();
        let total = page.rows.len();
        let mut last_returned = None;
        for (index, row) in page.rows.into_iter().enumerate() {
            let seq = row.creation_seq;
            response.checkpoints.push(self.checkpoint_out(row)?);
            let has_more = page.has_more || index + 1 < total;
            response.next_page_token = if paginated && has_more {
                checkpoint_token(uid, &req.sandbox_id, seq)
            } else {
                String::new()
            };
            if response.encoded_len() > limits.max_list_response_bytes {
                response.checkpoints.pop();
                if !paginated || response.checkpoints.is_empty() {
                    return Err(pagination_required());
                }
                response.next_page_token = checkpoint_token(
                    uid,
                    &req.sandbox_id,
                    last_returned.expect("nonempty response has a cursor"),
                );
                break;
            }
            last_returned = Some(seq);
        }
        debug_assert!(response.encoded_len() <= limits.max_list_response_bytes);
        Ok(Response::new(response))
    }

    /// DeleteCheckpoint: a cleanup-class RPC, as DeleteSandbox. The engine publishes
    /// DELETING, hands the removal to its supervisor and answers with its first attempt;
    /// a departed waiter leaves the supervisor running.
    pub(super) async fn delete_checkpoint_rpc(
        &self,
        req: Request<pb::DeleteCheckpointRequest>,
    ) -> Result<Response<pb::DeleteCheckpointResponse>, Status> {
        let uid = caller_uid(&req)?;
        let _permit = self.rpc_permit(&req, RpcClass::Cleanup, uid)?;
        self.manager.checkpoint_rpc_gate().map_err(status)?;
        let req = req.into_inner();
        let checkpoint = self
            .manager
            .delete_checkpoint(&req.id, uid, req.release_request_id)
            .await
            .map_err(status)?;
        Ok(Response::new(pb::DeleteCheckpointResponse {
            checkpoint: Some(self.checkpoint_out(checkpoint)?),
        }))
    }

    /// A checkpoint as the API shows it, with its live expiry view.
    fn checkpoint_out(&self, c: Checkpoint) -> Result<pb::Checkpoint, Status> {
        let view = self.manager.checkpoint_expiry_view(&c).map_err(status)?;
        Ok(checkpoint_pb(c, view))
    }
}

pub fn checkpoint_pb(c: Checkpoint, v: CheckpointExpiryView) -> pb::Checkpoint {
    let state = match c.state {
        CheckpointState::Capturing => pb::CheckpointState::Capturing,
        CheckpointState::Ready => pb::CheckpointState::Ready,
        CheckpointState::Deleting => pb::CheckpointState::Deleting,
        CheckpointState::Deleted => pb::CheckpointState::Deleted,
        CheckpointState::Failed => pb::CheckpointState::Failed,
        CheckpointState::Quarantined => pb::CheckpointState::Quarantined,
    };
    let deletion_reason = match c.deletion_reason {
        None => pb::DeletionReason::Unspecified,
        Some(DeletionReason::Requested) => pb::DeletionReason::Requested,
        Some(DeletionReason::ExpiredIdle) => pb::DeletionReason::ExpiredIdle,
        Some(DeletionReason::ExpiredLifetime) => pb::DeletionReason::ExpiredLifetime,
    };
    // The token first, as every stored refusal is written (design 7.3).
    let failure_reason = c.failure.map_or_else(String::new, |f| {
        if f.detail.is_empty() {
            f.token
        } else {
            format!("{}: {}", f.token, f.detail)
        }
    });
    let seal = c.seal.as_ref();
    pb::Checkpoint {
        id: c.id.as_str().to_string(),
        state: state.into(),
        owner_uid: c.owner_uid,
        sandbox_id: c.source_sandbox_id,
        created_at_unix_ms: c.created_at_ms,
        ready_at_unix_ms: c.ready_at_ms.unwrap_or(0),
        size_bytes: seal.map_or(0, |s| s.charge_bytes),
        logical_bytes: seal.map_or(0, |s| s.logical_bytes),
        allocated_bytes: seal.map_or(0, |s| s.allocated_bytes),
        content_sha256: seal.map_or_else(String::new, |s| s.content_sha256.to_string()),
        image: c.image,
        image_content_sha256: c.image_content_sha256.to_string(),
        read_only_root: c.read_only_root,
        writable_paths: c.writable_paths,
        excluded_paths: c.excluded_paths,
        scope: pb::CheckpointScope::PersistentOverlay.into(),
        expiry: Some(pb::CheckpointExpiryStatus {
            effective: Some(pb::ExpiryPolicy {
                max_lifetime_ms: c.expiry.lifetime_ms,
                idle_timeout_ms: c.expiry.idle_ms,
            }),
            lifetime_expires_at_unix_ms: v.lifetime_expires_at_ms,
            idle_expires_at_unix_ms: v.idle_expires_at_ms,
            last_activity_at_unix_ms: v.last_activity_at_ms,
            idle_paused: v.idle_paused,
        }),
        failure_reason,
        deletion_reason: deletion_reason.into(),
        request_id: c.request_id.unwrap_or_default(),
        request_id_released: c.request_id_released_at_ms.is_some(),
        format_version: c.format_version,
        max_size_bytes: c.max_size_bytes,
    }
}

/// The source filter's binding in a continuation: the first 8 bytes of its SHA-256,
/// zero for no filter.
fn filter_tag(sandbox_id: &str) -> u64 {
    if sandbox_id.is_empty() {
        return 0;
    }
    let digest = Digest::of(sandbox_id.as_bytes());
    let mut first = [0; 8];
    first.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_be_bytes(first)
}

/// A ListCheckpoints continuation, opaque to clients: the caller, the source filter's
/// tag and the last returned creation sequence, each at a fixed width so the length
/// never varies (the byte bound counts it).
pub(super) fn checkpoint_token(uid: u32, sandbox_id: &str, last: i64) -> String {
    format!(
        "c1:{uid:08x}:{:016x}:{last:016x}",
        filter_tag(sandbox_id)
    )
}

/// The `before_seq` a continuation names, if it was issued to this caller for this
/// filter; anything else is `INVALID_ARGUMENT`.
pub(super) fn parse_checkpoint_token(
    token: &str,
    uid: u32,
    sandbox_id: &str,
) -> Result<i64, Status> {
    let invalid = || {
        Status::invalid_argument(
            "invalid page_token, or it was issued for another caller or sandbox_id",
        )
    };
    if token.len() > 128 || !token.is_ascii() {
        return Err(invalid());
    }
    let parts: Vec<_> = token.split(':').collect();
    if parts.len() != 4
        || parts[0] != "c1"
        || parts[1] != format!("{uid:08x}")
        || parts[2] != format!("{:016x}", filter_tag(sandbox_id))
    {
        return Err(invalid());
    }
    let last = parts[3];
    if last.len() != 16
        || !last
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    let last = i64::from_str_radix(last, 16).map_err(|_| invalid())?;
    if last <= 0 {
        return Err(invalid());
    }
    Ok(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::CheckpointReason;

    /// Design 7.3, one-to-one: every engine reason reaches the wire with exactly its
    /// gRPC code, its `kilnd-reason` trailer and its token as the message prefix.
    #[test]
    fn every_checkpoint_reason_maps_to_one_status_and_trailer() {
        use tonic::Code;
        let expected = [
            (CheckpointReason::BackendUnsupported, Code::Unimplemented),
            (CheckpointReason::SandboxUnsupported, Code::FailedPrecondition),
            (CheckpointReason::Busy, Code::FailedPrecondition),
            (CheckpointReason::NotReady, Code::FailedPrecondition),
            (CheckpointReason::Expired, Code::FailedPrecondition),
            (CheckpointReason::LayoutUnsupported, Code::FailedPrecondition),
            (CheckpointReason::MetadataUnsupported, Code::FailedPrecondition),
            (CheckpointReason::ImageUnavailable, Code::FailedPrecondition),
            (CheckpointReason::SpecMismatch, Code::InvalidArgument),
            (CheckpointReason::DiskTooSmall, Code::InvalidArgument),
            (CheckpointReason::ExpiryRequired, Code::InvalidArgument),
            (CheckpointReason::Quota, Code::ResourceExhausted),
            (CheckpointReason::SizeLimit, Code::ResourceExhausted),
            (CheckpointReason::Workers, Code::ResourceExhausted),
            (CheckpointReason::Corrupt, Code::DataLoss),
            (CheckpointReason::Io, Code::Unavailable),
            (CheckpointReason::InFlight, Code::DeadlineExceeded),
        ];
        assert_eq!(expected.len(), CheckpointReason::ALL.len());
        let mut tokens = std::collections::HashSet::new();
        for (reason, code) in expected {
            let s = status(reason.error("detail"));
            assert_eq!(s.code(), code, "{reason:?}");
            let trailer = s.metadata().get(REASON_KEY).unwrap().to_str().unwrap();
            assert_eq!(trailer, reason.token(), "{reason:?}");
            assert_eq!(s.message(), format!("{}: detail", reason.token()));
            assert!(tokens.insert(trailer.to_string()), "{trailer} twice");
        }
    }

    #[test]
    fn continuations_are_fixed_width_strict_and_bound_to_caller_and_filter() {
        let sb = "sb-0123456789abcdef";
        let t = checkpoint_token(1000, sb, 42);
        assert_eq!(t.len(), checkpoint_token(0, "", i64::MAX).len());
        assert_eq!(parse_checkpoint_token(&t, 1000, sb).unwrap(), 42);
        for (token, uid, filter) in [
            (t.as_str(), 1001, sb),
            (t.as_str(), 1000, ""),
            (t.as_str(), 1000, "sb-0123456789abcdee"),
        ] {
            assert!(parse_checkpoint_token(token, uid, filter).is_err(), "{uid} {filter}");
        }
        let unfiltered = checkpoint_token(1000, "", 7);
        assert_eq!(parse_checkpoint_token(&unfiltered, 1000, "").unwrap(), 7);
        for bad in [
            "",
            "c1",
            "v2:0:000003e8:0000000000000000:0000000000000007",
            "c1:000003e8:0000000000000000:000000000000000",
            "c1:000003e8:0000000000000000:000000000000000G",
            "c1:000003e8:0000000000000000:0000000000000000",
            "c1:000003e8:0000000000000000:ffffffffffffffff",
            "c1:000003E8:0000000000000000:0000000000000007",
            "c1:000003e8:0000000000000000:0000000000000007:",
        ] {
            assert!(parse_checkpoint_token(bad, 1000, "").is_err(), "{bad}");
        }
    }
}
