//! The gRPC service: translates between `kilnd.v1` messages and the manager.

use std::collections::BTreeMap;
use std::sync::Arc;

use kilnd_api::v1 as pb;
use prost::Message;
use tonic::{Request, Response, Status};

use crate::admission::{ConnectionLane, RpcClass, RpcPermit};
use crate::manager::{
    CreateKey, CreateRequest, Error, ExecRequest, ExpiryView, Feature, Limits, Manager, Refusal,
    RefusalCode,
};
use crate::model::{
    CancelReason, Captured, DeletionReason, Execution, ExecutionState, Network, Sandbox,
    SandboxSpec, SandboxState,
};
use crate::runtime::Runtime;
use crate::server::{HeadersReceived, PeerIdentity};

pub struct Service<R> {
    manager: Arc<Manager<R>>,
}

impl<R> Service<R> {
    pub fn new(manager: Arc<Manager<R>>) -> Self {
        Self { manager }
    }
}

#[tonic::async_trait]
impl<R: Runtime> pb::kilnd_service_server::KilndService for Service<R> {
    async fn health(
        &self,
        req: Request<pb::HealthRequest>,
    ) -> Result<Response<pb::HealthResponse>, Status> {
        let uid = req
            .extensions()
            .get::<PeerIdentity>()
            .and_then(|peer| peer.uid);
        let _permit = self
            .manager
            .admission()
            .try_health(uid)
            .map_err(|_| Status::resource_exhausted("Health RPC capacity reached"))?;
        let h = self.manager.health().await.map_err(status)?;
        // The node's request records and the caller's own (design 3.3).
        let requests = self
            .manager
            .create_request_stats(uid)
            .unwrap_or_else(|error| {
                tracing::warn!(error = %format!("{error:#}"), "read create request counts");
                crate::manager::CreateRequestStats {
                    max_node: self.manager.limits().create_requests.max_node,
                    max_per_uid: self.manager.limits().create_requests.max_per_uid,
                    ..Default::default()
                }
            });
        let mut admission = admission_pb(h.admission);
        admission.max_create_requests = requests.max_node;
        admission.current_create_requests = requests.node;
        admission.max_create_requests_per_uid = requests.max_per_uid;
        admission.caller_create_requests = requests.caller;
        admission.rejected_create_requests = requests.rejected;
        let status = if h.shutting_down {
            pb::health_response::Status::ShuttingDown
        } else if h.serving {
            pb::health_response::Status::Serving
        } else {
            pb::health_response::Status::Degraded
        };
        Ok(Response::new(pb::HealthResponse {
            status: status.into(),
            version: env!("CARGO_PKG_VERSION").into(),
            backend: h.backend.into(),
            backend_version: h.backend_version,
            detail: h.detail,
            started_at_unix_ms: h.started_at_ms,
            active_sandboxes: h.active_sandboxes,
            running_executions: h.running_executions,
            admission: Some(admission),
            node_resources: Some(node_resources_pb(h.node_resources)),
            runtime_capabilities: Some(runtime_capabilities_pb(
                h.capabilities,
                &h.features,
                self.manager.limits(),
            )),
            lifecycle: Some(pb::LifecycleStats {
                expired_idle: h.lifecycle.expired_idle,
                expired_lifetime: h.lifecycle.expired_lifetime,
                pending_expiry_deletes: h.lifecycle.pending_expiry_deletes,
                failed_expiry_deletes: h.lifecycle.failed_expiry_deletes,
                create_retries_answered: h.lifecycle.create_retries_answered,
                request_ids_released: h.lifecycle.request_ids_released,
            }),
        }))
    }

    async fn create_sandbox(
        &self,
        req: Request<pb::CreateSandboxRequest>,
    ) -> Result<Response<pb::CreateSandboxResponse>, Status> {
        // The deadline runs from the headers, like tonic's own timeout; a request
        // that never passed the server (a direct test call) starts now.
        let received_at = req
            .extensions()
            .get::<HeadersReceived>()
            .map_or_else(tokio::time::Instant::now, |h| h.0);
        let uid = caller_uid(&req)?;
        let deadline = rpc_deadline(&req, received_at);
        let _permit = self.rpc_permit(&req, RpcClass::Ordinary, uid)?;
        let req = req.into_inner();
        if req.request_id.is_empty() {
            // Unkeyed: exactly the path before idempotent create.
            let expiry = req.expiry.map(|e| crate::expiry::RequestedExpiry {
                max_lifetime_ms: e.max_lifetime_ms,
                idle_timeout_ms: e.idle_timeout_ms,
            });
            let sandbox = self
                .manager
                .create_owned(create_request(req.spec.unwrap_or_default(), expiry)?, uid)
                .await
                .map_err(status)?;
            return Ok(Response::new(pb::CreateSandboxResponse {
                sandbox: Some(self.sandbox_out(sandbox)),
            }));
        }
        // Design 3.1 step 1: the grammar and the digest of the request as sent. Its
        // conversion errors are validation, reported only after the lookups.
        crate::idempotency::validate_request_id(&req.request_id)
            .map_err(Status::invalid_argument)?;
        let key = CreateKey {
            sha256: crate::idempotency::request_digest(&req),
            request_id: req.request_id.clone(),
        };
        let expiry = req.expiry.map(|e| crate::expiry::RequestedExpiry {
            max_lifetime_ms: e.max_lifetime_ms,
            idle_timeout_ms: e.idle_timeout_ms,
        });
        let converted = create_request(req.spec.unwrap_or_default(), expiry)
            .map_err(|s| s.message().to_string());
        let sandbox = self
            .manager
            .create_keyed(converted, uid, key, deadline)
            .await
            .map_err(status)?;
        Ok(Response::new(pb::CreateSandboxResponse {
            sandbox: Some(self.sandbox_out(sandbox)),
        }))
    }

    async fn get_sandbox(
        &self,
        req: Request<pb::GetSandboxRequest>,
    ) -> Result<Response<pb::GetSandboxResponse>, Status> {
        let uid = caller_uid(&req)?;
        let _permit = self.rpc_permit(&req, RpcClass::Cleanup, uid)?;
        let req = req.into_inner();
        self.manager.authorize(&req.id, uid).map_err(status)?;
        let (sandbox, executions) = self
            .manager
            .get(&req.id, req.execution_limit)
            .map_err(status)?;
        Ok(Response::new(pb::GetSandboxResponse {
            sandbox: Some(self.sandbox_out(sandbox)),
            recent_executions: executions.into_iter().map(execution_pb).collect(),
        }))
    }

    async fn list_sandboxes(
        &self,
        req: Request<pb::ListSandboxesRequest>,
    ) -> Result<Response<pb::ListSandboxesResponse>, Status> {
        let uid = caller_uid(&req)?;
        let _permit = self.rpc_permit(&req, RpcClass::Ordinary, uid)?;
        let req = req.into_inner();
        let limits = self.manager.limits();
        let paginated = req.page_size.is_some();
        if !paginated && !req.page_token.is_empty() {
            return Err(Status::invalid_argument("page_token requires page_size"));
        }
        let count = match req.page_size {
            None => limits.max_list_page_size,
            Some(0) => 100.min(limits.max_list_page_size),
            Some(n) if n <= limits.max_list_page_size => n,
            Some(_) => return Err(Status::invalid_argument("page_size exceeds server maximum")),
        };
        let (upper, before) = if req.page_token.is_empty() {
            (None, None)
        } else {
            let (upper, last) = parse_page_token(&req.page_token, req.include_deleted, uid)?;
            (Some(upper), Some(last))
        };
        let page = self
            .manager
            .list_page_owned(
                req.include_deleted,
                upper,
                before,
                count,
                (uid != 0).then_some(uid),
            )
            .map_err(status)?;
        if !paginated && page.has_more {
            return Err(pagination_required());
        }
        let mut response = pb::ListSandboxesResponse::default();
        let total = page.rows.len();
        let mut last_returned = None;
        for (index, row) in page.rows.into_iter().enumerate() {
            let seq = row.list_seq;
            response.sandboxes.push(self.sandbox_out(row.sandbox));
            let has_more = page.has_more || index + 1 < total;
            response.next_page_token = if paginated && has_more {
                page_token(req.include_deleted, uid, page.upper_seq, seq)
            } else {
                String::new()
            };
            if response.encoded_len() > limits.max_list_response_bytes {
                response.sandboxes.pop();
                if !paginated || response.sandboxes.is_empty() {
                    return Err(pagination_required());
                }
                response.next_page_token = page_token(
                    req.include_deleted,
                    uid,
                    page.upper_seq,
                    last_returned.expect("nonempty response has a cursor"),
                );
                break;
            }
            last_returned = Some(seq);
        }
        // A continuation was included in every candidate measurement; its
        // fixed canonical length also covers stopping on the byte bound.
        debug_assert!(response.encoded_len() <= limits.max_list_response_bytes);
        Ok(Response::new(response))
    }

    async fn delete_sandbox(
        &self,
        req: Request<pb::DeleteSandboxRequest>,
    ) -> Result<Response<pb::DeleteSandboxResponse>, Status> {
        let uid = caller_uid(&req)?;
        let _permit = self.rpc_permit(&req, RpcClass::Cleanup, uid)?;
        let req = req.into_inner();
        let id = req.id;
        self.manager.authorize(&id, uid).map_err(status)?;
        let sandbox = self
            .manager
            .delete_releasing(&id, req.release_request_id)
            .await
            .map_err(status)?;
        Ok(Response::new(pb::DeleteSandboxResponse {
            sandbox: Some(self.sandbox_out(sandbox)),
        }))
    }

    async fn renew_sandbox(
        &self,
        req: Request<pb::RenewSandboxRequest>,
    ) -> Result<Response<pb::RenewSandboxResponse>, Status> {
        let uid = caller_uid(&req)?;
        let _permit = self.rpc_permit(&req, RpcClass::Ordinary, uid)?;
        let id = req.into_inner().id;
        self.manager.authorize(&id, uid).map_err(status)?;
        let sandbox = self.manager.renew(&id).map_err(status)?;
        Ok(Response::new(pb::RenewSandboxResponse {
            sandbox: Some(self.sandbox_out(sandbox)),
        }))
    }

    async fn exec(
        &self,
        req: Request<pb::ExecRequest>,
    ) -> Result<Response<pb::ExecResponse>, Status> {
        let received_at = tokio::time::Instant::now();
        let uid = caller_uid(&req)?;
        let _permit = self.rpc_permit(&req, RpcClass::Ordinary, uid)?;
        let req = req.into_inner();
        self.manager
            .authorize(&req.sandbox_id, uid)
            .map_err(status)?;
        let execution = self
            .manager
            .exec_received(
                ExecRequest {
                    sandbox_id: req.sandbox_id,
                    argv: req.argv,
                    stdin: req.stdin,
                    timeout_ms: req.timeout_ms,
                },
                received_at,
            )
            .await
            .map_err(status)?;
        Ok(Response::new(pb::ExecResponse {
            execution: Some(execution_pb(execution)),
        }))
    }

    async fn get_execution(
        &self,
        req: Request<pb::GetExecutionRequest>,
    ) -> Result<Response<pb::GetExecutionResponse>, Status> {
        let uid = caller_uid(&req)?;
        let _permit = self.rpc_permit(&req, RpcClass::Ordinary, uid)?;
        let id = req.into_inner().id;
        // Decide before the row's output BLOBs are read.
        self.manager.authorize_execution(&id, uid).map_err(status)?;
        let execution = self.manager.execution(&id).map_err(status)?;
        Ok(Response::new(pb::GetExecutionResponse {
            execution: Some(execution_pb(execution)),
        }))
    }
}

impl<R: Runtime> Service<R> {
    /// A row as the API shows it, with its live expiry view.
    fn sandbox_out(&self, sandbox: Sandbox) -> pb::Sandbox {
        let view = self.manager.expiry_view(&sandbox);
        let mut out = sandbox_pb(sandbox);
        out.expiry = Some(expiry_status_pb(view));
        out
    }

    /// The caller's RPC permit (B7, B6-BI-03). A connection on a reserved slot or the
    /// root slot serves only Health and cleanup; an ordinary RPC needs a global permit
    /// within the UID's share, and a cleanup RPC may fall back to the cleanup lane (and
    /// for UID 0, to its root permit).
    fn rpc_permit<T>(
        &self,
        req: &Request<T>,
        class: RpcClass,
        uid: u32,
    ) -> Result<RpcPermit, Status> {
        let lane = req
            .extensions()
            .get::<PeerIdentity>()
            .map_or(ConnectionLane::General, |peer| peer.lane);
        if lane.health_and_cleanup_only() && class == RpcClass::Ordinary {
            return Err(Status::resource_exhausted(
                "connection capacity reached: this connection holds a reserved slot, which serves only Health, GetSandbox and DeleteSandbox",
            ));
        }
        self.manager
            .admission()
            .try_rpc(class, Some(uid))
            .map_err(|_| Status::resource_exhausted("ordinary RPC capacity reached"))
    }
}

/// The connection's kernel-reported uid. There is no fallback identity: a
/// request without one is refused, never treated as root.
fn caller_uid<T>(req: &Request<T>) -> Result<u32, Status> {
    req.extensions()
        .get::<PeerIdentity>()
        .and_then(|peer| peer.uid)
        .ok_or_else(|| Status::unauthenticated("peer credentials unavailable"))
}

fn admission_pb(s: crate::admission::AdmissionSnapshot) -> pb::AdmissionStats {
    pb::AdmissionStats {
        max_connections: s.connections.max,
        current_connections: s.connections.current,
        rejected_connections: s.connections.rejected,
        max_concurrent_rpcs: s.rpcs.max,
        current_rpcs: s.rpcs.current,
        rejected_rpcs: s.rpcs.rejected,
        max_concurrent_health: s.health.max,
        current_health: s.health.current,
        rejected_health: s.health.rejected,
        max_concurrent_execs: s.execs.max,
        current_execs: s.execs.current,
        rejected_execs: s.execs.rejected,
        max_queued_exec_stdin_bytes: s.stdin.max,
        current_stdin_bytes: s.stdin.current,
        rejected_stdin: s.stdin.rejected,
        max_queued_execs_per_sandbox: s.max_queued_execs_per_sandbox,
        rejected_sandbox_execs: s.rejected_sandbox_execs,
        // Filled by Health from the store, for the caller.
        ..Default::default()
    }
}

fn feature_pb(f: Feature) -> pb::Feature {
    match f {
        Feature::SandboxExpiry => pb::Feature::SandboxExpiry,
        Feature::IdempotentCreate => pb::Feature::IdempotentCreate,
        Feature::ExecCwd => pb::Feature::ExecCwd,
        Feature::ExecEnv => pb::Feature::ExecEnv,
        Feature::SandboxDefaultEnv => pb::Feature::SandboxDefaultEnv,
        Feature::ExecStream => pb::Feature::ExecStream,
        Feature::TypedReasons => pb::Feature::TypedReasons,
        Feature::RequestIdRelease => pb::Feature::RequestIdRelease,
    }
}

/// Every cap, minimum and default a client could hit (design section 7). Fields of
/// features this daemon does not list are zero.
fn api_limits_pb(l: &Limits) -> pb::ApiLimits {
    let ms = |d: std::time::Duration| u32::try_from(d.as_millis()).unwrap_or(u32::MAX);
    pb::ApiLimits {
        max_sandbox_lifetime_ms: l.expiry.max_lifetime_ms,
        max_sandbox_idle_ms: l.expiry.max_idle_ms,
        default_sandbox_lifetime_ms: l.expiry.default_lifetime_ms,
        default_sandbox_idle_ms: l.expiry.default_idle_ms,
        create_request_retention_ms: l
            .retention
            .create_request_retention_secs
            .saturating_mul(1000),
        max_cwd_bytes: 0,
        max_env_entries: 0,
        max_env_name_bytes: 0,
        max_env_value_bytes: 0,
        max_env_total_bytes: 0,
        default_exec_timeout_ms: ms(l.default_timeout),
        max_exec_timeout_ms: ms(l.max_timeout),
        default_stream_timeout_ms: 0,
        max_stream_timeout_ms: 0,
        max_output_bytes: l.max_output_bytes as u64,
        stream_chunk_bytes: 0,
        stream_buffer_bytes: 0,
        min_sandbox_lifetime_ms: crate::expiry::MIN_EXPIRY_MS,
        min_sandbox_idle_ms: crate::expiry::MIN_EXPIRY_MS,
    }
}

fn runtime_capabilities_pb(
    c: crate::runtime::RuntimeCapabilities,
    features: &[Feature],
    limits: &Limits,
) -> pb::RuntimeCapabilities {
    pb::RuntimeCapabilities {
        features: features.iter().map(|f| feature_pb(*f).into()).collect(),
        limits: Some(api_limits_pb(limits)),
        network_modes: c
            .network_modes
            .iter()
            .map(|mode| {
                match mode {
                    crate::model::Network::None => pb::NetworkMode::None,
                    crate::model::Network::Full => pb::NetworkMode::Full,
                    crate::model::Network::Allow(_) => pb::NetworkMode::Allowlist,
                }
                .into()
            })
            .collect(),
        interruption_preserves_session: c.interruption_preserves_session,
        checkpoint: c.checkpoint,
    }
}

fn node_resources_pb(s: crate::manager::NodeResourceSnapshot) -> pb::NodeResourceStats {
    use crate::manager::NodeAccountingStatus as Accounting;
    // A daemon's local sum is the node total only for a backend with no node
    // authority, which reserves no CPU, vCPU or host PIDs. A node authority's own
    // totals are reported whole. Otherwise an unreadable authority reports nothing
    // rather than a number that looks authoritative.
    let (status, generation, observed_at_ms) = match s.accounting {
        Accounting::LocalLegacy => (pb::NodeAccountingStatus::LocalLegacy, 0, 0),
        Accounting::Unavailable => (pb::NodeAccountingStatus::Unavailable, 0, 0),
        Accounting::Authoritative {
            generation,
            observed_at_ms,
        } => (
            pb::NodeAccountingStatus::Authoritative,
            generation,
            observed_at_ms,
        ),
    };
    let total = |value: u64| match s.accounting {
        Accounting::LocalLegacy | Accounting::Authoritative { .. } => value,
        Accounting::Unavailable => 0,
    };
    let host = |value: u64| match s.accounting {
        Accounting::Authoritative { .. } => value,
        Accounting::LocalLegacy | Accounting::Unavailable => 0,
    };
    pb::NodeResourceStats {
        max_sandboxes: total(s.limits.sandboxes),
        reserved_sandboxes: total(s.reserved.sandboxes),
        max_memory_bytes: total(s.limits.memory_bytes),
        reserved_memory_bytes: total(s.reserved.memory_bytes),
        max_pids: total(s.limits.pids),
        reserved_pids: total(s.reserved.pids),
        max_disk_bytes: total(s.limits.disk_bytes),
        reserved_disk_bytes: total(s.reserved.disk_bytes),
        rejected_creates: s.rejected_creates,
        max_host_cpu_millis: host(s.limits.host_cpu_millis),
        reserved_host_cpu_millis: host(s.reserved.host_cpu_millis),
        max_virtual_cpu_slots: host(s.limits.virtual_cpu_slots),
        reserved_virtual_cpu_slots: host(s.reserved.virtual_cpu_slots),
        max_host_pids: host(s.limits.host_pids),
        reserved_host_pids: host(s.reserved.host_pids),
        accounting_status: status.into(),
        accounting_generation: generation,
        accounting_observed_at_unix_ms: observed_at_ms,
    }
}

fn pagination_required() -> Status {
    Status::resource_exhausted(
        "list exceeds response bounds; request pagination with page_size (or a smaller item is required)",
    )
}

// Every field has a fixed width, so a continuation's length never varies.
fn page_token(include_deleted: bool, uid: u32, upper: i64, last: i64) -> String {
    format!(
        "v2:{}:{uid:08x}:{upper:016x}:{last:016x}",
        u8::from(include_deleted)
    )
}

fn parse_page_token(token: &str, include_deleted: bool, uid: u32) -> Result<(i64, i64), Status> {
    let invalid = || {
        Status::invalid_argument(
            "invalid page_token, or it was issued for another caller or include_deleted",
        )
    };
    if token.len() > 128 || !token.is_ascii() {
        return Err(invalid());
    }
    let parts: Vec<_> = token.split(':').collect();
    if parts.len() != 5
        || parts[0] != "v2"
        || parts[1] != if include_deleted { "1" } else { "0" }
        || parts[2] != format!("{uid:08x}")
    {
        return Err(invalid());
    }
    let hex = |s: &str| -> Result<i64, Status> {
        if s.len() != 16
            || !s
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid());
        }
        i64::from_str_radix(s, 16).map_err(|_| invalid())
    };
    let (upper, last) = (hex(parts[3])?, hex(parts[4])?);
    if last <= 0 || upper < last {
        return Err(invalid());
    }
    Ok((upper, last))
}

fn status(e: Error) -> Status {
    match e {
        Error::InvalidArgument(m) => Status::invalid_argument(m),
        Error::NotFound(m) => Status::not_found(format!("{m} not found")),
        Error::FailedPrecondition(r) => refusal(tonic::Code::FailedPrecondition, r),
        Error::ResourceExhausted(m) => Status::resource_exhausted(m),
        Error::DeadlineExceeded(m) => Status::deadline_exceeded(m),
        Error::ShuttingDown => Status::unavailable("kilnd is shutting down"),
        Error::Backend(m) => Status::internal(m),
        Error::Refused(code, r) => refusal(
            match code {
                RefusalCode::AlreadyExists => tonic::Code::AlreadyExists,
                RefusalCode::ResourceExhausted => tonic::Code::ResourceExhausted,
                RefusalCode::DeadlineExceeded => tonic::Code::DeadlineExceeded,
                RefusalCode::Unavailable => tonic::Code::Unavailable,
            },
            r,
        ),
        Error::RequestIdTaken => {
            tracing::error!("a request-ID race escaped the manager");
            Status::internal("internal error; see the kilnd log")
        }
        Error::Internal(e) => {
            tracing::error!(error = %format!("{e:#}"), "internal error");
            Status::internal("internal error; see the kilnd log")
        }
    }
}

/// A refusal as gRPC sends it: the code is unchanged, and a typed one gains the
/// `kilnd-reason` trailer and its token as the message prefix (design section 1).
fn refusal(code: tonic::Code, r: Refusal) -> Status {
    let message = r.to_string();
    match r.reason() {
        Some(reason) => {
            let mut metadata = tonic::metadata::MetadataMap::new();
            metadata.insert(
                REASON_KEY,
                tonic::metadata::MetadataValue::from_static(reason),
            );
            Status::with_metadata(code, message, metadata)
        }
        None => Status::new(code, message),
    }
}

/// The reason trailer's key: ASCII metadata, matched by clients instead of prose.
pub const REASON_KEY: &str = "kilnd-reason";

/// The caller's own deadline, from its `grpc-timeout` header, a little early so the
/// typed `create_in_flight` answer reaches it before its transport gives up: 5 % of
/// the timeout, at most 250 ms. `received_at` is when the request's headers arrived,
/// where tonic starts that same timeout, however late its body follows. No header,
/// or a malformed one: no deadline.
fn rpc_deadline<T>(req: &Request<T>, received_at: tokio::time::Instant) -> Option<tokio::time::Instant> {
    let timeout = parse_grpc_timeout(req.metadata().get("grpc-timeout")?.to_str().ok()?)?;
    let margin = (timeout / 20).min(std::time::Duration::from_millis(250));
    received_at.checked_add(timeout.saturating_sub(margin))
}

/// gRPC's `TimeoutValue TimeoutUnit`: 1 to 8 ASCII digits and one of H M S m u n.
fn parse_grpc_timeout(value: &str) -> Option<std::time::Duration> {
    use std::time::Duration;
    let (digits, unit) = value.split_at(value.len().checked_sub(1)?);
    if digits.is_empty() || digits.len() > 8 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = digits.parse().ok()?;
    Some(match unit {
        "H" => Duration::from_secs(n.checked_mul(3600)?),
        "M" => Duration::from_secs(n.checked_mul(60)?),
        "S" => Duration::from_secs(n),
        "m" => Duration::from_millis(n),
        "u" => Duration::from_micros(n),
        "n" => Duration::from_nanos(n),
        _ => return None,
    })
}

fn create_request(
    spec: pb::SandboxSpec,
    expiry: Option<crate::expiry::RequestedExpiry>,
) -> Result<CreateRequest, Status> {
    let limits = spec.limits.unwrap_or_default();
    let net = spec.network.unwrap_or_default();
    let mode = pb::NetworkMode::try_from(net.mode)
        .map_err(|_| Status::invalid_argument("unknown network mode"))?;
    let network = match mode {
        pb::NetworkMode::Unspecified | pb::NetworkMode::None if net.allow.is_empty() => {
            Network::None
        }
        pb::NetworkMode::Full if net.allow.is_empty() => Network::Full,
        pb::NetworkMode::Allowlist => Network::Allow(net.allow),
        _ => {
            return Err(Status::invalid_argument(
                "network.allow is only valid with NETWORK_MODE_ALLOWLIST",
            ));
        }
    };
    Ok(CreateRequest {
        image: spec.image,
        memory_bytes: limits.memory_bytes,
        cpu_millis: limits.cpu_millis,
        pids: limits.pids,
        disk_bytes: limits.disk_bytes,
        network,
        read_only_root: spec.read_only_root,
        writable_paths: spec.writable_paths,
        labels: spec.labels.into_iter().collect::<BTreeMap<_, _>>(),
        expiry,
    })
}

fn spec_pb(s: SandboxSpec) -> pb::SandboxSpec {
    let (mode, allow) = match s.network {
        Network::None => (pb::NetworkMode::None, vec![]),
        Network::Full => (pb::NetworkMode::Full, vec![]),
        Network::Allow(a) => (pb::NetworkMode::Allowlist, a),
    };
    pb::SandboxSpec {
        image: s.image,
        limits: Some(pb::ResourceLimits {
            memory_bytes: s.memory_bytes,
            cpu_millis: s.cpu_millis,
            pids: s.pids,
            disk_bytes: s.disk_bytes,
        }),
        network: Some(pb::NetworkPolicy {
            mode: mode.into(),
            allow,
        }),
        read_only_root: s.read_only_root,
        writable_paths: s.writable_paths,
        labels: s.labels.into_iter().collect(),
    }
}

pub fn sandbox_pb(s: Sandbox) -> pb::Sandbox {
    let state = match s.state {
        SandboxState::Creating => pb::SandboxState::Creating,
        SandboxState::Ready => pb::SandboxState::Ready,
        SandboxState::Deleting => pb::SandboxState::Deleting,
        SandboxState::Deleted => pb::SandboxState::Deleted,
        SandboxState::Failed => pb::SandboxState::Failed,
        SandboxState::Lost => pb::SandboxState::Lost,
        SandboxState::Quarantined => pb::SandboxState::Quarantined,
    };
    let reservation = s.accounting.reservation;
    let deletion_reason = match s.lifecycle.deletion_reason {
        None => pb::DeletionReason::Unspecified,
        Some(DeletionReason::Requested) => pb::DeletionReason::Requested,
        Some(DeletionReason::ExpiredIdle) => pb::DeletionReason::ExpiredIdle,
        Some(DeletionReason::ExpiredLifetime) => pb::DeletionReason::ExpiredLifetime,
    };
    let policy = s.lifecycle.expiry;
    let expiry = pb::ExpiryStatus {
        effective: Some(pb::ExpiryPolicy {
            max_lifetime_ms: policy.max_lifetime_ms.unwrap_or(0),
            idle_timeout_ms: policy.idle_timeout_ms.unwrap_or(0),
        }),
        last_activity_at_unix_ms: s.lifecycle.activity_at_ms.unwrap_or(0),
        ..Default::default()
    };
    pb::Sandbox {
        request_id: s.lifecycle.request_id.clone().unwrap_or_default(),
        request_id_released: s.lifecycle.request_id_released_at_ms.is_some(),
        deletion_reason: deletion_reason.into(),
        expiry: Some(expiry),
        id: s.id,
        state: state.into(),
        spec: Some(spec_pb(s.spec)),
        backend: s.backend,
        backend_id: s.backend_id.unwrap_or_default(),
        created_at_unix_ms: s.created_at_ms,
        updated_at_unix_ms: s.updated_at_ms,
        deleted_at_unix_ms: s.deleted_at_ms.unwrap_or(0),
        failure_reason: s.failure_reason.unwrap_or_default(),
        owner_uid: s.owner_uid,
        reservation: Some(pb::ResourceReservation {
            memory_bytes: reservation.memory_bytes,
            disk_bytes: reservation.disk_bytes,
            pids: reservation.pids,
            host_cpu_millis: reservation.host_cpu_millis,
            virtual_cpu_slots: reservation.virtual_cpu_slots,
            host_pids: reservation.host_pids,
        }),
        runtime_profile: s.accounting.runtime_profile,
        runtime_artifact_digest: s.accounting.runtime_artifact_digest,
    }
}

fn expiry_status_pb(v: ExpiryView) -> pb::ExpiryStatus {
    pb::ExpiryStatus {
        effective: Some(pb::ExpiryPolicy {
            max_lifetime_ms: v.policy.max_lifetime_ms.unwrap_or(0),
            idle_timeout_ms: v.policy.idle_timeout_ms.unwrap_or(0),
        }),
        lifetime_expires_at_unix_ms: v.lifetime_expires_at_ms.unwrap_or(0),
        idle_expires_at_unix_ms: v.idle_expires_at_ms.unwrap_or(0),
        last_activity_at_unix_ms: v.last_activity_at_ms.unwrap_or(0),
        idle_paused: v.idle_paused,
    }
}

fn output_pb(c: Captured) -> pb::Output {
    pb::Output {
        truncated: c.truncated(),
        total_bytes: c.total_bytes,
        data: c.data,
        total_bytes_known: c.total_bytes_known,
    }
}

pub fn execution_pb(e: Execution) -> pb::Execution {
    let state = match e.state {
        ExecutionState::Running => pb::ExecutionState::Running,
        ExecutionState::Exited => pb::ExecutionState::Exited,
        ExecutionState::TimedOut => pb::ExecutionState::TimedOut,
        ExecutionState::Canceled => pb::ExecutionState::Canceled,
        ExecutionState::Failed => pb::ExecutionState::Failed,
        ExecutionState::Interrupted => pb::ExecutionState::Interrupted,
    };
    pb::Execution {
        id: e.id,
        sandbox_id: e.sandbox_id,
        argv: e.argv,
        state: state.into(),
        exit_code: (e.state == ExecutionState::Exited)
            .then_some(e.exit_code)
            .flatten(),
        command_status: e.command_status.map(|status| pb::CommandStatus {
            termination: Some(match status {
                crate::model::CommandStatus::Exited(code) => {
                    pb::command_status::Termination::ExitCode(code)
                }
                crate::model::CommandStatus::Signaled {
                    signal,
                    core_dumped,
                } => pb::command_status::Termination::Signal(pb::SignalStatus {
                    // Runtime command status validates positive signal numbers.
                    number: signal as u32,
                    core_dumped,
                }),
            }),
        }),
        runtime_error: e.runtime_error.map(runtime_diagnostic_pb),
        failure_reason: e.failure_reason.unwrap_or_default(),
        started_at_unix_ms: e.started_at_ms,
        finished_at_unix_ms: e.finished_at_ms.unwrap_or(0),
        timeout_ms: e.timeout_ms,
        stdin_bytes: e.stdin_bytes,
        stdout: Some(output_pb(e.stdout)),
        stderr: Some(output_pb(e.stderr)),
        sandbox_reusable: e.sandbox_reusable,
        cleanup_evidence: match e.cleanup_evidence {
            crate::model::CleanupEvidence::Unknown => pb::CleanupEvidence::Unknown,
            crate::model::CleanupEvidence::NoChildStarted => pb::CleanupEvidence::NoChildStarted,
            crate::model::CleanupEvidence::RuntimeDrained => pb::CleanupEvidence::RuntimeDrained,
            crate::model::CleanupEvidence::SandboxStopped => pb::CleanupEvidence::SandboxStopped,
        }
        .into(),
        cancel_reason: match e.cancel_reason {
            None => pb::CancelReason::Unspecified,
            Some(CancelReason::ClientDisconnected) => pb::CancelReason::ClientDisconnected,
            Some(CancelReason::SandboxDeleted) => pb::CancelReason::SandboxDeleted,
            Some(CancelReason::DaemonShutdown) => pb::CancelReason::DaemonShutdown,
            Some(CancelReason::SandboxExpiredLifetime) => pb::CancelReason::SandboxExpiredLifetime,
        }
        .into(),
    }
}

fn runtime_diagnostic_pb(d: crate::model::RuntimeDiagnostic) -> pb::RuntimeDiagnostic {
    use crate::model::{RuntimeErrorKind as K, RuntimeStage as S};
    let kind = match d.kind {
        K::InvalidRequest => pb::RuntimeErrorKind::InvalidRequest,
        K::Unavailable => pb::RuntimeErrorKind::Unavailable,
        K::NotFound => pb::RuntimeErrorKind::NotFound,
        K::Incompatible => pb::RuntimeErrorKind::Incompatible,
        K::Busy => pb::RuntimeErrorKind::Busy,
        K::LaunchFailed => pb::RuntimeErrorKind::LaunchFailed,
        K::Io => pb::RuntimeErrorKind::Io,
        K::Protocol => pb::RuntimeErrorKind::Protocol,
        K::CleanupFailed => pb::RuntimeErrorKind::CleanupFailed,
        K::Internal => pb::RuntimeErrorKind::Internal,
        K::Stopped => pb::RuntimeErrorKind::Stopped,
    };
    let stage = match d.stage {
        S::None => pb::RuntimeStage::Unspecified,
        S::Validate => pb::RuntimeStage::Validate,
        S::Connect => pb::RuntimeStage::Connect,
        S::Request => pb::RuntimeStage::Request,
        S::Prepare => pb::RuntimeStage::Prepare,
        S::Fork => pb::RuntimeStage::Fork,
        S::Admission => pb::RuntimeStage::Admission,
        S::Stdio => pb::RuntimeStage::Stdio,
        S::Exec => pb::RuntimeStage::Exec,
        S::Wait => pb::RuntimeStage::Wait,
        S::Cleanup => pb::RuntimeStage::Cleanup,
        S::Report => pb::RuntimeStage::Report,
        S::Capture => pb::RuntimeStage::Capture,
        S::Handshake => pb::RuntimeStage::Handshake,
    };
    pb::RuntimeDiagnostic {
        kind: kind.into(),
        stage: stage.into(),
        message: d.message,
        native_code: d.native_code,
        message_truncated: d.message_truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::Limits;
    use crate::runtime::fake::{FakeGate, FakeRuntime};
    use crate::store::Store;
    use pb::kilnd_service_server::KilndService;
    use std::time::Duration;

    /// What the transport attaches: tests have no socket, so they name a caller.
    fn as_uid<T>(message: T, uid: u32) -> Request<T> {
        let mut request = Request::new(message);
        request.extensions_mut().insert(PeerIdentity {
            uid: Some(uid),
            lane: ConnectionLane::General,
        });
        request
    }

    fn as_root<T>(message: T) -> Request<T> {
        as_uid(message, 0)
    }

    #[tokio::test]
    async fn invalid_create_contract_is_a_client_error_without_side_effects() {
        let fake = FakeRuntime::default();
        let manager = Arc::new(Manager::new(
            fake.clone(),
            Store::open_in_memory().unwrap(),
            Limits::default(),
        ));
        let service = Service::new(manager.clone());
        let invalid = [
            pb::SandboxSpec {
                network: Some(pb::NetworkPolicy {
                    mode: pb::NetworkMode::Allowlist.into(),
                    allow: vec!["/".into()],
                }),
                ..Default::default()
            },
            pb::SandboxSpec {
                read_only_root: true,
                writable_paths: vec!["/".into()],
                ..Default::default()
            },
        ];
        for spec in invalid {
            let error = service
                .create_sandbox(as_root(pb::CreateSandboxRequest { request_id: String::new(),
                    spec: Some(spec),
                    expiry: None,
                }))
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
        }
        assert!(manager.list(true).unwrap().is_empty());
        assert!(fake.state().created.is_empty());
    }

    #[tokio::test]
    async fn invalid_exec_contract_is_a_client_error_without_side_effects() {
        let fake = FakeRuntime::default();
        let manager = Arc::new(Manager::new(
            fake.clone(),
            Store::open_in_memory().unwrap(),
            Limits::default(),
        ));
        let sandbox = manager.create(CreateRequest::default()).await.unwrap();
        let service = Service::new(manager.clone());
        for argv in [
            vec![],
            vec![String::new()],
            vec!["echo".into(), "a\0b".into()],
        ] {
            let error = service
                .exec(as_root(pb::ExecRequest {
                    sandbox_id: sandbox.id.clone(),
                    argv,
                    ..Default::default()
                }))
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
        }
        assert!(manager.get(&sandbox.id, 100).unwrap().1.is_empty());
        assert!(fake.state().exec_calls.is_empty());
    }

    #[tokio::test]
    async fn rpc_admission_recovers_on_cancellation_error_and_completion() {
        let fake = FakeRuntime::default();
        let gate = FakeGate::default();
        fake.state().create_after_allocation = Some(gate.clone());
        let manager = Arc::new(Manager::new(
            fake.clone(),
            Store::open_in_memory().unwrap(),
            Limits {
                max_concurrent_rpcs: 1,
                max_concurrent_health: 1,
                ..Limits::default()
            },
        ));
        let service = Arc::new(Service::new(manager.clone()));
        let handler = tokio::spawn({
            let service = service.clone();
            async move {
                service
                    .create_sandbox(as_root(pb::CreateSandboxRequest::default()))
                    .await
            }
        });
        gate.entered().await;
        let error = service
            .list_sandboxes(as_root(pb::ListSandboxesRequest::default()))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
        let stats = service
            .health(Request::new(pb::HealthRequest {}))
            .await
            .unwrap()
            .into_inner()
            .admission
            .unwrap();
        assert_eq!((stats.current_rpcs, stats.rejected_rpcs), (1, 1));
        handler.abort();
        assert!(handler.await.unwrap_err().is_cancelled());
        assert_eq!(manager.admission().snapshot().rpcs.current, 0);
        let error = service
            .get_sandbox(as_root(pb::GetSandboxRequest::default()))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert_eq!(manager.admission().snapshot().rpcs.current, 0);
        gate.release();
        manager.begin_shutdown();
        manager.drain_operations().await;
        service
            .list_sandboxes(as_root(pb::ListSandboxesRequest::default()))
            .await
            .unwrap();
        assert_eq!(manager.admission().snapshot().rpcs.current, 0);
    }

    fn on_lane<T>(message: T, uid: u32, lane: ConnectionLane) -> Request<T> {
        let mut request = Request::new(message);
        request.extensions_mut().insert(PeerIdentity {
            uid: Some(uid),
            lane,
        });
        request
    }

    /// B6-BI-03: one UID's ordinary RPCs stop at its share while another UID's proceed;
    /// its Get and Delete still reach the cleanup lane, one at a time; and a connection
    /// on a reserved slot serves Health, Get and Delete but nothing else.
    #[tokio::test]
    async fn b7_rpc_shares_cleanup_lane_and_reserved_connections() {
        let manager = Arc::new(Manager::new(
            FakeRuntime::default(),
            Store::open_in_memory().unwrap(),
            Limits {
                max_concurrent_rpcs: 4,
                max_concurrent_rpcs_per_uid: 1,
                max_concurrent_cleanup: 2,
                ..Limits::default()
            },
        ));
        let service = Service::new(manager.clone());
        let hostile = create_as(&service, 1001).await;
        let victim = create_as(&service, 1002).await;
        let held = manager
            .admission()
            .try_rpc(RpcClass::Ordinary, Some(1001))
            .unwrap();
        let error = service
            .create_sandbox(as_uid(pb::CreateSandboxRequest::default(), 1001))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
        assert_eq!(manager.admission().snapshot().rejected_rpc_shares, 1);
        create_as(&service, 1002).await;
        // Its own Get through the cleanup lane; with that lane's one permit per UID
        // held, a second is refused.
        service
            .get_sandbox(as_uid(
                pb::GetSandboxRequest {
                    id: hostile.id.clone(),
                    ..Default::default()
                },
                1001,
            ))
            .await
            .unwrap();
        let cleanup = manager
            .admission()
            .try_rpc(RpcClass::Cleanup, Some(1001))
            .unwrap();
        assert_eq!(manager.admission().snapshot().cleanup.current, 1);
        let error = service
            .get_sandbox(as_uid(
                pb::GetSandboxRequest {
                    id: hostile.id.clone(),
                    ..Default::default()
                },
                1001,
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
        drop((held, cleanup));

        // A reserved-slot connection, and root's own slot: Health, Get and Delete,
        // never an ordinary RPC (Create, List, Exec and GetExecution, each valid on a
        // general connection).
        let execution = exec_as(&service, &victim.id, 1002).await;
        for (uid, lane) in [(1002, ConnectionLane::Reserved), (0, ConnectionLane::Root)] {
            let victim = create_as(&service, uid).await;
            let execution = if uid == 0 {
                exec_as(&service, &victim.id, 0).await
            } else {
                execution.clone()
            };
            for error in [
                service
                    .create_sandbox(on_lane(pb::CreateSandboxRequest::default(), uid, lane))
                    .await
                    .unwrap_err(),
                service
                    .list_sandboxes(on_lane(pb::ListSandboxesRequest::default(), uid, lane))
                    .await
                    .unwrap_err(),
                service
                    .exec(on_lane(
                        pb::ExecRequest {
                            sandbox_id: victim.id.clone(),
                            argv: vec!["echo".into(), "secret".into()],
                            ..Default::default()
                        },
                        uid,
                        lane,
                    ))
                    .await
                    .unwrap_err(),
                service
                    .get_execution(on_lane(
                        pb::GetExecutionRequest {
                            id: execution.id.clone(),
                        },
                        uid,
                        lane,
                    ))
                    .await
                    .unwrap_err(),
            ] {
                assert_eq!(error.code(), tonic::Code::ResourceExhausted, "{lane:?}");
                assert!(error.message().contains("reserved slot"), "{error:?}");
            }
            service
                .health(on_lane(pb::HealthRequest {}, uid, lane))
                .await
                .unwrap();
            service
                .get_sandbox(on_lane(
                    pb::GetSandboxRequest {
                        id: victim.id.clone(),
                        ..Default::default()
                    },
                    uid,
                    lane,
                ))
                .await
                .unwrap();
            service
                .delete_sandbox(on_lane(
                    pb::DeleteSandboxRequest { release_request_id: false,
                        id: victim.id.clone(),
                    },
                    uid,
                    lane,
                ))
                .await
                .unwrap();
        }
        let snapshot = manager.admission().snapshot();
        assert_eq!((snapshot.rpcs.current, snapshot.cleanup.current), (0, 0));
    }

    /// B7 milestone 2 (MEDIUM-2): with the Health lane, the ordinary RPCs and the cleanup
    /// lane all held by other UIDs, root on its own slot still gets Health, Get and
    /// Delete; another UID gets none of them.
    #[tokio::test]
    async fn b7m2_root_reaches_health_and_cleanup_with_every_lane_held() {
        let manager = Arc::new(Manager::new(
            FakeRuntime::default(),
            Store::open_in_memory().unwrap(),
            Limits {
                max_concurrent_rpcs: 2,
                max_concurrent_rpcs_per_uid: 1,
                max_concurrent_cleanup: 2,
                max_concurrent_health: 1,
                ..Limits::default()
            },
        ));
        let service = Service::new(manager.clone());
        let sandbox = create_as(&service, 0).await;
        let admission = manager.admission();
        let mut held = Vec::new();
        for uid in [1001, 1002] {
            held.push(admission.try_rpc(RpcClass::Ordinary, Some(uid)).unwrap());
            held.push(admission.try_rpc(RpcClass::Cleanup, Some(uid)).unwrap());
        }
        held.push(admission.try_health(Some(1003)).unwrap());
        let root = ConnectionLane::Root;
        let other = create_as_error(&service, 1004).await;
        assert_eq!(other.code(), tonic::Code::ResourceExhausted);
        assert!(
            service
                .health(on_lane(
                    pb::HealthRequest {},
                    1004,
                    ConnectionLane::Reserved
                ))
                .await
                .is_err()
        );
        service
            .health(on_lane(pb::HealthRequest {}, 0, root))
            .await
            .unwrap();
        service
            .get_sandbox(on_lane(
                pb::GetSandboxRequest {
                    id: sandbox.id.clone(),
                    ..Default::default()
                },
                0,
                root,
            ))
            .await
            .unwrap();
        service
            .delete_sandbox(on_lane(
                pb::DeleteSandboxRequest { release_request_id: false,
                    id: sandbox.id.clone(),
                },
                0,
                root,
            ))
            .await
            .unwrap();
        assert_eq!(admission.snapshot().root_rpc.current, 0);
        drop(held);
    }

    #[tokio::test]
    async fn health_has_reserved_rpc_capacity_and_shared_probe_survives_handler_drop() {
        let fake = FakeRuntime::default();
        let gate = FakeGate::default();
        fake.state().version_gate = Some(gate.clone());
        let manager = Arc::new(Manager::new(
            fake.clone(),
            Store::open_in_memory().unwrap(),
            Limits {
                max_concurrent_health: 1,
                ..Limits::default()
            },
        ));
        let service = Arc::new(Service::new(manager.clone()));
        let first = tokio::spawn({
            let service = service.clone();
            async move { service.health(Request::new(pb::HealthRequest {})).await }
        });
        gate.entered().await;
        let error = service
            .health(Request::new(pb::HealthRequest {}))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        assert_eq!(manager.admission().snapshot().health.current, 0);
        assert_eq!(fake.state().active_version_calls, 1);
        let next = tokio::spawn({
            let service = service.clone();
            async move { service.health(Request::new(pb::HealthRequest {})).await }
        });
        gate.release();
        next.await.unwrap().unwrap();
        assert_eq!(fake.state().version_calls, 1);
        assert_eq!(manager.admission().snapshot().health.current, 0);
        assert_eq!(manager.admission().snapshot().health.rejected, 1);
    }

    #[test]
    fn page_tokens_are_canonical_strict_and_filter_bound() {
        let valid = "v2:0:000003e9:000000000000000f:0000000000000001";
        assert_eq!(page_token(false, 1001, 15, 1), valid);
        assert_eq!(parse_page_token(valid, false, 1001).unwrap(), (15, 1));
        assert!(parse_page_token(valid, true, 1001).is_err());
        // Bound to the caller, in both directions, and root is no exception.
        assert!(parse_page_token(valid, false, 1002).is_err());
        assert!(parse_page_token(valid, false, 0).is_err());
        assert!(parse_page_token(&page_token(false, 0, 15, 1), false, 1001).is_err());
        assert_eq!(page_token(false, 0, 15, 1).len(), valid.len());
        assert_eq!(page_token(true, u32::MAX, 15, 1).len(), valid.len());
        for invalid in [
            "",
            // Cursors issued before uid binding do not carry over an upgrade.
            "v1:0:000000000000000f:0000000000000001",
            "v3:0:000003e9:000000000000000f:0000000000000001",
            "v2:2:000003e9:000000000000000f:0000000000000001",
            "v2:00:000003e9:000000000000000f:0000000000000001",
            "v2:0:3e9:000000000000000f:0000000000000001",
            "v2:0:000003E9:000000000000000f:0000000000000001",
            "v2:0:0000003e9:000000000000000f:0000000000000001",
            "v2:0:000000000000000f:0000000000000001",
            "v2:0:000003e9:000000000000000F:0000000000000001",
            "v2:0:000003e9:f:1",
            "v2:0:000003e9:0000000000000000:0000000000000000",
            "v2:0:000003e9:0000000000000001:0000000000000002",
            "v2:0:000003e9:8000000000000000:0000000000000001",
            "v2:0:000003e9:000000000000000f:0000000000000001:",
            "v2:0:000003e9:000000000000000f:0000000000000001\n",
            "v2:0:000003e9:000000000000000f:000000000000000é",
        ] {
            assert_eq!(
                parse_page_token(invalid, false, 1001).unwrap_err().code(),
                tonic::Code::InvalidArgument,
                "{invalid:?}"
            );
        }
        assert!(parse_page_token(&"a".repeat(129), false, 1001).is_err());
        assert_eq!(
            status(Error::DeadlineExceeded("queued".into())).code(),
            tonic::Code::DeadlineExceeded
        );
    }

    #[tokio::test]
    async fn legacy_list_fails_over_count_and_pages_exclude_later_inserts() {
        let manager = Arc::new(Manager::new(
            FakeRuntime::default(),
            Store::open_in_memory().unwrap(),
            Limits {
                max_list_page_size: 2,
                ..Limits::default()
            },
        ));
        let mut ids = Vec::new();
        for _ in 0..5 {
            ids.push(manager.create(Default::default()).await.unwrap().id);
        }
        ids.reverse();
        let service = Service::new(manager.clone());
        assert_eq!(
            service
                .list_sandboxes(as_root(pb::ListSandboxesRequest::default()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );
        let mut token = String::new();
        let mut got = Vec::new();
        loop {
            let response = service
                .list_sandboxes(as_root(pb::ListSandboxesRequest {
                    page_size: Some(0),
                    page_token: token,
                    include_deleted: false,
                }))
                .await
                .unwrap()
                .into_inner();
            assert!(response.sandboxes.len() <= 2);
            if got.is_empty() {
                manager.create(Default::default()).await.unwrap();
            }
            got.extend(response.sandboxes.into_iter().map(|s| s.id));
            token = response.next_page_token;
            if token.is_empty() {
                break;
            }
            assert_eq!(
                service
                    .list_sandboxes(as_root(pb::ListSandboxesRequest {
                        include_deleted: true,
                        page_size: Some(2),
                        page_token: token.clone()
                    }))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
        assert_eq!(got, ids);
        for request in [
            pb::ListSandboxesRequest {
                page_size: Some(3),
                ..Default::default()
            },
            pb::ListSandboxesRequest {
                page_token: page_token(false, 0, 5, 2),
                ..Default::default()
            },
        ] {
            assert_eq!(
                service
                    .list_sandboxes(as_root(request))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
    }

    #[tokio::test]
    async fn list_byte_bound_accounts_for_continuation_and_refuses_unfittable_item() {
        let manager = Arc::new(Manager::new(
            FakeRuntime::default(),
            Store::open_in_memory().unwrap(),
            Limits {
                max_list_response_bytes: 400,
                ..Limits::default()
            },
        ));
        let mut ids = Vec::new();
        for _ in 0..3 {
            ids.push(
                manager
                    .create(CreateRequest {
                        labels: BTreeMap::from([("label".into(), "x".repeat(160))]),
                        ..Default::default()
                    })
                    .await
                    .unwrap()
                    .id,
            );
        }
        ids.reverse();
        let service = Service::new(manager);
        assert_eq!(
            service
                .list_sandboxes(as_root(pb::ListSandboxesRequest::default()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );
        let mut token = String::new();
        let mut got = Vec::new();
        loop {
            let response = service
                .list_sandboxes(as_root(pb::ListSandboxesRequest {
                    page_size: Some(3),
                    page_token: token,
                    ..Default::default()
                }))
                .await
                .unwrap()
                .into_inner();
            assert!(response.encoded_len() <= 400);
            assert_eq!(response.sandboxes.len(), 1);
            got.push(response.sandboxes[0].id.clone());
            token = response.next_page_token;
            if token.is_empty() {
                break;
            }
        }
        assert_eq!(got, ids);
        let manager = Arc::new(Manager::new(
            FakeRuntime::default(),
            Store::open_in_memory().unwrap(),
            Limits {
                max_list_response_bytes: 1,
                ..Limits::default()
            },
        ));
        manager.create(Default::default()).await.unwrap();
        assert_eq!(
            Service::new(manager)
                .list_sandboxes(as_root(pb::ListSandboxesRequest {
                    page_size: Some(1),
                    ..Default::default()
                }))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );
    }

    #[tokio::test]
    async fn maximum_argv_and_both_output_streams_fit_the_validated_response_budget() {
        let max_output = 1024;
        let max_argv = Limits::default().max_argv_bytes;
        let max_response = (2 * max_output) + max_argv + (64 * 1024);
        let manager = Arc::new(Manager::new(
            FakeRuntime::default(),
            Store::open_in_memory().unwrap(),
            Limits {
                max_output_bytes: max_output,
                max_response_bytes: max_response,
                ..Limits::default()
            },
        ));
        let sandbox = manager.create(Default::default()).await.unwrap();
        let command = "spew-both";
        let count = max_output.to_string();
        let fixed = command.len() + 1 + count.len() + 1;
        let filler = "x".repeat(max_argv - fixed - 1);
        let response = Service::new(manager)
            .exec(as_root(pb::ExecRequest {
                sandbox_id: sandbox.id,
                argv: vec![command.into(), count, filler],
                stdin: vec![],
                timeout_ms: 1_000,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(response.encoded_len() <= max_response);
        let execution = response.execution.unwrap();
        assert_eq!(execution.stdout.unwrap().data.len(), max_output);
        assert_eq!(execution.stderr.unwrap().data.len(), max_output);
    }

    #[tokio::test]
    async fn dropping_create_handler_does_not_drop_owned_operation() {
        let fake = FakeRuntime::default();
        let gate = FakeGate::default();
        fake.state().create_after_allocation = Some(gate.clone());
        let manager = Arc::new(Manager::new(
            fake.clone(),
            Store::open_in_memory().unwrap(),
            Limits::default(),
        ));
        let service = Arc::new(Service::new(manager.clone()));
        let handler = tokio::spawn(async move {
            KilndService::create_sandbox(
                service.as_ref(),
                as_root(pb::CreateSandboxRequest { request_id: String::new(),
                    spec: None,
                    expiry: None,
                }),
            )
            .await
        });

        gate.entered().await;
        handler.abort();
        assert!(handler.await.unwrap_err().is_cancelled());
        gate.release();
        manager.begin_shutdown();
        tokio::time::timeout(Duration::from_secs(5), manager.drain_operations())
            .await
            .expect("owned create did not finish");

        let row = manager.list(true).unwrap().remove(0);
        assert_eq!(row.state, SandboxState::Ready);
        assert_eq!(
            row.backend_id.as_ref(),
            fake.state().sandboxes.keys().next()
        );
    }

    #[tokio::test]
    async fn dropping_exec_handler_cancels_and_finalizes_owned_operation() {
        let fake = FakeRuntime::default();
        let manager = Arc::new(Manager::new(
            fake.clone(),
            Store::open_in_memory().unwrap(),
            Limits::default(),
        ));
        let sandbox = manager.create(Default::default()).await.unwrap();
        let gate = FakeGate::default();
        fake.state().exec_before_run = Some(gate.clone());
        let service = Arc::new(Service::new(manager.clone()));
        let handler = tokio::spawn({
            let service = service.clone();
            let sandbox_id = sandbox.id.clone();
            async move {
                KilndService::exec(
                    service.as_ref(),
                    as_root(pb::ExecRequest {
                        sandbox_id,
                        argv: vec!["sleep".into()],
                        ..Default::default()
                    }),
                )
                .await
            }
        });

        gate.entered().await;
        let execution_id = manager.get(&sandbox.id, 1).unwrap().1[0].id.clone();
        handler.abort();
        assert!(handler.await.unwrap_err().is_cancelled());
        assert_eq!(
            manager.execution(&execution_id).unwrap().state,
            ExecutionState::Running
        );
        assert_eq!(fake.state().active_execs, 1);

        gate.release();
        let execution = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let execution = manager.execution(&execution_id).unwrap();
                if execution.state != ExecutionState::Running {
                    break execution;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("supervised exec did not finalize");
        assert_eq!(execution.state, ExecutionState::Canceled);
        assert_eq!(
            execution.failure_reason.as_deref(),
            Some("client disconnected")
        );
        assert_eq!(fake.state().active_execs, 0);
        assert_eq!(fake.state().canceled_execs, 1);

        let next = manager
            .exec(ExecRequest {
                sandbox_id: sandbox.id,
                argv: vec!["echo".into(), "usable".into()],
                stdin: vec![],
                timeout_ms: 0,
            })
            .await
            .unwrap();
        assert_eq!(next.state, ExecutionState::Exited);
        assert_eq!(next.stdout.data, b"usable\n");
    }

    #[tokio::test]
    async fn health_and_rows_expose_additive_evidence_fields_for_kiln_semantics() {
        let (fake, _manager, service) = owned_service(Limits::default());
        let sandbox = create_as(&service, 0).await;
        let reservation = sandbox.reservation.unwrap();
        let limits = sandbox.spec.unwrap().limits.unwrap();
        assert_eq!(reservation.memory_bytes, limits.memory_bytes);
        assert_eq!(reservation.disk_bytes, limits.disk_bytes);
        assert_eq!(reservation.pids, u64::from(limits.pids));
        assert_eq!(reservation.host_cpu_millis, 0);
        assert_eq!(reservation.virtual_cpu_slots, 0);
        assert_eq!(reservation.host_pids, 0);
        assert_eq!(sandbox.runtime_profile, "fake");
        assert_eq!(sandbox.runtime_artifact_digest, "");

        let health = service
            .health(as_root(pb::HealthRequest {}))
            .await
            .unwrap()
            .into_inner();
        let stats = health.node_resources.unwrap();
        assert_eq!(
            stats.accounting_status,
            pb::NodeAccountingStatus::LocalLegacy as i32
        );
        assert_eq!(stats.reserved_sandboxes, 1);
        assert_eq!(stats.reserved_memory_bytes, reservation.memory_bytes);
        assert_eq!(
            (
                stats.max_host_cpu_millis,
                stats.reserved_host_cpu_millis,
                stats.max_virtual_cpu_slots,
                stats.reserved_virtual_cpu_slots,
                stats.max_host_pids,
                stats.reserved_host_pids,
            ),
            (0, 0, 0, 0, 0, 0),
            "kiln reserves no CPU, vCPU or host PIDs"
        );
        let capabilities = health.runtime_capabilities.unwrap();
        assert!(capabilities.interruption_preserves_session);
        assert!(!capabilities.checkpoint);
        assert_eq!(capabilities.network_modes.len(), 3);

        let exec = |argv: &[&str], id: &str| {
            as_root(pb::ExecRequest {
                sandbox_id: id.to_string(),
                argv: argv.iter().map(|a| a.to_string()).collect(),
                ..Default::default()
            })
        };
        let done = KilndService::exec(&service, exec(&["exit", "127"], &sandbox.id))
            .await
            .unwrap()
            .into_inner()
            .execution
            .unwrap();
        assert_eq!(done.exit_code, Some(127), "exit projection is unchanged");
        assert_eq!(done.sandbox_reusable, Some(true));
        assert_eq!(
            done.cleanup_evidence,
            pb::CleanupEvidence::RuntimeDrained as i32
        );

        let failed = KilndService::exec(&service, exec(&["cleanup-fail"], &sandbox.id))
            .await
            .unwrap()
            .into_inner()
            .execution
            .unwrap();
        assert_eq!(failed.sandbox_reusable, Some(false));
        assert_eq!(failed.cleanup_evidence, pb::CleanupEvidence::Unknown as i32);
        let refused = KilndService::exec(&service, exec(&["echo"], &sandbox.id))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
        assert_eq!(fake.state().exec_calls.len(), 2);
        let got = service
            .get_sandbox(as_root(pb::GetSandboxRequest {
                id: sandbox.id,
                execution_limit: 0,
            }))
            .await
            .unwrap()
            .into_inner()
            .sandbox
            .unwrap();
        assert_eq!(got.state, pb::SandboxState::Quarantined as i32);
    }

    #[tokio::test]
    async fn health_reports_the_node_authoritys_own_totals_and_generation() {
        use crate::runtime::NodeTotals;
        use crate::store::{SandboxBudgets, SandboxResources};
        let fake = FakeRuntime::fenced();
        let totals = NodeTotals {
            generation: 41,
            limits: SandboxBudgets {
                sandboxes: 3,
                memory_bytes: 3072 << 20,
                pids: 2048,
                disk_bytes: 16 << 30,
                host_cpu_millis: 3500,
                virtual_cpu_slots: 3,
                host_pids: 128,
            },
            reserved: SandboxResources {
                sandboxes: 1,
                memory_bytes: (896 + 128) << 20,
                pids: 192 + 32,
                disk_bytes: (1408 << 20) + (512 << 20),
                host_cpu_millis: 1500,
                virtual_cpu_slots: 1,
                host_pids: 64,
            },
            over_committed: false,
            node_fault: None,
            degraded: None,
        };
        fake.state().node_totals = Some(totals.clone());
        let manager = Arc::new(Manager::new(
            fake.clone(),
            Store::open_in_memory().unwrap(),
            Limits::default(),
        ));
        let service = Service::new(manager.clone());
        let health = service
            .health(as_root(pb::HealthRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            health.status,
            pb::health_response::Status::Serving as i32,
            "{}",
            health.detail
        );
        let stats = health.node_resources.unwrap();
        assert_eq!(
            stats.accounting_status,
            pb::NodeAccountingStatus::Authoritative as i32
        );
        assert_eq!(stats.accounting_generation, 41);
        assert!(stats.accounting_observed_at_unix_ms > 0);
        assert_eq!(
            (
                stats.max_sandboxes,
                stats.reserved_sandboxes,
                stats.reserved_memory_bytes,
                stats.reserved_host_cpu_millis,
                stats.max_virtual_cpu_slots,
                stats.reserved_host_pids,
            ),
            (3, 1, (896 + 128) << 20, 1500, 3, 64)
        );
        // Commitments over a lowered ceiling degrade Health; nothing is discounted.
        let mut over = totals;
        over.over_committed = true;
        over.generation = 42;
        fake.state().node_totals = Some(over);
        let manager = Arc::new(Manager::new(
            fake,
            Store::open_in_memory().unwrap(),
            Limits::default(),
        ));
        let health = Service::new(manager)
            .health(as_root(pb::HealthRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(health.status, pb::health_response::Status::Degraded as i32);
        assert!(
            health.detail.contains("exceed its ceilings"),
            "{}",
            health.detail
        );
        assert_eq!(health.node_resources.unwrap().reserved_sandboxes, 1);
    }

    #[tokio::test]
    async fn an_unreadable_node_authority_is_never_replaced_by_a_local_sum() {
        let fake = FakeRuntime::fenced();
        let manager = Arc::new(Manager::new(
            fake,
            Store::open_in_memory().unwrap(),
            Limits::default(),
        ));
        let service = Service::new(manager.clone());
        let sandbox = create_as(&service, 0).await;
        assert_eq!(sandbox.reservation.unwrap().memory_bytes, 896 << 20);
        assert_eq!(sandbox.runtime_profile, "offline-768-v1");
        assert_eq!(sandbox.runtime_artifact_digest.len(), 64);
        assert_eq!(manager.store_resources_for_test().sandboxes, 1);
        let health = service
            .health(as_root(pb::HealthRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(health.status, pb::health_response::Status::Degraded as i32);
        let stats = health.node_resources.unwrap();
        assert_eq!(
            stats.accounting_status,
            pb::NodeAccountingStatus::Unavailable as i32
        );
        assert_eq!(
            (
                stats.reserved_sandboxes,
                stats.reserved_memory_bytes,
                stats.reserved_pids,
                stats.reserved_disk_bytes,
                stats.reserved_host_cpu_millis,
                stats.reserved_virtual_cpu_slots,
                stats.reserved_host_pids,
            ),
            (0, 0, 0, 0, 0, 0, 0),
            "local charges must not look like node totals"
        );
        let capabilities = health.runtime_capabilities.unwrap();
        assert!(!capabilities.interruption_preserves_session);
        assert_eq!(
            capabilities.network_modes,
            vec![pb::NetworkMode::None as i32]
        );
    }

    fn owned_service(
        limits: Limits,
    ) -> (FakeRuntime, Arc<Manager<FakeRuntime>>, Service<FakeRuntime>) {
        let fake = FakeRuntime::default();
        let manager = Arc::new(Manager::new(
            fake.clone(),
            Store::open_in_memory().unwrap(),
            Limits {
                max_node_memory_bytes: 1 << 40,
                ..limits
            },
        ));
        let service = Service::new(manager.clone());
        (fake, manager, service)
    }

    async fn create_as(service: &Service<FakeRuntime>, uid: u32) -> pb::Sandbox {
        service
            .create_sandbox(as_uid(pb::CreateSandboxRequest::default(), uid))
            .await
            .unwrap()
            .into_inner()
            .sandbox
            .unwrap()
    }

    async fn create_as_error(service: &Service<FakeRuntime>, uid: u32) -> Status {
        service
            .create_sandbox(as_uid(pb::CreateSandboxRequest::default(), uid))
            .await
            .unwrap_err()
    }

    async fn exec_as(service: &Service<FakeRuntime>, sandbox_id: &str, uid: u32) -> pb::Execution {
        service
            .exec(as_uid(
                pb::ExecRequest {
                    sandbox_id: sandbox_id.into(),
                    argv: vec!["echo".into(), "secret".into()],
                    ..Default::default()
                },
                uid,
            ))
            .await
            .unwrap()
            .into_inner()
            .execution
            .unwrap()
    }

    /// Every sandbox ID the caller gets by following pages to the end.
    async fn list_pages_as(
        service: &Service<FakeRuntime>,
        uid: u32,
        include_deleted: bool,
        page_size: u32,
    ) -> Vec<String> {
        let mut token = String::new();
        let mut ids = Vec::new();
        loop {
            let response = service
                .list_sandboxes(as_uid(
                    pb::ListSandboxesRequest {
                        include_deleted,
                        page_size: Some(page_size),
                        page_token: token,
                    },
                    uid,
                ))
                .await
                .unwrap()
                .into_inner();
            assert!(response.sandboxes.len() <= page_size as usize);
            // A foreign row may never produce a page of nothing to continue from.
            assert!(!response.sandboxes.is_empty() || response.next_page_token.is_empty());
            assert!(
                response
                    .sandboxes
                    .iter()
                    .all(|s| uid == 0 || s.owner_uid == uid)
            );
            ids.extend(response.sandboxes.into_iter().map(|s| s.id));
            token = response.next_page_token;
            if token.is_empty() {
                return ids;
            }
        }
    }

    #[tokio::test]
    async fn foreign_callers_get_not_found_and_change_nothing() {
        let (fake, manager, service) = owned_service(Limits::default());
        let sandbox = create_as(&service, 1001).await;
        assert_eq!(sandbox.owner_uid, 1001);
        let execution = exec_as(&service, &sandbox.id, 1001).await;
        let (row_before, executions_before) = manager.get(&sandbox.id, 100).unwrap();
        let exec_calls_before = fake.state().exec_calls.len();

        let missing_sandbox = "sb-00000000000000ff";
        let missing_execution = "ex-00000000000000ff";
        for (id, foreign, uid) in [
            (sandbox.id.as_str(), true, 1002),
            (missing_sandbox, false, 1001),
        ] {
            let get = service
                .get_sandbox(as_uid(
                    pb::GetSandboxRequest {
                        id: id.into(),
                        execution_limit: 0,
                    },
                    uid,
                ))
                .await
                .unwrap_err();
            let exec = service
                .exec(as_uid(
                    pb::ExecRequest {
                        sandbox_id: id.into(),
                        argv: vec!["echo".into(), "stolen".into()],
                        ..Default::default()
                    },
                    uid,
                ))
                .await
                .unwrap_err();
            // Even a request the manager would refuse is refused as absent.
            let invalid_exec = service
                .exec(as_uid(
                    pb::ExecRequest {
                        sandbox_id: id.into(),
                        argv: vec![],
                        ..Default::default()
                    },
                    uid,
                ))
                .await
                .unwrap_err();
            let delete = service
                .delete_sandbox(as_uid(pb::DeleteSandboxRequest { release_request_id: false, id: id.into() }, uid))
                .await
                .unwrap_err();
            for error in [get, exec, invalid_exec, delete] {
                assert_eq!(error.code(), tonic::Code::NotFound, "foreign={foreign}");
                assert_eq!(error.message(), format!("sandbox {id} not found"));
            }
        }
        for (id, uid) in [(execution.id.as_str(), 1002), (missing_execution, 1001)] {
            let error = service
                .get_execution(as_uid(pb::GetExecutionRequest { id: id.into() }, uid))
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::NotFound);
            // Identical to absence, so it cannot name the parent sandbox.
            assert_eq!(error.message(), format!("execution {id} not found"));
        }

        assert_eq!(fake.state().exec_calls.len(), exec_calls_before);
        assert!(fake.state().remove_attempts.is_empty());
        let (row_after, executions_after) = manager.get(&sandbox.id, 100).unwrap();
        assert_eq!(row_after, row_before);
        assert_eq!(executions_after, executions_before);
        assert_eq!(row_after.state, SandboxState::Ready);

        // Malformed IDs say so whoever asks; that reveals nothing about any row.
        assert_eq!(
            service
                .get_sandbox(as_uid(pb::GetSandboxRequest::default(), 1002))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            service
                .get_execution(as_uid(pb::GetExecutionRequest::default(), 1002))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }

    #[tokio::test]
    async fn owner_and_root_can_use_a_sandbox() {
        let (fake, _manager, service) = owned_service(Limits::default());
        for uid in [1001, 0] {
            let sandbox = create_as(&service, 1001).await;
            let got = service
                .get_sandbox(as_uid(
                    pb::GetSandboxRequest {
                        id: sandbox.id.clone(),
                        execution_limit: 0,
                    },
                    uid,
                ))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(got.sandbox.unwrap().owner_uid, 1001);
            let execution = exec_as(&service, &sandbox.id, uid).await;
            assert_eq!(execution.state, pb::ExecutionState::Exited as i32);
            let read = service
                .get_execution(as_uid(
                    pb::GetExecutionRequest {
                        id: execution.id.clone(),
                    },
                    uid,
                ))
                .await
                .unwrap()
                .into_inner()
                .execution
                .unwrap();
            assert_eq!(read.stdout.unwrap().data, b"secret\n");
            let deleted = service
                .delete_sandbox(as_uid(
                    pb::DeleteSandboxRequest { release_request_id: false,
                        id: sandbox.id.clone(),
                    },
                    uid,
                ))
                .await
                .unwrap()
                .into_inner()
                .sandbox
                .unwrap();
            assert_eq!(deleted.state, pb::SandboxState::Deleted as i32);
            // Root acting on a sandbox does not take it over.
            assert_eq!(deleted.owner_uid, 1001);
        }
        assert_eq!(fake.state().removed.len(), 2);
    }

    #[tokio::test]
    async fn root_created_sandboxes_are_not_usable_by_other_callers() {
        let (_fake, _manager, service) = owned_service(Limits::default());
        let sandbox = create_as(&service, 0).await;
        assert_eq!(sandbox.owner_uid, 0);
        assert_eq!(
            service
                .get_sandbox(as_uid(
                    pb::GetSandboxRequest {
                        id: sandbox.id,
                        execution_limit: 0
                    },
                    1001
                ))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::NotFound
        );
        assert!(list_pages_as(&service, 1001, true, 10).await.is_empty());
    }

    #[tokio::test]
    async fn owner_is_recorded_before_the_backend_runs() {
        let (fake, manager, service) = owned_service(Limits::default());
        let gate = FakeGate::default();
        fake.state().create_after_allocation = Some(gate.clone());
        let service = Arc::new(service);
        let creating = tokio::spawn({
            let service = service.clone();
            async move {
                service
                    .create_sandbox(as_uid(pb::CreateSandboxRequest::default(), 1001))
                    .await
            }
        });
        gate.entered().await;
        let row = manager.list(true).unwrap().remove(0);
        assert_eq!(row.state, SandboxState::Creating);
        assert_eq!(row.owner_uid, 1001);
        assert_eq!(
            service
                .delete_sandbox(as_uid(pb::DeleteSandboxRequest { release_request_id: false, id: row.id }, 1002))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::NotFound
        );
        gate.release();
        creating.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn requests_without_kernel_credentials_are_refused_before_any_effect() {
        let (fake, manager, service) = owned_service(Limits::default());
        let sandbox = manager.create(Default::default()).await.unwrap();
        let execution = manager
            .exec(ExecRequest {
                sandbox_id: sandbox.id.clone(),
                argv: vec!["echo".into()],
                stdin: vec![],
                timeout_ms: 0,
            })
            .await
            .unwrap();
        let created = fake.state().created.len();
        let exec_calls = fake.state().exec_calls.len();
        // No extension at all, then the transport's "the kernel gave no answer".
        for peer in [
            None,
            Some(PeerIdentity {
                uid: None,
                lane: ConnectionLane::General,
            }),
        ] {
            fn identified<T>(message: T, peer: Option<PeerIdentity>) -> Request<T> {
                let mut request = Request::new(message);
                if let Some(peer) = peer {
                    request.extensions_mut().insert(peer);
                }
                request
            }
            let errors = [
                service
                    .create_sandbox(identified(pb::CreateSandboxRequest::default(), peer))
                    .await
                    .unwrap_err(),
                service
                    .get_sandbox(identified(
                        pb::GetSandboxRequest {
                            id: sandbox.id.clone(),
                            execution_limit: 0,
                        },
                        peer,
                    ))
                    .await
                    .unwrap_err(),
                service
                    .list_sandboxes(identified(pb::ListSandboxesRequest::default(), peer))
                    .await
                    .unwrap_err(),
                service
                    .exec(identified(
                        pb::ExecRequest {
                            sandbox_id: sandbox.id.clone(),
                            argv: vec!["echo".into()],
                            ..Default::default()
                        },
                        peer,
                    ))
                    .await
                    .unwrap_err(),
                service
                    .delete_sandbox(identified(
                        pb::DeleteSandboxRequest { release_request_id: false,
                            id: sandbox.id.clone(),
                        },
                        peer,
                    ))
                    .await
                    .unwrap_err(),
                service
                    .get_execution(identified(
                        pb::GetExecutionRequest {
                            id: execution.id.clone(),
                        },
                        peer,
                    ))
                    .await
                    .unwrap_err(),
            ];
            for error in errors {
                assert_eq!(error.code(), tonic::Code::Unauthenticated);
            }
            service
                .health(identified(pb::HealthRequest {}, peer))
                .await
                .unwrap();
        }
        assert_eq!(fake.state().created.len(), created);
        assert_eq!(fake.state().exec_calls.len(), exec_calls);
        assert!(fake.state().remove_attempts.is_empty());
        assert_eq!(manager.list(true).unwrap().len(), 1);
        assert_eq!(manager.get(&sandbox.id, 100).unwrap().1.len(), 1);
    }

    #[tokio::test]
    async fn lists_hide_other_owners_before_count_watermark_and_continuation() {
        let (_fake, manager, service) = owned_service(Limits {
            max_list_page_size: 2,
            ..Limits::default()
        });
        // 1002 is interleaved with 1001 and root, and the oldest and newest rows
        // are foreign, so neither end can leak through the watermark or has_more.
        let mut mine = Vec::new();
        let mut all = Vec::new();
        for uid in [
            0, 1002, 1001, 0, 0, 1002, 1001, 0, 1001, 1002, 1001, 1001, 0,
        ] {
            let id = create_as(&service, uid).await.id;
            if uid == 1002 {
                mine.push(id.clone());
            }
            all.push(id);
        }
        mine.reverse();
        all.reverse();
        assert_eq!(list_pages_as(&service, 1002, false, 2).await, mine);
        assert_eq!(list_pages_as(&service, 1002, false, 1).await, mine);
        assert_eq!(list_pages_as(&service, 0, false, 2).await, all);
        assert!(list_pages_as(&service, 1003, true, 2).await.is_empty());

        let first = service
            .list_sandboxes(as_uid(
                pb::ListSandboxesRequest {
                    page_size: Some(2),
                    ..Default::default()
                },
                1002,
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(first.sandboxes.len(), 2);
        // The first page's watermark is the caller's own newest row, not the node's.
        let (upper, last) = parse_page_token(&first.next_page_token, false, 1002).unwrap();
        assert_eq!(
            (upper, last),
            (10, 6),
            "1002's rows hold list positions 2, 6 and 10"
        );

        // Later inserts by anyone stay out of a walk already under way.
        create_as(&service, 1002).await;
        create_as(&service, 1001).await;
        let second = service
            .list_sandboxes(as_uid(
                pb::ListSandboxesRequest {
                    page_size: Some(2),
                    page_token: first.next_page_token.clone(),
                    ..Default::default()
                },
                1002,
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(second.sandboxes.len(), 1);
        assert_eq!(second.sandboxes[0].id, mine[2]);
        // Its last row ends the walk even though an older foreign row remains.
        assert!(second.next_page_token.is_empty());

        // The complete-list form counts only the caller's rows: 1003 has one
        // while the node holds fifteen, and 1002 now exceeds the bound of two.
        create_as(&service, 1003).await;
        let legacy = service
            .list_sandboxes(as_uid(pb::ListSandboxesRequest::default(), 1003))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(legacy.sandboxes.len(), 1);
        assert!(legacy.next_page_token.is_empty());
        for uid in [1002, 0] {
            assert_eq!(
                service
                    .list_sandboxes(as_uid(pb::ListSandboxesRequest::default(), uid))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::ResourceExhausted
            );
        }

        // Deleted history stays private as well.
        let deleted = mine[0].clone();
        manager.delete(&deleted).await.unwrap();
        assert!(
            !list_pages_as(&service, 1002, false, 2)
                .await
                .contains(&deleted)
        );
        assert!(
            list_pages_as(&service, 1002, true, 2)
                .await
                .contains(&deleted)
        );
        assert!(
            !list_pages_as(&service, 1001, true, 2)
                .await
                .contains(&deleted)
        );
        assert!(list_pages_as(&service, 0, true, 2).await.contains(&deleted));
    }

    #[tokio::test]
    async fn list_byte_bound_counts_only_the_callers_rows() {
        let limit = 700;
        let (_fake, _manager, service) = owned_service(Limits {
            max_list_response_bytes: limit,
            ..Limits::default()
        });
        let create = |uid: u32, labels: usize| {
            let service = &service;
            async move {
                service
                    .create_sandbox(as_uid(
                        pb::CreateSandboxRequest { request_id: String::new(),
                            spec: Some(pb::SandboxSpec {
                                labels: (0..labels)
                                    .map(|n| (format!("label{n}"), "x".repeat(200)))
                                    .collect(),
                                ..Default::default()
                            }),
                            expiry: None,
                        },
                        uid,
                    ))
                    .await
                    .unwrap()
                    .into_inner()
                    .sandbox
                    .unwrap()
                    .id
            }
        };
        let mut mine = Vec::new();
        for _ in 0..3 {
            create(1001, 1).await;
            mine.push(create(1002, 1).await);
        }
        mine.reverse();
        let legacy = pb::ListSandboxesRequest::default();
        // Together the rows overflow one response. One owner's alone need pages,
        // and those pages are never spent on the other owner's rows.
        assert_eq!(
            service
                .list_sandboxes(as_uid(legacy.clone(), 0))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );
        let mut token = String::new();
        let mut got = Vec::new();
        let mut pages = 0;
        loop {
            let response = service
                .list_sandboxes(as_uid(
                    pb::ListSandboxesRequest {
                        page_size: Some(100),
                        page_token: token,
                        ..Default::default()
                    },
                    1002,
                ))
                .await
                .unwrap()
                .into_inner();
            assert!(response.encoded_len() <= limit);
            assert!(!response.sandboxes.is_empty());
            pages += 1;
            got.extend(response.sandboxes.into_iter().map(|s| s.id));
            token = response.next_page_token;
            if token.is_empty() {
                break;
            }
        }
        assert_eq!(got, mine);
        assert!(pages > 1, "fixture must overflow one response");

        // A caller's small complete list succeeds beside a foreign row too big
        // to fit, which also must not fail that caller.
        create(1003, 1).await;
        create(1001, 8).await;
        let small = service
            .list_sandboxes(as_uid(legacy, 1003))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(small.sandboxes.len(), 1);
    }

    #[tokio::test]
    async fn page_tokens_do_not_cross_callers_and_forgeries_stay_filtered() {
        let (_fake, _manager, service) = owned_service(Limits::default());
        let mut foreign = Vec::new();
        for uid in [1001, 1002, 1001, 1002, 1001, 1002] {
            let id = create_as(&service, uid).await.id;
            if uid == 1001 {
                foreign.push(id);
            }
        }
        let token_for = async |uid: u32| {
            service
                .list_sandboxes(as_uid(
                    pb::ListSandboxesRequest {
                        page_size: Some(1),
                        ..Default::default()
                    },
                    uid,
                ))
                .await
                .unwrap()
                .into_inner()
                .next_page_token
        };
        let list = async |token: String, uid: u32| {
            service
                .list_sandboxes(as_uid(
                    pb::ListSandboxesRequest {
                        page_size: Some(100),
                        page_token: token,
                        ..Default::default()
                    },
                    uid,
                ))
                .await
        };
        for (issued_to, replayed_by) in [(1001, 1002), (1001, 0), (0, 1001), (0, 1002)] {
            let token = token_for(issued_to).await;
            assert!(!token.is_empty());
            assert_eq!(
                list(token, replayed_by).await.unwrap_err().code(),
                tonic::Code::InvalidArgument,
                "{issued_to} to {replayed_by}"
            );
        }
        // A well-formed token naming the caller grants a position, not rows.
        let forged = page_token(false, 1002, i64::MAX, i64::MAX);
        let rows = list(forged, 1002).await.unwrap().into_inner().sandboxes;
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|s| s.owner_uid == 1002));
        assert!(rows.iter().all(|s| !foreign.contains(&s.id)));
    }

    #[tokio::test]
    async fn ownership_survives_reopening_the_database() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            tmp.path(),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .unwrap();
        let open = || {
            let manager = Arc::new(Manager::new(
                FakeRuntime::default(),
                Store::reopen_after_restart(tmp.path()),
                Limits::default(),
            ));
            (manager.clone(), Service::new(manager))
        };
        let (manager, service) = open();
        let sandbox = create_as(&service, 1001).await;
        let execution = exec_as(&service, &sandbox.id, 1001).await;
        manager.begin_shutdown();
        manager.drain_operations().await;
        drop(service);
        drop(manager);

        let (_manager, service) = open();
        let read = async |uid: u32| {
            service
                .get_sandbox(as_uid(
                    pb::GetSandboxRequest {
                        id: sandbox.id.clone(),
                        execution_limit: 0,
                    },
                    uid,
                ))
                .await
        };
        let get_execution = async |uid: u32| {
            service
                .get_execution(as_uid(
                    pb::GetExecutionRequest {
                        id: execution.id.clone(),
                    },
                    uid,
                ))
                .await
        };
        assert_eq!(
            read(1001)
                .await
                .unwrap()
                .into_inner()
                .sandbox
                .unwrap()
                .owner_uid,
            1001
        );
        read(0).await.unwrap();
        assert_eq!(read(1002).await.unwrap_err().code(), tonic::Code::NotFound);
        get_execution(1001).await.unwrap();
        assert_eq!(
            get_execution(1002).await.unwrap_err().code(),
            tonic::Code::NotFound
        );
        assert_eq!(
            list_pages_as(&service, 1001, false, 1).await,
            std::slice::from_ref(&sandbox.id)
        );
        assert!(list_pages_as(&service, 1002, true, 1).await.is_empty());
    }
}

#[cfg(test)]
mod m1_tests;

#[cfg(test)]
mod m2_tests;
