//! The gRPC service: translates between `kilnd.v1` messages and the manager.

use std::collections::BTreeMap;
use std::sync::Arc;

use kilnd_api::v1 as pb;
use prost::Message;
use tonic::{Request, Response, Status};

use crate::manager::{CreateRequest, Error, ExecRequest, Manager};
use crate::model::{
    Captured, Execution, ExecutionState, Network, Sandbox, SandboxSpec, SandboxState,
};
use crate::runtime::Runtime;

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
        _: Request<pb::HealthRequest>,
    ) -> Result<Response<pb::HealthResponse>, Status> {
        let _permit = self
            .manager
            .admission()
            .try_rpc(true)
            .map_err(|_| Status::resource_exhausted("Health RPC capacity reached"))?;
        let h = self.manager.health().await.map_err(status)?;
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
            admission: Some(admission_pb(h.admission)),
        }))
    }

    async fn create_sandbox(
        &self,
        req: Request<pb::CreateSandboxRequest>,
    ) -> Result<Response<pb::CreateSandboxResponse>, Status> {
        let _permit = self.rpc_permit()?;
        let spec = req.into_inner().spec.unwrap_or_default();
        let sandbox = self
            .manager
            .create(create_request(spec)?)
            .await
            .map_err(status)?;
        Ok(Response::new(pb::CreateSandboxResponse {
            sandbox: Some(sandbox_pb(sandbox)),
        }))
    }

    async fn get_sandbox(
        &self,
        req: Request<pb::GetSandboxRequest>,
    ) -> Result<Response<pb::GetSandboxResponse>, Status> {
        let _permit = self.rpc_permit()?;
        let req = req.into_inner();
        let (sandbox, executions) = self
            .manager
            .get(&req.id, req.execution_limit)
            .map_err(status)?;
        Ok(Response::new(pb::GetSandboxResponse {
            sandbox: Some(sandbox_pb(sandbox)),
            recent_executions: executions.into_iter().map(execution_pb).collect(),
        }))
    }

    async fn list_sandboxes(
        &self,
        req: Request<pb::ListSandboxesRequest>,
    ) -> Result<Response<pb::ListSandboxesResponse>, Status> {
        let _permit = self.rpc_permit()?;
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
            let (upper, last) = parse_page_token(&req.page_token, req.include_deleted)?;
            (Some(upper), Some(last))
        };
        let page = self
            .manager
            .list_page(req.include_deleted, upper, before, count)
            .map_err(status)?;
        if !paginated && page.has_more {
            return Err(pagination_required());
        }
        let mut response = pb::ListSandboxesResponse::default();
        let total = page.rows.len();
        let mut last_returned = None;
        for (index, row) in page.rows.into_iter().enumerate() {
            let seq = row.list_seq;
            response.sandboxes.push(sandbox_pb(row.sandbox));
            let has_more = page.has_more || index + 1 < total;
            response.next_page_token = if paginated && has_more {
                page_token(req.include_deleted, page.upper_seq, seq)
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
        let _permit = self.rpc_permit()?;
        let sandbox = self
            .manager
            .delete(&req.into_inner().id)
            .await
            .map_err(status)?;
        Ok(Response::new(pb::DeleteSandboxResponse {
            sandbox: Some(sandbox_pb(sandbox)),
        }))
    }

    async fn exec(
        &self,
        req: Request<pb::ExecRequest>,
    ) -> Result<Response<pb::ExecResponse>, Status> {
        let received_at = tokio::time::Instant::now();
        let _permit = self.rpc_permit()?;
        let req = req.into_inner();
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
        let _permit = self.rpc_permit()?;
        let execution = self
            .manager
            .execution(&req.into_inner().id)
            .map_err(status)?;
        Ok(Response::new(pb::GetExecutionResponse {
            execution: Some(execution_pb(execution)),
        }))
    }
}

impl<R: Runtime> Service<R> {
    fn rpc_permit(&self) -> Result<tokio::sync::OwnedSemaphorePermit, Status> {
        self.manager
            .admission()
            .try_rpc(false)
            .map_err(|_| Status::resource_exhausted("ordinary RPC capacity reached"))
    }
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
    }
}

fn pagination_required() -> Status {
    Status::resource_exhausted(
        "list exceeds response bounds; request pagination with page_size (or a smaller item is required)",
    )
}

fn page_token(include_deleted: bool, upper: i64, last: i64) -> String {
    format!("v1:{}:{upper:016x}:{last:016x}", u8::from(include_deleted))
}

fn parse_page_token(token: &str, include_deleted: bool) -> Result<(i64, i64), Status> {
    let invalid = || Status::invalid_argument("invalid page_token or include_deleted mismatch");
    if token.len() > 128 || !token.is_ascii() {
        return Err(invalid());
    }
    let parts: Vec<_> = token.split(':').collect();
    if parts.len() != 4 || parts[0] != "v1" || parts[1] != if include_deleted { "1" } else { "0" } {
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
    let (upper, last) = (hex(parts[2])?, hex(parts[3])?);
    if last <= 0 || upper < last {
        return Err(invalid());
    }
    Ok((upper, last))
}

fn status(e: Error) -> Status {
    match e {
        Error::InvalidArgument(m) => Status::invalid_argument(m),
        Error::NotFound(m) => Status::not_found(format!("{m} not found")),
        Error::FailedPrecondition(m) => Status::failed_precondition(m),
        Error::ResourceExhausted(m) => Status::resource_exhausted(m),
        Error::DeadlineExceeded(m) => Status::deadline_exceeded(m),
        Error::ShuttingDown => Status::unavailable("kilnd is shutting down"),
        Error::Backend(m) => Status::internal(m),
        Error::Internal(e) => {
            tracing::error!(error = %format!("{e:#}"), "internal error");
            Status::internal("internal error; see the kilnd log")
        }
    }
}

fn create_request(spec: pb::SandboxSpec) -> Result<CreateRequest, Status> {
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
    };
    pb::Sandbox {
        id: s.id,
        state: state.into(),
        spec: Some(spec_pb(s.spec)),
        backend: s.backend,
        backend_id: s.backend_id.unwrap_or_default(),
        created_at_unix_ms: s.created_at_ms,
        updated_at_unix_ms: s.updated_at_ms,
        deleted_at_unix_ms: s.deleted_at_ms.unwrap_or(0),
        failure_reason: s.failure_reason.unwrap_or_default(),
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
                .create_sandbox(Request::new(pb::CreateSandboxRequest {
                    spec: Some(spec),
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
        for argv in [vec![], vec![String::new()], vec!["echo".into(), "a\0b".into()]] {
            let error = service
                .exec(Request::new(pb::ExecRequest {
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
                    .create_sandbox(Request::new(pb::CreateSandboxRequest::default()))
                    .await
            }
        });
        gate.entered().await;
        let error = service
            .get_sandbox(Request::new(pb::GetSandboxRequest::default()))
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
            .get_sandbox(Request::new(pb::GetSandboxRequest::default()))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert_eq!(manager.admission().snapshot().rpcs.current, 0);
        gate.release();
        manager.begin_shutdown();
        manager.drain_operations().await;
        service
            .list_sandboxes(Request::new(pb::ListSandboxesRequest::default()))
            .await
            .unwrap();
        assert_eq!(manager.admission().snapshot().rpcs.current, 0);
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
        let valid = "v1:0:000000000000000f:0000000000000001";
        assert_eq!(parse_page_token(valid, false).unwrap(), (15, 1));
        assert!(parse_page_token(valid, true).is_err());
        for invalid in [
            "",
            "v2:0:000000000000000f:0000000000000001",
            "v1:2:000000000000000f:0000000000000001",
            "v1:00:000000000000000f:0000000000000001",
            "v1:0:000000000000000F:0000000000000001",
            "v1:0:f:1",
            "v1:0:0000000000000000:0000000000000000",
            "v1:0:0000000000000001:0000000000000002",
            "v1:0:8000000000000000:0000000000000001",
            "v1:0:000000000000000f:0000000000000001:",
            "v1:0:000000000000000f:0000000000000001\n",
            "v1:0:000000000000000f:000000000000000é",
        ] {
            assert_eq!(
                parse_page_token(invalid, false).unwrap_err().code(),
                tonic::Code::InvalidArgument,
                "{invalid:?}"
            );
        }
        assert!(parse_page_token(&"a".repeat(129), false).is_err());
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
                .list_sandboxes(Request::new(pb::ListSandboxesRequest::default()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );
        let mut token = String::new();
        let mut got = Vec::new();
        loop {
            let response = service
                .list_sandboxes(Request::new(pb::ListSandboxesRequest {
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
                    .list_sandboxes(Request::new(pb::ListSandboxesRequest {
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
                page_token: page_token(false, 5, 2),
                ..Default::default()
            },
        ] {
            assert_eq!(
                service
                    .list_sandboxes(Request::new(request))
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
                .list_sandboxes(Request::new(pb::ListSandboxesRequest::default()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );
        let mut token = String::new();
        let mut got = Vec::new();
        loop {
            let response = service
                .list_sandboxes(Request::new(pb::ListSandboxesRequest {
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
                .list_sandboxes(Request::new(pb::ListSandboxesRequest {
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
            .exec(Request::new(pb::ExecRequest {
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
                Request::new(pb::CreateSandboxRequest { spec: None }),
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
                    Request::new(pb::ExecRequest {
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
}
