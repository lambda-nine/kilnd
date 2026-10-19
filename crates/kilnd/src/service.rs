//! The gRPC service: translates between `kilnd.v1` messages and the manager.

use std::collections::BTreeMap;
use std::sync::Arc;

use kilnd_api::v1 as pb;
use tonic::{Request, Response, Status};

use crate::manager::{CreateRequest, Error, ExecRequest, Manager};
use crate::model::{Captured, Execution, ExecutionState, Network, Sandbox, SandboxSpec, SandboxState};
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
    async fn health(&self, _: Request<pb::HealthRequest>) -> Result<Response<pb::HealthResponse>, Status> {
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
        }))
    }

    async fn create_sandbox(
        &self,
        req: Request<pb::CreateSandboxRequest>,
    ) -> Result<Response<pb::CreateSandboxResponse>, Status> {
        let spec = req.into_inner().spec.unwrap_or_default();
        let sandbox = self.manager.create(create_request(spec)?).await.map_err(status)?;
        Ok(Response::new(pb::CreateSandboxResponse { sandbox: Some(sandbox_pb(sandbox)) }))
    }

    async fn get_sandbox(&self, req: Request<pb::GetSandboxRequest>) -> Result<Response<pb::GetSandboxResponse>, Status> {
        let req = req.into_inner();
        let (sandbox, executions) = self.manager.get(&req.id, req.execution_limit).map_err(status)?;
        Ok(Response::new(pb::GetSandboxResponse {
            sandbox: Some(sandbox_pb(sandbox)),
            recent_executions: executions.into_iter().map(execution_pb).collect(),
        }))
    }

    async fn list_sandboxes(
        &self,
        req: Request<pb::ListSandboxesRequest>,
    ) -> Result<Response<pb::ListSandboxesResponse>, Status> {
        let sandboxes = self.manager.list(req.into_inner().include_deleted).map_err(status)?;
        Ok(Response::new(pb::ListSandboxesResponse { sandboxes: sandboxes.into_iter().map(sandbox_pb).collect() }))
    }

    async fn delete_sandbox(
        &self,
        req: Request<pb::DeleteSandboxRequest>,
    ) -> Result<Response<pb::DeleteSandboxResponse>, Status> {
        let sandbox = self.manager.delete(&req.into_inner().id).await.map_err(status)?;
        Ok(Response::new(pb::DeleteSandboxResponse { sandbox: Some(sandbox_pb(sandbox)) }))
    }

    async fn exec(&self, req: Request<pb::ExecRequest>) -> Result<Response<pb::ExecResponse>, Status> {
        let req = req.into_inner();
        let execution = self
            .manager
            .exec(ExecRequest { sandbox_id: req.sandbox_id, argv: req.argv, stdin: req.stdin, timeout_ms: req.timeout_ms })
            .await
            .map_err(status)?;
        Ok(Response::new(pb::ExecResponse { execution: Some(execution_pb(execution)) }))
    }

    async fn get_execution(
        &self,
        req: Request<pb::GetExecutionRequest>,
    ) -> Result<Response<pb::GetExecutionResponse>, Status> {
        let execution = self.manager.execution(&req.into_inner().id).map_err(status)?;
        Ok(Response::new(pb::GetExecutionResponse { execution: Some(execution_pb(execution)) }))
    }
}

fn status(e: Error) -> Status {
    match e {
        Error::InvalidArgument(m) => Status::invalid_argument(m),
        Error::NotFound(m) => Status::not_found(format!("{m} not found")),
        Error::FailedPrecondition(m) => Status::failed_precondition(m),
        Error::ResourceExhausted(m) => Status::resource_exhausted(m),
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
    let mode = pb::NetworkMode::try_from(net.mode).map_err(|_| Status::invalid_argument("unknown network mode"))?;
    let network = match mode {
        pb::NetworkMode::Unspecified | pb::NetworkMode::None if net.allow.is_empty() => Network::None,
        pb::NetworkMode::Full if net.allow.is_empty() => Network::Full,
        pb::NetworkMode::Allowlist => Network::Allow(net.allow),
        _ => return Err(Status::invalid_argument("network.allow is only valid with NETWORK_MODE_ALLOWLIST")),
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
        network: Some(pb::NetworkPolicy { mode: mode.into(), allow }),
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
    pb::Output { truncated: c.truncated(), total_bytes: c.total_bytes, data: c.data }
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
        exit_code: e.exit_code,
        failure_reason: e.failure_reason.unwrap_or_default(),
        started_at_unix_ms: e.started_at_ms,
        finished_at_unix_ms: e.finished_at_ms.unwrap_or(0),
        timeout_ms: e.timeout_ms,
        stdin_bytes: e.stdin_bytes,
        stdout: Some(output_pb(e.stdout)),
        stderr: Some(output_pb(e.stderr)),
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
    async fn dropping_create_handler_does_not_drop_owned_operation() {
        let fake = FakeRuntime::default();
        let gate = FakeGate::default();
        fake.state().create_after_allocation = Some(gate.clone());
        let manager = Arc::new(Manager::new(fake.clone(), Store::open_in_memory().unwrap(), Limits::default()));
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
        assert_eq!(row.backend_id.as_ref(), fake.state().sandboxes.keys().next());
    }
}
