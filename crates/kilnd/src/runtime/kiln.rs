//! Unprivileged kiln runtime adapter: only the private root helper runs kiln.
use super::{BackendSandbox, CreateFailure, ExecOutcome, ExecSpec, Runtime, RuntimeError};
use crate::helper::{
    Client,
    protocol::{KilnRequest, Response},
};
use crate::model::SandboxSpec;
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub struct KilnRuntime {
    client: Client,
}
impl KilnRuntime {
    pub fn new(helper_socket: PathBuf) -> Self {
        Self {
            client: Client {
                path: helper_socket,
                expected_uid: 0,
            },
        }
    }
    async fn call(
        &self,
        op: KilnRequest,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<Response, RuntimeError> {
        match self.client.call(op, deadline, cancel).await? {
            Response::Error { error, .. } => Err(error.into()),
            reply => Ok(reply),
        }
    }
}
fn unexpected() -> RuntimeError {
    RuntimeError::Backend("unexpected root helper response".into())
}
impl Runtime for KilnRuntime {
    fn name(&self) -> &'static str {
        "kiln"
    }
    async fn version(
        &self,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<String, RuntimeError> {
        match self
            .call(KilnRequest::Capabilities { id: None }, deadline, cancel)
            .await?
        {
            Response::Version(s) => Ok(s),
            _ => Err(unexpected()),
        }
    }
    async fn validate_sandbox(
        &self,
        id: &str,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), RuntimeError> {
        match self
            .call(
                KilnRequest::Capabilities {
                    id: Some(id.into()),
                },
                deadline,
                cancel,
            )
            .await?
        {
            Response::Validated => Ok(()),
            _ => Err(unexpected()),
        }
    }
    async fn create(&self, spec: &SandboxSpec) -> Result<String, CreateFailure> {
        match self
            .client
            .call(
                KilnRequest::Create { spec: spec.clone() },
                Instant::now() + Duration::from_secs(120),
                &CancellationToken::new(),
            )
            .await?
        {
            Response::Created(id) => Ok(id),
            Response::Error {
                error,
                definitely_not_created: true,
            } => Err(CreateFailure::definitely_not_created(error.into())),
            Response::Error { error, .. } => Err(RuntimeError::from(error).into()),
            _ => Err(unexpected().into()),
        }
    }
    async fn exec(&self, id: &str, spec: &ExecSpec<'_>, cancel: &CancellationToken) -> ExecOutcome {
        self.client.exec(id, spec, cancel).await
    }
    async fn remove(&self, id: &str) -> Result<(), RuntimeError> {
        match self
            .call(
                KilnRequest::Rm { id: id.into() },
                Instant::now() + Duration::from_secs(120),
                &CancellationToken::new(),
            )
            .await?
        {
            Response::Removed => Ok(()),
            _ => Err(unexpected()),
        }
    }
    async fn list(&self) -> Result<Vec<BackendSandbox>, RuntimeError> {
        match self
            .call(
                KilnRequest::Ls,
                Instant::now() + Duration::from_secs(30),
                &CancellationToken::new(),
            )
            .await?
        {
            Response::Listed(rows) => Ok(rows.into_iter().map(Into::into).collect()),
            _ => Err(unexpected()),
        }
    }
    async fn gc(&self, ids: &[String]) -> Result<Vec<String>, RuntimeError> {
        let mut removed = Vec::new();
        for chunk in ids.chunks(crate::helper::protocol::MAX_GC_IDS) {
            match self
                .call(
                    KilnRequest::Gc {
                        ids: chunk.to_vec(),
                    },
                    Instant::now() + Duration::from_secs(30),
                    &CancellationToken::new(),
                )
                .await?
            {
                Response::Collected(ids) => removed.extend(ids),
                _ => return Err(unexpected()),
            }
        }
        Ok(removed)
    }
}
