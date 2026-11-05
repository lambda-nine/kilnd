//! Unprivileged kiln runtime adapter: only the private root helper runs kiln.
use super::{
    AbsenceReceipt, AllocationObservation, BackendInventory, BackendSandbox, CreateContext,
    CreateFailure, CreatedSandbox, ExecOutcome, ExecSpec, ExecutionContext, LegacyAbsence,
    LegacyProof, PrepareContext, PreparedCreate, RemoveTarget, Runtime, RuntimeCapabilities,
    RuntimeError, RuntimeReceipt,
    kiln_direct::{KILN_PROFILE, legacy_capabilities, legacy_inventory, unsupported_token},
};
use crate::helper::{
    Client,
    protocol::{KilnRequest, Response},
};
use crate::model::{Digest, SandboxSpec};
use std::path::PathBuf;
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
    fn capabilities(&self) -> RuntimeCapabilities {
        legacy_capabilities()
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
    async fn prepare(
        &self,
        _context: &PrepareContext,
        spec: &SandboxSpec,
        _deadline: Instant,
        _cancel: &CancellationToken,
    ) -> Result<PreparedCreate, RuntimeError> {
        Ok(PreparedCreate::legacy(spec.clone(), KILN_PROFILE))
    }
    async fn create(
        &self,
        _context: &CreateContext,
        prepared: &PreparedCreate,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<CreatedSandbox, CreateFailure> {
        match self
            .client
            .call(
                KilnRequest::Create {
                    spec: prepared.spec().clone(),
                },
                deadline,
                cancel,
            )
            .await?
        {
            Response::Created(backend_id) => Ok(CreatedSandbox {
                backend_id,
                receipt: RuntimeReceipt::Legacy,
            }),
            Response::Error {
                error,
                definitely_not_created: true,
            } => Err(CreateFailure::definitely_not_created(error.into())),
            Response::Error { error, .. } => Err(RuntimeError::from(error).into()),
            _ => Err(unexpected().into()),
        }
    }
    async fn inspect_allocation(
        &self,
        _context: &CreateContext,
        _prepared_digest: &Digest,
        _deadline: Instant,
        _cancel: &CancellationToken,
    ) -> Result<AllocationObservation, RuntimeError> {
        Ok(AllocationObservation::Unsupported)
    }
    async fn fence_absent(
        &self,
        _context: &CreateContext,
        _prepared_digest: &Digest,
        _deadline: Instant,
        _cancel: &CancellationToken,
    ) -> Result<AbsenceReceipt, RuntimeError> {
        Err(unsupported_token())
    }
    async fn exec(
        &self,
        id: &str,
        _execution: &ExecutionContext,
        spec: &ExecSpec<'_>,
        cancel: &CancellationToken,
    ) -> ExecOutcome {
        self.client.exec(id, spec, cancel).await
    }
    async fn remove(
        &self,
        target: RemoveTarget<'_>,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<AbsenceReceipt, RuntimeError> {
        // B7: a fenced binding is refused before any kiln call.
        let id = target.legacy()?;
        match self
            .call(KilnRequest::Rm { id: id.into() }, deadline, cancel)
            .await?
        {
            Response::Removed => Ok(AbsenceReceipt::Legacy(LegacyAbsence {
                backend_id: id.into(),
                proof: LegacyProof::StrictRemoval,
            })),
            _ => Err(unexpected()),
        }
    }
    async fn list(
        &self,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<BackendInventory, RuntimeError> {
        match self.call(KilnRequest::Ls, deadline, cancel).await? {
            Response::Listed(rows) => {
                let rows: Vec<BackendSandbox> = rows.into_iter().map(Into::into).collect();
                Ok(legacy_inventory(rows))
            }
            _ => Err(unexpected()),
        }
    }
    async fn gc(
        &self,
        targets: &[RemoveTarget<'_>],
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<Vec<AbsenceReceipt>, RuntimeError> {
        // B7: one fenced binding refuses the whole call before any kiln call.
        let ids = super::legacy_targets(targets)?;
        let ids = ids.as_slice();
        let mut removed = Vec::new();
        for chunk in ids.chunks(crate::helper::protocol::MAX_GC_IDS) {
            match self
                .call(
                    KilnRequest::Gc {
                        ids: chunk.to_vec(),
                    },
                    deadline,
                    cancel,
                )
                .await?
            {
                Response::Collected(ids) => removed.extend(ids.into_iter().map(|backend_id| {
                    AbsenceReceipt::Legacy(LegacyAbsence {
                        backend_id,
                        proof: LegacyProof::ScopedGc,
                    })
                })),
                _ => return Err(unexpected()),
            }
        }
        Ok(removed)
    }
}
