//! The unprivileged typed Firecracker client. It holds no privilege, opens no ledger
//! and has no direct Linux fallback. Nothing in `main.rs` selects this backend: B7
//! alone may enable it. B3's helper cannot publish READY, so `create` here can only
//! end in a matching absence fence or a charged ambiguous failure.
use super::{
    AbsenceReceipt, AccountingAuthority, AllocationObservation, BackendInventory, BackendRecord,
    BackendStatus, CreateContext, CreateFailure, CreatedSandbox, ExecOutcome, ExecSpec,
    ExecutionContext, FencedAbsence, PreparedCreate, Runtime, RuntimeCapabilities, RuntimeError,
};
use crate::firecracker::{canonical, offline_768_v1_reservation, strict_json};
use crate::helper::firecracker::journal::AccountingSnapshot;
use crate::helper::protocol::{
    AccountingReply, CreateReply, FIRECRACKER_GROUP_VERSION, FenceReply, FirecrackerOperation,
    FirecrackerRequest, FirecrackerResponse, GroupError, GroupErrorKind, InspectReply, ListStatus,
    PreparedReply, WireBytes,
};
use crate::helper::{AttachedConnection, Client};
use crate::model::{
    CleanupEvidence, Digest, Id128, Network, RuntimeDiagnostic, RuntimeErrorKind, RuntimeStage,
    SandboxDisposition, SandboxSpec,
};
use std::path::PathBuf;
use std::sync::Mutex;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

struct Attachment {
    epoch: Id128,
    /// Dropping this connection is the detach; the helper retires its epoch.
    _connection: AttachedConnection,
}

pub struct FirecrackerRuntime {
    client: Client,
    instance_id: Id128,
    database_uuid: Id128,
    attachment: tokio::sync::Mutex<Option<Attachment>>,
    node_id: Mutex<Option<Id128>>,
}

fn group_failure(error: GroupError) -> RuntimeError {
    let text = format!("Firecracker helper: {}", error.message);
    match error.kind {
        GroupErrorKind::Incompatible
        | GroupErrorKind::Disabled
        | GroupErrorKind::OwnershipConflict
        | GroupErrorKind::Unauthorized => RuntimeError::Incompatible(text),
        _ => RuntimeError::Backend(text),
    }
}

fn unexpected() -> RuntimeError {
    RuntimeError::Backend("unexpected Firecracker helper response".into())
}

/// Every prepared field is reconstructed from verified bytes; nothing is believed
/// because the helper said it. A fixture schema or any mismatched field fails here.
fn verify_prepared(
    context: &CreateContext,
    spec: &SandboxSpec,
    reply: PreparedReply,
) -> Result<PreparedCreate, RuntimeError> {
    let invalid = |why: &str| RuntimeError::Backend(format!("prepared plan refused: {why}"));
    if reply.plan_version != crate::helper::firecracker::config::PLAN_VERSION {
        return Err(invalid("plan version"));
    }
    if Digest::of(&reply.plan.0) != reply.plan_digest {
        return Err(invalid("plan digest"));
    }
    let document = strict_json(&reply.plan.0).map_err(|e| invalid(&e))?;
    if canonical(&document).map_err(|e| invalid(&e))? != reply.plan.0 {
        return Err(invalid("plan is not canonical"));
    }
    if document["schema"] != crate::helper::firecracker::config::PLAN_SCHEMA {
        return Err(invalid("plan schema"));
    }
    if document["host_spec"] != serde_json::to_value(spec).map_err(|e| invalid(&e.to_string()))? {
        return Err(invalid("plan does not bind the requested spec"));
    }
    let substitutions = &document["substitutions"];
    if substitutions["instance_id"] != context.instance_id.to_string()
        || substitutions["allocation_id"] != context.allocation_id.to_string()
        || substitutions["sandbox_id"] != context.sandbox_id.as_str()
    {
        return Err(invalid("plan does not bind this token"));
    }
    if document["profile"] != reply.profile.as_str()
        || document["manifest_sha256"] != reply.manifest_sha256.to_string()
        || document["node_id"] != reply.node_id.to_string()
    {
        return Err(invalid("plan metadata differs from the reply"));
    }
    if offline_768_v1_reservation(spec).map_err(|e| invalid(&e))? != reply.reservation {
        return Err(invalid("reservation differs from the versioned formula"));
    }
    let prepared = PreparedCreate::fenced(
        spec.clone(),
        reply.reservation,
        reply.plan_version,
        reply.plan.0,
        &reply.profile,
        reply.manifest_sha256,
        reply.node_id,
    )?;
    if prepared.host_spec_sha256() != reply.host_spec_sha256
        || prepared.guest_exec_spec_sha256() != reply.guest_exec_spec_sha256
        || prepared.plan_digest() != reply.plan_digest
    {
        return Err(invalid("spec digests differ"));
    }
    Ok(prepared)
}

#[cfg(test)]
pub(crate) fn test_verify_prepared(
    context: &CreateContext,
    spec: &SandboxSpec,
    reply: PreparedReply,
) -> Result<PreparedCreate, RuntimeError> {
    verify_prepared(context, spec, reply)
}

fn decode_fence(
    bytes: &[u8],
    context: &CreateContext,
    digest: &Digest,
) -> Result<FencedAbsence, RuntimeError> {
    let receipt = FencedAbsence::decode(bytes)?;
    if receipt.instance_id() != context.instance_id
        || receipt.allocation_id() != context.allocation_id
        || &receipt.plan_digest() != digest
    {
        return Err(RuntimeError::Backend(
            "absence receipt does not match this token".into(),
        ));
    }
    Ok(receipt)
}

impl FirecrackerRuntime {
    pub fn new(helper_socket: PathBuf, instance_id: Id128, database_uuid: Id128) -> Self {
        Self {
            client: Client {
                path: helper_socket,
                expected_uid: 0,
            },
            instance_id,
            database_uuid,
            attachment: tokio::sync::Mutex::new(None),
            node_id: Mutex::new(None),
        }
    }

    /// For tests that run the helper unprivileged, with the real peer check.
    #[cfg(test)]
    pub(crate) fn with_helper_uid(
        helper_socket: PathBuf,
        expected_uid: u32,
        instance_id: Id128,
        database_uuid: Id128,
    ) -> Self {
        let mut runtime = Self::new(helper_socket, instance_id, database_uuid);
        runtime.client.expected_uid = expected_uid;
        runtime
    }

    /// Drops the live attachment, as a daemon restart would.
    #[cfg(test)]
    pub(crate) async fn test_reattach(&self) {
        self.drop_attachment().await;
    }

    #[cfg(test)]
    pub(crate) fn test_instance(&self) -> Id128 {
        self.instance_id
    }

    /// The attachment's epoch, for tests that build raw frames.
    #[cfg(test)]
    pub(crate) async fn test_epoch(&self, deadline: Instant) -> Result<Id128, RuntimeError> {
        self.epoch(deadline).await
    }

    /// Attaches as this process, the same proof a serving daemon would have to give, and
    /// answers the node that accepted it.
    pub async fn prove_attachment(&self, deadline: Instant) -> Result<Id128, RuntimeError> {
        self.epoch(deadline).await?;
        self.node_id
            .lock()
            .unwrap()
            .ok_or_else(|| RuntimeError::Backend("attached with no node ID".into()))
    }

    /// The live epoch, attaching first if needed. Only one live holder may have this
    /// namespace, and a stale connection never revives: the helper issued its epoch.
    async fn epoch(&self, deadline: Instant) -> Result<Id128, RuntimeError> {
        let mut attachment = self.attachment.lock().await;
        if let Some(existing) = attachment.as_ref() {
            return Ok(existing.epoch);
        }
        let (response, connection) = self
            .client
            .attach(
                FirecrackerRequest {
                    group_version: FIRECRACKER_GROUP_VERSION,
                    instance_id: self.instance_id,
                    connection_epoch: None,
                    operation: FirecrackerOperation::AttachInstance {
                        database_uuid: self.database_uuid,
                    },
                },
                deadline,
            )
            .await?;
        match response {
            FirecrackerResponse::Attached {
                node_id,
                connection_epoch,
                ..
            } => {
                *self.node_id.lock().unwrap() = Some(node_id);
                *attachment = Some(Attachment {
                    epoch: connection_epoch,
                    _connection: connection,
                });
                Ok(connection_epoch)
            }
            FirecrackerResponse::Error(error) => Err(group_failure(error)),
            _ => Err(unexpected()),
        }
    }

    /// Drops the attachment after the helper said its epoch is stale, so the next
    /// call attaches anew and gets a helper-issued replacement.
    async fn drop_attachment(&self) {
        self.attachment.lock().await.take();
    }

    async fn call(
        &self,
        operation: FirecrackerOperation,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<FirecrackerResponse, RuntimeError> {
        let epoch = self.epoch(deadline).await?;
        let response = self
            .client
            .firecracker(
                FirecrackerRequest {
                    group_version: FIRECRACKER_GROUP_VERSION,
                    instance_id: self.instance_id,
                    connection_epoch: Some(epoch),
                    operation,
                },
                deadline,
                cancel,
            )
            .await?;
        if let FirecrackerResponse::Error(error) = &response
            && error.kind == GroupErrorKind::StaleEpoch
        {
            self.drop_attachment().await;
        }
        Ok(response)
    }

    /// Node-global totals with freshness, for Health. Unavailable never reads as zero.
    pub async fn node_accounting(
        &self,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<AccountingSnapshot, RuntimeError> {
        match self
            .call(FirecrackerOperation::Accounting, deadline, cancel)
            .await?
        {
            FirecrackerResponse::Accounting(AccountingReply::Fresh(snapshot)) => Ok(*snapshot),
            FirecrackerResponse::Accounting(AccountingReply::Unknown { reason }) => Err(
                RuntimeError::Backend(format!("node accounting unavailable: {reason}")),
            ),
            FirecrackerResponse::Error(error) => Err(group_failure(error)),
            _ => Err(unexpected()),
        }
    }

    fn unsupported(&self, what: &str) -> RuntimeError {
        RuntimeError::Unsupported(format!(
            "{what} needs the VM lifecycle, which this build of the backend does not have"
        ))
    }
}

impl Runtime for FirecrackerRuntime {
    fn name(&self) -> &'static str {
        "firecracker"
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities {
            network_modes: vec![Network::None],
            interruption_preserves_session: false,
            checkpoint: false,
            accounting: AccountingAuthority::Node,
        }
    }

    async fn version(
        &self,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<String, RuntimeError> {
        match self
            .call(FirecrackerOperation::Capabilities, deadline, cancel)
            .await?
        {
            FirecrackerResponse::Capabilities(reply) if reply.enabled => {
                Ok(format!("kilnd-helper {}", reply.helper_version))
            }
            FirecrackerResponse::Capabilities(_) => Err(RuntimeError::Incompatible(
                "the helper has the Firecracker backend disabled".into(),
            )),
            FirecrackerResponse::Error(error) => Err(group_failure(error)),
            _ => Err(unexpected()),
        }
    }

    async fn prepare(
        &self,
        context: &CreateContext,
        spec: &SandboxSpec,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<PreparedCreate, RuntimeError> {
        match self
            .call(
                FirecrackerOperation::Preflight {
                    allocation_id: context.allocation_id,
                    sandbox_id: context.sandbox_id.clone(),
                    profile: "offline-768-v1".into(),
                    spec: spec.clone(),
                },
                deadline,
                cancel,
            )
            .await?
        {
            FirecrackerResponse::Prepared(reply) => verify_prepared(context, spec, *reply),
            FirecrackerResponse::Error(error) => Err(group_failure(error)),
            _ => Err(unexpected()),
        }
    }

    async fn create(
        &self,
        context: &CreateContext,
        prepared: &PreparedCreate,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<CreatedSandbox, CreateFailure> {
        let plan_digest = prepared.plan_digest();
        let response = self
            .call(
                FirecrackerOperation::Create {
                    allocation_id: context.allocation_id,
                    sandbox_id: context.sandbox_id.clone(),
                    plan: WireBytes(prepared.backend_plan().to_vec()),
                    plan_digest,
                },
                deadline,
                cancel,
            )
            .await
            .map_err(CreateFailure::from)?;
        match response {
            FirecrackerResponse::Create(CreateReply::Absent { receipt }) => {
                let receipt =
                    decode_fence(&receipt.0, context, &plan_digest).map_err(CreateFailure::from)?;
                Err(CreateFailure::absent_fenced(
                    receipt,
                    RuntimeError::Backend("this allocation token is permanently fenced".into()),
                ))
            }
            // Accepted is a durable charge, never readiness: B3 has no READY.
            FirecrackerResponse::Create(CreateReply::Accepted { phase, .. }) => {
                Err(RuntimeError::Backend(format!(
                    "allocation accepted at {phase}; no VM launch exists in this build"
                ))
                .into())
            }
            FirecrackerResponse::Create(CreateReply::Ambiguous { class, message }) => {
                Err(RuntimeError::Backend(format!("create rejected ({class:?}): {message}")).into())
            }
            FirecrackerResponse::Error(error) => Err(group_failure(error).into()),
            _ => Err(unexpected().into()),
        }
    }

    async fn inspect_allocation(
        &self,
        context: &CreateContext,
        prepared_digest: &Digest,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<AllocationObservation, RuntimeError> {
        match self
            .call(
                FirecrackerOperation::Inspect {
                    allocation_id: context.allocation_id,
                },
                deadline,
                cancel,
            )
            .await?
        {
            FirecrackerResponse::Inspect(InspectReply::AbsentFenced { receipt }) => {
                Ok(AllocationObservation::AbsentFenced(decode_fence(
                    &receipt.0,
                    context,
                    prepared_digest,
                )?))
            }
            FirecrackerResponse::Inspect(InspectReply::StoppedWithResources { generation }) => {
                Ok(AllocationObservation::StoppedWithResources {
                    helper_generation: generation,
                })
            }
            // Without READY, a busy preparation is as unknown as a stale answer: the
            // manager then fences, which refuses until proof really exists.
            FirecrackerResponse::Inspect(InspectReply::PresentBusy { phase, .. }) => {
                Ok(AllocationObservation::Unknown {
                    reason: format!("allocation is at {phase}"),
                })
            }
            FirecrackerResponse::Inspect(InspectReply::Unknown { reason }) => {
                Ok(AllocationObservation::Unknown { reason })
            }
            FirecrackerResponse::Inspect(InspectReply::Incompatible { message }) => {
                Err(RuntimeError::Incompatible(message))
            }
            FirecrackerResponse::Error(error) => Err(group_failure(error)),
            _ => Err(unexpected()),
        }
    }

    async fn fence_absent(
        &self,
        context: &CreateContext,
        prepared_digest: &Digest,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<AbsenceReceipt, RuntimeError> {
        match self
            .call(
                FirecrackerOperation::FenceAbsent {
                    allocation_id: context.allocation_id,
                    sandbox_id: context.sandbox_id.clone(),
                    plan_digest: *prepared_digest,
                },
                deadline,
                cancel,
            )
            .await?
        {
            FirecrackerResponse::Fence(FenceReply::Absent { receipt }) => Ok(
                AbsenceReceipt::Fenced(decode_fence(&receipt.0, context, prepared_digest)?),
            ),
            FirecrackerResponse::Fence(FenceReply::Ambiguous { class, message }) => Err(
                RuntimeError::Backend(format!("allocation stays charged ({class:?}): {message}")),
            ),
            FirecrackerResponse::Error(error) => Err(group_failure(error)),
            _ => Err(unexpected()),
        }
    }

    async fn validate_sandbox(
        &self,
        _id: &str,
        _deadline: Instant,
        _cancel: &CancellationToken,
    ) -> Result<(), RuntimeError> {
        Err(self.unsupported("sandbox validation"))
    }

    async fn exec(
        &self,
        _id: &str,
        _execution: &ExecutionContext,
        _spec: &ExecSpec<'_>,
        _cancel: &CancellationToken,
    ) -> ExecOutcome {
        // No Exec was sent, so no command can have started. READY cannot exist in this
        // build; a caller reaching here has an impossible row and it stays quarantined.
        ExecOutcome {
            finish: Err(RuntimeDiagnostic::new(
                RuntimeErrorKind::Unavailable,
                RuntimeStage::Validate,
                "this build of the Firecracker backend has no execution path",
            )),
            command_status: None,
            stdout: crate::model::Captured::known_empty(),
            stderr: crate::model::Captured::known_empty(),
            disposition: SandboxDisposition::Quarantined,
            cleanup: CleanupEvidence::NoChildStarted,
        }
    }

    async fn remove(
        &self,
        _id: &str,
        _deadline: Instant,
        _cancel: &CancellationToken,
    ) -> Result<AbsenceReceipt, RuntimeError> {
        Err(self.unsupported("removal"))
    }

    async fn list(
        &self,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<BackendInventory, RuntimeError> {
        match self
            .call(FirecrackerOperation::List, deadline, cancel)
            .await?
        {
            FirecrackerResponse::List(reply) => Ok(BackendInventory {
                generation: reply.generation,
                complete: reply.complete,
                records: reply
                    .records
                    .into_iter()
                    .map(|record| BackendRecord {
                        id: format!("fc-{}", record.allocation_id),
                        status: match record.status {
                            ListStatus::Busy => BackendStatus::Busy,
                            ListStatus::StoppedWithResources => BackendStatus::StoppedWithResources,
                            ListStatus::Stale => BackendStatus::Stale,
                            ListStatus::Quarantined => BackendStatus::Quarantined,
                            ListStatus::Unknown => BackendStatus::Unknown,
                        },
                        allocation_id: Some(record.allocation_id),
                        plan_digest: Some(record.plan_digest),
                        generation: record.generation,
                    })
                    .collect(),
            }),
            FirecrackerResponse::Error(error) => Err(group_failure(error)),
            _ => Err(unexpected()),
        }
    }

    async fn gc(
        &self,
        ids: &[String],
        _deadline: Instant,
        _cancel: &CancellationToken,
    ) -> Result<Vec<AbsenceReceipt>, RuntimeError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        Err(self.unsupported("scoped collection"))
    }
}
