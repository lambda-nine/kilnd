//! The unprivileged typed Firecracker client. It holds no privilege, opens no ledger
//! and has no direct Linux fallback. `main.rs` selects it only for the isolated test
//! deployment (B6, `deploy/firecracker-test/`); B7 alone may enable it in production,
//! and until then the production helper serves no profile, so every Preflight there
//! is a C0 refusal.
//!
//! B6 wires the whole public path. `create` sends Create, which the helper answers
//! once C2 is durable, then follows Inspect until the journaled READY (C6); `exec`,
//! `validate_sandbox`, `remove` and `gc` are the helper's typed operations by exact
//! allocation token. The boot and inner sandbox a READY row was published with are
//! remembered per allocation and always re-read from the helper's journal when
//! missing, so a stale guess is never sent: the helper compares them with its own.
use super::{
    AbsenceReceipt, AccountingAuthority, AllocationObservation, BackendInventory, BackendRecord,
    BackendStatus, CreateContext, CreateFailure, CreatedSandbox, EvidenceRegime, ExecOutcome,
    ExecSpec, ExecutionContext, FencedAbsence, PreparedCreate, ReadyReceipt, Runtime,
    RuntimeCapabilities, RuntimeError, RuntimeReceipt,
};
use crate::firecracker::{canonical, offline_768_v1_reservation, strict_json};
use crate::helper::firecracker::journal::AccountingSnapshot;
use crate::helper::protocol::{
    AccountingReply, CreateReply, FIRECRACKER_GROUP_VERSION, FenceReply, FirecrackerOperation,
    FirecrackerRequest, FirecrackerResponse, GcOutcome, GroupError, GroupErrorKind, InspectReply,
    ListStatus, MAX_FIRECRACKER_GC_IDS, PreparedReply, ValidateReply, WireBytes,
};
use crate::helper::{AttachedConnection, Client};
use crate::model::{Digest, Id128, Network, SandboxSpec};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

struct Attachment {
    epoch: Id128,
    /// Dropping this connection is the detach; the helper retires its epoch.
    _connection: AttachedConnection,
}

/// The boot and persistent inner sandbox a READY allocation is bound to, as the
/// helper journaled them. Validate and Exec must name both; the helper refuses
/// anything else, so this is a binding, not an authority.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Session {
    boot_id: String,
    inner_id: String,
}

/// How often `create` reads READY back from the helper while the guest boots.
const READY_POLL: Duration = Duration::from_millis(100);
/// One Inspect inside a create's or an execution's own deadline.
const INSPECT_BUDGET: Duration = Duration::from_secs(5);

pub struct FirecrackerRuntime {
    client: Client,
    instance_id: Id128,
    database_uuid: Id128,
    attachment: tokio::sync::Mutex<Option<Attachment>>,
    node_id: Mutex<Option<Id128>>,
    sessions: Mutex<HashMap<Id128, Session>>,
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

/// The allocation a backend ID names: `fc-` and 32 lowercase hexadecimal digits. Nothing
/// here is ever NotFound: only a receipt says an allocation is gone.
fn allocation_of(id: &str) -> Result<Id128, RuntimeError> {
    id.strip_prefix("fc-")
        .and_then(|hex| Id128::parse(hex).ok())
        .ok_or_else(|| {
            RuntimeError::Incompatible(format!("{id:?} is not a Firecracker backend ID"))
        })
}

/// A removal or collection receipt for an allocation known only by its backend ID.
/// The plan digest is the manager's to compare with its row (`commit_absence`).
fn decode_removal(
    bytes: &[u8],
    instance: Id128,
    allocation: Id128,
) -> Result<FencedAbsence, RuntimeError> {
    let receipt = FencedAbsence::decode(bytes)?;
    if receipt.instance_id() != instance || receipt.allocation_id() != allocation {
        return Err(RuntimeError::Backend(
            "absence receipt does not match this allocation".into(),
        ));
    }
    Ok(receipt)
}

/// Phases in which a created allocation is still on its way to READY.
fn booting(phase: &str) -> bool {
    matches!(
        phase,
        "intent" | "preparing" | "spawn_intent" | "booting" | "ready"
    )
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
            sessions: Mutex::new(HashMap::new()),
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

    fn attached_node(&self) -> Result<Id128, RuntimeError> {
        self.node_id
            .lock()
            .unwrap()
            .ok_or_else(|| RuntimeError::Backend("not attached to a node".into()))
    }

    async fn inspect_raw(
        &self,
        allocation: Id128,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<InspectReply, RuntimeError> {
        let deadline = deadline.min(Instant::now() + INSPECT_BUDGET);
        match self
            .call(
                FirecrackerOperation::Inspect {
                    allocation_id: allocation,
                },
                deadline,
                cancel,
            )
            .await?
        {
            FirecrackerResponse::Inspect(reply) => {
                if let InspectReply::PresentReady {
                    boot_id, inner_id, ..
                } = &reply
                {
                    self.remember(allocation, boot_id, inner_id);
                }
                Ok(reply)
            }
            FirecrackerResponse::Error(error) => Err(group_failure(error)),
            _ => Err(unexpected()),
        }
    }

    fn remember(&self, allocation: Id128, boot_id: &str, inner_id: &str) {
        self.sessions.lock().unwrap().insert(
            allocation,
            Session {
                boot_id: boot_id.into(),
                inner_id: inner_id.into(),
            },
        );
    }

    fn forget(&self, allocation: Id128) {
        self.sessions.lock().unwrap().remove(&allocation);
    }

    /// The boot and inner sandbox to name. Missing after a daemon restart, it is read
    /// from the helper's journal; only a READY allocation has one.
    async fn session(
        &self,
        allocation: Id128,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<Session, RuntimeError> {
        if let Some(session) = self.sessions.lock().unwrap().get(&allocation).cloned() {
            return Ok(session);
        }
        match self.inspect_raw(allocation, deadline, cancel).await? {
            InspectReply::PresentReady {
                boot_id, inner_id, ..
            } => Ok(Session { boot_id, inner_id }),
            InspectReply::PresentBusy { phase, .. } => Err(RuntimeError::Backend(format!(
                "allocation {allocation} is at {phase}, not READY"
            ))),
            InspectReply::StoppedWithResources { .. } | InspectReply::AbsentFenced { .. } => Err(
                RuntimeError::Backend(format!("allocation {allocation} has no running VM")),
            ),
            InspectReply::Incompatible { message } => Err(RuntimeError::Incompatible(message)),
            InspectReply::Unknown { reason } => Err(RuntimeError::Backend(format!(
                "allocation {allocation} is unknown: {reason}"
            ))),
        }
    }

    /// C6: the helper answers Create once C2 is durable; READY is journaled later, by S,
    /// after the broker's handshake. Follow it by Inspect within the create deadline.
    /// Anything but READY is a charged failure the manager settles by exact token.
    async fn wait_ready(
        &self,
        context: &CreateContext,
        prepared: &PreparedCreate,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<CreatedSandbox, CreateFailure> {
        let node_id = match prepared.regime() {
            EvidenceRegime::AbsenceFenced { node_id } => node_id,
            EvidenceRegime::LegacyLocal => {
                return Err(RuntimeError::Backend("a legacy plan cannot boot a VM".into()).into());
            }
        };
        let plan_digest = prepared.plan_digest();
        let mut last = String::from("no answer yet");
        loop {
            if cancel.is_cancelled() || Instant::now() >= deadline {
                return Err(RuntimeError::Backend(format!(
                    "allocation {} did not reach READY before its deadline ({last}); it stays charged",
                    context.allocation_id
                ))
                .into());
            }
            match self
                .inspect_raw(context.allocation_id, deadline, cancel)
                .await
            {
                Ok(InspectReply::PresentReady {
                    generation,
                    boot_id,
                    ..
                }) => {
                    let receipt = ReadyReceipt {
                        node_id,
                        instance_id: context.instance_id,
                        allocation_id: context.allocation_id,
                        plan_digest,
                        helper_generation: generation,
                        boot_id,
                    };
                    receipt.validate()?;
                    return Ok(CreatedSandbox {
                        backend_id: format!("fc-{}", context.allocation_id),
                        receipt: RuntimeReceipt::Ready(receipt),
                    });
                }
                Ok(InspectReply::PresentBusy { phase, .. }) if booting(&phase) => {
                    last = format!("at {phase}");
                }
                Ok(InspectReply::PresentBusy { phase, .. }) => {
                    return Err(RuntimeError::Backend(format!(
                        "allocation reached {phase} before READY was published"
                    ))
                    .into());
                }
                Ok(InspectReply::StoppedWithResources { .. }) => {
                    return Err(RuntimeError::Backend(
                        "the VM stopped before READY; its resources stay charged".into(),
                    )
                    .into());
                }
                Ok(InspectReply::AbsentFenced { receipt }) => {
                    let receipt = decode_fence(&receipt.0, context, &plan_digest)?;
                    return Err(CreateFailure::absent_fenced(
                        receipt,
                        RuntimeError::Backend("the allocation was fenced before READY".into()),
                    ));
                }
                Ok(InspectReply::Incompatible { message }) => {
                    return Err(RuntimeError::Incompatible(message).into());
                }
                // A stop in progress, a stale supervisor observation or a missing ledger
                // answer: no proof either way yet, and the deadline still bounds it.
                Ok(InspectReply::Unknown { reason }) => last = reason,
                Err(error) => last = error.to_string(),
            }
            tokio::select! {
                () = tokio::time::sleep(READY_POLL) => {}
                () = cancel.cancelled() => {}
            }
        }
    }

    /// The helper's Remove by exact token: stop, remove every owned resource, persist
    /// ABSENT. A retired token answers with its fence; a token the helper never
    /// journaled is refused, untouched.
    async fn remove_allocation(
        &self,
        allocation: Id128,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<FencedAbsence, RuntimeError> {
        match self
            .call(
                FirecrackerOperation::Remove {
                    allocation_id: allocation,
                },
                deadline,
                cancel,
            )
            .await?
        {
            FirecrackerResponse::Remove(FenceReply::Absent { receipt }) => {
                self.forget(allocation);
                decode_removal(&receipt.0, self.instance_id, allocation)
            }
            FirecrackerResponse::Remove(FenceReply::Ambiguous { class, message }) => {
                Err(RuntimeError::Backend(format!(
                    "allocation {allocation} stays charged ({class:?}): {message}"
                )))
            }
            FirecrackerResponse::Error(error) => Err(group_failure(error)),
            _ => Err(unexpected()),
        }
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

    async fn node_totals(
        &self,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<Option<super::NodeTotals>, RuntimeError> {
        let snapshot = self.node_accounting(deadline, cancel).await?;
        if snapshot.node_id != self.attached_node()? {
            return Err(RuntimeError::Backend(
                "node accounting is for another node".into(),
            ));
        }
        let (ceilings, committed) = (snapshot.ceilings, snapshot.committed);
        Ok(Some(super::NodeTotals {
            generation: snapshot.generation,
            limits: crate::store::SandboxBudgets {
                sandboxes: ceilings.slots,
                memory_bytes: ceilings.memory_bytes,
                pids: ceilings.pids,
                disk_bytes: ceilings.disk_bytes,
                host_cpu_millis: ceilings.host_cpu_millis,
                virtual_cpu_slots: ceilings.virtual_cpu_slots,
                host_pids: ceilings.host_pids,
            },
            reserved: crate::store::SandboxResources {
                sandboxes: committed.slots,
                memory_bytes: committed.memory_bytes,
                pids: committed.pids,
                disk_bytes: committed.disk_bytes,
                host_cpu_millis: committed.host_cpu_millis,
                virtual_cpu_slots: committed.virtual_cpu_slots,
                host_pids: committed.host_pids,
            },
            over_committed: snapshot.over_committed,
        }))
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
            // Accepted is a durable charge, not readiness: READY is S's to journal.
            FirecrackerResponse::Create(CreateReply::Accepted { .. }) => {
                self.wait_ready(context, prepared, deadline, cancel).await
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
            .inspect_raw(context.allocation_id, deadline, cancel)
            .await?
        {
            // The helper's READY: idle on the journaled boot, no execution in flight.
            InspectReply::PresentReady {
                generation,
                boot_id,
                ..
            } => Ok(AllocationObservation::Present {
                receipt: ReadyReceipt {
                    node_id: self.attached_node()?,
                    instance_id: context.instance_id,
                    allocation_id: context.allocation_id,
                    plan_digest: *prepared_digest,
                    helper_generation: generation,
                    boot_id,
                },
                healthy_idle: true,
                uncertain_execution: false,
            }),
            InspectReply::AbsentFenced { receipt } => Ok(AllocationObservation::AbsentFenced(
                decode_fence(&receipt.0, context, prepared_digest)?,
            )),
            InspectReply::StoppedWithResources { generation } => {
                Ok(AllocationObservation::StoppedWithResources {
                    helper_generation: generation,
                })
            }
            // Booting or busy carries no ready receipt to compare: unknown, so the
            // manager settles by exact token, which stops it before any release.
            InspectReply::PresentBusy { phase, .. } => Ok(AllocationObservation::Unknown {
                reason: format!("allocation is at {phase}"),
            }),
            InspectReply::Unknown { reason } => Ok(AllocationObservation::Unknown { reason }),
            InspectReply::Incompatible { message } => Err(RuntimeError::Incompatible(message)),
        }
    }

    async fn fence_absent(
        &self,
        context: &CreateContext,
        prepared_digest: &Digest,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<AbsenceReceipt, RuntimeError> {
        // A token the helper journaled is removed by exact token: stop, remove, ABSENT.
        // Its FenceAbsent would close the token's gate and still refuse while resources
        // exist. A retired token answers with its fence either way. Only a token with no
        // journal record falls through to FenceAbsent, which fences it never-admitted.
        match self
            .remove_allocation(context.allocation_id, deadline, cancel)
            .await
        {
            Ok(receipt) if &receipt.plan_digest() == prepared_digest => {
                return Ok(AbsenceReceipt::Fenced(receipt));
            }
            Ok(_) => {
                return Err(RuntimeError::Backend(
                    "absence receipt does not match this token".into(),
                ));
            }
            Err(_) if cancel.is_cancelled() || Instant::now() >= deadline => {
                return Err(RuntimeError::Backend(
                    "the fence deadline expired; the allocation stays charged".into(),
                ));
            }
            Err(_) => {}
        }
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
        id: &str,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), RuntimeError> {
        let allocation = allocation_of(id)?;
        let session = self.session(allocation, deadline, cancel).await?;
        // Never NotFound from here: a socket failure or an unanswered probe is not
        // absence, only Inspect's own evidence is.
        match self
            .call(
                FirecrackerOperation::Validate {
                    allocation_id: allocation,
                    expected_boot_id: session.boot_id,
                    expected_inner_id: session.inner_id,
                },
                deadline,
                cancel,
            )
            .await?
        {
            FirecrackerResponse::Validate(ValidateReply::Ready { .. }) => Ok(()),
            FirecrackerResponse::Validate(ValidateReply::Busy { .. }) => Err(
                RuntimeError::Backend(format!("allocation {allocation} is executing")),
            ),
            FirecrackerResponse::Validate(ValidateReply::ControlBusy) => Err(
                RuntimeError::Backend(format!("allocation {allocation}'s control slot is busy")),
            ),
            FirecrackerResponse::Validate(ValidateReply::Incompatible { message }) => {
                self.forget(allocation);
                Err(RuntimeError::Incompatible(message))
            }
            FirecrackerResponse::Validate(ValidateReply::Unknown { reason }) => {
                Err(RuntimeError::Backend(reason))
            }
            FirecrackerResponse::Error(error) => Err(group_failure(error)),
            _ => Err(unexpected()),
        }
    }

    async fn exec(
        &self,
        id: &str,
        execution: &ExecutionContext,
        spec: &ExecSpec<'_>,
        cancel: &CancellationToken,
    ) -> ExecOutcome {
        // Before any Exec frame nothing can have reached the guest: a refusal here
        // keeps the session as it is, and only a failure to learn its boot stops use.
        let not_sent = |kind, message: String, disposition| ExecOutcome {
            finish: Err(crate::model::RuntimeDiagnostic::new(
                kind,
                crate::model::RuntimeStage::Validate,
                message,
            )),
            command_status: None,
            stdout: crate::model::Captured::known_empty(),
            stderr: crate::model::Captured::known_empty(),
            disposition,
            cleanup: crate::model::CleanupEvidence::NoChildStarted,
        };
        let allocation = match allocation_of(id) {
            Ok(allocation) => allocation,
            Err(error) => {
                return not_sent(
                    crate::model::RuntimeErrorKind::NotFound,
                    error.to_string(),
                    crate::model::SandboxDisposition::Quarantined,
                );
            }
        };
        let session = match self.session(allocation, spec.deadline, cancel).await {
            Ok(session) => session,
            Err(error) => {
                return not_sent(
                    crate::model::RuntimeErrorKind::Unavailable,
                    format!("the session's boot could not be established: {error}"),
                    crate::model::SandboxDisposition::Quarantined,
                );
            }
        };
        let epoch = match self.epoch(spec.deadline).await {
            Ok(epoch) => epoch,
            Err(error) => {
                return not_sent(
                    crate::model::RuntimeErrorKind::Unavailable,
                    format!("not attached to the helper: {error}"),
                    crate::model::SandboxDisposition::Reusable,
                );
            }
        };
        let request = FirecrackerRequest {
            group_version: FIRECRACKER_GROUP_VERSION,
            instance_id: self.instance_id,
            connection_epoch: Some(epoch),
            operation: FirecrackerOperation::Exec {
                allocation_id: allocation,
                expected_boot_id: session.boot_id,
                execution_token: execution.execution_token,
                execution_id: execution.execution_id.clone(),
                argv: spec.argv.to_vec(),
                stdin_bytes: spec.stdin.len(),
                max_output: spec.max_output,
            },
        };
        let outcome = self.client.firecracker_exec(request, spec, cancel).await;
        if outcome.disposition != crate::model::SandboxDisposition::Reusable {
            self.forget(allocation);
        }
        outcome
    }

    async fn remove(
        &self,
        id: &str,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<AbsenceReceipt, RuntimeError> {
        let allocation = allocation_of(id)?;
        self.remove_allocation(allocation, deadline, cancel)
            .await
            .map(AbsenceReceipt::Fenced)
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
                            ListStatus::Ready => BackendStatus::Ready,
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
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<Vec<AbsenceReceipt>, RuntimeError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        if ids.len() > MAX_FIRECRACKER_GC_IDS {
            return Err(RuntimeError::Backend(format!(
                "at most {MAX_FIRECRACKER_GC_IDS} allocations per collection"
            )));
        }
        let mut allocations = Vec::with_capacity(ids.len());
        for id in ids {
            let allocation = allocation_of(id)?;
            if allocations.contains(&allocation) {
                return Err(RuntimeError::Backend(format!("{id} is named twice")));
            }
            allocations.push(allocation);
        }
        let results = match self
            .call(
                FirecrackerOperation::Gc {
                    allocation_ids: allocations.clone(),
                },
                deadline,
                cancel,
            )
            .await?
        {
            FirecrackerResponse::Gc(results) => results,
            FirecrackerResponse::Error(error) => return Err(group_failure(error)),
            _ => return Err(unexpected()),
        };
        // Every receipt is individually proven; a skip or failure leaves that one
        // charged and discoverable, and is reported after the receipts are kept.
        let mut receipts = Vec::new();
        let mut refused = Vec::new();
        for result in results {
            if !allocations.contains(&result.allocation_id) {
                return Err(RuntimeError::Backend(format!(
                    "collection reported allocation {} outside its scope",
                    result.allocation_id
                )));
            }
            match result.outcome {
                GcOutcome::Removed { receipt } => {
                    self.forget(result.allocation_id);
                    receipts.push(AbsenceReceipt::Fenced(decode_removal(
                        &receipt.0,
                        self.instance_id,
                        result.allocation_id,
                    )?));
                }
                GcOutcome::Skipped { reason } => {
                    refused.push(format!("{}: skipped: {reason}", result.allocation_id));
                }
                GcOutcome::Failed { class, message } => {
                    refused.push(format!(
                        "{}: failed ({class:?}): {message}",
                        result.allocation_id
                    ));
                }
            }
        }
        if refused.is_empty() || !receipts.is_empty() {
            return Ok(receipts);
        }
        Err(RuntimeError::Backend(format!(
            "nothing was collected: {}",
            refused.join("; ")
        )))
    }
}
