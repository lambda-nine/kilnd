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
    ExecSpec, ExecutionContext, FencedAbsence, PrepareContext, PreparedCreate, ReadyReceipt,
    RemoveTarget, Runtime, RuntimeCapabilities, RuntimeError, RuntimeReceipt,
};
use crate::helper::firecracker::token;
use crate::firecracker::{canonical, offline_768_v1_reservation, strict_json};
use crate::helper::firecracker::journal::{AccountingSnapshot, MAX_ACTIVE_LISTED};
use crate::helper::protocol::{
    AccountingReply, AmbiguousClass, CreateReply, FIRECRACKER_GROUP_VERSION, FenceReply,
    FirecrackerOperation, FirecrackerRequest, FirecrackerResponse, GcOutcome, GcTarget,
    GroupError, GroupErrorKind, InspectReply, ListStatus, MAX_FIRECRACKER_GC_IDS, PreparedReply, ValidateReply,
    WireBytes,
};
use crate::helper::{AttachedConnection, Client};
use crate::model::{AllocationBinding, Digest, Id128, Network, SandboxSpec};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
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

/// The helper's per-node bound on non-durable token gates (`MAX_TOKEN_GATES` in
/// `helper/firecracker/mod.rs`), mirrored here; a test asserts the two are equal.
pub(crate) const HELPER_TOKEN_GATES: usize = 4096;
/// B7 RTC-13: the digest cache's backstop. An entry lives from `create` (after C1) to
/// the allocation's terminal answer, so the cache holds at most this instance's live
/// allocations, which a complete inventory bounds at `MAX_ACTIVE_LISTED` (1024), plus
/// those in flight, which the helper's node-wide token gates bound at 4096: 5120. At the
/// cap `prepare` refuses before Preflight; nothing past C1 is ever refused or evicted.
pub(crate) const MAX_DIGESTS: usize = MAX_ACTIVE_LISTED + HELPER_TOKEN_GATES;

pub struct FirecrackerRuntime {
    client: Client,
    instance_id: Id128,
    database_uuid: Id128,
    attachment: tokio::sync::Mutex<Option<Attachment>>,
    node_id: Mutex<Option<Id128>>,
    sessions: Mutex<HashMap<Id128, Session>>,
    /// B7 RTC-14: the highest complete token this daemon has recorded, reported at every
    /// attachment. Seeded from the Store at startup and raised by every verified prepare.
    highest_token: Mutex<Option<Id128>>,
    /// B7: each allocation's Store plan digest, learned at `create` (after C1) and by a
    /// non-terminal Inspect, so a later Validate or Exec can read its boot with the
    /// digest Inspect requires. Every terminal answer forgets it, and a learn begun
    /// before that answer never brings it back (recheck R3). Never a source of release
    /// evidence.
    digests: Mutex<DigestCache>,
    /// `MAX_DIGESTS`, lowered only by tests.
    max_digests: AtomicUsize,
}

/// B7 recheck R3: the digests, and the allocations with a learning call in flight (a
/// Create or an Inspect), each with how many and whether a terminal answer arrived
/// meanwhile. An in-flight entry lives only while its calls do, so both maps stay
/// bounded: the cap bounds the first, concurrent calls the second.
#[derive(Default)]
struct DigestCache {
    entries: HashMap<Id128, Digest>,
    in_flight: HashMap<Id128, InFlight>,
}

#[derive(Default)]
struct InFlight {
    calls: u32,
    forgotten: bool,
}

/// One learning call's claim on an allocation (B7 recheck R3). Its learn is refused if
/// the allocation reached a terminal answer after the claim began; dropped, it ends the
/// claim, whichever way the call ended (an answer, an error, a deadline or a cancel).
struct LearnClaim<'a> {
    cache: &'a Mutex<DigestCache>,
    sessions: &'a Mutex<HashMap<Id128, Session>>,
    allocation: Id128,
}

impl LearnClaim<'_> {
    fn learn(&self, digest: Digest) {
        let mut cache = self.cache.lock().unwrap();
        if !cache
            .in_flight
            .get(&self.allocation)
            .is_some_and(|claim| claim.forgotten)
        {
            cache.entries.insert(self.allocation, digest);
        }
    }

    /// Integrated recheck MEDIUM-1: a READY answer's session, published under the same
    /// terminal-aware claim as the digest. An answer delivered after a terminal one
    /// (produced before it) brings back neither. The digest cache's lock is held across
    /// the insert, as `forget_allocation` holds it across the removal, so the check and
    /// the publication cannot straddle a terminal answer.
    fn publish_session(&self, boot_id: &str, inner_id: &str) {
        let cache = self.cache.lock().unwrap();
        if !cache
            .in_flight
            .get(&self.allocation)
            .is_some_and(|claim| claim.forgotten)
        {
            self.sessions.lock().unwrap().insert(
                self.allocation,
                Session {
                    boot_id: boot_id.into(),
                    inner_id: inner_id.into(),
                },
            );
        }
    }
}

impl Drop for LearnClaim<'_> {
    fn drop(&mut self) {
        let mut cache = self.cache.lock().unwrap();
        if let Some(claim) = cache.in_flight.get_mut(&self.allocation) {
            claim.calls -= 1;
            if claim.calls == 0 {
                cache.in_flight.remove(&self.allocation);
            }
        }
    }
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

/// B7: L's NotIssued and the latch are reported as Incompatible; every other class is
/// an ordinary backend error. Either way the allocation stays charged.
fn ambiguous_error(class: AmbiguousClass, message: String) -> RuntimeError {
    match class {
        AmbiguousClass::NotIssued | AmbiguousClass::Latched => RuntimeError::Incompatible(message),
        _ => RuntimeError::Backend(message),
    }
}

/// B7 (section 9.1): a fenced binding must name this attachment's node and instance.
fn check_binding(
    binding: &AllocationBinding,
    node: Id128,
    instance: Id128,
) -> Result<(), RuntimeError> {
    if binding.node_id != node || binding.instance_id != instance {
        return Err(RuntimeError::Incompatible(format!(
            "allocation {} belongs to another node or instance",
            binding.allocation_id
        )));
    }
    Ok(())
}

fn unexpected() -> RuntimeError {
    RuntimeError::Backend("unexpected Firecracker helper response".into())
}

/// Every prepared field is reconstructed from verified bytes; nothing is believed
/// because the helper said it. A fixture schema or any mismatched field fails here.
/// B7 (section 9.1): the token is the helper's, so it is checked here, tag-free: 32 hex
/// digits with seq in range, named by the plan's substitutions, for this instance. The
/// tag itself only the helper can check.
fn verify_prepared(
    context: &PrepareContext,
    spec: &SandboxSpec,
    reply: PreparedReply,
) -> Result<PreparedCreate, RuntimeError> {
    let invalid = |why: &str| RuntimeError::Backend(format!("prepared plan refused: {why}"));
    let token = reply.allocation_id;
    if !token::shape_ok(token) {
        return Err(invalid("the issued token has no valid sequence"));
    }
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
        || substitutions["allocation_id"] != token.to_string()
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
        token,
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
    context: &PrepareContext,
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
            highest_token: Mutex::new(None),
            digests: Mutex::default(),
            max_digests: AtomicUsize::new(MAX_DIGESTS),
        }
    }

    /// Always records, even at the cap: it runs only past C1, where refusing or evicting
    /// would strand a live allocation's Validate and Exec.
    fn learn_digest(&self, allocation: Id128, digest: Digest) {
        self.digests.lock().unwrap().entries.insert(allocation, digest);
    }

    /// B7 recheck R3: claims `allocation` for one learning call. A terminal answer while
    /// the claim lives marks it, so the call's own learn cannot reinsert the digest, and
    /// reconciliation never drops a digest a claim may still need.
    fn claim_learn(&self, allocation: Id128) -> LearnClaim<'_> {
        let mut cache = self.digests.lock().unwrap();
        let claim = cache.in_flight.entry(allocation).or_default();
        if claim.calls == 0 {
            claim.forgotten = false;
        }
        claim.calls += 1;
        LearnClaim {
            cache: &self.digests,
            sessions: &self.sessions,
            allocation,
        }
    }

    /// B7 recheck R3: reconciliation's recovery of the cap. A complete inventory names
    /// every allocation of this instance the helper still holds; a digest or session
    /// (integrated recheck MEDIUM-1) known before it was asked whose allocation it omits
    /// is retired or absent and is dropped, unless a learning call held a claim on it at
    /// the start or still does.
    fn drop_unlisted(&self, before: &[Id128], listed: &[Id128]) {
        let mut cache = self.digests.lock().unwrap();
        let mut sessions = self.sessions.lock().unwrap();
        for allocation in before {
            if !listed.contains(allocation) && !cache.in_flight.contains_key(allocation) {
                cache.entries.remove(allocation);
                sessions.remove(allocation);
            }
        }
    }

    /// The allocations with a digest or a session known now and no learning call in
    /// flight: the only ones a complete inventory may drop.
    fn settled_allocations(&self) -> Vec<Id128> {
        let cache = self.digests.lock().unwrap();
        let sessions = self.sessions.lock().unwrap();
        let mut settled: Vec<Id128> = cache
            .entries
            .keys()
            .chain(sessions.keys())
            .filter(|allocation| !cache.in_flight.contains_key(allocation))
            .copied()
            .collect();
        settled.sort_unstable();
        settled.dedup();
        settled
    }

    /// B7 RTC-14: raises the reported highest token to `token` if its sequence is
    /// higher. The daemon seeds it from its Store (`Store::highest_fenced_token`).
    pub fn record_token(&self, token: Option<Id128>) {
        let Some(token) = token else { return };
        let mut highest = self.highest_token.lock().unwrap();
        if highest.is_none_or(|current| token::seq_of(token) > token::seq_of(current)) {
            *highest = Some(token);
        }
    }

    /// The reported highest token, for tests.
    #[cfg(test)]
    pub(crate) fn test_highest_token(&self) -> Option<Id128> {
        *self.highest_token.lock().unwrap()
    }

    #[cfg(test)]
    pub(crate) fn test_digest_count(&self) -> usize {
        self.digests.lock().unwrap().entries.len()
    }

    /// Seeds an entry, as an earlier create or Inspect would have.
    #[cfg(test)]
    pub(crate) fn test_learn_digest(&self, allocation: Id128, digest: Digest) {
        self.learn_digest(allocation, digest);
    }

    #[cfg(test)]
    pub(crate) fn test_set_max_digests(&self, cap: usize) {
        self.max_digests.store(cap, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn test_database(&self) -> Id128 {
        self.database_uuid
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
        let highest_token = *self.highest_token.lock().unwrap();
        let (response, connection) = self
            .client
            .attach(
                FirecrackerRequest {
                    group_version: FIRECRACKER_GROUP_VERSION,
                    instance_id: self.instance_id,
                    connection_epoch: None,
                    operation: FirecrackerOperation::AttachInstance {
                        database_uuid: self.database_uuid,
                        highest_token,
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

    /// One Inspect. A READY answer's session is published only through `claim`, the
    /// caller's terminal-aware claim on the allocation (integrated recheck MEDIUM-1).
    async fn inspect_raw(
        &self,
        claim: &LearnClaim<'_>,
        plan_digest: Digest,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<InspectReply, RuntimeError> {
        let allocation = claim.allocation;
        let deadline = deadline.min(Instant::now() + INSPECT_BUDGET);
        match self
            .call(
                FirecrackerOperation::Inspect {
                    allocation_id: allocation,
                    plan_digest,
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
                    claim.publish_session(boot_id, inner_id);
                }
                Ok(reply)
            }
            FirecrackerResponse::Error(error) => Err(group_failure(error)),
            _ => Err(unexpected()),
        }
    }

    /// The remembered boot is stale, but the allocation may be READY again: keep its
    /// digest so the next Validate or Exec re-reads the boot.
    fn forget_session(&self, allocation: Id128) {
        self.sessions.lock().unwrap().remove(&allocation);
    }

    /// The allocation reached a terminal answer: nothing will name it again, and a
    /// learning call begun before this answer cannot bring its digest back (recheck R3).
    fn forget_allocation(&self, allocation: Id128) {
        // The digest cache's lock first and across both, as `publish_session` takes them.
        let mut cache = self.digests.lock().unwrap();
        cache.entries.remove(&allocation);
        if let Some(claim) = cache.in_flight.get_mut(&allocation) {
            claim.forgotten = true;
        }
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
        // Claimed before the digest is read, so a terminal answer from here on keeps a
        // READY answer from publishing the session (integrated recheck MEDIUM-1).
        let claim = self.claim_learn(allocation);
        let Some(digest) = self.digests.lock().unwrap().entries.get(&allocation).copied() else {
            return Err(RuntimeError::Backend(format!(
                "allocation {allocation} has no known binding yet; reconciliation reads it"
            )));
        };
        match self.inspect_raw(&claim, digest, deadline, cancel).await? {
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
        claim: &LearnClaim<'_>,
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
                .inspect_raw(claim, plan_digest, deadline, cancel)
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
                    self.forget_allocation(context.allocation_id);
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
        plan_digest: Digest,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<FencedAbsence, RuntimeError> {
        match self
            .call(
                FirecrackerOperation::Remove {
                    allocation_id: allocation,
                    plan_digest,
                },
                deadline,
                cancel,
            )
            .await?
        {
            FirecrackerResponse::Remove(FenceReply::Absent { receipt }) => {
                let receipt = decode_removal(&receipt.0, self.instance_id, allocation)?;
                self.forget_allocation(allocation);
                Ok(receipt)
            }
            FirecrackerResponse::Remove(FenceReply::Ambiguous { class, message }) => {
                Err(ambiguous_error(
                    class,
                    format!("allocation {allocation} stays charged ({class:?}): {message}"),
                ))
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
            node_fault: snapshot.node_fault,
            degraded: snapshot.degraded,
        }))
    }

    async fn prepare(
        &self,
        context: &PrepareContext,
        spec: &SandboxSpec,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<PreparedCreate, RuntimeError> {
        if context.instance_id != self.instance_id {
            return Err(RuntimeError::Incompatible(
                "preparation names another instance".into(),
            ));
        }
        // RTC-13: checked before Preflight, so a refusal spends no seq.
        let cap = self.max_digests.load(Ordering::Relaxed);
        if self.digests.lock().unwrap().entries.len() >= cap {
            return Err(RuntimeError::Exhausted(format!(
                "this daemon already tracks {cap} unsettled Firecracker allocations"
            )));
        }
        match self
            .call(
                FirecrackerOperation::Preflight {
                    sandbox_id: context.sandbox_id.clone(),
                    profile: "offline-768-v1".into(),
                    spec: spec.clone(),
                },
                deadline,
                cancel,
            )
            .await?
        {
            FirecrackerResponse::Prepared(reply) => {
                let prepared = verify_prepared(context, spec, *reply)?;
                // Not learned here: a plan the manager refuses before C1 leaves no entry.
                self.record_token(prepared.allocation_id());
                Ok(prepared)
            }
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
        // The manager calls create only after C1: from here the allocation may exist.
        // The claim keeps reconciliation from dropping it before C2 is listed.
        let claim = self.claim_learn(context.allocation_id);
        self.learn_digest(context.allocation_id, plan_digest);
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
                self.forget_allocation(context.allocation_id);
                Err(CreateFailure::absent_fenced(
                    receipt,
                    RuntimeError::Backend("this allocation token is permanently fenced".into()),
                ))
            }
            // Accepted is a durable charge, not readiness: READY is S's to journal.
            FirecrackerResponse::Create(CreateReply::Accepted { .. }) => {
                self.wait_ready(&claim, context, prepared, deadline, cancel).await
            }
            FirecrackerResponse::Create(CreateReply::Ambiguous { class, message }) => {
                let error = ambiguous_error(class, format!("create rejected ({class:?}): {message}"));
                Err(if class == AmbiguousClass::Capacity {
                    CreateFailure::exhausted(error)
                } else {
                    error.into()
                })
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
        let claim = self.claim_learn(context.allocation_id);
        let reply = self
            .inspect_raw(&claim, *prepared_digest, deadline, cancel)
            .await?;
        // Only a non-terminal answer (re)learns the digest: how a restarted daemon
        // relearns its live allocations for Validate and Exec. A terminal answer that
        // arrived while this one was in flight (a Remove's, a Gc's) wins: the stale
        // continuation learns nothing (recheck R3). A refusal forgets: the digest it
        // names is not this token's.
        match reply {
            InspectReply::AbsentFenced { .. } => {}
            InspectReply::Incompatible { .. } => self.forget_allocation(context.allocation_id),
            _ => claim.learn(*prepared_digest),
        }
        drop(claim);
        match reply {
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
            InspectReply::AbsentFenced { receipt } => {
                let receipt = decode_fence(&receipt.0, context, prepared_digest)?;
                self.forget_allocation(context.allocation_id);
                Ok(AllocationObservation::AbsentFenced(receipt))
            }
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
        // The Store digest is passed explicitly and never cached here.
        match self
            .remove_allocation(context.allocation_id, *prepared_digest, deadline, cancel)
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
            FirecrackerResponse::Fence(FenceReply::Absent { receipt }) => {
                let receipt = decode_fence(&receipt.0, context, prepared_digest)?;
                self.forget_allocation(context.allocation_id);
                Ok(AbsenceReceipt::Fenced(receipt))
            }
            FirecrackerResponse::Fence(FenceReply::Ambiguous { class, message }) => Err(
                ambiguous_error(class, format!("allocation stays charged ({class:?}): {message}")),
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
                self.forget_session(allocation);
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
            self.forget_session(allocation);
        }
        outcome
    }

    /// B7 (section 9.1): `Legacy` is reachable here (a historical kiln row's Delete,
    /// compensation, reconciliation Gc) and is refused before any wire call. A fenced
    /// binding must be this attachment's node and instance; the helper acts only on the
    /// journaled resources of the row whose digest it names.
    async fn remove(
        &self,
        target: RemoveTarget<'_>,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<AbsenceReceipt, RuntimeError> {
        let binding = target.fenced()?;
        self.epoch(deadline).await?;
        check_binding(binding, self.attached_node()?, self.instance_id)?;
        // The Store digest is passed explicitly; only the absence forgets the entry.
        self.remove_allocation(binding.allocation_id, binding.plan_digest, deadline, cancel)
            .await
            .map(AbsenceReceipt::Fenced)
    }

    async fn list(
        &self,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<BackendInventory, RuntimeError> {
        let before = self.settled_allocations();
        match self
            .call(FirecrackerOperation::List, deadline, cancel)
            .await?
        {
            FirecrackerResponse::List(reply) => {
                // B7 recheck R3: a complete inventory recovers the cap from digests whose
                // allocations the helper no longer holds.
                if reply.complete {
                    let listed: Vec<Id128> =
                        reply.records.iter().map(|record| record.allocation_id).collect();
                    self.drop_unlisted(&before, &listed);
                }
                Ok(BackendInventory {
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
                })
            }
            FirecrackerResponse::Error(error) => Err(group_failure(error)),
            _ => Err(unexpected()),
        }
    }

    /// B7: the whole vector is checked before the first wire frame (no `Legacy`, no
    /// foreign binding, no duplicate, the length bound), so one bad target refuses the
    /// call with nothing sent.
    async fn gc(
        &self,
        targets: &[RemoveTarget<'_>],
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<Vec<AbsenceReceipt>, RuntimeError> {
        if targets.is_empty() {
            return Ok(Vec::new());
        }
        if targets.len() > MAX_FIRECRACKER_GC_IDS {
            return Err(RuntimeError::Backend(format!(
                "at most {MAX_FIRECRACKER_GC_IDS} allocations per collection"
            )));
        }
        let mut bindings = Vec::with_capacity(targets.len());
        for target in targets {
            bindings.push(target.fenced()?);
        }
        self.epoch(deadline).await?;
        let node = self.attached_node()?;
        let mut wire = Vec::with_capacity(bindings.len());
        for binding in bindings {
            check_binding(binding, node, self.instance_id)?;
            if wire
                .iter()
                .any(|t: &GcTarget| t.allocation_id == binding.allocation_id)
            {
                return Err(RuntimeError::Incompatible(format!(
                    "allocation {} is named twice",
                    binding.allocation_id
                )));
            }
            wire.push(GcTarget {
                allocation_id: binding.allocation_id,
                plan_digest: binding.plan_digest,
            });
        }
        let allocations: Vec<Id128> = wire.iter().map(|t| t.allocation_id).collect();
        let results = match self
            .call(
                FirecrackerOperation::Gc {
                    targets: wire.clone(),
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
                    let receipt =
                        decode_removal(&receipt.0, self.instance_id, result.allocation_id)?;
                    self.forget_allocation(result.allocation_id);
                    receipts.push(AbsenceReceipt::Fenced(receipt));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> SandboxSpec {
        SandboxSpec {
            image: "alpine".into(),
            memory_bytes: 512 << 20,
            cpu_millis: 1000,
            pids: 128,
            disk_bytes: 1 << 30,
            network: Network::None,
            read_only_root: false,
            writable_paths: vec![],
            labels: Default::default(),
        }
    }

    /// RTC-13's backstop: at the cap, prepare refuses as Exhausted with no helper call,
    /// so no seq is spent; below it the same call reaches the socket. Past C1 nothing is
    /// refused: `learn_digest` still records over the cap.
    #[tokio::test]
    async fn prepare_at_the_digest_cap_is_exhausted_before_any_helper_call() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("helper.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let instance = Id128::random();
        let runtime = FirecrackerRuntime::new(path, instance, Id128::random());
        runtime.test_set_max_digests(1);
        let context = PrepareContext {
            instance_id: instance,
            sandbox_id: "sb-cap".into(),
        };
        let cancel = CancellationToken::new();
        let soon = || Instant::now() + Duration::from_millis(200);
        // Below the cap the call reaches the socket (and times out unanswered).
        let below = runtime.prepare(&context, &spec(), soon(), &cancel).await;
        assert!(!matches!(below, Err(RuntimeError::Exhausted(_))), "{below:?}");
        let (first, _) = listener.accept().expect("below the cap, prepare connects");
        drop(first);
        runtime.learn_digest(Id128::random(), Digest::of(b"one"));
        match runtime.prepare(&context, &spec(), soon(), &cancel).await {
            Err(RuntimeError::Exhausted(reason)) => assert!(reason.contains('1'), "{reason}"),
            other => panic!("not exhausted: {other:?}"),
        }
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "at the cap, nothing reached the helper"
        );
        assert_eq!(runtime.test_highest_token(), None);
        runtime.learn_digest(Id128::random(), Digest::of(b"two"));
        assert_eq!(runtime.test_digest_count(), 2, "learning past C1 is never refused");
        assert_eq!(MAX_DIGESTS, 1024 + 4096);
    }

    /// B7 M1 recheck R3 (`reviews/poc-b7m1-recheck`, `poc_b7m1_stale_inspects_fill_the_
    /// digest_cap`, now a regression): each allocation is learned at Create, an Inspect's
    /// reply is in flight, Remove's terminal answer forgets the allocation, and then the
    /// delayed Inspect resumes. Its learn is refused, so the cap never fills with entries
    /// nothing will remove, and the next Preflight reaches the helper.
    #[tokio::test]
    async fn stale_learns_after_terminal_answers_never_fill_the_digest_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("helper.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let instance = Id128::random();
        let runtime = FirecrackerRuntime::new(path, instance, Id128::random());
        runtime.test_set_max_digests(2);
        for label in [b"one".as_slice(), b"two".as_slice()] {
            let allocation = Id128::random();
            let digest = Digest::of(label);
            runtime.learn_digest(allocation, digest); // Create, after C1.
            let inspect = runtime.claim_learn(allocation); // Inspect's reply in flight.
            runtime.forget_allocation(allocation); // Remove's terminal answer.
            inspect.learn(digest); // The delayed Inspect resumes.
            drop(inspect);
        }
        assert_eq!(runtime.test_digest_count(), 0, "no stale entry survives");
        // A claim begun after the terminal answer learns normally: a restarted daemon's
        // Inspect relearns its live allocations.
        let allocation = Id128::random();
        let claim = runtime.claim_learn(allocation);
        claim.learn(Digest::of(b"live"));
        drop(claim);
        assert_eq!(runtime.test_digest_count(), 1);
        let context = PrepareContext {
            instance_id: instance,
            sandbox_id: "sb-stale-inspects".into(),
        };
        let soon = Instant::now() + Duration::from_millis(200);
        let below = runtime.prepare(&context, &spec(), soon, &CancellationToken::new()).await;
        assert!(!matches!(below, Err(RuntimeError::Exhausted(_))), "{below:?}");
        listener.accept().expect("the Preflight reached the helper");
    }

    /// B7 M1 recheck R3: a complete inventory drops the digests of allocations it does not
    /// name (retired or absent), never one a learning call holds a claim on, nor one
    /// learned after the inventory was asked.
    #[test]
    fn a_complete_inventory_drops_only_unclaimed_unlisted_digests() {
        let runtime = FirecrackerRuntime::new("/nonexistent".into(), Id128::random(), Id128::random());
        let [live, retired, creating, later] = [(); 4].map(|_| Id128::random());
        for allocation in [live, retired, creating] {
            runtime.learn_digest(allocation, Digest::of(allocation.to_string().as_bytes()));
        }
        let claim = runtime.claim_learn(creating);
        let before = runtime.settled_allocations();
        assert_eq!(before.len(), 2, "a claimed digest is never a candidate");
        runtime.learn_digest(later, Digest::of(b"later"));
        runtime.drop_unlisted(&before, &[live]);
        let cache = runtime.digests.lock().unwrap();
        assert!(cache.entries.contains_key(&live));
        assert!(!cache.entries.contains_key(&retired), "the unlisted digest is dropped");
        assert!(cache.entries.contains_key(&creating));
        assert!(cache.entries.contains_key(&later));
        drop(cache);
        drop(claim);
        assert!(runtime.digests.lock().unwrap().in_flight.is_empty(), "claims end with their calls");
    }

    /// Integrated recheck MEDIUM-1 (`reviews/poc-b7-integrated/r3-stale-session-
    /// resurrection.sh`, inverted): for 32 allocations, an Inspect holds its claim, a
    /// terminal Remove forgets the allocation, and only then is the already-produced READY
    /// answer handled, publishing its session and learning its digest through the claim.
    /// Neither comes back: no session and no digest survives.
    #[test]
    fn stale_ready_answers_after_terminal_answers_resurrect_no_session() {
        let runtime = FirecrackerRuntime::new("/nonexistent".into(), Id128::random(), Id128::random());
        for index in 0..32u8 {
            let allocation = Id128::random();
            let digest = Digest::of(&[index]);
            runtime.learn_digest(allocation, digest);
            let claim = runtime.claim_learn(allocation);
            runtime.forget_allocation(allocation);
            // inspect_raw's READY arm, then inspect_allocation's guarded learn.
            claim.publish_session("stale-boot", "stale-inner");
            claim.learn(digest);
            drop(claim);
        }
        assert_eq!(runtime.digests.lock().unwrap().entries.len(), 0);
        assert_eq!(runtime.sessions.lock().unwrap().len(), 0, "no stale session returns");
        // A claim begun after the terminal answer publishes normally (a restarted daemon).
        let allocation = Id128::random();
        let claim = runtime.claim_learn(allocation);
        claim.publish_session("boot", "inner");
        drop(claim);
        assert_eq!(runtime.sessions.lock().unwrap().len(), 1);
    }

    /// Integrated recheck MEDIUM-1's recovery: a complete inventory also drops the
    /// sessions of allocations it does not name, never one a learning call holds a claim
    /// on, nor one published after the inventory was asked.
    #[test]
    fn a_complete_inventory_drops_only_unclaimed_unlisted_sessions() {
        let runtime = FirecrackerRuntime::new("/nonexistent".into(), Id128::random(), Id128::random());
        let [live, retired, creating, later] = [(); 4].map(|_| Id128::random());
        for allocation in [live, retired, creating] {
            let claim = runtime.claim_learn(allocation);
            claim.publish_session("boot", "inner");
        }
        let claim = runtime.claim_learn(creating);
        let before = runtime.settled_allocations();
        assert_eq!(before.len(), 2, "a claimed session is never a candidate");
        runtime.claim_learn(later).publish_session("boot", "inner");
        runtime.drop_unlisted(&before, &[live]);
        let sessions = runtime.sessions.lock().unwrap();
        assert!(sessions.contains_key(&live));
        assert!(!sessions.contains_key(&retired), "the unlisted session is dropped");
        assert!(sessions.contains_key(&creating));
        assert!(sessions.contains_key(&later));
        drop(sessions);
        drop(claim);
    }
}
