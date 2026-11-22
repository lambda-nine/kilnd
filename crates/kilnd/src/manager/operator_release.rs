//! `kilnd release-ambiguous`: the operator's proof that an ambiguous FAILED create
//! left nothing behind, and its audited release (schema 17).
//!
//! kilnd never releases a reservation it can't prove absent, and an ambiguous create
//! with no backend ID is one it can't: kiln never reported an ID, and `kiln ls` skips a
//! run directory without `shim.pid`, which a failed or killed create can leave
//! (kiln `runtime/src/container.rs:125-139`, `runtime/src/persistent.rs:902-908`).
//! With kilnd and kilnd-helper stopped, the operator can.
//!
//! **Why one pass is a fence and not a snapshot.** The state lock only proves no daemon
//! of this instance runs. The create may have been accepted by the separate root helper,
//! whose kiln work outlives the daemon, so the caller also holds the helper's serving
//! lock (`helper::ServeLock`) from before reconcile until after the commit below: no
//! helper serves, so nothing new starts a kiln create. An old one can still publish,
//! because kiln's create forks a detached shim before it has a run directory
//! (`runtime/src/persistent.rs:239-264`: `new_id`, `fork`, `setsid`, then
//! `supervise_persistent`), and that shim has no parent-death signal: when the helper
//! kills or loses the CLI, the shim goes on to `create_run_dir`, its setup and
//! `publish_shim_identity` (`runtime/src/container.rs:114-139`). With the serving lock
//! held, a new kiln process can only come from forking an existing one, and a published
//! shim's descendants (its sandbox init and what that runs) never create a host run
//! directory. So a scan of every process that finds only published shims, their
//! descendants and kiln's node services, followed by a read of the runs directory, is a
//! fence: nothing unscanned can still publish a run there afterwards. The scan reads
//! every process twice, so a shim forked while the first pass ran is in the second.
//!
//! The proof is everything below, in order, and any failure, deadline or unexplained
//! entry refuses with nothing released:
//!
//! 1. The row is a charged ambiguous FAILED legacy create with no backend ID.
//! 2. The startup reconciliation pass ([`Manager::reconcile`]) completes: the backend
//!    answers, the inventory is complete and validated (stale runs included), every
//!    managed backend is probed, and the checkpoint barrier's own inventory of
//!    checkpoint storage is clean. Each call keeps reconcile's own deadline. What it
//!    changes is what the next daemon start would change.
//! 3. Reconcile left no backend sandbox it can't name (`unmanaged`) and blocked
//!    nothing.
//! 4. A second complete inventory names only backends a live row owns.
//! 5. Every kiln process on the node is a published shim, a descendant of one, or a
//!    kiln node service ([`ReleaseNode::kiln_processes`]).
//! 6. kiln's runs directory, read by its own entries, holds only those backends and
//!    the checkpoint namespace kiln itself reserves there.
//!
//! The release commits with the SHA-256 of that inventory in its audit row.

use std::collections::HashSet;
use std::ffi::OsString;

use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;

use super::{Manager, Reconciled};
use crate::runtime::Runtime;
use crate::store::{
    OperatorRelease, OperatorReleaseError, OperatorReleased, operator_release_refusal,
    valid_release_reason,
};

/// The one name kiln reserves in its runs directory besides run IDs: the checkpoint
/// store (kiln `runtime/src/checkpoint/store.rs:41`, skipped by `registry_entries` at
/// `runtime/src/persistent.rs:1018` and by `image::blocking_references` at
/// `runtime/src/image.rs:321`). kiln's `.removing-*` names live inside that namespace
/// and inside `images/`, never directly here, so one here is unexplained.
pub const KILN_RUNS_RESERVED: &str = ".checkpoints";

/// What root sees of the node, for steps 5 and 6.
pub trait ReleaseNode {
    /// kiln's runs directory, read by its entries. The binary opens it as root before
    /// giving up root, so the listing needs no privilege when it is read.
    fn entries(&self) -> anyhow::Result<Vec<OsString>>;
    /// Every kiln process that is not a published shim, a descendant of one or a kiln
    /// node service, each as `PID EXE`, the first [`KilnProcesses::NAMED`] by name. The
    /// binary's root half reads every process twice
    /// (`release_ambiguous::unexplained_kiln_processes`).
    fn kiln_processes(&self) -> anyhow::Result<KilnProcesses>;
}

/// What a process scan found: the first [`KilnProcesses::NAMED`] unexplained kiln
/// processes, each as `PID EXE`, and how many there were in all, so that however many
/// there are the refusal stays short and still names some.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KilnProcesses {
    pub named: Vec<String>,
    pub total: usize,
}

impl KilnProcesses {
    /// The most processes a refusal names.
    pub const NAMED: usize = 64;

    pub fn push(&mut self, process: String) {
        if self.named.len() < Self::NAMED {
            self.named.push(process);
        }
        self.total += 1;
    }

    pub fn is_empty(&self) -> bool {
        self.total == 0
    }
}

impl<S: Into<String>> FromIterator<S> for KilnProcesses {
    fn from_iter<I: IntoIterator<Item = S>>(processes: I) -> Self {
        let mut found = Self::default();
        for process in processes {
            found.push(process.into());
        }
        found
    }
}

impl std::fmt::Display for KilnProcesses {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.named.join(", "))?;
        if self.total > self.named.len() {
            write!(
                f,
                " and {} more ({} in all)",
                self.total - self.named.len(),
                self.total
            )?;
        }
        Ok(())
    }
}

/// What the operator asks for.
#[derive(Clone, Copy, Debug)]
pub struct ReleaseRequest<'a> {
    pub sandbox_id: &'a str,
    pub reason: &'a str,
    pub operator_uid: u32,
}

/// A committed release.
#[derive(Debug)]
pub struct ReleaseProved {
    pub sandbox_id: String,
    pub released: OperatorReleased,
    pub inventory_sha256: String,
    pub reconciled: Reconciled,
}

/// Why nothing was released. The row keeps its charge in every case.
#[derive(Debug)]
pub enum ReleaseRefusal {
    NoSandbox,
    Ineligible(String),
    /// The backend, its listing or a helper call failed or timed out.
    Inventory(String),
    /// Reconciliation blocked admission or the checkpoint barrier.
    Blocked {
        admission: bool,
        checkpoints: bool,
    },
    /// Backend sandboxes no live row owns; `kiln gc` or `kiln rm` them by ID.
    UnexplainedRuns(Vec<String>),
    /// Entries in kiln's runs directory no live row owns.
    UnexplainedRunDirectories(Vec<String>),
    /// kiln processes that may still publish a run: a create a stopped helper started,
    /// or a kiln root runs by hand.
    KilnProcesses(KilnProcesses),
    Store(String),
}

impl ReleaseRefusal {
    /// The ineligible-target refusals, as against an unclean or unreadable node.
    pub fn is_ineligible(&self) -> bool {
        matches!(self, Self::NoSandbox | Self::Ineligible(_))
    }
}

impl std::fmt::Display for ReleaseRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSandbox => write!(f, "no such sandbox"),
            Self::Ineligible(why) => write!(f, "not an ambiguous reservation: {why}"),
            Self::Inventory(e) => write!(f, "the inventory is not complete: {e}"),
            Self::Blocked {
                admission,
                checkpoints,
            } => write!(
                f,
                "reconciliation blocked allocation (backend: {admission}, checkpoints: {checkpoints}); resolve what kilnd's log names and retry"
            ),
            Self::UnexplainedRuns(ids) => write!(
                f,
                "backend sandboxes no kilnd row owns: {}; inspect each and remove it by ID (`kiln gc ID` for a stale run, `kiln rm ID` for a live one you have checked), then retry",
                ids.join(" ")
            ),
            Self::UnexplainedRunDirectories(names) => write!(
                f,
                "entries in kiln's runs directory no kilnd row owns: {}; `kiln gc ID` (stale) or `kiln rm ID` (live) removes one that has shim.pid, and one without it must be inspected and removed by hand (no create may still be running in it), then retry",
                names.join(" ")
            ),
            Self::KilnProcesses(processes) => write!(
                f,
                "kiln processes that are not a published sandbox's shim or its descendants: {processes}; a create a stopped kilnd-helper started may still be setting up, and a kiln root runs by hand counts too; wait for them to finish (or stop them) and retry"
            ),
            Self::Store(e) => write!(f, "{e}"),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl<R: Runtime> Manager<R> {
    /// Proves the node clean of anything the ambiguous create may have left, then
    /// releases its reservation with an audit row. The caller holds the state lock, so
    /// no daemon of this instance runs beside it, and the helper's serving lock, so no
    /// helper does (see the module documentation).
    pub async fn release_ambiguous(
        &self,
        request: ReleaseRequest<'_>,
        node: &dyn ReleaseNode,
    ) -> Result<ReleaseProved, ReleaseRefusal> {
        let store_error = |e: anyhow::Error| ReleaseRefusal::Store(format!("{e:#}"));
        valid_release_reason(request.reason).map_err(ReleaseRefusal::Ineligible)?;
        let eligible = |manager: &Self| -> Result<(), ReleaseRefusal> {
            let row = manager
                .store
                .sandbox(request.sandbox_id)
                .map_err(store_error)?
                .ok_or(ReleaseRefusal::NoSandbox)?;
            if row.backend != manager.runtime.name() {
                return Err(ReleaseRefusal::Ineligible(format!(
                    "it belongs to the {} backend, not {}",
                    row.backend,
                    manager.runtime.name()
                )));
            }
            match operator_release_refusal(&row) {
                Some(why) => Err(ReleaseRefusal::Ineligible(why)),
                None => Ok(()),
            }
        };
        eligible(self)?;

        // 2-3: the startup pass itself.
        let reconciled = self
            .reconcile()
            .await
            .map_err(|e| ReleaseRefusal::Inventory(e.to_string()))?;
        if !reconciled.unmanaged.is_empty() {
            return Err(ReleaseRefusal::UnexplainedRuns(reconciled.unmanaged));
        }
        if reconciled.admission_blocked || reconciled.checkpoints_blocked {
            return Err(ReleaseRefusal::Blocked {
                admission: reconciled.admission_blocked,
                checkpoints: reconciled.checkpoints_blocked,
            });
        }

        // 4: the inventory as reconcile left it, every entry owned by a live row.
        let sandboxes = self.store.sandboxes(true).map_err(store_error)?;
        let cancel = CancellationToken::new();
        let inventory = self
            .validated_inventory(&sandboxes, &cancel)
            .await
            .map_err(|e| ReleaseRefusal::Inventory(e.to_string()))?;
        let owned: HashSet<String> = self
            .store
            .owned_backend_ids(self.runtime.name())
            .map_err(store_error)?
            .into_iter()
            .collect();
        let mut runs_listed: Vec<(String, String)> = inventory
            .iter()
            .map(|(id, record)| (id.clone(), format!("{:?}", record.status)))
            .collect();
        runs_listed.sort();
        let mut unexplained: Vec<String> = runs_listed
            .iter()
            .filter(|(id, _)| !owned.contains(id))
            .map(|(id, _)| id.clone())
            .collect();
        if !unexplained.is_empty() {
            unexplained.sort();
            return Err(ReleaseRefusal::UnexplainedRuns(unexplained));
        }

        // 5: no kiln process left that could still publish a run, so the read below
        // is the last word on the runs directory.
        let processes = node.kiln_processes().map_err(|e| {
            ReleaseRefusal::Inventory(format!("scan the node's kiln processes: {e:#}"))
        })?;
        if !processes.is_empty() {
            return Err(ReleaseRefusal::KilnProcesses(processes));
        }

        // 6: kiln's runs directory, whatever kiln's listing skips.
        let mut directories: Vec<String> = node
            .entries()
            .map_err(|e| ReleaseRefusal::Inventory(format!("read kiln's runs directory: {e:#}")))?
            .into_iter()
            .filter(|name| name != KILN_RUNS_RESERVED)
            .map(|name| match name.into_string() {
                Ok(name) => name,
                Err(name) => format!("{name:?}"),
            })
            .collect();
        directories.sort();
        let strays: Vec<String> = directories
            .iter()
            .filter(|name| !owned.contains(*name))
            .cloned()
            .collect();
        if !strays.is_empty() {
            return Err(ReleaseRefusal::UnexplainedRunDirectories(strays));
        }

        let mut hash = Sha256::new();
        hash.update(b"kilnd-operator-release-inventory-v1\n");
        hash.update(format!(
            "sandbox {}\nbackend {}\n",
            request.sandbox_id,
            self.runtime.name()
        ));
        for (id, status) in &runs_listed {
            hash.update(format!("run {id} {status}\n"));
        }
        for name in &directories {
            hash.update(format!("rundir {name}\n"));
        }
        hash.update(if self.maintained() {
            "checkpoints clean\n"
        } else {
            "checkpoints none\n"
        });
        let inventory_sha256 = hex(&hash.finalize());

        // The row may only have changed by this process's own reconcile; recheck it
        // here and again in the release's own transaction.
        eligible(self)?;
        let released = self
            .store
            .release_ambiguous_by_operator(&OperatorRelease {
                sandbox_id: request.sandbox_id,
                operator_uid: request.operator_uid,
                reason: request.reason,
                inventory_sha256: &inventory_sha256,
            })
            .map_err(|e| match e {
                OperatorReleaseError::NoSandbox => ReleaseRefusal::NoSandbox,
                OperatorReleaseError::Ineligible(why) => ReleaseRefusal::Ineligible(why),
                OperatorReleaseError::Store(e) => store_error(e),
            })?;
        Ok(ReleaseProved {
            sandbox_id: request.sandbox_id.to_string(),
            released,
            inventory_sha256,
            reconciled,
        })
    }
}
