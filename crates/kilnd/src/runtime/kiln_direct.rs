//! The kiln backend: drives the `kiln` CLI with argument vectors. kilnd
//! never links kiln's code or reads its state directories; the CLI's
//! `create`, `exec`, `ls`, `rm` and `gc` are the whole interface.

#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::kiln_protocol as protocol;
use super::{
    AbsenceReceipt, AccountingAuthority, AllocationObservation, BackendInventory, BackendSandbox,
    CreateContext, CreateFailure, CreatedSandbox, ExecOutcome, ExecSpec, ExecutionContext,
    LegacyAbsence, LegacyProof, PrepareContext, PreparedCreate, RemoveTarget, Runtime,
    RuntimeCapabilities, RuntimeError, RuntimeReceipt,
};
use crate::model::{Digest, Network, SandboxSpec};
use crate::process::{self, Finish};
// Phase 1b B5 moved the probe, listing, validation and execution core to kilnd-exec-core;
// `DirectKilnRuntime` delegates to it through `core()`.
// The adapter tests below still name these, as they did before the move.
#[cfg(test)]
use super::{BackendStatus, ExecFinish};
#[cfg(test)]
use crate::model::{CleanupEvidence, SandboxDisposition};
#[cfg(test)]
use crate::model::{RuntimeErrorKind as Kind, RuntimeStage as Stage};
#[cfg(test)]
use kilnd_exec_core::runtime::kiln_direct::CONTROL_OUTPUT;
pub(crate) use kilnd_exec_core::runtime::kiln_direct::valid_kiln_id;
use kilnd_exec_core::runtime::kiln_direct::{DirectKiln, QUERY_TIMEOUT, check_id, summarize};
pub use kilnd_exec_core::runtime::kiln_direct::{create_args, parse_ls};

/// `kiln create` exits with this only for failures known before it allocates.
const CREATE_PREFLIGHT_FAILED: i32 = 124;
const CREATE_TIMEOUT: Duration = Duration::from_secs(120);
const REMOVE_TIMEOUT: Duration = Duration::from_secs(60);

/// The profile recorded for new kiln rows. Descriptive only; historical rows
/// keep an empty profile.
pub(crate) const KILN_PROFILE: &str = "kiln";

pub(crate) fn legacy_capabilities() -> RuntimeCapabilities {
    RuntimeCapabilities {
        network_modes: vec![Network::None, Network::Full, Network::Allow(Vec::new())],
        interruption_preserves_session: true,
        checkpoint: false,
        accounting: AccountingAuthority::LocalLegacy,
    }
}

/// `kiln ls` was parsed strictly and completely, so it is a complete inventory by
/// the same standard reconciliation already required of it.
pub(crate) fn legacy_inventory(rows: Vec<BackendSandbox>) -> BackendInventory {
    BackendInventory {
        records: rows.into_iter().map(Into::into).collect(),
        generation: 0,
        complete: true,
    }
}

pub(crate) fn unsupported_token() -> RuntimeError {
    RuntimeError::Unsupported("the kiln backend has no allocation-token recovery".into())
}

pub struct DirectKilnRuntime {
    bin: process::KilnBinary,
    cgroup_root: PathBuf,
}

impl DirectKilnRuntime {
    pub fn new(bin: PathBuf) -> Self {
        Self {
            bin: process::KilnBinary::new(bin),
            cgroup_root: PathBuf::from("/sys/fs/cgroup/kiln"),
        }
    }

    /// The direct-kiln core over this runtime's CLI and kiln cgroup root.
    fn core(&self) -> DirectKiln<'_> {
        DirectKiln::new(&self.bin, &self.cgroup_root)
    }

    async fn call_until(
        &self,
        op: &str,
        args: &process::KilnArgs,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<process::Outcome, RuntimeError> {
        self.core().call_until(op, args, deadline, cancel).await
    }

    async fn run_control(
        &self,
        args: &process::KilnArgs,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> std::io::Result<process::Outcome> {
        self.core().run_control(args, deadline, cancel).await
    }

    async fn capabilities(
        &self,
        id: Option<&str>,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<protocol::Capabilities, RuntimeError> {
        self.core().capabilities(id, deadline, cancel).await
    }

    pub(crate) async fn list_until(
        &self,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<Vec<BackendSandbox>, RuntimeError> {
        self.core().list_until(deadline, cancel).await
    }

    /// Revalidates the installed CLI immediately before each create, because
    /// its exit status is evidence only if it advertised that contract. Failing
    /// this gate proves no create process started; from the spawn attempt on,
    /// only `create_result`'s exact evidence is definite.
    pub(crate) async fn create_until(
        &self,
        spec: &SandboxSpec,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<String, CreateFailure> {
        let deadline = deadline.min(Instant::now() + CREATE_TIMEOUT);
        self.capabilities(None, deadline.min(Instant::now() + QUERY_TIMEOUT), cancel)
            .await
            .map_err(CreateFailure::definitely_not_created)?;
        let out = self
            .run_control(&process::KilnArgs::create(spec), deadline, cancel)
            .await?;
        create_result(&out)
    }

    pub(crate) async fn remove_until(
        &self,
        id: &str,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), RuntimeError> {
        let deadline = deadline.min(Instant::now() + REMOVE_TIMEOUT);
        check_id(id)?;
        let removal = self
            .call_until("rm", &process::KilnArgs::rm(id)?, deadline, cancel)
            .await;
        // A successful rm or a list omission alone does not prove that the
        // exact sandbox released its resources. Reuse startup's direct probe,
        // complete listing and absent-cgroup standard on every release path.
        match self
            .validate_sandbox(id, deadline.min(Instant::now() + QUERY_TIMEOUT), cancel)
            .await
        {
            Err(RuntimeError::NotFound(_)) => removal
                .map(|_| ())
                .map_err(|_| RuntimeError::NotFound(id.to_string())),
            Ok(()) => Err(RuntimeError::Backend(format!(
                "kiln rm {id} did not prove absence: exact backend is still reachable"
            ))),
            Err(e) => Err(RuntimeError::Backend(format!(
                "kiln rm {id} did not prove absence: {e}"
            ))),
        }
    }

    pub(crate) async fn gc_until(
        &self,
        ids: &[String],
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<Vec<String>, RuntimeError> {
        let deadline = deadline.min(Instant::now() + QUERY_TIMEOUT);
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        for id in ids {
            check_id(id)?;
        }
        let args = process::KilnArgs::gc(ids)?;
        let out = self.call_until("gc", &args, deadline, cancel).await?;
        let requested: std::collections::HashSet<_> = ids.iter().map(String::as_str).collect();
        let mut removed = Vec::new();
        for line in String::from_utf8_lossy(&out.stderr.data).lines() {
            let id = line
                .strip_prefix("kiln: removed stale sandbox ")
                .map(str::trim)
                .ok_or_else(|| {
                    RuntimeError::Backend(format!("kiln gc printed unexpected output {line:?}"))
                })?;
            if !requested.contains(id) {
                return Err(RuntimeError::Backend(format!(
                    "kiln gc removed sandbox {id} outside its requested scope"
                )));
            }
            if removed.iter().any(|prior| prior == id) {
                return Err(RuntimeError::Backend(format!(
                    "kiln gc reported sandbox {id} more than once"
                )));
            }
            removed.push(id.to_string());
        }
        Ok(removed)
    }

    /// The feature bits the installed CLI (`None`) or one sandbox's PID 1 advertises,
    /// and whether exec options can reach it: bit 0x20 and a host whose memfds kiln
    /// accepts (API additions design 4.1).
    pub(crate) async fn exec_features(
        &self,
        id: Option<&str>,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(u32, bool), RuntimeError> {
        let caps = match id {
            None => self.capabilities(None, deadline, cancel).await?,
            Some(id) => {
                self.core()
                    .validate_sandbox_capabilities(id, deadline, cancel)
                    .await?
            }
        };
        let exec_options = caps.features & kilnd_exec_core::exec_options::FEATURE_EXEC_OPTIONS != 0
            && kilnd_exec_core::runtime::kiln_process::options_memfd_supported();
        Ok((caps.features, exec_options))
    }

    /// The helper's wire exec has no execution context, so its dispatch uses this
    /// directly. The cleanup contract is unchanged; disposition only names it.
    pub(crate) async fn exec_direct(
        &self,
        id: &str,
        spec: &ExecSpec<'_>,
        cancel: &CancellationToken,
    ) -> ExecOutcome {
        self.core().exec_direct(id, spec, cancel).await
    }

    #[cfg(test)]
    fn with_cgroup_root(bin: PathBuf, cgroup_root: &Path) -> Self {
        Self {
            bin: process::KilnBinary::new(bin),
            cgroup_root: cgroup_root.to_path_buf(),
        }
    }
}

impl Runtime for DirectKilnRuntime {
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
        let caps = self.capabilities(None, deadline, cancel).await?;
        Ok(format!(
            "{}: {} {} (persistent-exec v1)",
            self.bin.display(),
            caps.package,
            caps.provenance
        ))
    }

    async fn proven_features(
        &self,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<crate::manager::ProvenFeatures, RuntimeError> {
        let (_, exec_options) = self.exec_features(None, deadline, cancel).await?;
        Ok(super::kiln::exec_option_features(exec_options))
    }

    async fn validate_sandbox(
        &self,
        id: &str,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), RuntimeError> {
        self.core().validate_sandbox(id, deadline, cancel).await
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
        let backend_id = self.create_until(prepared.spec(), deadline, cancel).await?;
        let exec_features = self
            .exec_features(
                Some(&backend_id),
                Instant::now() + super::kiln::SANDBOX_FEATURES_TIMEOUT,
                &CancellationToken::new(),
            )
            .await
            .ok()
            .map(|(features, _)| features);
        Ok(CreatedSandbox {
            backend_id,
            receipt: RuntimeReceipt::Legacy,
            exec_features,
        })
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
        self.exec_direct(id, spec, cancel).await
    }

    async fn remove(
        &self,
        target: RemoveTarget<'_>,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<AbsenceReceipt, RuntimeError> {
        // B7: a fenced binding is refused before any kiln call.
        let id = target.legacy()?;
        self.remove_until(id, deadline, cancel).await?;
        Ok(AbsenceReceipt::Legacy(LegacyAbsence {
            backend_id: id.into(),
            proof: LegacyProof::StrictRemoval,
        }))
    }

    async fn list(
        &self,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<BackendInventory, RuntimeError> {
        Ok(legacy_inventory(self.list_until(deadline, cancel).await?))
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
        Ok(self
            .gc_until(ids, deadline, cancel)
            .await?
            .into_iter()
            .map(|backend_id| {
                AbsenceReceipt::Legacy(LegacyAbsence {
                    backend_id,
                    proof: LegacyProof::ScopedGc,
                })
            })
            .collect())
    }
}

/// Interprets a completed create attempt. The contract is the exit status of
/// the direct child, never its diagnostics: a preflight failure happens before
/// any ID exists or any descendant is forked, so printed output or a surviving
/// holder of its pipes contradicts exit 124 and leaves the failure ambiguous.
fn create_result(out: &process::Outcome) -> Result<String, CreateFailure> {
    let status = match &out.finish {
        Finish::Exited(status) => status,
        Finish::TimedOut => {
            return Err(RuntimeError::Backend("kiln create deadline expired".into()).into());
        }
        Finish::Canceled => {
            return Err(RuntimeError::Backend("kiln create was canceled".into()).into());
        }
    };
    if status.success() {
        let id = String::from_utf8_lossy(&out.stdout.data).trim().to_string();
        if !valid_kiln_id(&id) {
            return Err(RuntimeError::Backend(format!(
                "kiln create printed an unexpected ID {id:?}"
            ))
            .into());
        }
        return Ok(id);
    }
    let error = RuntimeError::Backend(format!(
        "kiln create failed ({status}): {}",
        summarize(&out.stderr.data)
    ));
    if status.code() == Some(CREATE_PREFLIGHT_FAILED)
        && out.stdout.total_bytes == 0
        && out.stdout_completion == process::CaptureCompletion::Eof
        && out.stderr_completion == process::CaptureCompletion::Eof
    {
        return Err(CreateFailure::definitely_not_created(error));
    }
    Err(error.into())
}

#[cfg(test)]
// Approved (design 7.1): test fixtures, compiled only under cfg(test). They build, signal,
// unmount and remove their own scratch resources and replacements directly.
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::super::kiln_process::tests::fixture;
    use super::*;
    use crate::model::CommandStatus;
    use crate::runtime::CreateCertainty;
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    impl DirectKilnRuntime {
        async fn create_now(&self, spec: &SandboxSpec) -> Result<String, CreateFailure> {
            self.create_until(
                spec,
                Instant::now() + CREATE_TIMEOUT,
                &CancellationToken::new(),
            )
            .await
        }

        async fn remove_now(&self, id: &str) -> Result<(), RuntimeError> {
            self.remove_until(
                id,
                Instant::now() + REMOVE_TIMEOUT,
                &CancellationToken::new(),
            )
            .await
        }

        async fn list_now(&self) -> Result<Vec<BackendSandbox>, RuntimeError> {
            self.list_until(Instant::now() + QUERY_TIMEOUT, &CancellationToken::new())
                .await
        }

        async fn gc_now(&self, ids: &[String]) -> Result<Vec<String>, RuntimeError> {
            self.gc_until(
                ids,
                Instant::now() + QUERY_TIMEOUT,
                &CancellationToken::new(),
            )
            .await
        }
    }

    fn fixture_runtime(tmp: &Path, body: &str) -> DirectKilnRuntime {
        let bin = tmp.join("kiln");
        fixture(&bin, body);
        let root = tmp.join("cgroup");
        fs::create_dir_all(root.join("abcd/exec")).unwrap();
        fs::write(root.join("abcd/exec/cgroup.events"), "populated 0\n").unwrap();
        DirectKilnRuntime::with_cgroup_root(bin, &root)
    }

    fn set_events(path: &Path, value: &str) {
        // Kernel cgroup.events reads are coherent; model that with atomic replacement.
        let next = path.with_extension("next");
        fs::write(&next, value).unwrap();
        fs::rename(next, path).unwrap();
    }

    fn failed_id_probe_runtime(
        tmp: &Path,
        present: bool,
        ls_override: Option<&str>,
    ) -> DirectKilnRuntime {
        let workload = tmp.join("workload");
        let trace = tmp.join("calls");
        let runtime = fixture_runtime(
            tmp,
            &format!("open({workload:?},'w').close()\nos.write(STATUS,EXIT125)\nsys.exit(125)"),
        );
        if !present {
            fs::remove_dir_all(runtime.cgroup_root.join("abcd")).unwrap();
        }
        let listing = if present {
            "ID\\tSTATUS\\tSHIM\\nabcd\\trunning\\t42\\n"
        } else {
            "ID\\tSTATUS\\tSHIM\\n"
        };
        let ls_body = ls_override
            .map(str::to_owned)
            .unwrap_or_else(|| format!("os.write(1,b'{listing}'); sys.exit(0)"));
        let source=fs::read_to_string(&runtime.bin).unwrap().replace("if sys.argv[1]=='capabilities':",&format!("open({trace:?},'a').write(' '.join(sys.argv[1:])+'\\n')\nif sys.argv[1]=='create':\n    print('abcd')\n    sys.exit(0)\nif sys.argv[1]=='ls':\n    {ls_body}\nif sys.argv[1]=='capabilities' and len(sys.argv)>3:\n    os.write(2,b'ID capability unavailable: legacy PID1 or removed sandbox')\n    sys.exit(2)\nif sys.argv[1]=='capabilities':"));
        fs::write(&runtime.bin, source).unwrap();
        runtime
    }

    // A valid listing may omit a live registry record. Exercise removal
    // through the manager so a false NotFound would release durable capacity.
    async fn assert_hidden_backend_retains_reservation(
        reachable: bool,
        rm_succeeds: bool,
        publication_fails: bool,
    ) {
        use crate::manager::{CreateRequest, Limits, Manager};
        use crate::model::SandboxState;
        use crate::store::Store;
        let tmp = tempfile::tempdir().unwrap();
        let runtime = failed_id_probe_runtime(
            tmp.path(),
            true,
            Some("os.write(1,b'ID\\tSTATUS\\tSHIM\\n'); sys.exit(0)"),
        );
        let mut source = fs::read_to_string(&runtime.bin).unwrap().replace(
            "if sys.argv[1]=='create':",
            &format!(
                "if sys.argv[1]=='rm':\n    sys.exit({})\nif sys.argv[1]=='create':",
                if rm_succeeds { 0 } else { 1 }
            ),
        );
        if reachable {
            // Remove the cgroup fixture: the positive exact-ID probe alone
            // must prevent release even if the filesystem evidence is absent.
            fs::remove_dir_all(runtime.cgroup_root.join("abcd")).unwrap();
            source = source.replace("and len(sys.argv)>3:", "and False:");
        }
        fs::write(&runtime.bin, source).unwrap();
        let store = Store::open_in_memory().unwrap();
        if publication_fails {
            store.reject_ready_updates().unwrap();
        }
        let manager = Arc::new(Manager::new(runtime, store, Limits::default()));
        let created = manager.create(CreateRequest::default()).await;
        let row = manager.list(true).unwrap().remove(0);
        if publication_fails {
            assert!(created.is_err());
        } else {
            created.unwrap();
            assert!(
                manager.delete(&row.id).await.is_err(),
                "hidden backend was deleted from accounting"
            );
        }
        assert_eq!(
            manager.get(&row.id, 0).unwrap().0.state,
            SandboxState::Deleting
        );
        assert_eq!(
            manager
                .health()
                .await
                .unwrap()
                .node_resources
                .reserved
                .sandboxes,
            1
        );
        if reachable {
            manager
                .runtime()
                .validate_sandbox(
                    "abcd",
                    Instant::now() + QUERY_TIMEOUT,
                    &CancellationToken::new(),
                )
                .await
                .unwrap();
        } else {
            assert!(manager.runtime().cgroup_root.join("abcd").exists());
        }
    }

    #[tokio::test]
    async fn hidden_registry_entry_keeps_delete_reservation() {
        assert_hidden_backend_retains_reservation(true, false, false).await;
    }

    #[tokio::test]
    async fn failed_rm_with_surviving_cgroup_keeps_delete_reservation() {
        assert_hidden_backend_retains_reservation(false, false, false).await;
    }

    #[tokio::test]
    async fn successful_rm_without_absence_evidence_keeps_delete_reservation() {
        assert_hidden_backend_retains_reservation(false, true, false).await;
    }

    #[tokio::test]
    async fn hidden_backend_keeps_failed_publication_compensation_reserved() {
        for reachable in [true, false] {
            assert_hidden_backend_retains_reservation(reachable, false, true).await;
        }
    }

    /// The adapter wraps existing behavior in typed results and adds no new action.
    #[tokio::test]
    async fn kiln_prepare_wraps_the_spec_and_has_no_allocation_recovery() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = failed_id_probe_runtime(tmp.path(), false, None);
        let trace = tmp.path().join("calls");
        let cancel = CancellationToken::new();
        let soon = Instant::now() + QUERY_TIMEOUT;
        let context = CreateContext {
            instance_id: crate::model::Id128::random(),
            allocation_id: crate::model::Id128::random(),
            sandbox_id: crate::model::new_id("sb"),
        };
        let prepare_context = PrepareContext {
            instance_id: context.instance_id,
            sandbox_id: context.sandbox_id.clone(),
        };
        let mut requested = spec(Network::Full);
        requested.labels.insert("k".into(), "v".into());
        let prepared = runtime
            .prepare(&prepare_context, &requested, soon, &cancel)
            .await
            .unwrap();
        assert!(!trace.exists(), "prepare must not reach the backend");
        assert_eq!(prepared.spec(), &requested);
        assert_eq!(
            prepared.regime(),
            crate::runtime::EvidenceRegime::LegacyLocal
        );
        assert_eq!(prepared.backend_plan(), b"");
        assert_eq!(prepared.plan_version(), 0);
        assert_eq!(prepared.runtime_profile(), KILN_PROFILE);
        let reservation = prepared.reservation();
        assert_eq!(reservation.memory_bytes, requested.memory_bytes);
        assert_eq!(reservation.disk_bytes, requested.disk_bytes);
        assert_eq!(reservation.pids, u64::from(requested.pids));
        assert_eq!(
            (
                reservation.host_cpu_millis,
                reservation.virtual_cpu_slots,
                reservation.host_pids
            ),
            (0, 0, 0),
            "legacy CPU, vCPU and host PIDs are explicitly not reserved"
        );
        assert_eq!(
            (
                prepared.host_spec_sha256(),
                prepared.guest_exec_spec_sha256()
            ),
            crate::model::spec_digests(&requested)
        );
        let digest = prepared.plan_digest();
        assert_eq!(
            runtime
                .inspect_allocation(&context, &digest, soon, &cancel)
                .await
                .unwrap(),
            AllocationObservation::Unsupported
        );
        assert!(matches!(
            runtime.fence_absent(&context, &digest, soon, &cancel).await,
            Err(RuntimeError::Unsupported(_))
        ));
        assert!(!trace.exists(), "token recovery must not reach the backend");

        // A strict removal is a legacy receipt; its bare NotFound stays NotFound,
        // so nothing downstream can mistake it for allocation-level proof.
        let removed = runtime
            .remove(RemoveTarget::Legacy { backend_id: "abcd" }, soon, &cancel)
            .await;
        let expected = AbsenceReceipt::Legacy(LegacyAbsence {
            backend_id: "abcd".into(),
            proof: LegacyProof::StrictRemoval,
        });
        assert!(
            matches!(&removed, Ok(receipt) if *receipt == expected)
                || matches!(removed, Err(RuntimeError::NotFound(_))),
            "{removed:?}"
        );
        let inventory = runtime.list(soon, &cancel).await.unwrap();
        assert!(inventory.complete);
        assert_eq!(inventory.generation, 0);
        assert!(runtime.gc(&[], soon, &cancel).await.unwrap().is_empty());
        let caps = Runtime::capabilities(&runtime);
        assert_eq!(caps.accounting, AccountingAuthority::LocalLegacy);
        assert!(caps.interruption_preserves_session);
        assert!(!caps.checkpoint);
    }

    #[tokio::test]
    async fn remove_accepts_only_confirmed_absence() {
        for rm_succeeds in [true, false] {
            let tmp = tempfile::tempdir().unwrap();
            let runtime = failed_id_probe_runtime(tmp.path(), false, None);
            let source = fs::read_to_string(&runtime.bin).unwrap().replace(
                "if sys.argv[1]=='create':",
                &format!(
                    "if sys.argv[1]=='rm':\n    sys.exit({})\nif sys.argv[1]=='create':",
                    if rm_succeeds { 0 } else { 1 }
                ),
            );
            fs::write(&runtime.bin, source).unwrap();
            assert!(matches!(
                runtime.remove_now("abcd").await,
                Ok(()) | Err(RuntimeError::NotFound(_))
            ));
        }
    }

    #[tokio::test]
    async fn failed_id_probe_confirms_absence_but_preserves_incompatible_live_pid1() {
        for present in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let runtime = failed_id_probe_runtime(tmp.path(), present, None);
            let error = runtime
                .validate_sandbox(
                    "abcd",
                    Instant::now() + Duration::from_secs(5),
                    &CancellationToken::new(),
                )
                .await
                .unwrap_err();
            if present {
                assert!(matches!(error, RuntimeError::Incompatible(_)));
                assert!(error.to_string().contains("legacy PID1"));
            } else {
                assert!(matches!(error,RuntimeError::NotFound(ref id) if id=="abcd"));
            }
            let out = execute(&runtime).await;
            let d = out.finish.unwrap_err();
            assert_eq!(
                (d.kind, d.stage),
                (
                    if present {
                        Kind::Incompatible
                    } else {
                        Kind::NotFound
                    },
                    Stage::Handshake
                )
            );
            assert!(!tmp.path().join("workload").exists());
            let calls = fs::read_to_string(tmp.path().join("calls")).unwrap();
            assert!(calls.contains(
                "capabilities --protocol=1\ngc --help\ncapabilities --protocol=1 abcd\nls\n"
            ));
        }
    }

    #[tokio::test]
    async fn manager_marks_only_confirmed_missing_sandbox_lost_before_exec() {
        use crate::manager::{CreateRequest, ExecRequest, Limits, Manager};
        use crate::model::{ExecutionState, SandboxState};
        use crate::store::Store;
        for present in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let runtime = failed_id_probe_runtime(tmp.path(), present, None);
            let manager = Arc::new(Manager::new(
                runtime,
                Store::open_in_memory().unwrap(),
                Limits::default(),
            ));
            let sandbox = manager.create(CreateRequest::default()).await.unwrap();
            assert_eq!(sandbox.state, SandboxState::Ready);
            let outcome = manager
                .exec(ExecRequest {
                    cwd: String::new(),
                    env: Vec::new(),
                    sandbox_id: sandbox.id.clone(),
                    argv: vec!["must-not-launch".into()],
                    stdin: vec![],
                    timeout_ms: 5000,
                })
                .await
                .unwrap();
            assert_eq!(outcome.state, ExecutionState::Failed);
            assert_eq!(outcome.exit_code, None);
            assert!(outcome.command_status.is_none());
            assert_eq!(
                outcome.runtime_error.as_ref().map(|d| (d.kind, d.stage)),
                Some((
                    if present {
                        Kind::Incompatible
                    } else {
                        Kind::NotFound
                    },
                    Stage::Handshake
                ))
            );
            assert_eq!(
                manager.get(&sandbox.id, 1).unwrap().0.state,
                if present {
                    SandboxState::Ready
                } else {
                    SandboxState::Lost
                }
            );
            assert!(!tmp.path().join("workload").exists());
            manager.begin_shutdown();
            manager.drain_operations().await;
        }
    }

    #[tokio::test]
    async fn successful_exit125_probes_capabilities_without_a_presence_lookup() {
        let tmp = tempfile::tempdir().unwrap();
        let trace = tmp.path().join("calls");
        let runtime = fixture_runtime(tmp.path(), "os.write(STATUS,EXIT125); sys.exit(125)");
        let source = fs::read_to_string(&runtime.bin).unwrap().replace(
            "if sys.argv[1]=='capabilities':",
            &format!(
                "open({trace:?},'a').write(sys.argv[1]+'\\n')\nif sys.argv[1]=='capabilities':"
            ),
        );
        fs::write(&runtime.bin, source).unwrap();
        let out = execute(&runtime).await;
        assert_eq!(out.finish, Ok(ExecFinish::Completed));
        assert_eq!(out.command_status, Some(CommandStatus::Exited(125)));
        assert_eq!(
            fs::read_to_string(trace).unwrap(),
            "capabilities\ngc\ncapabilities\nexec\n"
        );
    }

    #[tokio::test]
    async fn failed_presence_observation_never_claims_not_found() {
        for ls_body in [
            "sys.exit(3)",
            "os.write(1,b'malformed table'); sys.exit(0)",
            "os.write(1,b'ID\\tSTATUS\\tSHIM\\n'+b'x'*70000); sys.exit(0)",
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let runtime = failed_id_probe_runtime(tmp.path(), false, Some(ls_body));
            let error = runtime
                .validate_sandbox(
                    "abcd",
                    Instant::now() + Duration::from_secs(5),
                    &CancellationToken::new(),
                )
                .await
                .unwrap_err();
            assert!(matches!(error, RuntimeError::Incompatible(_)));
            assert!(
                error
                    .to_string()
                    .contains("presence could not be confirmed")
            );
            assert!(!tmp.path().join("workload").exists());
        }
    }

    #[tokio::test]
    async fn a_complete_listing_cannot_hide_an_existing_sandbox_cgroup() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = failed_id_probe_runtime(
            tmp.path(),
            true,
            Some("os.write(1,b'ID\\tSTATUS\\tSHIM\\n'); sys.exit(0)"),
        );
        let error = runtime
            .validate_sandbox(
                "abcd",
                Instant::now() + Duration::from_secs(5),
                &CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, RuntimeError::Incompatible(_)));
        assert!(error.to_string().contains("kiln ls omitted sandbox abcd"));
        assert!(error.to_string().contains("cgroup"));
        assert!(!tmp.path().join("workload").exists());
    }

    #[tokio::test]
    async fn list_rejects_output_beyond_the_64_kib_control_capture() {
        let tmp = tempfile::tempdir().unwrap();
        let body =
            format!("os.write(1,b'ID\\tSTATUS\\tSHIM\\n'+b'a'*{CONTROL_OUTPUT}); sys.exit(0)");
        let runtime = failed_id_probe_runtime(tmp.path(), false, Some(&body));
        let error = runtime.list_now().await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("kiln ls observation was truncated")
        );
        assert!(error.to_string().contains("stdout true"));
    }

    #[tokio::test]
    async fn garbage_collection_passes_and_enforces_an_explicit_id_scope() {
        let tmp = tempfile::tempdir().unwrap();
        let trace = tmp.path().join("gc-calls");
        let runtime = fixture_runtime(tmp.path(), "sys.exit(0)");
        let source = fs::read_to_string(&runtime.bin).unwrap().replace(
            "if sys.argv[1]=='capabilities':",
            &format!(
                "if sys.argv[1]=='gc':\n    open({trace:?},'a').write(' '.join(sys.argv[1:])+'\\n')\n    os.write(2,b'kiln: removed stale sandbox abcd\\n')\n    sys.exit(0)\nif sys.argv[1]=='capabilities':"
            ),
        );
        fs::write(&runtime.bin, source).unwrap();

        assert!(runtime.gc_now(&[]).await.unwrap().is_empty());
        assert_eq!(
            runtime
                .gc_now(&["abcd".into(), "beef".into()])
                .await
                .unwrap(),
            ["abcd"]
        );
        assert_eq!(fs::read_to_string(trace).unwrap(), "gc abcd beef\n");

        let error = runtime.gc_now(&["beef".into()]).await.unwrap_err();
        assert!(error.to_string().contains("outside its requested scope"));
    }

    fn delayed_listing_runtime(tmp: &Path, hold_stderr: bool) -> DirectKilnRuntime {
        let done = tmp.join("late-writer-done");
        let close_fd = if hold_stderr { 1 } else { 2 };
        let (output_fd, late_bytes) = if hold_stderr {
            (2, "late CLI diagnostic\\n")
        } else {
            (1, "abcd\\trunning\\t42\\n")
        };
        let body = format!(
            "os.write(1,b'ID\\tSTATUS\\tSHIM\\n')\n    if os.fork()==0:\n        os.close({close_fd})\n        time.sleep(.8)\n        try:\n            os.write({output_fd},b'{late_bytes}')\n        except OSError:\n            pass\n        open({done:?},'w').close()\n        os._exit(0)\n    os._exit(0)"
        );
        failed_id_probe_runtime(tmp, true, Some(&body))
    }

    #[tokio::test]
    async fn inherited_ls_writer_prevents_false_absence_after_header_only_success() {
        for hold_stderr in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let runtime = delayed_listing_runtime(tmp.path(), hold_stderr);
            let out = tokio::time::timeout(Duration::from_secs(2), execute(&runtime))
                .await
                .expect("incomplete ls observation was not bounded");
            let diagnostic = out.finish.unwrap_err();
            assert_eq!(
                (diagnostic.kind, diagnostic.stage),
                (Kind::Incompatible, Stage::Handshake)
            );
            assert!(
                diagnostic
                    .message
                    .contains("kiln ls observation was incomplete")
            );
            assert!(
                diagnostic
                    .message
                    .contains("250ms output drain grace expired")
            );
            assert!(!tmp.path().join("workload").exists());
            wait_marker(&tmp.path().join("late-writer-done")).await;
        }
    }

    #[tokio::test]
    async fn manager_keeps_ready_when_header_only_ls_has_an_inherited_writer() {
        use crate::manager::{CreateRequest, ExecRequest, Limits, Manager};
        use crate::model::{ExecutionState, SandboxState};
        use crate::store::Store;
        for hold_stderr in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let runtime = delayed_listing_runtime(tmp.path(), hold_stderr);
            let manager = Arc::new(Manager::new(
                runtime,
                Store::open_in_memory().unwrap(),
                Limits::default(),
            ));
            let sandbox = manager.create(CreateRequest::default()).await.unwrap();
            let outcome = tokio::time::timeout(
                Duration::from_secs(2),
                manager.exec(ExecRequest {
                    cwd: String::new(),
                    env: Vec::new(),
                    sandbox_id: sandbox.id.clone(),
                    argv: vec!["must-not-launch".into()],
                    stdin: vec![],
                    timeout_ms: 5000,
                }),
            )
            .await
            .expect("manager waited for the inherited ls writer")
            .unwrap();
            assert_eq!(outcome.state, ExecutionState::Failed);
            assert!(outcome.command_status.is_none());
            let diagnostic = outcome.runtime_error.unwrap();
            assert_eq!(
                (diagnostic.kind, diagnostic.stage),
                (Kind::Incompatible, Stage::Handshake)
            );
            assert!(
                diagnostic
                    .message
                    .contains("kiln ls observation was incomplete")
            );
            assert_eq!(
                manager.get(&sandbox.id, 1).unwrap().0.state,
                SandboxState::Ready
            );
            assert!(!tmp.path().join("workload").exists());
            manager.begin_shutdown();
            manager.drain_operations().await;
            wait_marker(&tmp.path().join("late-writer-done")).await;
        }
    }

    #[tokio::test]
    async fn presence_observation_uses_original_deadline_and_cancellation_budget() {
        for cancel_probe in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let marker = tmp.path().join("ls-entered");
            let runtime = failed_id_probe_runtime(
                tmp.path(),
                false,
                Some(&format!(
                    "open({marker:?},'w').close(); os.execl('/bin/sleep','sleep','30')"
                )),
            );
            let cancel = CancellationToken::new();
            let deadline = Instant::now() + Duration::from_secs(if cancel_probe { 5 } else { 1 });
            let (result, ()) =
                tokio::join!(runtime.validate_sandbox("abcd", deadline, &cancel), async {
                    wait_marker(&marker).await;
                    if cancel_probe {
                        cancel.cancel();
                    }
                });
            assert!(matches!(result, Err(RuntimeError::Incompatible(_))));
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("presence could not be confirmed")
            );
            if !cancel_probe {
                assert!(Instant::now() < deadline + Duration::from_secs(1));
            }
            assert!(!tmp.path().join("workload").exists());
        }
        for canceled in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let runtime = failed_id_probe_runtime(tmp.path(), false, None);
            let cancel = CancellationToken::new();
            let deadline = if canceled {
                cancel.cancel();
                Instant::now() + Duration::from_secs(5)
            } else {
                Instant::now() - Duration::from_secs(1)
            };
            assert!(matches!(
                runtime.validate_sandbox("abcd", deadline, &cancel).await,
                Err(RuntimeError::Incompatible(_))
            ));
            assert!(
                !tmp.path().join("calls").exists(),
                "probe or ls launched without budget"
            );
        }
    }

    async fn execute(runtime: &DirectKilnRuntime) -> ExecOutcome {
        let argv = vec!["--status-fd=999".into(), "ignored".into()];
        runtime
            .exec_direct(
                "abcd",
                &ExecSpec {
                    argv: &argv,
                    stdin: b"",
                    deadline: Instant::now() + Duration::from_secs(5),
                    max_output: 1024,
                    options: &kilnd_exec_core::exec_options::ExecOptions::EMPTY,
                },
                &CancellationToken::new(),
            )
            .await
    }

    async fn wait_marker(path: &Path) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !path.exists() {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("fixture did not reach marker");
    }

    fn failure_frame(kind: u16, stage: u16, cleanup: u8, message: &str) -> Vec<u8> {
        let mut bytes = super::super::kiln_protocol::tests::exit125();
        bytes[12..16].copy_from_slice(&(24u32 + message.len() as u32).to_le_bytes());
        bytes[16] = 2;
        bytes[17] = 0;
        bytes[18] = cleanup;
        bytes[20..24].fill(0);
        bytes[24..26].copy_from_slice(&kind.to_le_bytes());
        bytes[26..28].copy_from_slice(&stage.to_le_bytes());
        bytes[28..32].copy_from_slice(&5i32.to_le_bytes());
        bytes[32..36].copy_from_slice(&(message.len() as u32).to_le_bytes());
        bytes.extend_from_slice(message.as_bytes());
        bytes
    }

    #[tokio::test]
    async fn received_runtime_failure_wins_cancellation_and_timeout_while_cli_is_alive() {
        for (timeout, kind, stage, cleanup) in
            [(false, 6, 8, 1), (false, 9, 10, 0), (true, 9, 10, 0)]
        {
            let tmp = tempfile::tempdir().unwrap();
            let marker = tmp.path().join("ready");
            let frame = failure_frame(kind, stage, cleanup, "trusted PID1 failure");
            let runtime = fixture_runtime(
                tmp.path(),
                &format!(
                    "os.write(OUT,b'\\x00out'); os.write(ERR,b'\\xfferr'); os.write(STATUS,bytes({frame:?})); os.close(STATUS); open({marker:?},'w').close(); time.sleep(30)"
                ),
            );
            if cleanup == 1 {
                fs::remove_file(runtime.cgroup_root.join("abcd/exec/cgroup.events")).unwrap();
            }
            let argv = vec!["ignored".into()];
            let cancel = CancellationToken::new();
            let spec = ExecSpec {
                argv: &argv,
                stdin: b"",
                deadline: Instant::now() + Duration::from_secs(if timeout { 1 } else { 5 }),
                max_output: 1024,
                options: &kilnd_exec_core::exec_options::ExecOptions::EMPTY,
            };
            let (out, ()) = tokio::join!(runtime.exec_direct("abcd", &spec, &cancel), async {
                wait_marker(&marker).await;
                if !timeout {
                    cancel.cancel();
                }
            });
            let d = out.finish.unwrap_err();
            assert_eq!(
                d.kind,
                if kind == 9 {
                    Kind::CleanupFailed
                } else {
                    Kind::LaunchFailed
                }
            );
            assert_eq!(d.message, "trusted PID1 failure");
            assert_eq!(d.native_code.as_deref(), Some("errno:5"));
            assert_eq!(out.stdout.data, b"\0out");
            assert_eq!(out.stderr.data, b"\xfferr");
            assert!(out.command_status.is_none());
        }
    }

    #[tokio::test]
    async fn late_failure_frame_settles_after_kill_and_retains_cleanup_proof() {
        for (timeout, kind, stage, cleanup) in
            [(false, 6, 8, 1), (false, 9, 10, 0), (true, 9, 10, 0)]
        {
            let tmp = tempfile::tempdir().unwrap();
            let marker = tmp.path().join("ready");
            let frame = failure_frame(kind, stage, cleanup, "late PID1 failure");
            let runtime = fixture_runtime(
                tmp.path(),
                &format!(
                    "payload=bytes({frame:?})\nos.write(OUT,b'\\x00out'); os.write(ERR,b'\\xfferr')\nparent=os.getpid()\nif os.fork()==0:\n    while os.getppid()==parent: time.sleep(.002)\n    os.write(STATUS,payload[:10])\n    time.sleep(.05)\n    os.write(STATUS,payload[10:])\n    os.close(STATUS)\n    os._exit(0)\nopen({marker:?},'w').close()\ntime.sleep(30)"
                ),
            );
            if cleanup == 1 {
                fs::remove_file(runtime.cgroup_root.join("abcd/exec/cgroup.events")).unwrap();
            }
            let argv = vec!["ignored".into()];
            let cancel = CancellationToken::new();
            let spec = ExecSpec {
                argv: &argv,
                stdin: b"",
                deadline: Instant::now() + Duration::from_secs(if timeout { 1 } else { 5 }),
                max_output: 1024,
                options: &kilnd_exec_core::exec_options::ExecOptions::EMPTY,
            };
            let (out, ()) = tokio::join!(runtime.exec_direct("abcd", &spec, &cancel), async {
                wait_marker(&marker).await;
                if !timeout {
                    cancel.cancel();
                }
            });
            let d = out.finish.unwrap_err();
            assert_eq!(
                d.kind,
                if kind == 9 {
                    Kind::CleanupFailed
                } else {
                    Kind::LaunchFailed
                }
            );
            assert_eq!(d.message, "late PID1 failure");
            assert_eq!(d.native_code.as_deref(), Some("errno:5"));
            assert_eq!(out.stdout.data, b"\0out");
            assert_eq!(out.stderr.data, b"\xfferr");
        }
    }

    #[tokio::test]
    async fn canceled_exec_keeps_expected_empty_eof_but_rejects_received_malformed_status() {
        for (status, expected) in [
            ("b''", Ok(ExecFinish::Canceled)),
            ("b'bad'", Err(Kind::Protocol)),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let marker = tmp.path().join("ready");
            let runtime = fixture_runtime(
                tmp.path(),
                &format!(
                    "os.write(OUT,b'saved'); os.write(STATUS,{status}); open({marker:?},'w').close(); time.sleep(30)"
                ),
            );
            let argv = vec!["ignored".into()];
            let cancel = CancellationToken::new();
            let spec = ExecSpec {
                argv: &argv,
                stdin: b"",
                deadline: Instant::now() + Duration::from_secs(5),
                max_output: 1024,
                options: &kilnd_exec_core::exec_options::ExecOptions::EMPTY,
            };
            let (out, ()) = tokio::join!(runtime.exec_direct("abcd", &spec, &cancel), async {
                wait_marker(&marker).await;
                cancel.cancel();
            });
            assert_eq!(out.finish.map_err(|d| d.kind), expected);
            assert_eq!(out.stdout.data, b"saved");
        }
    }

    #[tokio::test]
    async fn late_command_proof_preserves_status_without_erasing_cancellation() {
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("ready");
        let runtime = fixture_runtime(
            tmp.path(),
            &format!(
                "parent=os.getpid()\nif os.fork()==0:\n    while os.getppid()==parent: time.sleep(.002)\n    os.write(STATUS,EXIT125)\n    os._exit(0)\nopen({marker:?},'w').close()\ntime.sleep(30)"
            ),
        );
        fs::remove_file(runtime.cgroup_root.join("abcd/exec/cgroup.events")).unwrap();
        let argv = vec!["ignored".into()];
        let cancel = CancellationToken::new();
        let spec = ExecSpec {
            argv: &argv,
            stdin: b"",
            deadline: Instant::now() + Duration::from_secs(5),
            max_output: 1024,
            options: &kilnd_exec_core::exec_options::ExecOptions::EMPTY,
        };
        let (out, ()) = tokio::join!(runtime.exec_direct("abcd", &spec, &cancel), async {
            wait_marker(&marker).await;
            cancel.cancel();
        });
        assert_eq!(out.finish, Ok(ExecFinish::Canceled));
        assert_eq!(out.command_status, Some(CommandStatus::Exited(125)));
    }

    #[tokio::test]
    async fn typed_exit125_exit143_signal15_and_bootstrap_failure() {
        for (body, expected_status, expected_error) in [
            (
                "os.write(OUT,b'\\x00\\xffout'); os.write(ERR,b'\\x00\\xfeerr'); os.write(STATUS,EXIT125); sys.exit(125)",
                Some(CommandStatus::Exited(125)),
                None,
            ),
            (
                "f=bytearray(EXIT125); f[20]=143; os.write(STATUS,f); sys.exit(143)",
                Some(CommandStatus::Exited(143)),
                None,
            ),
            (
                "f=bytearray(EXIT125); f[17]=2; f[20]=15; os.write(STATUS,f); sys.exit(143)",
                Some(CommandStatus::Signaled {
                    signal: 15,
                    core_dumped: false,
                }),
                None,
            ),
            (
                "f=bytearray(EXIT125); f[16]=2; f[17]=0; f[20]=0; f[24]=6; f[26]=8; f[28]=2; os.write(OUT,b'prior'); os.write(STATUS,f); sys.exit(127)",
                None,
                Some((Kind::LaunchFailed, Stage::Exec)),
            ),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let runtime = fixture_runtime(tmp.path(), body);
            let outcome = execute(&runtime).await;
            assert_eq!(outcome.command_status, expected_status);
            match expected_error {
                None => assert_eq!(outcome.finish, Ok(ExecFinish::Completed)),
                Some((kind, stage)) => {
                    let e = outcome.finish.unwrap_err();
                    assert_eq!((e.kind, e.stage), (kind, stage));
                    assert_eq!(e.native_code.as_deref(), Some("errno:2"));
                    assert_eq!(outcome.stdout.data, b"prior");
                }
            }
            if expected_status == Some(CommandStatus::Exited(125)) {
                assert_eq!(outcome.stdout.data, b"\0\xffout");
                assert_eq!(outcome.stderr.data, b"\0\xfeerr");
            }
        }
    }

    #[tokio::test]
    async fn malformed_missing_trailing_unsupported_and_abnormal_cli_preserve_output() {
        for status in [
            "b''",
            "b'bad'",
            "EXIT125[:20]",
            "EXIT125+b'x'",
            "EXIT125+EXIT125",
            "EXIT125[:8]+b'\\x02'+EXIT125[9:]",
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let runtime = fixture_runtime(
                tmp.path(),
                &format!(
                    "os.write(OUT,b'\\x00out'); os.write(ERR,b'\\xfferr'); os.write(2,b'CLI diagnostic'); os.write(STATUS,{status}); sys.exit(125)"
                ),
            );
            let out = execute(&runtime).await;
            assert_eq!(
                out.finish.as_ref().unwrap_err().kind,
                Kind::Protocol,
                "{status}: {out:?}"
            );
            assert_eq!(out.stdout.data, b"\0out");
            assert_eq!(out.stderr.data, b"\xfferr");
        }
        for ending in ["sys.exit(0)", "os.kill(os.getpid(),signal.SIGKILL)"] {
            let tmp = tempfile::tempdir().unwrap();
            let runtime = fixture_runtime(
                tmp.path(),
                &format!("os.write(OUT,b'saved'); os.write(STATUS,EXIT125); {ending}"),
            );
            let out = execute(&runtime).await;
            assert_eq!(out.finish.unwrap_err().kind, Kind::Protocol);
            assert_eq!(out.command_status, Some(CommandStatus::Exited(125)));
            assert_eq!(out.stdout.data, b"saved");
        }
    }

    #[tokio::test]
    async fn malformed_status_kills_a_hung_cli_without_waiting_for_exec_deadline() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = fixture_runtime(
            tmp.path(),
            "os.write(OUT,b'saved'); os.write(STATUS,b'bad'); os.close(STATUS); time.sleep(30)",
        );
        let out = tokio::time::timeout(Duration::from_secs(2), execute(&runtime))
            .await
            .expect("malformed status waited for the execution deadline");
        assert_eq!(out.finish.unwrap_err().kind, Kind::Protocol);
        assert_eq!(out.stdout.data, b"saved");
    }

    #[tokio::test]
    async fn capture_settlement_failure_keeps_observed_status_and_binary_output() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = fixture_runtime(
            tmp.path(),
            "os.write(OUT,b'\\x00\\xffout'); os.write(ERR,b'\\x00\\xfeerr'); os.write(STATUS,EXIT125); os.close(STATUS)\nif os.fork()==0:\n    time.sleep(3)\n    sys.exit(0)\nsys.exit(125)",
        );
        let out = execute(&runtime).await;
        let d = out.finish.unwrap_err();
        assert_eq!((d.kind, d.stage), (Kind::Io, Stage::Capture));
        assert_eq!(out.command_status, Some(CommandStatus::Exited(125)));
        assert_eq!(out.stdout.data, b"\0\xffout");
        assert_eq!(out.stdout.total_bytes, 5);
        assert!(!out.stdout.total_bytes_known);
        assert_eq!(out.stderr.data, b"\0\xfeerr");
        assert_eq!(out.stderr.total_bytes, 5);
        assert!(!out.stderr.total_bytes_known);
        tokio::time::sleep(Duration::from_millis(1100)).await;
    }

    #[tokio::test]
    async fn old_cli_misleading_version_and_old_pid1_never_launch() {
        for mode in ["legacy", "misleading", "old-pid1", "new-frame-version"] {
            let tmp = tempfile::tempdir().unwrap();
            let marker = tmp.path().join("workload");
            let runtime = fixture_runtime(
                tmp.path(),
                &format!("open({marker:?},'w').close()\nos.write(STATUS,EXIT125)\nsys.exit(125)"),
            );
            let mut source = fs::read_to_string(&runtime.bin).unwrap();
            source = match mode {
                "legacy" => "#!/bin/sh\necho 'unknown capabilities' >&2\nexit 2\n".into(),
                "misleading" => "#!/bin/sh\necho 'kiln 99.0 modern'\nexit 0\n".into(),
                "old-pid1" => source.replace(
                    "os.write(1,CAPS)",
                    "os.write(1, CAPS if len(sys.argv)==3 else b'legacy PID1')",
                ),
                _ => source.replace(
                    "os.write(1,CAPS)",
                    "os.write(1, CAPS[:8]+b'\\x02'+CAPS[9:])",
                ),
            };
            fs::write(&runtime.bin, source).unwrap();
            let out = execute(&runtime).await;
            let error = out.finish.unwrap_err();
            assert_eq!(
                (error.kind, error.stage),
                (Kind::Incompatible, Stage::Handshake)
            );
            assert!(error.message.contains(runtime.bin.path().to_str().unwrap()));
            if mode == "old-pid1" {
                assert!(error.message.contains("sandbox abcd"));
            }
            assert!(!marker.exists());
        }
    }

    #[tokio::test]
    async fn pre_canceled_and_expired_exec_never_probe_or_spawn() {
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("called");
        let bin = tmp.path().join("kiln");
        fs::write(
            &bin,
            format!("#!/bin/sh\ntouch '{marker}'\n", marker = marker.display()),
        )
        .unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        let runtime = DirectKilnRuntime::new(bin);
        let argv = vec!["true".into()];
        let cancel = CancellationToken::new();
        cancel.cancel();
        let mut spec = ExecSpec {
            argv: &argv,
            stdin: b"",
            deadline: Instant::now() + Duration::from_secs(5),
            max_output: 1,
            options: &kilnd_exec_core::exec_options::ExecOptions::EMPTY,
        };
        assert_eq!(
            runtime.exec_direct("abcd", &spec, &cancel).await.finish,
            Ok(ExecFinish::Canceled)
        );
        spec.deadline = Instant::now() - Duration::from_secs(1);
        assert_eq!(
            runtime
                .exec_direct("abcd", &spec, &CancellationToken::new())
                .await
                .finish,
            Ok(ExecFinish::TimedOut)
        );
        assert!(!marker.exists());
    }

    /// `capabilities_v1` advertises only the execution bits globally. Every
    /// call is traced; `body` is the whole `create` branch of the fixture.
    fn create_fixture(tmp: &Path, capabilities_v1: bool, body: &str) -> DirectKilnRuntime {
        let runtime = fixture_runtime(tmp, "sys.exit(0)");
        let trace = tmp.join("calls");
        let mut source = fs::read_to_string(&runtime.bin).unwrap().replace(
            "if sys.argv[1]=='capabilities':",
            &format!(
                "open({trace:?},'a').write(' '.join(sys.argv[1:])+'\\n')\nif sys.argv[1]=='ls':\n    os.write(1,b'ID\\tSTATUS\\tSHIM\\n'); sys.exit(0)\nif sys.argv[1]=='create':\n    {body}\nif sys.argv[1]=='capabilities':"
            ),
        );
        if capabilities_v1 {
            source = source.replace(
                "os.write(1,CAPS)",
                "os.write(1,CAPS[:16]+b'\\x0f'+CAPS[17:])",
            );
        }
        fs::write(&runtime.bin, source).unwrap();
        runtime
    }

    fn calls(tmp: &Path) -> Vec<String> {
        fs::read_to_string(tmp.join("calls"))
            .unwrap_or_default()
            .lines()
            .map(|call| call.split(' ').next().unwrap().to_string())
            .collect()
    }

    #[tokio::test]
    async fn trusted_create_exit_124_is_definite_after_the_feature_gate() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = create_fixture(
            tmp.path(),
            false,
            "os.write(2,b'image missing'); sys.exit(124)",
        );
        let failure = runtime.create_now(&spec(Network::None)).await.unwrap_err();
        assert_eq!(failure.certainty(), CreateCertainty::DefinitelyNotCreated);
        assert!(failure.to_string().contains("image missing"), "{failure}");
        // The gate runs for this exact create, then the flagged create follows.
        let trace = fs::read_to_string(tmp.path().join("calls")).unwrap();
        assert!(
            trace.starts_with(
                "capabilities --protocol=1\ngc --help\ncreate --require-exec-protocol=1 "
            ),
            "{trace}"
        );
    }

    #[tokio::test]
    async fn every_other_create_failure_stays_ambiguous() {
        for body in [
            // Generic and nearby statuses, including text that claims certainty.
            "sys.exit(1)",
            "sys.exit(123)",
            "sys.exit(125)",
            "os.write(2,b'definitely not created: preflight exit 124'); sys.exit(1)",
            // Signals, including one whose shell projection could be mistaken.
            "os.kill(os.getpid(),signal.SIGKILL)",
            "os.kill(os.getpid(),signal.SIGTERM)",
            // Malformed success, including a success that prints a real-looking
            // failure and an ID followed by junk.
            "sys.exit(0)",
            "print('not a kiln id'); sys.exit(0)",
            "print('abcd'); print('abcd'); sys.exit(0)",
            "os.write(2,b'image missing'); sys.exit(0)",
            // Exit 124 contradicted by an ID or by a descendant holding output.
            "print('abcd'); sys.exit(124)",
            "os.write(1,b'x'); sys.exit(124)",
            "\n    if os.fork()==0:\n        time.sleep(.6)\n        os._exit(0)\n    sys.exit(124)",
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let runtime = create_fixture(tmp.path(), false, body);
            let failure = runtime.create_now(&spec(Network::None)).await.unwrap_err();
            assert_eq!(
                failure.certainty(),
                CreateCertainty::AllocationAmbiguous,
                "{body}: {failure}"
            );
            assert!(calls(tmp.path()).contains(&"create".to_string()), "{body}");
        }
    }

    #[tokio::test]
    async fn create_succeeds_with_the_unchanged_id_format() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = create_fixture(
            tmp.path(),
            false,
            "print('18de453339a8cc89-3762'); sys.exit(0)",
        );
        assert_eq!(
            runtime.create_now(&spec(Network::None)).await.unwrap(),
            "18de453339a8cc89-3762"
        );
    }

    #[tokio::test]
    async fn an_unspawnable_create_after_the_gate_stays_ambiguous() {
        // The attempt began: this is not separable from a wait failure.
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("kiln");
        let runtime = create_fixture(tmp.path(), false, "sys.exit(0)");
        let source = fs::read_to_string(&bin).unwrap().replace(
            "if sys.argv[1:]==['gc','--help']:",
            &format!("if sys.argv[1:]==['gc','--help']:\n    os.remove({bin:?})"),
        );
        fs::write(&bin, source).unwrap();
        let failure = runtime.create_now(&spec(Network::None)).await.unwrap_err();
        assert!(matches!(failure.error(), RuntimeError::Io(_)), "{failure}");
        assert_eq!(failure.certainty(), CreateCertainty::AllocationAmbiguous);
    }

    #[tokio::test]
    async fn create_deadline_and_cancellation_stay_ambiguous_and_reap_the_child() {
        for cancel_create in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let marker = tmp.path().join("create-entered");
            let pid_file = tmp.path().join("pid");
            let runtime = create_fixture(
                tmp.path(),
                false,
                &format!(
                    "open({pid_file:?},'w').write(str(os.getpid())); open({marker:?},'w').close(); time.sleep(30)"
                ),
            );
            let cancel = CancellationToken::new();
            let deadline = Instant::now() + Duration::from_secs(if cancel_create { 20 } else { 1 });
            let sandbox_spec = spec(Network::None);
            let (result, ()) = tokio::join!(
                runtime.create_until(&sandbox_spec, deadline, &cancel),
                async {
                    wait_marker(&marker).await;
                    if cancel_create {
                        cancel.cancel();
                    }
                }
            );
            let failure = result.unwrap_err();
            assert_eq!(failure.certainty(), CreateCertainty::AllocationAmbiguous);
            assert!(Instant::now() < deadline + Duration::from_secs(1));
            let pid: libc::pid_t = fs::read_to_string(pid_file).unwrap().parse().unwrap();
            // SAFETY: signal zero only tests whether the recorded process exists.
            assert_eq!(unsafe { libc::kill(pid, 0) }, -1, "create child survived");
        }
    }

    #[tokio::test]
    async fn the_gate_is_definite_only_because_no_create_process_started() {
        // A legacy CLI cannot have exit 124 trusted, or even be asked to create.
        let tmp = tempfile::tempdir().unwrap();
        let runtime = create_fixture(tmp.path(), true, "print('abcd'); sys.exit(124)");
        let failure = runtime.create_now(&spec(Network::None)).await.unwrap_err();
        assert_eq!(failure.certainty(), CreateCertainty::DefinitelyNotCreated);
        assert!(matches!(failure.error(), RuntimeError::Incompatible(_)));
        assert!(failure.to_string().contains("0x10"), "{failure}");
        assert_eq!(calls(tmp.path()), ["capabilities"]);

        // A spent budget refuses before launching even the capability probe.
        let tmp = tempfile::tempdir().unwrap();
        let runtime = create_fixture(tmp.path(), false, "print('abcd'); sys.exit(0)");
        let cancel = CancellationToken::new();
        cancel.cancel();
        let failure = runtime
            .create_until(
                &spec(Network::None),
                Instant::now() + QUERY_TIMEOUT,
                &cancel,
            )
            .await
            .unwrap_err();
        assert_eq!(failure.certainty(), CreateCertainty::DefinitelyNotCreated);
        assert!(calls(tmp.path()).is_empty());
    }

    #[tokio::test]
    async fn create_requirement_rejects_old_replacement_before_resource_side_effect() {
        // The gate passes, then a binary without the flag replaces the CLI.
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("resource");
        let runtime = create_fixture(
            tmp.path(),
            false,
            &format!(
                "\n    if '--require-exec-protocol=1' in sys.argv:\n        os.write(2,b'unexpected argument'); sys.exit(2)\n    open({marker:?},'w').close(); print('abcd'); sys.exit(0)"
            ),
        );
        let failure = runtime.create_now(&spec(Network::None)).await.unwrap_err();
        assert_eq!(failure.certainty(), CreateCertainty::AllocationAmbiguous);
        assert!(!marker.exists());
    }

    #[tokio::test]
    async fn global_gate_requires_certainty_but_live_pid1_does_not() {
        use crate::manager::{Limits, Manager};
        use crate::store::Store;
        // An old PID 1 only advertises the execution bits and stays usable.
        let tmp = tempfile::tempdir().unwrap();
        let runtime = create_fixture(tmp.path(), false, "sys.exit(1)");
        let source = fs::read_to_string(&runtime.bin).unwrap().replace(
            "os.write(1,CAPS)",
            "os.write(1,CAPS if len(sys.argv)==3 else CAPS[:16]+b'\\x0f'+CAPS[17:])",
        );
        fs::write(&runtime.bin, source).unwrap();
        let cancel = CancellationToken::new();
        let deadline = Instant::now() + QUERY_TIMEOUT;
        runtime.version(deadline, &cancel).await.unwrap();
        runtime
            .validate_sandbox("abcd", deadline, &cancel)
            .await
            .unwrap();

        // A CLI without the bit is refused before reconciliation looks at
        // anything, and a usable-looking per-ID frame cannot substitute for it.
        let tmp = tempfile::tempdir().unwrap();
        let runtime = create_fixture(tmp.path(), true, "sys.exit(1)");
        let error = runtime.version(deadline, &cancel).await.unwrap_err();
        assert!(matches!(error, RuntimeError::Incompatible(_)), "{error}");
        assert!(error.to_string().contains("0x10"), "{error}");
        let manager = Manager::new(runtime, Store::open_in_memory().unwrap(), Limits::default());
        assert!(manager.reconcile().await.is_err());
        assert_eq!(calls(tmp.path()).last().unwrap(), "capabilities");
        assert!(!calls(tmp.path()).contains(&"ls".to_string()));
        assert!(!calls(tmp.path()).contains(&"gc".to_string()));
    }

    #[tokio::test]
    async fn manager_releases_only_a_trusted_exit_124_across_restart() {
        use crate::manager::{CreateRequest, Error, Limits, Manager};
        use crate::model::SandboxState;
        use crate::store::Store;
        for (body, definite) in [
            ("os.write(2,b'image missing'); sys.exit(124)", true),
            ("os.write(2,b'image missing'); sys.exit(1)", false),
            ("print('not an id'); sys.exit(0)", false),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let state = tmp.path().join("state");
            let bin = create_fixture(tmp.path(), false, body)
                .bin
                .path()
                .to_path_buf();
            let root = tmp.path().join("cgroup");
            let limits = Limits {
                max_sandboxes: 1,
                ..Limits::default()
            };
            let manager = Arc::new(Manager::new(
                DirectKilnRuntime::with_cgroup_root(bin.clone(), &root),
                Store::open(&state).unwrap(),
                limits.clone(),
            ));
            manager.create(CreateRequest::default()).await.unwrap_err();
            let id = manager.list(true).unwrap().remove(0).id;
            drop(manager);

            let manager = Arc::new(Manager::new(
                DirectKilnRuntime::with_cgroup_root(bin, &root),
                Store::reopen_after_restart(&state),
                limits,
            ));
            let reconciled = manager.reconcile().await.unwrap();
            assert_eq!(reconciled, Default::default());
            let row = manager.get(&id, 0).unwrap().0;
            assert_eq!((row.state, row.backend_id), (SandboxState::Failed, None));
            let reserved = manager.health().await.unwrap().node_resources.reserved;
            assert_eq!(reserved.sandboxes, u64::from(!definite), "{body}");
            if definite {
                let deleted = manager.delete(&id).await.unwrap();
                assert_eq!(deleted.state, SandboxState::Deleted);
                assert!(!calls(tmp.path()).contains(&"rm".to_string()));
            } else {
                assert!(matches!(
                    manager.delete(&id).await,
                    Err(Error::FailedPrecondition(_))
                ));
                let next = manager.create(CreateRequest::default()).await.unwrap_err();
                assert!(matches!(next, Error::ResourceExhausted(_)), "{next}");
            }
        }
    }

    #[tokio::test]
    async fn scoped_gc_compatibility_rejects_legacy_cli_before_reconciliation() {
        use crate::manager::{Limits, Manager};
        use crate::store::Store;
        for help in ["Usage: kiln gc\n", "Usage: kiln gc [ID]...\n"] {
            let tmp = tempfile::tempdir().unwrap();
            let runtime = fixture_runtime(tmp.path(), "sys.exit(0)");
            let trace = tmp.path().join("calls");
            let source = fs::read_to_string(&runtime.bin).unwrap().replace(
                "if sys.argv[1]=='capabilities':",
                &format!("open({trace:?},'a').write(' '.join(sys.argv[1:])+'\\n')\nif sys.argv[1]=='gc' and sys.argv[2:]==['--help']:\n    print({help:?},end='')\n    sys.exit(0)\nif sys.argv[1]=='capabilities':"),
            );
            fs::write(&runtime.bin, source).unwrap();
            let result = runtime
                .version(Instant::now() + QUERY_TIMEOUT, &CancellationToken::new())
                .await;
            if help.contains("[ID]...") {
                assert!(result.is_ok(), "{result:?}");
            } else {
                let error = result.unwrap_err();
                assert!(matches!(error, RuntimeError::Incompatible(_)));
                assert!(error.to_string().contains("scoped gc"), "{error}");
                let manager =
                    Manager::new(runtime, Store::open_in_memory().unwrap(), Limits::default());
                assert!(manager.reconcile().await.is_err());
                assert!(manager.list(true).unwrap().is_empty());
            }
            let calls = fs::read_to_string(trace).unwrap();
            assert!(calls.contains("gc --help\n"));
            assert!(
                calls
                    .lines()
                    .all(|call| call == "capabilities --protocol=1" || call == "gc --help")
            );
        }
    }

    #[tokio::test]
    async fn capability_frame_without_eof_is_incompatible() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = fixture_runtime(tmp.path(), "sys.exit(0)");
        let source = fs::read_to_string(&runtime.bin)
            .unwrap()
            .replace("os.write(1,CAPS)", "os.write(1,CAPS)\n    time.sleep(.5)");
        fs::write(&runtime.bin, source).unwrap();
        let error = runtime
            .version(
                Instant::now() + Duration::from_millis(100),
                &CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, RuntimeError::Incompatible(_)));
        assert!(error.to_string().contains("deadline expired"));
    }

    #[tokio::test]
    async fn malformed_status_waits_for_cleanup_and_delayed_output() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = fixture_runtime(
            tmp.path(),
            "os.write(OUT,b'before')\nif os.fork()==0:\n    os.close(STATUS)\n    time.sleep(.4)\n    os.write(OUT,b'after')\n    sys.exit(0)\nos.write(STATUS,b'bad'); os.close(STATUS); sys.exit(125)",
        );
        let events = runtime.cgroup_root.join("abcd/exec/cgroup.events");
        fs::write(&events, "populated 1\n").unwrap();
        let start = Instant::now();
        let (out, ()) = tokio::join!(execute(&runtime), async {
            tokio::time::sleep(Duration::from_millis(600)).await;
            set_events(&events, "populated 0\n");
        });
        assert!(start.elapsed() >= Duration::from_millis(600));
        assert_eq!(out.disposition, SandboxDisposition::Reusable);
        assert_eq!(out.cleanup, CleanupEvidence::RuntimeDrained);
        assert_eq!(out.finish.unwrap_err().kind, Kind::Protocol);
        assert_eq!(out.stdout.data, b"beforeafter");
        assert_eq!(out.stdout.total_bytes, 11);
        assert!(out.stdout.total_bytes_known);
    }

    #[tokio::test]
    async fn cleanup_failure_overrides_but_keeps_status_and_captures() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = fixture_runtime(
            tmp.path(),
            "f=bytearray(EXIT125); f[16]=2; f[18]=0; f[24]=9; f[26]=10; os.write(OUT,b'saved'); os.write(STATUS,f); sys.exit(125)",
        );
        fs::remove_file(runtime.cgroup_root.join("abcd/exec/cgroup.events")).unwrap();
        let out = execute(&runtime).await;
        assert_eq!(out.disposition, SandboxDisposition::Quarantined);
        assert_eq!(out.cleanup, CleanupEvidence::Unknown);
        assert_eq!(
            (
                out.finish.as_ref().unwrap_err().kind,
                out.finish.as_ref().unwrap_err().stage
            ),
            (Kind::CleanupFailed, Stage::Cleanup)
        );
        assert_eq!(out.command_status, Some(CommandStatus::Exited(125)));
        assert_eq!(out.stdout.data, b"saved");
    }

    #[tokio::test]
    async fn replacement_between_handshake_and_exec_rejects_before_workload() {
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("workload");
        let runtime = fixture_runtime(tmp.path(), &format!("open({marker:?},'w').close()"));
        let source=fs::read_to_string(&runtime.bin).unwrap().replace("os.write(1,CAPS)",&format!("if len(sys.argv)>3:\n        open({:?},'w').write('#!/bin/sh\\necho old-binary-rejects-protocol >&2\\nexit 2\\n')\n    os.write(1,CAPS)",runtime.bin.path()));
        fs::write(&runtime.bin, source).unwrap();
        let out = execute(&runtime).await;
        assert_eq!(out.finish.unwrap_err().kind, Kind::Protocol);
        assert!(!marker.exists());
    }

    fn spec(network: Network) -> SandboxSpec {
        SandboxSpec {
            image: "alpine".into(),
            memory_bytes: 64 << 20,
            cpu_millis: 500,
            pids: 32,
            disk_bytes: 16 << 20,
            network,
            read_only_root: false,
            writable_paths: vec![],
            labels: BTreeMap::new(),
        }
    }

    #[test]
    fn create_args_use_flag_equals_value() {
        assert_eq!(
            create_args(&spec(Network::None)),
            [
                "create",
                "--require-exec-protocol=1",
                "--image=alpine",
                "--memory=67108864",
                "--cpus=0.500",
                "--pids=32",
                "--disk=16777216",
                "--net=none"
            ]
        );
        let mut s = spec(Network::Allow(vec![
            "example.com:443".into(),
            "--net=full".into(),
        ]));
        s.cpu_millis = 2000;
        s.read_only_root = true;
        s.writable_paths = vec!["/data".into()];
        let args = create_args(&s);
        assert!(args.contains(&"--cpus=2.000".to_string()));
        assert!(args.contains(&"--allow=example.com:443".to_string()));
        // A hostile value stays the value of --allow.
        assert!(args.contains(&"--allow=--net=full".to_string()));
        assert!(!args.contains(&"--net=full".to_string()));
        assert!(args.ends_with(&["--read-only".to_string(), "--writable=/data".to_string()]));
        assert!(create_args(&spec(Network::Full)).contains(&"--net=full".to_string()));
    }

    #[test]
    fn parses_ls() {
        let got = parse_ls("ID\tSTATUS\tSHIM\n18de-1\trunning\t42\nab-2\tstale\t7\n").unwrap();
        assert_eq!(
            got,
            [
                BackendSandbox {
                    id: "18de-1".into(),
                    status: BackendStatus::Running
                },
                BackendSandbox {
                    id: "ab-2".into(),
                    status: BackendStatus::Stale
                },
            ]
        );
        assert_eq!(parse_ls("ID\tSTATUS\tSHIM\n").unwrap(), []);
        assert!(parse_ls("").is_err());
        assert!(parse_ls("NAME\tSTATE\n").is_err());
        assert!(parse_ls("ID\tSTATUS\tSHIM\nab-1\tzombie\t3\n").is_err());
        assert!(parse_ls("ID\tSTATUS\tSHIM\n../etc\trunning\t3\n").is_err());
        assert!(parse_ls("ID\tSTATUS\tSHIM\nab-1\trunning\t3").is_err());
        assert!(parse_ls("ID\tSTATUS\tSHIM\nab-1\trunning\n").is_err());
        assert!(parse_ls("ID\tSTATUS\tSHIM\nab-1\trunning\t3\textra\n").is_err());
        assert!(parse_ls("ID\tSTATUS\tSHIM\nab-1\trunning\tpid\n").is_err());
        assert!(parse_ls("ID\tSTATUS\tSHIM\nab-1\trunning\t3\nab-1\trunning\t3\n").is_err());
    }

    #[test]
    fn summarizes_stderr_as_one_line() {
        assert_eq!(
            summarize(b"Error: connect\n\nCaused by:\n    gone\n"),
            "Error: connect; Caused by:; gone"
        );
        assert_eq!(summarize(b"bad\x1b[31m"), "bad?[31m");
        assert_eq!(summarize(b""), "no error output");
    }

    #[test]
    fn rejects_bad_ids() {
        for id in ["", "-1", "../x", "ab cd", "ab\n"] {
            assert!(check_id(id).is_err(), "{id:?}");
        }
        assert!(check_id("18de453339a8cc89-3762").is_ok());
    }

    #[tokio::test]
    async fn version_deadline_reaps_the_backend_process_before_returning() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("fake-kiln");
        let pid_file = tmp.path().join("pid");
        fs::write(
            &bin,
            format!(
                "#!/bin/sh\nprintf '%s' \"$$\" > '{}'\nexec sleep 30\n",
                pid_file.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        let runtime = DirectKilnRuntime::new(bin);
        // Long enough for the fixture to record its PID on a loaded machine.
        let error = runtime
            .version(
                Instant::now() + Duration::from_secs(1),
                &CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("deadline expired"), "{error}");
        let pid: libc::pid_t = fs::read_to_string(pid_file).unwrap().parse().unwrap();
        // SAFETY: signal zero only tests whether the recorded process exists.
        let rc = unsafe { libc::kill(pid, 0) };
        assert_eq!(rc, -1, "version process {pid} still exists after timeout");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[tokio::test]
    async fn cancellation_waits_for_the_exec_cgroup_to_be_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("fake-kiln");
        let started = tmp.path().join("started");
        super::super::kiln_process::tests::fixture(
            &bin,
            &format!("open({started:?}, 'w').close()\ntime.sleep(30)"),
        );
        let cgroup_root = tmp.path().join("cgroup");
        let exec_scope = cgroup_root.join("abcd/exec");
        fs::create_dir_all(&exec_scope).unwrap();
        let events = exec_scope.join("cgroup.events");
        fs::write(&events, "populated 1\n").unwrap();

        let runtime = Arc::new(DirectKilnRuntime::with_cgroup_root(bin, &cgroup_root));
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let mut task = tokio::spawn(async move {
            let argv = vec!["sleep".to_string(), "30".to_string()];
            let spec = ExecSpec {
                argv: &argv,
                stdin: b"",
                deadline: Instant::now() + Duration::from_secs(30),
                max_output: 1024,
                options: &kilnd_exec_core::exec_options::ExecOptions::EMPTY,
            };
            runtime.exec_direct("abcd", &spec, &task_cancel).await
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while !started.exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("fake kiln client did not start");

        cancel.cancel();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut task)
                .await
                .is_err(),
            "runtime returned before kiln's execution cgroup was empty"
        );
        set_events(&events, "populated 0\n");
        let outcome = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(outcome.finish, Ok(ExecFinish::Canceled));
    }
}
