//! The broker's only executable is the pinned `/usr/local/bin/kiln`, driven through
//! kilnd's reviewed direct-kiln core (design 5.1): the same capability, create,
//! validation and persistent-exec code kilnd uses on the host, with argv arrays from
//! its typed constructors and the user's argv only after `--`.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;

use kilnd_broker_protocol::message::{
    CaptureFacts, Cleanup, Diagnostic, ExecResult, Finish, GuestExecSpec, KilnFacts, Termination,
};
use kilnd_broker_protocol::{Id128, InnerId, WireText};
use kilnd_exec_core::model::{Captured, CleanupEvidence, Network, SandboxSpec};
use kilnd_exec_core::process::{Finish as ProcessFinish, KilnArgs, KilnBinary};
use kilnd_exec_core::runtime::kiln_direct::{DirectKiln, valid_kiln_id};
use kilnd_exec_core::runtime::{ExecFinish, ExecOutcome, ExecSpec};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// The pinned CLI and kiln's cgroup root inside the guest.
pub const KILN: &str = "/usr/local/bin/kiln";
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup/kiln";
/// The persistent create and the smoke exec together, within a 120 s Create.
pub const INITIALIZE_BUDGET: Duration = Duration::from_secs(100);
const SMOKE_BUDGET: Duration = Duration::from_secs(30);

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// What the transport needs from kiln, so it can be tested against a fake.
pub trait KilnOps {
    /// Validates the CLI, creates the one persistent sandbox and runs a supervised
    /// `true` through the cleanup barrier. Any failure is final for this boot.
    fn initialize<'a>(
        &'a self,
        spec: &'a GuestExecSpec,
    ) -> BoxFuture<'a, Result<(InnerId, KilnFacts), String>>;
    /// One execution in the persistent sandbox.
    fn exec<'a>(
        &'a self,
        inner: &'a InnerId,
        spec: ExecSpec<'a>,
        cancel: &'a CancellationToken,
    ) -> BoxFuture<'a, ExecOutcome>;
    /// B5-04: the persistent sandbox is still alive, cheaply: its init answers kiln's
    /// fixed capability request on its control socket, and its cgroup exists.
    fn alive<'a>(&'a self, inner: &'a InnerId) -> BoxFuture<'a, Result<(), String>>;
}

/// The liveness check's budget, inside the host's two-second Probe stage.
pub const ALIVE_BUDGET: Duration = Duration::from_millis(1500);

pub struct Kiln {
    bin: KilnBinary,
    cgroup_root: PathBuf,
}

impl Kiln {
    pub fn new(bin: PathBuf, cgroup_root: PathBuf) -> Self {
        Self {
            bin: KilnBinary::new(bin),
            cgroup_root,
        }
    }

    fn core(&self) -> DirectKiln<'_> {
        DirectKiln::new(&self.bin, &self.cgroup_root)
    }

    /// The CLI's capability facts, for `HelloReply` before initialization.
    pub async fn probe(&self) -> Result<KilnFacts, String> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let caps = self
            .core()
            .capabilities(None, deadline, &CancellationToken::new())
            .await
            .map_err(|e| e.to_string())?;
        Ok(KilnFacts {
            protocol: u32::from(caps.private_version),
            features: caps.features,
        })
    }

    async fn initialize_inner(&self, spec: &GuestExecSpec) -> Result<(InnerId, KilnFacts), String> {
        spec.validate().map_err(|e| e.to_string())?;
        let deadline = Instant::now() + INITIALIZE_BUDGET;
        let cancel = CancellationToken::new();
        let core = self.core();
        let caps = core
            .capabilities(None, deadline, &cancel)
            .await
            .map_err(|e| format!("kiln capability check: {e}"))?;
        let facts = KilnFacts {
            protocol: u32::from(caps.private_version),
            features: caps.features,
        };
        let out = core
            .run_control(&KilnArgs::create(&sandbox_spec(spec)), deadline, &cancel)
            .await
            .map_err(|e| format!("kiln create: {e}"))?;
        let id = match out.finish {
            ProcessFinish::Exited(status) if status.success() => {
                String::from_utf8_lossy(&out.stdout.data).trim().to_string()
            }
            other => return Err(format!("kiln create did not succeed: {other:?}")),
        };
        if !valid_kiln_id(&id) {
            return Err("kiln create printed no valid sandbox ID".into());
        }
        core.validate_sandbox(&id, deadline, &cancel)
            .await
            .map_err(|e| format!("kiln could not validate the new sandbox: {e}"))?;
        let argv = vec!["true".to_string()];
        let smoke = core
            .exec_direct(
                &id,
                &ExecSpec {
                    argv: &argv,
                    stdin: b"",
                    deadline: deadline.min(Instant::now() + SMOKE_BUDGET),
                    max_output: 4096,
                    options: &kilnd_exec_core::exec_options::ExecOptions::EMPTY,
                    live: None,
                },
                &cancel,
            )
            .await;
        let exited_zero = matches!(
            smoke.command_status,
            Some(kilnd_exec_core::model::CommandStatus::Exited(0))
        );
        if smoke.finish != Ok(ExecFinish::Completed)
            || !exited_zero
            || smoke.cleanup != CleanupEvidence::RuntimeDrained
        {
            return Err(format!(
                "the smoke exec did not complete and drain: {:?} {:?} {:?}",
                smoke.finish, smoke.command_status, smoke.cleanup
            ));
        }
        let inner = InnerId::new(id).ok_or("kiln's sandbox ID is outside the wire grammar")?;
        Ok((inner, facts))
    }
}

impl KilnOps for Kiln {
    fn initialize<'a>(
        &'a self,
        spec: &'a GuestExecSpec,
    ) -> BoxFuture<'a, Result<(InnerId, KilnFacts), String>> {
        Box::pin(self.initialize_inner(spec))
    }

    fn exec<'a>(
        &'a self,
        inner: &'a InnerId,
        spec: ExecSpec<'a>,
        cancel: &'a CancellationToken,
    ) -> BoxFuture<'a, ExecOutcome> {
        Box::pin(async move { self.core().exec_direct(inner.as_str(), &spec, cancel).await })
    }

    fn alive<'a>(&'a self, inner: &'a InnerId) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let deadline = Instant::now() + ALIVE_BUDGET;
            // `kiln capabilities <id>`: the existing fixed argv mapping. It connects to
            // the sandbox's control socket, which only its live init serves.
            self.core()
                .capabilities(Some(inner.as_str()), deadline, &CancellationToken::new())
                .await
                .map_err(|e| format!("the persistent sandbox does not answer: {e}"))?;
            let cgroup = self.cgroup_root.join(inner.as_str());
            match tokio::fs::metadata(&cgroup).await {
                Ok(meta) if meta.is_dir() => Ok(()),
                Ok(_) => Err(format!("{} is not a cgroup", cgroup.display())),
                Err(e) => Err(format!("the persistent sandbox's cgroup is gone: {e}")),
            }
        })
    }
}

/// kilnd's `SandboxSpec` for the label-free spec: `create_args` maps it to
/// `create --require-exec-protocol=1 --image= --memory= --cpus= --pids= --disk=
/// --net=none [--read-only --writable=...]`.
pub fn sandbox_spec(spec: &GuestExecSpec) -> SandboxSpec {
    SandboxSpec {
        image: spec.image.clone(),
        memory_bytes: spec.memory_bytes,
        cpu_millis: spec.cpu_millis,
        pids: spec.pids,
        disk_bytes: spec.disk_bytes,
        network: Network::None,
        read_only_root: spec.read_only_root,
        writable_paths: spec.writable_paths.clone(),
        labels: Default::default(),
    }
}

fn facts_of(captured: &Captured) -> CaptureFacts {
    let kept = captured.data.len() as u64;
    let total = captured.total_bytes.max(kept);
    CaptureFacts {
        kept,
        total,
        total_known: captured.total_bytes_known,
        truncated: total > kept,
    }
}

/// The typed result for one outcome. Only the core's own evidence becomes
/// `GuestCgroupDrained`; nothing is inferred from an exit code or CLI output.
pub fn result_of(token: Id128, inner: &InnerId, outcome: &ExecOutcome) -> ExecResult {
    let (finish, diagnostic) = match &outcome.finish {
        Ok(ExecFinish::Completed) => (Finish::Completed, None),
        Ok(ExecFinish::TimedOut) => (Finish::TimedOut, None),
        Ok(ExecFinish::Canceled) => (Finish::Canceled, None),
        Err(d) => {
            let (message, cut) = WireText::narrow(&d.message);
            (
                Finish::Failed {
                    kind: d.kind,
                    stage: d.stage,
                },
                Some(Diagnostic {
                    kind: d.kind,
                    stage: d.stage,
                    message,
                    message_truncated: d.message_truncated || cut,
                }),
            )
        }
    };
    ExecResult {
        token,
        finish,
        termination: outcome.command_status.as_ref().map(Termination::from),
        diagnostic,
        stdout: facts_of(&outcome.stdout),
        stderr: facts_of(&outcome.stderr),
        cleanup: match outcome.cleanup {
            CleanupEvidence::NoChildStarted => Cleanup::NoChildStarted,
            CleanupEvidence::RuntimeDrained => Cleanup::GuestCgroupDrained,
            CleanupEvidence::Unknown | CleanupEvidence::SandboxStopped => Cleanup::Unknown,
        },
        inner_id: inner.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kilnd_exec_core::model::{
        CommandStatus, RuntimeDiagnostic, RuntimeErrorKind, RuntimeStage, SandboxDisposition,
    };

    #[test]
    fn create_argv_is_the_fixed_mapping_with_flag_equals_values() {
        let spec = crate::session::tests::spec();
        let args = KilnArgs::create(&sandbox_spec(&spec));
        assert_eq!(
            args.as_slice(),
            [
                "create",
                "--require-exec-protocol=1",
                "--image=alpine",
                "--memory=536870912",
                "--cpus=1.000",
                "--pids=128",
                "--disk=1073741824",
                "--net=none"
            ]
        );
        let mut ro = spec;
        ro.read_only_root = true;
        ro.writable_paths = vec!["/workspace".into()];
        let args = KilnArgs::create(&sandbox_spec(&ro));
        assert_eq!(
            &args.as_slice()[8..],
            ["--read-only", "--writable=/workspace"]
        );
    }

    fn outcome(
        finish: Result<ExecFinish, RuntimeDiagnostic>,
        cleanup: CleanupEvidence,
    ) -> ExecOutcome {
        ExecOutcome {
            finish,
            command_status: Some(CommandStatus::Signaled {
                signal: 15,
                core_dumped: false,
            }),
            stdout: Captured {
                data: b"abc".to_vec(),
                total_bytes: 10,
                truncated: true,
                total_bytes_known: true,
            },
            stderr: Captured::known_empty(),
            disposition: SandboxDisposition::Reusable,
            cleanup,
        }
    }

    #[test]
    fn results_carry_only_the_cores_own_evidence() {
        let inner = InnerId::new("abcd").unwrap();
        let r = result_of(
            Id128([1; 16]),
            &inner,
            &outcome(Ok(ExecFinish::Completed), CleanupEvidence::RuntimeDrained),
        );
        assert_eq!(r.finish, Finish::Completed);
        assert_eq!(r.cleanup, Cleanup::GuestCgroupDrained);
        assert_eq!(
            r.termination,
            Some(Termination::Signaled {
                signal: 15,
                core_dumped: false
            })
        );
        assert_eq!(
            (r.stdout.kept, r.stdout.total, r.stdout.truncated),
            (3, 10, true)
        );
        assert!(r.validate().is_ok());
        let d = RuntimeDiagnostic::new(
            RuntimeErrorKind::CleanupFailed,
            RuntimeStage::Cleanup,
            "x".repeat(3000),
        );
        let r = result_of(
            Id128([1; 16]),
            &inner,
            &outcome(Err(d), CleanupEvidence::Unknown),
        );
        assert_eq!(r.cleanup, Cleanup::Unknown);
        let diagnostic = r.diagnostic.unwrap();
        assert!(diagnostic.message_truncated);
        assert_eq!(diagnostic.message.as_str().len(), 2048);
    }
}
