//! An in-memory backend for tests. Commands are simulated by name:
//!
//! - `echo ARGS...`: prints its arguments and exits 0
//! - `cat`: copies stdin to stdout
//! - `exit N`: exits with N
//! - `sleep`: waits until the timeout or cancellation
//! - `spew N`: writes N bytes to stdout
//! - `vanish`: the sandbox disappears mid-command, like a crashed shim
//! - anything else: exits 127

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use super::{
    BackendSandbox, BackendStatus, ExecFinish, ExecOutcome, ExecSpec, Runtime, RuntimeError,
};
use crate::model::{
    Captured, CommandStatus, RuntimeDiagnostic, RuntimeErrorKind, RuntimeStage, SandboxSpec,
};

/// A deterministic one-shot pause for lifecycle tests. Tests wait for
/// `entered`, cancel a caller or begin shutdown, then explicitly `release`.
#[derive(Clone)]
pub struct FakeGate {
    entered: Arc<Semaphore>,
    release: Arc<Semaphore>,
}

impl Default for FakeGate {
    fn default() -> Self {
        Self {
            entered: Arc::new(Semaphore::new(0)),
            release: Arc::new(Semaphore::new(0)),
        }
    }
}

impl FakeGate {
    pub async fn entered(&self) {
        self.entered
            .acquire()
            .await
            .expect("fake gate closed")
            .forget();
    }

    pub fn release(&self) {
        self.release.add_permits(1);
    }

    async fn hold(&self) {
        self.entered.add_permits(1);
        self.release
            .acquire()
            .await
            .expect("fake gate closed")
            .forget();
    }
}

#[derive(Default)]
pub struct FakeState {
    pub sandboxes: BTreeMap<String, BackendStatus>,
    /// Specs passed to `create`, in order.
    pub created: Vec<SandboxSpec>,
    pub removed: Vec<String>,
    /// Removal attempts, including failed ones.
    pub remove_attempts: Vec<String>,
    /// Commands whose backend execution was entered, in order.
    pub exec_calls: Vec<Vec<String>>,
    pub exec_deadlines: Vec<tokio::time::Instant>,
    pub version_calls: u32,
    pub active_version_calls: u32,
    pub version_gate: Option<FakeGate>,
    pub panic_version: bool,
    pub active_execs: u32,
    pub canceled_execs: u32,
    pub gc_runs: u32,
    /// When set, `create` fails with this message.
    pub fail_create: Option<String>,
    /// Panics before allocating a backend, for supervisor recovery tests.
    pub panic_create: bool,
    /// Panics after the optional exec gate. Without a gate this is before the
    /// backend future's first await; with one it exercises a polling panic.
    pub panic_exec: bool,
    /// When set, `remove` fails while the sandbox stays.
    pub fail_remove: bool,
    /// Optional one-shot pause before create allocates a backend.
    pub create_before_allocation: Option<FakeGate>,
    /// Optional one-shot pause after allocation but before create returns.
    pub create_after_allocation: Option<FakeGate>,
    /// Optional one-shot pause after exec entry and before observing cancel.
    pub exec_before_run: Option<FakeGate>,
    /// Optional one-shot pause before remove changes backend state.
    pub remove_before_delete: Option<FakeGate>,
    /// When set, `list` and `version` fail, like a missing kiln binary.
    pub unavailable: bool,
    pub incompatible_sandboxes: Vec<String>,
    next: u64,
}

#[derive(Clone, Default)]
pub struct FakeRuntime {
    state: Arc<Mutex<FakeState>>,
}

struct ActiveExec {
    state: Arc<Mutex<FakeState>>,
}

struct ActiveVersion(Arc<Mutex<FakeState>>);

impl Drop for ActiveVersion {
    fn drop(&mut self) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .active_version_calls -= 1;
    }
}

impl Drop for ActiveExec {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.active_execs -= 1;
    }
}

impl FakeRuntime {
    pub fn state(&self) -> MutexGuard<'_, FakeState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Adds a sandbox the way something other than kilnd would.
    pub fn insert(&self, status: BackendStatus) -> String {
        let mut s = self.state();
        s.next += 1;
        let id = format!("f00d-{}", s.next);
        s.sandboxes.insert(id.clone(), status);
        id
    }

    fn running(&self, id: &str) -> Result<(), RuntimeError> {
        match self.state().sandboxes.get(id) {
            Some(BackendStatus::Running) => Ok(()),
            _ => Err(RuntimeError::NotFound(id.to_string())),
        }
    }
}

fn exited(code: i32, stdout: Vec<u8>, max: usize) -> ExecOutcome {
    let total = stdout.len() as u64;
    let data = stdout[..stdout.len().min(max)].to_vec();
    ExecOutcome {
        finish: Ok(ExecFinish::Completed),
        command_status: Some(CommandStatus::Exited(code)),
        stdout: Captured {
            data,
            total_bytes: total,
        },
        stderr: Captured::default(),
    }
}

impl Runtime for FakeRuntime {
    fn name(&self) -> &'static str {
        "fake"
    }

    async fn version(
        &self,
        deadline: tokio::time::Instant,
        cancel: &CancellationToken,
    ) -> Result<String, RuntimeError> {
        let (gate, panic_version) = {
            let mut state = self.state();
            state.version_calls += 1;
            state.active_version_calls += 1;
            (state.version_gate.take(), state.panic_version)
        };
        let _active = ActiveVersion(self.state.clone());
        if let Some(gate) = gate {
            tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(RuntimeError::Backend("version probe canceled".into())),
                () = tokio::time::sleep_until(deadline) => return Err(RuntimeError::Backend("version probe timed out".into())),
                () = gate.hold() => {}
            }
        }
        assert!(!panic_version, "injected fake version panic");
        if self.state().unavailable {
            return Err(RuntimeError::Backend("fake backend unavailable".into()));
        }
        Ok("fake 1.0".into())
    }

    async fn create(&self, spec: &SandboxSpec) -> Result<String, RuntimeError> {
        let before = self.state().create_before_allocation.take();
        if let Some(gate) = before {
            gate.hold().await;
        }
        let (id, after) = {
            let mut s = self.state();
            assert!(!s.panic_create, "injected fake create panic");
            if let Some(msg) = &s.fail_create {
                return Err(RuntimeError::Backend(msg.clone()));
            }
            s.created.push(spec.clone());
            s.next += 1;
            let id = format!("f00d-{}", s.next);
            s.sandboxes.insert(id.clone(), BackendStatus::Running);
            (id, s.create_after_allocation.take())
        };
        if let Some(gate) = after {
            gate.hold().await;
        }
        Ok(id)
    }

    async fn validate_sandbox(
        &self,
        id: &str,
        _deadline: tokio::time::Instant,
        _cancel: &CancellationToken,
    ) -> Result<(), RuntimeError> {
        if self.state().incompatible_sandboxes.iter().any(|s| s == id) {
            return Err(RuntimeError::Incompatible(format!(
                "sandbox {id} incompatible"
            )));
        }
        self.running(id)
    }

    async fn exec(&self, id: &str, spec: &ExecSpec<'_>, cancel: &CancellationToken) -> ExecOutcome {
        if let Err(e) = self.running(id) {
            return ExecOutcome {
                finish: Err(RuntimeDiagnostic::new(
                    RuntimeErrorKind::NotFound,
                    RuntimeStage::Connect,
                    e.to_string(),
                )),
                command_status: None,
                stdout: Default::default(),
                stderr: Default::default(),
            };
        }
        if cancel.is_cancelled() {
            self.state().canceled_execs += 1;
            return ExecOutcome {
                finish: Ok(ExecFinish::Canceled),
                command_status: None,
                stdout: Captured::default(),
                stderr: Captured::default(),
            };
        }
        let (gate, panic_exec) = {
            let mut state = self.state();
            state.exec_calls.push(spec.argv.to_vec());
            state.exec_deadlines.push(spec.deadline);
            state.active_execs += 1;
            (state.exec_before_run.take(), state.panic_exec)
        };
        let _active = ActiveExec {
            state: self.state.clone(),
        };
        if let Some(gate) = gate {
            gate.hold().await;
        }
        assert!(!panic_exec, "injected fake exec panic");
        let args = &spec.argv[1..];
        match spec.argv[0].as_str() {
            "echo" => exited(
                0,
                format!("{}\n", args.join(" ")).into_bytes(),
                spec.max_output,
            ),
            "cat" => exited(0, spec.stdin.to_vec(), spec.max_output),
            "exit" => exited(
                args.first().and_then(|a| a.parse().ok()).unwrap_or(1),
                vec![],
                spec.max_output,
            ),
            "spew" => exited(
                0,
                vec![b'x'; args.first().and_then(|a| a.parse().ok()).unwrap_or(0)],
                spec.max_output,
            ),
            "spew-both" => {
                let total = args.first().and_then(|a| a.parse().ok()).unwrap_or(0);
                let kept = total.min(spec.max_output);
                ExecOutcome {
                    finish: Ok(ExecFinish::Completed),
                    command_status: Some(CommandStatus::Exited(0)),
                    stdout: Captured {
                        data: vec![b'x'; kept],
                        total_bytes: total as u64,
                    },
                    stderr: Captured {
                        data: vec![b'y'; kept],
                        total_bytes: total as u64,
                    },
                }
            }
            "sleep" => {
                let finish = tokio::select! {
                    () = tokio::time::sleep_until(spec.deadline) => ExecFinish::TimedOut,
                    () = cancel.cancelled() => {
                        self.state().canceled_execs += 1;
                        ExecFinish::Canceled
                    },
                };
                ExecOutcome {
                    finish: Ok(finish),
                    command_status: None,
                    stdout: Captured::default(),
                    stderr: Captured::default(),
                }
            }
            "vanish" => {
                self.state().sandboxes.remove(id);
                ExecOutcome {
                    finish: Err(RuntimeDiagnostic::new(
                        RuntimeErrorKind::NotFound,
                        RuntimeStage::Connect,
                        format!("sandbox {id} not found in backend"),
                    )),
                    command_status: None,
                    stdout: Default::default(),
                    stderr: Default::default(),
                }
            }
            "signal" => ExecOutcome {
                command_status: Some(CommandStatus::Signaled {
                    signal: args.first().and_then(|s| s.parse().ok()).unwrap_or(15),
                    core_dumped: args.get(1).is_some_and(|s| s == "core"),
                }),
                ..exited(0, vec![], spec.max_output)
            },
            "invalid-completed" => ExecOutcome {
                command_status: None,
                ..exited(0, b"saved".to_vec(), spec.max_output)
            },
            "runtime-failure" => ExecOutcome {
                finish: Err(RuntimeDiagnostic::new(
                    RuntimeErrorKind::Io,
                    RuntimeStage::Capture,
                    "injected binary evidence failure",
                )),
                command_status: Some(CommandStatus::Exited(125)),
                stdout: Captured {
                    data: b"\0\xffout"[..5.min(spec.max_output)].to_vec(),
                    total_bytes: 99,
                },
                stderr: Captured {
                    data: b"\0\xfeerr"[..5.min(spec.max_output)].to_vec(),
                    total_bytes: 101,
                },
            },
            _ => ExecOutcome {
                finish: Ok(ExecFinish::Completed),
                command_status: Some(CommandStatus::Exited(127)),
                stdout: Captured::default(),
                stderr: Captured {
                    data: b"not found\n".to_vec(),
                    total_bytes: 10,
                },
            },
        }
    }

    async fn remove(&self, id: &str) -> Result<(), RuntimeError> {
        let gate = {
            let mut s = self.state();
            s.remove_attempts.push(id.to_string());
            if !s.sandboxes.contains_key(id) {
                return Err(RuntimeError::NotFound(id.to_string()));
            }
            s.remove_before_delete.take()
        };
        if let Some(gate) = gate {
            gate.hold().await;
        }
        let mut s = self.state();
        if !s.sandboxes.contains_key(id) {
            return Err(RuntimeError::NotFound(id.to_string()));
        }
        if s.fail_remove {
            return Err(RuntimeError::Backend("fake remove failed".into()));
        }
        s.sandboxes.remove(id);
        s.removed.push(id.to_string());
        Ok(())
    }

    async fn list(&self) -> Result<Vec<BackendSandbox>, RuntimeError> {
        let s = self.state();
        if s.unavailable {
            return Err(RuntimeError::Backend("fake backend unavailable".into()));
        }
        Ok(s.sandboxes
            .iter()
            .map(|(id, status)| BackendSandbox {
                id: id.clone(),
                status: *status,
            })
            .collect())
    }

    async fn gc(&self) -> Result<Vec<String>, RuntimeError> {
        let mut s = self.state();
        if s.unavailable {
            return Err(RuntimeError::Backend("fake backend unavailable".into()));
        }
        s.gc_runs += 1;
        let stale: Vec<String> = s
            .sandboxes
            .iter()
            .filter(|(_, st)| **st == BackendStatus::Stale)
            .map(|(id, _)| id.clone())
            .collect();
        for id in &stale {
            s.sandboxes.remove(id);
        }
        Ok(stale)
    }
}
