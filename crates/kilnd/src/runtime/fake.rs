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

use super::{BackendSandbox, BackendStatus, ExecFinish, ExecOutcome, ExecSpec, Runtime, RuntimeError};
use crate::model::{Captured, SandboxSpec};

/// A deterministic one-shot pause for lifecycle tests. Tests wait for
/// `entered`, cancel a caller or begin shutdown, then explicitly `release`.
#[derive(Clone)]
pub struct FakeGate {
    entered: Arc<Semaphore>,
    release: Arc<Semaphore>,
}

impl Default for FakeGate {
    fn default() -> Self {
        Self { entered: Arc::new(Semaphore::new(0)), release: Arc::new(Semaphore::new(0)) }
    }
}

impl FakeGate {
    pub async fn entered(&self) {
        self.entered.acquire().await.expect("fake gate closed").forget();
    }

    pub fn release(&self) {
        self.release.add_permits(1);
    }

    async fn hold(&self) {
        self.entered.add_permits(1);
        self.release.acquire().await.expect("fake gate closed").forget();
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
    pub gc_runs: u32,
    /// When set, `create` fails with this message.
    pub fail_create: Option<String>,
    /// Panics before allocating a backend, for supervisor recovery tests.
    pub panic_create: bool,
    /// When set, `remove` fails while the sandbox stays.
    pub fail_remove: bool,
    /// Optional one-shot pause before create allocates a backend.
    pub create_before_allocation: Option<FakeGate>,
    /// Optional one-shot pause after allocation but before create returns.
    pub create_after_allocation: Option<FakeGate>,
    /// Optional one-shot pause before remove changes backend state.
    pub remove_before_delete: Option<FakeGate>,
    /// When set, `list` and `version` fail, like a missing kiln binary.
    pub unavailable: bool,
    next: u64,
}

#[derive(Clone, Default)]
pub struct FakeRuntime {
    state: Arc<Mutex<FakeState>>,
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
    ExecOutcome { finish: ExecFinish::Exited(code), stdout: Captured { data, total_bytes: total }, stderr: Captured::default() }
}

impl Runtime for FakeRuntime {
    fn name(&self) -> &'static str {
        "fake"
    }

    async fn version(&self) -> Result<String, RuntimeError> {
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

    async fn exec(&self, id: &str, spec: &ExecSpec<'_>, cancel: &CancellationToken) -> Result<ExecOutcome, RuntimeError> {
        self.running(id)?;
        let args = &spec.argv[1..];
        Ok(match spec.argv[0].as_str() {
            "echo" => exited(0, format!("{}\n", args.join(" ")).into_bytes(), spec.max_output),
            "cat" => exited(0, spec.stdin.to_vec(), spec.max_output),
            "exit" => exited(args.first().and_then(|a| a.parse().ok()).unwrap_or(1), vec![], spec.max_output),
            "spew" => exited(0, vec![b'x'; args.first().and_then(|a| a.parse().ok()).unwrap_or(0)], spec.max_output),
            "sleep" => {
                let finish = tokio::select! {
                    () = tokio::time::sleep(spec.timeout) => ExecFinish::TimedOut,
                    () = cancel.cancelled() => ExecFinish::Canceled,
                };
                ExecOutcome { finish, stdout: Captured::default(), stderr: Captured::default() }
            }
            "vanish" => {
                self.state().sandboxes.remove(id);
                return Err(RuntimeError::NotFound(id.to_string()));
            }
            _ => ExecOutcome {
                finish: ExecFinish::Exited(127),
                stdout: Captured::default(),
                stderr: Captured { data: b"not found\n".to_vec(), total_bytes: 10 },
            },
        })
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
        Ok(s.sandboxes.iter().map(|(id, status)| BackendSandbox { id: id.clone(), status: *status }).collect())
    }

    async fn gc(&self) -> Result<Vec<String>, RuntimeError> {
        let mut s = self.state();
        if s.unavailable {
            return Err(RuntimeError::Backend("fake backend unavailable".into()));
        }
        s.gc_runs += 1;
        let stale: Vec<String> =
            s.sandboxes.iter().filter(|(_, st)| **st == BackendStatus::Stale).map(|(id, _)| id.clone()).collect();
        for id in &stale {
            s.sandboxes.remove(id);
        }
        Ok(stale)
    }
}
