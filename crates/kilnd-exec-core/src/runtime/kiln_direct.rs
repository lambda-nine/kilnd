//! The direct-kiln core: drives the `kiln` CLI with argument vectors, probes its
//! capabilities, validates a sandbox and runs one persistent-sandbox execution through
//! the cleanup barrier. kilnd never links kiln's code or reads its state directories;
//! the CLI's `capabilities`, `exec` and `ls` are this core's whole interface.
//!
//! Moved from `kilnd::runtime::kiln_direct` (Phase 1b B5) so the guest broker reuses
//! the reviewed logic instead of reimplementing it. kilnd's `DirectKilnRuntime` keeps
//! its API and delegates here through [`DirectKiln`].

use std::io::ErrorKind;
use std::path::Path;
use std::time::Duration;

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::{
    BackendSandbox, BackendStatus, ExecFinish, ExecOutcome, ExecSpec, RuntimeError,
    legacy_exec_evidence,
};
use super::{
    kiln_process::{self, OwnedExec, Stop},
    kiln_protocol as protocol,
};
use crate::model::{Captured, CleanupEvidence, Network, SandboxDisposition, SandboxSpec};
use crate::model::{RuntimeDiagnostic, RuntimeErrorKind as Kind, RuntimeStage as Stage};
use crate::process::{self, Finish};

/// Capability negotiation, rather than package strings, gates compatibility.
const CLI_REQUIREMENT: &str =
    "persistent-exec protocol v1, scoped gc ID... and persistent-create certainty (feature 0x10)";
const SANDBOX_REQUIREMENT: &str = "persistent-exec protocol v1";
/// kiln's own output (IDs, `ls` tables, errors) is small.
pub const CONTROL_OUTPUT: usize = 64 * 1024;
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(30);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(60);
const CLEANUP_POLL: Duration = Duration::from_millis(10);

/// The direct-kiln core over one verified CLI and kiln's cgroup root
/// (`/sys/fs/cgroup/kiln` in production).
#[derive(Clone, Copy)]
pub struct DirectKiln<'a> {
    bin: &'a process::KilnBinary,
    cgroup_root: &'a Path,
}

impl<'a> DirectKiln<'a> {
    pub fn new(bin: &'a process::KilnBinary, cgroup_root: &'a Path) -> Self {
        Self { bin, cgroup_root }
    }

    pub async fn call_until(
        &self,
        op: &str,
        args: &process::KilnArgs,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<process::Outcome, RuntimeError> {
        let out = self.run_control(args, deadline, cancel).await?;
        match out.finish {
            Finish::Exited(status) if status.success() => Ok(out),
            Finish::Exited(status) => Err(RuntimeError::Backend(format!(
                "kiln {op} failed ({status}): {}",
                summarize(&out.stderr.data)
            ))),
            Finish::TimedOut => Err(RuntimeError::Backend(format!("kiln {op} deadline expired"))),
            Finish::Canceled => Err(RuntimeError::Backend(format!("kiln {op} was canceled"))),
        }
    }

    pub async fn run_control(
        &self,
        args: &process::KilnArgs,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> std::io::Result<process::Outcome> {
        let req = process::Request {
            tool: process::Tool::Kiln {
                bin: self.bin,
                args,
            },
            stdin: b"",
            deadline,
            max_output: CONTROL_OUTPUT,
        };
        process::run(&req, cancel).await
    }

    pub async fn capabilities(
        &self,
        id: Option<&str>,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<protocol::Capabilities, RuntimeError> {
        let args = process::KilnArgs::capabilities(id);
        let scope = id.map(|id| format!(" sandbox {id}")).unwrap_or_default();
        let result = async {
            let args = args.map_err(|e| e.to_string())?;
            let out = kiln_process::probe(
                self.bin,
                &args,
                deadline.min(Instant::now() + Duration::from_secs(2)),
                cancel,
            )
            .await
            .map_err(|e| e.to_string())?;
            let observed = || {
                format!(
                    "observed CLI {:?}; stop {:?}{}; stdout {}; stderr {}",
                    out.child_status,
                    out.stop,
                    if matches!(out.stop, Stop::TimedOut) {
                        " (deadline expired)"
                    } else {
                        ""
                    },
                    summarize(&out.status.bytes),
                    summarize(&out.stderr.captured.data)
                )
            };
            if !matches!(out.stop, Stop::Exited)
                || !out.child_status.is_some_and(|s| s.success())
                || !out.status.eof
                || out.status.error.is_some()
            {
                return Err(format!(
                    "capability exchange failed ({}); {}",
                    out.status
                        .error
                        .as_deref()
                        .unwrap_or("missing EOF, deadline expired or nonzero CLI exit"),
                    observed()
                ));
            }
            let caps = protocol::capabilities(&out.status.bytes)
                .map_err(|e| format!("{e}; {}", observed()))?;
            caps.require_v1()?;
            if id.is_none() {
                caps.require_create_certainty()?;
                self.require_scoped_gc(deadline, cancel).await?;
            }
            Ok::<_, String>(caps)
        }
        .await;
        result.map_err(|e| {
            let requirement = if id.is_some() {
                SANDBOX_REQUIREMENT
            } else {
                CLI_REQUIREMENT
            };
            RuntimeError::Incompatible(format!(
                "{}{} requires {requirement}: {e}",
                self.bin.display(),
                scope
            ))
        })
    }

    /// Scoped GC predates a capability feature bit. Check its advertised CLI
    /// grammar without invoking collection, including on an empty database.
    async fn require_scoped_gc(
        &self,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), String> {
        let out = self
            .call_until("gc --help", &process::KilnArgs::gc_help(), deadline, cancel)
            .await
            .map_err(|e| format!("scoped gc capability check failed: {e}"))?;
        if out.stdout_completion != process::CaptureCompletion::Eof
            || out.stderr_completion != process::CaptureCompletion::Eof
            || out.stdout.truncated()
            || out.stderr.truncated()
        {
            return Err(format!(
                "scoped gc capability check received incomplete help output: stdout {:?}; stderr {:?}",
                out.stdout_completion, out.stderr_completion
            ));
        }
        let text = std::str::from_utf8(&out.stdout.data)
            .map_err(|e| format!("scoped gc help is not UTF-8: {e}"))?;
        if !text
            .lines()
            .any(|line| line.starts_with("Usage: ") && line.ends_with(" gc [ID]..."))
        {
            return Err("scoped gc ID... is required; install kiln 40d9aa500320 or later with scoped GC support (global GC is never used)".into());
        }
        Ok(())
    }

    pub async fn list_until(
        &self,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<Vec<BackendSandbox>, RuntimeError> {
        let deadline = deadline.min(Instant::now() + QUERY_TIMEOUT);
        let out = self
            .call_until("ls", &process::KilnArgs::ls(), deadline, cancel)
            .await?;
        if out.stdout_completion != process::CaptureCompletion::Eof
            || out.stderr_completion != process::CaptureCompletion::Eof
        {
            return Err(RuntimeError::Backend(format!(
                "kiln ls observation was incomplete: stdout {:?}; stderr {:?}",
                out.stdout_completion, out.stderr_completion
            )));
        }
        if out.stdout.truncated() || out.stderr.truncated() {
            return Err(RuntimeError::Backend(format!(
                "kiln ls observation was truncated: stdout {}; stderr {}",
                out.stdout.truncated(),
                out.stderr.truncated()
            )));
        }
        let text = std::str::from_utf8(&out.stdout.data).map_err(|e| {
            RuntimeError::Backend(format!("kiln ls observation was not UTF-8: {e}"))
        })?;
        parse_ls(text)
    }

    /// A killed `kiln exec` client cannot receive PID 1's post-cleanup reply.
    /// The required kiln revision gives every command a fixed `exec` cgroup;
    /// observing `populated 0` is the host-side cleanup acknowledgment.
    pub async fn wait_exec_cleanup(&self, id: &str) -> Result<(), RuntimeError> {
        let events = self.cgroup_root.join(id).join("exec/cgroup.events");
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        loop {
            match tokio::fs::read_to_string(&events).await {
                Ok(value) => match exec_populated(&value) {
                    Some(false) => return Ok(()),
                    Some(true) => {}
                    None => {
                        return Err(RuntimeError::Backend(format!(
                            "kiln cleanup barrier {} has no populated state",
                            events.display()
                        )));
                    }
                },
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    return Err(RuntimeError::Backend(format!(
                        "kiln cleanup barrier {} is missing; kiln 3b42552 or later is required",
                        events.display()
                    )));
                }
                Err(error) => return Err(RuntimeError::Io(error)),
            }
            if Instant::now() >= deadline {
                return Err(RuntimeError::Backend(format!(
                    "kiln did not empty execution cgroup {} within {}s",
                    events.display(),
                    CLEANUP_TIMEOUT.as_secs()
                )));
            }
            tokio::time::sleep(CLEANUP_POLL).await;
        }
    }

    /// The helper's wire exec has no execution context, so its dispatch uses this
    /// directly. The cleanup contract is unchanged; disposition only names it.
    pub async fn exec_direct(
        &self,
        id: &str,
        spec: &ExecSpec<'_>,
        cancel: &CancellationToken,
    ) -> ExecOutcome {
        // Every early return precedes the spawn, so no child can need cleanup
        // unless the probe proved this sandbox gone.
        let empty = |finish: Result<ExecFinish, RuntimeDiagnostic>| {
            let (disposition, _) = legacy_exec_evidence(&finish);
            ExecOutcome {
                finish,
                command_status: None,
                stdout: Captured::known_empty(),
                stderr: Captured::known_empty(),
                disposition,
                cleanup: if disposition == SandboxDisposition::Reusable {
                    CleanupEvidence::NoChildStarted
                } else {
                    CleanupEvidence::Unknown
                },
            }
        };
        if let Err(e) = check_id(id) {
            return empty(Err(RuntimeDiagnostic::new(
                Kind::InvalidRequest,
                Stage::Validate,
                e.to_string(),
            )));
        }
        let stopped = || {
            if cancel.is_cancelled() {
                Some(ExecFinish::Canceled)
            } else if Instant::now() >= spec.deadline {
                Some(ExecFinish::TimedOut)
            } else {
                None
            }
        };
        if let Some(finish) = stopped() {
            return empty(Ok(finish));
        }
        for global in [true, false] {
            let validation = if global {
                self.capabilities(None, spec.deadline, cancel)
                    .await
                    .map(|_| ())
            } else {
                self.validate_sandbox(id, spec.deadline, cancel).await
            };
            if let Err(e) = validation {
                if let Some(finish) = stopped() {
                    return empty(Ok(finish));
                }
                return empty(Err(RuntimeDiagnostic::new(
                    match e {
                        RuntimeError::NotFound(_) => Kind::NotFound,
                        RuntimeError::Incompatible(_) => Kind::Incompatible,
                        _ => Kind::Unavailable,
                    },
                    Stage::Handshake,
                    e.to_string(),
                )));
            }
        }
        if let Some(finish) = stopped() {
            return empty(Ok(finish));
        }
        let mut owner = match OwnedExec::spawn(self.bin, id, spec) {
            Ok(owner) => owner,
            Err(e) => {
                return empty(Err(RuntimeDiagnostic::new(
                    Kind::Io,
                    Stage::Prepare,
                    e.to_string(),
                )));
            }
        };
        let mut stop = owner.supervise(spec.deadline, cancel).await;
        // StatusReady means the reader is joined and its complete final bytes
        // are immutable. Decode once here so malformed replies stop a hung CLI.
        let mut decoded = None;
        if matches!(stop, Stop::StatusReady) {
            decoded = Some(decode_status(&owner.status()));
            stop = match decoded.as_ref().expect("status decoded") {
                Ok(_) => owner.supervise(spec.deadline, cancel).await,
                Err(error) => Stop::Transport(error.clone()),
            };
        }
        let reap_error = owner.kill_reap().await.err();
        owner.settle_status().await;
        let status = owner.status();
        let decoded = decoded.unwrap_or_else(|| decode_status(&status));
        let command_status = decoded
            .as_ref()
            .ok()
            .and_then(|out| out.command_status.clone());
        let trusted_cleanup = decoded.as_ref().is_ok_and(|out| {
            matches!(
                out.cleanup,
                protocol::Cleanup::NoChildStarted | protocol::Cleanup::Drained
            )
        });
        let mut host_protocol_failure = matches!(&stop, Stop::Transport(_))
            || (matches!(&stop, Stop::Exited) && decoded.is_err());
        let mut finish = match &stop {
            Stop::StatusReady => Err(RuntimeDiagnostic::new(
                Kind::Internal,
                Stage::Report,
                "status supervision did not advance to CLI completion",
            )),
            Stop::TimedOut | Stop::Canceled => match &decoded {
                Ok(out) if out.diagnostic.is_some() => {
                    Err(out.diagnostic.clone().expect("diagnostic present"))
                }
                // Killing the CLI normally closes an otherwise empty status
                // socket. It does not turn a won cancellation into Protocol.
                Err(error)
                    if !status.bytes.is_empty()
                        || !status.eof
                        || status.error.as_deref() != Some("missing status frame") =>
                {
                    host_protocol_failure = true;
                    Err(RuntimeDiagnostic::new(Kind::Protocol, Stage::Report, error))
                }
                _ => Ok(if matches!(stop, Stop::TimedOut) {
                    ExecFinish::TimedOut
                } else {
                    ExecFinish::Canceled
                }),
            },
            Stop::Panic => Err(RuntimeDiagnostic::new(
                Kind::Internal,
                Stage::Report,
                "machine exec supervision panicked",
            )),
            Stop::Transport(e) => Err(RuntimeDiagnostic::new(Kind::Protocol, Stage::Report, e)),
            Stop::Exited => match &decoded {
                Ok(out) => out
                    .diagnostic
                    .clone()
                    .map_or(Ok(ExecFinish::Completed), Err),
                Err(e) => Err(RuntimeDiagnostic::new(
                    Kind::Protocol,
                    Stage::Report,
                    e.clone(),
                )),
            },
        };
        if let Some(e) = reap_error {
            finish = Err(RuntimeDiagnostic::new(Kind::Io, Stage::Wait, e.to_string()));
        }
        if !trusted_cleanup && let Err(e) = self.wait_exec_cleanup(id).await {
            finish = Err(RuntimeDiagnostic::new(
                Kind::CleanupFailed,
                Stage::Cleanup,
                e.to_string(),
            ));
        }
        // Readers remain alive during the entire cleanup barrier, then reach EOF.
        let raw = owner.settle().await;
        if matches!(stop, Stop::Exited)
            && !matches!(&finish, Err(d) if d.kind == Kind::CleanupFailed)
            && let Ok(out) = &decoded
            && raw.child_status.and_then(|s| s.code()) != Some(out.projection())
        {
            host_protocol_failure = true;
            finish = Err(RuntimeDiagnostic::new(
                Kind::Protocol,
                Stage::Report,
                "CLI exit status disagrees with typed outcome",
            ));
        }
        if finish.is_ok()
            && let Some(error) = raw.stdout.error.as_ref().or(raw.stderr.error.as_ref())
        {
            finish = Err(RuntimeDiagnostic::new(Kind::Io, Stage::Capture, error));
        }
        if let Err(d) = &mut finish
            && host_protocol_failure
            && d.kind == Kind::Protocol
        {
            let mut augmented = RuntimeDiagnostic::new(
                d.kind,
                d.stage,
                format!(
                    "{}; CLI stdout: {}; CLI stderr: {}; status: {} bytes{}",
                    d.message,
                    summarize(&raw.cli_stdout.captured.data),
                    summarize(&raw.cli_stderr.captured.data),
                    raw.status.bytes.len(),
                    raw.status
                        .error
                        .as_ref()
                        .map(|e| format!(" ({e})"))
                        .unwrap_or_default()
                ),
            );
            augmented.message_truncated |= d.message_truncated;
            *d = augmented;
        }
        let (disposition, cleanup) = legacy_exec_evidence(&finish);
        ExecOutcome {
            finish,
            command_status,
            stdout: raw.stdout.captured,
            stderr: raw.stderr.captured,
            disposition,
            cleanup,
        }
    }

    pub async fn validate_sandbox(
        &self,
        id: &str,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), RuntimeError> {
        check_id(id)?;
        match self.capabilities(Some(id), deadline, cancel).await {
            Ok(_) => Ok(()),
            Err(probe_error) => {
                if cancel.is_cancelled() || Instant::now() >= deadline {
                    return Err(RuntimeError::Incompatible(format!(
                        "{probe_error}; sandbox presence was not observed: no remaining deadline/cancellation budget"
                    )));
                }
                match self.list_until(deadline, cancel).await {
                    Ok(sandboxes) if !sandboxes.iter().any(|sandbox| sandbox.id == id) => {
                        if cancel.is_cancelled() || Instant::now() >= deadline {
                            return Err(RuntimeError::Incompatible(format!(
                                "{probe_error}; sandbox absence was not confirmed within the original deadline/cancellation budget"
                            )));
                        }
                        let cgroup = self.cgroup_root.join(id);
                        match tokio::fs::metadata(&cgroup).await {
                            Ok(_) => Err(RuntimeError::Incompatible(format!(
                                "{probe_error}; kiln ls omitted sandbox {id}, but its cgroup {} still exists",
                                cgroup.display()
                            ))),
                            Err(error) if error.kind() == ErrorKind::NotFound => {
                                Err(RuntimeError::NotFound(id.into()))
                            }
                            Err(error) => Err(RuntimeError::Incompatible(format!(
                                "{probe_error}; sandbox presence could not be confirmed: inspect cgroup {}: {error}",
                                cgroup.display()
                            ))),
                        }
                    }
                    Ok(_) => Err(probe_error),
                    Err(observation_error) => Err(RuntimeError::Incompatible(format!(
                        "{probe_error}; sandbox presence could not be confirmed: {observation_error}"
                    ))),
                }
            }
        }
    }
}

/// `kiln create` flags for a spec. Every value uses the `--flag=value` form,
/// so a value can never be read as another flag.
pub fn create_args(spec: &SandboxSpec) -> Vec<String> {
    let mut args = vec![
        "create".to_string(),
        "--require-exec-protocol=1".to_string(),
        format!("--image={}", spec.image),
        format!("--memory={}", spec.memory_bytes),
        format!(
            "--cpus={}.{:03}",
            spec.cpu_millis / 1000,
            spec.cpu_millis % 1000
        ),
        format!("--pids={}", spec.pids),
        format!("--disk={}", spec.disk_bytes),
    ];
    match &spec.network {
        Network::None => args.push("--net=none".into()),
        Network::Full => args.push("--net=full".into()),
        Network::Allow(allow) => args.extend(allow.iter().map(|a| format!("--allow={a}"))),
    }
    if spec.read_only_root {
        args.push("--read-only".into());
        args.extend(
            spec.writable_paths
                .iter()
                .map(|p| format!("--writable={p}")),
        );
    }
    args
}

/// Parses `kiln ls`: a header, then `ID<TAB>STATUS<TAB>SHIM` per sandbox.
/// Anything unexpected is an error, so a format change can't make live
/// sandboxes look missing.
pub fn parse_ls(text: &str) -> Result<Vec<BackendSandbox>, RuntimeError> {
    if !text.ends_with('\n') {
        return Err(RuntimeError::Backend(
            "kiln ls observation ended with a partial line".into(),
        ));
    }
    let mut lines = text.split_terminator('\n');
    if lines.next() != Some("ID\tSTATUS\tSHIM") {
        return Err(RuntimeError::Backend("unexpected kiln ls header".into()));
    }
    let mut seen = std::collections::HashSet::new();
    let mut sandboxes = Vec::new();
    for line in lines {
        let mut fields = line.split('\t');
        let (Some(id), Some(status), Some(shim), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(RuntimeError::Backend(format!(
                "unexpected kiln ls line {line:?}"
            )));
        };
        let status = match status {
            "running" => BackendStatus::Running,
            "stale" => BackendStatus::Stale,
            _ => {
                return Err(RuntimeError::Backend(format!(
                    "unexpected kiln ls status {status:?}"
                )));
            }
        };
        if !valid_kiln_id(id) {
            return Err(RuntimeError::Backend(format!(
                "unexpected kiln ls ID {id:?}"
            )));
        }
        if !seen.insert(id) {
            return Err(RuntimeError::Backend(format!(
                "duplicate kiln ls ID {id:?}"
            )));
        }
        let Ok(shim) = shim.parse::<u32>() else {
            return Err(RuntimeError::Backend(format!(
                "unexpected kiln ls shim PID {shim:?}"
            )));
        };
        if shim == 0 || shim > i32::MAX as u32 {
            return Err(RuntimeError::Backend(format!(
                "unexpected kiln ls shim PID {shim}"
            )));
        }
        sandboxes.push(BackendSandbox {
            id: id.to_string(),
            status,
        });
    }
    Ok(sandboxes)
}

/// kiln IDs are hex digits and dashes, like `18de453339a8cc89-3762`.
pub fn valid_kiln_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
        && !id.starts_with('-')
}

pub fn check_id(id: &str) -> Result<(), RuntimeError> {
    if valid_kiln_id(id) {
        Ok(())
    } else {
        Err(RuntimeError::Backend(format!(
            "invalid kiln sandbox ID {id:?}"
        )))
    }
}

pub fn exec_populated(events: &str) -> Option<bool> {
    events.lines().find_map(|line| match line.split_once(' ')? {
        ("populated", "0") => Some(false),
        ("populated", "1") => Some(true),
        _ => None,
    })
}

pub fn decode_status(status: &kiln_process::StatusState) -> Result<protocol::Outcome, String> {
    if status.eof && status.error.is_none() {
        protocol::outcome(&status.bytes)
    } else {
        Err(status
            .error
            .clone()
            .unwrap_or_else(|| "status EOF was not observed".into()))
    }
}

/// The end of kiln's stderr as one printable line, for error messages.
pub fn summarize(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let text = text.trim();
    let tail: String = text
        .chars()
        .rev()
        .take(1000)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let line: String = tail
        .split('\n')
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    if line.is_empty() {
        "no error output".into()
    } else {
        line
    }
}
