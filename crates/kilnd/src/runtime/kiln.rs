//! The kiln backend: drives the `kiln` CLI with argument vectors. kilnd
//! never links kiln's code or reads its state directories; the CLI's
//! `create`, `exec`, `ls`, `rm` and `gc` are the whole interface.

use std::ffi::OsStr;
use std::io::ErrorKind;
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::{BackendSandbox, BackendStatus, ExecFinish, ExecOutcome, ExecSpec, Runtime, RuntimeError};
use crate::model::{Network, SandboxSpec};
use crate::process::{self, Finish};

/// `kiln exec` exits with this when kiln itself failed rather than the
/// command (kiln 3736329 and later).
const EXEC_FAILED: i32 = 125;
/// kiln's own output (IDs, `ls` tables, errors) is small.
const CONTROL_OUTPUT: usize = 64 * 1024;
const CREATE_TIMEOUT: Duration = Duration::from_secs(120);
const REMOVE_TIMEOUT: Duration = Duration::from_secs(60);
const QUERY_TIMEOUT: Duration = Duration::from_secs(30);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(60);
const CLEANUP_POLL: Duration = Duration::from_millis(10);

pub struct KilnRuntime {
    bin: PathBuf,
    cgroup_root: PathBuf,
}

impl KilnRuntime {
    pub fn new(bin: PathBuf) -> Self {
        Self { bin, cgroup_root: PathBuf::from("/sys/fs/cgroup/kiln") }
    }

    /// Runs a kiln subcommand that should exit 0, returning its stdout.
    async fn call(&self, op: &str, args: &[String], timeout: Duration) -> Result<process::Outcome, RuntimeError> {
        let args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
        let req = process::Request { program: &self.bin, args: &args, stdin: b"", timeout, max_output: CONTROL_OUTPUT };
        let out = process::run(&req, &CancellationToken::new()).await?;
        match out.finish {
            Finish::Exited(status) if status.success() => Ok(out),
            Finish::Exited(status) => Err(RuntimeError::Backend(format!(
                "kiln {op} failed ({status}): {}",
                summarize(&out.stderr.data)
            ))),
            Finish::TimedOut => Err(RuntimeError::Backend(format!("kiln {op} timed out after {}s", timeout.as_secs()))),
            Finish::Canceled => Err(RuntimeError::Backend(format!("kiln {op} was canceled"))),
        }
    }

    async fn is_known(&self, id: &str) -> Result<bool, RuntimeError> {
        Ok(self.list().await?.iter().any(|s| s.id == id))
    }

    /// A killed `kiln exec` client cannot receive PID 1's post-cleanup reply.
    /// The required kiln revision gives every command a fixed `exec` cgroup;
    /// observing `populated 0` is the host-side cleanup acknowledgment.
    async fn wait_exec_cleanup(&self, id: &str) -> Result<(), RuntimeError> {
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
                    if !self.is_known(id).await? {
                        return Err(RuntimeError::NotFound(id.to_string()));
                    }
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

    #[cfg(test)]
    fn with_cgroup_root(bin: PathBuf, cgroup_root: &Path) -> Self {
        Self { bin, cgroup_root: cgroup_root.to_path_buf() }
    }
}

impl Runtime for KilnRuntime {
    fn name(&self) -> &'static str {
        "kiln"
    }

    async fn version(&self) -> Result<String, RuntimeError> {
        let out = self.call("--version", &["--version".into()], QUERY_TIMEOUT).await?;
        Ok(String::from_utf8_lossy(&out.stdout.data).trim().to_string())
    }

    async fn create(&self, spec: &SandboxSpec) -> Result<String, RuntimeError> {
        let out = self.call("create", &create_args(spec), CREATE_TIMEOUT).await?;
        let id = String::from_utf8_lossy(&out.stdout.data).trim().to_string();
        if !valid_kiln_id(&id) {
            return Err(RuntimeError::Backend(format!("kiln create printed an unexpected ID {id:?}")));
        }
        Ok(id)
    }

    async fn exec(&self, id: &str, spec: &ExecSpec<'_>, cancel: &CancellationToken) -> Result<ExecOutcome, RuntimeError> {
        check_id(id)?;
        if cancel.is_cancelled() {
            return Ok(ExecOutcome {
                finish: ExecFinish::Canceled,
                stdout: crate::model::Captured::default(),
                stderr: crate::model::Captured::default(),
            });
        }
        let mut args: Vec<&OsStr> = vec![OsStr::new("exec"), OsStr::new(id), OsStr::new("--")];
        args.extend(spec.argv.iter().map(OsStr::new));
        let req = process::Request {
            program: &self.bin,
            args: &args,
            stdin: spec.stdin,
            timeout: spec.timeout,
            max_output: spec.max_output,
        };
        // Killing the `kiln exec` client asks kiln's PID 1 to tear down the
        // command's per-execution cgroup. Because the killed client cannot
        // receive PID 1's eventual reply, timeout and cancellation explicitly
        // wait for the host cgroup to report empty before returning.
        let out = process::run(&req, cancel).await?;
        let finish = match out.finish {
            Finish::Exited(status) => match status.code() {
                Some(EXEC_FAILED) => {
                    if !self.is_known(id).await? {
                        return Err(RuntimeError::NotFound(id.to_string()));
                    }
                    return Err(RuntimeError::Backend(format!(
                        "kiln exec failed: {}",
                        summarize(&out.stderr.data)
                    )));
                }
                Some(code) => ExecFinish::Exited(code),
                None => return Err(RuntimeError::Backend(format!("kiln exec ended abnormally ({status})"))),
            },
            Finish::TimedOut => {
                self.wait_exec_cleanup(id).await?;
                ExecFinish::TimedOut
            }
            Finish::Canceled => {
                self.wait_exec_cleanup(id).await?;
                ExecFinish::Canceled
            }
        };
        Ok(ExecOutcome { finish, stdout: out.stdout, stderr: out.stderr })
    }

    async fn remove(&self, id: &str) -> Result<(), RuntimeError> {
        check_id(id)?;
        match self.call("rm", &["rm".into(), id.into()], REMOVE_TIMEOUT).await {
            Ok(_) => Ok(()),
            Err(e) => {
                if !self.is_known(id).await? {
                    return Err(RuntimeError::NotFound(id.to_string()));
                }
                Err(e)
            }
        }
    }

    async fn list(&self) -> Result<Vec<BackendSandbox>, RuntimeError> {
        let out = self.call("ls", &["ls".into()], QUERY_TIMEOUT).await?;
        parse_ls(&String::from_utf8_lossy(&out.stdout.data))
    }

    async fn gc(&self) -> Result<Vec<String>, RuntimeError> {
        let out = self.call("gc", &["gc".into()], QUERY_TIMEOUT).await?;
        Ok(String::from_utf8_lossy(&out.stderr.data)
            .lines()
            .filter_map(|l| l.strip_prefix("kiln: removed stale sandbox "))
            .map(|id| id.trim().to_string())
            .collect())
    }
}

/// `kiln create` flags for a spec. Every value uses the `--flag=value` form,
/// so a value can never be read as another flag.
pub fn create_args(spec: &SandboxSpec) -> Vec<String> {
    let mut args = vec![
        "create".to_string(),
        format!("--image={}", spec.image),
        format!("--memory={}", spec.memory_bytes),
        format!("--cpus={}.{:03}", spec.cpu_millis / 1000, spec.cpu_millis % 1000),
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
        args.extend(spec.writable_paths.iter().map(|p| format!("--writable={p}")));
    }
    args
}

/// Parses `kiln ls`: a header, then `ID<TAB>STATUS<TAB>SHIM` per sandbox.
/// Anything unexpected is an error, so a format change can't make live
/// sandboxes look missing.
pub fn parse_ls(text: &str) -> Result<Vec<BackendSandbox>, RuntimeError> {
    let mut lines = text.lines();
    if lines.next().map(str::split_whitespace).map(Iterator::collect::<Vec<_>>) != Some(vec!["ID", "STATUS", "SHIM"]) {
        return Err(RuntimeError::Backend("unexpected kiln ls header".into()));
    }
    lines
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let mut fields = line.split('\t');
            let (Some(id), Some(status)) = (fields.next(), fields.next()) else {
                return Err(RuntimeError::Backend(format!("unexpected kiln ls line {line:?}")));
            };
            let status = match status {
                "running" => BackendStatus::Running,
                "stale" => BackendStatus::Stale,
                _ => return Err(RuntimeError::Backend(format!("unexpected kiln ls status {status:?}"))),
            };
            if !valid_kiln_id(id) {
                return Err(RuntimeError::Backend(format!("unexpected kiln ls ID {id:?}")));
            }
            Ok(BackendSandbox { id: id.to_string(), status })
        })
        .collect()
}

/// kiln IDs are hex digits and dashes, like `18de453339a8cc89-3762`.
fn valid_kiln_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') && !id.starts_with('-')
}

fn check_id(id: &str) -> Result<(), RuntimeError> {
    if valid_kiln_id(id) { Ok(()) } else { Err(RuntimeError::Backend(format!("invalid kiln sandbox ID {id:?}"))) }
}

fn exec_populated(events: &str) -> Option<bool> {
    events.lines().find_map(|line| match line.split_once(' ')? {
        ("populated", "0") => Some(false),
        ("populated", "1") => Some(true),
        _ => None,
    })
}

/// The end of kiln's stderr as one printable line, for error messages.
fn summarize(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let text = text.trim();
    let tail: String = text.chars().rev().take(1000).collect::<Vec<_>>().into_iter().rev().collect();
    let line: String = tail
        .split('\n')
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    if line.is_empty() { "no error output".into() } else { line }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

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
            ["create", "--image=alpine", "--memory=67108864", "--cpus=0.500", "--pids=32", "--disk=16777216", "--net=none"]
        );
        let mut s = spec(Network::Allow(vec!["example.com:443".into(), "--net=full".into()]));
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
        let got = parse_ls("ID\tSTATUS\tSHIM\n18de-1\trunning\t42\nab-2\tstale\t\n").unwrap();
        assert_eq!(
            got,
            [
                BackendSandbox { id: "18de-1".into(), status: BackendStatus::Running },
                BackendSandbox { id: "ab-2".into(), status: BackendStatus::Stale },
            ]
        );
        assert_eq!(parse_ls("ID\tSTATUS\tSHIM\n").unwrap(), []);
        assert!(parse_ls("").is_err());
        assert!(parse_ls("NAME\tSTATE\n").is_err());
        assert!(parse_ls("ID\tSTATUS\tSHIM\nab-1\tzombie\t3\n").is_err());
        assert!(parse_ls("ID\tSTATUS\tSHIM\n../etc\trunning\t3\n").is_err());
    }

    #[test]
    fn summarizes_stderr_as_one_line() {
        assert_eq!(summarize(b"Error: connect\n\nCaused by:\n    gone\n"), "Error: connect; Caused by:; gone");
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
    async fn cancellation_waits_for_the_exec_cgroup_to_be_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("fake-kiln");
        let started = tmp.path().join("started");
        fs::write(
            &bin,
            format!(
                "#!/bin/sh\nexec </dev/null >/dev/null 2>&1\n: > '{}'\nexec sleep 30\n",
                started.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        let cgroup_root = tmp.path().join("cgroup");
        let exec_scope = cgroup_root.join("abcd/exec");
        fs::create_dir_all(&exec_scope).unwrap();
        let events = exec_scope.join("cgroup.events");
        fs::write(&events, "populated 1\n").unwrap();

        let runtime = Arc::new(KilnRuntime::with_cgroup_root(bin, &cgroup_root));
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let mut task = tokio::spawn(async move {
            let argv = vec!["sleep".to_string(), "30".to_string()];
            let spec = ExecSpec { argv: &argv, stdin: b"", timeout: Duration::from_secs(30), max_output: 1024 };
            runtime.exec("abcd", &spec, &task_cancel).await
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
            tokio::time::timeout(Duration::from_millis(100), &mut task).await.is_err(),
            "runtime returned before kiln's execution cgroup was empty"
        );
        fs::write(&events, "populated 0\n").unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(5), task).await.unwrap().unwrap().unwrap();
        assert_eq!(outcome.finish, ExecFinish::Canceled);
    }
}
