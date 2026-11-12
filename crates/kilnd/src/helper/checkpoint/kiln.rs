//! The checkpoint group's kiln CLI adapter: the fixed worker commands, their strict
//! output parsers and the host process table. Every worker is the configured kiln
//! executable with typed arguments (`KilnArgs`), run by kilnd's one subprocess runner:
//! cleared environment, parent-death SIGKILL, and a future that returns only after the
//! child was reaped.
use crate::checkpoint::CheckpointId;
use crate::helper::protocol::ItemKind;
use crate::model::Id128;
use crate::process::{self, CaptureCompletion, Finish, KilnArgs, KilnBinary, Outcome};
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// kiln's operation 6 lease (kiln `docs/checkpoint-lease-v1.md`).
pub const FEATURE_CHECKPOINT_LEASE: u32 = 0x40;
/// Every worker's retained stdout and stderr. A listing of the 4,096-entry inventory
/// bound is about half of it; anything longer is incomplete, never trusted.
pub const WORKER_OUTPUT: usize = 1 << 20;

pub type WorkerFuture = Pin<Box<dyn Future<Output = io::Result<Outcome>> + Send>>;
pub type SupportFuture = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;

/// One live process's arguments, for the untracked-worker scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessArgs {
    /// `setsid` made it a session leader: a kiln sandbox shim, never a worker.
    pub session_leader: bool,
    pub argv: Vec<String>,
}

/// How the checkpoint node starts workers and reads the process table. Tests replace
/// it; production is [`KilnWorkers`].
pub trait Workers: Send + Sync + 'static {
    /// Runs one kiln CLI. At the deadline or on cancellation it is killed, and the
    /// future resolves only once it was reaped. An unkillable child never resolves, so
    /// its caller keeps its slot and its artifact's dependency.
    fn run(&self, args: KilnArgs, deadline: Instant, cancel: CancellationToken) -> WorkerFuture;
    /// Every live process's arguments. An error means no absence can be certified.
    fn processes(&self) -> io::Result<Vec<ProcessArgs>>;
    /// Whether the installed CLI grants leases and lists the artifact namespace.
    fn support(&self, deadline: Instant, cancel: CancellationToken) -> SupportFuture;
}

pub struct KilnWorkers {
    bin: KilnBinary,
    cgroup_root: PathBuf,
}

impl KilnWorkers {
    pub fn new(bin: PathBuf) -> Self {
        Self {
            bin: KilnBinary::new(bin),
            cgroup_root: PathBuf::from("/sys/fs/cgroup/kiln"),
        }
    }
}

impl Workers for KilnWorkers {
    fn run(&self, args: KilnArgs, deadline: Instant, cancel: CancellationToken) -> WorkerFuture {
        let bin = self.bin.clone();
        Box::pin(async move {
            process::run(
                &process::Request {
                    tool: process::Tool::Kiln {
                        bin: &bin,
                        args: &args,
                    },
                    stdin: b"",
                    deadline,
                    max_output: WORKER_OUTPUT,
                },
                &cancel,
            )
            .await
        })
    }

    fn processes(&self) -> io::Result<Vec<ProcessArgs>> {
        process_table()
    }

    fn support(&self, deadline: Instant, cancel: CancellationToken) -> SupportFuture {
        let bin = self.bin.clone();
        let cgroup_root = self.cgroup_root.clone();
        Box::pin(async move {
            let core = kilnd_exec_core::runtime::kiln_direct::DirectKiln::new(&bin, &cgroup_root);
            let caps = core
                .capabilities(None, deadline, &cancel)
                .await
                .map_err(|e| format!("kiln capabilities: {e}"))?;
            if caps.features & FEATURE_CHECKPOINT_LEASE == 0 {
                return Err("the installed kiln does not grant checkpoint leases".into());
            }
            let out = process::run(
                &process::Request {
                    tool: process::Tool::Kiln {
                        bin: &bin,
                        args: &KilnArgs::checkpoint_ls(),
                    },
                    stdin: b"",
                    deadline,
                    max_output: WORKER_OUTPUT,
                },
                &cancel,
            )
            .await
            .map_err(|e| format!("kiln checkpoint ls: {e}"))?;
            let text = success_stdout(&out).ok_or("kiln checkpoint ls failed")?;
            parse_inventory(text)?;
            // Removal must be generation-checked: an older kiln would delete any
            // generation published under the name.
            let out = process::run(
                &process::Request {
                    tool: process::Tool::Kiln {
                        bin: &bin,
                        args: &KilnArgs::checkpoint_rm_help(),
                    },
                    stdin: b"",
                    deadline,
                    max_output: WORKER_OUTPUT,
                },
                &cancel,
            )
            .await
            .map_err(|e| format!("kiln checkpoint rm --help: {e}"))?;
            match success_stdout(&out) {
                Some(help) if help.contains("--generation") => Ok(()),
                _ => Err("the installed kiln's checkpoint rm does not check generations".into()),
            }
        })
    }
}

/// The exit code of a run whose stdout and stderr both reached EOF untruncated.
pub fn exit_code(out: &Outcome) -> Option<i32> {
    let complete = |data: &crate::model::Captured, completion: &CaptureCompletion| {
        *completion == CaptureCompletion::Eof && !data.truncated() && data.total_bytes_known
    };
    match &out.finish {
        Finish::Exited(status)
            if complete(&out.stdout, &out.stdout_completion)
                && complete(&out.stderr, &out.stderr_completion) =>
        {
            status.code()
        }
        _ => None,
    }
}

/// Stdout of a complete, successful run.
pub fn success_stdout(out: &Outcome) -> Option<&str> {
    (exit_code(out) == Some(0))
        .then(|| std::str::from_utf8(&out.stdout.data).ok())
        .flatten()
}

/// kiln's failure exit for checkpoint commands.
pub const CHECKPOINT_FAILED: i32 = 125;
/// `kiln create`'s exit for refusals known before allocation.
pub const CREATE_PREFLIGHT_FAILED: i32 = 124;

/// `kiln-checkpoint-removed 1`: whether anything existed.
pub fn parse_removed(text: &str) -> Result<bool, String> {
    match text {
        "kiln-checkpoint-removed 1\nexisted yes\n" => Ok(true),
        "kiln-checkpoint-removed 1\nexisted no\n" => Ok(false),
        _ => Err("malformed removal record".into()),
    }
}

/// One `kiln-checkpoint-inventory 1` line: its kind, owner instance (`None` for `-`)
/// and name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InventoryLine {
    pub kind: Option<ItemKind>,
    pub instance: Option<Id128>,
    pub name: String,
}

impl InventoryLine {
    /// The capture generation a staging or removal entry's name records:
    /// `.staging-C-G-nonce` and `.removing-C-G-pid-n`. None for a published artifact
    /// (its header holds it), an older kiln's `.removing-C-pid-n`, or `G` 0 (unknown).
    pub fn generation(&self) -> Option<u64> {
        let rest = match self.kind? {
            ItemKind::Published => return None,
            ItemKind::Staging => self.name.strip_prefix(".staging-")?.get(36..)?,
            ItemKind::Removing => self.name.strip_prefix(".removing-")?.get(36..)?,
        };
        let parts: Vec<&str> = rest.split('-').collect();
        let generation = match (self.kind?, parts.as_slice()) {
            (ItemKind::Staging, [g, _]) | (ItemKind::Removing, [g, _, _]) => *g,
            _ => return None,
        };
        if generation.is_empty() || !generation.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        generation.parse().ok().filter(|g| *g != 0)
    }

    /// The checkpoint a published, staging or removal entry belongs to.
    pub fn checkpoint(&self) -> Option<CheckpointId> {
        let id = match self.kind? {
            ItemKind::Published => self.name.as_str(),
            ItemKind::Staging => self.name.strip_prefix(".staging-")?.get(..35)?,
            ItemKind::Removing => self.name.strip_prefix(".removing-")?.get(..35)?,
        };
        CheckpointId::parse(id).ok()
    }
}

/// Strict: the header, then `published|staging|removing|unknown <instance or -> <name>`
/// per line, and a final newline. kiln lists names lossily; a name holding a newline
/// makes the listing malformed, so it is never read as complete.
pub fn parse_inventory(text: &str) -> Result<Vec<InventoryLine>, String> {
    let body = text
        .strip_suffix('\n')
        .ok_or("inventory without a final newline")?;
    let mut lines = body.split('\n');
    if lines.next() != Some("kiln-checkpoint-inventory 1") {
        return Err("unexpected inventory header".into());
    }
    let mut out = Vec::new();
    for line in lines {
        let (word, rest) = line.split_once(' ').ok_or("malformed inventory line")?;
        let (instance, name) = rest.split_once(' ').ok_or("malformed inventory line")?;
        let kind = match word {
            "published" => Some(ItemKind::Published),
            "staging" => Some(ItemKind::Staging),
            "removing" => Some(ItemKind::Removing),
            "unknown" => None,
            _ => return Err("unknown inventory kind".into()),
        };
        let instance = match instance {
            "-" if kind.is_none() => None,
            text => Some(Id128::parse(text)?),
        };
        if name.is_empty() {
            return Err("empty inventory name".into());
        }
        let line = InventoryLine {
            kind,
            instance,
            name: name.to_string(),
        };
        if kind.is_some() && line.checkpoint().is_none() {
            return Err("inventory entry without a checkpoint ID".into());
        }
        out.push(line);
    }
    Ok(out)
}

/// The value of `--flag V` or `--flag=V`.
fn flag<'a>(argv: &'a [String], name: &str) -> Option<&'a str> {
    argv.iter().enumerate().find_map(|(i, arg)| {
        if arg == name {
            argv.get(i + 1).map(String::as_str)
        } else {
            arg.strip_prefix(name)?.strip_prefix('=')
        }
    })
}

/// The artifact a process's arguments name, if any: a `checkpoint` subcommand with an
/// instance and checkpoint, or a `--from-checkpoint` create that is not a sandbox shim.
/// Matching is on arguments alone, whatever the executable, so a root operator's own
/// command blocks absence too.
pub fn named_artifact(process: &ProcessArgs) -> Option<(String, String)> {
    let argv = &process.argv;
    if let Some(source) = flag(argv, "--from-checkpoint") {
        // A restoring shim holds the artifact's lock, which keeps kiln's removal busy;
        // once restored it never reads it again. Only the CLI is a worker.
        if process.session_leader {
            return None;
        }
        let (instance, checkpoint) = source.split_once('/')?;
        return Some((instance.into(), checkpoint.into()));
    }
    if argv.iter().any(|arg| arg == "checkpoint") {
        return Some((
            flag(argv, "--instance")?.into(),
            flag(argv, "--checkpoint")?.into(),
        ));
    }
    None
}

/// The most process directories one scan reads; a busier host fails the scan, and so
/// certifies no absence.
#[cfg(target_os = "linux")]
const MAX_PROCESSES: usize = 65_536;

/// Every live process's arguments and session leadership, read beneath the helper's
/// private procfs instance (`crate::sys::procfs`: no link followed, no mount crossed).
/// A process that exits during the scan is skipped; any other failure fails the scan.
#[cfg(target_os = "linux")]
pub(crate) fn process_table() -> io::Result<Vec<ProcessArgs>> {
    use crate::sys::procfs;
    use std::io::Read;
    let gone = |e: &io::Error| {
        e.kind() == io::ErrorKind::NotFound || e.raw_os_error() == Some(libc::ESRCH)
    };
    let mut out = Vec::new();
    for entry in procfs::read_root_dir(MAX_PROCESSES)? {
        let Some(pid) = std::str::from_utf8(&entry.name)
            .ok()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let mut cmdline = Vec::new();
        match procfs::open(&format!("{pid}/cmdline"), libc::O_RDONLY)
            .and_then(|f| f.take(256 << 10).read_to_end(&mut cmdline))
        {
            Ok(_) => {}
            Err(e) if gone(&e) => continue,
            Err(e) => return Err(e),
        }
        // Kernel threads and zombies have no arguments and can do nothing more.
        if cmdline.is_empty() {
            continue;
        }
        let stat = match procfs::read_to_string(&format!("{pid}/stat")) {
            Ok(stat) => stat,
            Err(e) if gone(&e) => continue,
            Err(e) => return Err(e),
        };
        // `comm` may hold spaces and parentheses; the fields follow its last ')'.
        let session = stat
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().nth(3))
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or_else(|| io::Error::other("malformed process stat"))?;
        out.push(ProcessArgs {
            session_leader: session == pid,
            argv: cmdline
                .split(|b| *b == 0)
                .filter(|a| !a.is_empty())
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect(),
        });
    }
    Ok(out)
}

/// Production runs on Linux only: elsewhere no scan can prove anything.
#[cfg(not(target_os = "linux"))]
pub(crate) fn process_table() -> io::Result<Vec<ProcessArgs>> {
    Err(io::Error::other("no process table on this platform"))
}

/// The reason token at the start of a `kiln create` cause line (exit 124), or none.
pub fn create_reason(stderr: &[u8]) -> Option<crate::checkpoint::Reason> {
    let text = String::from_utf8_lossy(stderr);
    text.lines().find_map(|line| {
        let line = line.trim_start();
        // anyhow's numbered causes: `0: token: ...`.
        let line = match line.split_once(": ") {
            Some((n, rest)) if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) => rest,
            _ => line,
        };
        let line = line.strip_prefix("Error: ").unwrap_or(line);
        // A failure after allocation: `sandbox shim failed during setup: <token>: …`.
        let line = line
            .strip_prefix("sandbox shim failed during setup: ")
            .unwrap_or(line);
        let (token, _) = line.split_once(':')?;
        // `sandbox_unsupported:workspace_checkpoint` holds a colon of its own.
        let token = if token == "sandbox_unsupported" {
            "sandbox_unsupported:workspace_checkpoint"
        } else {
            token
        };
        crate::checkpoint::Reason::from_token(token)
    })
}
