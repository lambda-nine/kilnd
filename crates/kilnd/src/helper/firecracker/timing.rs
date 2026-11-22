//! M3-1: the create path's step timings, for diagnosis only. Every time is
//! `CLOCK_MONOTONIC` (the same clock as the wire's absolute deadlines, shared by H and the
//! workers it forks). P and S time their own steps and carry them back on the frames they
//! already send to H; H times its own steps and its calls to L and M. H keeps one bounded
//! timeline per create in memory and, once the create ends, writes it as one routine log
//! line. Nothing here is journaled, decides anything or changes when anything happens.
//!
//! A line holds the allocation ID, an outcome, step names from the fixed table below, and
//! numbers. The allocation ID is logged on purpose, so an operator can pick one create's
//! line: kilnd already logs it as the backend ID `fc-<id>`. No boot nonce, token key, work
//! UUID, instance or sandbox ID, leased uid, gid or cid, path or refusal reason is logged:
//! `kilnd-helper create-timings` reads only these fields back, and refuses a step name
//! outside the table.
//!
//! H never waits for a line. It writes one only after the create has ended, never before
//! it has answered S's READY record, and only with a write that can't block: see [`emit`].
use super::identity::AllocationKey;
use crate::model::Id128;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt::Write as _;
use std::io::{self, BufRead, Read};
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicU64, Ordering};

/// What precedes the JSON of every timing line, wherever it is found in a log line.
pub const LINE_PREFIX: &str = "kilnd-helper: create timing v1 ";
/// Steps one worker frame carries at most; later ones are not kept.
pub const MAX_FRAME_STEPS: usize = 32;
/// Steps one timeline keeps at most.
pub const MAX_TIMELINE_STEPS: usize = 256;
/// Creates timed at once; the oldest is ended as `evicted` to make room.
pub const MAX_OPEN: usize = 64;
/// The longest log line the report reads; longer lines are skipped.
const MAX_LINE: usize = 256 * 1024;
/// The most allocations one report prints.
pub const MAX_REPORTED: usize = 10_000;

/// Every step name a line can carry. The prefix says who timed it: `h` is H itself, `l`
/// and `m` are H's round trips to L and M, `p` is P, `s` is S, and `gap` is derived by the
/// report. `h.rec.*` is H's handling of one of S's records, its L call included.
pub const NAMES: &[&str] = &[
    "other",
    // C0: Preflight.
    "h.preflight.slot",
    "l.issue",
    "p.preflight",
    "p.preflight.walk",
    "p.preflight.manifest_read",
    "p.preflight.manifest_verify",
    "p.preflight.list",
    "p.preflight.hash.image",
    "p.preflight.hash.rootfs",
    "p.preflight.hash.kernel_config",
    "p.preflight.hash.kiln",
    "p.preflight.hash.broker",
    "p.preflight.hash.other",
    "p.preflight.table",
    "p.preflight.plan",
    "h.preflight.reply",
    // C1 is the daemon's: the report derives it from the gap before Create.
    "gap.daemon",
    // C2 and C3: Create, up to S's gate.
    "h.create.call",
    "h.create.serial",
    "l.lookup",
    "p.revalidate",
    "p.revalidate.verify_plan",
    "p.revalidate.walk",
    "p.revalidate.manifest_read",
    "p.revalidate.manifest_verify",
    "p.revalidate.list",
    "p.revalidate.hash.image",
    "p.revalidate.hash.rootfs",
    "p.revalidate.hash.kernel_config",
    "p.revalidate.hash.kiln",
    "p.revalidate.hash.broker",
    "p.revalidate.hash.other",
    "p.revalidate.table",
    "l.admit",
    "h.effects_check",
    "h.spawn_s",
    "m.watch",
    "l.record_worker",
    "l.preparing",
    "h.prep_lease",
    "h.open_gate",
    // S, C3 to READY (`link.step` names, then the spans inside them).
    "s.other",
    "s.parse_plan",
    "s.cgroup",
    "s.join",
    "s.artifacts",
    "s.hash.image",
    "s.hash.rootfs",
    "s.work_dir",
    "s.work_file",
    "s.fallocate",
    "s.mkfs",
    "s.mkfs.exec",
    "s.mkfs.run",
    "s.mkfs.sync",
    "s.private_files",
    "s.loop",
    "s.loop_configure",
    "s.loop_discard_off",
    "s.loop_persist",
    "s.jail",
    "s.jail_mount",
    "s.binds",
    "s.spawn_intent",
    "s.fork_jailer",
    "s.release_jailer",
    "s.jailer_observe",
    "s.continue_jailer",
    "s.adopt",
    "s.vmm_exe",
    "s.vmm_seccomp",
    "s.vmm_records",
    "s.vmm_checks",
    "s.harden",
    "s.journal_booting",
    "s.broker_workers",
    "s.broker_ready",
    "s.broker_journal",
    "s.journal_ready",
    "s.cleanup_stop",
    "s.cleanup_unmount",
    "s.cleanup_loop",
    "s.cleanup_files",
    // H's handling of each of S's records.
    "h.rec.intent",
    "h.rec.cgroup",
    "h.rec.work_dir",
    "h.rec.work_file",
    "h.rec.private_files",
    "h.rec.loop_intent",
    "h.rec.loop",
    "h.rec.loop_released",
    "h.rec.jail_intent",
    "h.rec.jail_dir",
    "h.rec.jail_mount",
    "h.rec.jail_binds",
    "h.rec.vmm",
    "h.rec.broker",
    "h.rec.exec",
    "h.rec.exec_history",
    "h.rec.phase.spawn_intent",
    "h.rec.phase.booting",
    "h.rec.phase.ready",
    "h.rec.phase.other",
    "h.rec.child.jailer",
    "h.rec.child.vm",
    "h.rec.child.relay",
    "h.rec.child.console",
    "h.rec.observed",
    "h.rec.inferred",
    "h.rec.initialize",
];

/// The record whose L commit is BOOTING, and the one whose commit is READY.
pub const BOOTING_RECORD: &str = "h.rec.phase.booting";
pub const READY_RECORD: &str = "h.rec.phase.ready";

/// One name from [`NAMES`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Name(&'static str);

impl Name {
    pub fn get(name: &str) -> Option<Self> {
        NAMES.iter().copied().find(|known| *known == name).map(Name)
    }

    /// A name from the table. One outside it is a mistake the tests catch; it is kept as
    /// `other`, never as its own text.
    pub fn of(name: &str) -> Self {
        debug_assert!(Self::get(name).is_some(), "{name} is not a timing name");
        Self::get(name).unwrap_or(Name("other"))
    }

    /// S's `link.step` name, as `s.<step>`.
    pub fn supervisor(step: &str) -> Self {
        NAMES
            .iter()
            .copied()
            .find(|known| known.strip_prefix("s.") == Some(step))
            .map(Name)
            .unwrap_or(Name("s.other"))
    }

    /// P's name for one bundle artifact's hash, in a preflight or a revalidation.
    pub fn artifact(revalidate: bool, artifact: &str) -> Self {
        let which = match artifact {
            "Image" => "image",
            "rootfs.squashfs" => "rootfs",
            "kernel.config" => "kernel_config",
            "kiln" => "kiln",
            "kilnd-guest-broker" => "broker",
            _ => "other",
        };
        Self::of(&format!("{}.hash.{which}", job_prefix(revalidate)))
    }

    /// One of P's steps, in a preflight or a revalidation.
    pub fn prep(revalidate: bool, step: &str) -> Self {
        Self::of(&format!("{}.{step}", job_prefix(revalidate)))
    }

    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

fn job_prefix(revalidate: bool) -> &'static str {
    if revalidate {
        "p.revalidate"
    } else {
        "p.preflight"
    }
}

impl Serialize for Name {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0)
    }
}

impl<'de> Deserialize<'de> for Name {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::get(&text).ok_or_else(|| serde::de::Error::custom("not a timing step name"))
    }
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

fn is_zero32(value: &u32) -> bool {
    *value == 0
}

/// One timed step: its monotonic start and end, the poll iterations and time it spent in
/// bounded waits, the records it waited on (S's, answered by H once L has them) and any
/// retries. On a log line the two times are offsets from the timeline's anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    #[serde(rename = "n")]
    pub name: Name,
    #[serde(rename = "s")]
    pub start_ns: u64,
    #[serde(rename = "e")]
    pub end_ns: u64,
    #[serde(rename = "p", default, skip_serializing_if = "is_zero32")]
    pub polls: u32,
    #[serde(rename = "w", default, skip_serializing_if = "is_zero")]
    pub waited_ns: u64,
    #[serde(rename = "r", default, skip_serializing_if = "is_zero32")]
    pub records: u32,
    #[serde(rename = "rw", default, skip_serializing_if = "is_zero")]
    pub record_ns: u64,
    #[serde(rename = "x", default, skip_serializing_if = "is_zero32")]
    pub retries: u32,
}

impl Step {
    pub fn new(name: Name, start_ns: u64, end_ns: u64) -> Self {
        Self {
            name,
            start_ns,
            end_ns: end_ns.max(start_ns),
            polls: 0,
            waited_ns: 0,
            records: 0,
            record_ns: 0,
            retries: 0,
        }
    }

    pub fn duration_ns(&self) -> u64 {
        self.end_ns.saturating_sub(self.start_ns)
    }
}

pub fn now() -> u64 {
    super::workers::monotonic_ns()
}

/// A worker's step clock: one open step at a time, each ended by the next. Completed
/// steps wait here until the worker's next frame to H carries them.
#[derive(Debug, Default)]
pub struct Clock {
    open: Option<Step>,
    done: Vec<Step>,
}

impl Clock {
    /// Ends the open step, if any, and opens `name`.
    pub fn begin(&mut self, name: Name) {
        self.begin_at(name, now());
    }

    pub fn begin_at(&mut self, name: Name, at: u64) {
        self.close_at(at);
        self.open = Some(Step::new(name, at, at));
    }

    /// Ends the open step.
    pub fn close(&mut self) {
        self.close_at(now());
    }

    fn close_at(&mut self, at: u64) {
        if let Some(mut step) = self.open.take() {
            step.end_ns = at.max(step.start_ns);
            if self.done.len() < MAX_FRAME_STEPS {
                self.done.push(step);
            }
        }
    }

    /// A bounded wait inside the open step: its iterations and its time.
    pub fn waited(&mut self, polls: u32, waited_ns: u64) {
        if let Some(step) = self.open.as_mut() {
            step.polls = step.polls.saturating_add(polls);
            step.waited_ns = step.waited_ns.saturating_add(waited_ns);
        }
    }

    /// One record the open step waited on until H answered.
    pub fn recorded(&mut self, waited_ns: u64) {
        if let Some(step) = self.open.as_mut() {
            step.records = step.records.saturating_add(1);
            step.record_ns = step.record_ns.saturating_add(waited_ns);
        }
    }

    pub fn retried(&mut self) {
        if let Some(step) = self.open.as_mut() {
            step.retries = step.retries.saturating_add(1);
        }
    }

    /// The completed steps, for the next frame.
    pub fn take(&mut self) -> Vec<Step> {
        std::mem::take(&mut self.done)
    }

    /// Ends the open step and returns everything, for a worker's last frame.
    pub fn finish(&mut self) -> Vec<Step> {
        self.close();
        self.take()
    }
}

/// How a timed create ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// READY was journaled.
    Ready,
    /// Preflight refused after the token was issued.
    PreflightRefused,
    /// Create was answered with anything but a new acceptance.
    Rejected,
    /// S stopped before READY: refused, expired or contained.
    Refused,
    Expired,
    /// The token's absence fence answered before READY was timed.
    Absent,
    /// The timeline made room for a newer one.
    Evicted,
}

impl Outcome {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::PreflightRefused => "preflight_refused",
            Self::Rejected => "rejected",
            Self::Refused => "refused",
            Self::Expired => "expired",
            Self::Absent => "absent",
            Self::Evicted => "evicted",
        }
    }
}

/// One finished create, as a log line carries it: step times are offsets from the
/// anchor, the start of its Preflight (or of its Create, when H never saw the Preflight).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub allocation: Id128,
    pub outcome: Outcome,
    /// READY was journaled, but S's last steps never reached H: S was gone, or the
    /// timeline was ended for room, before S's next frame.
    #[serde(default, skip_serializing_if = "is_false")]
    pub incomplete: bool,
    /// Lines this helper dropped before this one, since it started, because they could
    /// not be written without blocking (see [`emit`]).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub dropped: u64,
    pub steps: Vec<Step>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

struct Timeline {
    anchor_ns: u64,
    steps: Vec<Step>,
    created: bool,
    /// L committed READY; the line waits for S's last steps, on its next frame.
    ready: bool,
}

/// H's open timelines, bounded.
#[derive(Default)]
pub struct Book {
    open: HashMap<AllocationKey, Timeline>,
    order: VecDeque<AllocationKey>,
}

impl Book {
    /// A new timeline anchored at `anchor_ns`. Returns the record of one evicted for it.
    pub fn begin(&mut self, key: AllocationKey, anchor_ns: u64) -> Option<Record> {
        if self.open.contains_key(&key) {
            return None;
        }
        let evicted = if self.open.len() >= MAX_OPEN {
            self.order
                .front()
                .copied()
                .and_then(|oldest| self.finish(oldest, Outcome::Evicted))
        } else {
            None
        };
        self.open.insert(
            key,
            Timeline {
                anchor_ns,
                steps: Vec::new(),
                created: false,
                ready: false,
            },
        );
        self.order.push_back(key);
        evicted
    }

    /// The first Create of this token; a duplicate's steps are not recorded. Creates a
    /// timeline anchored here if H never saw this token's Preflight.
    pub fn create_call(&mut self, key: AllocationKey, at: u64) -> (bool, Option<Record>) {
        let evicted = self.begin(key, at);
        let timeline = self.open.get_mut(&key).expect("just begun");
        if timeline.created {
            return (false, evicted);
        }
        timeline.created = true;
        push(timeline, Step::new(Name::of("h.create.call"), at, at));
        (true, evicted)
    }

    pub fn step(&mut self, key: AllocationKey, step: Step) {
        if let Some(timeline) = self.open.get_mut(&key) {
            push(timeline, step);
        }
    }

    pub fn steps(&mut self, key: AllocationKey, steps: Vec<Step>) {
        if let Some(timeline) = self.open.get_mut(&key) {
            for step in steps {
                push(timeline, step);
            }
        }
    }

    pub fn is_open(&self, key: AllocationKey) -> bool {
        self.open.contains_key(&key)
    }

    /// L committed this create's READY. Its line waits for S's last steps, which S sends
    /// with its next frame, after H's answer: [`Book::ready_tail`].
    pub fn ready_committed(&mut self, key: AllocationKey) {
        if let Some(timeline) = self.open.get_mut(&key) {
            timeline.ready = true;
        }
    }

    /// S's last steps after READY (`s.journal_ready`, closed by H's answer): the
    /// timeline ends as READY, complete.
    pub fn ready_tail(&mut self, key: AllocationKey, steps: Vec<Step>) -> Option<Record> {
        self.steps(key, steps);
        self.finish(key, Outcome::Ready)
    }

    /// S is gone. A timeline whose READY was committed ends now, as READY but
    /// incomplete; any other stays open for its token's fence, as before.
    pub fn supervisor_gone(&mut self, key: AllocationKey) -> Option<Record> {
        if self.open.get(&key).is_some_and(|timeline| timeline.ready) {
            self.finish(key, Outcome::Ready)
        } else {
            None
        }
    }

    /// Ends the timeline and returns its record. Once READY is committed the outcome is
    /// READY whatever ended it, and incomplete unless S's last steps came first.
    pub fn finish(&mut self, key: AllocationKey, outcome: Outcome) -> Option<Record> {
        let timeline = self.open.remove(&key)?;
        self.order.retain(|other| *other != key);
        let anchor = timeline.anchor_ns;
        let tail = timeline
            .steps
            .iter()
            .any(|step| step.name.as_str() == READY_TAIL);
        let steps = timeline
            .steps
            .into_iter()
            .map(|mut step| {
                step.start_ns = step.start_ns.saturating_sub(anchor);
                step.end_ns = step.end_ns.saturating_sub(anchor).max(step.start_ns);
                step
            })
            .collect();
        let (outcome, incomplete) = if timeline.ready {
            (Outcome::Ready, !tail)
        } else {
            (outcome, false)
        };
        Some(Record {
            allocation: key.allocation,
            outcome,
            incomplete,
            dropped: 0,
            steps,
        })
    }
}

/// S's last step, from sending the READY record to H's answer. It reaches H on the frame
/// after that answer.
pub const READY_TAIL: &str = "s.journal_ready";

fn push(timeline: &mut Timeline, step: Step) {
    if timeline.steps.len() < MAX_TIMELINE_STEPS {
        timeline.steps.push(step);
    }
}

/// Lines not written since this helper started, because no write that can't block
/// could take them whole.
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// Lines dropped so far; the next line written carries this count.
pub fn dropped() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}

/// Writes one finished timeline to standard error. See [`emit_to`].
pub fn emit(record: Record) {
    emit_to(libc::STDERR_FILENO, record);
}

/// [`emit`], when a timeline did end.
pub fn emit_some(record: Option<Record>) {
    if let Some(record) = record {
        emit(record);
    }
}

/// Writes one finished timeline to `fd` without ever blocking H, which runs every
/// create on one thread. Returns whether the whole line was written; any other line is
/// dropped and counted, and the next line written carries the count as `dropped`.
///
/// - A socket (journald's stream, under systemd): one send with `MSG_DONTWAIT`. A socket
///   that can't take the whole line now costs the line, never time.
/// - Anything else (a regular file, a pipe, a terminal): dropped. No write to a shared
///   descriptor of those is sure not to block without changing its flags for every
///   process sharing it, and the shipped unit logs to journald's socket.
pub fn emit_to(fd: RawFd, mut record: Record) -> bool {
    record.dropped = dropped();
    let written = match serde_json::to_string(&record) {
        Ok(json) => {
            let mut line = String::with_capacity(LINE_PREFIX.len() + json.len() + 1);
            line.push_str(LINE_PREFIX);
            line.push_str(&json);
            line.push('\n');
            write_nonblocking(fd, line.as_bytes())
        }
        Err(_) => false,
    };
    if !written {
        DROPPED.fetch_add(1, Ordering::Relaxed);
    }
    written
}

fn write_nonblocking(fd: RawFd, bytes: &[u8]) -> bool {
    // SAFETY: stat is writable; fstat on a possibly closed descriptor only fails.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return false;
    }
    stat.st_mode & libc::S_IFMT == libc::S_IFSOCK && send_once(fd, bytes)
}

/// One non-blocking send. A partial line is ended, so it can't run into the next one,
/// and counts as dropped.
fn send_once(fd: RawFd, bytes: &[u8]) -> bool {
    let send = |bytes: &[u8]| {
        // SAFETY: the slice is live for the call.
        unsafe {
            libc::send(
                fd,
                bytes.as_ptr().cast(),
                bytes.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        }
    };
    let sent = send(bytes);
    if sent > 0 && (sent as usize) < bytes.len() {
        send(b"\n");
    }
    sent >= 0 && sent as usize == bytes.len()
}

// ---- the operator's report -------------------------------------------------------------

/// Which finished creates the report prints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Select {
    /// The last N in the input.
    Last(usize),
    /// The last line for this allocation.
    Allocation(Id128),
}

/// The timing records in `input` that `select` picks, oldest first. Lines without the
/// prefix, too long, or not a valid record are skipped.
pub fn read_records(mut input: impl BufRead, select: Select) -> io::Result<Vec<Record>> {
    let keep = match select {
        Select::Last(n) => n.clamp(1, MAX_REPORTED),
        Select::Allocation(_) => 1,
    };
    let mut records = VecDeque::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = (&mut input)
            .take(MAX_LINE as u64 + 1)
            .read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        if line.len() > MAX_LINE && line.last() != Some(&b'\n') {
            // Too long: drain the rest of the line in bounded pieces, keep none of it.
            loop {
                line.clear();
                let read = (&mut input)
                    .take(MAX_LINE as u64)
                    .read_until(b'\n', &mut line)?;
                if read == 0 || line.last() == Some(&b'\n') {
                    break;
                }
            }
            continue;
        }
        let Some(record) = parse_line(&line) else {
            continue;
        };
        if let Select::Allocation(wanted) = select
            && record.allocation != wanted
        {
            continue;
        }
        if records.len() == keep {
            records.pop_front();
        }
        records.push_back(record);
    }
    Ok(records.into())
}

fn parse_line(line: &[u8]) -> Option<Record> {
    let text = std::str::from_utf8(line).ok()?;
    let at = text.find(LINE_PREFIX)?;
    serde_json::from_str(text[at + LINE_PREFIX.len()..].trim_end()).ok()
}

fn ms(ns: u64) -> String {
    format!("{:.3}", ns as f64 / 1e6)
}

fn cell(value: u64, render: impl Fn(u64) -> String) -> String {
    if value == 0 {
        "-".into()
    } else {
        render(value)
    }
}

/// The end of the record whose commit is `name`, as an offset.
fn milestone(record: &Record, name: &str) -> Option<u64> {
    record
        .steps
        .iter()
        .find(|step| step.name.as_str() == name)
        .map(|step| step.end_ns)
}

/// The steps in start order, with the daemon's gap (Preflight's reply to Create's call:
/// its C1 commit and both hops) derived where both ends are present.
fn rows(record: &Record) -> Vec<Step> {
    let mut rows = record.steps.clone();
    let reply = milestone(record, "h.preflight.reply");
    let call = record
        .steps
        .iter()
        .find(|step| step.name.as_str() == "h.create.call")
        .map(|step| step.start_ns);
    if let (Some(reply), Some(call)) = (reply, call)
        && call >= reply
    {
        rows.push(Step::new(Name::of("gap.daemon"), reply, call));
    }
    rows.sort_by_key(|step| (step.start_ns, step.end_ns));
    rows
}

/// One create's waterfall: each step's start offset and duration, its waits, records and
/// retries.
pub fn waterfall(record: &Record) -> String {
    let mut out = String::new();
    let _ = write!(
        out,
        "allocation {}  outcome {}",
        record.allocation,
        record.outcome.as_str()
    );
    if record.incomplete {
        out.push_str(" (incomplete)");
    }
    for (label, name) in [("booting", BOOTING_RECORD), ("ready", READY_RECORD)] {
        if let Some(at) = milestone(record, name) {
            let _ = write!(out, "  {label} {} ms", ms(at));
        }
    }
    let _ = write!(out, "  steps {}", record.steps.len());
    if record.dropped > 0 {
        let _ = write!(out, "  dropped before {}", record.dropped);
    }
    out.push('\n');
    let _ = writeln!(
        out,
        "{:>11} {:>10} {:>6} {:>10} {:>5} {:>10} {:>5}  step",
        "start_ms", "dur_ms", "polls", "wait_ms", "recs", "rec_ms", "retry"
    );
    for step in rows(record) {
        let _ = writeln!(
            out,
            "{:>11} {:>10} {:>6} {:>10} {:>5} {:>10} {:>5}  {}",
            ms(step.start_ns),
            ms(step.duration_ns()),
            cell(step.polls.into(), |v| v.to_string()),
            cell(step.waited_ns, ms),
            cell(step.records.into(), |v| v.to_string()),
            cell(step.record_ns, ms),
            cell(step.retries.into(), |v| v.to_string()),
            step.name.as_str()
        );
    }
    out
}

/// Nearest rank, as B5's boot timings take it.
fn percentile(sorted: &[u64], q: f64) -> u64 {
    sorted[((q * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len()) - 1]
}

/// Per step name, over the creates given: each create's total time in that step (a step
/// that repeats, such as an intent record, is summed), then p50, p95 and max across the
/// creates that have it, slowest p50 first. BOOTING and READY lead.
pub fn summary(records: &[Record]) -> String {
    #[derive(Default)]
    struct Totals {
        duration: Vec<u64>,
        waited: Vec<u64>,
        recorded: Vec<u64>,
        rows: usize,
    }
    let mut by_name: BTreeMap<&'static str, Totals> = BTreeMap::new();
    let mut booting = Vec::new();
    let mut ready = Vec::new();
    for record in records {
        let mut this: BTreeMap<&'static str, (u64, u64, u64, usize)> = BTreeMap::new();
        for step in rows(record) {
            let entry = this.entry(step.name.as_str()).or_default();
            entry.0 = entry.0.saturating_add(step.duration_ns());
            entry.1 = entry.1.saturating_add(step.waited_ns);
            entry.2 = entry.2.saturating_add(step.record_ns);
            entry.3 += 1;
        }
        for (name, (duration, waited, recorded, rows)) in this {
            let totals = by_name.entry(name).or_default();
            totals.duration.push(duration);
            totals.waited.push(waited);
            totals.recorded.push(recorded);
            totals.rows += rows;
        }
        booting.extend(milestone(record, BOOTING_RECORD));
        ready.extend(milestone(record, READY_RECORD));
    }
    let mut out = String::new();
    let _ = writeln!(out, "creates {}", records.len());
    let header = |out: &mut String| {
        let _ = writeln!(
            out,
            "{:>4} {:>5} {:>10} {:>10} {:>10} {:>11} {:>10}  step",
            "n", "rows", "p50_ms", "p95_ms", "max_ms", "wait_p50", "rec_p50"
        );
    };
    header(&mut out);
    for (label, values) in [
        ("BOOTING (offset)", &mut booting),
        ("READY (offset)", &mut ready),
    ] {
        if values.is_empty() {
            continue;
        }
        values.sort_unstable();
        let _ = writeln!(
            out,
            "{:>4} {:>5} {:>10} {:>10} {:>10} {:>11} {:>10}  {label}",
            values.len(),
            "-",
            ms(percentile(values, 0.5)),
            ms(percentile(values, 0.95)),
            ms(*values.last().unwrap()),
            "-",
            "-"
        );
    }
    let mut lines: Vec<(u64, String)> = by_name
        .into_iter()
        .map(|(name, mut totals)| {
            totals.duration.sort_unstable();
            totals.waited.sort_unstable();
            totals.recorded.sort_unstable();
            let p50 = percentile(&totals.duration, 0.5);
            let line = format!(
                "{:>4} {:>5} {:>10} {:>10} {:>10} {:>11} {:>10}  {name}",
                totals.duration.len(),
                totals.rows,
                ms(p50),
                ms(percentile(&totals.duration, 0.95)),
                ms(*totals.duration.last().unwrap()),
                cell(percentile(&totals.waited, 0.5), ms),
                cell(percentile(&totals.recorded, 0.5), ms),
            );
            (p50, line)
        })
        .collect();
    lines.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    for (_, line) in lines {
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// `kilnd-helper create-timings`: the selected creates' waterfalls, or their summary.
pub fn report(input: impl BufRead, select: Select, summarize: bool) -> io::Result<String> {
    let records = read_records(input, select)?;
    if records.is_empty() {
        return Ok("no create timings found\n".into());
    }
    if summarize {
        return Ok(summary(&records));
    }
    let mut out = String::new();
    for record in &records {
        out.push_str(&waterfall(record));
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> AllocationKey {
        AllocationKey {
            instance: Id128::from_bytes([1; 16]),
            allocation: Id128::from_bytes([n; 16]),
        }
    }

    #[test]
    fn names_are_unique_and_plain() {
        let mut seen = std::collections::BTreeSet::new();
        for name in NAMES {
            assert!(seen.insert(*name), "{name} twice");
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._".contains(&b)),
                "{name}"
            );
        }
        for revalidate in [false, true] {
            for artifact in [
                "Image",
                "rootfs.squashfs",
                "kernel.config",
                "kiln",
                "kilnd-guest-broker",
                "anything else",
            ] {
                assert_ne!(Name::artifact(revalidate, artifact).as_str(), "other");
            }
            for step in ["walk", "manifest_read", "manifest_verify", "list", "table"] {
                assert_ne!(Name::prep(revalidate, step).as_str(), "other");
            }
        }
        assert_ne!(Name::prep(false, "plan").as_str(), "other");
        assert_ne!(Name::prep(true, "verify_plan").as_str(), "other");
    }

    /// Every step name the code uses is in the table: S's `link.step` names and every
    /// literal timing name in the files that time steps.
    #[test]
    fn every_name_the_code_uses_is_in_the_table() {
        let files = [
            ("mod.rs", include_str!("mod.rs")),
            ("lifecycle.rs", include_str!("lifecycle.rs")),
            ("supervisor.rs", include_str!("supervisor.rs")),
            ("broker.rs", include_str!("broker.rs")),
            ("workers.rs", include_str!("workers.rs")),
        ];
        let mut checked = 0;
        for (file, text) in files {
            for (at, _) in text.match_indices("link.step(\"") {
                let rest = &text[at + "link.step(\"".len()..];
                let step = &rest[..rest.find('"').unwrap()];
                assert_ne!(
                    Name::supervisor(step).as_str(),
                    "s.other",
                    "{file}: link.step({step:?}) has no s.{step}"
                );
                checked += 1;
            }
            for (at, _) in text.match_indices('"') {
                let rest = &text[at + 1..];
                let Some(end) = rest.find('"') else { continue };
                let literal = &rest[..end];
                let timed = ["h.", "l.", "m.", "p.", "s.", "gap."]
                    .iter()
                    .any(|prefix| literal.starts_with(prefix))
                    && literal.len() > 2
                    && literal.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b"._".contains(&b)
                    });
                if timed {
                    assert!(Name::get(literal).is_some(), "{file}: {literal:?}");
                    checked += 1;
                }
            }
        }
        assert!(checked > 60, "only {checked} names found");
    }

    #[test]
    fn the_clock_ends_each_step_with_the_next_and_bounds_a_frame() {
        let mut clock = Clock::default();
        clock.waited(3, 7);
        clock.recorded(9);
        assert!(clock.take().is_empty(), "nothing is open, nothing counted");
        clock.begin_at(Name::of("s.cgroup"), 100);
        clock.waited(2, 40);
        clock.waited(1, 10);
        clock.recorded(25);
        clock.recorded(5);
        clock.retried();
        clock.begin_at(Name::of("s.join"), 150);
        let steps = clock.take();
        assert_eq!(steps.len(), 1);
        let step = steps[0];
        assert_eq!(
            (step.name.as_str(), step.start_ns, step.end_ns),
            ("s.cgroup", 100, 150)
        );
        assert_eq!(
            (
                step.polls,
                step.waited_ns,
                step.records,
                step.record_ns,
                step.retries
            ),
            (3, 50, 2, 30, 1)
        );
        // An earlier end than start is clamped, never negative.
        clock.begin_at(Name::of("s.artifacts"), 120);
        assert_eq!(clock.take()[0].duration_ns(), 0);
        for at in 0..(MAX_FRAME_STEPS as u64 + 10) {
            clock.begin_at(Name::of("s.loop"), 200 + at);
        }
        assert_eq!(clock.take().len(), MAX_FRAME_STEPS);
        let last = clock.finish();
        assert_eq!(last.len(), 1, "finish ends the open step");
        assert!(clock.finish().is_empty());
    }

    #[test]
    fn the_book_keeps_one_timeline_per_create_and_bounds_them() {
        let mut book = Book::default();
        assert!(book.begin(key(1), 1_000).is_none());
        book.step(key(1), Step::new(Name::of("l.issue"), 1_010, 1_050));
        book.step(key(9), Step::new(Name::of("l.issue"), 0, 1));
        let (first, _) = book.create_call(key(1), 2_000);
        assert!(first);
        let (again, _) = book.create_call(key(1), 2_500);
        assert!(!again, "a duplicate Create is not timed");
        book.steps(key(1), vec![Step::new(Name::of("s.mkfs"), 3_000, 3_400)]);
        let record = book.finish(key(1), Outcome::Ready).unwrap();
        assert!(book.finish(key(1), Outcome::Ready).is_none(), "once");
        assert_eq!(record.outcome, Outcome::Ready);
        assert!(!record.incomplete);
        let offsets: Vec<_> = record
            .steps
            .iter()
            .map(|s| (s.name.as_str(), s.start_ns, s.end_ns))
            .collect();
        assert_eq!(
            offsets,
            vec![
                ("l.issue", 10, 50),
                ("h.create.call", 1_000, 1_000),
                ("s.mkfs", 2_000, 2_400)
            ]
        );
        // A Create H never saw the Preflight of is anchored at its call.
        let (first, _) = book.create_call(key(2), 5_000);
        assert!(first);
        let record = book.finish(key(2), Outcome::Rejected).unwrap();
        assert_eq!(record.steps[0].start_ns, 0);
        // Full: the oldest makes room, ended as evicted.
        for n in 0..MAX_OPEN {
            assert!(book.begin(key(10 + n as u8), n as u64).is_none());
        }
        let evicted = book.begin(key(200), 0).expect("one evicted");
        assert_eq!(
            (evicted.allocation, evicted.outcome),
            (key(10).allocation, Outcome::Evicted)
        );
        assert!(book.is_open(key(200)) && !book.is_open(key(10)));
        // A timeline keeps at most its bound of steps.
        for at in 0..(MAX_TIMELINE_STEPS as u64 + 5) {
            book.step(key(200), Step::new(Name::of("h.rec.intent"), at, at));
        }
        let record = book.finish(key(200), Outcome::Absent).unwrap();
        assert_eq!(record.steps.len(), MAX_TIMELINE_STEPS);
    }

    fn line(allocation: u8, outcome: &str, steps: &str) -> String {
        format!(
            "Nov 22 12:00:00 vm kilnd-helper[42]: {LINE_PREFIX}{{\"allocation\":\"{}\",\"outcome\":\"{outcome}\",\"steps\":[{steps}]}}\n",
            Id128::from_bytes([allocation; 16])
        )
    }

    #[test]
    fn the_report_reads_only_valid_timing_lines_and_selects_them() {
        let good = |n: u8| {
            line(
                n,
                "ready",
                &format!(
                    r#"{{"n":"h.preflight.slot","s":0,"e":1000}},{{"n":"h.preflight.reply","s":2000000,"e":2000000}},{{"n":"h.create.call","s":5000000,"e":5000000}},{{"n":"s.mkfs","s":6000000,"e":{},"p":4,"w":3000000,"r":1,"rw":500000,"x":1}},{{"n":"h.rec.phase.booting","s":9000000,"e":9500000}},{{"n":"h.rec.phase.ready","s":12000000,"e":12250000}}"#,
                    6_000_000 + u64::from(n) * 1_000_000
                ),
            )
        };
        let mut input = String::new();
        input.push_str("an ordinary log line\n");
        input.push_str(&good(1));
        input.push_str(&line(2, "ready", r#"{"n":"not.a.name","s":0,"e":1}"#));
        input.push_str(&line(3, "ready", r#"{"n":"s.mkfs","s":0,"e":1,"extra":1}"#));
        input.push_str(&format!("{LINE_PREFIX}{{not json\n"));
        input.push_str(&format!("{LINE_PREFIX}{}\n", "x".repeat(MAX_LINE + 10)));
        input.push_str(&good(4));
        input.push_str(&good(5));
        let read = |select| read_records(input.as_bytes(), select).unwrap();
        let all = read(Select::Last(100));
        let ids: Vec<_> = all.iter().map(|r| r.allocation).collect();
        assert_eq!(
            ids,
            [1u8, 4, 5].map(|n| Id128::from_bytes([n; 16])).to_vec(),
            "unknown names, unknown fields, bad JSON and overlong lines are skipped"
        );
        assert_eq!(
            read(Select::Last(1))[0].allocation,
            Id128::from_bytes([5; 16])
        );
        let one = read(Select::Allocation(Id128::from_bytes([4; 16])));
        assert_eq!(one.len(), 1);
        assert!(read(Select::Allocation(Id128::from_bytes([2; 16]))).is_empty());

        let shown = waterfall(&one[0]);
        assert!(shown.contains("booting 9.500 ms"), "{shown}");
        assert!(shown.contains("ready 12.250 ms"), "{shown}");
        let gap = shown.lines().find(|l| l.ends_with("gap.daemon")).unwrap();
        assert!(gap.contains("2.000") && gap.contains("3.000"), "{gap}");
        let mkfs = shown.lines().find(|l| l.ends_with("s.mkfs")).unwrap();
        assert!(mkfs.contains("4.000") && mkfs.contains("3.000"), "{mkfs}");

        let summary = summary(&all);
        assert!(summary.starts_with("creates 3\n"), "{summary}");
        let mkfs = summary.lines().find(|l| l.ends_with("  s.mkfs")).unwrap();
        // 1, 4 and 5 ms: p50 4, p95 5, max 5.
        assert!(
            mkfs.contains(" 4.000 ") && mkfs.contains(" 5.000 "),
            "{mkfs}"
        );
        let first_step = summary.lines().nth(4).unwrap();
        assert!(
            first_step.ends_with("s.mkfs"),
            "slowest p50 first: {summary}"
        );
        assert!(summary.contains("READY (offset)"));
        assert_eq!(
            report(&b"nothing\n"[..], Select::Last(5), false).unwrap(),
            "no create timings found\n"
        );
    }

    /// A line names only the allocation, the outcome and the table's steps: these are
    /// the only keys a record can serialize.
    #[test]
    fn a_line_has_only_the_allocation_outcome_and_steps() {
        let mut book = Book::default();
        book.begin(key(7), 10);
        let mut step = Step::new(Name::of("s.loop_configure"), 11, 20);
        (
            step.polls,
            step.waited_ns,
            step.records,
            step.record_ns,
            step.retries,
        ) = (1, 2, 3, 4, 5);
        book.step(key(7), step);
        let record = book.finish(key(7), Outcome::Ready).unwrap();
        let value = serde_json::to_value(&record).unwrap();
        let keys: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys, ["allocation", "outcome", "steps"]);
        let keys: Vec<_> = value["steps"][0]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert_eq!(keys, ["e", "n", "p", "r", "rw", "s", "w", "x"]);
    }
    /// READY's commit doesn't end the line: S's last step comes on its next frame, after
    /// H's answer. Without it the line still ends, once, as READY marked incomplete.
    #[test]
    fn ready_waits_for_the_supervisors_tail() {
        let tail = |at: u64| vec![Step::new(Name::of(READY_TAIL), at, at + 5)];
        let mut book = Book::default();
        book.begin(key(1), 0);
        book.step(key(1), Step::new(Name::of(READY_RECORD), 10, 20));
        book.ready_committed(key(1));
        assert!(book.is_open(key(1)), "the commit alone ends nothing");
        assert!(book.supervisor_gone(key(9)).is_none());
        let record = book.ready_tail(key(1), tail(15)).unwrap();
        assert_eq!((record.outcome, record.incomplete), (Outcome::Ready, false));
        assert!(record.steps.iter().any(|s| s.name.as_str() == READY_TAIL));
        assert!(book.ready_tail(key(1), tail(15)).is_none(), "once");
        assert!(book.supervisor_gone(key(1)).is_none(), "once");

        // S gone after the commit, before its tail.
        book.begin(key(2), 0);
        book.ready_committed(key(2));
        let record = book.supervisor_gone(key(2)).unwrap();
        assert_eq!((record.outcome, record.incomplete), (Outcome::Ready, true));
        // A tail without the step, or another end after the commit, is incomplete READY.
        book.begin(key(3), 0);
        book.ready_committed(key(3));
        let record = book.ready_tail(key(3), Vec::new()).unwrap();
        assert_eq!((record.outcome, record.incomplete), (Outcome::Ready, true));
        book.begin(key(4), 0);
        book.ready_committed(key(4));
        let record = book.finish(key(4), Outcome::Absent).unwrap();
        assert_eq!((record.outcome, record.incomplete), (Outcome::Ready, true));
        let value = serde_json::to_value(&record).unwrap();
        assert_eq!(value["incomplete"], true);
        // Before any commit, S's exit leaves the timeline for its token's fence.
        book.begin(key(5), 0);
        assert!(book.supervisor_gone(key(5)).is_none());
        let record = book.finish(key(5), Outcome::Absent).unwrap();
        assert_eq!((record.outcome, record.incomplete), (Outcome::Absent, false));
        let value = serde_json::to_value(&record).unwrap();
        assert!(value.get("incomplete").is_none() && value.get("dropped").is_none());
    }

    fn one_record() -> Record {
        let mut book = Book::default();
        book.begin(key(3), 0);
        book.step(key(3), Step::new(Name::of("l.issue"), 1, 2));
        book.finish(key(3), Outcome::Ready).unwrap()
    }

    /// Runs `emit_to` on its own thread: a write that blocked would hang this test.
    fn emit_within(fd: RawFd, bound: std::time::Duration) -> (bool, std::time::Duration) {
        let (done, result) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let started = std::time::Instant::now();
            let written = emit_to(fd, one_record());
            let _ = done.send((written, started.elapsed()));
        });
        result
            .recv_timeout(bound)
            .expect("emit_to blocked on a stalled sink")
    }

    fn pipe() -> (std::os::fd::OwnedFd, std::os::fd::OwnedFd) {
        use std::os::fd::FromRawFd;
        let mut fds = [0; 2];
        // SAFETY: fds is writable.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: both just created and owned here.
        unsafe {
            (
                std::os::fd::OwnedFd::from_raw_fd(fds[0]),
                std::os::fd::OwnedFd::from_raw_fd(fds[1]),
            )
        }
    }

    fn set_nonblocking(fd: RawFd, on: bool) {
        // SAFETY: fcntl on an owned descriptor.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            let flags = if on {
                flags | libc::O_NONBLOCK
            } else {
                flags & !libc::O_NONBLOCK
            };
            assert_eq!(libc::fcntl(fd, libc::F_SETFL, flags), 0);
        }
    }

    /// Fills `fd` until not one more byte fits, then leaves it blocking, as a stderr
    /// whose reader has stalled would be.
    fn fill(fd: RawFd, socket: bool) {
        set_nonblocking(fd, true);
        for chunk in [65_536usize, 1] {
            let bytes = vec![b'x'; chunk];
            loop {
                // SAFETY: the buffer is live for the call.
                let n = unsafe {
                    if socket {
                        libc::send(fd, bytes.as_ptr().cast(), chunk, libc::MSG_DONTWAIT)
                    } else {
                        libc::write(fd, bytes.as_ptr().cast(), chunk)
                    }
                };
                if n <= 0 {
                    break;
                }
            }
        }
        set_nonblocking(fd, false);
    }

    /// M3-1 follow-up: a stalled sink costs the line, never time. H emits on the thread
    /// that answers S, so a write that waited could hold S's acknowledgements.
    #[test]
    fn a_stalled_sink_never_blocks_the_emit_and_drops_are_counted() {
        use std::io::Read as _;
        use std::os::fd::AsRawFd;
        let bound = std::time::Duration::from_secs(10);

        // A full, blocking pipe nobody reads: H's stderr behind a stalled reader.
        let (_reader, writer) = pipe();
        fill(writer.as_raw_fd(), false);
        let before = dropped();
        let (written, took) = emit_within(writer.as_raw_fd(), bound);
        assert!(!written, "a full pipe takes no line");
        assert!(took < std::time::Duration::from_secs(1), "{took:?}");
        assert!(dropped() > before, "the drop is counted");

        // A full, blocking socket. (Darwin can block a partial send despite MSG_DONTWAIT;
        // H's journald socket is a Linux one.)
        #[cfg(target_os = "linux")]
        {
            let (ours, _theirs) = std::os::unix::net::UnixStream::pair().unwrap();
            fill(ours.as_raw_fd(), true);
            let before = dropped();
            let (written, took) = emit_within(ours.as_raw_fd(), bound);
            assert!(!written, "a full socket takes no line");
            assert!(took < std::time::Duration::from_secs(1), "{took:?}");
            assert!(dropped() > before);
        }

        // A regular file is never written either.
        let file = tempfile::tempfile().unwrap();
        let before = dropped();
        assert!(!emit_within(file.as_raw_fd(), bound).0);
        assert!(dropped() > before);
        assert_eq!(file.metadata().unwrap().len(), 0);

        // A socket with room takes the whole line, which carries the count so far.
        let (ours, mut theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let floor = dropped();
        assert!(emit_within(ours.as_raw_fd(), bound).0);
        drop(ours);
        let mut text = String::new();
        theirs.read_to_string(&mut text).unwrap();
        let records = read_records(text.as_bytes(), Select::Last(5)).unwrap();
        assert_eq!(records.len(), 1, "{text}");
        assert!(records[0].dropped >= floor && floor >= 2, "{text}");

        // A pipe with room is dropped too, and left blocking for everyone else.
        let (reader, writer) = pipe();
        let before = dropped();
        assert!(!emit_within(writer.as_raw_fd(), bound).0);
        assert!(dropped() > before);
        // SAFETY: fcntl on an owned descriptor.
        let flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(flags & libc::O_NONBLOCK, 0, "the shared descriptor is unchanged");
        drop(writer);
        let mut text = String::new();
        std::fs::File::from(reader).read_to_string(&mut text).unwrap();
        assert!(text.is_empty(), "{text}");
    }
}
