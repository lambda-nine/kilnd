//! M3-1: the create path's step timings, for diagnosis only. Every time is
//! `CLOCK_MONOTONIC` (the same clock as the wire's absolute deadlines, shared by H and the
//! workers it forks). P and S time their own steps and carry them back on the frames they
//! already send to H; H times its own steps and its calls to L and M. H keeps one bounded
//! timeline per create in memory and, once the create ends, writes it as one routine log
//! line. Nothing here is journaled, decides anything or changes when anything happens.
//!
//! A line holds the allocation ID (kilnd already logs it as the backend ID `fc-<id>`), an
//! outcome and step names from the fixed table below, and numbers. Never a boot nonce,
//! token key, work UUID, identity, path or reason: `kilnd-helper create-timings` reads only
//! these fields back, and refuses a step name outside the table.
use super::identity::AllocationKey;
use crate::model::Id128;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt::Write as _;
use std::io::{self, BufRead, Read};

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
    pub steps: Vec<Step>,
}

struct Timeline {
    anchor_ns: u64,
    steps: Vec<Step>,
    created: bool,
}

/// H's open timelines, bounded.
#[derive(Default)]
pub struct Book {
    open: HashMap<AllocationKey, Timeline>,
    order: VecDeque<AllocationKey>,
}

impl Book {
    /// A new timeline anchored at `anchor_ns`. Returns the line of one evicted for it.
    pub fn begin(&mut self, key: AllocationKey, anchor_ns: u64) -> Option<String> {
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
            },
        );
        self.order.push_back(key);
        evicted
    }

    /// The first Create of this token; a duplicate's steps are not recorded. Creates a
    /// timeline anchored here if H never saw this token's Preflight.
    pub fn create_call(&mut self, key: AllocationKey, at: u64) -> (bool, Option<String>) {
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

    /// Ends the timeline and returns its line (without [`LINE_PREFIX`]).
    pub fn finish(&mut self, key: AllocationKey, outcome: Outcome) -> Option<String> {
        let timeline = self.open.remove(&key)?;
        self.order.retain(|other| *other != key);
        let anchor = timeline.anchor_ns;
        let steps = timeline
            .steps
            .into_iter()
            .map(|mut step| {
                step.start_ns = step.start_ns.saturating_sub(anchor);
                step.end_ns = step.end_ns.saturating_sub(anchor).max(step.start_ns);
                step
            })
            .collect();
        serde_json::to_string(&Record {
            allocation: key.allocation,
            outcome,
            steps,
        })
        .ok()
    }
}

fn push(timeline: &mut Timeline, step: Step) {
    if timeline.steps.len() < MAX_TIMELINE_STEPS {
        timeline.steps.push(step);
    }
}

/// Writes one finished timeline to standard error without ever blocking H: on a socket
/// (journald's stream, under systemd) a single non-blocking send, dropped if the socket
/// can't take it; on a regular file an ordinary write; anything else (a pipe, a
/// terminal, which a stalled reader could block) is skipped.
pub fn emit(json: &str) {
    let mut line = String::with_capacity(LINE_PREFIX.len() + json.len() + 1);
    line.push_str(LINE_PREFIX);
    line.push_str(json);
    line.push('\n');
    let bytes = line.as_bytes();
    // SAFETY: stat is writable; fstat on a possibly closed descriptor only fails.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(libc::STDERR_FILENO, &mut stat) } != 0 {
        return;
    }
    match stat.st_mode & libc::S_IFMT {
        libc::S_IFSOCK => {
            // SAFETY: the slice is live for the call.
            let sent = unsafe {
                libc::send(
                    libc::STDERR_FILENO,
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            // A partial line is ended, so it can't run into the next one.
            if sent > 0 && (sent as usize) < bytes.len() {
                // SAFETY: a one-byte static buffer.
                unsafe {
                    libc::send(
                        libc::STDERR_FILENO,
                        b"\n".as_ptr().cast(),
                        1,
                        libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                    )
                };
            }
        }
        libc::S_IFREG => {
            // SAFETY: the slice is live for the call.
            unsafe { libc::write(libc::STDERR_FILENO, bytes.as_ptr().cast(), bytes.len()) };
        }
        _ => {}
    }
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
    for (label, name) in [("booting", BOOTING_RECORD), ("ready", READY_RECORD)] {
        if let Some(at) = milestone(record, name) {
            let _ = write!(out, "  {label} {} ms", ms(at));
        }
    }
    let _ = writeln!(out, "  steps {}", record.steps.len());
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
        let line = book.finish(key(1), Outcome::Ready).unwrap();
        assert!(book.finish(key(1), Outcome::Ready).is_none(), "once");
        let record: Record = serde_json::from_str(&line).unwrap();
        assert_eq!(record.outcome, Outcome::Ready);
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
        let record: Record =
            serde_json::from_str(&book.finish(key(2), Outcome::Rejected).unwrap()).unwrap();
        assert_eq!(record.steps[0].start_ns, 0);
        // Full: the oldest makes room, ended as evicted.
        for n in 0..MAX_OPEN {
            assert!(book.begin(key(10 + n as u8), n as u64).is_none());
        }
        let evicted: Record =
            serde_json::from_str(&book.begin(key(200), 0).expect("one evicted")).unwrap();
        assert_eq!(
            (evicted.allocation, evicted.outcome),
            (key(10).allocation, Outcome::Evicted)
        );
        assert!(book.is_open(key(200)) && !book.is_open(key(10)));
        // A timeline keeps at most its bound of steps.
        for at in 0..(MAX_TIMELINE_STEPS as u64 + 5) {
            book.step(key(200), Step::new(Name::of("h.rec.intent"), at, at));
        }
        let record: Record =
            serde_json::from_str(&book.finish(key(200), Outcome::Absent).unwrap()).unwrap();
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
        let line = book.finish(key(7), Outcome::Ready).unwrap();
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
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
}
