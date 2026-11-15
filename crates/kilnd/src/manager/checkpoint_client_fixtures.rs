//! Checkpoint milestone C6a: the harness's three uses (design 1, 11.2 item 7) as client
//! fixtures through the gRPC service, as a non-root uid, with the call shapes the harness
//! sends: keyed creates `kiln-harness:<session>` with an explicit expiry, ExecStream
//! turns, Delete with `release_request_id` only after confirmed absence, and refusals
//! matched by their `kilnd-reason` trailer.
//!
//! - F1, rewind: capture between turns, busy while a turn runs, fork an earlier turn
//!   after its source is gone, fork a fork (depth 2), keyed retries.
//! - F2, best-of-four: four concurrent forks against one restore worker, retried until
//!   all are READY; keep one, delete the rest and the checkpoint; accounting returns to
//!   its baseline.
//! - F3, eval reset: one seed, a fork per run with its own released key, idle refreshed
//!   by forks, a typed refusal past the lifetime and a re-seed.
//!
//! The fake backend has no files and no workers, so these prove the API contract (call
//! sequences, provenance, digests stable across forks, typed refusals, keys, retries,
//! accounting, idle refresh and expiry), not workspace content. Byte-for-byte content
//! across forks is milestone C6b's, in the VM.
//!
//! `harness_contract_goldens_match` pins every fixture step, the typed reason table and
//! flag-on Health in `tests/data/checkpoint-contract.json`; `wire` pins the checkpoint
//! messages' protobuf encoding in `tests/data/checkpoint-wire.json` and a previous
//! client's decode of it.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;

use tokio_stream::StreamExt;

use super::*;
use crate::manager::Feature;

const UID: u32 = 1000;
const MIN: u64 = 60_000;

/// The expiry the harness sends on every create.
fn session_expiry() -> Option<pb::ExpiryPolicy> {
    Some(pb::ExpiryPolicy {
        max_lifetime_ms: 120 * MIN,
        idle_timeout_ms: 30 * MIN,
    })
}

fn keyed_create(key: &str) -> pb::CreateSandboxRequest {
    pb::CreateSandboxRequest {
        request_id: key.into(),
        expiry: session_expiry(),
        ..Default::default()
    }
}

fn keyed_fork(key: &str, checkpoint: &str) -> pb::CreateSandboxRequest {
    pb::CreateSandboxRequest {
        from_checkpoint: checkpoint.into(),
        ..keyed_create(key)
    }
}

fn capture_with(
    sandbox_id: &str,
    key: &str,
    lifetime_ms: u64,
    idle_ms: u64,
) -> pb::CheckpointSandboxRequest {
    pb::CheckpointSandboxRequest {
        sandbox_id: sandbox_id.into(),
        request_id: key.into(),
        expiry: Some(pb::ExpiryPolicy {
            max_lifetime_ms: lifetime_ms,
            idle_timeout_ms: idle_ms,
        }),
        max_size_bytes: 0,
    }
}

fn turn_req(sandbox_id: &str, argv: &[&str]) -> pb::ExecStreamRequest {
    pb::ExecStreamRequest {
        exec: Some(pb::ExecRequest {
            sandbox_id: sandbox_id.into(),
            argv: argv.iter().map(|a| a.to_string()).collect(),
            ..Default::default()
        }),
    }
}

/// Where the fixtures' injected clock starts: far past any host time, so a time the
/// daemon took from it renders as its exact offset from here, `<clock+N>`, and one the
/// host clock stamped (sandbox and execution rows) as `<wall>`.
const CLOCK_WALL_MS: i64 = 4_000_000_000_000;
/// No fixture runs its clock this far; a time past it is no offset of the clock's.
const CLOCK_SPAN_MS: i64 = 24 * 60 * MIN as i64;

/// A daemon as the harness meets it: started, SERVING, with ExecStream and workspace
/// checkpoints listed.
async fn daemon() -> (M, FakeRuntime, ManualClock, Api) {
    let clock = ManualClock::new(CLOCK_WALL_MS, 1_000_000, "boot-a");
    let fake = FakeRuntime::default().with_checkpoints();
    let m = Arc::new(Manager::with_clock(
        fake.clone(),
        Store::open_in_memory().unwrap(),
        test_limits(),
        Arc::new(clock.clone()),
    ));
    fake.state().proven_features = Ok(vec![Feature::ExecStream]);
    startup(&m).await;
    let s = api(&m);
    let caps = health_now(&s).await.runtime_capabilities.unwrap();
    for f in [pb::Feature::ExecStream, pb::Feature::WorkspaceCheckpoint] {
        assert!(caps.features.contains(&(f as i32)), "{caps:?}");
    }
    (m, fake, clock, s)
}

async fn health_now(s: &Api) -> pb::HealthResponse {
    s.health(as_uid(pb::HealthRequest {}, UID))
        .await
        .unwrap()
        .into_inner()
}

// --- The recorder ----------------------------------------------------------------------

/// A JSON value that keeps its keys in insertion order, written as serde_json's pretty
/// printer writes it.
#[derive(Clone, Debug, PartialEq)]
enum J {
    S(String),
    N(u64),
    B(bool),
    A(Vec<J>),
    O(Vec<(String, J)>),
}

fn obj<const N: usize>(fields: [(&str, J); N]) -> J {
    J::O(
        fields
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
}

impl J {
    fn write(&self, out: &mut String, depth: usize) {
        let pad = |out: &mut String, d: usize| out.push_str(&"  ".repeat(d));
        match self {
            J::S(s) => out.push_str(&serde_json::to_string(s).unwrap()),
            J::N(n) => out.push_str(&n.to_string()),
            J::B(b) => out.push_str(if *b { "true" } else { "false" }),
            J::A(items) if items.is_empty() => out.push_str("[]"),
            J::O(fields) if fields.is_empty() => out.push_str("{}"),
            J::A(items) => {
                out.push_str("[\n");
                for (i, item) in items.iter().enumerate() {
                    pad(out, depth + 1);
                    item.write(out, depth + 1);
                    out.push_str(if i + 1 < items.len() { ",\n" } else { "\n" });
                }
                pad(out, depth);
                out.push(']');
            }
            J::O(fields) => {
                out.push_str("{\n");
                for (i, (k, v)) in fields.iter().enumerate() {
                    pad(out, depth + 1);
                    out.push_str(&serde_json::to_string(k).unwrap());
                    out.push_str(": ");
                    v.write(out, depth + 1);
                    out.push_str(if i + 1 < fields.len() { ",\n" } else { "\n" });
                }
                pad(out, depth);
                out.push('}');
            }
        }
    }

    fn text(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, 0);
        out.push('\n');
        out
    }

    fn value(&self) -> serde_json::Value {
        serde_json::from_str(&self.text()).unwrap()
    }

    /// The first entry, in file order, where `file` differs from this value.
    fn first_difference(&self, path: &str, file: Option<&serde_json::Value>) -> Option<String> {
        use serde_json::Value as V;
        match (self, file) {
            (J::O(fields), Some(V::Object(theirs))) => {
                for (k, v) in fields {
                    if let Some(d) = v.first_difference(&format!("{path}.{k}"), theirs.get(k)) {
                        return Some(d);
                    }
                }
                theirs
                    .keys()
                    .find(|k| !fields.iter().any(|(ours, _)| ours == *k))
                    .map(|k| format!("{path}.{k}: in the file, not produced"))
            }
            (J::A(items), Some(V::Array(theirs))) => {
                for (i, v) in items.iter().enumerate() {
                    if let Some(d) = v.first_difference(&format!("{path}[{i}]"), theirs.get(i)) {
                        return Some(d);
                    }
                }
                (theirs.len() > items.len())
                    .then(|| format!("{path}[{}]: in the file, not produced", items.len()))
            }
            (ours, Some(theirs)) if ours.value() == *theirs => None,
            (ours, theirs) => {
                let ours = ours.value().to_string();
                let theirs = theirs.map_or("(missing)".to_string(), |t| t.to_string());
                let at = ours
                    .chars()
                    .zip(theirs.chars())
                    .position(|(a, b)| a != b)
                    .unwrap_or(0);
                let near = |s: &str| -> String {
                    s.chars().skip(at.saturating_sub(40)).take(120).collect()
                };
                Some(format!(
                    "{path}: the file has …{}…, the run produced …{}…",
                    near(&theirs),
                    near(&ours)
                ))
            }
        }
    }
}

/// Stable names for volatile values, by first appearance: the same value always gets
/// the same placeholder, so equalities between fields are part of the golden.
#[derive(Default)]
struct Placeholders {
    names: HashMap<String, String>,
    counts: BTreeMap<&'static str, usize>,
    /// Test-only: added to every nonzero `Checkpoint.expiry.idle_expires_at_unix_ms`
    /// before it renders, as a service that published a later deadline than it enforces
    /// would (`the_golden_catches_a_published_idle_deadline_shift`).
    idle_shift_ms: i64,
}

/// An ID or digest starting at `s` (already at a word boundary): its kind and length.
fn volatile_at(s: &str) -> Option<(&'static str, usize)> {
    let b = s.as_bytes();
    let hex = |from: usize| {
        b[from.min(b.len())..]
            .iter()
            .take_while(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
            .count()
    };
    let ends = |at: usize| b.get(at).is_none_or(|c| !c.is_ascii_alphanumeric());
    for (prefix, kind, n) in [("sb-", "sb", 16), ("ex-", "ex", 16), ("cp-", "cp", 32)] {
        if s.starts_with(prefix) && hex(3) == n && ends(3 + n) {
            return Some((kind, 3 + n));
        }
    }
    match hex(0) {
        64 if ends(64) => Some(("sha", 64)),
        32 if ends(32) => Some(("id", 32)),
        _ => None,
    }
}

impl Placeholders {
    fn name(&mut self, kind: &'static str, value: &str) -> String {
        if let Some(name) = self.names.get(value) {
            return name.clone();
        }
        let n = self.counts.entry(kind).or_default();
        *n += 1;
        let name = format!("<{kind}-{n}>");
        self.names.insert(value.to_string(), name.clone());
        name
    }

    /// `text` with every sandbox, execution and checkpoint ID, digest and 128-bit ID
    /// replaced, and every nonzero `*_unix_ms` time: the injected clock's as its exact
    /// offset `<clock+N>`, the host clock's as `<wall>` (their values and equalities
    /// depend on when and how fast the test runs).
    fn render(&mut self, text: &str) -> String {
        const TIME: &str = "_unix_ms: ";
        let b = text.as_bytes();
        let mut out = String::with_capacity(text.len());
        let mut i = 0;
        while i < b.len() {
            if (i == 0 || !b[i - 1].is_ascii_alphanumeric())
                && let Some((kind, len)) = volatile_at(&text[i..])
            {
                out.push_str(&self.name(kind, &text[i..i + len]));
                i += len;
                continue;
            }
            if text[i..].starts_with(TIME) {
                out.push_str(TIME);
                i += TIME.len();
                let end = i + text[i..]
                    .bytes()
                    .take_while(|c| c.is_ascii_digit() || *c == b'-')
                    .count();
                match text[i..end].parse::<i64>().unwrap() {
                    0 => out.push('0'),
                    t if t >= CLOCK_WALL_MS => {
                        let t = t + self.shift_at(&text[..i]);
                        let offset = t - CLOCK_WALL_MS;
                        assert!(offset < CLOCK_SPAN_MS, "{text}");
                        out.push_str(&format!("<clock+{offset}>"));
                    }
                    _ => out.push_str("<wall>"),
                }
                i = end;
                continue;
            }
            let c = text[i..].chars().next().unwrap();
            out.push(c);
            i += c.len_utf8();
        }
        out
    }

    /// The test-only shift for the time whose field `before` ends with.
    fn shift_at(&self, before: &str) -> i64 {
        const IDLE: &str = "idle_expires_at_unix_ms: ";
        const STATUS: &str = "ExpiryStatus {";
        // The field is in both ExpiryStatus and CheckpointExpiryStatus; the nearest
        // opener is its own.
        let in_checkpoint = before
            .rfind(STATUS)
            .is_some_and(|at| before[..at].ends_with("Checkpoint"));
        if self.idle_shift_ms != 0 && before.ends_with(IDLE) && in_checkpoint {
            self.idle_shift_ms
        } else {
            0
        }
    }

    fn debug(&mut self, value: &impl Debug) -> J {
        J::S(self.render(&format!("{value:?}")))
    }

    /// A refusal as the harness matches it: the code, the `kilnd-reason` trailer and
    /// the message up to the first `:` after the token (or the first `:` at all).
    fn error(&mut self, e: &Status) -> J {
        let message = e.message();
        let reason = trailer(e).unwrap_or("");
        let skip = if message.starts_with(reason) {
            reason.len()
        } else {
            0
        };
        let prefix = match message[skip..].find(':') {
            Some(at) => &message[..skip + at + 1],
            None => message,
        };
        obj([
            ("code", J::S(format!("{:?}", e.code()))),
            ("reason", J::S(reason.into())),
            ("message", J::S(self.render(prefix))),
        ])
    }
}

/// One fixture's calls, as the golden pins them. The plain fixture tests pass a
/// throwaway one; the golden test keeps them.
#[derive(Default)]
struct Recorder {
    steps: Vec<J>,
    names: Placeholders,
}

impl Recorder {
    fn call<Q: Debug, A: Debug>(
        &mut self,
        label: &str,
        rpc: &str,
        request: &Q,
        result: &Result<A, Status>,
    ) {
        let request = self.names.debug(request);
        let outcome = match result {
            Ok(a) => ("response", self.names.debug(a)),
            Err(e) => ("error", self.names.error(e)),
        };
        self.steps.push(obj([
            ("label", J::S(label.into())),
            ("rpc", J::S(rpc.into())),
            ("uid", J::N(UID.into())),
            ("request", request),
            outcome,
        ]));
    }

    /// An ExecStream turn: its messages in order.
    fn turn(&mut self, label: &str, request: &pb::ExecStreamRequest, result: &Turn) {
        let request = self.names.debug(request);
        let outcome = match result {
            Ok(messages) => (
                "response",
                J::A(messages.iter().map(|m| self.names.debug(m)).collect()),
            ),
            Err(e) => ("error", self.names.error(e)),
        };
        self.steps.push(obj([
            ("label", J::S(label.into())),
            ("rpc", J::S("ExecStream".into())),
            ("uid", J::N(UID.into())),
            ("request", request),
            outcome,
        ]));
    }

    /// Every typed refusal recorded: (token, gRPC code).
    fn refusals(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for step in &self.steps {
            let J::O(fields) = step else { continue };
            let Some((_, J::O(error))) = fields.iter().find(|(k, _)| k == "error") else {
                continue;
            };
            let field = |name: &str| match error.iter().find(|(k, _)| k == name) {
                Some((_, J::S(s))) => s.clone(),
                _ => String::new(),
            };
            if !field("reason").is_empty() {
                out.push((field("reason"), field("code")));
            }
        }
        out
    }
}

// --- Recorded RPCs ---------------------------------------------------------------------

/// A checkpoint's published deadlines are its effective policy's offsets from their
/// anchors (design Appendix A), checked before the recorder renders them: the lifetime
/// from READY, idle from the last activity, and none on a row no timer holds or (idle)
/// one a restore pins.
#[track_caller]
fn published_deadlines(c: &pb::Checkpoint) {
    let x = c.expiry.unwrap();
    let policy = x.effective.unwrap();
    let after = |anchor: i64, ms: u64| anchor + i64::try_from(ms).unwrap();
    let (lifetime, idle) = if state(c) == pb::CheckpointState::Ready {
        (
            after(c.ready_at_unix_ms, policy.max_lifetime_ms),
            if x.idle_paused {
                0
            } else {
                after(x.last_activity_at_unix_ms, policy.idle_timeout_ms)
            },
        )
    } else {
        (0, 0)
    };
    assert_eq!(
        (x.lifetime_expires_at_unix_ms, x.idle_expires_at_unix_ms),
        (lifetime, idle),
        "{c:?}"
    );
}

/// A live sandbox's published idle deadline is its policy's offset from its last
/// activity (its lifetime's anchor, the creation on the daemon's clock, is not
/// published).
#[track_caller]
fn published_sandbox_idle(s: &pb::Sandbox) {
    let x = s.expiry.unwrap();
    let idle = x.effective.unwrap().idle_timeout_ms;
    if sandbox_state(s) == pb::SandboxState::Ready && !x.idle_paused {
        assert_eq!(
            x.idle_expires_at_unix_ms,
            x.last_activity_at_unix_ms + i64::try_from(idle).unwrap(),
            "{s:?}"
        );
    }
}

async fn rpc_create(
    s: &Api,
    rec: &mut Recorder,
    label: &str,
    msg: pb::CreateSandboxRequest,
) -> Result<pb::Sandbox, Status> {
    let r = s
        .create_sandbox(as_uid(msg.clone(), UID))
        .await
        .map(|r| r.into_inner().sandbox.unwrap());
    if let Ok(sb) = &r {
        published_sandbox_idle(sb);
    }
    rec.call(label, "CreateSandbox", &msg, &r);
    r
}

async fn rpc_capture(
    s: &Api,
    rec: &mut Recorder,
    label: &str,
    msg: pb::CheckpointSandboxRequest,
) -> Result<pb::Checkpoint, Status> {
    let r = s
        .checkpoint_sandbox(as_uid(msg.clone(), UID))
        .await
        .map(|r| r.into_inner().checkpoint.unwrap());
    if let Ok(c) = &r {
        assert_eq!(
            c.expiry.unwrap().effective,
            msg.expiry,
            "the policy asked for"
        );
        published_deadlines(c);
    }
    rec.call(label, "CheckpointSandbox", &msg, &r);
    r
}

async fn rpc_get_checkpoint(s: &Api, rec: &mut Recorder, label: &str, id: &str) -> pb::Checkpoint {
    let msg = pb::GetCheckpointRequest { id: id.into() };
    let r = s
        .get_checkpoint(as_uid(msg.clone(), UID))
        .await
        .map(|r| r.into_inner().checkpoint.unwrap());
    if let Ok(c) = &r {
        published_deadlines(c);
    }
    rec.call(label, "GetCheckpoint", &msg, &r);
    r.unwrap()
}

/// ListCheckpoints never refreshes idle, so it observes expiry without moving it.
async fn rpc_list_checkpoints(
    s: &Api,
    rec: &mut Recorder,
    label: &str,
    sandbox_id: &str,
) -> Vec<pb::Checkpoint> {
    let msg = pb::ListCheckpointsRequest {
        sandbox_id: sandbox_id.into(),
        page_size: 0,
        page_token: String::new(),
    };
    let r = s
        .list_checkpoints(as_uid(msg.clone(), UID))
        .await
        .map(|r| r.into_inner());
    if let Ok(page) = &r {
        page.checkpoints.iter().for_each(published_deadlines);
    }
    rec.call(label, "ListCheckpoints", &msg, &r);
    r.unwrap().checkpoints
}

async fn rpc_delete_checkpoint(
    s: &Api,
    rec: &mut Recorder,
    label: &str,
    id: &str,
) -> pb::Checkpoint {
    let msg = pb::DeleteCheckpointRequest {
        id: id.into(),
        release_request_id: false,
    };
    let r = s
        .delete_checkpoint(as_uid(msg.clone(), UID))
        .await
        .map(|r| r.into_inner().checkpoint.unwrap());
    if let Ok(c) = &r {
        published_deadlines(c);
    }
    rec.call(label, "DeleteCheckpoint", &msg, &r);
    let c = r.unwrap();
    assert_eq!(state(&c), pb::CheckpointState::Deleted, "{c:?}");
    c
}

async fn rpc_get_sandbox(s: &Api, rec: &mut Recorder, label: &str, id: &str) -> pb::Sandbox {
    let msg = pb::GetSandboxRequest {
        id: id.into(),
        execution_limit: 1,
    };
    let r = s
        .get_sandbox(as_uid(msg.clone(), UID))
        .await
        .map(|r| r.into_inner());
    if let Ok(got) = &r {
        published_sandbox_idle(got.sandbox.as_ref().unwrap());
    }
    rec.call(label, "GetSandbox", &msg, &r);
    r.unwrap().sandbox.unwrap()
}

async fn rpc_delete_sandbox(
    s: &Api,
    rec: &mut Recorder,
    label: &str,
    id: &str,
    release_request_id: bool,
) -> pb::Sandbox {
    let msg = pb::DeleteSandboxRequest {
        id: id.into(),
        release_request_id,
    };
    let r = s
        .delete_sandbox(as_uid(msg.clone(), UID))
        .await
        .map(|r| r.into_inner().sandbox.unwrap());
    rec.call(label, "DeleteSandbox", &msg, &r);
    r.unwrap()
}

/// The harness's cleanup: Delete, confirm absence in the default listing, then (when
/// releasing) Delete again with `release_request_id`, once absence is confirmed.
async fn rpc_cleanup(s: &Api, rec: &mut Recorder, what: &str, id: &str, release: bool) {
    let d = rpc_delete_sandbox(s, rec, &format!("delete {what}"), id, false).await;
    assert_eq!(sandbox_state(&d), pb::SandboxState::Deleted, "{d:?}");
    let msg = pb::ListSandboxesRequest::default();
    let r = s
        .list_sandboxes(as_uid(msg.clone(), UID))
        .await
        .map(|r| r.into_inner());
    rec.call(&format!("{what} is absent"), "ListSandboxes", &msg, &r);
    assert!(
        r.unwrap().sandboxes.iter().all(|x| x.id != id),
        "{what} listed"
    );
    if release {
        let d = rpc_delete_sandbox(s, rec, &format!("release {what}'s key"), id, true).await;
        assert!(d.request_id_released, "{d:?}");
    }
}

type Turn = Result<Vec<pb::ExecStreamResponse>, Status>;

/// One ExecStream turn, drained to its end.
async fn turn_raw(s: &Api, msg: pb::ExecStreamRequest) -> Turn {
    let mut body = s.exec_stream(as_uid(msg, UID)).await?.into_inner();
    let mut messages = Vec::new();
    while let Some(m) = body.next().await {
        messages.push(m?);
    }
    Ok(messages)
}

/// The turn's exit code, from its ExecFinished.
#[track_caller]
fn exit_code(turn: &Turn) -> i32 {
    use pb::exec_stream_response::Event;
    let messages = turn.as_ref().unwrap();
    match &messages.last().unwrap().event {
        Some(Event::Finished(f)) => f.execution.as_ref().unwrap().exit_code.unwrap(),
        other => panic!("{other:?}"),
    }
}

async fn rpc_turn(s: &Api, rec: &mut Recorder, label: &str, id: &str, argv: &[&str]) -> i32 {
    let msg = turn_req(id, argv);
    let r = turn_raw(s, msg.clone()).await;
    rec.turn(label, &msg, &r);
    exit_code(&r)
}

/// A fork's provenance is the checkpoint and the digest the journal recorded.
#[track_caller]
fn forked_from(f: &pb::Sandbox, journal: &(String, String)) {
    assert_eq!(sandbox_state(f), pb::SandboxState::Ready, "{f:?}");
    assert_eq!(
        (&f.from_checkpoint, &f.checkpoint_content_sha256),
        (&journal.0, &journal.1),
        "{f:?}"
    );
}

fn journal(c: &pb::Checkpoint) -> (String, String) {
    assert_eq!(state(c), pb::CheckpointState::Ready, "{c:?}");
    assert_eq!(c.content_sha256.len(), 64, "{c:?}");
    (c.id.clone(), c.content_sha256.clone())
}

// --- F1: rewind ------------------------------------------------------------------------

/// Rewind: a capture between turns is journaled, one during a turn is busy, an earlier
/// turn forks after its source is gone with its digest unchanged, a fork's checkpoint
/// forks again (depth 2), and keyed creates and forks retry to the same sandbox.
async fn f1_rewind(rec: &mut Recorder) {
    let (m, fake, _clock, s) = daemon().await;
    let session = keyed_create("kiln-harness:f1-rewind");
    let a = rpc_create(&s, rec, "the session's keyed create", session.clone())
        .await
        .unwrap();
    assert_eq!(sandbox_state(&a), pb::SandboxState::Ready);
    assert_eq!(a.request_id, "kiln-harness:f1-rewind");
    assert!(a.from_checkpoint.is_empty() && a.checkpoint_content_sha256.is_empty());
    let again = rpc_create(&s, rec, "a retry of the create", session)
        .await
        .unwrap();
    assert_eq!(again.id, a.id);
    assert_eq!(
        rpc_turn(&s, rec, "turn 1", &a.id, &["echo", "turn 1"]).await,
        0
    );

    // Between turns: capture, and journal its ID and digest.
    let hour = 60 * MIN;
    let c1 = rpc_capture(
        &s,
        rec,
        "capture after turn 1",
        capture_with(&a.id, "kiln-harness:f1-rewind/1", hour, 10 * MIN),
    )
    .await
    .unwrap();
    let turn1 = journal(&c1);
    assert_eq!(
        (c1.sandbox_id.as_str(), c1.request_id.as_str()),
        (a.id.as_str(), "kiln-harness:f1-rewind/1")
    );

    // Turn 2 is held in the backend: a capture now is busy at once, and leaves no key
    // record, so the same key captures after the turn.
    let gate = FakeGate::default();
    fake.state().exec_before_run = Some(gate.clone());
    let held = turn_req(&a.id, &["echo", "turn 2"]);
    let running = {
        let (s, msg) = (Arc::clone(&s), held.clone());
        tokio::spawn(async move { turn_raw(&s, msg).await })
    };
    gate.entered().await;
    let second = capture_with(&a.id, "kiln-harness:f1-rewind/2", hour, 10 * MIN);
    let e = rpc_capture(&s, rec, "capture while turn 2 runs", second.clone())
        .await
        .unwrap_err();
    refused(&e, Code::FailedPrecondition, "checkpoint_busy");
    let rows = m.store.checkpoint_page(None, None, None, 10).unwrap().rows;
    assert_eq!(rows.len(), 1, "no row for the refused capture");
    gate.release();
    let done = running.await.unwrap();
    rec.turn("turn 2, held during the refused capture", &held, &done);
    assert_eq!(exit_code(&done), 0);
    let c2 = rpc_capture(&s, rec, "the same capture after turn 2", second)
        .await
        .unwrap();
    journal(&c2);
    assert_ne!(c2.id, c1.id);
    assert_eq!(
        rpc_turn(&s, rec, "turn 3 (destructive)", &a.id, &["exit", "1"]).await,
        1
    );

    // Rewind to turn 1: the source goes, the checkpoint stays, a new key forks it.
    rpc_cleanup(&s, rec, "the session's sandbox", &a.id, false).await;
    let b = rpc_create(
        &s,
        rec,
        "fork turn 1",
        keyed_fork("kiln-harness:f1-rewind-a", &turn1.0),
    )
    .await
    .unwrap();
    forked_from(&b, &turn1);
    assert_eq!(b.request_id, "kiln-harness:f1-rewind-a");
    let c1_now = rpc_get_checkpoint(&s, rec, "turn 1's checkpoint, source gone", &turn1.0).await;
    assert_eq!(journal(&c1_now), turn1, "the digest is unchanged");
    assert_eq!(
        c1_now.sandbox_id, a.id,
        "source provenance outlives the source"
    );
    assert_eq!(
        rpc_turn(
            &s,
            rec,
            "turn 2 again, in the fork",
            &b.id,
            &["echo", "turn 2b"]
        )
        .await,
        0
    );

    // Depth 2: capture the fork and fork that.
    let c3 = rpc_capture(
        &s,
        rec,
        "capture the fork",
        capture_with(&b.id, "kiln-harness:f1-rewind-a/1", hour, 10 * MIN),
    )
    .await
    .unwrap();
    let fork_turn = journal(&c3);
    assert_eq!(c3.sandbox_id, b.id, "a fork's checkpoint names the fork");
    assert_ne!(c3.content_sha256, c1.content_sha256);
    let restores = calls(&fake, "restore");
    let fork2 = keyed_fork("kiln-harness:f1-rewind-b", &fork_turn.0);
    let c = rpc_create(
        &s,
        rec,
        "fork the fork's checkpoint (depth 2)",
        fork2.clone(),
    )
    .await
    .unwrap();
    forked_from(&c, &fork_turn);
    let retry = rpc_create(&s, rec, "a retry of the depth-2 fork", fork2)
        .await
        .unwrap();
    assert_eq!(retry.id, c.id);
    assert_eq!(
        calls(&fake, "restore"),
        restores + 1,
        "the retry restores nothing"
    );
    assert_eq!(
        rpc_turn(
            &s,
            rec,
            "turn 3 in the depth-2 fork",
            &c.id,
            &["echo", "turn 3c"]
        )
        .await,
        0
    );

    // Cleanup: forks, then checkpoints; nothing stays charged.
    rpc_cleanup(&s, rec, "the depth-2 fork", &c.id, true).await;
    rpc_cleanup(&s, rec, "the first fork", &b.id, true).await;
    for (what, id) in [
        ("turn 1", &c1.id),
        ("turn 2", &c2.id),
        ("the fork's", &c3.id),
    ] {
        rpc_delete_checkpoint(&s, rec, &format!("delete {what} checkpoint"), id).await;
    }
    assert_eq!(charge(&m), (0, 0));
}

#[tokio::test]
async fn f1_rewind_forks_an_earlier_turn_after_its_source_is_gone() {
    f1_rewind(&mut Recorder::default()).await;
}

// --- F2: best of four ------------------------------------------------------------------

/// What must return to its baseline: Health's current checkpoint use (not its history
/// or since-startup counters), the node's and the uid's checkpoint charges, and the
/// checkpoint share of node disk.
fn current_use(h: &pb::HealthResponse, m: &M) -> (Vec<u64>, crate::store::CheckpointUsage) {
    let c = h.admission.as_ref().unwrap().checkpoints.unwrap();
    let node = h.node_resources.as_ref().unwrap();
    let mut usage = m.store.checkpoint_usage(UID).unwrap();
    // Records and keys are history, compared separately.
    for counts in [&mut usage.node, &mut usage.uid] {
        counts.records = 0;
        counts.keys = 0;
    }
    (
        vec![
            c.current_count,
            c.caller_count,
            c.reserved_bytes,
            c.caller_reserved_bytes,
            c.current_workers,
            c.caller_workers,
            c.pending_deletes,
            c.current_cleanup_workers,
            node.checkpoint_reserved_disk_bytes,
        ],
        usage,
    )
}

fn stats(h: &pb::HealthResponse) -> pb::CheckpointStats {
    h.admission.as_ref().unwrap().checkpoints.unwrap()
}

async fn rpc_health_stats(s: &Api, rec: &mut Recorder, label: &str) -> pb::HealthResponse {
    let h = health_now(s).await;
    rec.call(
        label,
        "Health",
        &pb::HealthRequest {},
        &Ok::<_, Status>(stats(&h)),
    );
    h
}

const BRANCHES: usize = 4;
/// Most rounds of fork attempts before the fixture gives up, as a harness bounds its
/// retries.
const MAX_ROUNDS: usize = 8;

/// Best-of-four: concurrent forks past the one restore worker are refused typed and
/// retried to READY; the kept branch outlives its checkpoint; current use returns to the
/// baseline exactly.
async fn f2_best_of_four(rec: &mut Recorder) {
    let (m, fake, _clock, s) = daemon().await;
    let before = rpc_health_stats(&s, rec, "baseline (CheckpointStats)").await;
    let baseline = current_use(&before, &m);
    let sandboxes = m.store_resources_for_test();
    let seed = rpc_create(
        &s,
        rec,
        "the seed's keyed create",
        keyed_create("kiln-harness:f2-seed"),
    )
    .await
    .unwrap();
    assert_eq!(
        rpc_turn(&s, rec, "seed the workspace", &seed.id, &["echo", "seed"]).await,
        0
    );
    let c = rpc_capture(
        &s,
        rec,
        "capture the seed",
        capture_with(&seed.id, "kiln-harness:f2-seed/1", 60 * MIN, 10 * MIN),
    )
    .await
    .unwrap();
    let seeded = journal(&c);

    // Every round, each pending branch forks at once. The one restore worker this uid
    // has admits exactly one (held in its restore until the others answered); the rest
    // are refused checkpoint_workers and retry next round.
    let key = |b: usize| format!("kiln-harness:f2-branch-{b}");
    let mut pending: Vec<usize> = (0..BRANCHES).collect();
    let mut forks: BTreeMap<usize, pb::Sandbox> = BTreeMap::new();
    let mut refusals = 0;
    for round in 0..MAX_ROUNDS {
        let Some((&first, rest)) = pending.split_first() else {
            break;
        };
        let gate = gate_restore(&fake);
        let admitted = {
            let (s, msg) = (Arc::clone(&s), keyed_fork(&key(first), &seeded.0));
            tokio::spawn(async move {
                let r = s
                    .create_sandbox(as_uid(msg.clone(), UID))
                    .await
                    .map(|r| r.into_inner().sandbox.unwrap());
                (msg, r)
            })
        };
        gate.entered().await;
        let others: Vec<_> = rest
            .iter()
            .map(|&b| {
                let (s, msg) = (Arc::clone(&s), keyed_fork(&key(b), &seeded.0));
                tokio::spawn(async move {
                    let r = s
                        .create_sandbox(as_uid(msg.clone(), UID))
                        .await
                        .map(|r| r.into_inner().sandbox.unwrap());
                    (msg, r)
                })
            })
            .collect();
        let mut still = Vec::new();
        for (&b, other) in rest.iter().zip(others) {
            let (msg, r) = other.await.unwrap();
            rec.call(
                &format!("round {round}: branch {b}, refused"),
                "CreateSandbox",
                &msg,
                &r,
            );
            let e = r.unwrap_err();
            refused(&e, Code::ResourceExhausted, "checkpoint_workers");
            refusals += 1;
            still.push(b);
        }
        gate.release();
        let (msg, r) = admitted.await.unwrap();
        if let Ok(f) = &r {
            published_sandbox_idle(f);
        }
        rec.call(
            &format!("round {round}: branch {first}, admitted"),
            "CreateSandbox",
            &msg,
            &r,
        );
        let f = r.unwrap();
        forked_from(&f, &seeded);
        forks.insert(first, f);
        pending = still;
    }
    assert!(
        pending.is_empty(),
        "every branch READY within {MAX_ROUNDS} rounds"
    );
    assert_eq!(refusals, BRANCHES * (BRANCHES - 1) / 2);
    let backends: std::collections::BTreeSet<_> = forks.values().map(|f| &f.backend_id).collect();
    assert_eq!(backends.len(), BRANCHES, "independent sandboxes");

    // Each branch runs its check; branch 2's passes. Keep it, delete the rest and the
    // checkpoint: the winner outlives the checkpoint.
    const WINNER: usize = 2;
    for (&b, f) in &forks {
        let code = if b == WINNER { "0" } else { "1" };
        let got = rpc_turn(
            &s,
            rec,
            &format!("branch {b}'s check"),
            &f.id,
            &["exit", code],
        )
        .await;
        assert_eq!(got, i32::from(b != WINNER));
    }
    for (&b, f) in &forks {
        if b != WINNER {
            rpc_cleanup(&s, rec, &format!("branch {b}"), &f.id, true).await;
        }
    }
    rpc_delete_checkpoint(&s, rec, "delete the seed's checkpoint", &seeded.0).await;
    let winner = &forks[&WINNER];
    let kept = rpc_get_sandbox(&s, rec, "the kept branch, its checkpoint gone", &winner.id).await;
    forked_from(&kept, &seeded);
    assert_eq!(
        rpc_turn(
            &s,
            rec,
            "the kept branch runs on",
            &winner.id,
            &["echo", "next"]
        )
        .await,
        0
    );

    // Accounting: current use is the baseline exactly; history grew by exactly this
    // fixture's checkpoint and refusals.
    let after = rpc_health_stats(&s, rec, "after (CheckpointStats)").await;
    assert_eq!(current_use(&after, &m), baseline);
    let (b, a) = (stats(&before), stats(&after));
    assert_eq!(a.rejected_forks, b.rejected_forks + refusals as u64);
    assert_eq!(a.rejected_captures, b.rejected_captures);
    assert_eq!(
        (a.current_records, a.caller_records),
        (b.current_records + 1, b.caller_records + 1)
    );
    assert_eq!(
        a.request_records,
        b.request_records + 1,
        "the seed's capture key"
    );
    assert_eq!(charge(&m), (0, 0));
    rpc_cleanup(&s, rec, "the kept branch", &winner.id, true).await;
    rpc_cleanup(&s, rec, "the seed", &seed.id, true).await;
    assert_eq!(
        m.store_resources_for_test(),
        sandboxes,
        "node reservations too"
    );
}

#[tokio::test]
async fn f2_best_of_four_retries_worker_refusals_and_returns_to_baseline() {
    f2_best_of_four(&mut Recorder::default()).await;
}

// --- F3: eval reset --------------------------------------------------------------------

const RUNS: usize = 5;
const LIFETIME_MS: u64 = 10 * MIN;
const IDLE_MS: u64 = 5 * MIN;
/// Between runs: less than the idle timeout, more than it over all runs, and the last
/// fork's idle deadline falls after the lifetime, so the lifetime is what expires it.
const BETWEEN_RUNS: i64 = 90 * SEC;

/// Seed once: a source, its seed turn, a capture with a lifetime, the source deleted.
async fn f3_seed(s: &Api, rec: &mut Recorder, name: &str) -> pb::Checkpoint {
    let key = format!("kiln-harness:f3-{name}");
    let seed = rpc_create(s, rec, &format!("{name}: keyed create"), keyed_create(&key))
        .await
        .unwrap();
    assert_eq!(
        rpc_turn(
            s,
            rec,
            &format!("{name}: seed the workspace"),
            &seed.id,
            &["echo", name]
        )
        .await,
        0
    );
    let c = rpc_capture(
        s,
        rec,
        &format!("{name}: capture with a lifetime"),
        capture_with(&seed.id, &format!("{key}/1"), LIFETIME_MS, IDLE_MS),
    )
    .await
    .unwrap();
    journal(&c);
    rpc_cleanup(s, rec, &format!("the {name} source"), &seed.id, true).await;
    c
}

/// One run: fork with the run's own key, exec, delete, and release the key after
/// confirmed absence.
async fn f3_run(s: &Api, rec: &mut Recorder, n: usize, seeded: &(String, String)) -> pb::Sandbox {
    let key = format!("kiln-harness:eval-{n}");
    let r = rpc_create(
        s,
        rec,
        &format!("run {n}: fork"),
        keyed_fork(&key, &seeded.0),
    )
    .await
    .unwrap();
    forked_from(&r, seeded);
    assert_eq!(r.request_id, key);
    let run = format!("run {n}");
    assert_eq!(
        rpc_turn(s, rec, &format!("{run}: the eval"), &r.id, &["echo", &run]).await,
        0
    );
    rpc_cleanup(s, rec, &run, &r.id, true).await;
    r
}

/// Eval reset: five runs fork one seed with their own released keys, forks keep idle
/// alive past its first deadline, and past the lifetime the next fork is refused typed
/// and the harness re-seeds under the same key.
async fn f3_eval_reset(rec: &mut Recorder) {
    let (m, _fake, clock, s) = daemon().await;
    let c = f3_seed(&s, rec, "seed").await;
    let seeded = journal(&c);
    let expiry = c.expiry.unwrap();
    let first_idle_deadline = expiry.idle_expires_at_unix_ms;
    assert_eq!(
        expiry.lifetime_expires_at_unix_ms - c.ready_at_unix_ms,
        LIFETIME_MS as i64
    );
    let mut ids = Vec::new();
    for n in 1..=RUNS {
        if n > 1 {
            // Idle restarted at the last fork, so a sweep now expires nothing.
            clock.advance(BETWEEN_RUNS);
            m.expire_checkpoints_due();
            let listed = rpc_list_checkpoints(&s, rec, &format!("before run {n}"), "").await;
            let now = listed.iter().find(|x| x.id == seeded.0).unwrap();
            assert_eq!(journal(now), seeded, "READY, with the same digest");
        }
        let r = f3_run(&s, rec, n, &seeded).await;
        assert!(
            m.store
                .create_request(UID, &r.request_id)
                .unwrap()
                .is_none()
        );
        if n == 1 {
            // Released: the same key forks a fresh sandbox, not the DELETED one.
            let fresh = rpc_create(
                &s,
                rec,
                "run 1's released key, reused",
                keyed_fork(&r.request_id, &seeded.0),
            )
            .await
            .unwrap();
            assert_ne!(fresh.id, r.id);
            forked_from(&fresh, &seeded);
            rpc_cleanup(&s, rec, "the reused key's fork", &fresh.id, true).await;
        }
        ids.push(r.id);
    }
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), RUNS);
    let listed = rpc_list_checkpoints(&s, rec, "after the last run", "").await;
    let now = listed.iter().find(|x| x.id == seeded.0).unwrap();
    let wall = |x: &pb::Checkpoint| x.expiry.unwrap();
    assert!(
        wall(now).last_activity_at_unix_ms > first_idle_deadline,
        "the runs went past the first idle deadline: {now:?}"
    );
    assert_eq!(
        wall(now).lifetime_expires_at_unix_ms,
        expiry.lifetime_expires_at_unix_ms
    );
    assert!(wall(now).idle_expires_at_unix_ms > expiry.lifetime_expires_at_unix_ms);

    // Past the lifetime, forks never extended: the next run's fork is refused typed,
    // before any record, and the harness re-seeds; the same key then forks.
    let elapsed = BETWEEN_RUNS * (RUNS as i64 - 1);
    clock.advance(LIFETIME_MS as i64 - elapsed + SEC);
    let next = keyed_fork(&format!("kiln-harness:eval-{}", RUNS + 1), &seeded.0);
    let e = rpc_create(
        &s,
        rec,
        "past the lifetime: the next run's fork",
        next.clone(),
    )
    .await
    .unwrap_err();
    refused(&e, Code::FailedPrecondition, "checkpoint_expired");
    assert!(
        m.store
            .create_request(UID, &next.request_id)
            .unwrap()
            .is_none()
    );
    m.expire_checkpoints_due();
    until("lifetime ABSENT", || {
        row(&m, &seeded.0).state == CheckpointState::Deleted
    })
    .await;
    let gone = rpc_get_checkpoint(&s, rec, "the expired checkpoint", &seeded.0).await;
    assert_eq!(state(&gone), pb::CheckpointState::Deleted);
    assert_eq!(
        gone.deletion_reason,
        pb::DeletionReason::ExpiredLifetime as i32
    );
    assert_eq!(gone.content_sha256, seeded.1, "history keeps the digest");
    let c2 = f3_seed(&s, rec, "reseed").await;
    let reseeded = journal(&c2);
    let r = f3_run(&s, rec, RUNS + 1, &reseeded).await;
    assert_eq!(r.request_id, next.request_id);
    rpc_delete_checkpoint(&s, rec, "delete the re-seeded checkpoint", &reseeded.0).await;
    assert_eq!(charge(&m), (0, 0));
}

#[tokio::test]
async fn f3_eval_reset_forks_per_run_and_reseeds_past_the_lifetime() {
    f3_eval_reset(&mut Recorder::default()).await;
}

// --- The golden ------------------------------------------------------------------------

const BLESS: &str = "KILND_BLESS_CHECKPOINT_CONTRACT";

fn data_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name)
}

/// Whether this run rewrites the goldens, from `KILND_BLESS_CHECKPOINT_CONTRACT` and `CI`:
/// only when asked with `1`, and never under CI (any nonempty `CI`), where a rewritten
/// golden would pass whatever the run produced.
fn bless_requested(
    bless: Option<&std::ffi::OsStr>,
    ci: Option<&std::ffi::OsStr>,
) -> Result<bool, String> {
    if bless.is_none_or(|v| v != "1") {
        return Ok(false);
    }
    if ci.is_some_and(|v| !v.is_empty()) {
        return Err(format!(
            "{BLESS}=1 is refused while CI is set: bless the goldens locally and review the diff"
        ));
    }
    Ok(true)
}

/// Where `file` (a golden's text) differs from `golden`, or None when it is the same.
fn golden_mismatch(golden: &J, file: &str) -> Option<String> {
    if file == golden.text() {
        return None;
    }
    Some(match serde_json::from_str::<serde_json::Value>(file) {
        Err(_) => "the file is missing or not JSON".to_string(),
        Ok(v) => golden
            .first_difference("$", Some(&v))
            .unwrap_or_else(|| "only its formatting differs".to_string()),
    })
}

/// Compares `golden` with `tests/data/<name>`, or rewrites that file when blessing.
#[track_caller]
fn check_golden(name: &str, golden: &J) {
    let path = data_path(name);
    let blessing = bless_requested(
        std::env::var_os(BLESS).as_deref(),
        std::env::var_os("CI").as_deref(),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    if blessing {
        bless(&path, &golden.text());
        return;
    }
    let file = std::fs::read_to_string(&path).unwrap_or_default();
    if let Some(what) = golden_mismatch(golden, &file) {
        panic!(
            "tests/data/{name} differs from this run: {what}. If the change is intended, rerun with {BLESS}=1 (not under CI) and review the diff."
        );
    }
}

#[test]
fn blessing_needs_1_and_no_ci() {
    use std::ffi::OsStr;
    let os = |s: &'static str| Some(OsStr::new(s));
    assert_eq!(bless_requested(None, None), Ok(false));
    assert_eq!(bless_requested(os("0"), os("true")), Ok(false));
    assert_eq!(bless_requested(os(""), None), Ok(false));
    assert_eq!(bless_requested(os("1"), None), Ok(true));
    assert_eq!(bless_requested(os("1"), os("")), Ok(true));
    for ci in ["true", "1", "false"] {
        let e = bless_requested(os("1"), os(ci)).unwrap_err();
        assert!(e.contains("refused while CI is set"), "{e}");
    }
}

/// The Firecracker shape refusing new captures and forks, as
/// `firecracker_refuses_capture_and_fork_before_any_allocation` provokes it.
async fn firecracker_refusals(rec: &mut Recorder) {
    let (m, fake, _clock, s) = daemon().await;
    let src = rpc_create(&s, rec, "a source", keyed_create("kiln-harness:fc"))
        .await
        .unwrap();
    let c = rpc_capture(
        &s,
        rec,
        "its checkpoint",
        capture_with(&src.id, "", 60 * MIN, 10 * MIN),
    )
    .await
    .unwrap();
    {
        let mut st = fake.state();
        st.mode = crate::runtime::fake::FakeEvidenceMode::Fenced;
        st.fenced.node_id = Some(Id128::random());
    }
    assert!(!m.runtime.checkpoint_backend());
    let e = rpc_capture(
        &s,
        rec,
        "capture on Firecracker",
        capture_with(&src.id, "", 60 * MIN, 10 * MIN),
    )
    .await
    .unwrap_err();
    refused(&e, Code::Unimplemented, UNSUPPORTED);
    let e = rpc_create(
        &s,
        rec,
        "fork on Firecracker",
        keyed_fork("kiln-harness:fc-fork", &c.id),
    )
    .await
    .unwrap_err();
    refused(&e, Code::Unimplemented, UNSUPPORTED);
}

/// Every reason the engine defines, with the gRPC code its refusals carry.
fn reason_table() -> J {
    J::A(
        CheckpointReason::ALL
            .iter()
            .map(|r| {
                obj([
                    ("token", J::S(r.token().into())),
                    ("code", J::S(format!("{:?}", r.code()))),
                ])
            })
            .collect(),
    )
}

/// Flag-on Health: the feature list, the checkpoint boolean and limits, and the stats on
/// an empty node and with one READY checkpoint.
async fn flag_on_health() -> J {
    let (_m, _fake, _clock, s) = daemon().await;
    let mut names = Placeholders::default();
    let empty = health_now(&s).await;
    let caps = empty.runtime_capabilities.clone().unwrap();
    let features = caps
        .features
        .iter()
        .map(|f| J::S(pb::Feature::try_from(*f).unwrap().as_str_name().into()))
        .collect();
    let src = api_source(&s, UID).await;
    api_capture(&s, &src.id, UID).await.unwrap();
    let one = health_now(&s).await;
    obj([
        ("features", J::A(features)),
        ("checkpoint", J::B(caps.checkpoint)),
        (
            "limits_checkpoint",
            names.debug(&caps.limits.unwrap().checkpoint),
        ),
        (
            "stats_empty",
            names.debug(&empty.admission.unwrap().checkpoints),
        ),
        (
            "stats_one_ready",
            names.debug(&one.admission.unwrap().checkpoints),
        ),
    ])
}

/// The contract golden as this run produces it; `idle_shift_ms` is the recorder's
/// test-only shift of published checkpoint idle deadlines.
async fn contract(idle_shift_ms: i64) -> J {
    let recorder = || {
        let mut rec = Recorder::default();
        rec.names.idle_shift_ms = idle_shift_ms;
        rec
    };
    let mut fixtures = Vec::new();
    let mut refusals = Vec::new();
    for (name, rec) in [
        ("f1_rewind", {
            let mut rec = recorder();
            f1_rewind(&mut rec).await;
            rec
        }),
        ("f2_best_of_four", {
            let mut rec = recorder();
            f2_best_of_four(&mut rec).await;
            rec
        }),
        ("f3_eval_reset", {
            let mut rec = recorder();
            f3_eval_reset(&mut rec).await;
            rec
        }),
    ] {
        refusals.extend(rec.refusals());
        fixtures.push((name.to_string(), J::A(rec.steps)));
    }
    let mut fc = recorder();
    firecracker_refusals(&mut fc).await;
    refusals.extend(fc.refusals());
    // Every typed refusal the fixtures met carries the table's code.
    for (token, code) in &refusals {
        if let Some(r) = CheckpointReason::ALL.iter().find(|r| r.token() == token) {
            assert_eq!(*code, format!("{:?}", r.code()), "{token}");
        }
    }
    let notes = [
        "Recorded against the fake backend, which has no files: steps pin call sequences, provenance, digests, typed refusals, keys and accounting, not workspace content.",
        "Volatile values are placeholders by first appearance within each section: <sb-N>, <ex-N>, <cp-N> IDs, <sha-N> digests and <id-N> 128-bit IDs. Equal placeholders are equal values.",
        "<clock+N> is a nonzero *_unix_ms time from the daemon's injected clock, as its exact offset N in ms from the clock's start: deadlines, activity, and checkpoint creation and READY times. The fixtures also check each published checkpoint deadline against its effective policy before recording it.",
        "<wall> is a nonzero time the host clock stamped (sandbox and execution rows); neither its value nor its equalities are pinned.",
        "Messages are their Debug form. An error is its gRPC code, its kilnd-reason trailer and its message up to the first ':' after the token.",
        "Flag-off Health is pinned byte for byte by flag_off_health_bytes_are_unchanged, and the checkpoint messages' protobuf encoding by checkpoint-wire.json, not here.",
        "Regenerate with KILND_BLESS_CHECKPOINT_CONTRACT=1 scripts/build.sh default test -p kilnd --lib harness_contract_goldens_match (refused when CI is set).",
    ];
    obj([
        ("format", J::N(1)),
        (
            "notes",
            J::A(notes.iter().map(|n| J::S(n.to_string())).collect()),
        ),
        ("fixtures", J::O(fixtures)),
        (
            "reasons",
            obj([("table", reason_table()), ("firecracker", J::A(fc.steps))]),
        ),
        ("health", flag_on_health().await),
    ])
}

const CONTRACT: &str = "checkpoint-contract.json";

#[tokio::test]
async fn harness_contract_goldens_match() {
    check_golden(CONTRACT, &contract(0).await);
}

/// A service that publishes a checkpoint's idle deadline 1 s later than the engine
/// enforces it changes the golden (C6a adversarial review H8: `<wall>` normalization
/// hid it).
#[tokio::test]
async fn the_golden_catches_a_published_idle_deadline_shift() {
    let shifted = contract(1000).await;
    let file = std::fs::read_to_string(data_path(CONTRACT)).unwrap();
    let what =
        golden_mismatch(&shifted, &file).expect("a 1 s later idle deadline is a contract change");
    assert!(what.contains("idle_expires_at_unix_ms: <clock+"), "{what}");
}

#[path = "checkpoint_wire_tests.rs"]
mod wire;

#[cfg(test)]
// Approved (design 7.1): a test fixture, compiled only under cfg(test). It rewrites its
// own golden file in the source tree, and only when asked to bless it.
#[allow(clippy::disallowed_methods)]
fn bless(path: &std::path::Path, text: &str) {
    std::fs::write(path, text).unwrap();
}
