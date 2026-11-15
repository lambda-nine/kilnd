//! Checkpoint milestone C6b: the fake-runtime regressions that close the acceptance
//! ledger's design 11.2 item 4 and item 7 gaps, through the gRPC service where the gate
//! under test lives there, over the C5 engine, the fake backend's scripted helper group
//! and the real store.
//!
//! - `11.2.4-queued-exec-stream`: a capture against an ExecStream queued behind a
//!   running Exec, and against one admitted in the same scheduler turn as the capture.
//! - `11.2.4-fork-get`: Gets racing a fork's preflight, its pinned restore, and a fork
//!   that fails.
//! - `11.2.4-output-queue` and `11.2.4-control-queue`: Health, Get, List and Delete keep
//!   progressing, and a capture of the busy source refuses at once, while an ExecStream's
//!   output queue is full, while the source's Exec queue is full, and while the ordinary
//!   RPC lane is at its cap.
//! - `11.2.7-wall-clock-jumps` and `11.2.7-suspend`: checkpoint deadlines follow
//!   CLOCK_BOOTTIME, and the sweeper's rescan notices a resume from suspend.
//!
//! `c6b_fake_daemon_overhead` is an ignored benchmark of the daemon's own cost per
//! capture, fork and delete on the fake backend.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::task::Poll;

use kilnd_api::v1 as pb;
use pb::kilnd_service_server::KilndService;
use tokio_stream::StreamExt;
use tonic::{Code, Request, Response, Status};

use super::*;
use crate::admission::{ConnectionLane, RpcClass};
use crate::exec_stream::{LiveEvent, StreamBuffer};
use crate::manager::Feature;
use crate::runtime::fake::FakeRestore;
use crate::server::PeerIdentity;
use crate::service::{REASON_KEY, Service};

const UID: u32 = 1000;
const DAY: i64 = 86_400 * SEC;
/// How long a call that must not wait on a stalled queue may take.
const BOUND: Duration = Duration::from_secs(2);

type Api = Arc<Service<FakeRuntime>>;

fn api(m: &M) -> Api {
    Arc::new(Service::new(Arc::clone(m)))
}

fn as_uid<T>(message: T, uid: u32) -> Request<T> {
    let mut request = Request::new(message);
    request.extensions_mut().insert(PeerIdentity {
        uid: Some(uid),
        lane: ConnectionLane::General,
    });
    request
}

/// A typed refusal: its code, its `kilnd-reason` trailer and its message's token.
#[track_caller]
fn refused(s: &Status, code: Code, token: &str) {
    assert_eq!(s.code(), code, "{s:?}");
    assert_eq!(
        s.metadata().get(REASON_KEY).map(|v| v.to_str().unwrap()),
        Some(token),
        "{s:?}"
    );
    assert!(s.message().starts_with(&format!("{token}: ")), "{s:?}");
}

/// The error of a call whose success type has no `Debug`.
#[track_caller]
fn failed<T>(r: Result<T, Status>) -> Status {
    match r {
        Ok(_) => panic!("the call succeeded"),
        Err(s) => s,
    }
}

/// `what` must finish within [`BOUND`], whatever else is stalled.
async fn within<T>(what: &str, f: impl Future<Output = T>) -> T {
    tokio::time::timeout(BOUND, f)
        .await
        .unwrap_or_else(|_| panic!("{what} stalled past {BOUND:?}"))
}

/// Polls `f` once, without yielding to the scheduler.
async fn poll_once<F: Future + ?Sized>(mut f: Pin<&mut F>) -> Poll<F::Output> {
    std::future::poll_fn(|cx| Poll::Ready(f.as_mut().poll(cx))).await
}

/// The backend proved ExecStream in a Health probe; the service is up.
async fn streaming(m: &M, fake: &FakeRuntime) -> Api {
    fake.state().proven_features = Ok(vec![Feature::ExecStream]);
    let s = api(m);
    assert_eq!(health(&s).await.status, serving());
    s
}

fn serving() -> i32 {
    pb::health_response::Status::Serving as i32
}

async fn health(s: &Api) -> pb::HealthResponse {
    s.health(as_uid(pb::HealthRequest {}, UID))
        .await
        .unwrap()
        .into_inner()
}

async fn api_source(s: &Api) -> pb::Sandbox {
    s.create_sandbox(as_uid(pb::CreateSandboxRequest::default(), UID))
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap()
}

fn capture_msg(sandbox_id: &str, lifetime_s: u64, idle_s: u64) -> pb::CheckpointSandboxRequest {
    pb::CheckpointSandboxRequest {
        sandbox_id: sandbox_id.into(),
        expiry: Some(pb::ExpiryPolicy {
            max_lifetime_ms: lifetime_s * 1000,
            idle_timeout_ms: idle_s * 1000,
        }),
        ..Default::default()
    }
}

async fn api_capture_with(
    s: &Api,
    sandbox_id: &str,
    lifetime_s: u64,
    idle_s: u64,
) -> Result<pb::Checkpoint, Status> {
    s.checkpoint_sandbox(as_uid(capture_msg(sandbox_id, lifetime_s, idle_s), UID))
        .await
        .map(|r| r.into_inner().checkpoint.unwrap())
}

/// A capture with `{}`: the node's default expiry.
async fn api_capture(s: &Api, sandbox_id: &str) -> Result<pb::Checkpoint, Status> {
    api_capture_with(s, sandbox_id, 0, 0).await
}

async fn api_get(s: &Api, id: &str) -> Result<pb::Checkpoint, Status> {
    s.get_checkpoint(as_uid(pb::GetCheckpointRequest { id: id.into() }, UID))
        .await
        .map(|r| r.into_inner().checkpoint.unwrap())
}

async fn api_list(s: &Api) -> Result<Vec<pb::Checkpoint>, Status> {
    s.list_checkpoints(as_uid(
        pb::ListCheckpointsRequest {
            page_size: 100,
            ..Default::default()
        },
        UID,
    ))
    .await
    .map(|r| r.into_inner().checkpoints)
}

/// One checkpoint as ListCheckpoints shows it (List never refreshes idle).
async fn list_one(s: &Api, id: &str) -> pb::Checkpoint {
    api_list(s)
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.id == id)
        .unwrap()
}

async fn api_delete(s: &Api, id: &str) -> Result<pb::Checkpoint, Status> {
    s.delete_checkpoint(as_uid(
        pb::DeleteCheckpointRequest {
            id: id.into(),
            release_request_id: false,
        },
        UID,
    ))
    .await
    .map(|r| r.into_inner().checkpoint.unwrap())
}

async fn api_fork(s: &Api, checkpoint: &str) -> Result<pb::Sandbox, Status> {
    s.create_sandbox(as_uid(
        pb::CreateSandboxRequest {
            from_checkpoint: checkpoint.into(),
            ..Default::default()
        },
        UID,
    ))
    .await
    .map(|r| r.into_inner().sandbox.unwrap())
}

async fn api_delete_sandbox(s: &Api, id: &str) -> Result<pb::Sandbox, Status> {
    s.delete_sandbox(as_uid(
        pb::DeleteSandboxRequest {
            id: id.into(),
            release_request_id: false,
        },
        UID,
    ))
    .await
    .map(|r| r.into_inner().sandbox.unwrap())
}

async fn api_exec(s: &Api, id: &str, argv: &[&str]) -> Result<pb::Execution, Status> {
    s.exec(as_uid(
        pb::ExecRequest {
            sandbox_id: id.into(),
            argv: argv.iter().map(|a| a.to_string()).collect(),
            ..Default::default()
        },
        UID,
    ))
    .await
    .map(|r| r.into_inner().execution.unwrap())
}

fn spawn_exec(
    s: &Api,
    id: &str,
    argv: &[&str],
) -> tokio::task::JoinHandle<Result<pb::Execution, Status>> {
    let (s, id) = (Arc::clone(s), id.to_string());
    let argv: Vec<String> = argv.iter().map(|a| a.to_string()).collect();
    tokio::spawn(async move {
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        api_exec(&s, &id, &argv).await
    })
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

/// An ExecStream response body, drained to its end: the turn's exit code.
async fn drained(
    r: Result<Response<<Service<FakeRuntime> as KilndService>::ExecStreamStream>, Status>,
) -> i32 {
    use pb::exec_stream_response::Event;
    let mut body = r.map_err(|s| format!("{s:?}")).unwrap().into_inner();
    let mut last = None;
    while let Some(m) = body.next().await {
        last = Some(m.unwrap());
    }
    match last.and_then(|m| m.event) {
        Some(Event::Finished(f)) => f.execution.unwrap().exit_code.unwrap(),
        other => panic!("{other:?}"),
    }
}

fn state(c: &pb::Checkpoint) -> pb::CheckpointState {
    pb::CheckpointState::try_from(c.state).unwrap()
}

fn sandbox_state(s: &pb::Sandbox) -> pb::SandboxState {
    pb::SandboxState::try_from(s.state).unwrap()
}

fn execution_rows(m: &M) -> i64 {
    m.store
        .query_for_test("SELECT count(*) FROM executions", [])
        .unwrap()
}

/// Everything a capture could reserve: the node's checkpoint charge, rows, workers in
/// use, helper capture calls and the shared disk reservation.
#[derive(Debug, PartialEq, Eq)]
struct Reserved {
    charge: (u64, u64),
    rows: usize,
    workers: usize,
    captures: usize,
    disk: u64,
}

fn reserved(m: &M, fake: &FakeRuntime) -> Reserved {
    Reserved {
        charge: charge(m),
        rows: m
            .store
            .checkpoint_page(None, None, None, 1000)
            .unwrap()
            .rows
            .len(),
        workers: m.checkpoint.workers.lock().unwrap().0,
        captures: calls(fake, "capture"),
        disk: m.store_resources_for_test().disk_bytes,
    }
}

// --- 11.2.4-queued-exec-stream ---------------------------------------------------------

/// A capture refuses `checkpoint_busy`, reserving nothing, while an ExecStream is
/// queued behind a running Exec and while that stream runs; it succeeds once both end.
/// Then the stream gate alone: a stream admitted in the same scheduler turn as a
/// capture, before its supervisor took the exec mutex, still makes the capture busy
/// (only its queued admission marks the source). And the reverse: a capture holding the
/// source refuses a new ExecStream at the service, typed, with no row.
#[tokio::test]
async fn capture_refuses_busy_while_an_exec_stream_is_queued_behind_a_running_exec() {
    let (m, fake, _) = engine();
    let s = streaming(&m, &fake).await;
    let src = api_source(&s).await;
    let slot = m.slot(&src.id);
    let idle = slot.capacity;
    let base = reserved(&m, &fake);

    // A running Exec, held inside the backend.
    let exec_gate = FakeGate::default();
    fake.state().exec_before_run = Some(exec_gate.clone());
    let running = spawn_exec(&s, &src.id, &["echo", "running"]);
    exec_gate.entered().await;
    // The stream's own command holds too, once it runs.
    let stream_gate = FakeGate::default();
    fake.state().exec_before_run = Some(stream_gate.clone());
    // A second request on the source: an ExecStream through the service's handler.
    let queued = {
        let (s, id) = (Arc::clone(&s), src.id.clone());
        tokio::spawn(async move {
            drained(
                s.exec_stream(as_uid(turn_req(&id, &["echo", "queued"]), UID))
                    .await,
            )
            .await
        })
    };
    until("the stream is admitted and queued", || {
        slot.outstanding_execs.available_permits() == idle - 2
    })
    .await;
    assert_eq!(fake.state().exec_calls.len(), 1, "the stream has not run");
    assert!(!queued.is_finished());
    let e = api_capture(&s, &src.id).await.unwrap_err();
    refused(&e, Code::FailedPrecondition, "checkpoint_busy");
    assert_eq!(reserved(&m, &fake), base, "busy behind a running Exec");
    assert!(!slot.capturing());

    // The Exec ends; the queued stream runs next, and the source stays busy.
    exec_gate.release();
    assert_eq!(running.await.unwrap().unwrap().exit_code, Some(0));
    stream_gate.entered().await;
    assert_eq!(slot.outstanding_execs.available_permits(), idle - 1);
    let e = api_capture(&s, &src.id).await.unwrap_err();
    refused(&e, Code::FailedPrecondition, "checkpoint_busy");
    assert_eq!(reserved(&m, &fake), base, "busy while the stream runs");
    stream_gate.release();
    assert_eq!(queued.await.unwrap(), 0);
    until("the stream's ticket is released", || {
        slot.outstanding_execs.available_permits() == idle
    })
    .await;
    // Both ended: the capture succeeds.
    let c = api_capture(&s, &src.id).await.unwrap();
    assert_eq!(state(&c), pb::CheckpointState::Ready);
    assert_eq!(charge(&m), (1, S));

    // The stream gate alone. The capture's supervisor is spawned first, then the stream
    // is admitted (its ticket taken, its supervisor spawned but not yet run), so the
    // capture's source gate runs while nothing holds the exec mutex.
    let base = reserved(&m, &fake);
    let execs = fake.state().exec_calls.len();
    let mut capturing = s.checkpoint_sandbox(as_uid(capture_msg(&src.id, 0, 0), UID));
    assert!(poll_once(capturing.as_mut()).await.is_pending());
    let mut admitted = s.exec_stream(as_uid(turn_req(&src.id, &["echo", "admitted"]), UID));
    assert!(poll_once(admitted.as_mut()).await.is_pending());
    assert_eq!(
        slot.outstanding_execs.available_permits(),
        idle - 1,
        "the stream holds its admission ticket"
    );
    assert!(
        slot.exec_lock.try_lock().is_ok(),
        "nothing holds the exec mutex yet"
    );
    let e = capturing.await.unwrap_err();
    refused(&e, Code::FailedPrecondition, "checkpoint_busy");
    assert_eq!(
        reserved(&m, &fake),
        base,
        "busy on the queued admission alone"
    );
    assert!(!slot.capturing());
    assert_eq!(drained(admitted.await).await, 0, "the stream then runs");
    assert_eq!(fake.state().exec_calls.len(), execs + 1);

    // The reverse: a capture holds the source, so the stream's admission refuses.
    let gate = gate_capture(&fake);
    let holding = {
        let (s, id) = (Arc::clone(&s), src.id.clone());
        tokio::spawn(async move { api_capture(&s, &id).await })
    };
    gate.entered().await;
    let rows = execution_rows(&m);
    let e = failed(
        s.exec_stream(as_uid(turn_req(&src.id, &["echo"]), UID))
            .await,
    );
    refused(&e, Code::FailedPrecondition, "checkpoint_busy");
    assert_eq!(execution_rows(&m), rows, "no execution row");
    assert_eq!(
        m.admission.snapshot().streams.current,
        0,
        "no stream permit kept"
    );
    gate.release();
    assert_eq!(
        state(&holding.await.unwrap().unwrap()),
        pb::CheckpointState::Ready
    );
    assert_eq!(
        drained(
            s.exec_stream(as_uid(turn_req(&src.id, &["echo"]), UID))
                .await
        )
        .await,
        0
    );
}

// --- 11.2.4-fork-get -------------------------------------------------------------------

/// Design 7.2 and 8.1: idle refreshes on a successful Get and on an accepted fork (its
/// pin's transaction), is paused while restore pins are live, and the last pin's
/// release records finish activity; lifetime never pauses. Gets racing a fork's
/// preflight (no pin yet) and its pinned restore all answer READY, the latter idle
/// paused even past the idle timeout; the fork is READY with the checkpoint's digest,
/// and Get then reports idle running again from the release. A fork whose restore
/// fails leaves the checkpoint READY, its pin released and Get unpaused.
#[tokio::test]
async fn a_fork_racing_get_of_its_checkpoint_has_one_consistent_winner() {
    let (m, fake, clock) = engine();
    let s = api(&m);
    let src = api_source(&s).await;
    let c = api_capture_with(&s, &src.id, 3600, 60).await.unwrap();
    let idle_ms = 60 * SEC;
    let expiry = |c: &pb::Checkpoint| c.expiry.unwrap();
    let gets = |n: usize| {
        let (s, id) = (Arc::clone(&s), c.id.clone());
        async move {
            let tasks: Vec<_> = (0..n)
                .map(|_| {
                    let (s, id) = (Arc::clone(&s), id.clone());
                    tokio::spawn(async move { api_get(&s, &id).await })
                })
                .collect();
            let mut out = Vec::new();
            for t in tasks {
                out.push(t.await.unwrap().unwrap());
            }
            out
        }
    };
    let lifetime_at = expiry(&c).lifetime_expires_at_unix_ms;

    // Gets racing the fork's preflight await (before its accepting transaction): READY,
    // not paused, and the fork is still admitted after their activity CAS.
    let preflight = FakeGate::default();
    fake.checkpoints(|g| g.capabilities_gate = Some(preflight.clone()));
    let restore = {
        let gate = FakeGate::default();
        fake.checkpoints(|g| g.restore_gate = Some(gate.clone()));
        gate
    };
    let forking = {
        let (s, id) = (Arc::clone(&s), c.id.clone());
        tokio::spawn(async move { api_fork(&s, &id).await })
    };
    preflight.entered().await;
    let seq = row(&m, &c.id).activity_seq;
    for got in gets(4).await {
        assert_eq!(state(&got), pb::CheckpointState::Ready);
        assert!(!expiry(&got).idle_paused && expiry(&got).idle_expires_at_unix_ms > 0);
        assert_eq!(got.content_sha256, c.content_sha256);
    }
    assert!(row(&m, &c.id).activity_seq > seq, "the Gets refreshed idle");
    assert!(m.store.checkpoint_pins(&c.id).unwrap().is_empty());
    preflight.release();

    // The restore runs with the pin live: every Get answers READY, idle paused.
    restore.entered().await;
    let pins = m.store.checkpoint_pins(&c.id).unwrap();
    assert_eq!(pins.len(), 1);
    assert!(pins[0].released_at_ms.is_none());
    let seq = row(&m, &c.id).activity_seq;
    for got in gets(4).await {
        assert_eq!(state(&got), pb::CheckpointState::Ready);
        let e = expiry(&got);
        assert!(e.idle_paused, "{e:?}");
        assert_eq!(e.idle_expires_at_unix_ms, 0, "paused: no idle deadline");
        assert_eq!(
            e.lifetime_expires_at_unix_ms, lifetime_at,
            "lifetime never moves"
        );
    }
    assert!(
        row(&m, &c.id).activity_seq > seq,
        "a Get under a pin still records activity"
    );
    // Past the idle timeout with the pin live, and no Get since: a sweep leaves it READY
    // and paused (read through List, which refreshes nothing).
    clock.advance(idle_ms + SEC);
    m.expire_checkpoints_due();
    let listed = list_one(&s, &c.id).await;
    assert_eq!(state(&listed), pb::CheckpointState::Ready);
    assert!(expiry(&listed).idle_paused);
    restore.release();
    let f = forking.await.unwrap().unwrap();
    assert_eq!(sandbox_state(&f), pb::SandboxState::Ready, "{f:?}");
    assert_eq!(
        (
            f.from_checkpoint.as_str(),
            f.checkpoint_content_sha256.as_str()
        ),
        (c.id.as_str(), c.content_sha256.as_str())
    );
    let pin = m.store.checkpoint_pin(&f.id).unwrap().unwrap();
    assert_eq!(pin.released_by.as_deref(), Some("complete"));
    // Unpaused, and idle runs again from the pin's release (its finish activity), not
    // from the last Get 61 s earlier: List, which refreshes nothing, shows it, and a
    // sweep leaves it READY.
    let e = expiry(&list_one(&s, &c.id).await);
    assert!(!e.idle_paused, "{e:?}");
    assert_eq!(e.idle_expires_at_unix_ms, clock.wall_ms() + idle_ms);
    m.expire_checkpoints_due();
    assert_eq!(row(&m, &c.id).state, CheckpointState::Ready);
    let got = api_get(&s, &c.id).await.unwrap();
    assert_eq!(state(&got), pb::CheckpointState::Ready);
    let e = expiry(&got);
    assert!(!e.idle_paused);
    assert_eq!(e.idle_expires_at_unix_ms, clock.wall_ms() + idle_ms);
    assert_eq!(e.lifetime_expires_at_unix_ms, lifetime_at);

    // Gets racing a fork that fails: the restore's reader settles not_created.
    let restore = {
        let gate = FakeGate::default();
        fake.checkpoints(|g| {
            g.restore_gate = Some(gate.clone());
            g.restores.push_back(FakeRestore::NotCreated(
                crate::checkpoint::Reason::ImageUnavailable,
            ));
        });
        gate
    };
    let failing = {
        let (s, id) = (Arc::clone(&s), c.id.clone());
        tokio::spawn(async move { api_fork(&s, &id).await })
    };
    restore.entered().await;
    // Past the idle timeout under this pin: a sweep and every Get leave it READY, paused.
    clock.advance(idle_ms + SEC);
    m.expire_checkpoints_due();
    for got in gets(4).await {
        assert_eq!(state(&got), pb::CheckpointState::Ready);
        assert!(expiry(&got).idle_paused);
    }
    restore.release();
    let e = failing.await.unwrap().unwrap_err();
    refused(&e, Code::FailedPrecondition, "checkpoint_image_unavailable");
    assert_eq!(row(&m, &c.id).state, CheckpointState::Ready);
    let live: Vec<_> = m
        .store
        .checkpoint_pins(&c.id)
        .unwrap()
        .into_iter()
        .filter(|p| p.released_at_ms.is_none())
        .collect();
    assert!(live.is_empty(), "{live:?}");
    let got = api_get(&s, &c.id).await.unwrap();
    assert_eq!(state(&got), pb::CheckpointState::Ready);
    assert!(!expiry(&got).idle_paused && expiry(&got).idle_expires_at_unix_ms > 0);
    assert_eq!(got.content_sha256, c.content_sha256);
    assert_eq!(charge(&m), (1, S));
    // The checkpoint still forks.
    let again = api_fork(&s, &c.id).await.unwrap();
    assert_eq!(sandbox_state(&again), pb::SandboxState::Ready);
}

// --- 11.2.4-output-queue ---------------------------------------------------------------

/// An ExecStream whose consumer never reads fills its bounded output queue and drops
/// live bytes. Meanwhile Health, Get, List and Delete of another checkpoint each
/// complete within the bound, a capture of the streaming source refuses busy at once
/// with nothing reserved, and the stream is still running and full afterwards. Deleting
/// the source also completes within the bound and ends the stream with its final
/// message.
#[tokio::test]
async fn a_full_exec_stream_output_queue_never_stalls_checkpoint_health_or_delete() {
    let buffer = StreamBuffer {
        buffer_bytes: 64 * 1024,
        chunk_bytes: 16 * 1024,
    };
    let (m, fake, _) = engine_with(
        FakeRuntime::default().with_checkpoints(),
        Limits {
            exec_stream: buffer,
            ..test_limits()
        },
    );
    let s = streaming(&m, &fake).await;
    let src = api_source(&s).await;
    let kept = api_capture(&s, &src.id).await.unwrap();
    let doomed = api_capture(&s, &src.id).await.unwrap();
    // The stream is admitted as the service admits it (an ordinary RPC permit for the
    // uid), at the manager, so the test can watch its queue. 16 KiB chunks a
    // millisecond apart, for far longer than the test, until its source is deleted.
    let rpc = m.admission.try_rpc(RpcClass::Ordinary, Some(UID)).unwrap();
    m.authorize(&src.id, UID).unwrap();
    let mut start = m
        .exec_stream_received(
            exec_req(&src.id, &["stream", "1000000", "16384", "1"]),
            tokio::time::Instant::now(),
            UID,
            rpc,
        )
        .await
        .unwrap();
    // Nobody reads the handle: the queue fills and starts dropping.
    until("the stream's queue is full", || {
        start.handle.queue().queue_dropped()[0] > 0
    })
    .await;
    assert!(start.handle.queue().queued_bytes() <= buffer.buffer_bytes);
    let dropped = start.handle.queue().queue_dropped()[0];

    let h = within("Health", health(&s)).await;
    assert_eq!(h.status, serving());
    assert_eq!(h.running_executions, 1);
    let got = within("GetCheckpoint", api_get(&s, &kept.id))
        .await
        .unwrap();
    assert_eq!(state(&got), pb::CheckpointState::Ready);
    let listed = within("ListCheckpoints", api_list(&s)).await.unwrap();
    let ids: Vec<&str> = listed.iter().map(|c| c.id.as_str()).collect();
    assert!(
        ids.contains(&kept.id.as_str()) && ids.contains(&doomed.id.as_str()),
        "{ids:?}"
    );
    let d = within("DeleteCheckpoint", api_delete(&s, &doomed.id))
        .await
        .unwrap();
    assert_eq!(state(&d), pb::CheckpointState::Deleted);
    assert_eq!(charge(&m), (1, S));
    let base = reserved(&m, &fake);
    let e = within(
        "a capture of the streaming source",
        api_capture(&s, &src.id),
    )
    .await
    .unwrap_err();
    refused(&e, Code::FailedPrecondition, "checkpoint_busy");
    assert_eq!(reserved(&m, &fake), base);
    // None of that waited for the stream: it still runs, still full and dropping.
    assert_eq!(
        m.execution(&start.execution_id).unwrap().state,
        ExecutionState::Running
    );
    until("more live bytes dropped", || {
        start.handle.queue().queue_dropped()[0] > dropped
    })
    .await;

    // Deleting the source cancels the command; the final message takes its reserved
    // slot even though the queue is full.
    let gone = within(
        "DeleteSandbox of the streaming source",
        api_delete_sandbox(&s, &src.id),
    )
    .await
    .unwrap();
    assert_eq!(sandbox_state(&gone), pb::SandboxState::Deleted);
    let last = within("the stream's end", async {
        let mut last = None;
        while let Some(event) = std::future::poll_fn(|cx| start.handle.poll_event(cx)).await {
            last = Some(event);
        }
        last
    })
    .await;
    match last {
        Some(LiveEvent::Finished { execution, .. }) => {
            let execution = (*execution).unwrap();
            assert_ne!(execution.state, ExecutionState::Running);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        state(&api_get(&s, &kept.id).await.unwrap()),
        pb::CheckpointState::Ready
    );
}

// --- 11.2.4-control-queue --------------------------------------------------------------

/// The control queue, two ways. First the source's own request queue: the per-sandbox
/// Exec queue (`max_queued_execs_per_sandbox`), the only place the daemon queues control
/// requests (one running, the rest waiting on the exec mutex), full so the next Exec is
/// refused. Then, on top, the ordinary RPC lane at its cap (admission refuses rather
/// than queues there). In both, Health, Get and checkpoint Delete keep progressing
/// within the bound: Health has its own lane and Get/Delete fall back to the cleanup
/// lane. A capture of the source refuses busy at once with the Exec queue full, and
/// ordinary RPCs are refused at once with the lane full; nothing waits.
#[tokio::test]
async fn a_full_control_queue_never_stalls_checkpoint_health_or_delete() {
    let (m, fake, _) = engine_with(
        FakeRuntime::default().with_checkpoints(),
        Limits {
            max_queued_execs_per_sandbox: 2,
            max_concurrent_rpcs: 8,
            max_concurrent_rpcs_per_uid: 8,
            ..test_limits()
        },
    );
    let s = api(&m);
    let src = api_source(&s).await;
    let kept = api_capture(&s, &src.id).await.unwrap();
    let doomed = api_capture(&s, &src.id).await.unwrap();
    let also_doomed = api_capture(&s, &src.id).await.unwrap();
    let slot = m.slot(&src.id);
    assert_eq!(slot.capacity, 3, "one running plus two queued");

    // One Exec running, held in the backend, and two queued behind it.
    let gate = FakeGate::default();
    fake.state().exec_before_run = Some(gate.clone());
    let mut execs = vec![spawn_exec(&s, &src.id, &["echo", "0"])];
    gate.entered().await;
    execs.push(spawn_exec(&s, &src.id, &["echo", "1"]));
    execs.push(spawn_exec(&s, &src.id, &["echo", "2"]));
    until("the Exec queue is full", || {
        slot.outstanding_execs.available_permits() == 0
    })
    .await;
    let e = within("an Exec past the queue", api_exec(&s, &src.id, &["echo"]))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::ResourceExhausted, "{e:?}");

    let h = within("Health", health(&s)).await;
    assert_eq!(h.status, serving());
    let got = within("GetCheckpoint", api_get(&s, &kept.id))
        .await
        .unwrap();
    assert_eq!(state(&got), pb::CheckpointState::Ready);
    within("ListCheckpoints", api_list(&s)).await.unwrap();
    let d = within("DeleteCheckpoint", api_delete(&s, &doomed.id))
        .await
        .unwrap();
    assert_eq!(state(&d), pb::CheckpointState::Deleted);
    let base = reserved(&m, &fake);
    let e = within("a capture of the source", api_capture(&s, &src.id))
        .await
        .unwrap_err();
    refused(&e, Code::FailedPrecondition, "checkpoint_busy");
    assert_eq!(reserved(&m, &fake), base);

    // The ordinary RPC lane at its cap too (the three Execs hold three of its permits).
    let mut held = Vec::new();
    while let Ok(p) = m.admission.try_rpc(RpcClass::Ordinary, Some(UID)) {
        held.push(p);
    }
    assert_eq!(held.len(), 8 - 3);
    let e = within("an ordinary RPC", api_list(&s)).await.unwrap_err();
    assert_eq!(e.code(), Code::ResourceExhausted, "{e:?}");
    let e = within("a capture", api_capture(&s, &src.id))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::ResourceExhausted, "{e:?}");
    let h = within("Health", health(&s)).await;
    assert_eq!(h.status, serving());
    let got = within("GetCheckpoint", api_get(&s, &kept.id))
        .await
        .unwrap();
    assert_eq!(state(&got), pb::CheckpointState::Ready);
    let d = within("DeleteCheckpoint", api_delete(&s, &also_doomed.id))
        .await
        .unwrap();
    assert_eq!(state(&d), pb::CheckpointState::Deleted);
    assert_eq!(charge(&m), (1, S));
    assert_eq!(reserved(&m, &fake).workers, 0);

    // Both queues drain; then the source captures again.
    drop(held);
    gate.release();
    for (i, t) in execs.into_iter().enumerate() {
        let out = t.await.unwrap().unwrap();
        assert_eq!(out.exit_code, Some(0), "exec {i}");
    }
    until("the Exec queue drained", || {
        slot.outstanding_execs.available_permits() == slot.capacity
    })
    .await;
    let c = api_capture(&s, &src.id).await.unwrap();
    assert_eq!(state(&c), pb::CheckpointState::Ready);
}

// --- 11.2.7-wall-clock-jumps -----------------------------------------------------------

/// Each listed checkpoint's published (lifetime, idle) wall projections.
async fn projections(s: &Api) -> BTreeMap<String, (i64, i64)> {
    api_list(s)
        .await
        .unwrap()
        .into_iter()
        .map(|c| {
            let e = c.expiry.unwrap();
            (
                c.id,
                (e.lifetime_expires_at_unix_ms, e.idle_expires_at_unix_ms),
            )
        })
        .collect()
}

fn timer(m: &M, id: &str) -> Option<i64> {
    m.checkpoint.timers.lock().unwrap().get(id).copied()
}

async fn until_deleted(m: &M, id: &str, why: DeletionReason) {
    until("DELETED", || row(m, id).state == CheckpointState::Deleted).await;
    assert_eq!(row(m, id).deletion_reason, Some(why));
}

/// A day forward and a day back on the wall clock alone, boottime running normally:
/// a READY checkpoint's idle expiry and another's lifetime expiry each fire exactly at
/// their boottime deadline, never early after the forward step nor late after the back
/// step. The published wall projections move by the step; the timers do not.
#[tokio::test]
async fn checkpoint_expiry_follows_boottime_not_wall_clock_jumps() {
    for step in [DAY, -DAY] {
        let (m, _, clock) = engine();
        let s = api(&m);
        let src = api_source(&s).await;
        // Idle-bound: idle 30 s of a 600 s lifetime. Lifetime-bound: 40 s, kept active
        // by a Get so its idle (30 s) never comes first.
        let idle_c = api_capture_with(&s, &src.id, 600, 30).await.unwrap();
        let life_c = api_capture_with(&s, &src.id, 40, 30).await.unwrap();
        let ready = clock.boottime_ms();
        for c in [&idle_c, &life_c] {
            assert_eq!(row(&m, &c.id).ready_boottime_ms, Some(ready));
        }
        assert_eq!(timer(&m, &idle_c.id), Some(ready + 30 * SEC));
        assert_eq!(timer(&m, &life_c.id), Some(ready + 30 * SEC));
        clock.advance(10 * SEC);
        let before = projections(&s).await;
        assert_eq!(
            before[&idle_c.id],
            (clock.wall_ms() + 590 * SEC, clock.wall_ms() + 20 * SEC)
        );

        clock.step_wall(step);
        m.expire_checkpoints_due();
        let after = projections(&s).await;
        for c in [&idle_c, &life_c] {
            assert_eq!(row(&m, &c.id).state, CheckpointState::Ready, "step {step}");
            let (b, a) = (before[&c.id], after[&c.id]);
            assert_eq!(
                (a.0 - b.0, a.1 - b.1),
                (step, step),
                "the projections move with the wall"
            );
        }
        assert_eq!(
            timer(&m, &idle_c.id),
            Some(ready + 30 * SEC),
            "the deadline does not"
        );
        assert_eq!(timer(&m, &life_c.id), Some(ready + 30 * SEC));

        // A Get after the step: READY, not expired early, idle refreshed by boottime.
        clock.advance(10 * SEC);
        let got = api_get(&s, &life_c.id).await.unwrap();
        assert_eq!(state(&got), pb::CheckpointState::Ready);
        let e = got.expiry.unwrap();
        assert_eq!(e.lifetime_expires_at_unix_ms, clock.wall_ms() + 20 * SEC);
        assert_eq!(e.idle_expires_at_unix_ms, clock.wall_ms() + 30 * SEC);
        assert_eq!(
            timer(&m, &life_c.id),
            Some(ready + 40 * SEC),
            "now lifetime-bound"
        );

        // Idle, by boottime: not a millisecond early, not late.
        clock.advance(10 * SEC - 1);
        m.expire_checkpoints_due();
        assert_eq!(
            row(&m, &idle_c.id).state,
            CheckpointState::Ready,
            "step {step}"
        );
        clock.advance(1);
        m.expire_checkpoints_due();
        until_deleted(&m, &idle_c.id, DeletionReason::ExpiredIdle).await;
        assert_eq!(row(&m, &life_c.id).state, CheckpointState::Ready);
        // Lifetime, by boottime.
        clock.advance(10 * SEC - 1);
        m.expire_checkpoints_due();
        assert_eq!(
            row(&m, &life_c.id).state,
            CheckpointState::Ready,
            "step {step}"
        );
        clock.advance(1);
        m.expire_checkpoints_due();
        until_deleted(&m, &life_c.id, DeletionReason::ExpiredLifetime).await;
        assert_eq!(charge(&m), (0, 0));
    }
}

// --- 11.2.7-suspend --------------------------------------------------------------------

async fn settle() {
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
}

/// A suspend: CLOCK_BOOTTIME (and the wall clock) run on by 100 s while the runtime's
/// monotonic timers stand still, same boot ID, no restart. ManualClock's `advance`
/// moves boottime and wall time; tokio's paused clock is not advanced, as
/// CLOCK_MONOTONIC is not across a suspend. The running sweeper's rescan notices within
/// one interval: one checkpoint past its idle deadline expires idle, one past both
/// deadlines with lifetime the earlier expires on lifetime, each settles DELETED with
/// its charge released, and one whose deadlines are still ahead stays READY. Nothing is
/// rebased: a suspend is not a reboot.
#[tokio::test(start_paused = true)]
async fn checkpoint_expiry_counts_suspended_time_toward_lifetime_and_idle() {
    let (m, _, clock) = engine();
    let rescan = m.limits.expiry.rescan;
    assert_eq!(rescan, Duration::from_secs(30));
    let src = source(&m, UID).await;
    let capture = |lifetime_s, idle_s| {
        let m = Arc::clone(&m);
        let r = short(&src, lifetime_s, idle_s);
        async move { m.capture_checkpoint(r, UID, None, None).await.unwrap() }
    };
    let idle_c = capture(600, 60).await;
    let life_c = capture(100, 90).await;
    let kept = capture(3600, 600).await;
    let sweeper = m.start_expiry().unwrap();
    tokio::task::yield_now().await;

    // 20 s of ordinary running time; a Get keeps `life_c` active, so its idle deadline
    // (110 s) falls after its lifetime (100 s).
    clock.advance(20 * SEC);
    tokio::time::advance(Duration::from_secs(20)).await;
    m.get_checkpoint(life_c.id.as_str(), UID).unwrap();
    settle().await;
    for c in [&idle_c, &life_c, &kept] {
        assert_eq!(row(&m, c.id.as_str()).state, CheckpointState::Ready);
    }
    assert_eq!(charge(&m), (3, 3 * S));

    // The suspend: 100 s of boottime; the sweeper's sleep does not tick.
    let boot = clock.boot_id();
    clock.advance(100 * SEC);
    assert_eq!(clock.boot_id(), boot);
    // The sweeper last armed for min(next deadline, rescan) = 30 s at the Get.
    tokio::time::advance(rescan - Duration::from_secs(1)).await;
    settle().await;
    assert_eq!(row(&m, idle_c.id.as_str()).state, CheckpointState::Ready);
    tokio::time::advance(Duration::from_secs(1)).await;
    until_deleted(&m, idle_c.id.as_str(), DeletionReason::ExpiredIdle).await;
    until_deleted(&m, life_c.id.as_str(), DeletionReason::ExpiredLifetime).await;
    let k = row(&m, kept.id.as_str());
    assert_eq!(k.state, CheckpointState::Ready);
    assert_eq!(k.clock_boot_id.as_deref(), Some(boot.as_str()));
    assert_eq!(charge(&m), (1, S));
    assert_eq!(
        m.rebase_expiry_clocks().unwrap(),
        0,
        "a suspend is not a reboot"
    );
    // The survivor's deadline is still its boottime one: idle at 600 s from READY.
    assert_eq!(
        timer(&m, kept.id.as_str()),
        Some(k.ready_boottime_ms.unwrap() + 600 * SEC)
    );
    m.begin_shutdown();
    sweeper.await.unwrap();
}

// --- The benchmark ---------------------------------------------------------------------

/// Nearest-rank percentile of sorted microseconds.
fn percentile(sorted: &[u128], p: usize) -> u128 {
    let rank = (sorted.len() * p).div_ceil(100).max(1);
    sorted[rank - 1]
}

/// The daemon's own cost on the fake backend: 1,000 captures and 1,000 forks through
/// the gRPC service as uid 1000, each call timed alone, deleting the fork and the
/// checkpoint as it goes so no budget binds. The store is SQLite in a temporary
/// directory (`KILND_C6B_PERF_STORE=memory` for the in-memory store). Prints one
/// `C6B fake overhead {json}` line and, with `KILND_C6B_PERF_OUT` (a new file, or a
/// directory to put `fake-overhead.csv` in), writes every call's time as CSV.
#[tokio::test]
#[ignore = "benchmark: run by hand on a Mac"]
async fn c6b_fake_daemon_overhead() {
    const N: usize = 1000;
    let in_memory = std::env::var("KILND_C6B_PERF_STORE").as_deref() == Ok("memory");
    let (_tmp, m, store) = if in_memory {
        let (m, _, _) = engine();
        (None, m, "sqlite-in-memory")
    } else {
        let (tmp, _dir, m, _, _) = persistent().await;
        m.start_checkpoints().unwrap();
        (Some(tmp), m, "sqlite-tempdir")
    };
    let s = api(&m);
    let src = api_source(&s).await;
    let ops = ["capture", "fork", "checkpoint_delete", "sandbox_delete"];
    let mut times: [Vec<u128>; 4] = Default::default();
    let us = |t: std::time::Instant| t.elapsed().as_micros();
    for _ in 0..N {
        let t = std::time::Instant::now();
        let c = api_capture(&s, &src.id).await.unwrap();
        times[0].push(us(t));
        assert_eq!(state(&c), pb::CheckpointState::Ready);
        let t = std::time::Instant::now();
        let f = api_fork(&s, &c.id).await.unwrap();
        times[1].push(us(t));
        assert_eq!(sandbox_state(&f), pb::SandboxState::Ready);
        let t = std::time::Instant::now();
        let d = api_delete(&s, &c.id).await.unwrap();
        times[2].push(us(t));
        assert_eq!(state(&d), pb::CheckpointState::Deleted);
        let t = std::time::Instant::now();
        let d = api_delete_sandbox(&s, &f.id).await.unwrap();
        times[3].push(us(t));
        assert_eq!(sandbox_state(&d), pb::SandboxState::Deleted);
    }
    assert_eq!(charge(&m), (0, 0));
    if let Ok(path) = std::env::var("KILND_C6B_PERF_OUT") {
        let mut csv = String::from("op,iteration,micros\n");
        for (op, v) in ops.iter().zip(&times) {
            for (i, us) in v.iter().enumerate() {
                csv.push_str(&format!("{op},{i},{us}\n"));
            }
        }
        // A directory (as the VM perf run's `KILND_C6B_PERF_OUT` is) gets the CSV as
        // `fake-overhead.csv` inside it. Never overwrites: a new file only.
        let mut path = std::path::PathBuf::from(path);
        if path.is_dir() {
            path.push("fake-overhead.csv");
        }
        use std::io::Write;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .and_then(|mut f| f.write_all(csv.as_bytes()))
            .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    }
    let mut summary = serde_json::Map::new();
    summary.insert("store".into(), store.into());
    summary.insert(
        "build".into(),
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
        .into(),
    );
    summary.insert("iterations".into(), N.into());
    for (op, v) in ops.iter().zip(&mut times) {
        assert_eq!(v.len(), N);
        v.sort_unstable();
        summary.insert(
            format!("{op}_us"),
            serde_json::json!({ "p50": percentile(v, 50) as u64, "p95": percentile(v, 95) as u64 }),
        );
    }
    println!("C6B fake overhead {}", serde_json::Value::Object(summary));
}
