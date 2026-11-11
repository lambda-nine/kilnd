//! API additions M4 (design sections 5, 6, 7 and 8): ExecStream's order of checks and
//! admission, its live queue, disconnect, permits at handoff, tail-gap exactness and
//! schema 14's mode, driven by the fake runtime.

use std::future::poll_fn;
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::admission::RpcClass;
use crate::exec_stream::{Delivery, LiveEvent, LiveStream, StreamBuffer, StreamHandle};
use crate::expiry::ManualClock;
use crate::model::ExecutionMode;
use crate::runtime::fake::FakeRuntime;

fn limits() -> Limits {
    Limits {
        max_node_memory_bytes: 1 << 40,
        max_node_pids: 1 << 20,
        max_node_disk_bytes: 1 << 50,
        max_sandboxes: 64,
        health_success_cache: Duration::from_millis(1),
        health_failure_cache: Duration::from_millis(1),
        ..Limits::default()
    }
}

fn manager_on(fake: FakeRuntime, limits: Limits) -> Arc<Manager<FakeRuntime>> {
    Arc::new(Manager::with_clock(
        fake,
        Store::open_in_memory().unwrap(),
        limits,
        Arc::new(ManualClock::default()),
    ))
}

/// A manager whose backend has proven `features` in a Health probe.
async fn proven_with(
    features: &[Feature],
    limits: Limits,
) -> (Arc<Manager<FakeRuntime>>, FakeRuntime) {
    let fake = FakeRuntime::default();
    fake.state().proven_features = Ok(features.to_vec());
    let m = manager_on(fake.clone(), limits);
    assert!(m.health().await.unwrap().serving);
    (m, fake)
}

async fn streaming() -> (Arc<Manager<FakeRuntime>>, FakeRuntime) {
    proven_with(&[Feature::ExecStream], limits()).await
}

fn req(id: &str, argv: &[&str]) -> ExecRequest {
    ExecRequest {
        sandbox_id: id.into(),
        argv: argv.iter().map(|s| s.to_string()).collect(),
        stdin: vec![],
        timeout_ms: 0,
        cwd: String::new(),
        env: Vec::new(),
    }
}

async fn stream_as(
    m: &Arc<Manager<FakeRuntime>>,
    request: ExecRequest,
    uid: u32,
) -> Result<StreamStart> {
    let rpc = m
        .admission
        .try_rpc(RpcClass::Ordinary, Some(uid))
        .expect("an RPC permit");
    m.exec_stream_received(request, Instant::now(), uid, rpc)
        .await
}

async fn stream(m: &Arc<Manager<FakeRuntime>>, request: ExecRequest) -> Result<StreamStart> {
    stream_as(m, request, 1000).await
}

async fn drain(handle: &mut StreamHandle) -> Vec<LiveEvent> {
    let mut events = Vec::new();
    while let Some(event) = poll_fn(|cx| handle.poll_event(cx)).await {
        events.push(event);
    }
    events
}

fn finished(events: &[LiveEvent]) -> (&Execution, Delivery, Delivery) {
    match events.last() {
        Some(LiveEvent::Finished {
            execution,
            stdout,
            stderr,
        }) => (execution.as_ref().as_ref().unwrap(), *stdout, *stderr),
        other => panic!("the last event is not Finished: {other:?}"),
    }
}

/// Every stdout byte the stream delivered, checking offsets are gap-free.
fn delivered(events: &[LiveEvent], which: LiveStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    for event in events {
        match event {
            LiveEvent::Chunk {
                stream,
                offset,
                data,
            } if *stream == which => {
                assert_eq!(*offset, bytes.len() as u64, "no gap expected");
                bytes.extend_from_slice(data);
            }
            LiveEvent::Gap { stream, .. } if *stream == which => panic!("unexpected gap"),
            _ => {}
        }
    }
    bytes
}

fn reason(error: &Error) -> Option<&'static str> {
    match error {
        Error::FailedPrecondition(r) | Error::Refused(_, r) => r.reason(),
        _ => None,
    }
}

fn execution_rows(m: &Manager<FakeRuntime>) -> i64 {
    m.store
        .query_for_test("SELECT count(*) FROM executions", [])
        .unwrap()
}

/// Nothing allocated (design 8): no execution row, no ticket, no stream permit, no RPC
/// permit kept, no backend call.
fn assert_nothing_ran(m: &Manager<FakeRuntime>, fake: &FakeRuntime, rows_before: i64) {
    assert_eq!(execution_rows(m), rows_before);
    let snapshot = m.admission.snapshot();
    assert_eq!(snapshot.execs.current, 0);
    assert_eq!(snapshot.streams.current, 0);
    assert_eq!(snapshot.rpcs.current, 0);
    assert!(fake.state().exec_calls.is_empty());
}

async fn terminal(m: &Manager<FakeRuntime>, id: &str) -> Execution {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let execution = m.execution(id).unwrap();
        if execution.state != ExecutionState::Running {
            return execution;
        }
        assert!(std::time::Instant::now() < deadline, "{id} never finished");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn permits_released(m: &Manager<FakeRuntime>) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let s = m.admission.snapshot();
        if s.execs.current == 0 && s.streams.current == 0 && s.rpcs.current == 0 {
            return;
        }
        assert!(std::time::Instant::now() < deadline, "permits held: {s:?}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn a_stream_delivers_its_output_in_order_and_ends_with_the_stored_row() {
    let (m, _) = streaming().await;
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    let mut start = stream(&m, req(&sandbox.id, &["stream", "6", "20000", "1"]))
        .await
        .unwrap();
    assert_eq!(start.sandbox_id, sandbox.id);
    assert_eq!(start.timeout_ms, 1_800_000, "the stream default");
    let events = drain(&mut start.handle).await;
    let (execution, stdout, stderr) = finished(&events);
    // Parity (design 5): the row as GetExecution reads it, after publication.
    assert_eq!(execution, &m.execution(&start.execution_id).unwrap());
    assert_eq!(execution.id, start.execution_id);
    assert_eq!(execution.state, ExecutionState::Exited);
    assert_eq!(execution.mode, Some(ExecutionMode::Stream));
    let out = delivered(&events, LiveStream::Stdout);
    let expected: Vec<u8> = (0..6u8).flat_map(|i| vec![i; 20000]).collect();
    assert_eq!(out, expected);
    assert_eq!(
        &out[..execution.stdout.data.len()],
        &execution.stdout.data[..]
    );
    let err = delivered(&events, LiveStream::Stderr);
    assert_eq!(err, b"e0\ne1\ne2\ne3\ne4\ne5\n");
    assert_eq!(
        stdout,
        Delivery {
            delivered_bytes: 120_000,
            dropped_bytes: 0,
            dropped_bytes_known: true
        }
    );
    assert_eq!(stderr.delivered_bytes, err.len() as u64);
    // Every chunk is within the chunk size.
    for event in &events {
        if let LiveEvent::Chunk { data, .. } = event {
            assert!(!data.is_empty() && data.len() <= StreamBuffer::default().chunk_bytes);
        }
    }
    permits_released(&m).await;
    // A unary Exec records its own mode; a history row has none.
    let unary = m.exec(req(&sandbox.id, &["echo", "hi"])).await.unwrap();
    assert_eq!(unary.mode, Some(ExecutionMode::Unary));
    assert_eq!(
        m.execution(&unary.id).unwrap().mode,
        Some(ExecutionMode::Unary)
    );
}

#[tokio::test]
async fn every_refusal_before_the_row_is_an_error_and_allocates_nothing() {
    let (m, fake) = proven_with(&[], limits()).await;
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    // Not proven: UNIMPLEMENTED backend_unsupported:exec_stream.
    let error = stream(&m, req(&sandbox.id, &["true"])).await.err().unwrap();
    assert!(matches!(
        error,
        Error::Refused(RefusalCode::Unimplemented, _)
    ));
    assert_eq!(reason(&error), Some("backend_unsupported:exec_stream"));
    // Design 6: several unsupported fields report the first in Feature order.
    let mut with_cwd = req(&sandbox.id, &["true"]);
    with_cwd.cwd = "/w".into();
    let error = stream(&m, with_cwd).await.err().unwrap();
    assert_eq!(reason(&error), Some("backend_unsupported:exec_cwd"));
    assert_nothing_ran(&m, &fake, 0);

    let (m, fake) = streaming().await;
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    // Validation: argv, then the stream's own timeout limit (decision 4).
    let error = stream(&m, req(&sandbox.id, &[])).await.err().unwrap();
    assert!(matches!(error, Error::InvalidArgument(_)), "{error}");
    let mut long = req(&sandbox.id, &["true"]);
    long.timeout_ms = 7_200_001;
    let error = stream(&m, long).await.err().unwrap();
    assert!(error.to_string().contains("7200000"), "{error}");
    // Sandbox checks: an unknown or not-ready sandbox.
    let error = stream(&m, req("sb-0000000000000000", &["true"]))
        .await
        .err()
        .unwrap();
    assert!(matches!(error, Error::NotFound(_)), "{error}");
    let gone = m.create(CreateRequest::default()).await.unwrap();
    m.delete(&gone.id).await.unwrap();
    let error = stream(&m, req(&gone.id, &["true"])).await.err().unwrap();
    assert_eq!(reason(&error), Some("sandbox_deleted"));
    assert_nothing_ran(&m, &fake, 0);
    // A stream may run longer than a unary Exec may: two hours, not one.
    let mut two_hours = req(&sandbox.id, &["true"]);
    two_hours.timeout_ms = 7_200_000;
    let mut start = stream(&m, two_hours).await.unwrap();
    let events = drain(&mut start.handle).await;
    assert_eq!(finished(&events).0.timeout_ms, 7_200_000);
    let mut unary = req(&sandbox.id, &["true"]);
    unary.timeout_ms = 3_600_001;
    assert!(matches!(
        m.exec(unary).await.unwrap_err(),
        Error::InvalidArgument(_)
    ));
}

#[tokio::test]
async fn firecracker_refuses_exec_stream_before_prepare_or_any_row() {
    let fake = FakeRuntime::fenced();
    let m = manager_on(fake.clone(), limits());
    m.health().await.unwrap();
    assert!(!m.has_feature(Feature::ExecStream));
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    let prepared = fake.state().fenced.prepare_calls;
    let error = stream(&m, req(&sandbox.id, &["true"])).await.err().unwrap();
    assert!(matches!(
        error,
        Error::Refused(RefusalCode::Unimplemented, _)
    ));
    assert_eq!(reason(&error), Some("backend_unsupported:exec_stream"));
    assert_eq!(
        fake.state().fenced.prepare_calls,
        prepared,
        "no token issued"
    );
    assert_nothing_ran(&m, &fake, 0);
}

#[tokio::test]
async fn stream_caps_hold_per_uid_and_node_and_leave_unary_exec_room() {
    let (m, _) = proven_with(
        &[Feature::ExecStream],
        Limits {
            max_exec_streams: 3,
            max_exec_streams_per_uid: 2,
            max_concurrent_execs: 8,
            ..limits()
        },
    )
    .await;
    let mut sandboxes = Vec::new();
    for _ in 0..5 {
        sandboxes.push(m.create(CreateRequest::default()).await.unwrap());
    }
    let sleep = |i: usize| req(&sandboxes[i].id, &["sleep"]);
    let a = stream_as(&m, sleep(0), 1).await.unwrap();
    let b = stream_as(&m, sleep(1), 1).await.unwrap();
    // The uid's share is spent.
    let error = stream_as(&m, sleep(2), 1).await.err().unwrap();
    assert!(matches!(
        error,
        Error::Refused(RefusalCode::ResourceExhausted, _)
    ));
    assert_eq!(reason(&error), Some("exec_stream_limit"));
    let c = stream_as(&m, sleep(2), 2).await.unwrap();
    // The node is full for every uid.
    let error = stream_as(&m, sleep(3), 3).await.err().unwrap();
    assert_eq!(reason(&error), Some("exec_stream_limit"));
    let snapshot = m.admission.snapshot();
    assert_eq!(
        (
            snapshot.streams.max,
            snapshot.streams.current,
            snapshot.streams.rejected
        ),
        (3, 3, 2)
    );
    // A refused stream holds nothing, so its Exec ticket was never taken.
    assert_eq!(snapshot.execs.current, 3);
    assert_eq!(snapshot.execs.rejected, 0);
    // Another uid's unary Exec still gets through.
    let unary = m.exec(req(&sandboxes[4].id, &["echo", "x"])).await.unwrap();
    assert_eq!(unary.state, ExecutionState::Exited);
    // Disconnects cancel each, and every permit comes back.
    let ids = [&a, &b, &c].map(|s| s.execution_id.clone());
    drop((a, b, c));
    for id in ids {
        let execution = terminal(&m, &id).await;
        assert_eq!(execution.state, ExecutionState::Canceled);
        assert_eq!(
            execution.cancel_reason,
            Some(CancelReason::ClientDisconnected)
        );
    }
    permits_released(&m).await;
}

#[tokio::test]
async fn a_disconnect_cancels_like_exec_and_the_row_stays_readable() {
    let (m, fake) = streaming().await;
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    let start = stream(&m, req(&sandbox.id, &["sleep"])).await.unwrap();
    let id = start.execution_id.clone();
    drop(start);
    let execution = terminal(&m, &id).await;
    assert_eq!(execution.state, ExecutionState::Canceled);
    assert_eq!(
        execution.cancel_reason,
        Some(CancelReason::ClientDisconnected)
    );
    assert_eq!(execution.mode, Some(ExecutionMode::Stream));
    assert_eq!(fake.state().canceled_execs, 1);
    permits_released(&m).await;
}

#[tokio::test]
async fn a_queued_stream_whose_rpc_goes_away_never_runs() {
    let (m, fake) = streaming().await;
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    let gate = crate::runtime::fake::FakeGate::default();
    fake.state().exec_before_run = Some(gate.clone());
    let busy = {
        let m = m.clone();
        let id = sandbox.id.clone();
        tokio::spawn(async move { m.exec(req(&id, &["true"])).await })
    };
    while fake.state().exec_calls.is_empty() {
        tokio::task::yield_now().await;
    }
    let queued = {
        let m = m.clone();
        let id = sandbox.id.clone();
        tokio::spawn(async move { stream(&m, req(&id, &["echo", "late"])).await.map(|_| ()) })
    };
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    queued.abort();
    assert!(queued.await.unwrap_err().is_cancelled());
    gate.release();
    busy.await.unwrap().unwrap();
    permits_released(&m).await;
    assert_eq!(
        fake.state().exec_calls.len(),
        1,
        "the queued stream never ran"
    );
    assert_eq!(execution_rows(&m), 1);
}

#[tokio::test]
async fn the_deadline_is_fixed_at_admission_and_includes_queueing() {
    let (m, fake) = streaming().await;
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    let received = Instant::now();
    let rpc = m.admission.try_rpc(RpcClass::Ordinary, Some(1)).unwrap();
    let mut timed = req(&sandbox.id, &["true"]);
    timed.timeout_ms = 300_000;
    let mut start = m
        .exec_stream_received(timed, received, 1, rpc)
        .await
        .unwrap();
    drain(&mut start.handle).await;
    assert_eq!(
        fake.state().exec_deadlines[0],
        received + Duration::from_millis(300_000)
    );
    // Queued behind a running command past its whole budget: refused before its row.
    let gate = crate::runtime::fake::FakeGate::default();
    fake.state().exec_before_run = Some(gate.clone());
    let busy = {
        let m = m.clone();
        let id = sandbox.id.clone();
        tokio::spawn(async move { m.exec(req(&id, &["true"])).await })
    };
    while fake.state().exec_calls.len() < 2 {
        tokio::task::yield_now().await;
    }
    let mut short = req(&sandbox.id, &["true"]);
    short.timeout_ms = 50;
    let rows = execution_rows(&m);
    let error = stream(&m, short).await.err().unwrap();
    assert!(matches!(error, Error::DeadlineExceeded(_)), "{error}");
    assert_eq!(execution_rows(&m), rows);
    gate.release();
    busy.await.unwrap().unwrap();
    permits_released(&m).await;
}

/// Design 8: a never-reading client while the command writes at full rate. The command
/// finishes on time, the permits come back at handoff while the final message is still
/// unread, and the totals are exact because capture's are.
#[tokio::test]
async fn a_client_that_never_reads_only_loses_live_bytes_and_gets_its_permits_back() {
    let buffer = StreamBuffer {
        buffer_bytes: 64 * 1024,
        chunk_bytes: 16 * 1024,
    };
    let (m, _) = proven_with(
        &[Feature::ExecStream],
        Limits {
            exec_stream: buffer,
            ..limits()
        },
    )
    .await;
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    let started = std::time::Instant::now();
    let mut start = stream(&m, req(&sandbox.id, &["flood", "300"]))
        .await
        .unwrap();
    // Nobody polls the handle while the command runs.
    let execution = terminal(&m, &start.execution_id).await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "a stalled client slowed the command: {:?}",
        started.elapsed()
    );
    assert_eq!(execution.state, ExecutionState::Exited);
    permits_released(&m).await;
    assert!(start.handle.queue().queued_bytes() <= buffer.buffer_bytes);
    let total = execution.stdout.total_bytes;
    assert!(execution.stdout.total_bytes_known);
    assert!(
        total > buffer.buffer_bytes as u64 * 4,
        "flood wrote {total}"
    );
    let events = drain(&mut start.handle).await;
    let (last, stdout, _) = finished(&events);
    assert_eq!(last, &execution);
    assert!(stdout.dropped_bytes > 0);
    assert_eq!(stdout.delivered_bytes + stdout.dropped_bytes, total);
    assert!(stdout.dropped_bytes_known);
    // Gaps come before the next chunk and offsets account for every byte.
    let mut next = 0u64;
    let mut last_was_gap = false;
    for event in &events {
        match event {
            LiveEvent::Gap {
                stream: LiveStream::Stdout,
                offset,
                dropped_bytes,
                dropped_bytes_known,
            } => {
                assert_eq!(*offset, next);
                assert!(*dropped_bytes_known && *dropped_bytes > 0);
                assert!(!last_was_gap, "two gaps in a row");
                next += dropped_bytes;
                last_was_gap = true;
            }
            LiveEvent::Chunk {
                stream: LiveStream::Stdout,
                offset,
                data,
            } => {
                assert_eq!(*offset, next);
                next += data.len() as u64;
                last_was_gap = false;
            }
            _ => {}
        }
    }
    assert_eq!(next, total);
}

/// Design 8: a helper that dies after an EAGAIN drop and before settlement. The
/// interior gap is exact; the tail is not, so the delivery says so.
#[tokio::test]
async fn a_torn_capture_reports_an_exact_interior_gap_and_an_unknown_tail() {
    let (m, _) = streaming().await;
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    let mut start = stream(&m, req(&sandbox.id, &["torn"])).await.unwrap();
    let events = drain(&mut start.handle).await;
    let gaps: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            LiveEvent::Gap {
                stream: LiveStream::Stdout,
                offset,
                dropped_bytes,
                dropped_bytes_known,
            } => Some((*offset, *dropped_bytes, *dropped_bytes_known)),
            _ => None,
        })
        .collect();
    assert_eq!(gaps, [(10, 20, true), (33, 0, false)]);
    let (execution, stdout, stderr) = finished(&events);
    assert_eq!(execution.state, ExecutionState::Failed);
    assert!(!execution.stdout.total_bytes_known);
    assert_eq!(
        stdout,
        Delivery {
            delivered_bytes: 13,
            dropped_bytes: 20,
            dropped_bytes_known: false
        }
    );
    assert!(!stderr.dropped_bytes_known);
}

/// The stream's start races nothing: the row exists before `ExecStarted`, and the
/// disconnect of a stream that already finished cancels nothing.
#[tokio::test]
async fn dropping_a_finished_stream_changes_nothing() {
    let (m, _) = streaming().await;
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    let start = stream(&m, req(&sandbox.id, &["echo", "done"]))
        .await
        .unwrap();
    assert_eq!(
        m.execution(&start.execution_id).unwrap().mode,
        Some(ExecutionMode::Stream)
    );
    let execution = terminal(&m, &start.execution_id).await;
    permits_released(&m).await;
    drop(start);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(m.execution(&execution.id).unwrap(), execution);
    assert_eq!(execution.state, ExecutionState::Exited);
    assert_eq!(execution.stdout.data, b"done\n");
}

/// Design 1: EXEC_STREAM is dynamic. A failed probe withdraws it and the next stream is
/// refused before anything is allocated; a fresh success restores it.
#[tokio::test]
async fn a_failed_probe_withdraws_exec_stream_until_a_fresh_success() {
    let (m, fake) = streaming().await;
    assert!(m.features().contains(&Feature::ExecStream));
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    fake.state().proven_features = Err("older helper".into());
    tokio::time::sleep(Duration::from_millis(5)).await;
    let _ = m.health().await;
    assert!(!m.has_feature(Feature::ExecStream));
    let error = stream(&m, req(&sandbox.id, &["true"])).await.err().unwrap();
    assert_eq!(reason(&error), Some("backend_unsupported:exec_stream"));
    assert_nothing_ran(&m, &fake, 0);
    fake.state().proven_features = Ok(vec![Feature::ExecStream]);
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert!(m.health().await.unwrap().serving);
    let mut start = stream(&m, req(&sandbox.id, &["echo", "back"]))
        .await
        .unwrap();
    let events = drain(&mut start.handle).await;
    assert_eq!(finished(&events).0.stdout.data, b"back\n");
}

/// Design 5.1: a daemon crash ends the stream without `ExecFinished`; after restart the
/// row is INTERRUPTED, as for unary Exec, and keeps its mode.
#[tokio::test]
async fn an_interrupted_stream_row_keeps_its_mode() {
    let (m, _) = streaming().await;
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    let running = Execution {
        id: new_id("ex"),
        sandbox_id: sandbox.id.clone(),
        argv: vec!["sleep".into()],
        state: ExecutionState::Running,
        exit_code: None,
        command_status: None,
        runtime_error: None,
        failure_reason: None,
        started_at_ms: now_ms(),
        finished_at_ms: None,
        timeout_ms: 1000,
        stdin_bytes: 0,
        stdout: Captured::default(),
        stderr: Captured::default(),
        sandbox_reusable: None,
        cleanup_evidence: CleanupEvidence::Unknown,
        cancel_reason: None,
        cwd: None,
        env_names: Vec::new(),
        env_sha256: None,
        mode: Some(ExecutionMode::Stream),
    };
    assert!(m.store.start_execution(&running).unwrap());
    assert_eq!(
        m.store
            .interrupt_running_executions_for_backend("fake", "kilnd restarted")
            .unwrap(),
        1
    );
    let after = m.execution(&running.id).unwrap();
    assert_eq!(after.state, ExecutionState::Interrupted);
    assert_eq!(after.mode, Some(ExecutionMode::Stream));
}
