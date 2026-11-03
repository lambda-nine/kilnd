//! Stream-level adversaries over in-memory duplex pipes, on tokio's paused clock so
//! every deadline is exact (design 5.6 and the B5 exit criteria): no first byte, a
//! first byte only, trickled bytes, a never-reading peer, endless valid frames (empty
//! and full), cumulative wire-byte and frame-count limits across both channels,
//! unsolicited replies, trailing bytes and a missing EOF. Healthy exchanges still
//! complete inside their own deadlines while hostile ones run beside them.

mod common;

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use common::*;
use kilnd_broker_protocol::budget::{ExchangeBudget, ExecBudget};
use kilnd_broker_protocol::exchange::{HostConnection, HostEvent};
use kilnd_broker_protocol::message::*;
use kilnd_broker_protocol::stream::{Due, FrameReader, FrameWriter};
use kilnd_broker_protocol::*;
use tokio::io::{AsyncRead, AsyncWriteExt, DuplexStream, ReadBuf, duplex};
use tokio::time::Instant;

const TWO: Duration = Duration::from_secs(2);

/// Counts the bytes its reader actually consumed.
struct Counting {
    inner: DuplexStream,
    read: Arc<AtomicUsize>,
}

impl AsyncRead for Counting {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        self.read
            .fetch_add(buf.filled().len() - before, Ordering::SeqCst);
        poll
    }
}

fn host_reader(stream: DuplexStream) -> (FrameReader<Counting>, Arc<AtomicUsize>) {
    let read = Arc::new(AtomicUsize::new(0));
    (
        FrameReader::new(
            Counting {
                inner: stream,
                read: read.clone(),
            },
            Direction::GuestToHost,
        ),
        read,
    )
}

fn guest_writer(stream: DuplexStream) -> FrameWriter<DuplexStream> {
    FrameWriter::new(stream, Direction::GuestToHost)
}

fn far() -> Instant {
    Instant::now() + Duration::from_secs(3600)
}

#[tokio::test(start_paused = true)]
async fn no_first_byte_times_out_at_the_stage_deadline() {
    let (host, _guest) = duplex(4096);
    let (mut reader, _) = host_reader(host);
    let start = Instant::now();
    let result = reader
        .read_frame(Due::By(start + TWO), &mut ExchangeBudget::default())
        .await;
    assert_eq!(result, Err(ProtocolError::Timeout(Stage::FirstByte)));
    assert_eq!(start.elapsed(), TWO);
}

#[tokio::test(start_paused = true)]
async fn a_first_byte_alone_never_extends_the_frame_deadline() {
    let (host, mut guest) = duplex(4096);
    let (mut reader, _) = host_reader(host);
    let start = Instant::now();
    guest.write_all(b"K").await.unwrap();
    let result = reader
        .read_frame(Due::By(start + TWO), &mut ExchangeBudget::default())
        .await;
    assert_eq!(result, Err(ProtocolError::Timeout(Stage::Frame)));
    assert_eq!(start.elapsed(), TWO);
}

async fn trickle(mut guest: DuplexStream, bytes: Vec<u8>, gap: Duration) {
    for byte in bytes {
        if guest.write_all(&[byte]).await.is_err() {
            return;
        }
        tokio::time::sleep(gap).await;
    }
}

fn stdout_frame(seq: u32, len: usize) -> Vec<u8> {
    encode_frame(Kind::Stdout, Id128([1; 16]), seq, &vec![b'x'; len]).unwrap()
}

#[tokio::test(start_paused = true)]
async fn trickled_bytes_never_reset_the_frame_deadline() {
    let (host, guest) = duplex(4096);
    let (mut reader, read) = host_reader(host);
    let start = Instant::now();
    tokio::spawn(trickle(
        guest,
        stdout_frame(0, 100),
        Duration::from_millis(100),
    ));
    let result = reader
        .read_frame(Due::By(start + TWO), &mut ExecBudget::new(1024, 1024))
        .await;
    assert_eq!(result, Err(ProtocolError::Timeout(Stage::Frame)));
    assert_eq!(start.elapsed(), TWO);
    // Twenty bytes in two seconds; memory never exceeded the header buffer.
    assert!(read.load(Ordering::SeqCst) <= 21);
    assert_eq!(reader.held(), HEADER_LEN);
}

#[tokio::test(start_paused = true)]
async fn a_long_wait_for_output_then_a_trickle_still_settles_in_two_seconds() {
    let (host, guest) = duplex(4096);
    let (mut reader, _) = host_reader(host);
    let start = Instant::now();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(10)).await;
        trickle(guest, stdout_frame(0, 100), Duration::from_millis(100)).await;
    });
    let result = reader
        .read_frame(
            Due::FirstByte {
                first: start + Duration::from_secs(60),
                then: TWO,
            },
            &mut ExecBudget::new(1024, 1024),
        )
        .await;
    assert_eq!(result, Err(ProtocolError::Timeout(Stage::Frame)));
    assert_eq!(start.elapsed(), Duration::from_secs(12));
    assert_eq!(
        reader.first_byte_at(),
        Some(start + Duration::from_secs(10))
    );
}

#[tokio::test(start_paused = true)]
async fn a_never_reading_peer_cannot_pin_the_writer() {
    let (host, _guest_never_reads) = duplex(4096);
    let mut writer = FrameWriter::new(host, Direction::HostToGuest);
    let start = Instant::now();
    let result = writer
        .send(
            Id128([1; 16]),
            &Message::Stdin(vec![0; 64 * 1024]),
            start + TWO,
        )
        .await;
    assert_eq!(result, Err(ProtocolError::Timeout(Stage::Write)));
    assert_eq!(start.elapsed(), TWO);
    // And the guest's output writer to a host that never reads.
    let (guest, _host_never_reads) = duplex(4096);
    let mut writer = guest_writer(guest);
    let start = Instant::now();
    assert_eq!(
        writer
            .send(
                Id128([1; 16]),
                &Message::Stdout(vec![0; 64 * 1024]),
                start + TWO
            )
            .await,
        Err(ProtocolError::Timeout(Stage::Write))
    );
    assert_eq!(start.elapsed(), TWO);
}

async fn endless(guest: DuplexStream, len: usize) {
    let mut writer = guest_writer(guest);
    loop {
        if writer
            .send(Id128([1; 16]), &Message::Stdout(vec![b'x'; len]), far())
            .await
            .is_err()
        {
            return;
        }
    }
}

#[tokio::test(start_paused = true)]
async fn endless_empty_valid_frames_hit_the_frame_count() {
    let (host, guest) = duplex(64 * 1024);
    let (mut reader, read) = host_reader(host);
    tokio::spawn(endless(guest, 0));
    let mut budget = ExecBudget::new(1024 * 1024, 1024 * 1024);
    let mut frames = 0;
    let error = loop {
        match reader.read_frame(Due::By(far()), &mut budget).await {
            Ok(Some(_)) => frames += 1,
            Ok(None) => panic!("EOF"),
            Err(error) => break error,
        }
    };
    assert_eq!(error, ProtocolError::Budget(BudgetKind::Frames));
    assert_eq!(frames, 128);
    assert_eq!(read.load(Ordering::SeqCst), 129 * HEADER_LEN);
}

#[tokio::test(start_paused = true)]
async fn endless_full_valid_frames_stop_at_the_retained_limit_before_reading_the_body() {
    let (host, guest) = duplex(256 * 1024);
    let (mut reader, read) = host_reader(host);
    tokio::spawn(endless(guest, 64 * 1024));
    let mut budget = ExecBudget::new(1024 * 1024, 1024 * 1024);
    let mut frames = 0;
    let error = loop {
        match reader.read_frame(Due::By(far()), &mut budget).await {
            Ok(Some(_)) => frames += 1,
            Ok(None) => panic!("EOF"),
            Err(error) => break error,
        }
        assert!(reader.held() <= HEADER_LEN + 64 * 1024);
    };
    assert_eq!(error, ProtocolError::Budget(BudgetKind::Stdout));
    assert_eq!(frames, 16);
    // The refused frame's header was read, and not one byte of its body.
    assert_eq!(
        read.load(Ordering::SeqCst),
        16 * (HEADER_LEN + 64 * 1024) + HEADER_LEN
    );
}

#[tokio::test(start_paused = true)]
async fn one_execution_budget_spans_both_channels() {
    // 120 empty frames on the exec channel, then CancelAcks on the control channel
    // charged to the same execution: the 129th guest frame overall is refused.
    let (exec_host, exec_guest) = duplex(64 * 1024);
    let (control_host, control_guest) = duplex(64 * 1024);
    let (mut exec_reader, _) = host_reader(exec_host);
    let (mut control_reader, _) = host_reader(control_host);
    tokio::spawn(async move {
        let mut w = guest_writer(exec_guest);
        for _ in 0..120 {
            w.send(Id128([1; 16]), &Message::Stdout(Vec::new()), far())
                .await
                .unwrap();
        }
        std::future::pending::<()>().await;
    });
    tokio::spawn(async move {
        let mut w = guest_writer(control_guest);
        loop {
            let ack = Message::CancelAck(CancelAck {
                token: Id128([1; 16]),
                active: true,
            });
            if w.send(Id128([2; 16]), &ack, far()).await.is_err() {
                return;
            }
        }
    });
    let mut budget = ExecBudget::new(1024 * 1024, 1024 * 1024);
    for _ in 0..120 {
        exec_reader
            .read_frame(Due::By(far()), &mut budget)
            .await
            .unwrap()
            .unwrap();
    }
    let mut acks = 0;
    let error = loop {
        match control_reader.read_frame(Due::By(far()), &mut budget).await {
            Ok(Some(_)) => acks += 1,
            other => break other.unwrap_err(),
        }
    };
    assert_eq!(acks, 8);
    assert_eq!(error, ProtocolError::Budget(BudgetKind::Frames));
}

#[tokio::test(start_paused = true)]
async fn cumulative_wire_bytes_are_bounded_even_when_each_frame_is_valid() {
    // Small retained limits: every frame is within its kind's 64 KiB bound, but the
    // execution's control allowance runs out.
    let (host, guest) = duplex(256 * 1024);
    let (mut reader, _) = host_reader(host);
    tokio::spawn(async move {
        let mut w = guest_writer(guest);
        let filler = Message::Error(ErrorReply {
            code: ErrorCode::Internal,
            state: BrokerState::Faulted,
            message: WireText::new("e".repeat(2048)).unwrap(),
        });
        loop {
            if w.send(Id128([1; 16]), &filler, far()).await.is_err() {
                return;
            }
        }
    });
    let mut budget = ExecBudget::new(0, 0);
    let mut frames = 0u64;
    let error = loop {
        match reader.read_frame(Due::By(far()), &mut budget).await {
            Ok(Some(_)) => frames += 1,
            other => break other.unwrap_err(),
        }
    };
    assert!(matches!(
        error,
        ProtocolError::Budget(BudgetKind::Control | BudgetKind::WireBytes)
    ));
    assert!(budget.wire() <= budget.max_wire());
    assert!(frames < 128);
}

#[tokio::test(start_paused = true)]
async fn endless_unsolicited_control_replies_fail_at_once() {
    let mut rng = Rng::new(1);
    let h = hello(&mut rng, Channel::Control);
    let hello_id = Id128([3; 16]);
    let reply = hello_reply(&mut rng, h.challenge);
    let mut conn = HostConnection::new(hello_id, &h);
    let (host, guest) = duplex(64 * 1024);
    let (mut reader, _) = host_reader(host);
    tokio::spawn(async move {
        let mut w = guest_writer(guest);
        w.send(hello_id, &Message::HelloReply(Box::new(reply)), far())
            .await
            .unwrap();
        loop {
            let unsolicited = Message::ProbeReply(ProbeReply {
                boot_id: BootId::new("0f8e2c1a-1b2c-3d4e-5f60-718293a4b5c6").unwrap(),
                inner_id: InnerId::new("abcd").unwrap(),
                state: BrokerState::Idle,
                active: None,
            });
            if w.send(hello_id, &unsolicited, far()).await.is_err() {
                return;
            }
        }
    });
    let mut budget = ExchangeBudget::default();
    let first = reader
        .read_frame(Due::By(far()), &mut budget)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(conn.received(first), Ok(HostEvent::HelloReply(_))));
    let second = reader
        .read_frame(Due::By(far()), &mut budget)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        conn.received(second),
        Err(ProtocolError::UnexpectedKind { .. })
    ));
}

#[tokio::test(start_paused = true)]
async fn trailing_bytes_and_missing_eof_after_the_terminal_frame() {
    let (host, mut guest) = duplex(4096);
    let (mut reader, _) = host_reader(host);
    guest.write_all(b"x").await.unwrap();
    assert_eq!(
        reader.read_eof(Instant::now() + TWO).await,
        Err(ProtocolError::TrailingBytes)
    );
    let (host, _guest) = duplex(4096);
    let (mut reader, _) = host_reader(host);
    let start = Instant::now();
    assert_eq!(
        reader.read_eof(start + TWO).await,
        Err(ProtocolError::Timeout(Stage::Eof))
    );
    assert_eq!(start.elapsed(), TWO);
    let (host, guest) = duplex(4096);
    let (mut reader, _) = host_reader(host);
    drop(guest);
    assert_eq!(reader.read_eof(Instant::now() + TWO).await, Ok(()));
    // EOF in the middle of a frame is not clean.
    let (host, mut guest) = duplex(4096);
    let (mut reader, _) = host_reader(host);
    guest.write_all(&stdout_frame(0, 10)[..40]).await.unwrap();
    drop(guest);
    assert_eq!(
        reader
            .read_frame(Due::By(far()), &mut ExecBudget::new(64, 64))
            .await,
        Err(ProtocolError::PrematureEof {
            part: FramePart::Payload,
            got: 4,
            need: 10
        })
    );
}

#[tokio::test(start_paused = true)]
async fn a_blocked_output_writer_never_delays_the_control_channel() {
    // The guest's exec channel is full and unread; its independent control channel
    // still answers Cancel immediately.
    let (exec_guest, _exec_host_never_reads) = duplex(4096);
    let (control_guest, control_host) = duplex(4096);
    tokio::spawn(async move {
        let mut w = guest_writer(exec_guest);
        let _ = w
            .send(Id128([1; 16]), &Message::Stdout(vec![0; 64 * 1024]), far())
            .await;
    });
    tokio::task::yield_now().await;
    let start = Instant::now();
    let mut control = guest_writer(control_guest);
    control
        .send(
            Id128([2; 16]),
            &Message::CancelAck(CancelAck {
                token: Id128([1; 16]),
                active: true,
            }),
            start + TWO,
        )
        .await
        .unwrap();
    let (mut reader, _) = host_reader(control_host);
    let frame = reader
        .read_frame(Due::By(start + TWO), &mut ExchangeBudget::default())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(frame.kind(), Kind::CancelAck);
    assert_eq!(start.elapsed(), Duration::ZERO);
}

/// A full, healthy exec exchange from both ends, with three hostile connections
/// (no first byte, trickle, endless frames) running at the same time. Every hostile
/// one fails at its own bound; the healthy one finishes inside its deadlines.
#[tokio::test(start_paused = true)]
async fn a_healthy_exchange_meets_its_deadlines_beside_three_hostile_ones() {
    let mut hostile = Vec::new();
    {
        let (host, guest) = duplex(4096);
        hostile.push(tokio::spawn(async move {
            let _keep = guest;
            let (mut r, _) = host_reader(host);
            r.read_frame(Due::By(Instant::now() + TWO), &mut ExecBudget::new(1, 1))
                .await
        }));
        let (host, guest) = duplex(4096);
        tokio::spawn(trickle(
            guest,
            stdout_frame(0, 100),
            Duration::from_millis(50),
        ));
        hostile.push(tokio::spawn(async move {
            let (mut r, _) = host_reader(host);
            r.read_frame(
                Due::By(Instant::now() + TWO),
                &mut ExecBudget::new(1024, 1024),
            )
            .await
        }));
        let (host, guest) = duplex(64 * 1024);
        tokio::spawn(endless(guest, 0));
        hostile.push(tokio::spawn(async move {
            let (mut r, _) = host_reader(host);
            let mut budget = ExecBudget::new(1024, 1024);
            loop {
                match r.read_frame(Due::By(far()), &mut budget).await {
                    Ok(Some(_)) => {}
                    other => return other,
                }
            }
        }));
    }

    let mut rng = Rng::new(99);
    let h = hello(&mut rng, Channel::Exec);
    let hello_id = rng.id();
    let reply = hello_reply(&mut rng, h.challenge);
    let token = rng.id();
    let exec = Exec {
        token,
        execution_id: rng.execution_id(),
        argv: vec!["cat".into()],
        stdin_bytes: 5,
        max_output: 1024,
        remaining_ms: 30_000,
    };
    let (host_side, guest_side) = duplex(64 * 1024);
    let (host_read, host_write) = tokio::io::split(host_side);
    let (guest_read, guest_write) = tokio::io::split(guest_side);

    // The guest: answer Hello, accept, read stdin, run "for 5 s", report.
    let guest = tokio::spawn(async move {
        let mut r = FrameReader::new(guest_read, Direction::HostToGuest);
        let mut w = FrameWriter::new(guest_write, Direction::GuestToHost);
        let mut conn = kilnd_broker_protocol::exchange::GuestConnection::default();
        let mut budget = kilnd_broker_protocol::budget::HostBudget::default();
        let mut stdin = Vec::new();
        loop {
            let f = r
                .read_frame(Due::By(far()), &mut budget)
                .await
                .unwrap()
                .unwrap();
            let id = f.request_id();
            match conn.received(f).unwrap() {
                kilnd_broker_protocol::exchange::GuestEvent::Hello(_) => w
                    .send(id, &Message::HelloReply(Box::new(reply.clone())), far())
                    .await
                    .unwrap(),
                kilnd_broker_protocol::exchange::GuestEvent::Exec(e) => w
                    .send(id, &Message::Accepted(Accepted { token: e.token }), far())
                    .await
                    .unwrap(),
                kilnd_broker_protocol::exchange::GuestEvent::Stdin(b) => stdin.extend(b),
                kilnd_broker_protocol::exchange::GuestEvent::StdinEnd => break,
                other => panic!("{other:?}"),
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
        w.send(token, &Message::Stdout(stdin.clone()), far())
            .await
            .unwrap();
        let result = ExecResult {
            token,
            finish: Finish::Completed,
            termination: Some(Termination::Exited { code: 0 }),
            diagnostic: None,
            stdout: CaptureFacts {
                kept: 5,
                total: 5,
                total_known: true,
                truncated: false,
            },
            stderr: CaptureFacts {
                kept: 0,
                total: 0,
                total_known: true,
                truncated: false,
            },
            cleanup: Cleanup::GuestCgroupDrained,
            inner_id: InnerId::new("abcd").unwrap(),
        };
        w.send(token, &Message::Result(Box::new(result)), far())
            .await
            .unwrap();
        w.finish(far()).await.unwrap();
    });

    // The host, with the design's stage deadlines.
    let start = Instant::now();
    let mut r = FrameReader::new(host_read, Direction::GuestToHost);
    let mut w = FrameWriter::new(host_write, Direction::HostToGuest);
    let mut conn = HostConnection::new(hello_id, &h);
    let mut budget = ExecBudget::new(exec.max_output, exec.max_output);
    w.send(hello_id, &Message::Hello(h.clone()), start + TWO)
        .await
        .unwrap();
    let f = r
        .read_frame(Due::By(start + TWO), &mut budget)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(conn.received(f), Ok(HostEvent::HelloReply(_))));
    let sent = Instant::now();
    conn.sending(token, &Message::Exec(exec.clone())).unwrap();
    w.send(token, &Message::Exec(exec.clone()), sent + TWO)
        .await
        .unwrap();
    let f = r
        .read_frame(Due::By(sent + TWO), &mut budget)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(conn.received(f), Ok(HostEvent::Accepted));
    for m in [
        Message::Stdin(b"hello".to_vec()),
        Message::StdinEnd(StdinEnd { token, total: 5 }),
    ] {
        conn.sending_stdin(token, &m).unwrap();
        w.send(token, &m, sent + TWO).await.unwrap();
    }
    let exec_deadline = sent + Duration::from_millis(exec.remaining_ms);
    let first = r
        .read_frame(
            Due::FirstByte {
                first: exec_deadline,
                then: TWO,
            },
            &mut budget,
        )
        .await
        .unwrap()
        .unwrap();
    let settle_by = r.first_byte_at().unwrap() + TWO;
    assert_eq!(
        conn.received(first),
        Ok(HostEvent::Stdout(b"hello".to_vec()))
    );
    let f = r
        .read_frame(Due::By(settle_by), &mut budget)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(conn.received(f), Ok(HostEvent::Result(_))));
    r.read_eof(settle_by).await.unwrap();
    conn.eof().unwrap();
    guest.await.unwrap();
    assert_eq!(start.elapsed(), Duration::from_secs(5));

    let outcomes: Vec<_> = futures_join(hostile).await;
    assert_eq!(outcomes[0], Err(ProtocolError::Timeout(Stage::FirstByte)));
    assert_eq!(outcomes[1], Err(ProtocolError::Timeout(Stage::Frame)));
    assert_eq!(outcomes[2], Err(ProtocolError::Budget(BudgetKind::Frames)));
}

async fn futures_join(
    handles: Vec<tokio::task::JoinHandle<Result<Option<Frame>>>>,
) -> Vec<Result<Option<Frame>>> {
    let mut out = Vec::new();
    for handle in handles {
        out.push(handle.await.unwrap());
    }
    out
}

/// Daybreak B5 milestone 1 finding 3: a timed-out reader or writer is poisoned, so no
/// retry can complete a partial frame under a fresh deadline.
#[tokio::test(start_paused = true)]
async fn a_timed_out_stream_is_poisoned_for_every_later_call() {
    let (host, mut guest) = duplex(4096);
    let (mut reader, _) = host_reader(host);
    let frame = stdout_frame(0, 4);
    guest.write_all(&frame[..1]).await.unwrap();
    let start = Instant::now();
    assert_eq!(
        reader
            .read_frame(Due::By(start + TWO), &mut ExecBudget::new(64, 64))
            .await,
        Err(ProtocolError::Timeout(Stage::Frame))
    );
    // The rest of the frame arrives; a retry under a new deadline still fails.
    guest.write_all(&frame[1..]).await.unwrap();
    assert_eq!(
        reader
            .read_frame(Due::By(Instant::now() + TWO), &mut ExecBudget::new(64, 64))
            .await,
        Err(ProtocolError::Timeout(Stage::Frame))
    );
    assert_eq!(
        reader.read_eof(Instant::now() + TWO).await,
        Err(ProtocolError::Timeout(Stage::Frame))
    );
    // A writer whose write timed out is poisoned too.
    let (host, _never_reads) = duplex(1024);
    let mut writer = FrameWriter::new(host, Direction::HostToGuest);
    let big = Message::Stdin(vec![0; 8192]);
    assert_eq!(
        writer
            .send(Id128([1; 16]), &big, Instant::now() + TWO)
            .await,
        Err(ProtocolError::Timeout(Stage::Write))
    );
    assert_eq!(
        writer
            .send(
                Id128([1; 16]),
                &Message::Stdin(vec![1]),
                Instant::now() + TWO
            )
            .await,
        Err(ProtocolError::Timeout(Stage::Write))
    );
}

/// Daybreak B5 milestone 1 finding 1: the execution's budget is shared by its exec and
/// Cancel readers through a synchronous admission, so a stalled exec read never blocks
/// the control channel's CancelAck, and both still count against one budget.
#[tokio::test(start_paused = true)]
async fn a_stalled_exec_reader_never_blocks_cancel_admission_on_a_shared_budget() {
    use kilnd_broker_protocol::budget::SharedBudget;
    let budget = SharedBudget::new(ExecBudget::new(1024, 1024));
    // The exec channel: one byte, then nothing until its deadline.
    let (exec_host, mut exec_guest) = duplex(4096);
    exec_guest
        .write_all(&stdout_frame(0, 4)[..1])
        .await
        .unwrap();
    let mut exec_budget = budget.clone();
    let (mut exec_reader, _) = host_reader(exec_host);
    let local = tokio::task::LocalSet::new();
    let stalled = local.spawn_local(async move {
        exec_reader
            .read_frame(
                Due::By(Instant::now() + Duration::from_secs(60)),
                &mut exec_budget,
            )
            .await
    });
    local.run_until(tokio::task::yield_now()).await;
    // The control channel delivers a CancelAck at once.
    let (control_host, control_guest) = duplex(4096);
    let mut w = guest_writer(control_guest);
    let ack = Message::CancelAck(CancelAck {
        token: Id128([1; 16]),
        active: true,
    });
    w.send(Id128([2; 16]), &ack, far()).await.unwrap();
    let (mut control_reader, _) = host_reader(control_host);
    let mut control_budget = budget.clone();
    let start = Instant::now();
    let frame = control_reader
        .read_frame(Due::By(start + TWO), &mut control_budget)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(frame.kind(), Kind::CancelAck);
    assert_eq!(start.elapsed(), Duration::ZERO);
    assert_eq!(budget.with(|b| b.frames()), 1);
    drop(exec_guest);
    let _ = local.run_until(stalled).await;
}
