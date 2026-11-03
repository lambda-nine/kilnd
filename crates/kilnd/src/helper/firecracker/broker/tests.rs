//! The host relay's exchanges against a scripted guest over in-memory pipes, on a
//! paused clock: Firecracker's CONNECT handshake, identity and hardening checks,
//! readiness, probe, cancel and full executions, and the hostile cases R must end
//! within its bounds (endless output, trickled results, a silent guest). Also R's
//! descriptor passing and its whole job loop over real socket pairs.

use super::*;
use kilnd_broker_protocol::budget::HostBudget;
use kilnd_broker_protocol::exchange::{GuestConnection, GuestEvent};
use kilnd_broker_protocol::message::*;
use kilnd_broker_protocol::{ExecutionId, ProtocolError};
use tokio::io::{DuplexStream, duplex};

fn binding() -> SessionBinding {
    SessionBinding {
        instance_id: Id128([1; 16]),
        allocation_id: Id128([2; 16]),
        sandbox_id: kilnd_broker_protocol::SandboxId::new("sb-0123456789abcdef").unwrap(),
        boot_nonce: Hex32([3; 32]),
        manifest_sha256: Hex32([4; 32]),
        launch_sha256: Hex32([5; 32]),
        guest_exec_spec_sha256: Hex32([6; 32]),
    }
}

fn work_uuid() -> WorkUuid {
    WorkUuid::new("51b8e65e-23b9-4eba-a21c-7c1cce2c5f94").unwrap()
}

fn boot() -> BootId {
    BootId::new("0f8e2c1a-1b2c-3d4e-5f60-718293a4b5c6").unwrap()
}

fn inner() -> InnerId {
    InnerId::new("abcd-1").unwrap()
}

fn expected() -> Expected {
    Expected {
        binding: binding(),
        work_uuid: work_uuid(),
        broker_sha256: Hex32([7; 32]),
        boot_id: None,
        inner_id: None,
    }
}

fn identity() -> GuestIdentity {
    let b = binding();
    GuestIdentity {
        instance_id: b.instance_id,
        allocation_id: b.allocation_id,
        sandbox_id: b.sandbox_id,
        boot_nonce: b.boot_nonce,
        manifest_sha256: b.manifest_sha256,
        launch_sha256: b.launch_sha256,
        work_uuid: work_uuid(),
        guest_exec_spec_sha256: b.guest_exec_spec_sha256,
    }
}

fn reply(challenge: Hex32) -> HelloReply {
    HelloReply {
        protocol: 1,
        challenge,
        identity: identity(),
        boot_id: boot(),
        broker_sha256: Hex32([7; 32]),
        kiln: KilnFacts {
            protocol: 1,
            features: 0x1f,
        },
        hardening: kilnd_broker_protocol::identity::hardening_from_mask(0x7f),
        work: WorkMount {
            uuid: work_uuid(),
            nosuid: true,
            nodev: true,
            noexec: true,
            prjquota: true,
        },
        state: BrokerState::Idle,
        inner_id: Some(inner()),
    }
}

/// How the scripted guest behaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Honest,
    /// HelloReply with another allocation's identity.
    ForeignIdentity,
    /// HelloReply missing a hardening check.
    Unhardened,
    /// After Accepted, endless valid Stdout frames.
    EndlessOutput,
    /// The Result arrives a byte every 300 ms.
    TrickleResult,
    /// Accept, then never send output.
    Silent,
    /// The VMM answers CONNECT with garbage.
    BadConnect,
    /// HelloReply with a broker digest other than the pinned one (B5-10).
    WrongBroker,
    /// HelloReply without the required kiln features (B5-10).
    NoFeatures,
    /// An honest Hello, then Ready without the required kiln features (B5-10).
    ReadyNoFeatures,
}

/// Records what the guest saw, so tests can prove nothing was dispatched.
#[derive(Default, Debug)]
struct Seen {
    exec: bool,
}

async fn guest(stream: DuplexStream, mode: Mode, seen: std::rc::Rc<std::cell::RefCell<Seen>>) {
    let (mut read, mut write) = tokio::io::split(stream);
    let mut line = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        if read.read(&mut byte).await.unwrap_or(0) == 0 {
            return;
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    assert_eq!(line, CONNECT_REQUEST);
    let ok: &[u8] = if mode == Mode::BadConnect {
        b"NOPE\n"
    } else {
        b"OK 1073741824\n"
    };
    write.write_all(ok).await.unwrap();
    let far = Instant::now() + Duration::from_secs(7200);
    let mut reader = FrameReader::new(read, Direction::HostToGuest);
    let mut writer = FrameWriter::new(write, Direction::GuestToHost);
    let mut conn = GuestConnection::default();
    let mut budget = HostBudget::default();
    let mut next = async |reader: &mut FrameReader<_>, conn: &mut GuestConnection| {
        let frame = reader.read_frame(Due::By(far), &mut budget).await.ok()??;
        let id = frame.request_id();
        Some((id, conn.received(frame).ok()?))
    };
    let Some((hello_id, GuestEvent::Hello(hello))) = next(&mut reader, &mut conn).await else {
        return;
    };
    let mut r = reply(hello.challenge);
    match mode {
        Mode::ForeignIdentity => r.identity.allocation_id = Id128([0xee; 16]),
        Mode::Unhardened => r.hardening.kaslr = false,
        Mode::WrongBroker => r.broker_sha256 = Hex32([0xbb; 32]),
        Mode::NoFeatures => r.kiln.features = 0,
        _ => {}
    }
    writer
        .send(hello_id, &Message::HelloReply(Box::new(r)), far)
        .await
        .unwrap();
    let Some((id, event)) = next(&mut reader, &mut conn).await else {
        return;
    };
    match event {
        GuestEvent::Request(Message::Initialize(_)) => {
            let ready = Ready {
                binding: binding(),
                boot_id: boot(),
                inner_id: inner(),
                kiln: KilnFacts {
                    protocol: 1,
                    features: if mode == Mode::ReadyNoFeatures {
                        0
                    } else {
                        0x1f
                    },
                },
                idle: true,
                work_quota_verified: true,
            };
            writer
                .send(id, &Message::Ready(Box::new(ready)), far)
                .await
                .unwrap();
            writer.finish(far).await.unwrap();
        }
        GuestEvent::Request(Message::Probe(probe)) => {
            let reply = ProbeReply {
                boot_id: probe.boot_id,
                inner_id: probe.inner_id,
                state: BrokerState::Idle,
                active: None,
            };
            writer
                .send(id, &Message::ProbeReply(reply), far)
                .await
                .unwrap();
            writer.finish(far).await.unwrap();
        }
        GuestEvent::Request(Message::Cancel(cancel)) => {
            let ack = CancelAck {
                token: cancel.token,
                active: true,
            };
            writer
                .send(id, &Message::CancelAck(ack), far)
                .await
                .unwrap();
            writer.finish(far).await.unwrap();
        }
        GuestEvent::Exec(exec) => {
            seen.borrow_mut().exec = true;
            let token = exec.token;
            writer
                .send(token, &Message::Accepted(Accepted { token }), far)
                .await
                .unwrap();
            let mut stdin = Vec::new();
            loop {
                match next(&mut reader, &mut conn).await {
                    Some((_, GuestEvent::Stdin(bytes))) => stdin.extend(bytes),
                    Some((_, GuestEvent::StdinEnd)) => break,
                    _ => return,
                }
            }
            match mode {
                Mode::Silent => {
                    std::future::pending::<()>().await;
                }
                Mode::EndlessOutput => loop {
                    if writer
                        .send(token, &Message::Stdout(vec![b'x'; 1024]), far)
                        .await
                        .is_err()
                    {
                        return;
                    }
                },
                _ => {}
            }
            let kept = stdin.len().min(exec.max_output as usize);
            for chunk in stdin[..kept].chunks(kilnd_broker_protocol::MAX_DATA_PAYLOAD) {
                writer
                    .send(token, &Message::Stdout(chunk.to_vec()), far)
                    .await
                    .unwrap();
            }
            let result = ExecResult {
                token,
                finish: Finish::Completed,
                termination: Some(Termination::Exited { code: 0 }),
                diagnostic: None,
                stdout: CaptureFacts {
                    kept: kept as u64,
                    total: stdin.len() as u64,
                    total_known: true,
                    truncated: kept < stdin.len(),
                },
                stderr: CaptureFacts {
                    kept: 0,
                    total: 0,
                    total_known: true,
                    truncated: false,
                },
                cleanup: Cleanup::GuestCgroupDrained,
                inner_id: inner(),
            };
            if mode == Mode::TrickleResult {
                let payload = Message::Result(Box::new(result)).encode_payload().unwrap();
                let seq = 2 + kept.div_ceil(kilnd_broker_protocol::MAX_DATA_PAYLOAD) as u32;
                let frame = kilnd_broker_protocol::encode_frame(Kind::Result, token, seq, &payload)
                    .unwrap();
                let mut raw = writer.into_inner();
                for byte in frame {
                    if raw.write_all(&[byte]).await.is_err() {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
                return;
            }
            writer
                .send(token, &Message::Result(Box::new(result)), far)
                .await
                .unwrap();
            writer.finish(far).await.unwrap();
        }
        _ => {}
    }
}

use kilnd_broker_protocol::Kind;

async fn local<F: std::future::Future<Output = ()>>(f: F) {
    tokio::task::LocalSet::new().run_until(f).await;
}

fn spawn_guest(mode: Mode) -> (DuplexStream, std::rc::Rc<std::cell::RefCell<Seen>>) {
    let (host, g) = duplex(256 * 1024);
    let seen = std::rc::Rc::new(std::cell::RefCell::new(Seen::default()));
    let s = seen.clone();
    tokio::task::spawn_local(guest(g, mode, s));
    (host, seen)
}

fn spec() -> GuestExecSpec {
    GuestExecSpec {
        image: "alpine".into(),
        memory_bytes: 512 << 20,
        cpu_millis: 1000,
        pids: 128,
        disk_bytes: 1 << 30,
        network: "none".into(),
        read_only_root: false,
        writable_paths: vec![],
    }
}

use kilnd_broker_protocol::message::GuestExecSpec;

fn init() -> Initialize {
    let spec = spec();
    Initialize {
        guest_exec_spec_sha256: spec.sha256(),
        spec,
    }
}

fn soon(seconds: u64) -> Instant {
    Instant::now() + Duration::from_secs(seconds)
}

#[tokio::test(start_paused = true)]
async fn readiness_needs_the_journaled_identity_and_full_hardening() {
    local(async {
        let (host, _) = spawn_guest(Mode::Honest);
        match initialize(host, 1, &expected(), init(), soon(100)).await {
            RelayReport::Ready { ready, hello, .. } => {
                assert_eq!(ready.inner_id, inner());
                assert_eq!(hello.boot_id, boot());
            }
            other => panic!("{other:?}"),
        }
        for mode in [
            Mode::ForeignIdentity,
            Mode::Unhardened,
            Mode::WrongBroker,
            Mode::NoFeatures,
            Mode::ReadyNoFeatures,
        ] {
            let (host, _) = spawn_guest(mode);
            assert!(
                matches!(
                    initialize(host, 1, &expected(), init(), soon(100)).await,
                    RelayReport::Failed {
                        reach: Reach::Guest,
                        ..
                    }
                ),
                "{mode:?}"
            );
        }
        // No OK: nothing listens yet. Only readiness retries this.
        let (host, _) = spawn_guest(Mode::BadConnect);
        assert!(matches!(
            initialize(host, 1, &expected(), init(), soon(100)).await,
            RelayReport::Unreachable { .. }
        ));
        // Once READY, a different boot or inner sandbox is another guest.
        let mut later = expected();
        later.boot_id = Some(BootId::new("00000000-0000-4000-8000-000000000000").unwrap());
        let (host, _) = spawn_guest(Mode::Honest);
        let probe_request = Probe {
            boot_id: boot(),
            inner_id: inner(),
        };
        assert!(matches!(
            probe(host, 2, &later, probe_request, soon(5)).await,
            RelayReport::Failed { .. }
        ));
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn probe_and_cancel_on_their_own_connections() {
    local(async {
        let mut ready = expected();
        ready.boot_id = Some(boot());
        ready.inner_id = Some(inner());
        let (host, _) = spawn_guest(Mode::Honest);
        let request = Probe {
            boot_id: boot(),
            inner_id: inner(),
        };
        assert!(matches!(
            probe(host, 3, &ready, request, soon(5)).await,
            RelayReport::Probed { reply, .. } if reply.state == BrokerState::Idle
        ));
        let (host, _) = spawn_guest(Mode::Honest);
        let request = Cancel {
            token: Id128([9; 16]),
            reason: CancelReason::Timeout,
        };
        assert!(matches!(
            cancel(host, 4, &ready, request, soon(5), None).await,
            RelayReport::CancelAcked { ack, .. } if ack.active
        ));
    })
    .await;
}

fn exec_request(stdin: u64, max_output: u64) -> Exec {
    Exec {
        token: Id128([8; 16]),
        execution_id: ExecutionId::new("ex-0123456789abcdef").unwrap(),
        argv: vec!["cat".into()],
        stdin_bytes: stdin,
        max_output,
        remaining_ms: 1,
    }
}

/// Runs one exec job with kilnd's side of the stdio pairs in memory.
async fn run_exec(
    mode: Mode,
    stdin: &[u8],
    declared: u64,
    deadline: Instant,
) -> (RelayReport, Vec<u8>, bool, bool) {
    run_exec_into(mode, stdin, declared, deadline, 2 << 20).await
}

/// `run_exec` with kilnd's stdout socket holding at most `out_capacity` unread bytes.
async fn run_exec_into(
    mode: Mode,
    stdin: &[u8],
    declared: u64,
    deadline: Instant,
    out_capacity: usize,
) -> (RelayReport, Vec<u8>, bool, bool) {
    let (host, seen) = spawn_guest(mode);
    let (mut kilnd_in, relay_in) = duplex(2 << 20);
    let (relay_out, mut kilnd_out) = duplex(out_capacity);
    let (relay_err, _kilnd_err) = duplex(2 << 20);
    kilnd_in.write_all(stdin).await.unwrap();
    drop(kilnd_in);
    let accepted = std::cell::Cell::new(false);
    let report = exec(
        host,
        5,
        &expected(),
        exec_request(declared, 1 << 20),
        deadline,
        relay_in,
        relay_out,
        relay_err,
        kilnd_broker_protocol::budget::SharedBudget::new(ExecBudget::new(1 << 20, 1 << 20)),
        |_| accepted.set(true),
    )
    .await;
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_millis(10), kilnd_out.read_to_end(&mut out)).await;
    let exec_seen = seen.borrow().exec;
    (report, out, accepted.get(), exec_seen)
}

#[tokio::test(start_paused = true)]
async fn a_full_execution_delivers_its_output_after_a_validated_result() {
    local(async {
        let stdin: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        let (report, out, accepted, _) =
            run_exec(Mode::Honest, &stdin, stdin.len() as u64, soon(30)).await;
        match report {
            RelayReport::Executed {
                result, delivered, ..
            } => {
                assert!(delivered);
                assert_eq!(result.stdout.kept, 200_000);
            }
            other => panic!("{other:?}"),
        }
        assert!(accepted);
        assert_eq!(out, stdin);
    })
    .await;
}

/// B5-08: a caller's stdout that stops reading after a prefix gets that prefix, and
/// R reports exactly the bytes delivered, so H never copies the guest's full facts.
#[tokio::test(start_paused = true)]
async fn b5_08_a_partial_delivery_reports_the_bytes_delivered() {
    local(async {
        let stdin: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        let (report, out, _, _) =
            run_exec_into(Mode::Honest, &stdin, stdin.len() as u64, soon(30), 4096).await;
        match report {
            RelayReport::Executed {
                result,
                delivered,
                stdout_delivered,
                stderr_delivered,
                ..
            } => {
                assert!(!delivered);
                assert_eq!(result.stdout.kept, 200_000);
                assert_eq!(stdout_delivered, 4096);
                assert_eq!(stderr_delivered, 0);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(out, stdin[..4096]);
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn short_stdin_fails_before_any_exec_byte() {
    local(async {
        let (report, _, accepted, exec_seen) = run_exec(Mode::Honest, b"abc", 10, soon(30)).await;
        assert!(matches!(
            report,
            RelayReport::Failed {
                reach: Reach::Local,
                ..
            }
        ));
        assert!(!accepted && !exec_seen);
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn a_silent_guest_holds_the_job_only_until_the_execution_deadline() {
    local(async {
        let start = Instant::now();
        let (report, _, accepted, _) = run_exec(Mode::Silent, b"", 0, soon(30)).await;
        assert!(accepted);
        assert!(matches!(report, RelayReport::Failed { reach: Reach::Dispatched, ref reason, .. } if reason.contains("FirstByte")));
        assert_eq!(start.elapsed(), Duration::from_secs(30));
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn endless_output_is_refused_at_the_negotiated_limit() {
    local(async {
        let start = Instant::now();
        let (report, out, _, _) = run_exec(Mode::EndlessOutput, b"", 0, soon(30)).await;
        assert!(
            matches!(
                report,
                RelayReport::Failed {
                    reach: Reach::Dispatched,
                    ..
                }
            ),
            "{report:?}"
        );
        // Nothing reached kilnd: output is forwarded only after a validated Result.
        assert!(out.is_empty());
        assert!(start.elapsed() < Duration::from_secs(1));
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn a_trickled_result_must_settle_within_two_seconds_of_its_start() {
    local(async {
        let start = Instant::now();
        let (report, _, _, _) = run_exec(Mode::TrickleResult, b"", 0, soon(600)).await;
        assert!(
            matches!(
                report,
                RelayReport::Failed {
                    reach: Reach::Dispatched,
                    ..
                }
            ),
            "{report:?}"
        );
        assert!(
            start.elapsed() <= Duration::from_secs(3),
            "{:?}",
            start.elapsed()
        );
    })
    .await;
}

#[test]
fn remaining_budget_rounds_down_and_never_dispatches_zero() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap();
    rt.block_on(async {
        assert_eq!(remaining_ms(Instant::now()), None);
        assert_eq!(
            remaining_ms(Instant::now() + Duration::from_micros(999)),
            None
        );
        assert_eq!(remaining_ms(soon(7200)), Some(MAX_REMAINING_MS));
        assert_eq!(
            remaining_ms(Instant::now() + Duration::from_millis(1500)),
            Some(1500)
        );
    });
}

#[tokio::test(start_paused = true)]
async fn connect_replies_are_bounded_and_exact() {
    for (reply, ok) in [
        (&b"OK 5252\n"[..], true),
        (b"OK 4294967295\n", true),
        (b"OK \n", false),
        (b"OK 12a\n", false),
        (b"ok 1\n", false),
        (b"OK 99999999999\n", false),
        (&[b'O'; 40][..], false),
    ] {
        let (mut host, mut vmm) = duplex(1024);
        vmm.write_all(reply).await.unwrap();
        let result = connect_port(&mut host, soon(2)).await;
        assert_eq!(result.is_ok(), ok, "{:?}", String::from_utf8_lossy(reply));
    }
    // A VMM that never answers is bounded by the stage deadline.
    let (mut host, _vmm) = duplex(1024);
    let start = Instant::now();
    assert!(
        connect_port(&mut host, start + STAGE_TIMEOUT)
            .await
            .is_err()
    );
    assert_eq!(start.elapsed(), STAGE_TIMEOUT);
    let _ = ProtocolError::TrailingBytes;
}

#[cfg(unix)]
#[test]
fn descriptors_cross_with_their_job_tag() {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixDatagram;
    let (a, b) = UnixDatagram::pair().unwrap();
    b.set_nonblocking(true).unwrap();
    let (x, _y) = std::os::unix::net::UnixStream::pair().unwrap();
    assert!(relay::recv_fds(b.as_raw_fd()).unwrap().is_none());
    relay::send_fds(&a, 42, &[x.as_raw_fd(), x.as_raw_fd()]).unwrap();
    let (tag, fds) = relay::recv_fds(b.as_raw_fd()).unwrap().unwrap();
    assert_eq!(tag, 42);
    assert_eq!(fds.len(), 2);
}

/// R's whole job loop on a thread, over real socket pairs, as S drives it.
#[cfg(unix)]
#[test]
fn the_relay_loop_runs_a_probe_job_and_reports_it() {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::{UnixDatagram, UnixStream as StdUnixStream};
    let (control_s, control_r) = StdUnixStream::pair().unwrap();
    let (fds_s, fds_r) = UnixDatagram::pair().unwrap();
    let relay = std::thread::spawn(move || relay::relay_main(control_r, fds_r));
    // The "VM side" of the vsock connection runs the scripted guest on its own thread.
    let (vsock_relay, vsock_guest) = StdUnixStream::pair().unwrap();
    let guest_thread = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        tokio::task::LocalSet::new().block_on(&rt, async move {
            vsock_guest.set_nonblocking(true).unwrap();
            let stream = tokio::net::UnixStream::from_std(vsock_guest).unwrap();
            let (g, mut bridge) = duplex(64 * 1024);
            let (mut r, mut w) = tokio::io::split(stream);
            let (mut br, mut bw) = tokio::io::split(&mut bridge);
            let seen = std::rc::Rc::new(std::cell::RefCell::new(Seen::default()));
            tokio::join!(guest(g, Mode::Honest, seen), async {
                let _ = tokio::join!(
                    async {
                        let _ = tokio::io::copy(&mut r, &mut bw).await;
                        let _ = bw.shutdown().await;
                    },
                    async {
                        let _ = tokio::io::copy(&mut br, &mut w).await;
                        let _ = w.shutdown().await;
                    }
                );
            });
        });
    });
    let mut control = super::super::workers::Endpoint::new(control_s);
    let mut ready = expected();
    ready.boot_id = Some(boot());
    ready.inner_id = Some(inner());
    let job = RelayJob::Probe {
        job: 77,
        expected: ready,
        probe: Probe {
            boot_id: boot(),
            inner_id: inner(),
        },
        deadline_ns: super::super::workers::monotonic_ns() + 5_000_000_000,
    };
    relay::send_fds(&fds_s, 77, &[vsock_relay.as_raw_fd()]).unwrap();
    drop(vsock_relay);
    control.send(0, &job, Duration::from_secs(1)).unwrap();
    let report = loop {
        match control
            .receive::<RelayReport>(Duration::from_secs(5))
            .unwrap()
        {
            super::super::workers::Received::Message { body, .. } => break body,
            super::super::workers::Received::Idle => continue,
            super::super::workers::Received::Closed => panic!("relay closed"),
        }
    };
    assert!(
        matches!(report, RelayReport::Probed { job: 77, ref reply } if reply.state == BrokerState::Idle),
        "{report:?}"
    );
    drop(control);
    relay.join().unwrap();
    let _ = guest_thread.join();
}

/// An endless guest: every read is filled completely, at once.
struct Endless;

impl AsyncRead for Endless {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let n = buf.remaining();
        buf.put_slice(&vec![b'x'; n]);
        std::task::Poll::Ready(Ok(()))
    }
}

/// Section 5.6: R reads a line-rate guest at most 4 MiB/s after its 256 KiB burst, in
/// reads of at most 64 KiB, on the paused clock.
#[tokio::test(start_paused = true)]
async fn guest_reads_are_paced_to_four_mib_per_second_after_the_burst() {
    let mut paced = Paced::new(Endless);
    let mut chunk = vec![0u8; 1024 * 1024];
    let began = Instant::now();
    let mut total = 0usize;
    let mut largest = 0usize;
    while total < 4 * 1024 * 1024 + READ_BURST as usize {
        let n = paced.read(&mut chunk).await.unwrap();
        assert!(n > 0);
        largest = largest.max(n);
        total += n;
    }
    assert_eq!(largest, READ_QUANTUM);
    let took = began.elapsed();
    // 4 MiB beyond the burst takes one second; never sooner, and the sleeps round
    // only to whole quanta.
    assert!(took >= Duration::from_secs(1), "{took:?}");
    assert!(took <= Duration::from_millis(1020), "{took:?}");
    // An idle second refills only the burst, never more.
    tokio::time::sleep(Duration::from_secs(10)).await;
    let began = Instant::now();
    let mut burst = 0usize;
    while burst < READ_BURST as usize {
        burst += paced.read(&mut chunk).await.unwrap();
    }
    assert_eq!(burst, READ_BURST as usize);
    assert_eq!(began.elapsed(), Duration::ZERO);
}
