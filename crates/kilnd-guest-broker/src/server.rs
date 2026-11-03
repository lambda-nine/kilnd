//! One broker connection (design 5.2, 5.3, 5.6): `Hello` within two seconds of accept,
//! then exactly one operation. A control connection carries one `Initialize`, `Probe`
//! or `Cancel`; an exec connection one execution: `Exec`, `Accepted`, the declared
//! stdin, the command, then contiguous `Stdout`, `Stderr`, `Result` and EOF, all
//! settled within two seconds once output starts. Every read and write has an absolute
//! deadline; a stalled or hostile peer ends its own connection, never the broker's
//! state machine, and an exec connection that fails mid-way faults the session.
//!
//! At most one exec and one control connection are open at a time (the accept loop
//! caps the total at two), and they never share a writer, so a blocked output writer
//! cannot delay `Cancel`.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

use kilnd_broker_protocol::budget::HostBudget;
use kilnd_broker_protocol::exchange::{GuestConnection, GuestEvent};
use kilnd_broker_protocol::message::{
    Accepted, BrokerState, Channel, ErrorCode, ErrorReply, Exec, Message,
};
use kilnd_broker_protocol::stream::{Due, FrameReader, FrameWriter};
use kilnd_broker_protocol::{
    Direction, Id128, MAX_DATA_PAYLOAD, ProtocolError, Result, STAGE_TIMEOUT,
};
use kilnd_exec_core::model::SandboxDisposition;
use kilnd_exec_core::runtime::ExecSpec;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;

use crate::kiln::{KilnOps, result_of};
use crate::session::{InitStep, Session, error};

/// State every connection of this boot shares.
pub struct Shared<K> {
    pub session: RefCell<Session>,
    pub kiln: K,
    exec_open: Cell<bool>,
    control_open: Cell<bool>,
}

impl<K: KilnOps> Shared<K> {
    pub fn new(session: Session, kiln: K) -> Self {
        Self {
            session: RefCell::new(session),
            kiln,
            exec_open: Cell::new(false),
            control_open: Cell::new(false),
        }
    }
}

/// Clears a channel's slot when its connection ends, however it ends.
struct Slot<'a>(&'a Cell<bool>);
impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

fn stage() -> Instant {
    Instant::now() + STAGE_TIMEOUT
}

struct Conn<R, W> {
    reader: FrameReader<R>,
    writer: FrameWriter<W>,
    conn: GuestConnection,
    budget: HostBudget,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> Conn<R, W> {
    async fn next(&mut self, due: Due) -> Result<(Id128, GuestEvent)> {
        let frame = self
            .reader
            .read_frame(due, &mut self.budget)
            .await?
            .ok_or(ProtocolError::EofBeforeTerminal)?;
        let id = frame.request_id();
        Ok((id, self.conn.received(frame)?))
    }

    /// The last frame of an exchange, then a clean write EOF.
    async fn last(&mut self, id: Id128, message: &Message, by: Instant) -> Result<()> {
        self.writer.send(id, message, by).await?;
        self.writer.finish(by).await
    }

    async fn refuse(&mut self, id: Id128, reply: ErrorReply) -> Result<()> {
        self.last(id, &Message::Error(reply), stage()).await
    }
}

/// Serves one accepted connection. `accepted` starts the Hello stage: the timer runs
/// from accept, before the first byte.
pub async fn serve<S, K>(shared: Rc<Shared<K>>, stream: S, accepted: Instant) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    K: KilnOps,
{
    let (read, write) = tokio::io::split(stream);
    let mut c = Conn {
        reader: FrameReader::new(read, Direction::HostToGuest),
        writer: FrameWriter::new(write, Direction::GuestToHost),
        conn: GuestConnection::default(),
        budget: HostBudget::default(),
    };
    let (hello_id, event) = c.next(Due::By(accepted + STAGE_TIMEOUT)).await?;
    let GuestEvent::Hello(hello) = event else {
        return Err(ProtocolError::EofBeforeTerminal);
    };
    let reply = shared.session.borrow().hello(&hello);
    let reply = match reply {
        Ok(reply) => reply,
        Err(refusal) => return c.refuse(hello_id, refusal).await,
    };
    let slot = match hello.channel {
        Channel::Exec => &shared.exec_open,
        Channel::Control => &shared.control_open,
    };
    if slot.replace(true) {
        let state = shared.session.borrow().state();
        return c
            .refuse(
                hello_id,
                error(ErrorCode::Admission, state, "that channel is already open"),
            )
            .await;
    }
    let _slot = Slot(slot);
    c.writer
        .send(hello_id, &Message::HelloReply(Box::new(reply)), stage())
        .await?;
    match hello.channel {
        Channel::Control => control(&shared, &mut c).await,
        Channel::Exec => exec(&shared, &mut c).await,
    }
}

async fn control<K, R, W>(shared: &Shared<K>, c: &mut Conn<R, W>) -> Result<()>
where
    K: KilnOps,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (id, event) = c.next(Due::By(stage())).await?;
    let GuestEvent::Request(request) = event else {
        return Err(ProtocolError::EofBeforeTerminal);
    };
    let reply = match request {
        Message::Initialize(init) => {
            let step = shared.session.borrow_mut().begin_initialize(&init);
            match step {
                InitStep::Start => {
                    let result = shared.kiln.initialize(&init.spec).await;
                    match shared.session.borrow_mut().finish_initialize(result) {
                        Ok(ready) => Message::Ready(Box::new(ready)),
                        Err(refusal) => Message::Error(refusal),
                    }
                }
                InitStep::Replay(ready) => Message::Ready(ready),
                InitStep::Refuse(refusal) => Message::Error(refusal),
            }
        }
        Message::Probe(probe) => {
            let checked = shared.session.borrow().probe(&probe);
            match checked {
                // B5-04: idle is claimed only for a persistent sandbox that is alive.
                // A dead one faults the session for good, and the reply says so.
                Ok(reply) if reply.state == BrokerState::Idle => {
                    if let Err(reason) = shared.kiln.alive(&reply.inner_id).await {
                        eprintln!("kilnd-guest-broker: {reason}");
                        shared.session.borrow_mut().fault();
                    }
                    let now = shared.session.borrow().probe(&probe);
                    match now {
                        Ok(reply) => Message::ProbeReply(reply),
                        Err(refusal) => Message::Error(refusal),
                    }
                }
                Ok(reply) => Message::ProbeReply(reply),
                Err(refusal) => Message::Error(refusal),
            }
        }
        Message::Cancel(cancel) => {
            Message::CancelAck(shared.session.borrow_mut().cancel(cancel.token))
        }
        other => {
            // The exchange layer admits only the three requests.
            return Err(ProtocolError::UnexpectedKind {
                kind: other.kind(),
                state: "on a control channel",
            });
        }
    };
    c.last(id, &reply, stage()).await
}

async fn exec<K, R, W>(shared: &Shared<K>, c: &mut Conn<R, W>) -> Result<()>
where
    K: KilnOps,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (token, event) = c.next(Due::By(stage())).await?;
    let GuestEvent::Exec(request) = event else {
        return Err(ProtocolError::EofBeforeTerminal);
    };
    let admitted = shared.session.borrow_mut().begin_exec(token);
    let cancel = match admitted {
        Ok(cancel) => cancel,
        Err(refusal) => return c.refuse(token, refusal).await,
    };
    // From here on, anything but a delivered result faults the session.
    let outcome = run(shared, c, token, &request, &cancel).await;
    if outcome.is_err() {
        shared.session.borrow_mut().fault();
    }
    outcome
}

async fn run<K, R, W>(
    shared: &Shared<K>,
    c: &mut Conn<R, W>,
    token: Id128,
    request: &Exec,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<()>
where
    K: KilnOps,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let accepted = Instant::now();
    // The guest's own deadline starts at acceptance; the host's is authoritative.
    let deadline = accepted + Duration::from_millis(request.remaining_ms);
    c.writer
        .send(token, &Message::Accepted(Accepted { token }), stage())
        .await?;
    // All stdin within two seconds of acceptance or the remaining budget.
    let stdin_by = (accepted + STAGE_TIMEOUT).min(deadline);
    let mut stdin = Vec::new();
    loop {
        match c.next(Due::By(stdin_by)).await? {
            (_, GuestEvent::Stdin(bytes)) => stdin.extend_from_slice(&bytes),
            (_, GuestEvent::StdinEnd) => break,
            (_, _) => return Err(ProtocolError::EofBeforeTerminal),
        }
    }
    let inner = shared
        .session
        .borrow()
        .inner()
        .cloned()
        .ok_or(ProtocolError::InvalidField("no inner sandbox"))?;
    let outcome = shared
        .kiln
        .exec(
            &inner,
            ExecSpec {
                argv: &request.argv,
                stdin: &stdin,
                deadline,
                max_output: request.max_output as usize,
            },
            cancel,
        )
        .await;
    drop(stdin);
    shared.session.borrow_mut().draining(token);
    let result = result_of(token, &inner, &outcome);
    let reusable = outcome.disposition == SandboxDisposition::Reusable
        && result.cleanup != kilnd_broker_protocol::message::Cleanup::Unknown;
    // The whole transfer settles within two seconds of its start.
    let by = stage();
    for chunk in outcome.stdout.data.chunks(MAX_DATA_PAYLOAD) {
        c.writer
            .send(token, &Message::Stdout(chunk.to_vec()), by)
            .await?;
    }
    for chunk in outcome.stderr.data.chunks(MAX_DATA_PAYLOAD) {
        c.writer
            .send(token, &Message::Stderr(chunk.to_vec()), by)
            .await?;
    }
    c.last(token, &Message::Result(Box::new(result)), by)
        .await?;
    shared.session.borrow_mut().settle(token, reusable);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kiln::BoxFuture;
    use crate::session::tests::{facts, kiln, spec};
    use kilnd_broker_protocol::budget::ExecBudget;
    use kilnd_broker_protocol::exchange::{HostConnection, HostEvent};
    use kilnd_broker_protocol::message::*;
    use kilnd_broker_protocol::{Hex32, InnerId, Stage};
    use kilnd_exec_core::model::{Captured, CleanupEvidence, CommandStatus};
    use kilnd_exec_core::runtime::{ExecFinish, ExecOutcome};
    use tokio::io::{DuplexStream, duplex};
    use tokio_util::sync::CancellationToken;

    /// Echoes stdin to stdout; `sleep` argv waits for cancellation or the deadline.
    /// `inner_dead` models guest root killing the persistent sandbox (B5-04).
    #[derive(Default)]
    struct FakeKiln {
        inner_dead: std::cell::Cell<bool>,
    }

    impl KilnOps for FakeKiln {
        fn initialize<'a>(
            &'a self,
            _spec: &'a GuestExecSpec,
        ) -> BoxFuture<'a, std::result::Result<(InnerId, KilnFacts), String>> {
            Box::pin(async { Ok((InnerId::new("abcd").unwrap(), kiln())) })
        }

        fn exec<'a>(
            &'a self,
            _inner: &'a InnerId,
            spec: ExecSpec<'a>,
            cancel: &'a CancellationToken,
        ) -> BoxFuture<'a, kilnd_exec_core::runtime::ExecOutcome> {
            Box::pin(async move {
                let mut finish = Ok(ExecFinish::Completed);
                if spec.argv[0] == "sleep" {
                    tokio::select! {
                        _ = cancel.cancelled() => finish = Ok(ExecFinish::Canceled),
                        _ = tokio::time::sleep_until(spec.deadline) => finish = Ok(ExecFinish::TimedOut),
                    }
                }
                let keep = spec.stdin.len().min(spec.max_output);
                ExecOutcome {
                    finish,
                    command_status: Some(CommandStatus::Exited(0)),
                    stdout: Captured {
                        data: spec.stdin[..keep].to_vec(),
                        total_bytes: spec.stdin.len() as u64,
                        truncated: keep < spec.stdin.len(),
                        total_bytes_known: true,
                    },
                    stderr: Captured::known_empty(),
                    disposition: SandboxDisposition::Reusable,
                    cleanup: CleanupEvidence::RuntimeDrained,
                }
            })
        }

        fn alive<'a>(
            &'a self,
            _inner: &'a InnerId,
        ) -> BoxFuture<'a, std::result::Result<(), String>> {
            Box::pin(async move { self.check() })
        }
    }

    impl FakeKiln {
        fn check(&self) -> std::result::Result<(), String> {
            if self.inner_dead.get() {
                Err("init is gone".into())
            } else {
                Ok(())
            }
        }
    }

    fn shared() -> Rc<Shared<FakeKiln>> {
        Rc::new(Shared::new(Session::new(facts()), FakeKiln::default()))
    }

    struct Host {
        reader: FrameReader<tokio::io::ReadHalf<DuplexStream>>,
        writer: FrameWriter<tokio::io::WriteHalf<DuplexStream>>,
        conn: HostConnection,
        budget: ExecBudget,
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(3600)
    }

    /// Connects a host to a new broker connection and completes the Hello exchange.
    async fn connect(shared: &Rc<Shared<FakeKiln>>, channel: Channel) -> Host {
        let (host, guest) = duplex(256 * 1024);
        let s = shared.clone();
        tokio::task::spawn_local(async move {
            let _ = serve(s, guest, Instant::now()).await;
        });
        let (r, w) = tokio::io::split(host);
        let hello = Hello {
            protocol: 1,
            channel,
            challenge: Hex32([8; 32]),
            expected: facts().identity.binding(),
        };
        let hello_id = Id128([9; 16]);
        let mut h = Host {
            reader: FrameReader::new(r, Direction::GuestToHost),
            writer: FrameWriter::new(w, Direction::HostToGuest),
            conn: HostConnection::new(hello_id, &hello),
            budget: ExecBudget::new(1 << 20, 1 << 20),
        };
        h.writer
            .send(hello_id, &Message::Hello(hello), far())
            .await
            .unwrap();
        let f = h.read().await.unwrap();
        assert!(matches!(f, HostEvent::HelloReply(_)), "{f:?}");
        h
    }

    impl Host {
        async fn read(&mut self) -> Result<HostEvent> {
            let frame = self
                .reader
                .read_frame(Due::By(far()), &mut self.budget)
                .await?
                .ok_or(ProtocolError::EofBeforeTerminal)?;
            self.conn.received(frame)
        }

        async fn request(&mut self, id: Id128, message: Message) -> HostEvent {
            self.conn.sending(id, &message).unwrap();
            self.writer.send(id, &message, far()).await.unwrap();
            let event = self.read().await.unwrap();
            self.reader.read_eof(far()).await.unwrap();
            event
        }
    }

    fn init() -> Message {
        let spec = spec();
        Message::Initialize(Initialize {
            guest_exec_spec_sha256: spec.sha256(),
            spec,
        })
    }

    fn exec_msg(token: Id128, argv: &str, stdin: u64) -> Exec {
        Exec {
            token,
            execution_id: kilnd_broker_protocol::ExecutionId::new("ex-0123456789abcdef").unwrap(),
            argv: vec![argv.into()],
            stdin_bytes: stdin,
            max_output: 1 << 20,
            remaining_ms: 10_000,
        }
    }

    async fn initialized() -> Rc<Shared<FakeKiln>> {
        let s = shared();
        let mut h = connect(&s, Channel::Control).await;
        match h.request(Id128([1; 16]), init()).await {
            HostEvent::Reply(Message::Ready(ready)) => {
                assert_eq!(ready.inner_id.as_str(), "abcd");
                assert!(ready.idle);
            }
            other => panic!("{other:?}"),
        }
        s
    }

    async fn run_local<F: std::future::Future<Output = ()>>(f: F) {
        tokio::task::LocalSet::new().run_until(f).await;
    }

    #[tokio::test(start_paused = true)]
    async fn initialize_then_probe_then_replay() {
        run_local(async {
            let s = initialized().await;
            let mut h = connect(&s, Channel::Control).await;
            let probe = Message::Probe(Probe {
                boot_id: facts().boot_id,
                inner_id: InnerId::new("abcd").unwrap(),
            });
            match h.request(Id128([2; 16]), probe).await {
                HostEvent::Reply(Message::ProbeReply(reply)) => {
                    assert_eq!(reply.state, BrokerState::Idle)
                }
                other => panic!("{other:?}"),
            }
            let mut h = connect(&s, Channel::Control).await;
            assert!(matches!(
                h.request(Id128([3; 16]), init()).await,
                HostEvent::Reply(Message::Ready(_))
            ));
        })
        .await;
    }

    /// B5-04: once guest root kills the persistent sandbox, Probe answers Faulted, not
    /// Idle, and the session never admits another Exec.
    #[tokio::test(start_paused = true)]
    async fn b5_04_probe_reports_a_dead_inner_sandbox_as_faulted() {
        run_local(async {
            let s = initialized().await;
            s.kiln.inner_dead.set(true);
            let probe = || {
                Message::Probe(Probe {
                    boot_id: facts().boot_id,
                    inner_id: InnerId::new("abcd").unwrap(),
                })
            };
            let mut h = connect(&s, Channel::Control).await;
            match h.request(Id128([2; 16]), probe()).await {
                HostEvent::Reply(Message::ProbeReply(reply)) => {
                    assert_eq!(reply.state, BrokerState::Faulted)
                }
                other => panic!("{other:?}"),
            }
            // Faulted is terminal: even a healthy check later cannot make it Idle.
            s.kiln.inner_dead.set(false);
            let mut h = connect(&s, Channel::Control).await;
            match h.request(Id128([3; 16]), probe()).await {
                HostEvent::Reply(Message::ProbeReply(reply)) => {
                    assert_eq!(reply.state, BrokerState::Faulted)
                }
                other => panic!("{other:?}"),
            }
            assert_eq!(s.session.borrow().state(), BrokerState::Faulted);
        })
        .await;
    }

    async fn full_exec(s: &Rc<Shared<FakeKiln>>, token: Id128, stdin: &[u8]) -> ExecResult {
        let mut h = connect(s, Channel::Exec).await;
        let exec = exec_msg(token, "cat", stdin.len() as u64);
        h.conn.sending(token, &Message::Exec(exec.clone())).unwrap();
        h.writer
            .send(token, &Message::Exec(exec), far())
            .await
            .unwrap();
        assert_eq!(h.read().await.unwrap(), HostEvent::Accepted);
        for chunk in stdin.chunks(MAX_DATA_PAYLOAD) {
            let m = Message::Stdin(chunk.to_vec());
            h.conn.sending_stdin(token, &m).unwrap();
            h.writer.send(token, &m, far()).await.unwrap();
        }
        let end = Message::StdinEnd(StdinEnd {
            token,
            total: stdin.len() as u64,
        });
        h.conn.sending_stdin(token, &end).unwrap();
        h.writer.send(token, &end, far()).await.unwrap();
        let mut out = Vec::new();
        loop {
            match h.read().await.unwrap() {
                HostEvent::Stdout(bytes) => out.extend(bytes),
                HostEvent::Result(result) => {
                    h.reader.read_eof(far()).await.unwrap();
                    assert_eq!(out, stdin);
                    return *result;
                }
                other => panic!("{other:?}"),
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_execution_streams_its_prefix_and_returns_to_idle() {
        run_local(async {
            let s = initialized().await;
            let stdin: Vec<u8> = (0..300_000u32).map(|i| i as u8).collect();
            let result = full_exec(&s, Id128([5; 16]), &stdin).await;
            assert_eq!(result.finish, Finish::Completed);
            assert_eq!(result.stdout.kept, 300_000);
            assert_eq!(result.cleanup, Cleanup::GuestCgroupDrained);
            assert_eq!(s.session.borrow().state(), BrokerState::Idle);
            // The sandbox is reusable: a second execution runs.
            full_exec(&s, Id128([6; 16]), b"again").await;
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn exec_before_initialize_is_refused() {
        run_local(async {
            let s = shared();
            let mut h = connect(&s, Channel::Exec).await;
            let token = Id128([5; 16]);
            let exec = exec_msg(token, "cat", 0);
            h.conn.sending(token, &Message::Exec(exec.clone())).unwrap();
            h.writer.send(token, &Message::Exec(exec), far()).await.unwrap();
            assert!(matches!(h.read().await.unwrap(), HostEvent::Error(e) if e.code == ErrorCode::Admission));
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn cancel_on_the_control_channel_reaches_only_the_active_token() {
        run_local(async {
            let s = initialized().await;
            let token = Id128([5; 16]);
            let mut h = connect(&s, Channel::Exec).await;
            let exec = exec_msg(token, "sleep", 0);
            h.conn.sending(token, &Message::Exec(exec.clone())).unwrap();
            h.writer
                .send(token, &Message::Exec(exec), far())
                .await
                .unwrap();
            assert_eq!(h.read().await.unwrap(), HostEvent::Accepted);
            let end = Message::StdinEnd(StdinEnd { token, total: 0 });
            h.conn.sending_stdin(token, &end).unwrap();
            h.writer.send(token, &end, far()).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(s.session.borrow().state(), BrokerState::Executing);
            // A foreign token is not canceled.
            let mut c = connect(&s, Channel::Control).await;
            let other = Message::Cancel(Cancel {
                token: Id128([6; 16]),
                reason: CancelReason::Timeout,
            });
            assert!(matches!(
                c.request(Id128([7; 16]), other).await,
                HostEvent::Reply(Message::CancelAck(CancelAck { active: false, .. }))
            ));
            let mut c = connect(&s, Channel::Control).await;
            let mine = Message::Cancel(Cancel {
                token,
                reason: CancelReason::Timeout,
            });
            assert!(matches!(
                c.request(Id128([8; 16]), mine).await,
                HostEvent::Reply(Message::CancelAck(CancelAck { active: true, .. }))
            ));
            match h.read().await.unwrap() {
                HostEvent::Result(result) => assert_eq!(result.finish, Finish::Canceled),
                other => panic!("{other:?}"),
            }
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_foreign_identity_is_refused_and_closed() {
        run_local(async {
            let s = shared();
            let (host, guest) = duplex(4096);
            let s2 = s.clone();
            tokio::task::spawn_local(async move {
                let _ = serve(s2, guest, Instant::now()).await;
            });
            let (r, w) = tokio::io::split(host);
            let mut writer = FrameWriter::new(w, Direction::HostToGuest);
            let mut reader = FrameReader::new(r, Direction::GuestToHost);
            let mut expected = facts().identity.binding();
            expected.allocation_id = Id128([0xee; 16]);
            let hello = Hello {
                protocol: 1,
                channel: Channel::Control,
                challenge: Hex32([1; 32]),
                expected,
            };
            writer
                .send(Id128([1; 16]), &Message::Hello(hello), far())
                .await
                .unwrap();
            let f = reader
                .read_frame(Due::By(far()), &mut ExecBudget::new(0, 0))
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(f.message().unwrap(), Message::Error(e) if e.code == ErrorCode::Incompatible));
            reader.read_eof(far()).await.unwrap();
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_or_stalling_host_ends_its_own_connection_on_time() {
        run_local(async {
            let s = initialized().await;
            // No Hello at all.
            let (_host, guest) = duplex(4096);
            let start = Instant::now();
            assert_eq!(
                serve(s.clone(), guest, start).await,
                Err(ProtocolError::Timeout(Stage::FirstByte))
            );
            assert_eq!(start.elapsed(), STAGE_TIMEOUT);
            // Stdin that never finishes faults the session: the host retires the VM.
            let token = Id128([5; 16]);
            let mut h = connect(&s, Channel::Exec).await;
            let exec = exec_msg(token, "cat", 10);
            h.conn.sending(token, &Message::Exec(exec.clone())).unwrap();
            h.writer
                .send(token, &Message::Exec(exec), far())
                .await
                .unwrap();
            assert_eq!(h.read().await.unwrap(), HostEvent::Accepted);
            tokio::time::sleep(Duration::from_secs(3)).await;
            assert_eq!(s.session.borrow().state(), BrokerState::Faulted);
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_never_reading_host_cannot_pin_the_result_writer() {
        run_local(async {
            let s = initialized().await;
            let (host, guest) = duplex(8192);
            let s2 = s.clone();
            let done = Rc::new(Cell::new(None));
            let d2 = done.clone();
            tokio::task::spawn_local(async move {
                d2.set(Some(serve(s2, guest, Instant::now()).await));
            });
            let (r, w) = tokio::io::split(host);
            let mut writer = FrameWriter::new(w, Direction::HostToGuest);
            let mut reader = FrameReader::new(r, Direction::GuestToHost);
            let mut budget = ExecBudget::new(1 << 20, 1 << 20);
            let hello = Hello {
                protocol: 1,
                channel: Channel::Exec,
                challenge: Hex32([1; 32]),
                expected: facts().identity.binding(),
            };
            writer
                .send(Id128([1; 16]), &Message::Hello(hello), far())
                .await
                .unwrap();
            reader
                .read_frame(Due::By(far()), &mut budget)
                .await
                .unwrap();
            let token = Id128([5; 16]);
            let stdin = vec![7u8; 60_000];
            writer
                .send(
                    token,
                    &Message::Exec(exec_msg(token, "cat", stdin.len() as u64)),
                    far(),
                )
                .await
                .unwrap();
            reader
                .read_frame(Due::By(far()), &mut budget)
                .await
                .unwrap();
            writer
                .send(token, &Message::Stdin(stdin), far())
                .await
                .unwrap();
            writer
                .send(
                    token,
                    &Message::StdinEnd(StdinEnd {
                        token,
                        total: 60_000,
                    }),
                    far(),
                )
                .await
                .unwrap();
            // Now stop reading: 60,000 bytes of output cannot fit the pipe.
            tokio::time::sleep(Duration::from_secs(5)).await;
            assert_eq!(done.take(), Some(Err(ProtocolError::Timeout(Stage::Write))));
            assert_eq!(s.session.borrow().state(), BrokerState::Faulted);
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn only_one_exec_channel_at_a_time() {
        run_local(async {
            let s = initialized().await;
            let token = Id128([5; 16]);
            let mut first = connect(&s, Channel::Exec).await;
            let exec = exec_msg(token, "sleep", 0);
            first
                .conn
                .sending(token, &Message::Exec(exec.clone()))
                .unwrap();
            first
                .writer
                .send(token, &Message::Exec(exec), far())
                .await
                .unwrap();
            assert_eq!(first.read().await.unwrap(), HostEvent::Accepted);
            let (host, guest) = duplex(4096);
            let s2 = s.clone();
            tokio::task::spawn_local(async move {
                let _ = serve(s2, guest, Instant::now()).await;
            });
            let (r, w) = tokio::io::split(host);
            let mut writer = FrameWriter::new(w, Direction::HostToGuest);
            let mut reader = FrameReader::new(r, Direction::GuestToHost);
            let hello = Hello {
                protocol: 1,
                channel: Channel::Exec,
                challenge: Hex32([1; 32]),
                expected: facts().identity.binding(),
            };
            writer
                .send(Id128([1; 16]), &Message::Hello(hello), far())
                .await
                .unwrap();
            let f = reader
                .read_frame(Due::By(far()), &mut ExecBudget::new(0, 0))
                .await
                .unwrap()
                .unwrap();
            assert!(
                matches!(f.message().unwrap(), Message::Error(e) if e.code == ErrorCode::Admission)
            );
        })
        .await;
    }
}
