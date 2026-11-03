//! The broker's state machine (design B5): Uninitialized -> Initializing -> Idle ->
//! Executing -> Draining -> Idle, with Faulted terminal until the VM stops. Every
//! transition is a method here, so the transport cannot skip one. Any initialization
//! uncertainty faults the session: it never creates a second inner sandbox.

use kilnd_broker_protocol::message::{
    BrokerState, CancelAck, ErrorCode, ErrorReply, GuestIdentity, Hardening, Hello, HelloReply,
    Initialize, KilnFacts, Probe, ProbeReply, Ready, WorkMount,
};
use kilnd_broker_protocol::{BootId, Hex32, Id128, InnerId, PROTOCOL_VERSION, WireText};
use tokio_util::sync::CancellationToken;

/// What the broker learned about itself at start, before any connection.
#[derive(Clone, Debug)]
pub struct Facts {
    pub identity: GuestIdentity,
    pub boot_id: BootId,
    pub broker_sha256: Hex32,
    pub hardening: Hardening,
    pub work: WorkMount,
    /// The CLI's capability facts from the start-up probe; `None` if it failed, which
    /// faults the session.
    pub kiln: Option<KilnFacts>,
}

pub fn error(code: ErrorCode, state: BrokerState, message: &str) -> ErrorReply {
    ErrorReply {
        code,
        state,
        message: WireText::narrow(message).0,
    }
}

#[derive(Debug)]
enum State {
    Uninitialized,
    Initializing,
    Idle,
    Executing {
        token: Id128,
        cancel: CancellationToken,
    },
    Draining {
        token: Id128,
    },
    Faulted,
}

/// What an `Initialize` should do now.
pub enum InitStep {
    /// Run the persistent create and the smoke exec.
    Start,
    /// An identical request already succeeded: the same `Ready` again.
    Replay(Box<Ready>),
    Refuse(ErrorReply),
}

#[derive(Debug)]
pub struct Session {
    facts: Facts,
    state: State,
    inner: Option<InnerId>,
    kiln: Option<KilnFacts>,
    initialized_with: Option<Hex32>,
}

impl Session {
    pub fn new(facts: Facts) -> Self {
        // A guest whose hardening record is incomplete answers Hello honestly but never
        // initializes.
        let state = if facts.hardening.all() && facts.kiln.is_some() {
            State::Uninitialized
        } else {
            State::Faulted
        };
        Self {
            facts,
            state,
            inner: None,
            kiln: None,
            initialized_with: None,
        }
    }

    pub fn state(&self) -> BrokerState {
        match self.state {
            State::Uninitialized => BrokerState::Uninitialized,
            State::Initializing => BrokerState::Initializing,
            State::Idle => BrokerState::Idle,
            State::Executing { .. } => BrokerState::Executing,
            State::Draining { .. } => BrokerState::Draining,
            State::Faulted => BrokerState::Faulted,
        }
    }

    pub fn inner(&self) -> Option<&InnerId> {
        self.inner.as_ref()
    }

    fn refuse(&self, code: ErrorCode, message: &str) -> ErrorReply {
        error(code, self.state(), message)
    }

    /// Faults the session for good: nothing further is admitted until the VM stops.
    pub fn fault(&mut self) {
        if let State::Executing { cancel, .. } = &self.state {
            cancel.cancel();
        }
        self.state = State::Faulted;
    }

    /// A `Hello` must expect exactly this guest's identity and speak protocol 1.
    pub fn hello(&self, hello: &Hello) -> Result<HelloReply, ErrorReply> {
        if hello.protocol != PROTOCOL_VERSION {
            return Err(self.refuse(ErrorCode::Incompatible, "unsupported protocol"));
        }
        if hello.expected != self.facts.identity.binding() {
            return Err(self.refuse(
                ErrorCode::Incompatible,
                "the expected session is not this guest's",
            ));
        }
        Ok(HelloReply {
            protocol: PROTOCOL_VERSION,
            challenge: hello.challenge,
            identity: self.facts.identity.clone(),
            boot_id: self.facts.boot_id.clone(),
            broker_sha256: self.facts.broker_sha256,
            kiln: self.kiln.or(self.facts.kiln).unwrap_or(KilnFacts {
                protocol: 0,
                features: 0,
            }),
            hardening: self.facts.hardening,
            work: self.facts.work.clone(),
            state: self.state(),
            inner_id: self.inner.clone(),
        })
    }

    fn ready(&self) -> Option<Ready> {
        Some(Ready {
            binding: self.facts.identity.binding(),
            boot_id: self.facts.boot_id.clone(),
            inner_id: self.inner.clone()?,
            kiln: self.kiln?,
            idle: matches!(self.state, State::Idle),
            work_quota_verified: self.facts.work.prjquota,
        })
    }

    /// Once per cold boot. A duplicate identical request replays the result; a
    /// conflicting one faults the session.
    pub fn begin_initialize(&mut self, init: &Initialize) -> InitStep {
        let digest = init.spec.sha256();
        if digest != init.guest_exec_spec_sha256
            || digest != self.facts.identity.guest_exec_spec_sha256
        {
            self.fault();
            return InitStep::Refuse(self.refuse(
                ErrorCode::Incompatible,
                "the execution spec does not match its digest or this guest's identity",
            ));
        }
        match (&self.state, self.initialized_with) {
            (State::Uninitialized, _) => {
                self.state = State::Initializing;
                self.initialized_with = Some(digest);
                InitStep::Start
            }
            (State::Idle | State::Executing { .. } | State::Draining { .. }, Some(done))
                if done == digest =>
            {
                match self.ready() {
                    Some(ready) => InitStep::Replay(Box::new(ready)),
                    None => InitStep::Refuse(self.refuse(ErrorCode::Internal, "no ready record")),
                }
            }
            (State::Initializing, _) => {
                InitStep::Refuse(self.refuse(ErrorCode::Admission, "initialization is in progress"))
            }
            (State::Faulted, _) => {
                InitStep::Refuse(self.refuse(ErrorCode::Admission, "the broker has faulted"))
            }
            _ => {
                self.fault();
                InitStep::Refuse(self.refuse(ErrorCode::Protocol, "a conflicting Initialize"))
            }
        }
    }

    /// The persistent create and smoke exec finished: Idle with the inner sandbox, or
    /// Faulted on anything uncertain.
    pub fn finish_initialize(
        &mut self,
        result: Result<(InnerId, KilnFacts), String>,
    ) -> Result<Ready, ErrorReply> {
        if !matches!(self.state, State::Initializing) {
            self.fault();
            return Err(self.refuse(ErrorCode::Internal, "initialization was interrupted"));
        }
        match result {
            Ok((inner, kiln)) => {
                self.inner = Some(inner);
                self.kiln = Some(kiln);
                self.state = State::Idle;
                self.ready()
                    .ok_or_else(|| self.refuse(ErrorCode::Internal, "no ready record"))
            }
            Err(reason) => {
                self.fault();
                Err(self.refuse(ErrorCode::Internal, &reason))
            }
        }
    }

    pub fn probe(&self, probe: &Probe) -> Result<ProbeReply, ErrorReply> {
        if probe.boot_id != self.facts.boot_id || Some(&probe.inner_id) != self.inner.as_ref() {
            return Err(self.refuse(
                ErrorCode::Incompatible,
                "the expected boot or inner sandbox is not this one",
            ));
        }
        Ok(ProbeReply {
            boot_id: self.facts.boot_id.clone(),
            inner_id: probe.inner_id.clone(),
            state: self.state(),
            active: match &self.state {
                State::Executing { token, .. } | State::Draining { token } => Some(*token),
                _ => None,
            },
        })
    }

    /// Admits one execution, only when idle. The token cancels it.
    pub fn begin_exec(&mut self, token: Id128) -> Result<CancellationToken, ErrorReply> {
        match self.state {
            State::Idle => {
                let cancel = CancellationToken::new();
                self.state = State::Executing {
                    token,
                    cancel: cancel.clone(),
                };
                Ok(cancel)
            }
            _ => Err(self.refuse(ErrorCode::Admission, "not idle")),
        }
    }

    /// The command settled; its result is being sent.
    pub fn draining(&mut self, token: Id128) {
        match &self.state {
            State::Executing { token: active, .. } if *active == token => {
                self.state = State::Draining { token };
            }
            _ => self.fault(),
        }
    }

    /// The result transfer finished. A drained, fully delivered execution leaves the
    /// sandbox idle; anything else faults it.
    pub fn settle(&mut self, token: Id128, reusable: bool) {
        match &self.state {
            State::Draining { token: active } if *active == token && reusable => {
                self.state = State::Idle;
            }
            _ => self.fault(),
        }
    }

    /// Idempotent on the active token; never cancels another. Not cleanup proof.
    pub fn cancel(&mut self, token: Id128) -> CancelAck {
        let active = match &self.state {
            State::Executing {
                token: active,
                cancel,
            } if *active == token => {
                cancel.cancel();
                true
            }
            State::Draining { token: active } => *active == token,
            _ => false,
        };
        CancelAck { token, active }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use kilnd_broker_protocol::message::{Channel, GuestExecSpec};
    use kilnd_broker_protocol::{SandboxId, WorkUuid};

    pub(crate) fn facts() -> Facts {
        let spec = spec();
        Facts {
            identity: GuestIdentity {
                instance_id: Id128([1; 16]),
                allocation_id: Id128([2; 16]),
                sandbox_id: SandboxId::new("sb-0123456789abcdef").unwrap(),
                boot_nonce: Hex32([3; 32]),
                manifest_sha256: Hex32([4; 32]),
                launch_sha256: Hex32([5; 32]),
                work_uuid: WorkUuid::new("51b8e65e-23b9-4eba-a21c-7c1cce2c5f94").unwrap(),
                guest_exec_spec_sha256: spec.sha256(),
            },
            boot_id: BootId::new("0f8e2c1a-1b2c-3d4e-5f60-718293a4b5c6").unwrap(),
            broker_sha256: Hex32([6; 32]),
            hardening: kilnd_broker_protocol::identity::hardening_from_mask(0x7f),
            work: WorkMount {
                uuid: WorkUuid::new("51b8e65e-23b9-4eba-a21c-7c1cce2c5f94").unwrap(),
                nosuid: true,
                nodev: true,
                noexec: true,
                prjquota: true,
            },
            kiln: Some(kiln()),
        }
    }

    pub(crate) fn spec() -> GuestExecSpec {
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

    fn init() -> Initialize {
        let spec = spec();
        Initialize {
            guest_exec_spec_sha256: spec.sha256(),
            spec,
        }
    }

    pub(crate) fn kiln() -> KilnFacts {
        KilnFacts {
            protocol: 1,
            features: 0x1f,
        }
    }

    fn ready_session() -> Session {
        let mut s = Session::new(facts());
        assert!(matches!(s.begin_initialize(&init()), InitStep::Start));
        s.finish_initialize(Ok((InnerId::new("abcd").unwrap(), kiln())))
            .unwrap();
        s
    }

    #[test]
    fn hello_requires_this_guests_exact_identity() {
        let s = Session::new(facts());
        let mut hello = Hello {
            protocol: 1,
            channel: Channel::Control,
            challenge: Hex32([9; 32]),
            expected: facts().identity.binding(),
        };
        let reply = s.hello(&hello).unwrap();
        assert_eq!(reply.challenge, hello.challenge);
        assert_eq!(reply.state, BrokerState::Uninitialized);
        hello.expected.boot_nonce = Hex32([0; 32]);
        assert_eq!(s.hello(&hello).unwrap_err().code, ErrorCode::Incompatible);
    }

    #[test]
    fn incomplete_hardening_faults_from_the_start() {
        let mut f = facts();
        f.hardening.kaslr = false;
        let mut s = Session::new(f);
        assert_eq!(s.state(), BrokerState::Faulted);
        assert!(matches!(s.begin_initialize(&init()), InitStep::Refuse(_)));
    }

    #[test]
    fn initialize_once_replays_identically_and_faults_on_conflict() {
        let mut s = Session::new(facts());
        assert!(matches!(s.begin_initialize(&init()), InitStep::Start));
        // A second Initialize while the first runs is refused, not started.
        assert!(matches!(s.begin_initialize(&init()), InitStep::Refuse(_)));
        let ready = s
            .finish_initialize(Ok((InnerId::new("abcd").unwrap(), kiln())))
            .unwrap();
        assert!(ready.idle && ready.work_quota_verified);
        match s.begin_initialize(&init()) {
            InitStep::Replay(again) => assert_eq!(*again, ready),
            _ => panic!("expected a replay"),
        }
        let mut other = init();
        other.spec.pids = 7;
        other.guest_exec_spec_sha256 = other.spec.sha256();
        assert!(matches!(s.begin_initialize(&other), InitStep::Refuse(_)));
        assert_eq!(s.state(), BrokerState::Faulted);
    }

    #[test]
    fn a_spec_digest_mismatch_faults() {
        let mut s = Session::new(facts());
        let mut bad = init();
        bad.guest_exec_spec_sha256 = Hex32([0; 32]);
        assert!(matches!(s.begin_initialize(&bad), InitStep::Refuse(_)));
        assert_eq!(s.state(), BrokerState::Faulted);
    }

    #[test]
    fn a_failed_initialization_faults_and_never_retries() {
        let mut s = Session::new(facts());
        assert!(matches!(s.begin_initialize(&init()), InitStep::Start));
        assert!(s.finish_initialize(Err("create failed".into())).is_err());
        assert_eq!(s.state(), BrokerState::Faulted);
        assert!(matches!(s.begin_initialize(&init()), InitStep::Refuse(_)));
    }

    #[test]
    fn exec_cycle_and_cancel_rules() {
        let mut s = ready_session();
        let token = Id128([7; 16]);
        let cancel = s.begin_exec(token).unwrap();
        assert_eq!(s.state(), BrokerState::Executing);
        assert!(s.begin_exec(Id128([8; 16])).is_err());
        // Another token is never canceled; the active one is, idempotently.
        assert!(!s.cancel(Id128([8; 16])).active);
        assert!(!cancel.is_cancelled());
        assert!(s.cancel(token).active);
        assert!(s.cancel(token).active);
        assert!(cancel.is_cancelled());
        s.draining(token);
        assert_eq!(s.state(), BrokerState::Draining);
        assert!(s.begin_exec(token).is_err());
        s.settle(token, true);
        assert_eq!(s.state(), BrokerState::Idle);
        // An undelivered or uncertain result faults the sandbox.
        s.begin_exec(token).unwrap();
        s.draining(token);
        s.settle(token, false);
        assert_eq!(s.state(), BrokerState::Faulted);
        assert!(s.begin_exec(token).is_err());
    }

    #[test]
    fn probe_checks_boot_and_inner_and_reports_the_active_token() {
        let mut s = ready_session();
        let probe = Probe {
            boot_id: facts().boot_id,
            inner_id: InnerId::new("abcd").unwrap(),
        };
        assert_eq!(s.probe(&probe).unwrap().state, BrokerState::Idle);
        s.begin_exec(Id128([7; 16])).unwrap();
        assert_eq!(s.probe(&probe).unwrap().active, Some(Id128([7; 16])));
        let mut wrong = probe.clone();
        wrong.inner_id = InnerId::new("beef").unwrap();
        assert!(s.probe(&wrong).is_err());
    }
}
