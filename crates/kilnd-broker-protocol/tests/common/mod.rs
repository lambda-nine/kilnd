//! Shared builders and a deterministic generator for the protocol tests.
#![allow(dead_code)]

use kilnd_broker_protocol::message::*;
use kilnd_broker_protocol::types::*;
use kilnd_broker_protocol::{Direction, Kind, Message};
use kilnd_exec_core::model::{RuntimeErrorKind, RuntimeStage};

/// xorshift64*: deterministic, so every failure reproduces from its seed.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n.max(1)
    }
    pub fn bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u64() as u8).collect()
    }
    pub fn id(&mut self) -> Id128 {
        Id128(self.bytes(16).try_into().unwrap())
    }
    pub fn hex32(&mut self) -> Hex32 {
        Hex32(self.bytes(32).try_into().unwrap())
    }
    fn hex(&mut self, n: usize) -> String {
        (0..n)
            .map(|_| char::from_digit(self.below(16) as u32, 16).unwrap())
            .collect()
    }
    pub fn sandbox_id(&mut self) -> SandboxId {
        SandboxId::new(format!("sb-{}", self.hex(16))).unwrap()
    }
    pub fn execution_id(&mut self) -> ExecutionId {
        ExecutionId::new(format!("ex-{}", self.hex(16))).unwrap()
    }
    pub fn boot_id(&mut self) -> BootId {
        BootId::new(format!(
            "{}-{}-{}-{}-{}",
            self.hex(8),
            self.hex(4),
            self.hex(4),
            self.hex(4),
            self.hex(12)
        ))
        .unwrap()
    }
    pub fn work_uuid(&mut self) -> WorkUuid {
        WorkUuid::new(format!(
            "{}-{}-4{}-a{}-{}",
            self.hex(8),
            self.hex(4),
            self.hex(3),
            self.hex(3),
            self.hex(12)
        ))
        .unwrap()
    }
    pub fn inner_id(&mut self) -> InnerId {
        InnerId::new(format!("{}-{}", self.hex(16), self.below(10000))).unwrap()
    }
    /// Arbitrary UTF-8, including quotes, backslashes, controls and non-ASCII.
    pub fn text(&mut self, max: usize) -> String {
        let pool = [
            "a", "Z", "0", " ", "\"", "\\", "\n", "\t", "\u{1}", "é", "€", "𝄞", "/", "-",
        ];
        let mut out = String::new();
        let n = self.below(max as u64 + 1) as usize;
        while out.len() < n {
            let piece = pool[self.below(pool.len() as u64) as usize];
            if out.len() + piece.len() > max {
                break;
            }
            out.push_str(piece);
        }
        out
    }
}

pub fn binding(rng: &mut Rng) -> SessionBinding {
    SessionBinding {
        instance_id: rng.id(),
        allocation_id: rng.id(),
        sandbox_id: rng.sandbox_id(),
        boot_nonce: rng.hex32(),
        manifest_sha256: rng.hex32(),
        launch_sha256: rng.hex32(),
        guest_exec_spec_sha256: rng.hex32(),
    }
}

pub fn identity(rng: &mut Rng) -> GuestIdentity {
    let b = binding(rng);
    GuestIdentity {
        instance_id: b.instance_id,
        allocation_id: b.allocation_id,
        sandbox_id: b.sandbox_id,
        boot_nonce: b.boot_nonce,
        manifest_sha256: b.manifest_sha256,
        launch_sha256: b.launch_sha256,
        work_uuid: rng.work_uuid(),
        guest_exec_spec_sha256: b.guest_exec_spec_sha256,
    }
}

pub fn hello(rng: &mut Rng, channel: Channel) -> Hello {
    Hello {
        protocol: 1,
        channel,
        challenge: rng.hex32(),
        expected: binding(rng),
    }
}

pub fn hello_reply(rng: &mut Rng, challenge: Hex32) -> HelloReply {
    HelloReply {
        protocol: 1,
        challenge,
        identity: identity(rng),
        boot_id: rng.boot_id(),
        broker_sha256: rng.hex32(),
        kiln: KilnFacts {
            protocol: 1,
            features: rng.below(64) as u32,
        },
        hardening: Hardening {
            cmdline: true,
            kernel_log_bounded: true,
            kaslr: true,
            memory_initialization: true,
            kstack_offset: true,
            lockdown_confidentiality: rng.bool(),
            kexec_absent: true,
        },
        work: WorkMount {
            uuid: rng.work_uuid(),
            nosuid: true,
            nodev: true,
            noexec: true,
            prjquota: rng.bool(),
        },
        state: BrokerState::Idle,
        inner_id: rng.bool().then(|| rng.inner_id()),
    }
}

pub fn spec(rng: &mut Rng) -> GuestExecSpec {
    let read_only_root = rng.bool();
    GuestExecSpec {
        image: "alpine".into(),
        memory_bytes: 1 + rng.below(512 * 1024 * 1024),
        cpu_millis: 1 + rng.below(1000) as u32,
        pids: 1 + rng.below(4096) as u32,
        disk_bytes: 1 + rng.below(1 << 34),
        network: "none".into(),
        read_only_root,
        writable_paths: if read_only_root {
            (0..rng.below(4))
                .map(|i| format!("/w{i}/{}", rng.below(99)))
                .collect()
        } else {
            Vec::new()
        },
    }
}

pub fn exec(rng: &mut Rng, token: Id128) -> Exec {
    let argc = 1 + rng.below(8) as usize;
    let mut argv: Vec<String> = (0..argc).map(|_| rng.text(40)).collect();
    argv[0] = format!("p{}", argv[0]).replace('\0', "");
    Exec {
        token,
        execution_id: rng.execution_id(),
        argv,
        stdin_bytes: rng.below(1024 * 1024 + 1),
        max_output: rng.below(1024 * 1024 + 1),
        remaining_ms: 1 + rng.below(3_600_000),
    }
}

pub fn facts(rng: &mut Rng) -> CaptureFacts {
    let kept = rng.below(1024 * 1024 + 1);
    let total = kept + if rng.bool() { 0 } else { rng.below(1 << 40) };
    CaptureFacts {
        kept,
        total,
        total_known: rng.bool(),
        truncated: total > kept,
    }
}

pub fn result(rng: &mut Rng, token: Id128) -> ExecResult {
    let kinds = [
        RuntimeErrorKind::Io,
        RuntimeErrorKind::Protocol,
        RuntimeErrorKind::CleanupFailed,
    ];
    let stages = [
        RuntimeStage::Exec,
        RuntimeStage::Cleanup,
        RuntimeStage::None,
    ];
    ExecResult {
        token,
        finish: match rng.below(4) {
            0 => Finish::Completed,
            1 => Finish::TimedOut,
            2 => Finish::Canceled,
            _ => Finish::Failed {
                kind: kinds[rng.below(3) as usize],
                stage: stages[rng.below(3) as usize],
            },
        },
        termination: match rng.below(3) {
            0 => None,
            1 => Some(Termination::Exited {
                code: rng.below(256) as i32,
            }),
            _ => Some(Termination::Signaled {
                signal: 1 + rng.below(64) as i32,
                core_dumped: rng.bool(),
            }),
        },
        diagnostic: rng.bool().then(|| Diagnostic {
            kind: kinds[rng.below(3) as usize],
            stage: stages[rng.below(3) as usize],
            message: WireText::narrow(&rng.text(3000)).0,
            message_truncated: rng.bool(),
        }),
        stdout: facts(rng),
        stderr: facts(rng),
        cleanup: [
            Cleanup::NoChildStarted,
            Cleanup::GuestCgroupDrained,
            Cleanup::Unknown,
        ][rng.below(3) as usize],
        inner_id: rng.inner_id(),
    }
}

/// A random valid message of `kind`.
pub fn message(rng: &mut Rng, kind: Kind) -> Message {
    let token = rng.id();
    match kind {
        Kind::Hello => {
            let channel = if rng.bool() {
                Channel::Exec
            } else {
                Channel::Control
            };
            Message::Hello(hello(rng, channel))
        }
        Kind::HelloReply => {
            let challenge = rng.hex32();
            Message::HelloReply(Box::new(hello_reply(rng, challenge)))
        }
        Kind::Initialize => {
            let spec = spec(rng);
            Message::Initialize(Initialize {
                guest_exec_spec_sha256: spec.sha256(),
                spec,
            })
        }
        Kind::Ready => Message::Ready(Box::new(Ready {
            binding: binding(rng),
            boot_id: rng.boot_id(),
            inner_id: rng.inner_id(),
            kiln: KilnFacts {
                protocol: 1,
                features: 0x1f,
            },
            idle: true,
            work_quota_verified: true,
        })),
        Kind::Probe => Message::Probe(Probe {
            boot_id: rng.boot_id(),
            inner_id: rng.inner_id(),
        }),
        Kind::ProbeReply => Message::ProbeReply(ProbeReply {
            boot_id: rng.boot_id(),
            inner_id: rng.inner_id(),
            state: BrokerState::Executing,
            active: rng.bool().then(|| rng.id()),
        }),
        Kind::Exec => Message::Exec(exec(rng, token)),
        Kind::Accepted => Message::Accepted(Accepted { token }),
        Kind::Stdin | Kind::Stdout | Kind::Stderr => {
            let n = rng.below(64 * 1024 + 1) as usize;
            let bytes = rng.bytes(n);
            match kind {
                Kind::Stdin => Message::Stdin(bytes),
                Kind::Stdout => Message::Stdout(bytes),
                _ => Message::Stderr(bytes),
            }
        }
        Kind::StdinEnd => Message::StdinEnd(StdinEnd {
            token,
            total: rng.below(1024 * 1024 + 1),
        }),
        Kind::Cancel => Message::Cancel(Cancel {
            token,
            reason: CancelReason::Timeout,
        }),
        Kind::CancelAck => Message::CancelAck(CancelAck {
            token,
            active: rng.bool(),
        }),
        Kind::Result => Message::Result(Box::new(result(rng, token))),
        Kind::Error => Message::Error(ErrorReply {
            code: ErrorCode::Admission,
            state: BrokerState::Faulted,
            message: WireText::narrow(&rng.text(2048)).0,
        }),
    }
}

pub fn direction(kind: Kind) -> Direction {
    kind.direction()
}
