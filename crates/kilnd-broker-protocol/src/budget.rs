//! Cumulative bounds (design 5.6), charged from each header before its payload is
//! read. A valid per-frame length never authorizes an unbounded stream: frames,
//! wire bytes and each payload class are counted, empty frames included.

use crate::error::{BudgetKind, ProtocolError, Result};
use crate::header::{HEADER_LEN, Header, Kind};
use crate::{
    MAX_EXCHANGE_FRAMES, MAX_EXCHANGE_PAYLOAD, MAX_EXEC_FRAMES, MAX_EXEC_H2G_FRAMES,
    MAX_G2H_CONTROL_PAYLOAD, MAX_OUTPUT_BYTES, MAX_STDIN_BYTES,
};

/// Admits a frame from its checked header, or refuses it before the payload is read.
pub trait Budget {
    fn admit(&mut self, header: &Header) -> Result<()>;
}

fn over(kind: BudgetKind) -> ProtocolError {
    ProtocolError::Budget(kind)
}

/// One execution's guest-to-host allowance, across the exec channel and any control
/// exchange spent on that token (design 5.6): retained stdout and stderr up to their
/// negotiated limits, every other control payload combined up to 64 KiB, at most 128
/// frames and at most `stdout + stderr + 64 KiB + 128 * 36` wire bytes.
#[derive(Clone, Debug)]
pub struct ExecBudget {
    stdout_limit: u64,
    stderr_limit: u64,
    frames: u32,
    wire: u64,
    stdout: u64,
    stderr: u64,
    control: u64,
}

impl ExecBudget {
    /// Limits above 1 MiB are clamped to 1 MiB.
    pub fn new(stdout_limit: u64, stderr_limit: u64) -> Self {
        Self {
            stdout_limit: stdout_limit.min(MAX_OUTPUT_BYTES),
            stderr_limit: stderr_limit.min(MAX_OUTPUT_BYTES),
            frames: 0,
            wire: 0,
            stdout: 0,
            stderr: 0,
            control: 0,
        }
    }

    pub fn max_wire(&self) -> u64 {
        self.stdout_limit
            + self.stderr_limit
            + MAX_G2H_CONTROL_PAYLOAD as u64
            + u64::from(MAX_EXEC_FRAMES) * HEADER_LEN as u64
    }

    pub fn frames(&self) -> u32 {
        self.frames
    }

    pub fn wire(&self) -> u64 {
        self.wire
    }
}

impl Budget for ExecBudget {
    fn admit(&mut self, header: &Header) -> Result<()> {
        let len = u64::from(header.payload_len);
        let frames = self
            .frames
            .checked_add(1)
            .filter(|n| *n <= MAX_EXEC_FRAMES)
            .ok_or(over(BudgetKind::Frames))?;
        let wire = self
            .wire
            .checked_add(HEADER_LEN as u64 + len)
            .filter(|n| *n <= self.max_wire())
            .ok_or(over(BudgetKind::WireBytes))?;
        let (counter, limit, kind) = match header.kind {
            Kind::Stdout => (self.stdout, self.stdout_limit, BudgetKind::Stdout),
            Kind::Stderr => (self.stderr, self.stderr_limit, BudgetKind::Stderr),
            _ => (
                self.control,
                MAX_G2H_CONTROL_PAYLOAD as u64,
                BudgetKind::Control,
            ),
        };
        let counted = counter
            .checked_add(len)
            .filter(|n| *n <= limit)
            .ok_or(over(kind))?;
        self.frames = frames;
        self.wire = wire;
        match header.kind {
            Kind::Stdout => self.stdout = counted,
            Kind::Stderr => self.stderr = counted,
            _ => self.control = counted,
        }
        Ok(())
    }
}

/// A non-exec exchange's guest-to-host allowance: 64 KiB of payload and 16 frames.
#[derive(Clone, Debug, Default)]
pub struct ExchangeBudget {
    frames: u32,
    payload: u64,
}

impl Budget for ExchangeBudget {
    fn admit(&mut self, header: &Header) -> Result<()> {
        let frames = self
            .frames
            .checked_add(1)
            .filter(|n| *n <= MAX_EXCHANGE_FRAMES)
            .ok_or(over(BudgetKind::Frames))?;
        let payload = self
            .payload
            .checked_add(u64::from(header.payload_len))
            .filter(|n| *n <= MAX_EXCHANGE_PAYLOAD as u64)
            .ok_or(over(BudgetKind::Control))?;
        self.frames = frames;
        self.payload = payload;
        Ok(())
    }
}

/// The broker's bound on what the host may send on one connection: a control
/// connection carries `Hello` and one request; an exec connection `Hello`, `Exec`, at
/// most 1 MiB of stdin and `StdinEnd`, in at most [`MAX_EXEC_H2G_FRAMES`] frames.
#[derive(Clone, Debug, Default)]
pub struct HostBudget {
    frames: u32,
    stdin: u64,
}

impl Budget for HostBudget {
    fn admit(&mut self, header: &Header) -> Result<()> {
        let frames = self
            .frames
            .checked_add(1)
            .filter(|n| *n <= MAX_EXEC_H2G_FRAMES)
            .ok_or(over(BudgetKind::Frames))?;
        let stdin = if header.kind == Kind::Stdin {
            self.stdin
                .checked_add(u64::from(header.payload_len))
                .filter(|n| *n <= MAX_STDIN_BYTES)
                .ok_or(over(BudgetKind::Stdin))?
        } else {
            self.stdin
        };
        self.frames = frames;
        self.stdin = stdin;
        Ok(())
    }
}
