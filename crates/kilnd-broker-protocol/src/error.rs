//! Every protocol failure as a typed value. None of them is ever evidence of success
//! or absence: the host treats each one after dispatch as a breach that retires the VM.

use crate::header::{Direction, Kind};

/// Which part of a frame was incomplete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramePart {
    Header,
    Payload,
}

/// Which cumulative bound a frame would have crossed (design 5.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetKind {
    /// Guest-to-host frames, empty frames included.
    Frames,
    /// Header and payload bytes on the wire.
    WireBytes,
    /// Retained stdout payload.
    Stdout,
    /// Retained stderr payload.
    Stderr,
    /// Every other guest-to-host control payload, combined.
    Control,
    /// Host-to-guest stdin payload.
    Stdin,
}

/// What a deadline was protecting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// The first byte of a frame that is due.
    FirstByte,
    /// The rest of a frame after it became due, never reset by trickled bytes.
    Frame,
    /// The clean end of stream after a terminal frame.
    Eof,
    /// Writing a frame or the end of stream.
    Write,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolError {
    #[error("bad frame magic {0:02x?}")]
    BadMagic([u8; 4]),
    #[error("unsupported broker protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("unknown frame flags {0:#x}")]
    UnknownFlags(u32),
    #[error("unknown frame kind {0}")]
    UnknownKind(u16),
    #[error("{kind:?} frames never travel {direction:?}")]
    WrongDirection { kind: Kind, direction: Direction },
    #[error("{kind:?} payload of {len} bytes exceeds its bound of {max}")]
    PayloadTooLarge { kind: Kind, len: u32, max: u32 },
    #[error("premature EOF: {got} of {need} {part:?} bytes")]
    PrematureEof {
        part: FramePart,
        got: usize,
        need: usize,
    },
    #[error("frame sequence {got} where {expected} was due")]
    Sequence { expected: u32, got: u32 },
    #[error("frame sequence counter overflowed")]
    SequenceOverflow,
    #[error("frame request ID does not belong to this exchange")]
    RequestId,
    #[error("{kind:?} is not allowed {state}")]
    UnexpectedKind { kind: Kind, state: &'static str },
    #[error("end of stream before the exchange's terminal frame")]
    EofBeforeTerminal,
    #[error("bytes after the terminal frame")]
    TrailingBytes,
    #[error("a second terminal frame")]
    DuplicateTerminal,
    #[error("an empty data frame where bytes were due")]
    EmptyData,
    #[error("control payload is not UTF-8")]
    Utf8,
    #[error("JSON syntax error at byte {0}")]
    JsonSyntax(usize),
    #[error("JSON nests deeper than 8")]
    JsonDepth,
    #[error("JSON number is not an integer")]
    JsonFloat,
    #[error("JSON object repeats a key")]
    JsonDuplicateKey,
    #[error("JSON schema: {0}")]
    Schema(String),
    #[error("{0} exceeds its bound")]
    FieldBound(&'static str),
    #[error("invalid {0}")]
    InvalidField(&'static str),
    #[error("cumulative {0:?} bound exceeded")]
    Budget(BudgetKind),
    #[error("stdin carried {got} bytes of the {declared} declared")]
    StdinLength { declared: u64, got: u64 },
    #[error("retained output disagrees with the Result's capture facts")]
    CaptureMismatch,
    #[error("deadline expired during {0:?}")]
    Timeout(Stage),
    #[error("transport I/O: {0:?}")]
    Io(std::io::ErrorKind),
}

impl From<std::io::Error> for ProtocolError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.kind())
    }
}

pub type Result<T> = std::result::Result<T, ProtocolError>;
