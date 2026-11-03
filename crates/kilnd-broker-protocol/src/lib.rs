//! Broker protocol version 1 (design section 5.2): the strict codec between the root
//! helper, over the jail's Firecracker vsock Unix socket, and the guest broker on
//! AF_VSOCK port 5252.
//!
//! Every frame is a fixed 36-byte `KGB1` header and a payload: strict JSON for control
//! messages, raw bytes for `Stdin`, `Stdout` and `Stderr`. This crate checks magic,
//! version, kind, flags, direction, per-kind payload bounds, per-direction sequence
//! numbers, request IDs, message order, strict JSON (unknown fields, duplicate keys,
//! floats, nesting beyond 8) and every field bound, and charges cumulative frame, wire
//! and payload budgets from each header before reading its payload. Nothing is ever
//! allocated from a length that was not checked first. It has no `unsafe` code.
//!
//! Layers, bottom up: [`header`], [`json`] and [`message`] (one frame, no I/O);
//! [`frame::FrameDecoder`] and [`budget`] (a stream of frames, no I/O);
//! [`exchange`] (one connection's order and totals); [`stream`] (tokio I/O with
//! absolute deadlines).
#![forbid(unsafe_code)]

pub mod budget;
pub mod error;
pub mod exchange;
pub mod frame;
pub mod header;
pub mod identity;
pub mod json;
pub mod message;
pub mod stream;
pub mod types;

pub use error::{BudgetKind, FramePart, ProtocolError, Result, Stage};
pub use frame::{Frame, FrameDecoder, Sequence, encode_frame};
pub use header::{Direction, HEADER_LEN, Header, Kind};
pub use message::Message;
pub use types::{BootId, ExecutionId, Hex32, Id128, InnerId, SandboxId, WireText, WorkUuid};

/// The only protocol version.
pub const PROTOCOL_VERSION: u32 = 1;
/// The broker's AF_VSOCK port; the helper writes `CONNECT 5252\n`.
pub const BROKER_PORT: u32 = 5252;
/// The only peer CID the broker accepts: the host.
pub const HOST_CID: u32 = 2;

const KIB: usize = 1024;

/// Host-to-guest control payloads, after JSON escaping (argv is at most 256 KiB).
pub const MAX_H2G_CONTROL_PAYLOAD: usize = 384 * KIB;
/// Guest-to-host control payloads, per frame and cumulatively per execution.
pub const MAX_G2H_CONTROL_PAYLOAD: usize = 64 * KIB;
/// `Stdin`, `Stdout` and `Stderr` payloads.
pub const MAX_DATA_PAYLOAD: usize = 64 * KIB;
/// Total stdin per execution.
pub const MAX_STDIN_BYTES: u64 = 1024 * 1024;
/// Retained stdout or stderr prefix per execution.
pub const MAX_OUTPUT_BYTES: u64 = 1024 * 1024;
/// Guest-to-host frames per execution, empty frames included, across both channels.
pub const MAX_EXEC_FRAMES: u32 = 128;
/// Guest-to-host frames of one non-exec exchange.
pub const MAX_EXCHANGE_FRAMES: u32 = 16;
/// Guest-to-host payload of one non-exec exchange.
pub const MAX_EXCHANGE_PAYLOAD: usize = 64 * KIB;
/// Host-to-guest frames on one connection: `Hello`, `Exec`, at most 1024 `Stdin`
/// frames and `StdinEnd`.
pub const MAX_EXEC_H2G_FRAMES: u32 = 3 + 1024;
/// Arguments, and argv bytes counted as kilnd's validation counts them.
pub const MAX_ARGC: usize = 4096;
pub const MAX_ARGV_BYTES: usize = 256 * KIB;
/// The guest-relative execution budget, `1..=3_600_000` milliseconds.
pub const MAX_REMAINING_MS: u64 = 3_600_000;
/// A wire diagnostic's message.
pub const MAX_DIAGNOSTIC_BYTES: usize = 2048;
/// Frame assembly and every request/response stage (design 5.6).
pub const STAGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
