//! The fixed 36-byte `KGB1` header, in network byte order (design 5.2):
//! magic[4] = "KGB1", version:u16 = 1, kind:u16, flags:u32 = 0, payload_length:u32,
//! request_id:[u8;16], sequence:u32.

use crate::error::{ProtocolError, Result};
use crate::types::Id128;
use crate::{MAX_DATA_PAYLOAD, MAX_G2H_CONTROL_PAYLOAD, MAX_H2G_CONTROL_PAYLOAD};

pub const MAGIC: [u8; 4] = *b"KGB1";
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 36;

/// Which way a frame travels. The helper is the host; the broker is the guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    HostToGuest,
    GuestToHost,
}

/// The sixteen frame kinds of broker protocol version 1 (design 5.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Kind {
    Hello = 1,
    HelloReply = 2,
    Initialize = 3,
    Ready = 4,
    Probe = 5,
    ProbeReply = 6,
    Exec = 7,
    Accepted = 8,
    Stdin = 9,
    StdinEnd = 10,
    Cancel = 11,
    CancelAck = 12,
    Stdout = 13,
    Stderr = 14,
    Result = 15,
    Error = 16,
}

impl Kind {
    pub const ALL: [Kind; 16] = [
        Kind::Hello,
        Kind::HelloReply,
        Kind::Initialize,
        Kind::Ready,
        Kind::Probe,
        Kind::ProbeReply,
        Kind::Exec,
        Kind::Accepted,
        Kind::Stdin,
        Kind::StdinEnd,
        Kind::Cancel,
        Kind::CancelAck,
        Kind::Stdout,
        Kind::Stderr,
        Kind::Result,
        Kind::Error,
    ];

    pub fn from_u16(value: u16) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| *kind as u16 == value)
            .ok_or(ProtocolError::UnknownKind(value))
    }

    pub fn direction(self) -> Direction {
        match self {
            Kind::Hello
            | Kind::Initialize
            | Kind::Probe
            | Kind::Exec
            | Kind::Stdin
            | Kind::StdinEnd
            | Kind::Cancel => Direction::HostToGuest,
            _ => Direction::GuestToHost,
        }
    }

    /// Raw bytes rather than a JSON control payload.
    pub fn is_data(self) -> bool {
        matches!(self, Kind::Stdin | Kind::Stdout | Kind::Stderr)
    }

    /// The largest payload a single frame of this kind may declare.
    pub fn max_payload(self) -> u32 {
        let bytes = if self.is_data() {
            MAX_DATA_PAYLOAD
        } else if self.direction() == Direction::HostToGuest {
            MAX_H2G_CONTROL_PAYLOAD
        } else {
            MAX_G2H_CONTROL_PAYLOAD
        };
        bytes as u32
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: Kind,
    pub payload_len: u32,
    pub request_id: Id128,
    pub sequence: u32,
}

impl Header {
    /// Parses and checks a header received travelling `direction`. Magic, version,
    /// flags, kind, direction and the kind's payload bound are all checked here, before
    /// any byte of the payload is read or any buffer is sized from its length.
    pub fn parse(bytes: &[u8; HEADER_LEN], direction: Direction) -> Result<Self> {
        let magic: [u8; 4] = bytes[0..4].try_into().expect("4 bytes");
        if magic != MAGIC {
            return Err(ProtocolError::BadMagic(magic));
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }
        let flags = u32::from_be_bytes(bytes[8..12].try_into().expect("4 bytes"));
        if flags != 0 {
            return Err(ProtocolError::UnknownFlags(flags));
        }
        let kind = Kind::from_u16(u16::from_be_bytes([bytes[6], bytes[7]]))?;
        if kind.direction() != direction {
            return Err(ProtocolError::WrongDirection { kind, direction });
        }
        let payload_len = u32::from_be_bytes(bytes[12..16].try_into().expect("4 bytes"));
        if payload_len > kind.max_payload() {
            return Err(ProtocolError::PayloadTooLarge {
                kind,
                len: payload_len,
                max: kind.max_payload(),
            });
        }
        Ok(Self {
            kind,
            payload_len,
            request_id: Id128(bytes[16..32].try_into().expect("16 bytes")),
            sequence: u32::from_be_bytes(bytes[32..36].try_into().expect("4 bytes")),
        })
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&MAGIC);
        out[4..6].copy_from_slice(&VERSION.to_be_bytes());
        out[6..8].copy_from_slice(&(self.kind as u16).to_be_bytes());
        // flags stay zero.
        out[12..16].copy_from_slice(&self.payload_len.to_be_bytes());
        out[16..32].copy_from_slice(&self.request_id.0);
        out[32..36].copy_from_slice(&self.sequence.to_be_bytes());
        out
    }
}
