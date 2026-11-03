//! Frames, per-direction sequence numbers and the incremental decoder. The decoder
//! never reads past the frame in progress, checks the header and charges the budget
//! before accepting a payload byte, and grows its buffer only as payload bytes arrive,
//! so no allocation is ever sized from a length the peer wrote.

use crate::budget::Budget;
use crate::error::{FramePart, ProtocolError, Result};
use crate::header::{Direction, HEADER_LEN, Header, Kind};
use crate::message::Message;
use crate::types::Id128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub header: Header,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn kind(&self) -> Kind {
        self.header.kind
    }

    pub fn request_id(&self) -> Id128 {
        self.header.request_id
    }

    /// Decodes and validates the payload.
    pub fn message(&self) -> Result<Message> {
        Message::decode(self.header.kind, self.payload.clone())
    }

    pub fn into_message(self) -> Result<Message> {
        Message::decode(self.header.kind, self.payload)
    }
}

/// One direction's sequence counter: zero first, one step per frame, and an error
/// rather than a wrap once `u32::MAX` has been used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sequence(Option<u32>);

impl Default for Sequence {
    fn default() -> Self {
        Self(Some(0))
    }
}

impl Sequence {
    /// A counter whose next value is `next`, for tests near the overflow.
    pub fn starting_at(next: u32) -> Self {
        Self(Some(next))
    }

    pub fn take(&mut self) -> Result<u32> {
        let value = self.0.ok_or(ProtocolError::SequenceOverflow)?;
        self.0 = value.checked_add(1);
        Ok(value)
    }
}

/// Encodes one frame. The payload must fit its kind's bound; the host-to-guest control
/// bound (384 KiB) is applied to the encoded JSON, after escaping.
pub fn encode_frame(
    kind: Kind,
    request_id: Id128,
    sequence: u32,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let max = kind.max_payload();
    let len = u32::try_from(payload.len())
        .ok()
        .filter(|len| *len <= max)
        .ok_or(ProtocolError::PayloadTooLarge {
            kind,
            len: u32::try_from(payload.len()).unwrap_or(u32::MAX),
            max,
        })?;
    let header = Header {
        kind,
        payload_len: len,
        request_id,
        sequence,
    };
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(payload);
    Ok(out)
}

/// The incremental decoder for one direction of one connection.
#[derive(Debug)]
pub struct FrameDecoder {
    direction: Direction,
    header: [u8; HEADER_LEN],
    have: usize,
    pending: Option<Header>,
    payload: Vec<u8>,
    sequence: Sequence,
    failed: Option<ProtocolError>,
}

impl FrameDecoder {
    pub fn new(direction: Direction) -> Self {
        Self::with_sequence(direction, Sequence::default())
    }

    pub fn with_sequence(direction: Direction, sequence: Sequence) -> Self {
        Self {
            direction,
            header: [0; HEADER_LEN],
            have: 0,
            pending: None,
            payload: Vec::new(),
            sequence,
            failed: None,
        }
    }

    /// Bytes still needed to finish the current header or payload; always at least 1.
    pub fn wanted(&self) -> usize {
        match &self.pending {
            Some(header) => header.payload_len as usize - self.payload.len(),
            None => HEADER_LEN - self.have,
        }
    }

    /// Whether no byte of a frame is pending, so an EOF here is clean.
    pub fn at_boundary(&self) -> bool {
        self.pending.is_none() && self.have == 0
    }

    /// Bytes the decoder holds: never more than one header and the part of one
    /// checked payload that has actually arrived.
    pub fn held(&self) -> usize {
        HEADER_LEN + self.payload.capacity()
    }

    /// The error for an EOF now, or `Ok` at a frame boundary.
    pub fn finish(&self) -> Result<()> {
        match &self.pending {
            Some(header) => Err(ProtocolError::PrematureEof {
                part: FramePart::Payload,
                got: self.payload.len(),
                need: header.payload_len as usize,
            }),
            None if self.have > 0 => Err(ProtocolError::PrematureEof {
                part: FramePart::Header,
                got: self.have,
                need: HEADER_LEN,
            }),
            None => Ok(()),
        }
    }

    /// Feeds bytes; consumes at most [`Self::wanted`] of them, so it never reads into
    /// the next frame. Returns how many were consumed and the frame if one completed.
    /// After any error the decoder stays failed.
    pub fn feed<B: Budget + ?Sized>(
        &mut self,
        input: &[u8],
        budget: &mut B,
    ) -> Result<(usize, Option<Frame>)> {
        if let Some(error) = &self.failed {
            return Err(error.clone());
        }
        let result = self.feed_inner(input, budget);
        if let Err(error) = &result {
            self.failed = Some(error.clone());
            self.payload = Vec::new();
        }
        result
    }

    fn feed_inner<B: Budget + ?Sized>(
        &mut self,
        input: &[u8],
        budget: &mut B,
    ) -> Result<(usize, Option<Frame>)> {
        let take = input.len().min(self.wanted());
        let input = &input[..take];
        match self.pending {
            None => {
                self.header[self.have..self.have + take].copy_from_slice(input);
                self.have += take;
                if self.have < HEADER_LEN {
                    return Ok((take, None));
                }
                let header = Header::parse(&self.header, self.direction)?;
                let expected = self.sequence.take()?;
                if header.sequence != expected {
                    return Err(ProtocolError::Sequence {
                        expected,
                        got: header.sequence,
                    });
                }
                budget.admit(&header)?;
                self.have = 0;
                if header.payload_len == 0 {
                    return Ok((
                        take,
                        Some(Frame {
                            header,
                            payload: Vec::new(),
                        }),
                    ));
                }
                self.pending = Some(header);
                Ok((take, None))
            }
            Some(header) => {
                self.payload.reserve_exact(take);
                self.payload.extend_from_slice(input);
                if self.payload.len() < header.payload_len as usize {
                    return Ok((take, None));
                }
                self.pending = None;
                Ok((
                    take,
                    Some(Frame {
                        header,
                        payload: std::mem::take(&mut self.payload),
                    }),
                ))
            }
        }
    }
}
