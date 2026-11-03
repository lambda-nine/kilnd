//! Frame I/O over a byte stream with absolute deadlines (design 5.6). Timers start
//! before the first byte; a frame, once due, must arrive whole by its deadline, and
//! trickled bytes never extend it. Reads never go past the frame in progress, and
//! every write has a settlement deadline, so a never-reading peer cannot pin a worker.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, timeout_at};

use crate::budget::Budget;
use crate::error::{ProtocolError, Result, Stage};
use crate::frame::{Frame, FrameDecoder, Sequence, encode_frame};
use crate::header::{Direction, Kind};
use crate::message::Message;
use crate::types::Id128;

/// Reads are issued at most this large; the decoder caps each at the bytes it wants.
const READ_CHUNK: usize = 16 * 1024;

/// When the next frame must arrive.
#[derive(Clone, Copy, Debug)]
pub enum Due {
    /// The whole frame by this instant.
    By(Instant),
    /// The first byte by `first`, then the whole frame within `then` of that byte,
    /// never later than `first + then`. For a reply that waits on a long command.
    FirstByte { first: Instant, then: Duration },
}

/// Reads frames travelling `direction` from `R`.
pub struct FrameReader<R> {
    inner: R,
    decoder: FrameDecoder,
    first_byte_at: Option<Instant>,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    pub fn new(inner: R, direction: Direction) -> Self {
        Self::with_decoder(inner, FrameDecoder::new(direction))
    }

    pub fn with_decoder(inner: R, decoder: FrameDecoder) -> Self {
        Self {
            inner,
            decoder,
            first_byte_at: None,
        }
    }

    /// When the first byte of the last frame read with [`Due::FirstByte`] arrived.
    pub fn first_byte_at(&self) -> Option<Instant> {
        self.first_byte_at
    }

    /// Bytes the decoder holds.
    pub fn held(&self) -> usize {
        self.decoder.held()
    }

    pub fn into_inner(self) -> R {
        self.inner
    }

    /// The next frame, or `None` on a clean EOF at a frame boundary. The budget is
    /// charged from the header before any payload byte is read.
    pub async fn read_frame<B: Budget + ?Sized>(
        &mut self,
        due: Due,
        budget: &mut B,
    ) -> Result<Option<Frame>> {
        let mut deadline = match due {
            Due::By(at) => at,
            Due::FirstByte { first, .. } => first,
        };
        let mut started = false;
        let mut buf = [0u8; READ_CHUNK];
        loop {
            let want = self.decoder.wanted().min(READ_CHUNK);
            let n = match timeout_at(deadline, self.inner.read(&mut buf[..want])).await {
                Err(_) => {
                    return Err(ProtocolError::Timeout(if started {
                        Stage::Frame
                    } else {
                        Stage::FirstByte
                    }));
                }
                Ok(Err(error)) => return Err(error.into()),
                Ok(Ok(n)) => n,
            };
            if n == 0 {
                self.decoder.finish()?;
                return Ok(None);
            }
            if !started {
                started = true;
                if let Due::FirstByte { first, then } = due {
                    let now = Instant::now();
                    self.first_byte_at = Some(now);
                    deadline = (now + then).min(first + then);
                }
            }
            let (consumed, frame) = self.decoder.feed(&buf[..n], budget)?;
            debug_assert_eq!(consumed, n, "reads never exceed the decoder's want");
            if let Some(frame) = frame {
                return Ok(Some(frame));
            }
        }
    }

    /// The clean end of stream after a terminal frame. A byte instead is trailing data.
    pub async fn read_eof(&mut self, by: Instant) -> Result<()> {
        let mut buf = [0u8; 1];
        match timeout_at(by, self.inner.read(&mut buf)).await {
            Err(_) => Err(ProtocolError::Timeout(Stage::Eof)),
            Ok(Err(error)) => Err(error.into()),
            Ok(Ok(0)) => Ok(()),
            Ok(Ok(_)) => Err(ProtocolError::TrailingBytes),
        }
    }
}

/// Writes frames travelling `direction` to `W`, numbering them from zero.
pub struct FrameWriter<W> {
    inner: W,
    direction: Direction,
    sequence: Sequence,
}

impl<W: AsyncWrite + Unpin> FrameWriter<W> {
    pub fn new(inner: W, direction: Direction) -> Self {
        Self::with_sequence(inner, direction, Sequence::default())
    }

    pub fn with_sequence(inner: W, direction: Direction, sequence: Sequence) -> Self {
        Self {
            inner,
            direction,
            sequence,
        }
    }

    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Validates, encodes and writes one message; the whole frame by `by`.
    pub async fn send(&mut self, request_id: Id128, message: &Message, by: Instant) -> Result<()> {
        let payload = message.encode_payload()?;
        self.send_raw(message.kind(), request_id, &payload, by)
            .await
    }

    /// Writes one frame of `kind` with an already encoded payload.
    pub async fn send_raw(
        &mut self,
        kind: Kind,
        request_id: Id128,
        payload: &[u8],
        by: Instant,
    ) -> Result<()> {
        if kind.direction() != self.direction {
            return Err(ProtocolError::WrongDirection {
                kind,
                direction: self.direction,
            });
        }
        let mut next = self.sequence;
        let frame = encode_frame(kind, request_id, next.take()?, payload)?;
        match timeout_at(by, async {
            self.inner.write_all(&frame).await?;
            self.inner.flush().await
        })
        .await
        {
            Err(_) => Err(ProtocolError::Timeout(Stage::Write)),
            Ok(Err(error)) => Err(error.into()),
            Ok(Ok(())) => {
                self.sequence = next;
                Ok(())
            }
        }
    }

    /// Closes the write half (a clean EOF for the peer) by `by`.
    pub async fn finish(&mut self, by: Instant) -> Result<()> {
        match timeout_at(by, self.inner.shutdown()).await {
            Err(_) => Err(ProtocolError::Timeout(Stage::Write)),
            Ok(Err(error)) => Err(error.into()),
            Ok(Ok(())) => Ok(()),
        }
    }
}
