//! ExecStream's per-execution live queue (API additions design 5 and 5.1).
//!
//! The backend offers live bytes to a [`LiveQueue`] through the non-blocking
//! [`LiveTap`]: the kiln adapter from the helper's live socket, the fake runtime directly.
//! The queue is bounded by `--exec-stream-buffer-bytes` and drops an offer that does not
//! fit; nothing on this path waits, so a client that stops reading only loses live bytes
//! and can never stall capture, the cleanup barrier or terminal publication.
//!
//! The RPC's [`StreamHandle`] drains the queue at whatever pace the transport polls it.
//! Gaps are derived from the capture readers' offsets, so they take no queue space and
//! can never be dropped; the final message has its own slot. Dropping the handle is the
//! client's disconnect.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};

use tokio_util::sync::CancellationToken;

pub use kilnd_exec_core::live::{LiveStream, LiveTap};

use crate::model::Execution;

/// What each queued entry costs beyond its bytes: the deque slot and the allocation, so
/// a command writing one byte at a time cannot hold more memory than the buffer allows.
pub const ENTRY_OVERHEAD: usize = 64;
/// `--exec-stream-buffer-bytes` and `--exec-stream-chunk-bytes` defaults (design 7).
pub const DEFAULT_BUFFER_BYTES: usize = 256 * 1024;
pub const DEFAULT_CHUNK_BYTES: usize = 32 * 1024;
/// The largest chunk a flag may ask for.
pub const MAX_CHUNK_BYTES: usize = 64 * 1024;
/// The helper's ceiling for a live exec (decision 4), which caps `--max-stream-timeout-secs`.
pub const MAX_LIVE_EXEC_MS: u32 = crate::helper::protocol::MAX_LIVE_EXEC_MS;

/// The live path's sizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamBuffer {
    /// The queue's bound, entry overhead included.
    pub buffer_bytes: usize,
    /// The most data one `OutputChunk` carries.
    pub chunk_bytes: usize,
}

impl Default for StreamBuffer {
    fn default() -> Self {
        Self {
            buffer_bytes: DEFAULT_BUFFER_BYTES,
            chunk_bytes: DEFAULT_CHUNK_BYTES,
        }
    }
}

/// One stream's authoritative capture total, from the settled execution outcome.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CaptureTotal {
    pub total_bytes: u64,
    pub known: bool,
}

/// What the supervisor hands over after terminal publication: the row as GetExecution
/// reads it (or why it could not be read) and both capture totals.
pub struct StreamFinal {
    pub execution: Result<Execution, crate::manager::Error>,
    pub stdout: CaptureTotal,
    pub stderr: CaptureTotal,
}

/// One stream's live delivery, reported in `ExecFinished`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Delivery {
    pub delivered_bytes: u64,
    pub dropped_bytes: u64,
    pub dropped_bytes_known: bool,
}

/// One message after `ExecStarted`, in the order the stream carries them.
#[derive(Debug)]
pub enum LiveEvent {
    Chunk {
        stream: LiveStream,
        offset: u64,
        data: Vec<u8>,
    },
    /// Bytes from `offset` that were not delivered. Interior gaps are exact by offset
    /// arithmetic; a tail gap is exact only with an exact capture total.
    Gap {
        stream: LiveStream,
        offset: u64,
        dropped_bytes: u64,
        dropped_bytes_known: bool,
    },
    Finished {
        execution: Box<Result<Execution, crate::manager::Error>>,
        stdout: Delivery,
        stderr: Delivery,
    },
}

#[derive(Debug)]
struct Entry {
    stream: LiveStream,
    offset: u64,
    data: Vec<u8>,
}

impl Entry {
    fn end(&self) -> u64 {
        self.offset + self.data.len() as u64
    }
}

#[derive(Default)]
struct QueueState {
    entries: VecDeque<Entry>,
    /// Accounted bytes: data plus [`ENTRY_OVERHEAD`] per entry.
    queued: usize,
    /// Per stream, the end of the last offer seen; an offer starting before it is a
    /// source fault and is dropped, so offsets the consumer sees only increase.
    offered_end: [u64; 2],
    /// Bytes the queue itself dropped, per stream (diagnostic; gaps come from offsets).
    queue_dropped: [u64; 2],
    finished: Option<StreamFinal>,
    disconnected: bool,
    waker: Option<Waker>,
}

/// The bounded queue between the backend's live source and one ExecStream RPC.
pub struct LiveQueue {
    buffer: StreamBuffer,
    state: Mutex<QueueState>,
    disconnect: CancellationToken,
}

fn index(stream: LiveStream) -> usize {
    match stream {
        LiveStream::Stdout => 0,
        LiveStream::Stderr => 1,
    }
}

impl LiveQueue {
    pub fn new(buffer: StreamBuffer) -> Arc<Self> {
        Arc::new(Self {
            buffer,
            state: Mutex::new(QueueState::default()),
            disconnect: CancellationToken::new(),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, QueueState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The handle the RPC drains. Dropping it disconnects.
    pub fn handle(self: &Arc<Self>) -> StreamHandle {
        StreamHandle {
            queue: Arc::clone(self),
            next: [0; 2],
            delivered: [0; 2],
            dropped: [0; 2],
            held: None,
            last: None,
            tails: 0,
            done: false,
        }
    }

    /// Resolves once the RPC's handle is gone.
    pub async fn disconnected(&self) {
        self.disconnect.cancelled().await
    }

    pub fn is_disconnected(&self) -> bool {
        self.disconnect.is_cancelled()
    }

    /// The final message's reserved slot: never refused, never dropped. Called once,
    /// after terminal publication and after the backend stopped offering.
    pub fn finish(&self, last: StreamFinal) {
        let mut state = self.state();
        if state.disconnected {
            return;
        }
        state.finished = Some(last);
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
    }

    /// Accounted bytes queued now (for tests and Health-like checks).
    pub fn queued_bytes(&self) -> usize {
        self.state().queued
    }

    /// Bytes the queue dropped per stream (stdout, stderr).
    pub fn queue_dropped(&self) -> [u64; 2] {
        self.state().queue_dropped
    }

    fn disconnect(&self) {
        let mut state = self.state();
        state.disconnected = true;
        state.entries.clear();
        state.entries.shrink_to_fit();
        state.queued = 0;
        state.finished = None;
        state.waker = None;
        drop(state);
        self.disconnect.cancel();
    }
}

impl LiveTap for LiveQueue {
    /// Never waits: the lock guards only this in-memory queue and is never held across
    /// an await or I/O. An offer that does not fit whole, chunk by chunk, is dropped.
    fn offer(&self, stream: LiveStream, offset: u64, bytes: &[u8]) {
        let mut state = self.state();
        if state.disconnected || state.finished.is_some() || bytes.is_empty() {
            return;
        }
        let i = index(stream);
        if offset < state.offered_end[i] {
            return;
        }
        state.offered_end[i] = offset + bytes.len() as u64;
        let capacity = self.buffer.buffer_bytes;
        let chunk = self.buffer.chunk_bytes;
        let mut accepted = false;
        for (n, piece) in bytes.chunks(chunk).enumerate() {
            let at = offset + (n * chunk) as u64;
            // Contiguous bytes of the same stream join the last entry, up to one chunk.
            let state = &mut *state;
            if let Some(last) = state.entries.back_mut()
                && last.stream == stream
                && last.end() == at
                && last.data.len() + piece.len() <= chunk
                && state.queued + piece.len() <= capacity
            {
                last.data.extend_from_slice(piece);
                state.queued += piece.len();
                accepted = true;
                continue;
            }
            if state.queued + piece.len() + ENTRY_OVERHEAD > capacity {
                state.queue_dropped[i] += piece.len() as u64;
                continue;
            }
            state.entries.push_back(Entry {
                stream,
                offset: at,
                data: piece.to_vec(),
            });
            state.queued += piece.len() + ENTRY_OVERHEAD;
            accepted = true;
        }
        if accepted && let Some(waker) = state.waker.take() {
            waker.wake();
        }
    }
}

/// The RPC side of one stream: the next events in order. Dropping it is the client's
/// disconnect.
pub struct StreamHandle {
    queue: Arc<LiveQueue>,
    /// Per stream, the offset the next delivered byte must have.
    next: [u64; 2],
    delivered: [u64; 2],
    dropped: [u64; 2],
    /// A chunk held back behind the gap reported before it.
    held: Option<Entry>,
    last: Option<StreamFinal>,
    /// Tail gaps considered so far (stdout, then stderr).
    tails: usize,
    done: bool,
}

impl StreamHandle {
    pub fn queue(&self) -> &Arc<LiveQueue> {
        &self.queue
    }

    fn deliver(&mut self, entry: Entry) -> LiveEvent {
        let i = index(entry.stream);
        self.next[i] = entry.end();
        self.delivered[i] += entry.data.len() as u64;
        LiveEvent::Chunk {
            stream: entry.stream,
            offset: entry.offset,
            data: entry.data,
        }
    }

    /// Takes up to one chunk from the front of the queue: the front entry's bytes and
    /// any contiguous bytes of the same stream after it.
    fn take_chunk(&self, state: &mut QueueState) -> Option<Entry> {
        let chunk = self.queue.buffer.chunk_bytes;
        let mut out: Option<Entry> = None;
        while let Some(front) = state.entries.front_mut() {
            if let Some(out) = &out
                && (front.stream != out.stream
                    || front.offset != out.end()
                    || out.data.len() >= chunk)
            {
                break;
            }
            let room = chunk - out.as_ref().map_or(0, |o| o.data.len());
            let whole = front.data.len() <= room;
            let (stream, offset) = (front.stream, front.offset);
            let piece = if whole {
                state.queued -= front.data.len() + ENTRY_OVERHEAD;
                std::mem::take(&mut front.data)
            } else {
                state.queued -= room;
                let rest = front.data.split_off(room);
                front.offset += room as u64;
                std::mem::replace(&mut front.data, rest)
            };
            if whole {
                state.entries.pop_front();
            }
            match &mut out {
                Some(out) => out.data.extend_from_slice(&piece),
                None => {
                    out = Some(Entry {
                        stream,
                        offset,
                        data: piece,
                    })
                }
            }
            if !whole {
                break;
            }
        }
        out
    }

    /// The tail gap of stream `i` once capture settled, if any: exact only with an exact
    /// capture total. With an inexact total the gap is always reported, its count a
    /// lower bound; kilnd never synthesizes an exact tail from offsets.
    fn tail(&mut self, i: usize, total: CaptureTotal) -> Option<LiveEvent> {
        let end = self.next[i];
        let missing = total.total_bytes.saturating_sub(end);
        if total.known && missing == 0 {
            return None;
        }
        self.dropped[i] += missing;
        Some(LiveEvent::Gap {
            stream: if i == 0 {
                LiveStream::Stdout
            } else {
                LiveStream::Stderr
            },
            offset: end,
            dropped_bytes: missing,
            dropped_bytes_known: total.known,
        })
    }

    /// The next event, or `None` after `Finished`.
    pub fn poll_event(&mut self, cx: &mut Context<'_>) -> Poll<Option<LiveEvent>> {
        if self.done {
            return Poll::Ready(None);
        }
        if let Some(entry) = self.held.take() {
            return Poll::Ready(Some(self.deliver(entry)));
        }
        if self.last.is_none() {
            let queue = Arc::clone(&self.queue);
            let mut state = queue.state();
            if let Some(entry) = self.take_chunk(&mut state) {
                drop(state);
                let i = index(entry.stream);
                if entry.offset > self.next[i] {
                    let missing = entry.offset - self.next[i];
                    let gap = LiveEvent::Gap {
                        stream: entry.stream,
                        offset: self.next[i],
                        dropped_bytes: missing,
                        dropped_bytes_known: true,
                    };
                    self.dropped[i] += missing;
                    self.next[i] = entry.offset;
                    self.held = Some(entry);
                    return Poll::Ready(Some(gap));
                }
                return Poll::Ready(Some(self.deliver(entry)));
            }
            match state.finished.take() {
                Some(last) => self.last = Some(last),
                None => {
                    state.waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
            }
        }
        let (stdout, stderr) = {
            let last = self.last.as_ref().expect("final message taken");
            (last.stdout, last.stderr)
        };
        while self.tails < 2 {
            let i = self.tails;
            self.tails += 1;
            if let Some(gap) = self.tail(i, if i == 0 { stdout } else { stderr }) {
                return Poll::Ready(Some(gap));
            }
        }
        self.done = true;
        let last = self.last.take().expect("final message taken");
        let delivery = |i: usize, total: CaptureTotal| Delivery {
            delivered_bytes: self.delivered[i],
            dropped_bytes: self.dropped[i],
            dropped_bytes_known: total.known,
        };
        Poll::Ready(Some(LiveEvent::Finished {
            stdout: delivery(0, stdout),
            stderr: delivery(1, stderr),
            execution: Box::new(last.execution),
        }))
    }
}

impl Drop for StreamHandle {
    fn drop(&mut self) {
        self.queue.disconnect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;

    fn small(buffer_bytes: usize, chunk_bytes: usize) -> Arc<LiveQueue> {
        LiveQueue::new(StreamBuffer {
            buffer_bytes,
            chunk_bytes,
        })
    }

    fn known(total_bytes: u64) -> CaptureTotal {
        CaptureTotal {
            total_bytes,
            known: true,
        }
    }

    fn finish(queue: &LiveQueue, stdout: CaptureTotal, stderr: CaptureTotal) {
        queue.finish(StreamFinal {
            execution: Err(crate::manager::Error::NotFound("test".into())),
            stdout,
            stderr,
        });
    }

    async fn drain(handle: &mut StreamHandle) -> Vec<LiveEvent> {
        let mut events = Vec::new();
        while let Some(event) = poll_fn(|cx| handle.poll_event(cx)).await {
            events.push(event);
        }
        events
    }

    fn summary(events: &[LiveEvent]) -> Vec<String> {
        events
            .iter()
            .map(|e| match e {
                LiveEvent::Chunk {
                    stream,
                    offset,
                    data,
                } => format!("chunk {stream:?} {offset} {}", data.len()),
                LiveEvent::Gap {
                    stream,
                    offset,
                    dropped_bytes,
                    dropped_bytes_known,
                } => format!("gap {stream:?} {offset} {dropped_bytes} {dropped_bytes_known}"),
                LiveEvent::Finished { stdout, stderr, .. } => format!(
                    "finished {}/{}/{} {}/{}/{}",
                    stdout.delivered_bytes,
                    stdout.dropped_bytes,
                    stdout.dropped_bytes_known,
                    stderr.delivered_bytes,
                    stderr.dropped_bytes,
                    stderr.dropped_bytes_known
                ),
            })
            .collect()
    }

    #[tokio::test]
    async fn contiguous_offers_coalesce_into_bounded_chunks_in_order() {
        let queue = small(4096, 100);
        let mut handle = queue.handle();
        queue.offer(LiveStream::Stdout, 0, &[1; 60]);
        queue.offer(LiveStream::Stdout, 60, &[2; 60]);
        queue.offer(LiveStream::Stderr, 0, &[3; 10]);
        queue.offer(LiveStream::Stdout, 120, &[4; 250]);
        finish(&queue, known(370), known(10));
        let events = drain(&mut handle).await;
        assert_eq!(
            summary(&events),
            [
                "chunk Stdout 0 100",
                "chunk Stdout 100 20",
                "chunk Stderr 0 10",
                "chunk Stdout 120 100",
                "chunk Stdout 220 100",
                "chunk Stdout 320 50",
                "finished 370/0/true 10/0/true",
            ]
        );
        // The bytes are the offered ones, in order.
        let mut stdout = Vec::new();
        for e in &events {
            if let LiveEvent::Chunk {
                stream: LiveStream::Stdout,
                data,
                ..
            } = e
            {
                stdout.extend_from_slice(data);
            }
        }
        let mut expected = vec![1; 60];
        expected.extend([2; 60]);
        expected.extend([4; 250]);
        assert_eq!(stdout, expected);
        assert_eq!(queue.queued_bytes(), 0);
    }

    #[tokio::test]
    async fn a_full_queue_drops_and_the_next_chunk_reports_an_exact_gap_first() {
        // Room for one 100-byte entry and its overhead, no more.
        let queue = small(100 + ENTRY_OVERHEAD, 100);
        let mut handle = queue.handle();
        queue.offer(LiveStream::Stdout, 0, &[0; 100]);
        queue.offer(LiveStream::Stdout, 100, &[0; 50]);
        queue.offer(LiveStream::Stderr, 0, &[0; 1]);
        assert_eq!(queue.queue_dropped(), [50, 1]);
        let first = poll_fn(|cx| handle.poll_event(cx)).await.unwrap();
        assert!(matches!(first, LiveEvent::Chunk { offset: 0, .. }));
        queue.offer(LiveStream::Stdout, 150, &[0; 10]);
        queue.offer(LiveStream::Stderr, 1, &[0; 2]);
        finish(&queue, known(200), known(3));
        assert_eq!(
            summary(&drain(&mut handle).await),
            [
                "gap Stdout 100 50 true",
                "chunk Stdout 150 10",
                "gap Stderr 0 1 true",
                "chunk Stderr 1 2",
                "gap Stdout 160 40 true",
                "finished 110/90/true 2/1/true",
            ]
        );
    }

    #[tokio::test]
    async fn an_inexact_total_makes_a_tail_gap_a_lower_bound_never_exact() {
        let queue = small(4096, 100);
        let mut handle = queue.handle();
        queue.offer(LiveStream::Stdout, 0, &[0; 10]);
        queue.offer(LiveStream::Stdout, 30, &[0; 10]);
        // The helper died after dropping bytes: capture's total is only a lower bound.
        finish(
            &queue,
            CaptureTotal {
                total_bytes: 45,
                known: false,
            },
            CaptureTotal::default(),
        );
        assert_eq!(
            summary(&drain(&mut handle).await),
            [
                "chunk Stdout 0 10",
                "gap Stdout 10 20 true",
                "chunk Stdout 30 10",
                "gap Stdout 40 5 false",
                "gap Stderr 0 0 false",
                "finished 20/25/false 0/0/false",
            ]
        );
    }

    #[tokio::test]
    async fn stale_or_overlapping_offers_are_dropped_and_late_offers_ignored() {
        let queue = small(4096, 100);
        let mut handle = queue.handle();
        queue.offer(LiveStream::Stdout, 10, &[0; 10]);
        queue.offer(LiveStream::Stdout, 15, &[0; 10]);
        queue.offer(LiveStream::Stdout, 0, &[0; 5]);
        finish(&queue, known(20), known(0));
        queue.offer(LiveStream::Stdout, 20, &[0; 5]);
        assert_eq!(
            summary(&drain(&mut handle).await),
            [
                "gap Stdout 0 10 true",
                "chunk Stdout 10 10",
                "finished 10/10/true 0/0/true"
            ]
        );
    }

    #[tokio::test]
    async fn one_byte_writes_are_bounded_by_entry_overhead() {
        let queue = small(16 * 1024, 1024);
        // Alternating streams defeat coalescing; overhead still bounds the entries.
        for offset in 0..100_000u64 {
            queue.offer(LiveStream::Stdout, offset, b"o");
            queue.offer(LiveStream::Stderr, offset, b"e");
        }
        assert!(queue.queued_bytes() <= 16 * 1024);
        assert!(queue.state().entries.len() <= 16 * 1024 / (ENTRY_OVERHEAD + 1));
    }

    #[tokio::test]
    async fn dropping_the_handle_disconnects_and_frees_the_queue() {
        let queue = small(4096, 100);
        let handle = queue.handle();
        queue.offer(LiveStream::Stdout, 0, &[0; 100]);
        assert!(!queue.is_disconnected());
        drop(handle);
        assert!(queue.is_disconnected());
        queue.disconnected().await;
        assert_eq!(queue.queued_bytes(), 0);
        queue.offer(LiveStream::Stdout, 100, &[0; 100]);
        assert_eq!(queue.queued_bytes(), 0);
        finish(&queue, known(200), known(0));
        assert!(queue.state().finished.is_none());
    }

    #[tokio::test]
    async fn a_pending_consumer_is_woken_by_an_offer_and_by_the_final_message() {
        let queue = small(4096, 100);
        let mut handle = queue.handle();
        let waiter = tokio::spawn(async move {
            let events = drain(&mut handle).await;
            summary(&events)
        });
        tokio::task::yield_now().await;
        queue.offer(LiveStream::Stderr, 0, b"hi");
        tokio::task::yield_now().await;
        finish(&queue, known(0), known(2));
        assert_eq!(
            waiter.await.unwrap(),
            ["chunk Stderr 0 2", "finished 0/0/true 2/0/true"]
        );
    }
}
