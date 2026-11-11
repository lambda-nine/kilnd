//! The live output tap (API additions design 5.1).
//!
//! A capture reader counts and retains each read first, then offers the same bytes to an
//! optional [`LiveTap`]. The tap is an observer: it cannot fail, await or apply
//! backpressure, and the readers stay the only count authority. A tap that refuses every
//! offer, or panics, leaves the capture evidence byte-identical to a capture without one.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Which output stream a live offer belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LiveStream {
    Stdout,
    Stderr,
}

impl LiveStream {
    /// The stream's byte in the helper's live message (`1` stdout, `2` stderr), which is
    /// also its `OutputStream` number in the API.
    pub fn code(self) -> u8 {
        match self {
            Self::Stdout => 1,
            Self::Stderr => 2,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Stdout),
            2 => Some(Self::Stderr),
            _ => None,
        }
    }
}

/// A non-blocking observer of captured output.
///
/// `offer` is called by a capture reader after it counted and retained `bytes`, which
/// start at byte `offset` of `stream` as that reader observed it. An implementation must
/// return promptly without waiting for I/O, a lock held across I/O or another task, and
/// may drop any offer; offsets alone tell the consumer what it missed.
pub trait LiveTap: Send + Sync {
    fn offer(&self, stream: LiveStream, offset: u64, bytes: &[u8]);
}

/// The tap one capture reader holds. A panic inside `offer` disables the tap for that
/// reader instead of unwinding into it, so a faulty tap cannot change capture evidence.
pub struct ReaderTap {
    tap: Arc<dyn LiveTap>,
    stream: LiveStream,
    failed: AtomicBool,
}

impl ReaderTap {
    pub fn new(tap: Arc<dyn LiveTap>, stream: LiveStream) -> Self {
        Self {
            tap,
            stream,
            failed: AtomicBool::new(false),
        }
    }

    /// Offers `bytes` at `offset`; never fails and never unwinds.
    pub fn offer(&self, offset: u64, bytes: &[u8]) {
        if bytes.is_empty() || self.failed.load(Ordering::Relaxed) {
            return;
        }
        if catch_unwind(AssertUnwindSafe(|| {
            self.tap.offer(self.stream, offset, bytes)
        }))
        .is_err()
        {
            self.failed.store(true, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recording(Mutex<Vec<(LiveStream, u64, Vec<u8>)>>);

    impl LiveTap for Recording {
        fn offer(&self, stream: LiveStream, offset: u64, bytes: &[u8]) {
            self.0
                .lock()
                .unwrap()
                .push((stream, offset, bytes.to_vec()));
        }
    }

    struct Panicking;

    impl LiveTap for Panicking {
        fn offer(&self, _: LiveStream, _: u64, _: &[u8]) {
            panic!("injected live tap panic");
        }
    }

    #[test]
    fn stream_codes_round_trip_and_reject_others() {
        for stream in [LiveStream::Stdout, LiveStream::Stderr] {
            assert_eq!(LiveStream::from_code(stream.code()), Some(stream));
        }
        for code in [0, 3, 0xff] {
            assert_eq!(LiveStream::from_code(code), None);
        }
    }

    #[test]
    fn reader_tap_skips_empty_offers_and_survives_a_panicking_tap() {
        let recording = Arc::new(Recording::default());
        let tap = ReaderTap::new(recording.clone(), LiveStream::Stderr);
        tap.offer(0, b"");
        tap.offer(0, b"ab");
        tap.offer(2, b"c");
        assert_eq!(
            *recording.0.lock().unwrap(),
            vec![
                (LiveStream::Stderr, 0, b"ab".to_vec()),
                (LiveStream::Stderr, 2, b"c".to_vec())
            ]
        );
        let panicking = ReaderTap::new(Arc::new(Panicking), LiveStream::Stdout);
        panicking.offer(0, b"x");
        assert!(panicking.failed.load(Ordering::Relaxed));
        // Disabled: no second panic, no unwinding.
        panicking.offer(1, b"y");
    }
}
