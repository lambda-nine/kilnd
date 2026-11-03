//! The console drainer D (sections 5.6 and 6.4). One per allocation, forked by S after
//! BOOTING into the allocation's `vm/console` leaf (whose `cpu.max` is the contract's
//! 5 ms per 100 ms, the 50 CPU-millis-per-second cap) and dropped to the VMM's own
//! UID/GID, holding only the console pipe and a one-byte report pipe to S.
//!
//! The serial console is a hostile source. D reads it continuously **to EOF** in 64 KiB
//! quanta, keeps only the first 64 KiB and checked counters, and discards everything
//! after the prefix rather than ceasing to read, so a full pipe cannot block the VMM's
//! stop path. Traffic beyond 1 MiB/s sustained with a 256 KiB burst is reported once
//! (`R`), and S retires the VM; D keeps draining under its CPU cap until the VM is gone.
//! A counter overflow is reported (`O`) the same way. D's own death also retires the
//! VM: S watches it.

use std::time::Instant;

pub const PREFIX: usize = 64 * 1024;
pub const QUANTUM: usize = 64 * 1024;
pub const RATE_BYTES_PER_SECOND: u64 = 1024 * 1024;
pub const BURST_BYTES: u64 = 256 * 1024;

/// Report bytes D writes to S.
pub const REPORT_RATE: u8 = b'R';
pub const REPORT_OVERFLOW: u8 = b'O';

/// The token bucket and counters, separate from I/O so they can be tested exactly.
#[derive(Debug)]
pub struct Meter {
    tokens: u64,
    last: Instant,
    pub total: u64,
    pub prefix: Vec<u8>,
    pub breached: bool,
}

impl Meter {
    pub fn new(now: Instant) -> Self {
        Self {
            tokens: BURST_BYTES,
            last: now,
            total: 0,
            prefix: Vec::new(),
            breached: false,
        }
    }

    /// Accounts one read. Returns a report byte the first time a bound is crossed.
    pub fn observe(&mut self, bytes: &[u8], now: Instant) -> Option<u8> {
        let elapsed = now.saturating_duration_since(self.last);
        self.last = now;
        let refill = (elapsed.as_nanos().min(u128::from(u64::MAX))
            * u128::from(RATE_BYTES_PER_SECOND)
            / 1_000_000_000) as u64;
        self.tokens = self.tokens.saturating_add(refill).min(BURST_BYTES);
        let room = PREFIX.saturating_sub(self.prefix.len());
        self.prefix
            .extend_from_slice(&bytes[..bytes.len().min(room)]);
        let Some(total) = self.total.checked_add(bytes.len() as u64) else {
            return self.breach(REPORT_OVERFLOW);
        };
        self.total = total;
        match self.tokens.checked_sub(bytes.len() as u64) {
            Some(left) => {
                self.tokens = left;
                None
            }
            None => {
                self.tokens = 0;
                self.breach(REPORT_RATE)
            }
        }
    }

    fn breach(&mut self, report: u8) -> Option<u8> {
        if self.breached {
            return None;
        }
        self.breached = true;
        Some(report)
    }
}

/// D's whole life: drain to EOF, report a breach once, exit on EOF.
#[cfg(unix)]
pub fn drainer_main(console: std::os::fd::OwnedFd, report: std::os::fd::OwnedFd) {
    use std::os::fd::AsRawFd;
    let mut meter = Meter::new(Instant::now());
    let mut chunk = vec![0u8; QUANTUM];
    loop {
        let mut entry = libc::pollfd {
            fd: console.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live pollfd.
        unsafe { libc::poll(&mut entry, 1, 1000) };
        // SAFETY: chunk is writable for its length; the descriptor is owned.
        let n = unsafe { libc::read(console.as_raw_fd(), chunk.as_mut_ptr().cast(), chunk.len()) };
        if n == 0 {
            return;
        }
        if n < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) {
                continue;
            }
            return;
        }
        if let Some(byte) = meter.observe(&chunk[..n as usize], Instant::now()) {
            // SAFETY: one readable byte; the report pipe is owned and nonblocking.
            unsafe { libc::write(report.as_raw_fd(), [byte].as_ptr().cast(), 1) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn the_prefix_is_kept_and_the_rest_counted() {
        let start = Instant::now();
        let mut meter = Meter::new(start);
        for i in 0..4 {
            meter.observe(&[i as u8; 30_000], start + Duration::from_secs(i));
        }
        assert_eq!(meter.prefix.len(), PREFIX);
        assert_eq!(meter.total, 120_000);
        assert!(!meter.breached);
    }

    #[test]
    fn a_burst_is_allowed_and_sustained_excess_is_reported_once() {
        let start = Instant::now();
        let mut meter = Meter::new(start);
        // 256 KiB at once is the burst.
        assert_eq!(meter.observe(&vec![0; 256 * 1024], start), None);
        // 1 MiB/s sustained for ten seconds stays within the rate.
        for tenth in 1..=100u64 {
            let at = start + Duration::from_millis(100 * tenth);
            assert_eq!(meter.observe(&vec![0; 100 * 1024], at), None, "{tenth}");
        }
        // A second's worth more in one instant crosses it, once.
        let at = start + Duration::from_secs(10);
        assert_eq!(meter.observe(&vec![0; 300 * 1024], at), Some(REPORT_RATE));
        assert_eq!(meter.observe(&vec![0; 300 * 1024], at), None);
        assert!(meter.breached);
    }

    #[test]
    fn counter_overflow_is_a_breach() {
        let start = Instant::now();
        let mut meter = Meter::new(start);
        meter.total = u64::MAX - 1;
        assert_eq!(meter.observe(&[0; 2], start), Some(REPORT_OVERFLOW));
    }
}
