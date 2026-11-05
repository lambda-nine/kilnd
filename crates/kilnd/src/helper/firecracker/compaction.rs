//! B7's compactor inside L (design section 16.5, RTC-13 and RTC-18; section 16.6's
//! `snapshot`, `advance` and `compact_batch`). Issuance writes nothing here: each pass
//! for an instance first takes at most one checkpoint of the exclusive issue pointer,
//! then raises W to the highest checkpoint one lease old by the boot clock, prunes every
//! checkpoint at or below W, and deletes one bounded batch of compactable rows. Safety
//! never depends on these clocks (RTC-13): they only choose when W moves.
//!
//! The fail-stop marker (`failstop` beside the ledger, RTC-R2-01) also lives here: once
//! any ledger commit fails or a fault commit is uncertain, L writes it, and every later
//! L latches forward effects at open until root's offline clear resets it.
use super::journal::{Advance, CompactBatch, CompactionPolicy, Ledger, LedgerConfig, LedgerError};
use crate::model::Id128;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd};

/// The fail-stop marker's name in the ledger directory and its two 8-byte states. It is
/// only ever rewritten in place at offset 0, so it never needs truncation; any other
/// content (a torn or foreign file) reads as latched.
pub const FAILSTOP_MARKER: &str = "failstop";
const LATCHED: &[u8; 8] = b"latched\n";
const CLEARED: &[u8; 8] = b"cleared\n";

/// Milliseconds on the boot clock: `CLOCK_BOOTTIME` on Linux, which counts suspend and
/// restarts at a reboot; `CLOCK_MONOTONIC` elsewhere. Test builds add the fixture's
/// injected offset, which may step either way. No wall clock is ever read (RTC-13).
pub fn boot_ms() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    #[cfg(target_os = "linux")]
    let clock = libc::CLOCK_BOOTTIME;
    #[cfg(not(target_os = "linux"))]
    let clock = libc::CLOCK_MONOTONIC;
    // SAFETY: time is writable and the clock ID is valid on this target.
    let real = if unsafe { libc::clock_gettime(clock, &mut time) } == 0 {
        (time.tv_sec as u64)
            .saturating_mul(1000)
            .saturating_add(time.tv_nsec as u64 / 1_000_000)
    } else {
        0
    };
    #[cfg(test)]
    {
        let offset = super::workers::faults::read("L.boot_clock_offset_ms")
            .and_then(|text| text.trim().parse::<i64>().ok())
            .unwrap_or(0);
        real.saturating_add_signed(offset)
    }
    #[cfg(not(test))]
    real
}

/// One pass's answer, on the compaction lane.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactReply {
    pub advanced: Option<Advance>,
    pub batch: CompactBatch,
    pub checkpoints: u64,
    /// Due again at once: a full batch, or compactable rows left after an advance.
    pub more: bool,
}

/// L's in-memory checkpoints: (exclusive pointer, boot ms), oldest first.
pub struct Compactor {
    policy: CompactionPolicy,
    points: HashMap<Id128, VecDeque<(u64, u64)>>,
    /// Tokens a batch could not compact, for Health. Bounded by the instances.
    stuck: HashMap<Id128, Vec<Id128>>,
}

impl Compactor {
    /// After any L start the only checkpoint per instance is (issue_next, now), so
    /// nothing advances for one lease (RTC-13).
    pub fn start(policy: CompactionPolicy, ledger: Option<&Ledger>, now: u64) -> Self {
        let mut points = HashMap::new();
        if let Some(ledger) = ledger
            && let Ok(instances) = ledger.instance_ids()
        {
            for instance in instances {
                if let Ok(pointers) = ledger.pointers(instance) {
                    points.insert(instance, VecDeque::from([(pointers.issue_next, now)]));
                }
            }
        }
        Self {
            policy,
            points,
            stuck: HashMap::new(),
        }
    }

    pub fn bound(&self) -> usize {
        self.policy.checkpoint_bound()
    }

    /// RTC-13's snapshot, with RTC-R2-02's empty-list rule: an empty list appends
    /// (issue_next, now); otherwise a point is added only when the pointer moved since
    /// the newest point and that point is at least one pass old, and at the bound the
    /// newest point is overwritten, which only delays maturity.
    pub fn snapshot(&mut self, instance: Id128, issue_next: u64, now: u64) {
        let bound = self.bound();
        let pass = self.policy.pass_ms;
        let list = self.points.entry(instance).or_default();
        match list.back().copied() {
            None => list.push_back((issue_next, now)),
            Some((pointer, time)) if issue_next > pointer && now.saturating_sub(time) >= pass => {
                if list.len() >= bound {
                    *list.back_mut().expect("nonempty") = (issue_next, now);
                } else {
                    list.push_back((issue_next, now));
                }
            }
            Some(_) => {}
        }
    }

    /// The highest checkpoint pointer at least one lease old, if any.
    pub fn matured(&self, instance: Id128, now: u64) -> Option<u64> {
        self.points.get(&instance).and_then(|list| {
            list.iter()
                .filter(|(_, time)| now.saturating_sub(*time) >= self.policy.lease_ms)
                .map(|(pointer, _)| *pointer)
                .max()
        })
    }

    /// Drops every checkpoint at or below W.
    pub fn prune(&mut self, instance: Id128, watermark: u64) {
        if let Some(list) = self.points.get_mut(&instance) {
            list.retain(|(pointer, _)| *pointer > watermark);
        }
    }

    pub fn checkpoints(&self, instance: Id128) -> u64 {
        self.points.get(&instance).map_or(0, |list| list.len() as u64)
    }

    /// How long the oldest checkpoint above W has waited: the compaction lag.
    pub fn lag_ms(&self, instance: Id128, now: u64) -> u64 {
        self.points
            .get(&instance)
            .and_then(|list| list.front())
            .map_or(0, |(_, time)| now.saturating_sub(*time))
    }

    pub fn lease_ms(&self) -> u64 {
        self.policy.lease_ms
    }

    pub fn stuck(&self) -> impl Iterator<Item = (&Id128, &Vec<Id128>)> {
        self.stuck.iter().filter(|(_, tokens)| !tokens.is_empty())
    }

    /// One compaction pass for one instance (RTC-13, RTC-18): checkpoint, advance, prune,
    /// then one delete transaction of at most `max_tokens` tokens.
    pub fn pass(
        &mut self,
        ledger: &mut Ledger,
        instance: Id128,
        max_tokens: u64,
        now: u64,
    ) -> Result<CompactReply, LedgerError> {
        let pointers = ledger.pointers(instance)?;
        self.snapshot(instance, pointers.issue_next, now);
        let target = self
            .matured(instance, now)
            .map_or(pointers.watermark, |pointer| pointer.min(pointers.issue_next))
            .max(pointers.watermark);
        let advanced = ledger.advance_watermark(instance, target)?;
        let watermark = advanced.map_or(pointers.watermark, |a| a.to);
        self.prune(instance, watermark);
        let batch = ledger.compact_batch(instance, max_tokens.max(1))?;
        self.stuck.insert(instance, batch.stuck.clone());
        Ok(CompactReply {
            more: batch.more,
            advanced,
            checkpoints: self.checkpoints(instance),
            batch,
        })
    }
}

fn ledger_directory(config: &LedgerConfig) -> Result<super::executable::ProtectedDir, LedgerError> {
    super::executable::walk_directory(&config.policy, &config.directory)
        .map_err(|e| LedgerError::Unsafe(e.to_string()))
}

/// Whether the fail-stop marker latches: present with anything but "cleared".
pub fn failstop_latched(config: &LedgerConfig) -> Result<bool, LedgerError> {
    let directory = ledger_directory(config)?;
    let name = CString::new(FAILSTOP_MARKER).expect("no NUL");
    // SAFETY: directory and name are live; O_NOFOLLOW refuses a symlink.
    let fd = unsafe {
        libc::openat(
            directory.file().as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(false);
        }
        return Ok(true);
    }
    // SAFETY: openat returned a new owned descriptor.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut content = Vec::new();
    use std::io::Read;
    if (&file).take(64).read_to_end(&mut content).is_err() {
        return Ok(true);
    }
    Ok(content.as_slice() != CLEARED)
}

/// Writes the marker's state in place and syncs it and its directory. Only L (latch)
/// and root's offline clear (reset) call this.
pub fn write_failstop(config: &LedgerConfig, latched: bool) -> Result<(), LedgerError> {
    let directory = ledger_directory(config)?;
    let name = CString::new(FAILSTOP_MARKER).expect("no NUL");
    // SAFETY: directory and name are live; O_NOFOLLOW refuses a symlink, and there is
    // no O_TRUNC: the 8-byte state is rewritten in place.
    let fd = unsafe {
        libc::openat(
            directory.file().as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: openat returned a new owned descriptor.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let bytes = if latched { LATCHED } else { CLEARED };
    use std::os::unix::fs::FileExt;
    file.write_all_at(bytes, 0)?;
    file.sync_all()?;
    directory.file().sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compactor(lease: u64, pass: u64) -> Compactor {
        Compactor {
            policy: CompactionPolicy {
                lease_ms: lease,
                pass_ms: pass,
            },
            points: HashMap::new(),
            stuck: HashMap::new(),
        }
    }

    #[test]
    fn rtc13_checkpoints_stay_bounded_under_any_issuance_rate() {
        let mut c = compactor(900_000, 60_000);
        let i = Id128::from_bytes([1; 16]);
        assert_eq!(c.bound(), 17);
        let mut pointer = 1;
        // A flood: a thousand issuances per second for an hour, no W movement.
        for second in 0..3600u64 {
            pointer += 1000;
            c.snapshot(i, pointer, second * 1000);
            assert!(c.checkpoints(i) as usize <= 17);
        }
        assert_eq!(c.checkpoints(i), 17, "the bound is reached and held");
        // Overflow overwrote the newest point with a later pointer and time, which only
        // delays maturity: one more pass after the flood takes the final pointer, and it
        // matures one lease later.
        c.snapshot(i, pointer, 3600 * 1000 + 60_000);
        assert_eq!(c.checkpoints(i), 17);
        assert_eq!(c.matured(i, 3600 * 1000 + 60_000 + 899_999).map(|p| p < pointer), Some(true));
        assert_eq!(c.matured(i, 3600 * 1000 + 60_000 + 900_000), Some(pointer));
    }

    #[test]
    fn rtc13_nothing_matures_before_a_lease_and_pruning_follows_w() {
        let mut c = compactor(900_000, 60_000);
        let i = Id128::from_bytes([1; 16]);
        c.snapshot(i, 10, 0);
        c.snapshot(i, 20, 30_000); // under a pass: nothing recorded
        assert_eq!(c.checkpoints(i), 1);
        c.snapshot(i, 20, 60_000);
        assert_eq!(c.checkpoints(i), 2);
        assert_eq!(c.matured(i, 899_999), None);
        assert_eq!(c.matured(i, 900_000), Some(10));
        assert_eq!(c.matured(i, 960_000), Some(20));
        c.prune(i, 20);
        assert_eq!(c.checkpoints(i), 0);
    }

    #[test]
    fn rtc_r2_02_an_empty_list_takes_the_next_pointer_at_once() {
        let mut c = compactor(900_000, 60_000);
        let i = Id128::from_bytes([1; 16]);
        c.snapshot(i, 5, 0);
        c.prune(i, 5);
        assert_eq!(c.checkpoints(i), 0, "fully idle and drained");
        // One token is issued much later: the very next pass records it.
        c.snapshot(i, 6, 10_000_000);
        assert_eq!(c.checkpoints(i), 1);
        assert_eq!(c.matured(i, 10_000_000 + 900_000), Some(6));
    }

    #[test]
    fn rtc13_a_stepped_clock_changes_only_when_w_moves() {
        let mut c = compactor(900_000, 60_000);
        let i = Id128::from_bytes([1; 16]);
        c.snapshot(i, 10, 1_000_000);
        // A step back: nothing matures, nothing is lost.
        assert_eq!(c.matured(i, 0), None);
        c.snapshot(i, 11, 0);
        assert_eq!(c.checkpoints(i), 1, "no pass has elapsed on a stepped-back clock");
        // A day forward: everything recorded so far matures at once, nothing beyond.
        assert_eq!(c.matured(i, 86_400_000), Some(10));
    }
}
