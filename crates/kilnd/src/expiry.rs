//! Sandbox expiry: the clocks it reads, its policy rules and the bounded timer queue
//! the manager's sweeper owns (API additions design, section 2).
//!
//! Every decision within one boot reads `CLOCK_BOOTTIME`, which counts suspend and
//! never steps with the wall clock. A deadline is `anchor + limit` in boottime. The
//! wall clock is read only for display projections, for the anchors' wall copies and
//! once per row by the startup cross-boot rebase.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use crate::model::{ExpiryPolicy, Sandbox, SandboxState};

/// The shortest lifetime or idle timeout a request may ask for, in ms.
pub const MIN_EXPIRY_MS: u64 = 10_000;
/// A Renew this soon after the last durable activity writes nothing.
pub const RENEW_COALESCE_MS: i64 = 1_000;
/// Expiry removal retry backoff.
pub const RETRY_MIN: Duration = Duration::from_secs(5);
pub const RETRY_MAX: Duration = Duration::from_secs(300);

/// The clocks expiry reads. Injectable so tests can step the wall clock, suspend
/// (advance boottime alone) and reboot (change the boot ID).
pub trait Clock: Send + Sync + 'static {
    /// Unix wall-clock milliseconds.
    fn wall_ms(&self) -> i64;
    /// `CLOCK_BOOTTIME` milliseconds: monotonic, counting suspend.
    fn boottime_ms(&self) -> i64;
    /// The kernel's ID for this boot.
    fn boot_id(&self) -> String;
}

/// One reading of all three clocks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClockReading {
    pub wall_ms: i64,
    pub boottime_ms: i64,
    pub boot_id: String,
}

impl ClockReading {
    pub fn now(clock: &dyn Clock) -> Self {
        Self {
            wall_ms: clock.wall_ms(),
            boottime_ms: clock.boottime_ms(),
            boot_id: clock.boot_id(),
        }
    }
}

/// The host's clocks. The boot ID is read once, at construction.
pub struct SystemClock {
    boot_id: String,
}

impl SystemClock {
    /// Fails if the kernel's boot ID cannot be read: without it no boottime anchor
    /// could be told apart from another boot's.
    pub fn new() -> std::io::Result<Self> {
        Ok(Self {
            boot_id: read_boot_id()?,
        })
    }
}

#[cfg(target_os = "linux")]
fn read_boot_id() -> std::io::Result<String> {
    let text = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let id = text.trim();
    if id.len() != 36 || !id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed kernel boot ID",
        ));
    }
    Ok(id.to_string())
}

/// kilnd serves only on Linux; elsewhere (unit tests on a development Mac) one
/// process is one boot.
#[cfg(not(target_os = "linux"))]
fn read_boot_id() -> std::io::Result<String> {
    Ok(format!("process-{}", std::process::id()))
}

impl Clock for SystemClock {
    fn wall_ms(&self) -> i64 {
        crate::model::now_ms()
    }

    fn boottime_ms(&self) -> i64 {
        #[cfg(target_os = "linux")]
        let id = libc::CLOCK_BOOTTIME;
        // macOS's CLOCK_MONOTONIC keeps counting while asleep.
        #[cfg(not(target_os = "linux"))]
        let id = libc::CLOCK_MONOTONIC;
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: a valid clock ID and a live timespec.
        let rc = unsafe { libc::clock_gettime(id, &mut ts) };
        assert_eq!(rc, 0, "clock_gettime(CLOCK_BOOTTIME) failed");
        // time_t and c_long are 64-bit on every target kilnd serves.
        ts.tv_sec
            .saturating_mul(1000)
            .saturating_add(ts.tv_nsec / 1_000_000)
    }

    fn boot_id(&self) -> String {
        self.boot_id.clone()
    }
}

/// A clock tests drive by hand. Cloning shares it.
#[derive(Clone)]
pub struct ManualClock {
    inner: Arc<ManualInner>,
}

struct ManualInner {
    wall: AtomicI64,
    boot: AtomicI64,
    boot_id: std::sync::Mutex<String>,
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new(1_800_000_000_000, 1_000_000, "boot-a")
    }
}

impl ManualClock {
    pub fn new(wall_ms: i64, boottime_ms: i64, boot_id: &str) -> Self {
        Self {
            inner: Arc::new(ManualInner {
                wall: AtomicI64::new(wall_ms),
                boot: AtomicI64::new(boottime_ms),
                boot_id: std::sync::Mutex::new(boot_id.into()),
            }),
        }
    }

    /// Real time passes: both clocks advance.
    pub fn advance(&self, ms: i64) {
        self.inner.wall.fetch_add(ms, Ordering::SeqCst);
        self.inner.boot.fetch_add(ms, Ordering::SeqCst);
    }

    /// An NTP or administrator step of the wall clock alone.
    pub fn step_wall(&self, ms: i64) {
        self.inner.wall.fetch_add(ms, Ordering::SeqCst);
    }

    /// A reboot: a new boot ID and boottime from `boottime_ms`; wall time advances
    /// by `down_ms`.
    pub fn reboot(&self, boot_id: &str, boottime_ms: i64, down_ms: i64) {
        *self.inner.boot_id.lock().unwrap() = boot_id.into();
        self.inner.boot.store(boottime_ms, Ordering::SeqCst);
        self.inner.wall.fetch_add(down_ms, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn wall_ms(&self) -> i64 {
        self.inner.wall.load(Ordering::SeqCst)
    }

    fn boottime_ms(&self) -> i64 {
        self.inner.boot.load(Ordering::SeqCst)
    }

    fn boot_id(&self) -> String {
        self.inner.boot_id.lock().unwrap().clone()
    }
}

/// Expiry limits, from the node flags (design section 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpiryLimits {
    /// 0: no cap.
    pub max_lifetime_ms: u64,
    /// 0: no cap.
    pub max_idle_ms: u64,
    /// For a zero field of a present policy. 0: never.
    pub default_lifetime_ms: u64,
    pub default_idle_ms: u64,
    pub restart_grace: Duration,
    pub degraded_after: Duration,
    pub rescan: Duration,
    pub max_concurrent_deletes: usize,
}

impl Default for ExpiryLimits {
    fn default() -> Self {
        Self {
            max_lifetime_ms: 7 * 86_400_000,
            max_idle_ms: 86_400_000,
            default_lifetime_ms: 0,
            default_idle_ms: 0,
            restart_grace: Duration::from_secs(60),
            degraded_after: Duration::from_secs(600),
            rescan: Duration::from_secs(30),
            max_concurrent_deletes: 4,
        }
    }
}

/// What a client sent in `CreateSandboxRequest.expiry`, if it sent one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RequestedExpiry {
    pub max_lifetime_ms: u64,
    pub idle_timeout_ms: u64,
}

/// Decision 2, exactly: an absent policy never expires, whatever the node says. A
/// present policy's nonzero field is used as given within [10 s, node max]; a zero
/// field takes the node default for that field (0: never).
pub fn resolve_expiry(
    requested: Option<RequestedExpiry>,
    limits: &ExpiryLimits,
) -> Result<ExpiryPolicy, String> {
    let Some(requested) = requested else {
        return Ok(ExpiryPolicy::default());
    };
    let field = |name: &str, value: u64, default: u64, max: u64| -> Result<Option<u64>, String> {
        if value == 0 {
            return Ok((default != 0).then_some(default));
        }
        if value < MIN_EXPIRY_MS {
            return Err(format!(
                "expiry.{name} {value} ms is below the minimum of {MIN_EXPIRY_MS} ms"
            ));
        }
        if max != 0 && value > max {
            return Err(format!(
                "expiry.{name} {value} ms is above the node maximum of {max} ms"
            ));
        }
        Ok(Some(value))
    };
    Ok(ExpiryPolicy {
        max_lifetime_ms: field(
            "max_lifetime_ms",
            requested.max_lifetime_ms,
            limits.default_lifetime_ms,
            limits.max_lifetime_ms,
        )?,
        idle_timeout_ms: field(
            "idle_timeout_ms",
            requested.idle_timeout_ms,
            limits.default_idle_ms,
            limits.max_idle_ms,
        )?,
    })
}

/// States whose deadlines run (design 2.1): a lost or quarantined sandbox still
/// holds a reservation, and expiry is how a vanished client's charge comes back.
pub fn deadlines_run(state: SandboxState) -> bool {
    matches!(
        state,
        SandboxState::Ready | SandboxState::Lost | SandboxState::Quarantined
    )
}

/// Whether expiry may publish a delete intent for this row at all. A legacy row
/// without a backend ID is an ambiguous reservation Delete refuses, so it is never
/// an expiry target; it stays charged for reconciliation.
pub fn is_target(s: &Sandbox) -> bool {
    deadlines_run(s.state)
        && s.lifecycle.expiry.expires()
        && s.lifecycle.ready_boottime_ms.is_some()
        && (s.is_fenced() || s.backend_id.is_some())
}

/// The lifetime deadline in boottime: absolute from the first READY.
pub fn lifetime_deadline(s: &Sandbox) -> Option<i64> {
    let limit = i64::try_from(s.lifecycle.expiry.max_lifetime_ms?).ok()?;
    Some(s.lifecycle.ready_boottime_ms?.saturating_add(limit))
}

/// The idle deadline in boottime, from the later of READY and the last activity,
/// never before `grace_until` (the restart grace). Callers drop it while paused.
pub fn idle_deadline(s: &Sandbox, grace_until: i64) -> Option<i64> {
    let limit = i64::try_from(s.lifecycle.expiry.idle_timeout_ms?).ok()?;
    let ready = s.lifecycle.ready_boottime_ms?;
    let anchor = s.lifecycle.activity_boottime_ms.unwrap_or(ready).max(ready);
    Some(anchor.saturating_add(limit).max(grace_until))
}

/// The retry delay after `failures` consecutive failed removals (at least one).
pub fn retry_delay(failures: u32) -> Duration {
    let factor = 1u32 << failures.saturating_sub(1).min(16);
    RETRY_MIN.saturating_mul(factor).min(RETRY_MAX)
}

/// The sandbox key: the 64-bit value of its 16 hex digits.
pub fn key(id: &str) -> Option<u64> {
    let hex = id.strip_prefix("sb-")?;
    (hex.len() == 16)
        .then(|| u64::from_str_radix(hex, 16).ok())
        .flatten()
}

pub fn id(key: u64) -> String {
    format!("sb-{key:016x}")
}

/// Which deadline an entry is for. Informational: the sweeper reloads the row and
/// decides from its own anchors when an entry comes due.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Due {
    Lifetime,
    Idle,
    Retry,
}

/// The indexed timer queue (design 2.4): one next-action time per sandbox, in a
/// hash map mirrored by an ordered set. Every update replaces that sandbox's one
/// entry in place, so there are no stale entries and the length is the number of
/// sandboxes with a pending action, whatever the churn.
#[derive(Default)]
pub struct ExpiryQueue {
    by_key: HashMap<u64, (i64, Due)>,
    order: BTreeSet<(i64, u64)>,
}

impl ExpiryQueue {
    /// Replaces `key`'s entry, or removes it with `None`. Returns whether the head
    /// time changed, so the sweeper's one timer can be re-armed.
    pub fn set(&mut self, key: u64, next: Option<(i64, Due)>) -> bool {
        let head = self.head();
        if let Some((time, _)) = self.by_key.remove(&key) {
            self.order.remove(&(time, key));
        }
        if let Some((time, due)) = next {
            self.by_key.insert(key, (time, due));
            self.order.insert((time, key));
        }
        head != self.head()
    }

    pub fn get(&self, key: u64) -> Option<(i64, Due)> {
        self.by_key.get(&key).copied()
    }

    /// The earliest next-action time.
    pub fn head(&self) -> Option<i64> {
        self.order.first().map(|(time, _)| *time)
    }

    /// Removes and returns every entry due at `now`, earliest first.
    pub fn pop_due(&mut self, now: i64) -> Vec<u64> {
        let mut due = Vec::new();
        while let Some(&(time, key)) = self.order.first() {
            if time > now {
                break;
            }
            self.order.pop_first();
            self.by_key.remove(&key);
            due.push(key);
        }
        due
    }

    pub fn len(&self) -> usize {
        debug_assert_eq!(self.by_key.len(), self.order.len());
        self.by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&mut self) {
        self.by_key.clear();
        self.order.clear();
    }

    /// The hash map's allocated capacity, for the churn test's flat-allocation check.
    pub fn capacity(&self) -> usize {
        self.by_key.capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_policy_never_expires_and_present_zeros_take_defaults() {
        let node = ExpiryLimits {
            default_lifetime_ms: 3_600_000,
            default_idle_ms: 600_000,
            ..ExpiryLimits::default()
        };
        assert_eq!(
            resolve_expiry(None, &node).unwrap(),
            ExpiryPolicy::default()
        );
        assert!(!resolve_expiry(None, &node).unwrap().expires());
        assert_eq!(
            resolve_expiry(Some(RequestedExpiry::default()), &node).unwrap(),
            ExpiryPolicy {
                max_lifetime_ms: Some(3_600_000),
                idle_timeout_ms: Some(600_000),
            }
        );
        let never = ExpiryLimits::default();
        assert!(
            !resolve_expiry(Some(RequestedExpiry::default()), &never)
                .unwrap()
                .expires()
        );
        let given = RequestedExpiry {
            max_lifetime_ms: 20_000,
            idle_timeout_ms: 0,
        };
        assert_eq!(
            resolve_expiry(Some(given), &node).unwrap(),
            ExpiryPolicy {
                max_lifetime_ms: Some(20_000),
                idle_timeout_ms: Some(600_000),
            }
        );
    }

    #[test]
    fn bounds_are_the_minimum_and_the_node_maximum_unless_uncapped() {
        let node = ExpiryLimits::default();
        for (lifetime, idle, ok) in [
            (MIN_EXPIRY_MS - 1, 0, false),
            (MIN_EXPIRY_MS, 0, true),
            (0, MIN_EXPIRY_MS - 1, false),
            (0, MIN_EXPIRY_MS, true),
            (node.max_lifetime_ms, node.max_idle_ms, true),
            (node.max_lifetime_ms + 1, 0, false),
            (0, node.max_idle_ms + 1, false),
        ] {
            let requested = RequestedExpiry {
                max_lifetime_ms: lifetime,
                idle_timeout_ms: idle,
            };
            assert_eq!(
                resolve_expiry(Some(requested), &node).is_ok(),
                ok,
                "{lifetime} {idle}"
            );
        }
        let uncapped = ExpiryLimits {
            max_lifetime_ms: 0,
            max_idle_ms: 0,
            ..node
        };
        let huge = RequestedExpiry {
            max_lifetime_ms: u64::MAX,
            idle_timeout_ms: u64::MAX,
        };
        assert!(resolve_expiry(Some(huge), &uncapped).is_ok());
    }

    #[test]
    fn queue_replaces_in_place_and_pops_in_order() {
        let mut queue = ExpiryQueue::default();
        assert!(queue.set(1, Some((50, Due::Idle))));
        assert!(queue.set(2, Some((40, Due::Lifetime))));
        assert!(!queue.set(1, Some((60, Due::Idle))));
        assert_eq!(queue.len(), 2);
        assert!(queue.set(2, Some((70, Due::Retry))));
        assert_eq!(queue.head(), Some(60));
        assert_eq!(queue.pop_due(59), Vec::<u64>::new());
        assert_eq!(queue.pop_due(70), vec![1, 2]);
        assert!(queue.is_empty());
        queue.set(3, Some((1, Due::Idle)));
        assert!(queue.set(3, None));
        assert!(queue.is_empty());
    }

    /// Design section 8's queue bound at the data-structure level: 10^6 renews and
    /// 10^6 short executions (each a pause then a resume) over 32 sandboxes with no
    /// idle cap keep exactly one entry per sandbox, with flat allocation.
    #[test]
    fn a_million_renews_and_short_execs_never_grow_the_queue() {
        let mut queue = ExpiryQueue::default();
        const SANDBOXES: u64 = 32;
        for key in 0..SANDBOXES {
            queue.set(key, Some((i64::MAX - 1, Due::Lifetime)));
        }
        let capacity = queue.capacity();
        let mut now = 0i64;
        for event in 0..1_000_000u64 {
            let key = event % SANDBOXES;
            now += 1;
            // Renew: the idle deadline moves; lifetime stays earlier or later.
            queue.set(key, Some((now + 86_400_000 * 365, Due::Idle)));
            assert!(queue.len() as u64 <= SANDBOXES);
            // Short Exec: start pauses idle (lifetime only), finish resumes it.
            queue.set(key, Some((i64::MAX - 1, Due::Lifetime)));
            assert!(queue.len() as u64 <= SANDBOXES);
            queue.set(key, Some((now + 1 + 86_400_000 * 365, Due::Idle)));
            assert!(queue.len() as u64 <= SANDBOXES);
        }
        assert_eq!(queue.len() as u64, SANDBOXES);
        assert_eq!(queue.capacity(), capacity, "allocation grew under churn");
    }

    #[test]
    fn retry_backoff_runs_from_five_seconds_to_five_minutes() {
        assert_eq!(retry_delay(1), Duration::from_secs(5));
        assert_eq!(retry_delay(2), Duration::from_secs(10));
        assert_eq!(retry_delay(7), Duration::from_secs(300));
        assert_eq!(retry_delay(u32::MAX), Duration::from_secs(300));
    }

    #[test]
    fn keys_round_trip_and_refuse_anything_else() {
        assert_eq!(key("sb-00000000000000ff"), Some(255));
        assert_eq!(id(255), "sb-00000000000000ff");
        assert_eq!(key("ex-00000000000000ff"), None);
        assert_eq!(key("sb-ff"), None);
        assert_eq!(key("sb-zz000000000000ff"), None);
    }
}
