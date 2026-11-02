//! Section 4.4's stop targets. M holds one per allocation from the moment its cgroup
//! exists, before J could clone V, so containment never waits for a PID to be
//! published. K executes a target: `cgroup.kill` on the pinned `vm` node (compared by
//! inode first) and a pidfd signal to the recorded VMM (compared by start time first).
//! A replaced directory or a reused PID is refused, never signaled.
use super::cgroup::{CgroupTarget, NodeState};
use super::workers::ProcessId;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// What M dispatches to K for one allocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopTarget {
    /// The VMM, once S has validated and published it.
    pub process: Option<ProcessId>,
    /// The allocation's `vm` subtree, once it exists.
    pub cgroup: Option<CgroupTarget>,
}

impl StopTarget {
    pub fn process(process: ProcessId) -> Self {
        Self {
            process: Some(process),
            cgroup: None,
        }
    }

    /// Adds what a later report learned without dropping what was known.
    pub fn merge(&mut self, other: &StopTarget) {
        if other.process.is_some() {
            self.process = other.process;
        }
        if other.cgroup.is_some() {
            self.cgroup = other.cgroup.clone();
        }
    }
}

/// Executes one stop. True only when every part of the target is proven gone: the
/// subtree empty or absent, and the process exited or provably another process.
pub fn execute(target: &StopTarget) -> bool {
    let mut gone = true;
    if let Some(cgroup) = &target.cgroup {
        gone &= kill_cgroup(cgroup);
    }
    if let Some(process) = target.process {
        gone &= kill_process(process);
    }
    gone
}

#[cfg(target_os = "linux")]
fn kill_cgroup(target: &CgroupTarget) -> bool {
    super::workers::fault_point("K.cgroup_kill");
    match super::cgroup::kill_node(target, Duration::from_secs(2)) {
        Ok(NodeState::Absent | NodeState::Empty) => true,
        // A replaced directory was not touched: whatever it holds is not this target.
        Ok(NodeState::Replaced) => true,
        Ok(NodeState::Populated) | Err(_) => false,
    }
}

#[cfg(not(target_os = "linux"))]
fn kill_cgroup(_: &CgroupTarget) -> bool {
    let _ = (Duration::ZERO, NodeState::Absent);
    false
}

/// A pidfd is opened first and the start time compared after, so the signal can
/// reach only the recorded process. The fake fixtures' VM leads its own group.
fn kill_process(target: ProcessId) -> bool {
    #[cfg(target_os = "linux")]
    {
        use super::workers::{ProcessState, process_state};
        let Ok(pidfd) = super::supervisor::pidfd_open(target.pid) else {
            return true;
        };
        match process_state(target.pid) {
            ProcessState::Running { start_time } if start_time == target.start_time => {}
            _ => return true,
        }
        let _ = super::supervisor::pidfd_signal(&pidfd, libc::SIGKILL);
        let end = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < end {
            if super::supervisor::pidfd_exited(&pidfd) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        super::workers::kill_target(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merging_keeps_both_halves_of_a_target() {
        let mut target = StopTarget {
            process: None,
            cgroup: Some(CgroupTarget {
                path: "kilnd-firecracker/a/fc-b/vm".into(),
                st_ino: 7,
            }),
        };
        target.merge(&StopTarget::process(ProcessId {
            pid: 3,
            start_time: 9,
        }));
        assert!(target.process.is_some() && target.cgroup.is_some());
    }
}
