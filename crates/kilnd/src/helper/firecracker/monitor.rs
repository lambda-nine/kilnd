//! Section 4.4's stop targets. M holds one per allocation from the moment its cgroup
//! exists, before J could clone V, so containment never waits for a PID to be
//! published. K executes a target only through section 7.1's proofs
//! (`super::proven`): `cgroup.kill` on the `vm` node once the boot ID and the
//! journaled inodes of the parent, `vm`, `vm/vmm` and `vm/console` are proven, and a
//! pidfd signal to the recorded VMM once its start time and boot ID are. A replaced
//! node or child, a reused PID or a missing boot ID is refused, never signaled.
use super::cgroup::{CgroupStopTarget, NodeState};
use super::workers::ProcessId;
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::time::Duration;

/// What M dispatches to K for one allocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopTarget {
    /// The VMM, once S has validated and published it.
    pub process: Option<ProcessId>,
    /// The allocation's tree and its journaled generation, once its intent exists.
    pub cgroup: Option<CgroupStopTarget>,
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
        // A journaled generation is never replaced by a target that has only an intent.
        match (&self.cgroup, &other.cgroup) {
            (_, None) => {}
            (Some(known), Some(later)) if known.identity.is_some() && later.identity.is_none() => {}
            (_, Some(later)) => self.cgroup = Some(later.clone()),
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

/// True only when the `vm` subtree is proven empty or absent. A replaced or unrecorded
/// tree is not signaled and is not gone: the allocation stays charged.
#[cfg(target_os = "linux")]
fn kill_cgroup(target: &CgroupStopTarget) -> bool {
    super::workers::fault_point("K.cgroup_kill");
    matches!(
        super::cgroup::kill_recorded(
            &target.relative,
            target.identity.as_ref(),
            Duration::from_secs(2)
        ),
        Ok(NodeState::Absent | NodeState::Empty)
    )
}

#[cfg(not(target_os = "linux"))]
fn kill_cgroup(_: &CgroupStopTarget) -> bool {
    let _ = NodeState::Absent;
    false
}

/// The recorded VMM, proven by pidfd, start time and boot ID before any signal.
pub fn kill_process(target: ProcessId) -> bool {
    super::proven::stop_process(&target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merging_keeps_both_halves_of_a_target() {
        let mut target = StopTarget {
            process: None,
            cgroup: Some(CgroupStopTarget {
                relative: "kilnd-firecracker/a/fc-b".into(),
                identity: None,
            }),
        };
        target.merge(&StopTarget::process(ProcessId {
            pid: 3,
            start_time: 9,
            boot_id: None,
        }));
        assert!(target.process.is_some() && target.cgroup.is_some());
    }
}
