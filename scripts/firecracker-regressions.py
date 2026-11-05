#!/usr/bin/env python3
"""Phase 1b B6: section 10's attacks on the real chain, through real daemons and kilndctl
in the isolated test deployment (deploy/firecracker-test/). Run in the kiln Lima VM as
your user, under the VM lock:

    python3 -I scripts/firecracker-regressions.py --evidence DIR

Each attack is one privileged test in crates/kilnd/src/helper/firecracker/tests/
recovery.rs (and the milestone-1 session in session.rs), run alone with a clean host:

  whole session                  create, persistent executions, a timeout that retires the
                                 VM, Delete to ABSENT (milestone 1)
  four-request race              two daemons race four 896 MiB requests for three slots:
                                 exactly three reach INTENT, the fourth is fenced
  disk and vCPU exhaustion       the second session is refused at C2, never oversubscribed
  duplicate attachment           the enrolled account, cgroup and image with a copy of the
                                 daemon's files is refused while the daemon holds it
  hostile I/O                    B5's three hostile sources beside real Create, Health,
                                 Get, Exec and Delete, each within its deadline
  stalled ledger in Remove       B5-R1: Delete answers in bound and gives its slot back
  quarantine and Unknown         blocked proof quarantines and Delete stays honest until
                                 proof exists
  hostile public caller          B7 (B6-BI-03): one UID holds 64 idle sockets that never
                                 send the HTTP/2 preface, reconnecting each one closed;
                                 Health, Get and Delete from another UID answer in their
                                 deadlines and every idle socket is closed
                                 (scripts/hostile-public-caller.py)

The crash matrix is scripts/firecracker-crash-matrix.py; B4's and B5's suites remain
scripts/b4-vm-tests.sh b4_linux_root and b5_linux_root.
"""
import os
import sys

# -I leaves the script's own directory off sys.path; the runner lives beside it.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from firecracker_matrix import run  # noqa: E402

SCENARIOS = [
    'b6_linux_root_a_whole_session_through_kilnd_and_kilndctl',
    'b6_linux_root_attack_two_daemons_race_four_requests_for_three_slots',
    'b6_linux_root_attack_disk_and_vcpu_exhaustion_never_oversubscribe',
    'b6_linux_root_attack_duplicate_instance_attachment_is_refused',
    'b6_linux_root_attack_hostile_io_beside_real_lifecycle_requests',
    'b6_linux_root_attack_a_stalled_ledger_fence_never_holds_remove',
    'b6_linux_root_attack_quarantine_stays_deletable_and_unknown_is_honest',
    'b7_linux_root_attack_hostile_public_caller_cannot_starve_health_or_cleanup',
]

if __name__ == '__main__':
    sys.exit(run('Phase 1b B6 attack regressions', 'b6_linux_root_attack_', SCENARIOS))
