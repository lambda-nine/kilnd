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
]

# B7 attack regressions (design 16.6), in crates/kilnd/src/helper/firecracker/tests/
# compaction.rs, through the real H, L, listener and adapter.
B7_SCENARIOS = [
    'b7_rtc3_forged_foreign_and_seq_zero_tokens_never_reach_a_gate_or_l',
    'b7_rtc3_a_valid_tag_at_the_pointer_reaches_l_and_is_not_issued_across_restarts',
    'b7_rtc8_real_wire_digests_after_compaction_and_a_helper_restart',
    'b7_rtc14_spoofed_highest_tokens_fail_only_their_own_attachment',
    'b7_rtc14_a_real_rollback_latches_every_forward_effect_until_the_offline_clear',
    'b7_rtc_r2_03_h_latches_before_the_commit_and_queued_work_starts_nothing',
    'b7_rtc_r2_01_an_uncertain_fault_commit_fails_stop_across_every_restart',
    'b7_rtc13_a_five_lease_flood_keeps_checkpoints_bounded_and_the_tail_matures',
    'b7_rtc12_a_never_admitted_flood_stops_at_the_floor_and_refills_after_a_lease',
    'b7_rtc17_an_instance_enrolled_beside_a_borrower_finds_its_share_at_once',
    'b7_rtc18_compaction_has_its_own_lane_and_a_full_batch_stays_under_100_ms',
    'b7_rtc18_a_busy_normal_lane_from_two_instances_never_starves_a_third_instances_refill',
    'b7_rtc14_a_latch_during_create_setup_is_rechecked_before_open_gate',
    'b7_rtc13_completed_sessions_leave_no_digest_entries',
    'b7_rtc13_stale_inspects_racing_removes_never_fill_the_digest_cap',
    'b7_rtc14_linux_root_a_latch_while_s_waits_grants_no_resource_authority',
    'b7_rtc14_linux_root_a_latch_while_h_awaits_l_refuses_the_acknowledgement',
    'b7_rtc14_linux_root_a_latch_before_initialize_sends_none',
]

if __name__ == '__main__':
    sys.exit(run('Phase 1b B6 and B7 attack regressions', 'b6_linux_root_attack_ and b7_rtc',
                 SCENARIOS + B7_SCENARIOS))
