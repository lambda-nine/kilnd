#!/usr/bin/env python3
"""Phase 1b B6: the global-ledger crash matrix (design 4.5, 8.3 and 10.2 items 6 and 15)
on the real chain, through real daemons and kilndctl in the isolated test deployment
(deploy/firecracker-test/). Run in the kiln Lima VM as your user, under the VM lock:

    python3 -I scripts/firecracker-crash-matrix.py --evidence DIR

Each scenario is one privileged test in crates/kilnd/src/helper/firecracker/tests/
recovery.rs, run alone with a clean host before and after:

  daemon death while booting      the restarted daemon adopts only the same READY boot
  daemon death mid-execution      interrupted, the VM retired by the disconnect, no replay
  daemon death before C2          the never-admitted token is fenced; a late Create
                                  allocates nothing
  ABSENT committed, publication   the helper's claim is released; the daemon stays charged
  lost                            until its restart replays the receipt
  ABSENT sync fails               nothing is released anywhere until a retry commits
  capacity commit, reply lost     L dies after the commit: one claim survives L's death and
                                  the helper's restart, never a second
  helper restart                  every claim replayed; the stopped boot never runs again
  helper restart while Create     after C2, before READY: no false READY, no second
  polls                           allocation, the old VM stopped, the one claim released
                                  only by its ABSENT receipt (B6-BI-04)
  daemon death mid-Remove         the helper owns the removal, before ABSENT: the row stays
                                  DELETING and charged until reconciliation settles it from
                                  the matching ABSENT receipt (B6-BI-04)
  stale database restored         admission blocked, the node keeps the charge, another
                                  daemon is never given the slot
  database lost                   the replacement instance is refused; the node ledger
                                  never discounts the lost daemon

B7 adds retired-token compaction's crash points (design 16.6), each a b7_crash_ test in
crates/kilnd/src/helper/firecracker/tests/compaction.rs through the real H, L, listener and
adapter with fake host effects and a FULL-sync ledger: the four issuance boundaries and a
refusal after issuance, L replaced while H lives, H process death, the watermark advance,
the G_W refresh, every delete-batch boundary, non-compactable rows, Create and Remove
racing compaction, a restored stale daemon database, a restart at the checkpoint bound,
the rollback fault commit at every boundary, and the offline clear. They run on macOS and
in CI as well.
"""
import os
import sys

# -I leaves the script's own directory off sys.path; the runner lives beside it.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from firecracker_matrix import run  # noqa: E402

SCENARIOS = [
    'b6_linux_root_crash_daemon_death_while_booting_adopts_only_the_same_boot',
    'b6_linux_root_crash_daemon_death_mid_execution_interrupts_without_replay',
    'b6_linux_root_crash_daemon_death_before_c2_fences_and_a_late_create_cannot_resurrect',
    'b6_linux_root_crash_absent_committed_but_publication_lost_replays_the_receipt',
    'b6_linux_root_crash_absent_sync_failure_stays_charged_until_retried',
    'b6_linux_root_crash_capacity_commit_reply_lost_keeps_one_claim',
    'b6_linux_root_crash_helper_restart_keeps_every_claim',
    'b6_linux_root_crash_helper_restart_while_create_polls_never_publishes_ready',
    'b6_linux_root_crash_daemon_death_mid_remove_stays_charged_until_absent',
    'b6_linux_root_crash_restored_stale_db_blocks_admission_and_keeps_the_charge',
    'b6_linux_root_crash_lost_db_never_discounts_the_node_claim',
]

B7_SCENARIOS = [
    'b7_crash_issuance_before_commit_issues_nothing',
    'b7_crash_issuance_committed_before_the_private_reply_is_abandoned',
    'b7_crash_issuance_private_reply_before_the_public_reply_is_abandoned',
    'b7_crash_issuance_public_reply_before_c1_is_never_presented_again',
    'b7_crash_issuance_then_a_preparation_refusal_consumes_one_seq_and_no_quota',
    'b7_crash_ledger_replaced_while_h_lives_serves_nothing_before_publication',
    'b7_crash_h_process_death_ends_l_and_a_restart_reuses_no_seq',
    'b7_crash_watermark_advance_before_and_after_its_commit',
    'b7_crash_g_w_refresh_for_a_late_pinned_fence_before_and_after_its_commit',
    'b7_crash_delete_batch_rolls_back_whole_at_every_boundary',
    'b7_crash_non_compactable_allocations_below_w_are_never_deleted',
    'b7_crash_a_create_racing_compaction_is_fenced_or_pinned_by_commit_order',
    'b7_crash_a_remove_racing_compaction_keeps_its_rows_and_its_own_receipt',
    'b7_crash_a_restored_stale_daemon_db_after_compaction_releases_by_synthesized_receipts',
    'b7_crash_a_helper_restart_resets_checkpoints_to_one_restart_point',
    'b7_crash_rollback_fault_commit_at_every_boundary_keeps_forward_effects_refused',
    'b7_crash_the_offline_clear_killed_before_or_after_its_commit',
]

if __name__ == '__main__':
    sys.exit(run('Phase 1b B6 and B7 global-ledger crash matrix', 'b6_linux_root_crash_ and b7_crash_',
                 SCENARIOS + B7_SCENARIOS))
