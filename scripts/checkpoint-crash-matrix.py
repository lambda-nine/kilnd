#!/usr/bin/env python3
"""Checkpoint milestone C6b: the VM acceptance matrix (design 10 and 11.2 items 2-7)
against the installed kiln, run as root in the kiln Lima VM under the shared VM lock:

    sudo python3 -I scripts/checkpoint-crash-matrix.py --test-binary T --evidence DIR \
        --set crash|hostile|clients|perf|v14-arm|v14-verify [--only NAME ...]

T is the kilnd library test binary built from this checkout (`scripts/build.sh default
test -p kilnd --lib --no-run`). Each scenario is one ignored root test in
crates/kilnd/src/manager/checkpoint_vm_*.rs, run alone. Before and after each one the
host is checked: `kiln ls` and the runs directory empty, no checkpoint artifacts, no
overlay mounts, the project quotas' usage unchanged (new project IDs at zero), the image
registry and images as they were, the loop devices unchanged, and no kiln worker or test
child process left. A scenario passes only with libtest's "1 passed", exactly one
`C6B matrix:` line and clean host checks. matrix.json and matrix.md go to DIR.

Nothing here touches the node's kilnd, kilnd-helper or their state: the scenarios run a
private daemon and helper on private sockets and state, with the feature on only there.
V14 is a real reboot: `--set v14-arm` leaves its state in /var/tmp for `--set
v14-verify` after the guest restarts, so its host check runs only before the arm and
after the verify.
"""
import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time

RUNS = '/var/lib/kiln/runs'
CHECKPOINTS = RUNS + '/.checkpoints'
IMAGES = '/var/lib/kiln/images'
REGISTRY = '/var/lib/kiln/image-registry'
KILN = os.environ.get('KILND_C5A_KILN', '/usr/local/bin/kiln')
# The kiln VM freezes at about 2 h 02 min of uptime; C6b's windows are 60 minutes.
MAX_UPTIME_MINUTES = 50

CRASH = [
    'c6b_v1_daemon_death_after_c1_before_dispatch_fails_without_recapture',
    'c6b_v2_daemon_death_mid_copy_reaps_the_worker_and_fails',
    'c6b_v3_helper_death_mid_copy_new_epoch_reaps_and_fails',
    'c6b_v4_copy_worker_death_fails_typed_and_removes_staging',
    'c6b_v5_complete_without_ready_is_discarded_never_promoted',
    'c6b_v6_ready_with_the_reply_lost_is_returned_by_the_key',
    'c6b_v7_deletion_interrupted_after_d1_completes_on_restart',
    'c6b_v8_absent_without_d3_is_reinspected_and_released_once',
    'c6b_v9_pin_committed_not_dispatched_retires_the_reader_and_releases_on_absent',
    'c6b_v10_daemon_death_mid_restore_reaps_the_reader_before_the_pin',
    'c6b_v11_restore_worker_death_fails_the_fork_and_keeps_the_checkpoint',
    'c6b_v12_restored_without_ready_is_compensated_never_promoted',
    'c6b_v13_helper_death_mid_restore_keeps_the_pin_until_absent',
    'c6b_v15_stale_backup_blocks_admission_and_never_adopts',
    'c6b_v16_corrupt_payload_quarantines_and_delete_releases',
    'c6b_v17_death_during_the_barrier_inventory_reruns_it',
]
SETS = {
    'crash': [('crash', n) for n in CRASH],
    'v14-arm': [('crash', 'c6b_v14_reboot_arm')],
    'v14-verify': [('crash', 'c6b_v14_reboot_verify')],
    'hostile': [('hostile', n) for n in [
        'c6b_hostile_links_and_roots_are_refused_or_round_trip',
        'c6b_hostile_special_files_and_metadata_are_refused_before_allocation',
        'c6b_hostile_names_depth_and_counts_hold_their_limits',
        'c6b_hostile_sizes_sparse_and_inode_bombs_hold_their_limits',
        'c6b_hostile_protected_trees_and_sentinels_are_unchanged',
        'c6b_hostile_callers_two_uids_get_only_their_own',
    ]],
    'clients': [('clients', n) for n in [
        'c6b_f1_rewind_on_real_kiln',
        'c6b_f2_best_of_four_on_real_kiln',
        'c6b_f3_eval_reset_on_real_kiln',
        'c6b_legacy_create_and_exec_are_unchanged_with_the_flag',
    ]],
    'perf': [('perf', 'c6b_perf')],
}
NO_CHECK_AFTER = {'c6b_v14_reboot_arm'}
NO_CHECK_BEFORE = {'c6b_v14_reboot_verify'}


def sh(*argv):
    return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def uptime_minutes():
    with open('/proc/uptime') as f:
        return float(f.read().split()[0]) / 60


def quota_usage():
    """Project ID -> (blocks used, inodes used), from `report -p -N -b -i`."""
    out = sh('xfs_quota', '-x', '-c', 'report -p -N -b -i', RUNS)
    if out.returncode != 0:
        raise RuntimeError('xfs_quota failed: ' + out.stdout)
    usage = {}
    for line in out.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 7 and fields[1].isdigit():
            usage[fields[0]] = (int(fields[1]), int(fields[6]))
    return usage


def leftovers(test_binary):
    """Processes a scenario may not leave: kiln artifact workers and test children."""
    found = []
    me = os.getpid()
    name = os.path.basename(test_binary)
    for pid in os.listdir('/proc'):
        if not pid.isdigit() or int(pid) == me:
            continue
        try:
            with open('/proc/%s/cmdline' % pid, 'rb') as f:
                argv = f.read().split(b'\0')
        except OSError:
            continue
        words = [a.decode('utf-8', 'replace') for a in argv if a]
        if not words:
            continue
        exe = os.path.basename(words[0])
        if exe == name or (exe == 'kiln' and any('checkpoint' in w for w in words)):
            found.append('%s %s' % (pid, ' '.join(words)[:200]))
    return found


def snapshot(test_binary):
    entries = sorted(os.listdir(RUNS))
    return {
        'kiln_ls': [l for l in sh(KILN, 'ls').stdout.splitlines()[1:] if l.strip()],
        'runs': [e for e in entries if e != '.checkpoints'],
        'checkpoints': (sorted(os.listdir(CHECKPOINTS)) if os.path.isdir(CHECKPOINTS) else None),
        'images': sorted(os.listdir(IMAGES)),
        'registry': os.path.exists(REGISTRY),
        'overlay': [l for l in open('/proc/self/mountinfo').read().splitlines()
                    if ' - overlay ' in l],
        'loops': sh('losetup', '-a').stdout.strip(),
        'quota': quota_usage(),
        'processes': leftovers(test_binary),
    }


def host_problems(baseline, now):
    problems = []
    for key in ('kiln_ls', 'runs', 'overlay', 'processes'):
        if now[key]:
            problems.append('%s: %s' % (key, now[key]))
    if now['checkpoints'] not in (None, []) or (baseline['checkpoints'] is None) != (now['checkpoints'] is None):
        problems.append('checkpoints: %s (before: %s)' % (now['checkpoints'], baseline['checkpoints']))
    for key in ('images', 'registry', 'loops'):
        if now[key] != baseline[key]:
            problems.append('%s: %s (before: %s)' % (key, now[key], baseline[key]))
    for project, used in now['quota'].items():
        before = baseline['quota'].get(project, (0, 0))
        if used != before:
            problems.append('quota %s used %s (before: %s)' % (project, used, before))
    return problems


def main():
    parser = argparse.ArgumentParser(description='C6b VM acceptance matrix')
    parser.add_argument('--test-binary', required=True)
    parser.add_argument('--evidence', required=True)
    parser.add_argument('--set', required=True, choices=sorted(SETS))
    parser.add_argument('--only', action='append', default=[])
    parser.add_argument('--timeout', type=int, default=600, help='seconds per scenario')
    parser.add_argument('--stop-at-minutes', type=float, default=42,
                        help='start no scenario past this VM uptime, so the restore starts on time')
    parser.add_argument('--ignore-uptime', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        print('run as root (sudo)', file=sys.stderr)
        return 2
    if not args.ignore_uptime and uptime_minutes() > MAX_UPTIME_MINUTES:
        print('VM uptime is %.0f min, over %d: restart the kiln VM first'
              % (uptime_minutes(), MAX_UPTIME_MINUTES), file=sys.stderr)
        return 2
    chosen = [(m, n) for m, n in SETS[args.set] if not args.only or n in args.only]
    unknown = set(args.only) - {n for _, n in SETS[args.set]}
    if unknown or not chosen:
        print('unknown or no scenarios: %s' % sorted(unknown), file=sys.stderr)
        return 2
    evidence = os.path.abspath(args.evidence)
    os.makedirs(evidence, exist_ok=True)
    binary = os.path.abspath(args.test_binary)
    baseline_path = os.path.join(evidence, 'host-baseline.json')
    if args.set == 'v14-verify' and os.path.exists(baseline_path):
        with open(baseline_path) as f:
            baseline = json.load(f)
        baseline['quota'] = {k: tuple(v) for k, v in baseline['quota'].items()}
    else:
        baseline = snapshot(binary)
        with open(baseline_path, 'w') as f:
            json.dump(baseline, f, indent=2)
    pre = host_problems(baseline, baseline)
    if pre and args.set != 'v14-verify':
        print('host not clean before the matrix: %s' % pre, file=sys.stderr)
        return 2
    results = {}
    started = time.time()
    log_path = os.path.join(evidence, 'tests-%s.log' % args.set)
    with open(log_path, 'a') as log:
        for module, name in chosen:
            if not args.ignore_uptime and uptime_minutes() > args.stop_at_minutes:
                print('stopping before %s: uptime %.1f min is past %.0f' % (
                    name, uptime_minutes(), args.stop_at_minutes), flush=True)
                break
            before = [] if name in NO_CHECK_BEFORE else host_problems(baseline, snapshot(binary))
            t0 = time.time()
            test = 'manager::checkpoint_vm_tests::%s::%s' % (module, name)
            # Its own session, so a timeout kills the scenario's children with it.
            proc = subprocess.Popen([binary, '--ignored', '--exact', test, '--test-threads=1',
                                     '--nocapture'], cwd=os.path.dirname(binary),
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                    start_new_session=True)
            try:
                output, _ = proc.communicate(timeout=args.timeout)
                code = proc.returncode
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                output, _ = proc.communicate()
                code = 'timeout'
            log.write('===== %s =====\n%s\n' % (name, output))
            log.flush()
            after = [] if name in NO_CHECK_AFTER else host_problems(baseline, snapshot(binary))
            lines = [json.loads(m) for m in re.findall(r'C6B matrix: (\{.*\})$', output, re.M)]
            ok = (code == 0 and re.search(r'^test result: ok\. 1 passed', output, re.M) is not None
                  and len(lines) == 1 and not before and not after)
            results[name] = {
                'passed': ok, 'exit': code, 'seconds': round(time.time() - t0, 1),
                'matrix': lines[0] if lines else None,
                'host_before': before, 'host_after': after,
                'uptime_minutes': round(uptime_minutes(), 1),
            }
            print('%s %s (%.1f s, uptime %.1f min)%s' % (
                'PASS' if ok else 'FAIL', name, results[name]['seconds'],
                results[name]['uptime_minutes'],
                '' if ok else ' host before %s after %s exit %s' % (before, after, code)), flush=True)
            if after:
                print('stopping: the host is not clean after %s' % name, flush=True)
                break
    failed = [n for n, r in results.items() if not r['passed']]
    commit = sh('git', '-c', 'safe.directory=*', '-C', os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), 'rev-parse', 'HEAD').stdout.strip()
    summary = {'set': args.set, 'commit': commit, 'kiln': sh(KILN, '--version').stdout.strip(),
               'kernel': os.uname().release, 'started_unix': int(started),
               'seconds': round(time.time() - started, 1), 'scenarios': results, 'failed': failed}
    with open(os.path.join(evidence, 'matrix-%s.json' % args.set), 'w') as f:
        json.dump(summary, f, indent=2)
    with open(os.path.join(evidence, 'matrix-%s.md' % args.set), 'w') as f:
        f.write('# C6b VM matrix: %s\n\nCommit `%s`, %s, kernel %s, %.0f s.\n\n'
                % (args.set, commit, summary['kiln'], summary['kernel'], summary['seconds']))
        f.write('| Scenario | Result | Outcome |\n|---|---|---|\n')
        for name, r in results.items():
            m = r['matrix'] or {}
            outcome = json.dumps(m.get('outcome'), sort_keys=True).replace('|', '/')
            f.write('| %s | %s (%s s) | `%s` |\n' % (m.get('scenario', name),
                    'pass' if r['passed'] else 'FAIL', r['seconds'], outcome))
    print('%d/%d passed; matrix in %s/matrix-%s.md' % (len(results) - len(failed), len(results),
                                                      evidence, args.set))
    return 1 if failed or len(results) != len(chosen) else 0


if __name__ == '__main__':
    sys.exit(main())
