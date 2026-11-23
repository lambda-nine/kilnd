#!/usr/bin/env python3
"""The pure parts of scripts/firecracker-two-daemon-stress.py: its percentiles, refusal
types, resumability and partial-result detection, pass rules, token and claim bookkeeping,
health and smaps parsing, and teardown's plan from recorded IDs. Nothing here needs root, a
VM or a node, so it runs anywhere, in CI too:

  python3 -I scripts/firecracker-two-daemon-stress-tests.py
"""
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))


def load():
    spec = importlib.util.spec_from_file_location(
        'firecracker_two_daemon_stress', os.path.join(HERE, 'firecracker-two-daemon-stress.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load()
MIB = 1 << 20
CEILINGS = {'slots': 3, 'memory_bytes': 3072 * MIB, 'disk_bytes': 16 << 30,
            'host_cpu_millis': 3500, 'virtual_cpu_slots': 3, 'pids': 2048, 'host_pids': 128}


class Percentiles(unittest.TestCase):
    def test_nearest_rank(self):
        values = list(range(1, 21))
        self.assertEqual(m.percentile(values, 0.5), 10)
        self.assertEqual(m.percentile(values, 0.95), 19)
        self.assertEqual(m.percentile(values, 1.0), 20)
        self.assertEqual(m.percentile([7], 0.95), 7)
        self.assertIsNone(m.percentile([], 0.5))

    def test_order_does_not_matter(self):
        self.assertEqual(m.percentile([5, 1, 4, 2, 3], 0.5), 3)

    def test_stats(self):
        s = m.stats([3, 1, 2])
        self.assertEqual((s['n'], s['min'], s['p50'], s['max']), (3, 1, 2, 3))
        self.assertEqual(m.stats([])['n'], 0)
        self.assertIsNone(m.stats([])['p95'])


class Refusals(unittest.TestCase):
    def test_the_helpers_capacity_messages(self):
        cases = {
            'kilndctl: resourceexhausted: every preparation slot is in use': 'prep_slot',
            'kilndctl: resourceexhausted: node capacity exhausted: MemoryBytes': 'node_capacity',
            'kilndctl: resourceexhausted: no admitted headroom is left for this instance':
                'headroom',
            "kilndctl: resourceexhausted: this instance's never-admitted fences fill its "
            'window quota': 'headroom',
            'kilndctl: resourceexhausted: the node ledger is past its share of the reservation':
                'headroom',
            "kilndctl: resourceexhausted: this instance's issue sequence is exhausted":
                'headroom',
            'kilndctl: resourceexhausted: node memory bytes budget exhausted: 2818572288 '
            'reserved + 939524096 requested exceeds limit 3221225472': 'daemon_budget',
            'kilndctl: resourceexhausted: something new': 'resource_exhausted_other',
            'kilndctl: unavailable: helper went away': 'unavailable',
            'kilndctl: deadlineexceeded: deadline': 'deadline',
            '\nclient timeout': 'client_timeout',
            '': 'other',
            None: 'other',
        }
        for message, kind in cases.items():
            self.assertEqual(m.classify_refusal(message), kind, message)

    def test_only_capacity_refusals_are_expected(self):
        self.assertEqual(set(m.EXPECTED_REFUSALS),
                         {'prep_slot', 'node_capacity', 'daemon_budget', 'headroom'})


class ScriptedNode:
    """kilndctl answers from a script: one (code, err) per call, the last repeated."""
    def __init__(self, answers, clock):
        self.answers, self.calls, self.clock = list(answers), [], clock

    def kilndctl(self, daemon, args, timeout, stdin=None):
        self.calls.append((daemon, args))
        code, err = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        start = int(self.clock.now * 1000)
        self.clock.now += 0.05
        return {'code': code, 'out': '', 'err': err, 'start': start,
                'end': int(self.clock.now * 1000), 'ms': 50.0}


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class DeleteRetry(unittest.TestCase):
    STUCK = 'kilndctl: internal: ... stays charged (ObservationUnavailable): no fresh namespace observation'

    def run_delete(self, answers):
        clock = FakeClock()
        node = ScriptedNode(answers, clock)
        failed = []
        out = m.delete_with_retry(node, 'fctest', 'sb-1', record=lambda n, r: failed.append(n),
                                  clock=clock, sleep=clock.sleep)
        return out, node, failed

    def test_first_attempt(self):
        out, node, failed = self.run_delete([(0, '')])
        self.assertEqual((out['ok'], out['attempts'], out['retried'], out['leaked']),
                         (True, 1, False, False))
        self.assertEqual(node.calls, [('fctest', ['rm', 'sb-1'])])
        self.assertEqual((failed, out['first_err']), ([], ''))

    def test_released_by_a_retry(self):
        out, _, failed = self.run_delete([(1, self.STUCK), (1, self.STUCK), (0, '')])
        self.assertEqual((out['ok'], out['attempts'], out['retried'], out['leaked']),
                         (True, 3, True, False))
        self.assertEqual(failed, [1, 2])
        # Three 50 ms calls and two 1 s waits (whole ms, so within one of 2150).
        self.assertAlmostEqual(out['release_ms'], 2150, delta=1)
        self.assertAlmostEqual(out['ms'], 2150, delta=1)
        self.assertIn('ObservationUnavailable', out['first_err'])
        tally = m.Tally()
        tally.deleted('fctest', 'sb-1', out)
        self.assertEqual(len(tally.delete_retried), 1)
        self.assertEqual(tally.delete_leaks, [])

    def test_leak_after_a_minute(self):
        out, node, failed = self.run_delete([(1, self.STUCK)])
        self.assertEqual((out['ok'], out['leaked'], out['release_ms']), (False, True, None))
        # The first failure, then one retry a second (plus 50 ms a call) until 60 s pass.
        self.assertEqual(out['attempts'], len(node.calls))
        self.assertTrue(57 <= out['attempts'] <= 61, out['attempts'])
        self.assertEqual(failed, list(range(1, out['attempts'] + 1)))
        tally = m.Tally()
        tally.deleted('fctest', 'sb-1', out)
        self.assertEqual((len(tally.delete_retried), len(tally.delete_leaks)), (1, 1))
        self.assertIn('ObservationUnavailable', tally.delete_leaks[0]['err'])


class Resumability(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = os.path.join(self.tmp.name, 's1')

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        os.makedirs(self.dir, exist_ok=True)
        with open(os.path.join(self.dir, name), 'w') as f:
            f.write(text)

    def test_absent(self):
        self.assertEqual(m.scenario_state(self.dir), 'absent')

    def test_records_without_done_are_partial(self):
        self.write('records.jsonl', '{"op": "create"}\n')
        self.assertEqual(m.scenario_state(self.dir), 'partial')

    def test_done_with_a_different_record_count_is_partial(self):
        self.write('records.jsonl', '{"a": 1}\n{"a": 2}\n')
        self.write('done.json', json.dumps({'complete': True, 'records': 3}))
        self.assertEqual(m.scenario_state(self.dir), 'partial')

    def test_torn_done_is_partial(self):
        self.write('records.jsonl', '{"a": 1}\n')
        self.write('done.json', '{"complete": tr')
        self.assertEqual(m.scenario_state(self.dir), 'partial')

    def test_complete(self):
        self.write('records.jsonl', '{"a": 1}\n\n{"a": 2}\n')
        self.write('done.json', json.dumps({'complete': True, 'records': 2}))
        self.assertEqual(m.scenario_state(self.dir), 'complete')

    def test_partial_names_never_collide(self):
        self.assertEqual(m.partial_name(self.dir), self.dir + '.partial-1')
        os.makedirs(self.dir + '.partial-1')
        self.assertEqual(m.partial_name(self.dir), self.dir + '.partial-2')

    def scenario(self, force=False):
        s = m.Scenario(self.tmp.name, 's1', force)
        m.uptime_minutes = lambda: 1.0
        m.sync = lambda: None
        return s

    def test_a_partial_run_is_moved_aside_and_run_again(self):
        self.write('records.jsonl', '{"stale": true}\n')
        s = self.scenario()
        self.assertTrue(s.begin())
        self.assertTrue(os.path.isdir(self.dir + '.partial-1'))
        with open(os.path.join(self.dir, 'records.jsonl')) as f:
            self.assertEqual(f.read(), '')
        s.record({'op': 'create'})
        s.record({'op': 'rm'})
        self.assertTrue(s.finish([m.check('a', True)], {'x': 1}))
        self.assertEqual(m.scenario_state(self.dir), 'complete')
        with open(os.path.join(self.dir, 'summary.txt')) as f:
            self.assertIn('PASS a', f.read())

    def test_a_complete_run_is_kept_unless_forced(self):
        s = self.scenario()
        s.begin()
        s.finish([m.check('a', False, 'why')], {})
        self.assertFalse(self.scenario().begin())
        with open(os.path.join(self.dir, 'done.json')) as f:
            self.assertFalse(json.load(f)['passed'])
        again = self.scenario(force=True)
        self.assertTrue(again.begin())
        again.finish([], {})
        self.assertTrue(os.path.isdir(self.dir + '.partial-1'))


class Bookkeeping(unittest.TestCase):
    def test_next_admit_gaps(self):
        releases = [100, 500, 900]
        creates = [(50, 60), (120, 1300), (480, 1500), (950, 2100)]
        self.assertEqual(m.next_admit_gaps(releases, creates),
                         [(20, 1200), (450, 1600), (50, 1200)])

    def test_a_release_after_the_last_create_has_no_gap(self):
        self.assertEqual(m.next_admit_gaps([1000], [(10, 20)]), [])

    def test_vector_violations(self):
        totals = {'slots': 3, 'memory_bytes': 3072 * MIB, 'pids': 2049}
        self.assertEqual(m.vector_violations(totals, CEILINGS), ['pids 2049 > 2048'])
        self.assertEqual(m.vector_violations({'slots': 4}, CEILINGS), ['slots 4 > 3'])

    def test_seq_of(self):
        self.assertEqual(m.seq_of('000000000000002a' + 'f' * 16), 42)

    def test_unaccounted_tokens(self):
        # Issued [3, 8): 3 and 5 retired, 4 and 6 admitted, 7 has no outcome.
        self.assertEqual(m.unaccounted_tokens((3, 8), [3, 5], [4, 6]), [7])
        self.assertEqual(m.unaccounted_tokens((5, 5), [], []), [])
        # Below the watermark is compacted and not looked at.
        self.assertEqual(m.unaccounted_tokens((4, 6), [], [4, 5, 1]), [])

    def test_quiescent_mismatch(self):
        claims = {'i1': {'a', 'b'}, 'i2': {'c'}}
        self.assertEqual(m.quiescent_mismatch(claims, {'i1': {'a', 'b'}, 'i2': {'c'}}), {})
        self.assertEqual(m.quiescent_mismatch(claims, {'i1': {'a'}, 'i2': {'c', 'd'}}),
                         {'i1': {'ledger_only': ['b'], 'daemon_only': []},
                          'i2': {'ledger_only': [], 'daemon_only': ['d']}})
        self.assertEqual(m.quiescent_mismatch({}, {'i3': {'e'}}),
                         {'i3': {'ledger_only': [], 'daemon_only': ['e']}})

    def test_host_name_is_identity_rs_formula(self):
        instance, allocation = '1' * 32, '2' * 32
        expected = hashlib.sha256(
            b'kilnd-firecracker-host-name-v1\0' + b'1' * 32 + b'\0' + b'2' * 32).hexdigest()
        self.assertEqual(m.host_name(instance, allocation), 'fc-' + expected[:32])
        self.assertNotEqual(m.host_name('3' * 32, allocation), m.host_name(instance, allocation))


SMAPS = """\
aaaac0000000-aaaac0100000 r-xp 00000000 00:00 0  /firecracker
Size:               1024 kB
Rss:                 900 kB
ffff40000000-ffff70000000 rw-p 00000000 00:00 0
Size:             786432 kB
Rss:              204800 kB
Pss:              204800 kB
ffff80000000-ffff80800000 rw-p 00000000 00:00 0
Size:               8192 kB
Rss:                4096 kB
"""


class Parsing(unittest.TestCase):
    def test_guest_mapping(self):
        self.assertEqual(m.guest_mapping_rss(SMAPS), 204800 * 1024)

    def test_no_guest_sized_mapping(self):
        self.assertIsNone(m.guest_mapping_rss(SMAPS.replace('786432', '100000')))
        self.assertIsNone(m.guest_mapping_rss(''))

    def test_overhead(self):
        self.assertEqual(m.session_overhead(900 * MIB, 700 * MIB), 200 * MIB)
        self.assertIsNone(m.session_overhead(None, 1))
        self.assertIsNone(m.session_overhead(1, None))

    def test_health_as_kilndctl_prints_it(self):
        text = (
            'status:             serving\n'
            'version:            0.1.0\n'
            'backend:            firecracker 1.17.0\n'
            'active sandboxes:   2\n'
            'node reservations:   sandboxes 2/3, memory 1946157056/3221225472 bytes, '
            'pids 1056/2048, disk 4294967296/17179869184 bytes\n'
            'host reservations:   cpu 2500/3500 millis, vcpus 2/3, host pids 96/128\n'
            'accounting:          authoritative (generation 41)\n'
            'rejected creates:   7\n'
            'detail:             fine\n')
        h = m.parse_health(text)
        self.assertEqual(h['status'], 'serving')
        self.assertEqual((h['node_sandboxes'], h['node_sandboxes_max']), (2, 3))
        self.assertEqual(h['node_memory'], 1946157056)
        self.assertEqual(h['node_disk_max'], 17179869184)
        self.assertEqual((h['host_cpu'], h['host_vcpus'], h['host_host_pids']), (2500, 2, 96))
        self.assertEqual(h['rejected_creates'], 7)
        self.assertEqual(h['accounting'], 'authoritative (generation 41)')
        self.assertEqual(h['detail'], 'fine')


def s2_outcome(**changes):
    outcome = {'intent': 3, 'ready': 3, 'claims_max': 3, 'vector_violations': [],
               'unaccounted': [], 'bad_releases': [],
               'final_refusals': ['node_capacity', 'headroom', 'prep_slot', 'node_capacity',
                                  'node_capacity'],
               'claims_after': 0, 'charged_after': 0}
    outcome.update(changes)
    return outcome


def churn_summary(**changes):
    summary = {'refusals': {'prep_slot': 10, 'node_capacity': 40},
               'sessions_by_daemon': {'fctest': 100, 'fctest2': 90}, 'claims_max': 3,
               'vector_violations': [], 'op_failures': 0, 'op_failure_samples': [],
               'capture_mismatches': 0, 'claims_after': 0, 'charged_after': 0,
               'unaccounted': {}, 'node_faults': 0, 'helper_rss_growth': 4 * MIB,
               'helper_fd_spread': 6, 'watermark_advanced': True, 'pointers_end': {},
               'delete_retries': 0, 'delete_retry_release_ms': m.stats([]),
               'delete_retry_samples': [], 'delete_leaks': 0, 'delete_leak_samples': []}
    summary.update(changes)
    return summary


def failing(checks):
    return [c['check'] for c in checks if not c['pass']]


class PassRules(unittest.TestCase):
    def test_s2_passes(self):
        self.assertEqual(failing(m.check_s2(s2_outcome(), CEILINGS)), [])

    def test_s2_four_intents_fail(self):
        self.assertEqual(failing(m.check_s2(s2_outcome(intent=4), CEILINGS)),
                         ['exactly three of eight reach INTENT'])

    def test_s2_oversubscription_fails(self):
        got = failing(m.check_s2(s2_outcome(claims_max=4, vector_violations=['slots 4 > 3']),
                                 CEILINGS))
        self.assertIn('never more than three node claims', got)
        self.assertIn('the node vector is never exceeded', got)

    def test_s2_a_token_without_absent_fails(self):
        self.assertEqual(failing(m.check_s2(s2_outcome(unaccounted=[7]), CEILINGS)),
                         ['every refused token gets a durable ABSENT'])

    def test_s2_a_release_by_other_evidence_fails(self):
        bad = [{'id': 'sb-1', 'evidence': 'r-2', 'receipt': 'r-1'}]
        self.assertEqual(failing(m.check_s2(s2_outcome(bad_releases=bad), CEILINGS)),
                         ['every refused row is released only by its ledger receipt'])

    def test_s2_an_unexplained_refusal_fails(self):
        self.assertEqual(failing(m.check_s2(s2_outcome(final_refusals=['unavailable']),
                                            CEILINGS)),
                         ['every refusal is a capacity refusal'])

    def test_s2_a_leak_fails(self):
        self.assertEqual(failing(m.check_s2(s2_outcome(charged_after=1), CEILINGS)),
                         ['all claims are released after the deletes'])

    def test_churn_passes(self):
        self.assertEqual(failing(m.check_churn(churn_summary(), CEILINGS, 25)), [])

    def test_churn_unexplained_refusal(self):
        self.assertEqual(failing(m.check_churn(churn_summary(refusals={'other': 1}),
                                               CEILINGS, 5)),
                         ['no unexplained refusal'])

    def test_churn_starvation(self):
        got = failing(m.check_churn(churn_summary(sessions_by_daemon={'a': 100, 'b': 49}),
                                    CEILINGS, 5))
        self.assertEqual(got, ['neither daemon starves'])
        self.assertEqual(failing(m.check_churn(
            churn_summary(sessions_by_daemon={'a': 100, 'b': 50}), CEILINGS, 5)), [])

    def test_churn_leaks_and_losses(self):
        got = failing(m.check_churn(churn_summary(claims_after=1, capture_mismatches=2,
                                                  op_failures=1, node_faults=1),
                                    CEILINGS, 5))
        self.assertEqual(got, ['every Exec and Delete succeeds', 'no capture loss',
                               'no capacity leak', 'no node fault'])

    def test_churn_helper_growth(self):
        got = failing(m.check_churn(churn_summary(helper_rss_growth=33 * MIB,
                                                  helper_fd_spread=40), CEILINGS, 5))
        self.assertEqual(got, ['helper RSS stays bounded', 'helper descriptors stay bounded'])

    def test_churn_delete_retries_and_leaks(self):
        retried = churn_summary(delete_retries=2, delete_retry_release_ms=m.stats([1200, 3400]))
        self.assertEqual(failing(m.check_churn(retried, CEILINGS, 25)),
                         ['every Delete succeeds at its first attempt'])
        leaked = churn_summary(delete_retries=1, delete_leaks=1,
                               delete_leak_samples=[{'id': 'sb-1', 'attempts': 61}])
        self.assertEqual(failing(m.check_churn(leaked, CEILINGS, 25)),
                         ['every Delete succeeds at its first attempt',
                          'every retried Delete releases within 60 s'])

    def test_watermark_is_checked_only_after_a_lease_and_a_pass(self):
        stuck = churn_summary(watermark_advanced=False)
        self.assertEqual(failing(m.check_churn(stuck, CEILINGS, 16)), [])
        self.assertEqual(failing(m.check_churn(stuck, CEILINGS, 17)),
                         ['compaction advances the watermark'])

    def test_format(self):
        self.assertEqual(m.format_checks([m.check('x', True), m.check('y', False, 'why')]),
                         ['PASS x', 'FAIL y: why'])


class Teardown(unittest.TestCase):
    def state(self):
        return {'instances': ['i1', 'i2'], 'made': [
            {'kind': 'dir', 'target': m.WORK},
            {'kind': 'loop', 'target': '/dev/loop7', 'backing': m.LEDGER_IMAGE},
            {'kind': 'dir', 'target': m.LEDGER_MOUNT},
            {'kind': 'mount', 'target': m.LEDGER_MOUNT},
            {'kind': 'account', 'target': 'kilnd-fctest'},
            {'kind': 'account', 'target': 'kilnd-fctest2'},
            {'kind': 'unit', 'target': 'kilnd-fctest.service'},
            {'kind': 'unit', 'target': 'kilnd-fctest2.service'},
            {'kind': 'unit', 'target': m.NODE_UNIT},
            {'kind': 'node', 'target': m.NODE_DIR},
        ]}

    def test_full_plan_order(self):
        plan = m.teardown_plan(self.state())
        kinds = [k for k, _ in plan]
        self.assertEqual(plan[0], ('stop-node', m.NODE_UNIT))
        # The node stops before anything of it is removed; the ledger's filesystem goes
        # last, unmounted before its loop is detached, and WORK after both.
        self.assertLess(kinds.index('kill-cgroup'), kinds.index('remove-account'))
        self.assertLess(kinds.index('unmount'), kinds.index('detach-loop'))
        self.assertEqual(plan[-1], ('remove-tree', m.WORK))
        self.assertEqual(plan[-2], ('remove-tree', m.LEDGER_MOUNT))
        self.assertIn(('kill-cgroup', m.FC_TREE + '/i1'), plan)
        self.assertIn(('kill-cgroup', m.FC_TREE + '/i2'), plan)
        self.assertIn(('detach-loop', '/dev/loop7'), plan)
        self.assertEqual(kinds.count('remove-account'), 2)

    def test_only_what_was_recorded(self):
        # A setup that stopped after making WORK and the loop removes just those.
        state = {'made': [{'kind': 'dir', 'target': m.WORK},
                          {'kind': 'loop', 'target': '/dev/loop3', 'backing': m.LEDGER_IMAGE}]}
        self.assertEqual(m.teardown_plan(state), [('detach-loop', '/dev/loop3'),
                                                  ('remove-tree', m.WORK)])
        self.assertEqual(m.teardown_plan({}), [])

    def test_nothing_outside_the_node_is_in_any_plan(self):
        for _, target in m.teardown_plan(self.state()):
            self.assertFalse(target.startswith('/var/lib/kilnd/'), target)
            self.assertNotEqual(target, '/var/lib/kilnd-helper')
            self.assertNotIn('kilnd.service', target.replace('kilnd-fctest', ''))

    def test_final_inventory(self):
        clean = {'offline_inventory': {'verdict': 'explained', 'unexplained': [], 'faults': 0,
                                       'failstop': False},
                 'unreleased_claims': 0, 'allocations': [{'allocation': 'a', 'present': []}]}
        self.assertEqual(failing(m.check_final(clean)), [])
        self.assertEqual(failing(m.check_final(None)), ['the node wrote its final inventory'])
        dirty = dict(clean, offline_inventory={'verdict': 'unexplained', 'unexplained': ['x']},
                     unreleased_claims=1,
                     allocations=[{'allocation': 'a', 'present': ['jail']}])
        self.assertEqual(failing(m.check_final(dirty)),
                         ['the final offline inventory is clean', 'no claim is left unreleased',
                          'no allocation is left on the host'])
        self.assertEqual(failing(m.check_final({'offline_inventory': {'error': 'locked'}})),
                         ['the final offline inventory is clean'])

    def test_node_processes_skip_this_script(self):
        out = '\n'.join([
            '9395 sudo python3 -I /var/tmp/m32-src/scripts/firecracker-two-daemon-stress.py'
            ' --evidence /var/tmp/m3-2-ev/w1 setup --bin /var/tmp/m32-bin',
            '9396 python3 -I /var/tmp/m32-src/scripts/firecracker-two-daemon-stress.py'
            ' --evidence /var/tmp/m3-2-ev/w1 setup',
            '9400 bash /tmp/m32-s/20-stress.sh w1 firecracker',
            '500 /usr/bin/firecracker --id x --config-file /config.json',
            '501 /var/tmp/m3-2/bin/kilnd-lib-tests --ignored',
            '502 /var/tmp/m3-2/artifacts/jailer --id y',
        ])
        self.assertEqual(m.node_processes(out, {9400}),
                         ['500 /usr/bin/firecracker --id x --config-file /config.json',
                          '501 /var/tmp/m3-2/bin/kilnd-lib-tests --ignored',
                          '502 /var/tmp/m3-2/artifacts/jailer --id y'])
        self.assertIn(os.getpid(), m.own_ancestry() or {os.getpid()})

    def test_inventory_problems(self):
        clean = {'paths': [], 'accounts': [], 'units': {u: 'inactive' for u in m.UNITS},
                 'loops': [], 'mounts': [], 'processes': [], 'sockets': []}
        self.assertEqual(m.inventory_problems(clean), [])
        dirty = dict(clean, paths=['/opt/kilnd'], accounts=['kilnd-fctest2'],
                     units={m.NODE_UNIT: 'active'}, loops=[('loop7', m.LEDGER_IMAGE)],
                     mounts=[m.LEDGER_MOUNT], processes=['123 firecracker'],
                     sockets=['/run/kilnd-fctest/kilnd.sock'])
        self.assertEqual(len(m.inventory_problems(dirty)), 7)


FAKE_KILNDCTL = r"""
import fcntl, json, os, random, sqlite3, sys, time
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
args = sys.argv[1:]
socket = args[args.index('--socket') + 1]
del args[args.index('--socket'):args.index('--socket') + 2]
daemon = os.path.dirname(socket)
instance = open(os.path.join(daemon, 'instance')).read().strip()
if os.path.exists(os.path.join(daemon, 'dead')):
    sys.stderr.write('kilndctl: unavailable: connection refused\n')
    sys.exit(1)
lock = open(os.path.join(root, 'lock'), 'w')
fcntl.flock(lock, fcntl.LOCK_EX)
ledger = sqlite3.connect(os.path.join(root, 'ledger.db'), isolation_level=None)
db = sqlite3.connect(os.path.join(daemon, 'kilnd.db'), isolation_level=None)
now = int(time.time() * 1000)
generation = ledger.execute('UPDATE meta SET generation = generation + 1 RETURNING generation').fetchone()[0]
command = args[0]
if command == 'health':
    claims = ledger.execute('SELECT COUNT(*) FROM capacity_claims WHERE released_generation IS NULL').fetchone()[0]
    print('status:             serving')
    print(f'node reservations:   sandboxes {claims}/3, memory 0/1 bytes, pids 0/1, disk 0/1 bytes')
elif command == 'create':
    seq = ledger.execute('UPDATE instance_tokens SET issue_next = issue_next + 1 WHERE instance_id = ? RETURNING issue_next - 1', (instance,)).fetchone()[0]
    allocation = f'{seq:016x}' + os.urandom(8).hex()
    sandbox = 'sb-' + os.urandom(8).hex()
    claims = ledger.execute('SELECT COUNT(*) FROM capacity_claims WHERE released_generation IS NULL').fetchone()[0]
    if claims >= 3:
        receipt = 'r-' + allocation
        ledger.execute('INSERT INTO retired_tokens VALUES (?, ?, ?, ?)', (instance, allocation, receipt, seq))
        db.execute("INSERT INTO sandboxes VALUES (?, 'failed', ?, ?, 'refused', ?, 'fenced')", (sandbox, allocation, receipt, now))
        sys.stderr.write('kilndctl: resourceexhausted: node capacity exhausted: Slots\n')
        sys.exit(1)
    ledger.execute("INSERT INTO allocations VALUES (?, ?, ?, 'ready', ?)", (instance, allocation, sandbox, generation))
    ledger.execute('INSERT INTO capacity_claims VALUES (?, ?, 1, 1, 1, 1, 1, 1, NULL)', (instance, allocation))
    db.execute("INSERT INTO sandboxes VALUES (?, 'ready', ?, NULL, NULL, ?, 'fenced')", (sandbox, allocation, now))
    del lock
    time.sleep(0.05)
    print(sandbox)
elif command == 'exec':
    sandbox = [a for a in args[1:args.index('--')] if a.startswith('sb-')][0]
    argv = args[args.index('--') + 1:]
    out = ' '.join(argv[1:]) + '\n' if argv[0] == 'echo' else 'ran\n'
    if '--stdin' in args:
        sys.stdin.read()
    db.execute("INSERT INTO executions VALUES (?, ?, 'finished', 0, ?, ?, 0, 1, x'', 0, 0, NULL, ?)",
               ('ex-' + os.urandom(8).hex(), sandbox, out.encode(), len(out), now))
    sys.stdout.write(out)
elif command == 'get':
    print('state: ready')
elif command == 'rm':
    sandbox = args[1]
    row = db.execute('SELECT allocation_id FROM sandboxes WHERE id = ?', (sandbox,)).fetchone()
    ledger.execute("UPDATE allocations SET phase = 'absent' WHERE allocation_id = ?", (row[0],))
    ledger.execute('UPDATE capacity_claims SET released_generation = ? WHERE allocation_id = ?', (generation, row[0]))
    db.execute("UPDATE sandboxes SET state = 'deleted', release_evidence_id = ? WHERE id = ?", ('d-' + row[0], sandbox))
else:
    sys.exit(2)
"""

LEDGER_SCHEMA = """
CREATE TABLE meta (generation INTEGER);
INSERT INTO meta VALUES (1);
CREATE TABLE allocations (instance_id, allocation_id, sandbox_id, phase, created_generation);
CREATE TABLE capacity_claims (instance_id, allocation_id, memory_bytes, disk_bytes, pids,
    host_cpu_millis, virtual_cpu_slots, host_pids, released_generation);
CREATE TABLE instance_tokens (instance_id, issue_next, watermark, retained_admitted);
CREATE TABLE retired_tokens (instance_id, allocation_id, receipt_id, issue_seq);
CREATE TABLE node_faults (id);
CREATE TABLE compaction_log (id, tokens_deleted);
"""

DAEMON_SCHEMA = """
CREATE TABLE sandboxes (id, state, allocation_id, release_evidence_id, failure_reason,
    created_at_ms, accounting_kind);
CREATE TABLE executions (id, sandbox_id, state, exit_code, stdout BLOB, stdout_bytes,
    stdout_truncated, stdout_total_bytes_known, stderr BLOB, stderr_bytes, stderr_truncated,
    failure_reason, started_at_ms);
"""


class FakeNode(unittest.TestCase):
    """Every scenario but s5 end to end against a fake node: a kilndctl that keeps the
    ledger's and daemons' tables the script reads, and a responder for the node's requests.
    It proves the script's plumbing, not the product: the VM runs prove that."""

    def setUp(self):
        import sqlite3
        import sys
        import threading
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        self.saved = {k: getattr(m, k) for k in ('NODE_DIR', 'BIN', 'STATE', 'unit_state',
                                                 'uptime_minutes', 'sync', 'SAMPLE_SECONDS',
                                                 'batch_probe')}
        m.NODE_DIR, m.BIN, m.STATE = (os.path.join(root, 'node'), os.path.join(root, 'bin'),
                                      os.path.join(root, 'state.json'))
        m.unit_state = lambda unit: 'active'
        m.uptime_minutes = lambda: 1.0
        m.sync = lambda: None
        m.SAMPLE_SECONDS = 1
        # RTC-18's probe is a real kilnd test binary: here only its place in s1 is checked.
        m.batch_probe = lambda scenario: {'passed': True, 'fake': True}
        for d in ('node/requests', 'node/responses', 'bin', 'ev'):
            os.makedirs(os.path.join(root, d))
        kilndctl = os.path.join(root, 'bin', 'kilndctl')
        with open(kilndctl, 'w') as f:
            f.write(f'#!{sys.executable} -I\n' + FAKE_KILNDCTL)
        os.chmod(kilndctl, 0o755)
        self.keep = []
        ledger = os.path.join(root, 'ledger.db')
        conn = sqlite3.connect(ledger, isolation_level=None)
        conn.execute('PRAGMA journal_mode=WAL')
        conn.executescript(LEDGER_SCHEMA)
        self.keep.append(conn)
        daemons = []
        for i, name in enumerate(('fctest', 'fctest2')):
            instance = f'{i + 1:032x}'
            directory = os.path.join(root, name)
            os.makedirs(directory)
            with open(os.path.join(directory, 'instance'), 'w') as f:
                f.write(instance)
            db = sqlite3.connect(os.path.join(directory, 'kilnd.db'), isolation_level=None)
            db.execute('PRAGMA journal_mode=WAL')
            db.executescript(DAEMON_SCHEMA)
            self.keep.append(db)
            conn.execute('INSERT INTO instance_tokens VALUES (?, 1, 1, 0)', (instance,))
            daemons.append({'name': name, 'instance': instance, 'state_dir': directory,
                            'socket': os.path.join(directory, 'kilnd.sock'),
                            'cgroup': '/none'})
        node = {'helper': {'ledger': ledger, 'log': os.path.join(root, 'child.log'),
                           'control': os.path.join(root, 'control.sock'), 'pid': None},
                'policy': {'ceilings': CEILINGS, 'shared': {'memory_bytes': 128 * MIB}},
                'daemons': daemons}
        m.write_json(os.path.join(m.NODE_DIR, 'node.json'), node)
        m.write_json(m.STATE, {'setup_done': True})
        self.stop = threading.Event()
        self.responder = threading.Thread(target=self.respond, daemon=True)
        self.responder.start()

    def respond(self):
        requests = os.path.join(m.NODE_DIR, 'requests')
        while not self.stop.is_set():
            for name in sorted(os.listdir(requests)):
                if name.endswith('.partial'):
                    continue
                seq, verb = name.split('-', 1)
                with open(os.path.join(requests, name)) as f:
                    argument = f.read()
                marker = os.path.join(self.tmp.name, argument, 'dead')
                if verb == 'kill-daemon':
                    open(marker, 'w').close()
                elif verb == 'start-daemon':
                    os.remove(marker)
                m.write_json(os.path.join(m.NODE_DIR, 'responses', f'{seq}.json'),
                             {'seq': seq, 'verb': verb, 'reply': {'ok': argument}})
                os.remove(os.path.join(requests, name))
            self.stop.wait(0.05)

    def tearDown(self):
        self.stop.set()
        self.responder.join()
        for conn in self.keep:
            conn.close()
        for k, v in self.saved.items():
            setattr(m, k, v)
        self.tmp.cleanup()

    def run_scenario(self, argv):
        import argparse
        import contextlib
        import io
        evidence = os.path.join(self.tmp.name, 'ev')
        node = m.Node()
        views = m.Views(node)
        defaults = {'evidence': evidence, 'force': False, 'label': None, 'lanes': 2,
                    'max_minutes': 2, 'warmup': 2, 'outage': 2, 'kill': 'daemon'}
        args = argparse.Namespace(**dict(defaults, **argv))
        runner = getattr(m, 'run_' + argv['command'])
        with contextlib.redirect_stdout(io.StringIO()) as out:
            passed = runner(args, node, views)
        return passed, out.getvalue()

    def test_scenarios_end_to_end(self):
        for argv, name in (({'command': 's2'}, 's2'),
                           ({'command': 's1', 'minutes': 0.15}, 's1'),
                           ({'command': 's3'}, 's3'),
                           ({'command': 's4', 'kill': 'daemon'}, 's4-daemon')):
            passed, out = self.run_scenario(argv)
            directory = os.path.join(self.tmp.name, 'ev', name)
            self.assertEqual(m.scenario_state(directory), 'complete', name)
            with open(os.path.join(directory, 'done.json')) as f:
                done = json.load(f)
            failed = [c for c in done['checks'] if not c['pass']]
            if name == 's3':
                # The fake keeps no session cgroups and floods nothing: only these fail.
                self.assertEqual([c['check'] for c in failed],
                                 ['the output flood is kept bounded and reported, not lost '
                                  'silently'] if failed else [], out)
                continue
            self.assertEqual(failed, [], out)
            self.assertTrue(passed, out)
            self.assertIn('PASS', out)
        with open(os.path.join(self.tmp.name, 'ev', 's2', 'metrics.json')) as f:
            s2 = json.load(f)
        self.assertEqual(s2['intent'], 3)
        self.assertEqual(len(s2['final_refusals']), 5)
        with open(os.path.join(self.tmp.name, 'ev', 's1', 'metrics.json')) as f:
            s1 = json.load(f)
        self.assertGreater(s1['sessions'], 0)
        self.assertGreater(s1['next_admit_start_ms']['n'], 0)
        # A complete scenario is not run again.
        passed, out = self.run_scenario({'command': 's2'})
        self.assertTrue(passed)
        self.assertIn('s2: already complete', out)


if __name__ == '__main__':
    unittest.main(verbosity=1)
