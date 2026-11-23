#!/usr/bin/env python3
"""M3-2: Firecracker capacity stress across two daemons, on the real chain, through the
public API only. Run in the kiln Lima VM as root, under the shared VM lock, with a release
build of this checkout (docs/setup.md, "Capacity stress across two daemons"):

    sudo python3 -I scripts/firecracker-two-daemon-stress.py --evidence DIR setup --bin BIN
    sudo python3 -I scripts/firecracker-two-daemon-stress.py --evidence DIR s2
    sudo python3 -I scripts/firecracker-two-daemon-stress.py --evidence DIR s1 --minutes 25
    sudo python3 -I scripts/firecracker-two-daemon-stress.py --evidence DIR s3
    sudo python3 -I scripts/firecracker-two-daemon-stress.py --evidence DIR s4 --kill daemon
    sudo python3 -I scripts/firecracker-two-daemon-stress.py --evidence DIR s5
    sudo python3 -I scripts/firecracker-two-daemon-stress.py --evidence DIR teardown
    sudo python3 -I scripts/firecracker-two-daemon-stress.py --evidence DIR inventory

BIN holds `kilnd` and `kilndctl` (the `firecracker-test-deployment` profile), `kilnd-helper`
(for its create-timings report) and `kilnd-lib-tests`, the static release build of kilnd's
library tests, whose node fixture is the only helper that serves the test profile.

`setup` starts one test helper and two kilnd instances (`fctest` and `fctest2`: own account,
unit, database, socket and instance ID) that share it and its node ledger, under the default
node policy. The helper's root, and so its ledger, is on a small loop-backed filesystem
whose image lives in /var/tmp/m3-2 and which is mounted at /run/kilnd-m32, so s5 can
throttle the ledger alone. Everything the node makes outside /var/tmp/m3-2 is what the
isolated test deployment always makes (deploy/firecracker-test/README.md): /opt/kilnd,
/var/lib/kilnd-helper/{jails,work}, /sys/fs/cgroup/kilnd-firecracker, the two accounts and
their transient units, /var/lib/kilnd-fctest{,2} and /run/kilnd-fctest{,2}. Setup refuses if
any of it already exists; `teardown` removes exactly what was recorded, and `inventory` proves
that nothing of it is left.

Each scenario is a resumable subcommand with its own evidence subdirectory: JSON lines
(`records.jsonl`, `samples.jsonl`), a short `summary.txt` with one PASS or FAIL line per
check, and `done.json` once complete. Evidence is synced after every scenario. A rerun of a
complete scenario does nothing (use --force); one that finds partial results moves them
aside and runs again. Hostile payloads (s3) run only inside guest sessions; they are the
files in scripts/stress-payloads/.

kiln is experimental shared-kernel isolation and this backend is an experimental microVM
test deployment: passing these scenarios shows the node's limits hold for these workloads
on one test node. It does not show readiness for hostile multi-tenant production.
"""
import argparse
import bisect
import hashlib
import json
import os
import random
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PAYLOADS = os.path.join(HERE, 'stress-payloads')

WORK = '/var/tmp/m3-2'
NODE_DIR = WORK + '/node'
BIN = WORK + '/bin'
ARTIFACTS = WORK + '/artifacts'
LEDGER_IMAGE = WORK + '/ledger.img'
LEDGER_IMAGE_BYTES = 512 << 20
LEDGER_MOUNT = '/run/kilnd-m32'
HELPER_ROOT = LEDGER_MOUNT + '/helper'
STATE = WORK + '/state.json'
NODE_UNIT = 'kilnd-m32-node.service'
NODE_TEST = 'helper::firecracker::tests::stress::m3_linux_root_two_daemon_stress_node'
DAEMONS = ('fctest', 'fctest2')
# Exactly deploy/kilnd-helper.service's bounding set, as scripts/b4-vm-tests.sh runs it.
CAPS = ('-all,+chown,+dac_override,+fowner,+kill,+setgid,+setuid,+setpcap,+net_admin,'
        '+sys_chroot,+sys_admin,+mknod')
JAIL_BASE = '/var/lib/kilnd-helper/jails'
WORK_BASE = '/var/lib/kilnd-helper/work'
CGROUP_ROOT = '/sys/fs/cgroup'
FC_TREE = CGROUP_ROOT + '/kilnd-firecracker'
# What the node makes outside WORK. None of it may exist before setup, and none after
# teardown. /var/lib/kilnd-helper itself is the installed helper's and is never touched.
NODE_PATHS = ('/opt/kilnd', JAIL_BASE, WORK_BASE, FC_TREE, LEDGER_MOUNT,
              '/var/lib/kilnd-fctest', '/var/lib/kilnd-fctest2',
              '/run/kilnd-fctest', '/run/kilnd-fctest2', '/run/kilnd-fctest-helper',
              '/var/lib/kilnd-b6-copies')
ACCOUNTS = ('kilnd-fctest', 'kilnd-fctest2')
UNITS = (NODE_UNIT, 'kilnd-fctest.service', 'kilnd-fctest2.service')
# A scenario starts only on a VM booted less than this long ago, so a long-running test VM
# is restarted between phases rather than run into its uptime limits.
MAX_UPTIME_MINUTES = 90
SAMPLE_SECONDS = 5
MIB = 1 << 20
GUEST_MEMORY = 768 * MIB
ASSUMED_OVERHEAD = 128 * MIB
SCENARIOS = ('s1', 's2', 's3', 's4-daemon', 's4-helper', 's4-L', 's5')
# Refusals a Create may meet under contention by design: P's two preparation slots, the
# node's ceilings and RTC-17's admitted headroom. Anything else is unexplained.
# The plan's refusal types: headroom, preparation slot and RESOURCE_EXHAUSTED, the last being the
# helper's node vector (node_capacity) or the daemon's own node budget (daemon_budget,
# manager.rs's `node <resource> budget exhausted`).
EXPECTED_REFUSALS = ('prep_slot', 'node_capacity', 'daemon_budget', 'headroom')


# ---------------------------------------------------------------------------------------
# Pure parts (scripts/firecracker-two-daemon-stress-tests.py tests these).
# ---------------------------------------------------------------------------------------

def percentile(values, q):
    """Nearest rank, as the helper's create-timings report and B5 take it."""
    ordered = sorted(values)
    if not ordered:
        return None
    rank = int(-(-q * len(ordered) // 1))  # ceil
    return ordered[min(max(rank, 1), len(ordered)) - 1]


def stats(values):
    values = list(values)
    if not values:
        return {'n': 0, 'min': None, 'p50': None, 'p95': None, 'max': None}
    return {'n': len(values), 'min': min(values), 'p50': percentile(values, 0.5),
            'p95': percentile(values, 0.95), 'max': max(values)}


def classify_refusal(stderr):
    """A failed kilndctl call's type, from its message (`kilndctl: <code>: <message>`)."""
    text = (stderr or '').lower()
    if 'preparation slot' in text:
        return 'prep_slot'
    if 'node capacity exhausted' in text:
        return 'node_capacity'
    if ('headroom' in text or 'never-admitted' in text or 'past its share' in text
            or 'issue sequence is exhausted' in text):
        return 'headroom'
    if re.search(r'node [a-z_ ]+ budget exhausted', text):
        return 'daemon_budget'
    if 'client timeout' in text:
        return 'client_timeout'
    if 'resourceexhausted' in text or 'resource_exhausted' in text:
        return 'resource_exhausted_other'
    if 'deadline' in text:
        return 'deadline'
    if 'unavailable' in text:
        return 'unavailable'
    return 'other'


def scenario_state(directory):
    """'absent', 'partial' or 'complete'. Complete means done.json says so and names as
    many records as records.jsonl holds; anything else that exists is partial."""
    if not os.path.isdir(directory):
        return 'absent'
    try:
        with open(os.path.join(directory, 'done.json')) as f:
            done = json.load(f)
        with open(os.path.join(directory, 'records.jsonl')) as f:
            count = sum(1 for line in f if line.strip())
    except (OSError, ValueError):
        return 'partial'
    if done.get('complete') is True and done.get('records') == count:
        return 'complete'
    return 'partial'


def partial_name(directory):
    """The first free `<dir>.partial-N` to move a partial run aside to."""
    n = 1
    while os.path.exists(f'{directory}.partial-{n}'):
        n += 1
    return f'{directory}.partial-{n}'


def next_admit_gaps(releases, creates):
    """For each release (a Delete's return, unix ms), the first successful Create that
    started at or after it: (start - release, ready - release) in ms. `creates` are
    (start_ms, end_ms) pairs of successful Creates."""
    ordered = sorted(creates)
    starts = [c[0] for c in ordered]
    gaps = []
    for release in sorted(releases):
        i = bisect.bisect_left(starts, release)
        if i < len(ordered):
            start, end = ordered[i]
            gaps.append((start - release, end - release))
    return gaps


def vector_violations(totals, ceilings):
    """Dimensions where reserved (claims plus the shared reserve) exceeds the ceiling.
    `totals` and `ceilings` use the helper's names."""
    out = []
    for name in ('memory_bytes', 'disk_bytes', 'host_cpu_millis', 'virtual_cpu_slots',
                 'pids', 'host_pids', 'slots'):
        if name in totals and name in ceilings and totals[name] > ceilings[name]:
            out.append(f'{name} {totals[name]} > {ceilings[name]}')
    return out


def unaccounted_tokens(pointers, retired_seqs, allocation_seqs):
    """Issued sequence numbers at or above the watermark with no durable outcome: neither
    an allocation row (admitted) nor a retired token (its ABSENT). At quiescence this must
    be empty for every instance. `pointers` is (watermark, issue_next)."""
    watermark, issue_next = pointers
    known = set(retired_seqs) | set(allocation_seqs)
    return [seq for seq in range(watermark, issue_next) if seq not in known]


def host_name(instance, allocation):
    """An allocation's node-unique host name (identity.rs host_name): its jail, work
    directory and cgroup are named for it, never for the bare allocation ID."""
    digest = hashlib.sha256(
        f'kilnd-firecracker-host-name-v1\0{instance}\0{allocation}'.encode()).hexdigest()
    return 'fc-' + digest[:32]


def seq_of(allocation_id):
    """An allocation token's issue sequence number: its first 16 hex digits."""
    return int(allocation_id[:16], 16)


def quiescent_mismatch(claims, charged):
    """Per instance, allocation IDs the ledger holds a claim for and the daemon's database
    does not charge, and the reverse. Both arguments map instance -> set of allocations."""
    out = {}
    for instance in sorted(set(claims) | set(charged)):
        ledger_only = sorted(set(claims.get(instance, ())) - set(charged.get(instance, ())))
        daemon_only = sorted(set(charged.get(instance, ())) - set(claims.get(instance, ())))
        if ledger_only or daemon_only:
            out[instance] = {'ledger_only': ledger_only, 'daemon_only': daemon_only}
    return out


def guest_mapping_rss(smaps, guest_bytes=GUEST_MEMORY):
    """The resident bytes of the VMM's guest memory mapping: the mapping whose size is
    closest to the guest's memory and within 1/16 of it. None when there is none."""
    best = None
    size = rss = None
    for line in smaps.splitlines():
        if re.match(r'^[0-9a-f]+-[0-9a-f]+ ', line):
            if size is not None and rss is not None:
                best = _closer(best, size, rss, guest_bytes)
            size = rss = None
        elif line.startswith('Size:'):
            size = int(line.split()[1]) * 1024
        elif line.startswith('Rss:'):
            rss = int(line.split()[1]) * 1024
    if size is not None and rss is not None:
        best = _closer(best, size, rss, guest_bytes)
    if best is None or abs(best[0] - guest_bytes) > guest_bytes // 16:
        return None
    return best[1]


def _closer(best, size, rss, target):
    if best is None or abs(size - target) < abs(best[0] - target):
        return (size, rss)
    return best


def session_overhead(memory_current, guest_rss):
    """Host memory charged to a session beyond the guest's own resident memory."""
    if memory_current is None or guest_rss is None:
        return None
    return memory_current - guest_rss


HEALTH_LINE = re.compile(r'^([a-z ]+):\s+(.*)$')


def parse_health(text):
    """kilndctl health's lines as numbers where they are numbers."""
    out = {}
    for line in text.splitlines():
        m = HEALTH_LINE.match(line.strip())
        if not m:
            continue
        key, value = m.group(1).strip(), m.group(2).strip()
        if key == 'node reservations':
            for name, used, cap in re.findall(r'(sandboxes|memory|pids|disk) (\d+)/(\d+)', value):
                out[f'node_{name}'] = int(used)
                out[f'node_{name}_max'] = int(cap)
        elif key == 'host reservations':
            for name, used, cap in re.findall(r'(cpu|vcpus|host pids) (\d+)/(\d+)', value):
                name = name.replace(' ', '_')
                out[f'host_{name}'] = int(used)
                out[f'host_{name}_max'] = int(cap)
        elif key == 'rejected creates':
            out['rejected_creates'] = int(value) if value.isdigit() else value
        else:
            out[key.replace(' ', '_')] = value
    return out


def check(name, passed, detail=''):
    return {'check': name, 'pass': bool(passed), 'detail': detail}


def format_checks(checks):
    return [f"{'PASS' if c['pass'] else 'FAIL'} {c['check']}"
            + (f": {c['detail']}" if c['detail'] else '') for c in checks]


def check_s2(outcome, ceilings):
    """Section M3-2 scenario 2's rules over one race's outcome (see run_s2)."""
    checks = [
        check('exactly three of eight reach INTENT', outcome['intent'] == 3,
              f"{outcome['intent']} allocations created"),
        check('three Creates are READY', outcome['ready'] == 3, f"{outcome['ready']} READY"),
        check('never more than three node claims', outcome['claims_max'] <= ceilings['slots'],
              f"max {outcome['claims_max']} of {ceilings['slots']}"),
        check('the node vector is never exceeded', not outcome['vector_violations'],
              '; '.join(outcome['vector_violations'][:5])),
        check('every refused token gets a durable ABSENT', not outcome['unaccounted'],
              f"unaccounted seqs {outcome['unaccounted'][:10]}"),
        check('every refused row is released only by its ledger receipt',
              not outcome['bad_releases'], json.dumps(outcome['bad_releases'][:5])),
        check('every refusal is a capacity refusal',
              all(t in EXPECTED_REFUSALS for t in outcome['final_refusals']),
              json.dumps(outcome['final_refusals'])),
        check('all claims are released after the deletes', outcome['claims_after'] == 0
              and outcome['charged_after'] == 0,
              f"claims {outcome['claims_after']}, charged rows {outcome['charged_after']}"),
    ]
    return checks


def check_churn(summary, ceilings, minutes):
    """Scenario 1's rules (also the neighbours' in s3 and s5): see run_s1."""
    other = {k: v for k, v in summary['refusals'].items() if k not in EXPECTED_REFUSALS}
    sessions = summary['sessions_by_daemon']
    low, high = min(sessions.values() or [0]), max(sessions.values() or [0])
    checks = [
        check('never more than the node slots claimed', summary['claims_max'] <= ceilings['slots'],
              f"max {summary['claims_max']} of {ceilings['slots']}"),
        check('the node vector is never exceeded', not summary['vector_violations'],
              '; '.join(summary['vector_violations'][:5])),
        check('no unexplained refusal', not other, json.dumps(other)),
        check('every Exec and Delete succeeds', summary['op_failures'] == 0,
              f"{summary['op_failures']} failed: {json.dumps(summary['op_failure_samples'][:3])}"),
        check('every Delete succeeds at its first attempt', summary['delete_retries'] == 0,
              f"{summary['delete_retries']} needed a retry, released after "
              f"{json.dumps(summary['delete_retry_release_ms'])} ms; "
              f"{json.dumps(summary['delete_retry_samples'][:2])}"),
        check(f'every retried Delete releases within {DELETE_RETRY_SECONDS} s',
              summary['delete_leaks'] == 0,
              f"{summary['delete_leaks']} leaked: {json.dumps(summary['delete_leak_samples'][:3])}"),
        check('no capture loss', summary['capture_mismatches'] == 0,
              f"{summary['capture_mismatches']} outputs differ"),
        check('no capacity leak', summary['claims_after'] == 0 and summary['charged_after'] == 0,
              f"claims {summary['claims_after']}, charged rows {summary['charged_after']}"),
        check('every issued token has a durable outcome', not summary['unaccounted'],
              json.dumps(summary['unaccounted'])[:300]),
        # One daemon starving the other: each completes at least half the other's count.
        check('neither daemon starves', high == 0 or low * 2 >= high,
              json.dumps(sessions)),
        check('no node fault', summary['node_faults'] == 0,
              f"{summary['node_faults']} samples with a fault"),
        check('helper RSS stays bounded', summary['helper_rss_growth'] is None
              or summary['helper_rss_growth'] <= 32 * MIB,
              f"growth {summary['helper_rss_growth']} bytes"),
        check('helper descriptors stay bounded', summary['helper_fd_spread'] is None
              or summary['helper_fd_spread'] <= 32, f"spread {summary['helper_fd_spread']}"),
    ]
    if minutes is not None and minutes >= 17:
        # A lease (15 min) plus a pass (1 min) has passed: W must have advanced.
        checks.append(check('compaction advances the watermark', summary['watermark_advanced'],
                            json.dumps(summary['pointers_end'])))
    return checks


def teardown_plan(state):
    """The ordered removals for what `state` (setup's record) says was made, and nothing
    else. Each action is (kind, target)."""
    made = state.get('made', [])
    kinds = {}
    for item in made:
        kinds.setdefault(item['kind'], []).append(item)
    plan = []
    if any(i['target'] == NODE_UNIT for i in kinds.get('unit', [])):
        plan.append(('stop-node', NODE_UNIT))
    for item in kinds.get('unit', []):
        if item['target'] != NODE_UNIT:
            plan.append(('stop-unit', item['target']))
    if any(i['kind'] == 'node' for i in made):
        for instance in state.get('instances', []):
            plan.append(('kill-cgroup', f'{FC_TREE}/{instance}'))
        plan.append(('unmount-under', JAIL_BASE))
        for instance in state.get('instances', []):
            plan.append(('detach-loops-under', f'{WORK_BASE}/{instance}'))
    for item in kinds.get('account', []):
        plan.append(('remove-account', item['target']))
    if any(i['kind'] == 'node' for i in made):
        for path in ('/var/lib/kilnd-fctest', '/var/lib/kilnd-fctest2',
                     '/opt/kilnd', JAIL_BASE, WORK_BASE, '/var/lib/kilnd-b6-copies'):
            plan.append(('remove-tree', path))
        plan.append(('remove-cgroup-tree', FC_TREE))
    for item in reversed(kinds.get('mount', [])):
        plan.append(('unmount', item['target']))
    for item in reversed(kinds.get('loop', [])):
        plan.append(('detach-loop', item['target']))
    for item in reversed(kinds.get('dir', [])):
        plan.append(('remove-tree', item['target']))
    return plan


def check_final(final):
    """The node's own last word (final.json, written before it dropped the deployment):
    root's offline inventory over the stopped helper's ledger and the daemons' databases is
    explained, with no fault or fail-stop, and no claim is left unreleased."""
    if final is None:
        return [check('the node wrote its final inventory', False, 'no final.json')]
    inventory = final.get('offline_inventory') or {}
    return [
        check('the final offline inventory is clean', inventory.get('verdict') == 'explained'
              and not inventory.get('unexplained') and not inventory.get('faults')
              and not inventory.get('failstop'), json.dumps(inventory)[:400]),
        check('no claim is left unreleased', not final.get('unreleased_claims'),
              json.dumps(final.get('unreleased_claims'))[:400]),
        check('no allocation is left on the host',
              not [a for a in final.get('allocations', []) if a.get('present')],
              json.dumps([a for a in final.get('allocations', []) if a.get('present')])[:400]),
    ]


def inventory_problems(observed):
    """Everything of the node that is still there. `observed` comes from observe()."""
    problems = []
    problems += [f'path {p}' for p in observed['paths']]
    problems += [f'account {a}' for a in observed['accounts']]
    problems += [f'unit {u} {s}' for u, s in observed['units'].items()
                 if s not in ('inactive', 'unknown', '')]
    problems += [f'loop {n} -> {b}' for n, b in observed['loops']]
    problems += [f'mount {m}' for m in observed['mounts']]
    problems += [f'process {p}' for p in observed['processes']]
    problems += [f'socket {s}' for s in observed['sockets']]
    return problems


# ---------------------------------------------------------------------------------------
# Host helpers.
# ---------------------------------------------------------------------------------------

def now_ms():
    return int(time.time() * 1000)


def log(*args):
    print(time.strftime('%H:%M:%SZ', time.gmtime()), *args, flush=True)


def run(args, check_rc=True, timeout=120, **kwargs):
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, **kwargs)
    if check_rc and proc.returncode != 0:
        raise SystemExit(f'{" ".join(args)}: exit {proc.returncode}\n{proc.stdout}{proc.stderr}')
    return proc


def read(path, default=None):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return default


def read_int(path):
    text = read(path)
    if text is None:
        return None
    text = text.strip()
    if text == 'max':
        return 'max'
    try:
        return int(text)
    except ValueError:
        return None


def keyed(path):
    """A cgroup `key value` file as a dict."""
    out = {}
    for line in (read(path) or '').splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip('-').isdigit():
            out[parts[0]] = int(parts[1])
    return out


def write_json(path, value):
    partial = path + '.partial'
    with open(partial, 'w') as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    os.replace(partial, path)


def sync():
    os.sync()


def uptime_minutes():
    return float(read('/proc/uptime').split()[0]) / 60


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def account_exists(name):
    return subprocess.run(['id', name], capture_output=True).returncode == 0


def unit_state(unit):
    return subprocess.run(['systemctl', 'is-active', unit], capture_output=True,
                          text=True).stdout.strip()


def loops():
    found = []
    for name in sorted(os.listdir('/sys/block')):
        if name.startswith('loop'):
            backing = read(f'/sys/block/{name}/loop/backing_file')
            if backing is not None:
                found.append((name, backing.strip()))
    return found


def mountinfo():
    entries = []
    for line in (read('/proc/self/mountinfo') or '').splitlines():
        fields = line.split(' ')
        sep = fields.index('-')
        entries.append({'target': fields[4].replace('\\040', ' '),
                        'fstype': fields[sep + 1], 'source': fields[sep + 2]})
    return entries


def proc_status(pid):
    out = {}
    for line in (read(f'/proc/{pid}/status') or '').splitlines():
        key, _, value = line.partition(':')
        if key in ('VmRSS', 'VmHWM', 'Threads'):
            out[key] = int(value.split()[0]) * (1024 if key != 'Threads' else 1)
    return out


def fd_count(pid):
    try:
        return len(os.listdir(f'/proc/{pid}/fd'))
    except OSError:
        return None


def smaps_rollup(pid):
    out = {}
    for line in (read(f'/proc/{pid}/smaps_rollup') or '').splitlines():
        key, _, value = line.partition(':')
        if key in ('Rss', 'Pss', 'Pss_Anon', 'Pss_File', 'Anonymous'):
            out[key] = int(value.split()[0]) * 1024
    return out


def pid_alive(pid):
    stat = read(f'/proc/{pid}/stat')
    if not stat:
        return False
    return stat.rsplit(')', 1)[1].split()[0] != 'Z'


# ---------------------------------------------------------------------------------------
# The node: its description, its requests, its ledger and its daemons' databases.
# ---------------------------------------------------------------------------------------

class Node:
    def __init__(self):
        text = read(os.path.join(NODE_DIR, 'node.json'))
        if text is None:
            raise SystemExit('no node: run setup first')
        self.desc = json.loads(text)
        self.kilndctl_path = os.path.join(BIN, 'kilndctl')
        self.daemons = {d['name']: d for d in self.desc['daemons']}
        self.ceilings = dict(self.desc['policy']['ceilings'])
        self.shared = dict(self.desc['policy']['shared'])
        self._seq_lock = threading.Lock()

    def reload(self):
        self.desc = json.loads(read(os.path.join(NODE_DIR, 'node.json')))
        self.daemons = {d['name']: d for d in self.desc['daemons']}

    @property
    def helper_pid(self):
        return self.desc['helper']['pid']

    def request(self, verb, argument='', timeout=300):
        """One request to the node test; its reply."""
        with self._seq_lock:
            # Past every response and every request still waiting.
            existing = (os.listdir(os.path.join(NODE_DIR, 'responses'))
                        + os.listdir(os.path.join(NODE_DIR, 'requests')))
            seq = 1 + max([int(n[:6]) for n in existing if n[:6].isdigit()] or [0])
            name = f'{seq:06d}-{verb}'
            path = os.path.join(NODE_DIR, 'requests', name)
            with open(path + '.partial', 'w') as f:
                f.write(argument)
            os.replace(path + '.partial', path)
            response = os.path.join(NODE_DIR, 'responses', f'{seq:06d}.json')
            end = time.monotonic() + timeout
            while not os.path.exists(response):
                if time.monotonic() > end:
                    raise RuntimeError(f'the node did not answer {verb} in {timeout} s')
                if unit_state(NODE_UNIT) not in ('active', 'activating') and verb != 'stop':
                    raise RuntimeError(f'the node unit is {unit_state(NODE_UNIT)}')
                time.sleep(0.1)
            with open(response) as f:
                reply = json.load(f)
        self.reload()
        return reply

    def kilndctl(self, daemon, args, timeout, stdin=None):
        started = now_ms()
        t0 = time.monotonic()
        try:
            proc = subprocess.run([self.kilndctl_path, '--socket', self.daemons[daemon]['socket'],
                                   *args], input=stdin, capture_output=True, timeout=timeout)
            code, out, err = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as e:
            code, out, err = -1, e.stdout or b'', (e.stderr or b'') + b'\nclient timeout'
        return {'code': code, 'out': out.decode(errors='replace'),
                'err': err.decode(errors='replace'), 'start': started,
                'end': now_ms(), 'ms': round((time.monotonic() - t0) * 1000, 1)}

    def health(self, daemon):
        ran = self.kilndctl(daemon, ['health'], timeout=10)
        parsed = parse_health(ran['out'])
        parsed['ms'] = ran['ms']
        parsed['code'] = ran['code']
        return parsed

    def census(self):
        """The test helper's census of its workers (its control socket)."""
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect(self.desc['helper']['control'])
                data = b''
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            return json.loads(data)
        except (OSError, ValueError):
            return None


def query(path, sql, args=(), attempts=50):
    """A query-only read of a live SQLite database as root. A database whose WAL index is
    missing (its owner stopped cleanly) is read from a copy, so root never creates a file
    in another account's state."""
    if not os.path.exists(path + '-shm') or not os.path.exists(path + '-wal'):
        with tempfile.TemporaryDirectory(prefix='m32-db-') as tmp:
            copy = os.path.join(tmp, 'copy.db')
            shutil.copyfile(path, copy)
            for suffix in ('-wal',):
                if os.path.exists(path + suffix):
                    shutil.copyfile(path + suffix, copy + suffix)
            return _query(copy, sql, args, attempts)
    return _query(path, sql, args, attempts)


def _query(path, sql, args, attempts):
    last = None
    for _ in range(attempts):
        try:
            conn = sqlite3.connect(f'file:{path}?mode=rw', uri=True, timeout=1)
            try:
                conn.execute('PRAGMA query_only = ON')
                return conn.execute(sql, args).fetchall()
            finally:
                conn.close()
        except sqlite3.Error as e:
            last = e
            time.sleep(0.02)
    raise RuntimeError(f'{path}: {last}')


class Views:
    """Reads of the node ledger and the daemons' databases."""

    def __init__(self, node):
        self.node = node

    @property
    def ledger(self):
        return self.node.desc['helper']['ledger']

    def db(self, daemon):
        return os.path.join(self.node.daemons[daemon]['state_dir'], 'kilnd.db')

    def claims(self):
        rows = query(self.ledger, """
            SELECT instance_id, allocation_id, memory_bytes, disk_bytes, pids, host_cpu_millis,
                   virtual_cpu_slots, host_pids
            FROM capacity_claims WHERE released_generation IS NULL""")
        totals = {'slots': len(rows)}
        for i, name in enumerate(('memory_bytes', 'disk_bytes', 'pids', 'host_cpu_millis',
                                  'virtual_cpu_slots', 'host_pids')):
            totals[name] = sum(r[2 + i] for r in rows) + self.node.shared.get(name, 0)
        by_instance = {}
        for r in rows:
            by_instance.setdefault(r[0], set()).add(r[1])
        return totals, by_instance

    def ledger_facts(self):
        pointers = {r[0]: {'issue_next': r[1], 'watermark': r[2], 'retained_admitted': r[3]}
                    for r in query(self.ledger, 'SELECT instance_id, issue_next, watermark, '
                                                'retained_admitted FROM instance_tokens')}
        phases = dict(query(self.ledger, 'SELECT phase, COUNT(*) FROM allocations GROUP BY phase'))
        retired = query(self.ledger, 'SELECT COUNT(*) FROM retired_tokens')[0][0]
        faults = query(self.ledger, 'SELECT COUNT(*) FROM node_faults')[0][0]
        compactions = query(self.ledger, 'SELECT COUNT(*), COALESCE(SUM(tokens_deleted), 0) '
                                         'FROM compaction_log')[0]
        sizes = {}
        for suffix in ('', '-wal', '-shm'):
            try:
                sizes['node.db' + suffix] = os.stat(self.ledger + suffix).st_size
            except OSError:
                pass
        # Live pages, as L measures the ledger against its space (journal.rs ledger_bytes).
        pages = query(self.ledger, 'SELECT * FROM pragma_page_count(), pragma_freelist_count(), '
                                   'pragma_page_size()')[0]
        return {'pointers': pointers, 'phases': phases, 'retired_tokens': retired,
                'node_faults': faults, 'compaction_rows': compactions[0],
                'compacted_tokens': compactions[1], 'file_bytes': sizes,
                'live_bytes': (pages[0] - pages[1]) * pages[2]}

    def token_outcomes(self):
        """Per instance: unaccounted issued seqs (see unaccounted_tokens)."""
        out = {}
        for instance, issue_next, watermark in query(
                self.ledger, 'SELECT instance_id, issue_next, watermark FROM instance_tokens'):
            retired = [r[0] for r in query(self.ledger, 'SELECT issue_seq FROM retired_tokens '
                                                        'WHERE instance_id = ?', (instance,))]
            allocations = [seq_of(r[0]) for r in query(
                self.ledger, 'SELECT allocation_id FROM allocations WHERE instance_id = ?',
                (instance,))]
            missing = unaccounted_tokens((watermark, issue_next), retired, allocations)
            if missing:
                out[instance] = missing
        return out

    def charged(self):
        """Per instance, the allocations each daemon's database still charges."""
        out = {}
        for name, daemon in self.node.daemons.items():
            rows = query(self.db(name), "SELECT allocation_id FROM sandboxes WHERE "
                                        "accounting_kind = 'fenced' AND release_evidence_id "
                                        "IS NULL AND allocation_id IS NOT NULL")
            out[daemon['instance']] = {r[0] for r in rows}
        return out

    def charged_count(self):
        return sum(len(v) for v in self.charged().values())

    def rows_since(self, daemon, since_ms):
        return query(self.db(daemon), """
            SELECT id, state, allocation_id, release_evidence_id, failure_reason, created_at_ms
            FROM sandboxes WHERE created_at_ms >= ? ORDER BY created_at_ms""", (since_ms,))

    def retired_receipt(self, allocation):
        rows = query(self.ledger, 'SELECT receipt_id FROM retired_tokens WHERE allocation_id = ?',
                     (allocation,))
        return rows[0][0] if rows else None

    def phase(self, allocation):
        rows = query(self.ledger, 'SELECT phase FROM allocations WHERE allocation_id = ?',
                     (allocation,))
        return rows[0][0] if rows else None

    def allocation_count(self):
        return query(self.ledger, 'SELECT COUNT(*), COALESCE(MAX(created_generation), 0) '
                                  'FROM allocations')[0]

    def allocations_after(self, generation):
        return query(self.ledger, 'SELECT instance_id, allocation_id, phase FROM allocations '
                                  'WHERE created_generation > ?', (generation,))

    def db_bytes(self):
        out = {}
        for name in self.node.daemons:
            total = 0
            for suffix in ('', '-wal', '-shm'):
                try:
                    total += os.stat(self.db(name) + suffix).st_size
                except OSError:
                    pass
            out[name] = total
        return out

    def execution(self, daemon, sandbox):
        rows = query(self.db(daemon), """
            SELECT id, state, exit_code, length(stdout), stdout_bytes, stdout_truncated,
                   stdout_total_bytes_known, length(stderr), stderr_bytes, stderr_truncated,
                   failure_reason
            FROM executions WHERE sandbox_id = ? ORDER BY started_at_ms""", (sandbox,))
        keys = ('id', 'state', 'exit_code', 'stdout_kept', 'stdout_bytes', 'stdout_truncated',
                'stdout_total_known', 'stderr_kept', 'stderr_bytes', 'stderr_truncated',
                'failure_reason')
        return [dict(zip(keys, r)) for r in rows]


# ---------------------------------------------------------------------------------------
# Sampling.
# ---------------------------------------------------------------------------------------

def allocation_cgroups():
    """Every allocation parent under the node tree: kilnd-firecracker/<I>/fc-<H>."""
    out = []
    try:
        instances = os.listdir(FC_TREE)
    except OSError:
        return out
    for instance in instances:
        base = os.path.join(FC_TREE, instance)
        if not os.path.isdir(base):
            continue
        for host in os.listdir(base):
            if host.startswith('fc-') and os.path.isdir(os.path.join(base, host)):
                out.append((instance, host, os.path.join(base, host)))
    return out


def cgroup_sample(path):
    events = keyed(os.path.join(path, 'memory.events'))
    stat = keyed(os.path.join(path, 'memory.stat'))
    out = {
        'memory_current': read_int(os.path.join(path, 'memory.current')),
        'memory_peak': read_int(os.path.join(path, 'memory.peak')),
        'memory_max': read_int(os.path.join(path, 'memory.max')),
        'oom': events.get('oom'), 'oom_kill': events.get('oom_kill'), 'max': events.get('max'),
        'anon': stat.get('anon'), 'file': stat.get('file'), 'kernel': stat.get('kernel'),
        'pids_current': read_int(os.path.join(path, 'pids.current')),
        'pids_peak': read_int(os.path.join(path, 'pids.peak')),
        'pids_max': read_int(os.path.join(path, 'pids.max')),
    }
    out['nodes'] = {}
    for node in ('control', 'relay', 'vm', 'vm/vmm', 'vm/console'):
        out['nodes'][node] = read_int(os.path.join(path, node, 'memory.current'))
    return out


def vmm_sample(pid):
    smaps = read(f'/proc/{pid}/smaps') or ''
    rollup = smaps_rollup(pid)
    return {'pid': pid, 'rss': rollup.get('Rss'), 'pss': rollup.get('Pss'),
            'pss_anon': rollup.get('Pss_Anon'), 'guest_rss': guest_mapping_rss(smaps)}


def process_sample(pid):
    if not pid or not pid_alive(pid):
        return None
    status = proc_status(pid)
    return {'pid': pid, 'rss': status.get('VmRSS'), 'hwm': status.get('VmHWM'),
            'threads': status.get('Threads'), 'fds': fd_count(pid)}


def jail_tmpfs():
    out = []
    for m in mountinfo():
        if m['source'].startswith('kilnd-jail-') and m['fstype'] == 'tmpfs':
            try:
                st = os.statvfs(m['target'])
            except OSError:
                continue
            out.append({'target': m['target'],
                        'used': (st.f_blocks - st.f_bfree) * st.f_frsize,
                        'size': st.f_blocks * st.f_frsize,
                        'inodes_used': st.f_files - st.f_ffree, 'inodes': st.f_files})
    return out


def host_sample():
    mem = {}
    for line in (read('/proc/meminfo') or '').splitlines():
        key, _, value = line.partition(':')
        if key in ('MemTotal', 'MemAvailable', 'MemFree', 'Cached'):
            mem[key] = int(value.split()[0]) * 1024
    vmstat = {}
    for line in (read('/proc/vmstat') or '').splitlines():
        key, _, value = line.partition(' ')
        if key in ('oom_kill',):
            vmstat[key] = int(value)
    st = os.statvfs('/')
    return {'mem': mem, 'oom_kill': vmstat.get('oom_kill'),
            'load': (read('/proc/loadavg') or '').split()[:3],
            'root_free': st.f_bavail * st.f_frsize}


def sample(node, views, t0):
    out = {'t': round(time.monotonic() - t0, 1), 'unix_ms': now_ms()}
    by_instance = {}
    try:
        totals, by_instance = views.claims()
        out['claims'] = totals
        out['claims_by_instance'] = {k: len(v) for k, v in by_instance.items()}
        out['vector_violations'] = vector_violations(totals, node.ceilings)
        out['ledger'] = views.ledger_facts()
    except RuntimeError as e:
        out['ledger_error'] = str(e)
    out['health'] = {name: node.health(name) for name in node.daemons}
    census = node.census()
    workers = {}
    vmms = []
    if census:
        workers['ledger'] = process_sample(census.get('ledger'))
        workers['monitor'] = process_sample(census.get('monitor'))
        for key in ('prep', 'recovery'):
            for i, pid in enumerate(census.get(key) or []):
                workers[f'{key}{i}'] = process_sample(pid)
        for allocation, entry in (census.get('supervisors') or {}).items():
            workers[f'S:{allocation}'] = process_sample(entry.get('pid'))
            if entry.get('vm'):
                v = vmm_sample(entry['vm'])
                v['allocation'] = allocation
                vmms.append(v)
        out['census'] = {k: census.get(k) for k in ('latched', 'pending_fault', 'latch_kind',
                                                    'attached', 'removing', 'lost_answers')}
    workers['helper'] = process_sample(node.helper_pid)
    out['workers'] = workers
    out['vmms'] = vmms
    hosts = {}
    for instance, allocations in by_instance.items():
        for allocation in allocations:
            hosts[host_name(instance, allocation)] = allocation
    guests = {v['allocation']: v['guest_rss'] for v in vmms}
    out['allocations'] = {}
    for instance, host, path in allocation_cgroups():
        cg = cgroup_sample(path)
        cg['allocation'] = hosts.get(host)
        cg['overhead'] = session_overhead(cg['memory_current'], guests.get(cg['allocation']))
        out['allocations'][f'{instance}/{host}'] = cg
    out['units'] = {
        'node': read_int(f'{CGROUP_ROOT}/system.slice/{NODE_UNIT}/memory.current'),
        **{name: read_int(f"{CGROUP_ROOT}{d['cgroup']}/memory.current")
           for name, d in node.daemons.items()},
    }
    out['jails'] = jail_tmpfs()
    out['db_bytes'] = views.db_bytes()
    out['host'] = host_sample()
    return out


class Sampler(threading.Thread):
    """Every SAMPLE_SECONDS a full sample to samples.jsonl; every half second the ledger's
    claims alone, keeping the maximum and every violation of the node vector."""

    def __init__(self, scenario, node, views, fast=0.5):
        super().__init__(daemon=True)
        self.scenario, self.node, self.views, self.fast = scenario, node, views, fast
        self.stop_event = threading.Event()
        self.claims_max = 0
        self.violations = []
        self.samples = []
        self.t0 = time.monotonic()

    def run(self):
        next_full = 0.0
        while not self.stop_event.is_set():
            now = time.monotonic()
            try:
                totals, _ = self.views.claims()
                self.claims_max = max(self.claims_max, totals['slots'])
                for v in vector_violations(totals, self.node.ceilings):
                    self.violations.append(f'{now_ms()} {v}')
            except RuntimeError:
                pass
            if now >= next_full:
                next_full = now + SAMPLE_SECONDS
                try:
                    s = sample(self.node, self.views, self.t0)
                except Exception as e:  # a sample must never end a scenario
                    s = {'t': round(now - self.t0, 1), 'sample_error': repr(e)}
                self.samples.append(s)
                self.scenario.sample(s)
            self.stop_event.wait(self.fast)

    def finish(self):
        self.stop_event.set()
        self.join(timeout=30)


# ---------------------------------------------------------------------------------------
# Scenario bookkeeping.
# ---------------------------------------------------------------------------------------

class Scenario:
    def __init__(self, evidence, name, force=False):
        self.name = name
        self.dir = os.path.join(evidence, name)
        self.records = 0
        self.lock = threading.Lock()
        self.force = force
        self.started = None

    def begin(self, extra=None):
        state = scenario_state(self.dir)
        if state == 'complete' and not self.force:
            log(f'{self.name}: already complete in {self.dir} (use --force to run it again)')
            return False
        if state != 'absent':
            aside = partial_name(self.dir)
            os.rename(self.dir, aside)
            log(f'{self.name}: earlier results ({state}) moved to {aside}; running again')
        os.makedirs(self.dir)
        self.started = now_ms()
        self._records = open(os.path.join(self.dir, 'records.jsonl'), 'a')
        self._samples = open(os.path.join(self.dir, 'samples.jsonl'), 'a')
        write_json(os.path.join(self.dir, 'started.json'),
                   {'scenario': self.name, 'unix_ms': self.started,
                    'uptime_minutes': round(uptime_minutes(), 1), **(extra or {})})
        return True

    def record(self, value):
        with self.lock:
            self._records.write(json.dumps(value, sort_keys=True) + '\n')
            self._records.flush()
            self.records += 1

    def sample(self, value):
        with self.lock:
            self._samples.write(json.dumps(value, sort_keys=True) + '\n')
            self._samples.flush()

    def finish(self, checks, metrics, lines=()):
        self._records.close()
        self._samples.close()
        summary = [f'# {self.name}', *format_checks(checks), '', *lines]
        with open(os.path.join(self.dir, 'summary.txt'), 'w') as f:
            f.write('\n'.join(summary) + '\n')
        write_json(os.path.join(self.dir, 'metrics.json'), metrics)
        passed = all(c['pass'] for c in checks)
        write_json(os.path.join(self.dir, 'done.json'),
                   {'complete': True, 'records': self.records, 'passed': passed,
                    'checks': checks, 'finished_unix_ms': now_ms(),
                    'uptime_minutes': round(uptime_minutes(), 1)})
        sync()
        print('\n'.join(summary), flush=True)
        return passed


def preflight(args):
    if os.geteuid() != 0:
        raise SystemExit('run as root (sudo)')
    if not args.ignore_uptime and uptime_minutes() > MAX_UPTIME_MINUTES:
        raise SystemExit(f'VM uptime is {uptime_minutes():.0f} min: restart the kiln VM first '
                         '(or pass --ignore-uptime)')


def wait_quiet(node, views, seconds=180):
    """Until the ledger holds no claim and no daemon charges a row."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        totals, _ = views.claims()
        if totals['slots'] == 0 and views.charged_count() == 0:
            return True
        time.sleep(1)
    return False


# A failed Delete is retried every second for up to a minute after its first failure, as the
# daemon's own "retry through Delete" asks. A Delete still failing then is a leak.
DELETE_RETRY_SECONDS = 60
DELETE_RETRY_INTERVAL = 1.0


def delete_with_retry(node, daemon, sandbox, record=None, timeout=120,
                      retry_seconds=DELETE_RETRY_SECONDS, interval=DELETE_RETRY_INTERVAL,
                      clock=time.monotonic, sleep=time.sleep):
    """Deletes `sandbox`, retrying a failed attempt every `interval` seconds until one
    succeeds or `retry_seconds` have passed since the first failure. `record(n, ran)` is
    called for each failed attempt n. The outcome: ok, attempts, retried, leaked, start and
    end (Unix ms of the first attempt's start and the last one's end), release_ms (first
    start to the successful end), and the first and last errors."""
    attempts = []
    give_up = None
    while True:
        ran = node.kilndctl(daemon, ['rm', sandbox], timeout=timeout)
        attempts.append(ran)
        if ran['code'] == 0:
            break
        if record is not None:
            record(len(attempts), ran)
        if give_up is None:
            give_up = clock() + retry_seconds
        if clock() >= give_up:
            break
        sleep(interval)
    first, last = attempts[0], attempts[-1]
    ok = last['code'] == 0
    return {'ok': ok, 'code': last['code'], 'attempts': len(attempts),
            'retried': len(attempts) > 1, 'leaked': not ok,
            'start': first['start'], 'end': last['end'],
            # Wall time, retries and their waits included (a neighbour's deadline is on it).
            'ms': first['ms'] if len(attempts) == 1 else float(last['end'] - first['start']),
            'release_ms': last['end'] - first['start'] if ok else None,
            'first_err': first['err'].strip()[-300:] if first['code'] != 0 else '',
            'err': last['err'].strip()[-300:]}


def retry_entry(daemon, sandbox, removed):
    """What a retried or leaked Delete leaves in the tally."""
    return {'daemon': daemon, 'id': sandbox, 'attempts': removed['attempts'],
            'release_ms': removed['release_ms'], 'first_err': removed['first_err'],
            'err': removed['err'] if removed['leaked'] else ''}


def remove_all(node, ids, timeout=120, tally=None):
    """Deletes every listed (daemon, sandbox), each with delete_with_retry; the Deletes still
    failing after their retries. Retried Deletes go to `tally` when given."""
    failures = []
    for daemon, sandbox in ids:
        removed = delete_with_retry(node, daemon, sandbox, timeout=timeout)
        if tally is not None:
            tally.deleted(daemon, sandbox, removed)
        if removed['leaked']:
            failures.append({'daemon': daemon, 'id': sandbox, 'attempts': removed['attempts'],
                             'err': removed['err']})
    return failures


# ---------------------------------------------------------------------------------------
# Lanes: create, exec, delete, through kilndctl.
# ---------------------------------------------------------------------------------------

class Tally:
    def __init__(self):
        self.lock = threading.Lock()
        self.sessions = {}
        self.refusals = {}
        self.refusals_by_daemon = {}
        self.ready_ms = {}
        self.creates = []          # (start, end) of successful creates
        self.releases = []         # end of successful deletes
        self.op_failures = 0
        self.op_failure_samples = []
        self.capture_mismatches = 0
        self.leftover = []         # (daemon, id) still to delete
        self.delete_retried = []   # Deletes that failed at first (retry_entry)
        self.delete_leaks = []     # Deletes still failing after their retries

    def refused(self, daemon, kind):
        with self.lock:
            self.refusals[kind] = self.refusals.get(kind, 0) + 1
            per = self.refusals_by_daemon.setdefault(daemon, {})
            per[kind] = per.get(kind, 0) + 1

    def deleted(self, daemon, sandbox, removed):
        with self.lock:
            if removed['retried'] or removed['leaked']:
                self.delete_retried.append(retry_entry(daemon, sandbox, removed))
            if removed['leaked']:
                self.delete_leaks.append(retry_entry(daemon, sandbox, removed))


def lane(node, scenario, tally, daemon, lane_id, stop, command=None, pause=None):
    """Create, one Exec, Delete, until `stop`. A capacity or preparation refusal waits a
    quarter second (jittered) and tries again, as an honest client would."""
    rng = random.Random(f'{daemon}-{lane_id}')
    while not stop.is_set():
        if pause is not None and pause.is_set():
            time.sleep(0.2)
            continue
        created = node.kilndctl(daemon, ['create', '--net', 'none'], timeout=180)
        if created['code'] != 0:
            kind = classify_refusal(created['err'])
            tally.refused(daemon, kind)
            scenario.record({'op': 'create', 'daemon': daemon, 'lane': lane_id, 'ok': False,
                             'refusal': kind, 'start': created['start'], 'ms': created['ms'],
                             'err': created['err'].strip()[-300:]})
            time.sleep(0.25 + rng.random() * 0.25 if kind in EXPECTED_REFUSALS else 1.0)
            continue
        sandbox = created['out'].strip()
        with tally.lock:
            tally.ready_ms.setdefault(daemon, []).append(created['ms'])
            tally.creates.append((created['start'], created['end']))
            tally.leftover.append((daemon, sandbox))
        scenario.record({'op': 'create', 'daemon': daemon, 'lane': lane_id, 'ok': True,
                         'id': sandbox, 'start': created['start'], 'ms': created['ms']})
        token = f'{daemon}-{lane_id}-{sandbox}'
        argv = command(token) if command else ['echo', token]
        ran = node.kilndctl(daemon, ['exec', '--timeout', '60s', sandbox, '--', *argv],
                            timeout=90)
        expected = token + '\n'
        ok = ran['code'] == 0
        if ok and ran['out'] != expected and command is None:
            with tally.lock:
                tally.capture_mismatches += 1
        scenario.record({'op': 'exec', 'daemon': daemon, 'lane': lane_id, 'id': sandbox,
                         'ok': ok, 'code': ran['code'], 'ms': ran['ms'],
                         'match': ran['out'] == expected, 'err': ran['err'].strip()[-300:]})
        removed = delete_with_retry(
            node, daemon, sandbox,
            record=lambda n, r: scenario.record(
                {'op': 'rm-retry', 'daemon': daemon, 'lane': lane_id, 'id': sandbox,
                 'attempt': n, 'code': r['code'], 'start': r['start'], 'ms': r['ms'],
                 'err': r['err'].strip()[-300:]}))
        rm_ok = removed['ok']
        tally.deleted(daemon, sandbox, removed)
        with tally.lock:
            if rm_ok:
                tally.releases.append(removed['end'])
                tally.leftover.remove((daemon, sandbox))
                tally.sessions[daemon] = tally.sessions.get(daemon, 0) + 1
            for what, good, r in (('exec', ok, ran), ('rm', rm_ok, removed)):
                if not good:
                    tally.op_failures += 1
                    if len(tally.op_failure_samples) < 20:
                        tally.op_failure_samples.append(
                            {'op': what, 'daemon': daemon, 'id': sandbox, 'code': r['code'],
                             'err': r['err'].strip()[-300:]})
        scenario.record({'op': 'rm', 'daemon': daemon, 'lane': lane_id, 'id': sandbox,
                         'ok': rm_ok, 'ms': removed['ms'], 'end': removed['end'],
                         'attempts': removed['attempts'], 'release_ms': removed['release_ms'],
                         'err': removed['err']})


def churn(node, views, scenario, sampler, lanes_per_daemon, seconds, pause=None, extra=None):
    """Steady churn for `seconds`; its tally, after every session is deleted."""
    tally = Tally()
    stop = threading.Event()
    threads = []
    for daemon in node.daemons:
        for i in range(lanes_per_daemon):
            t = threading.Thread(target=lane, args=(node, scenario, tally, daemon, i, stop),
                                 kwargs={'pause': pause}, daemon=True)
            t.start()
            threads.append(t)
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if extra is not None:
            extra(end - time.monotonic())
        time.sleep(1)
    stop.set()
    for t in threads:
        t.join(timeout=400)
    failures = remove_all(node, list(tally.leftover), tally=tally)
    tally.op_failures += len(failures)
    tally.op_failure_samples += failures
    return tally


def churn_summary(node, views, sampler, tally, started_ms):
    quiet = wait_quiet(node, views)
    totals, _ = views.claims()
    facts = views.ledger_facts()
    samples = [s for s in sampler.samples if 'workers' in s]
    rss = [s['workers']['helper']['rss'] for s in samples
           if s['workers'].get('helper') and s['workers']['helper'].get('rss')]
    fds = [s['workers']['helper']['fds'] for s in samples
           if s['workers'].get('helper') and s['workers']['helper'].get('fds') is not None]
    q = max(1, len(rss) // 4)
    growth = (max(rss[-q:]) - sorted(rss[:q])[len(rss[:q]) // 2]) if len(rss) >= 4 else None
    first = next((s['ledger']['pointers'] for s in sampler.samples if 'ledger' in s), {})
    advanced = any(facts['pointers'].get(i, {}).get('watermark', 0) > p.get('watermark', 0)
                   for i, p in first.items())
    faults = sum(1 for s in samples if s.get('ledger', {}).get('node_faults')
                 or (s.get('census') or {}).get('latched'))
    degraded = {d: sum(1 for s in samples if s['health'].get(d, {}).get('status') != 'serving')
                for d in node.daemons}
    gaps = next_admit_gaps(tally.releases, tally.creates)
    db = [s['db_bytes'] for s in samples]
    sessions = sum(tally.sessions.values())
    return {
        'sessions': sessions,
        'sessions_by_daemon': {d: tally.sessions.get(d, 0) for d in node.daemons},
        'ready_ms': {d: stats(tally.ready_ms.get(d, [])) for d in node.daemons},
        'refusals': tally.refusals,
        'refusals_by_daemon': tally.refusals_by_daemon,
        'next_admit_start_ms': stats([g[0] for g in gaps]),
        'next_admit_ready_ms': stats([g[1] for g in gaps]),
        'op_failures': tally.op_failures,
        'op_failure_samples': tally.op_failure_samples,
        'delete_retries': len(tally.delete_retried),
        'delete_retry_release_ms': stats([d['release_ms'] for d in tally.delete_retried
                                          if d['release_ms'] is not None]),
        'delete_retry_samples': tally.delete_retried[:10],
        'delete_leaks': len(tally.delete_leaks),
        'delete_leak_samples': tally.delete_leaks[:10],
        'capture_mismatches': tally.capture_mismatches,
        'claims_max': sampler.claims_max,
        'vector_violations': sampler.violations,
        'quiet': quiet,
        'claims_after': totals['slots'],
        'charged_after': views.charged_count(),
        'unaccounted': views.token_outcomes(),
        'node_faults': faults,
        'samples_not_serving': degraded,
        'helper_rss': stats(rss),
        'helper_rss_growth': growth,
        'helper_fd_spread': (max(fds) - min(fds)) if fds else None,
        'watermark_advanced': advanced,
        'pointers_start': first,
        'pointers_end': facts['pointers'],
        'ledger_live_bytes': stats([s['ledger']['live_bytes'] for s in samples if 'ledger' in s]),
        'compaction_lag_tokens': {
            i: stats([s['ledger']['pointers'][i]['issue_next'] - s['ledger']['pointers'][i]['watermark']
                      for s in samples if i in s.get('ledger', {}).get('pointers', {})])
            for i in facts['pointers']},
        'compacted_tokens': facts['compacted_tokens'],
        'db_bytes_start': db[0] if db else None,
        'db_bytes_end': db[-1] if db else None,
        'db_bytes_per_session': {
            d: round((db[-1][d] - db[0][d]) / max(1, tally.sessions.get(d, 0)), 1)
            for d in node.daemons} if len(db) >= 2 else None,
        'overhead_idle': overhead_stats(samples),
        'jail_tmpfs_max_used': max([j['used'] for s in samples for j in s.get('jails', [])] or [0]),
        'jail_tmpfs_size': max([j['size'] for s in samples for j in s.get('jails', [])] or [0]),
    }


def overhead_stats(samples, allocations=None):
    values, peaks, vmm_rss, vmm_pss = [], [], [], []
    for s in samples:
        for cg in s.get('allocations', {}).values():
            if allocations is not None and cg.get('allocation') not in allocations:
                continue
            if cg.get('overhead') is not None:
                values.append(cg['overhead'])
            if isinstance(cg.get('memory_peak'), int):
                peaks.append(cg['memory_peak'])
        for v in s.get('vmms', []):
            if allocations is not None and v['allocation'] not in allocations:
                continue
            if v.get('rss'):
                vmm_rss.append(v['rss'])
            if v.get('pss'):
                vmm_pss.append(v['pss'])
    return {'overhead_bytes': stats(values), 'memory_peak_bytes': stats(peaks),
            'vmm_rss': stats(vmm_rss), 'vmm_pss': stats(vmm_pss),
            'assumed_overhead_bytes': ASSUMED_OVERHEAD,
            'reserved_session_bytes': GUEST_MEMORY + ASSUMED_OVERHEAD}


def timing_report(node, scenario, offset):
    """The helper's create-timing lines written since `offset`, split by daemon through
    each daemon's allocation IDs, and kilnd-helper's summary of each."""
    path = node.desc['helper']['log']
    try:
        with open(path, 'rb') as f:
            f.seek(offset)
            lines = [l.decode(errors='replace') for l in f if b'create timing v1' in l]
    except OSError:
        return {}
    views = Views(node)
    out = {}
    for name in node.daemons:
        allocations = {r[0] for r in query(views.db(name), 'SELECT allocation_id FROM sandboxes '
                                                           'WHERE allocation_id IS NOT NULL')}
        mine = [l for l in lines if any(a in l for a in allocations)]
        text = ''.join(mine)
        with open(os.path.join(scenario.dir, f'timings-{name}.log'), 'w') as f:
            f.write(text)
        report = subprocess.run([os.path.join(BIN, 'kilnd-helper'), 'create-timings', '--last',
                                 str(max(1, len(mine))), '--summary'], input=text,
                                capture_output=True, text=True)
        with open(os.path.join(scenario.dir, f'timings-{name}-summary.txt'), 'w') as f:
            f.write(report.stdout + report.stderr)
        ready = re.search(r'^\s*(\d+)\s+-\s+([\d.]+)\s+([\d.]+)\s+([\d.]+).*READY \(offset\)',
                          report.stdout, re.M)
        out[name] = {'lines': len(mine), 'ready_offset_ms': None if not ready else {
            'n': int(ready.group(1)), 'p50': float(ready.group(2)),
            'p95': float(ready.group(3)), 'max': float(ready.group(4))}}
    return out


def log_offset(node):
    try:
        return os.stat(node.desc['helper']['log']).st_size
    except OSError:
        return 0


# ---------------------------------------------------------------------------------------
# Scenarios.
# ---------------------------------------------------------------------------------------

def run_s1(args, node, views):
    """Steady churn: three create/exec/delete lanes per daemon for N minutes, twice as many
    lanes as slots. Halfway, the RTC-18 batch probe times compaction batches beside it."""
    scenario = Scenario(args.evidence, args.label or 's1', args.force)
    if not scenario.begin({'minutes': args.minutes, 'lanes_per_daemon': args.lanes}):
        return True
    if not wait_quiet(node, views, 60):
        raise SystemExit('the node is not quiet: claims or charged rows remain')
    offset = log_offset(node)
    sampler = Sampler(scenario, node, views)
    sampler.start()
    probe = {'done': False}

    def extra(left):
        if not probe['done'] and left <= args.minutes * 30:
            probe['done'] = True
            probe['result'] = batch_probe(scenario)

    tally = churn(node, views, scenario, sampler, args.lanes, args.minutes * 60, extra=extra)
    summary = churn_summary(node, views, sampler, tally, scenario.started)
    sampler.finish()
    summary['timings'] = timing_report(node, scenario, offset)
    summary['compaction_batch_probe'] = probe.get('result')
    checks = check_churn(summary, node.ceilings, args.minutes)
    if probe.get('result'):
        r = probe['result']
        checks.append(check('a compaction batch stays under RTC-18\'s 100 ms beside the churn',
                            r.get('passed') is True, json.dumps(r)))
    return scenario.finish(checks, summary, churn_lines(summary))


def churn_lines(summary):
    lines = [f"sessions {summary['sessions']} {json.dumps(summary['sessions_by_daemon'])}"]
    for d, s in summary['ready_ms'].items():
        lines.append(f"READY (client) {d}: p50 {s['p50']} p95 {s['p95']} max {s['max']} ms (n {s['n']})")
    for d, t in (summary.get('timings') or {}).items():
        lines.append(f"READY (helper offset) {d}: {json.dumps(t.get('ready_offset_ms'))}")
    lines.append(f"refusals {json.dumps(summary['refusals_by_daemon'])}")
    lines.append(f"next admitted Create after a release: start {json.dumps(summary['next_admit_start_ms'])}"
                 f" ready {json.dumps(summary['next_admit_ready_ms'])}")
    lines.append(f"Deletes retried {summary['delete_retries']}, released after"
                 f" {json.dumps(summary['delete_retry_release_ms'])} ms; leaked {summary['delete_leaks']}")
    o = summary['overhead_idle']
    lines.append(f"session overhead (allocation memory.current - guest RSS): {json.dumps(o['overhead_bytes'])}"
                 f"; memory.peak {json.dumps(o['memory_peak_bytes'])}; VMM PSS {json.dumps(o['vmm_pss'])}")
    lines.append(f"helper RSS {json.dumps(summary['helper_rss'])}, growth {summary['helper_rss_growth']},"
                 f" fd spread {summary['helper_fd_spread']}")
    lines.append(f"ledger live bytes {json.dumps(summary['ledger_live_bytes'])};"
                 f" compaction lag (tokens) {json.dumps(summary['compaction_lag_tokens'])};"
                 f" compacted {summary['compacted_tokens']}")
    lines.append(f"daemon DB bytes per session {json.dumps(summary['db_bytes_per_session'])}")
    lines.append(f"jail tmpfs max used {summary['jail_tmpfs_max_used']} of {summary['jail_tmpfs_size']}")
    if summary.get('compaction_batch_probe'):
        lines.append(f"compaction batch probe {json.dumps(summary['compaction_batch_probe'])}")
    return lines


def batch_probe(scenario):
    """RTC-18's compaction-batch measurement (a full batch, COMPACTION_BATCH tokens, FULL
    sync on this VM's disk), run beside the churn as the invoking user."""
    uid, gid = int(os.environ.get('SUDO_UID', '0')), int(os.environ.get('SUDO_GID', '0'))
    if uid == 0:
        return {'skipped': 'no SUDO_UID: the probe runs unprivileged'}
    test = ('helper::firecracker::tests::compaction::'
            'b7_rtc18_compaction_has_its_own_lane_and_a_full_batch_stays_under_100_ms')
    started = time.monotonic()
    proc = subprocess.run(['setpriv', f'--reuid={uid}', f'--regid={gid}', '--init-groups',
                           'env', 'HOME=/tmp', os.path.join(BIN, 'kilnd-lib-tests'), '--exact',
                           test, '--nocapture', '--test-threads=1'],
                          capture_output=True, text=True, timeout=600, cwd='/tmp')
    text = proc.stdout + proc.stderr
    with open(os.path.join(scenario.dir, 'compaction-batch-probe.log'), 'w') as f:
        f.write(text)
    m = re.search(r'B7 matrix: (\{.*\})', text)
    outcome = json.loads(m.group(1)).get('outcome') if m else None
    return {'passed': proc.returncode == 0, 'exit': proc.returncode, 'outcome': outcome,
            'seconds': round(time.monotonic() - started, 1),
            'line': next((l for l in text.splitlines() if 'compact_batch p50' in l), None)}


def run_s2(args, node, views):
    """Saturation race: eight simultaneous Creates, five on one daemon and three on the
    other. Each racer retries a full preparation slot (P has two, design 6.4) for up to a
    minute, so all eight contend for the node's three slots."""
    scenario = Scenario(args.evidence, 's2', args.force)
    if not scenario.begin():
        return True
    if not wait_quiet(node, views, 60):
        raise SystemExit('the node is not quiet')
    names = list(node.daemons)
    plan = [names[0]] * 5 + [names[1]] * 3
    _, base_generation = views.allocation_count()
    pointers_before = views.ledger_facts()['pointers']
    since = now_ms() - 1000
    offset = log_offset(node)
    sampler = Sampler(scenario, node, views, fast=0.05)
    sampler.start()
    barrier = threading.Barrier(len(plan))
    results = [None] * len(plan)

    def racer(i, daemon):
        attempts = []
        barrier.wait()
        end = time.monotonic() + 60
        while True:
            ran = node.kilndctl(daemon, ['create', '--net', 'none'], timeout=180)
            kind = None if ran['code'] == 0 else classify_refusal(ran['err'])
            attempts.append({'start': ran['start'], 'ms': ran['ms'], 'code': ran['code'],
                             'refusal': kind, 'err': ran['err'].strip()[-300:],
                             'id': ran['out'].strip() if ran['code'] == 0 else None})
            if kind == 'prep_slot' and time.monotonic() < end:
                time.sleep(random.uniform(0.02, 0.2))
                continue
            break
        results[i] = {'racer': i, 'daemon': daemon, 'attempts': attempts}
        scenario.record(results[i])

    threads = [threading.Thread(target=racer, args=(i, d)) for i, d in enumerate(plan)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=400)
    time.sleep(3)
    created = views.allocations_after(base_generation)
    ready = [(r['daemon'], r['attempts'][-1]['id']) for r in results
             if r and r['attempts'][-1]['code'] == 0]
    final_refusals = [r['attempts'][-1]['refusal'] for r in results
                      if r and r['attempts'][-1]['code'] != 0]
    first_attempts = {}
    for r in results:
        if r:
            k = r['attempts'][0]['refusal'] or 'ready'
            first_attempts[k] = first_attempts.get(k, 0) + 1
    # Refused rows (post-C1 refusals) settle released by exactly their ledger receipt.
    bad = []
    settle_end = time.monotonic() + 30
    while True:
        bad = []
        for d in names:
            for sid, state, allocation, evidence, reason, _ in views.rows_since(d, since):
                if any(sid == x[1] for x in ready):
                    continue
                if allocation is None:
                    continue
                receipt = views.retired_receipt(allocation)
                if state != 'failed' or evidence is None or evidence != receipt:
                    bad.append({'daemon': d, 'id': sid, 'state': state, 'evidence': evidence,
                                'receipt': receipt, 'phase': views.phase(allocation)})
        if not bad or time.monotonic() > settle_end:
            break
        time.sleep(1)
    unaccounted = views.token_outcomes()
    s2_tally = Tally()
    failures = remove_all(node, ready, tally=s2_tally)
    quiet = wait_quiet(node, views, 120)
    totals, _ = views.claims()
    sampler.finish()
    outcome = {
        'plan': plan, 'intent': len(created), 'created': created, 'ready': len(ready),
        'ready_ids': ready, 'first_attempts': first_attempts, 'final_refusals': final_refusals,
        'claims_max': sampler.claims_max, 'vector_violations': sampler.violations,
        'unaccounted': sorted(s for v in unaccounted.values() for s in v),
        'bad_releases': bad, 'delete_failures': failures, 'quiet': quiet,
        'delete_retried': s2_tally.delete_retried,
        'claims_after': totals['slots'], 'charged_after': views.charged_count(),
        'pointers_before': pointers_before, 'pointers_after': views.ledger_facts()['pointers'],
        'attempts_total': sum(len(r['attempts']) for r in results if r),
        'ready_ms': {d: stats([r['attempts'][-1]['ms'] for r in results
                               if r and r['daemon'] == d and r['attempts'][-1]['code'] == 0])
                     for d in names},
    }
    outcome['timings'] = timing_report(node, scenario, offset)
    checks = check_s2(outcome, node.ceilings)
    lines = [f"first attempts {json.dumps(first_attempts)}",
             f"final refusals {json.dumps(final_refusals)}",
             f"attempts {outcome['attempts_total']}; READY {json.dumps(outcome['ready_ms'])}"]
    return scenario.finish(checks, outcome, lines)


# Each hostile payload, its arguments and its exec timeout. The exec timeout retires the VM
# if it fires (design: an interrupted execution retires the session); every payload bounds
# itself well inside it.
HOSTILE = [
    ('pid-limit-test.sh', ['20'], '90s'),
    ('memory-limit-test.sh', ['60'], '120s'),
    ('disk-fill-test.sh', ['90'], '150s'),
    ('inode-fill-test.sh', ['60'], '120s'),
    ('output-flood-test.sh', ['20'], '90s'),
]
NEIGHBOUR_DEADLINES = {'create': 120, 'health': 5, 'get': 5, 'exec': 60, 'rm': 60}


def hostile_lane(node, views, scenario, daemon, payloads, out, stop):
    """One fresh session per payload: create, run it, read its execution, delete."""
    for name, argv, timeout in payloads:
        if stop.is_set():
            break
        while not stop.is_set():
            created = node.kilndctl(daemon, ['create', '--net', 'none'], timeout=180)
            if created['code'] == 0:
                break
            scenario.record({'op': 'hostile-create', 'daemon': daemon, 'payload': name,
                             'refusal': classify_refusal(created['err']),
                             'err': created['err'].strip()[-300:]})
            time.sleep(0.5)
        else:
            break
        sandbox = created['out'].strip()
        with open(os.path.join(PAYLOADS, name), 'rb') as f:
            script = f.read()
        t0 = now_ms()
        ran = node.kilndctl(daemon, ['exec', '--timeout', timeout, '--stdin', sandbox, '--',
                                     'sh', '-s', '--', *argv], timeout=300, stdin=script)
        after = node.kilndctl(daemon, ['exec', '--timeout', '30s', sandbox, '--', 'echo',
                                       'after'], timeout=60)
        execution = views.execution(daemon, sandbox)
        got = node.kilndctl(daemon, ['get', sandbox], timeout=10)
        removed = delete_with_retry(node, daemon, sandbox)
        result = {'op': 'hostile', 'daemon': daemon, 'payload': name, 'id': sandbox,
                  'start': t0, 'ms': ran['ms'], 'code': ran['code'],
                  'out_tail': ran['out'][-600:], 'err_tail': ran['err'][-600:],
                  'session_after': {'code': after['code'], 'out': after['out'][-100:],
                                    'err': after['err'].strip()[-200:]},
                  'executions': execution, 'get': got['out'][-600:],
                  'rm': {'code': removed['code'], 'err': removed['err'][-200:],
                         'attempts': removed['attempts'], 'release_ms': removed['release_ms'],
                         'first_err': removed['first_err'][-200:]}}
        out.append(result)
        scenario.record(result)


def neighbour_lane(node, scenario, daemon, out, stop):
    """Create, Health, Get, Exec and Delete beside the hostile sessions, each against its
    deadline (B6's hostile-I/O limits). A capacity refusal answers in time too."""
    while not stop.is_set():
        created = node.kilndctl(daemon, ['create', '--net', 'none'], timeout=NEIGHBOUR_DEADLINES['create'] + 30)
        entry = {'op': 'create', 'daemon': daemon, 'ms': created['ms'], 'code': created['code'],
                 'refusal': None if created['code'] == 0 else classify_refusal(created['err']),
                 'start': created['start']}
        out.append(entry)
        scenario.record(entry)
        if created['code'] != 0:
            time.sleep(0.5)
            continue
        sandbox = created['out'].strip()
        for op, argv in (('health', ['health']), ('get', ['get', sandbox]),
                         ('exec', ['exec', '--timeout', '60s', sandbox, '--', 'echo', 'healthy']),
                         ('health', ['health']), ('rm', ['rm', sandbox])):
            if op == 'rm':
                removed = delete_with_retry(node, daemon, sandbox,
                                            timeout=NEIGHBOUR_DEADLINES[op] + 30)
                ran = {'code': removed['code'], 'ms': removed['ms'], 'start': removed['start'],
                       'out': '', 'err': removed['first_err'] or removed['err'],
                       'attempts': removed['attempts']}
            else:
                ran = node.kilndctl(daemon, argv, timeout=NEIGHBOUR_DEADLINES[op] + 30)
            entry = {'op': op, 'daemon': daemon, 'ms': ran['ms'], 'code': ran['code'],
                     'start': ran['start'], 'id': sandbox,
                     'ok': ran['code'] == 0 or op == 'health',
                     'match': ran['out'] == 'healthy\n' if op == 'exec' else None,
                     'err': ran['err'].strip()[-200:]}
            if 'attempts' in ran:
                entry['attempts'] = ran['attempts']
            out.append(entry)
            scenario.record(entry)


def run_s3(args, node, views):
    """Hostile tenants: one hostile lane per daemon runs each payload in a fresh session
    (both daemons busy), while one neighbour lane per daemon contends for the third slot."""
    scenario = Scenario(args.evidence, 's3', args.force)
    if not scenario.begin():
        return True
    if not wait_quiet(node, views, 60):
        raise SystemExit('the node is not quiet')
    offset = log_offset(node)
    sampler = Sampler(scenario, node, views)
    sampler.start()
    host_before = host_sample()
    names = list(node.daemons)
    stop = threading.Event()
    hostile_results, neighbour_results = [], []
    hostile_threads = [
        threading.Thread(target=hostile_lane, args=(node, views, scenario, names[0], HOSTILE,
                                                    hostile_results, stop)),
        threading.Thread(target=hostile_lane, args=(node, views, scenario, names[1],
                                                    list(reversed(HOSTILE)), hostile_results, stop)),
    ]
    neighbours = [threading.Thread(target=neighbour_lane, args=(node, scenario, d,
                                                                neighbour_results, stop))
                  for d in names]
    for t in hostile_threads + neighbours:
        t.start()
    end = time.monotonic() + args.max_minutes * 60
    for t in hostile_threads:
        t.join(timeout=max(1, end - time.monotonic()))
    stop.set()
    for t in hostile_threads + neighbours:
        t.join(timeout=400)
    quiet = wait_quiet(node, views)
    totals, _ = views.claims()
    host_after = host_sample()
    sampler.finish()
    samples = [s for s in sampler.samples if 'allocations' in s]
    late = [n for n in neighbour_results
            if n['ms'] > NEIGHBOUR_DEADLINES[n['op']] * 1000 or n['code'] == -1]
    failed = [n for n in neighbour_results if n.get('ok') is False]
    unexplained = [n for n in neighbour_results if n['op'] == 'create' and n['refusal']
                   and n['refusal'] not in EXPECTED_REFUSALS]
    mismatched = [n for n in neighbour_results if n['op'] == 'exec' and n['ok'] and not n['match']]
    host_ooms = (host_after['oom_kill'] or 0) - (host_before['oom_kill'] or 0)
    session_ooms = {k: v['oom_kill'] for s in samples for k, v in s['allocations'].items()
                    if v.get('oom_kill')}
    pid_over = [k for s in samples for k, v in s['allocations'].items()
                if isinstance(v.get('pids_max'), int) and isinstance(v.get('pids_peak'), int)
                and v['pids_peak'] > v['pids_max']]
    flood = [r for r in hostile_results if r['payload'] == 'output-flood-test.sh']
    silent_loss = []
    for r in flood:
        for e in r['executions'][:1]:
            if (e['stdout_kept'] or 0) > MIB or (
                    (e['stdout_bytes'] or 0) > (e['stdout_kept'] or 0) and not e['stdout_truncated']):
                silent_loss.append(e)
    root_shrink = host_before['root_free'] - host_after['root_free']
    hostile_allocations = set()
    for r in hostile_results:
        rows = query(views.db(r['daemon']), 'SELECT allocation_id FROM sandboxes WHERE id = ?',
                     (r['id'],))
        if rows and rows[0][0]:
            hostile_allocations.add(rows[0][0])
    neighbour_ready = [n['ms'] for n in neighbour_results if n['op'] == 'create' and n['code'] == 0]
    outcome = {
        'hostile': [{k: r[k] for k in ('daemon', 'payload', 'code', 'ms', 'session_after', 'rm')}
                    for r in hostile_results],
        'payloads_run': len(hostile_results),
        'neighbour_ops': len(neighbour_results),
        'neighbour_by_op': {op: stats([n['ms'] for n in neighbour_results if n['op'] == op])
                            for op in NEIGHBOUR_DEADLINES},
        'neighbour_ready_ms': stats(neighbour_ready),
        'late': late[:20], 'failed': failed[:20], 'unexplained': unexplained[:20],
        'mismatched': len(mismatched),
        'host_oom_kills': host_ooms, 'session_oom_kills': session_ooms,
        'pid_over': pid_over[:5], 'silent_capture_loss': silent_loss,
        'root_free_shrink_bytes': root_shrink,
        'claims_max': sampler.claims_max, 'vector_violations': sampler.violations,
        'quiet': quiet, 'claims_after': totals['slots'], 'charged_after': views.charged_count(),
        'unaccounted': views.token_outcomes(),
        'overhead_under_load': overhead_stats(samples, hostile_allocations or None),
        'jail_tmpfs_max_used': max([j['used'] for s in samples for j in s.get('jails', [])] or [0]),
        'jail_tmpfs_size': max([j['size'] for s in samples for j in s.get('jails', [])] or [0]),
        'helper_rss': stats([s['workers']['helper']['rss'] for s in samples
                             if s.get('workers', {}).get('helper')]),
    }
    outcome['timings'] = timing_report(node, scenario, offset)
    peak = outcome['overhead_under_load']['memory_peak_bytes']['max']
    checks = [
        check('every payload ran to an outcome', len(hostile_results) == 2 * len(HOSTILE),
              f"{len(hostile_results)} of {2 * len(HOSTILE)}"),
        check('neighbours meet their deadlines', not late, json.dumps(late[:3])),
        check('neighbours\' Exec and Delete succeed', not failed, json.dumps(failed[:3])),
        check('neighbours meet only capacity refusals', not unexplained, json.dumps(unexplained[:3])),
        check('neighbours\' output is exact', not mismatched, f'{len(mismatched)} differ'),
        check('no host OOM kill', host_ooms == 0, f'{host_ooms} kills'),
        check('no session hit its host memory limit', not session_ooms, json.dumps(session_ooms)),
        check('PIDs stay within each session\'s limit', not pid_over, json.dumps(pid_over[:3])),
        check('the output flood is kept bounded and reported, not lost silently',
              bool(flood) and not silent_loss, json.dumps(silent_loss[:2])),
        check('disk fill stays inside the preallocated work disk', root_shrink < 64 * MIB,
              f'root free space shrank {root_shrink} bytes'),
        check('a hostile session never exceeds its reservation',
              peak is None or peak <= GUEST_MEMORY + ASSUMED_OVERHEAD,
              f'memory.peak max {peak}'),
        check('the node vector is never exceeded', not sampler.violations,
              '; '.join(sampler.violations[:3])),
        check('no capacity leak', totals['slots'] == 0 and outcome['charged_after'] == 0,
              f"claims {totals['slots']}, charged {outcome['charged_after']}"),
        check('every issued token has a durable outcome', not outcome['unaccounted'],
              json.dumps(outcome['unaccounted'])[:300]),
    ]
    lines = [f"{r['daemon']} {r['payload']}: exit {r['code']} in {r['ms']} ms; after "
             f"{r['session_after']['code']}" for r in hostile_results]
    lines.append(f"neighbours {json.dumps(outcome['neighbour_by_op'])}")
    o = outcome['overhead_under_load']
    lines.append(f"session overhead under load: {json.dumps(o['overhead_bytes'])};"
                 f" memory.peak {json.dumps(o['memory_peak_bytes'])}")
    return scenario.finish(checks, outcome, lines)


def read_records(scenario):
    """The scenario's records so far (its writer flushes each line)."""
    with open(os.path.join(scenario.dir, 'records.jsonl')) as f:
        return [json.loads(line) for line in f if line.strip()]


def quiesce_check(node, views, label):
    """Claims against charged rows, per instance, with the lanes paused."""
    time.sleep(2)
    _, claims = views.claims()
    charged = views.charged()
    return {'label': label, 'unix_ms': now_ms(),
            'claims': {k: sorted(v) for k, v in claims.items()},
            'charged': {k: sorted(v) for k, v in charged.items()},
            'mismatch': quiescent_mismatch(claims, charged),
            'unaccounted': views.token_outcomes()}


def wait_pause_settled(node, views, seconds=240):
    """With the lanes paused, until no Create, Exec or Delete is in flight: the claim and
    charged sets agree twice in a row a second apart."""
    end = time.monotonic() + seconds
    last = None
    while time.monotonic() < end:
        _, claims = views.claims()
        charged = views.charged()
        now = (json.dumps({k: sorted(v) for k, v in claims.items()}, sort_keys=True),
               json.dumps({k: sorted(v) for k, v in charged.items()}, sort_keys=True))
        if now == last and not quiescent_mismatch(claims, charged):
            return True
        last = now
        time.sleep(1)
    return False


def run_s4(args, node, views):
    """Loss mid-run: with both daemons churning, SIGKILL one daemon, the helper or L. The
    survivor keeps working; claims stay exact; nothing is discounted for the dead daemon."""
    name = f's4-{args.kill}'
    scenario = Scenario(args.evidence, name, args.force)
    if not scenario.begin({'kill': args.kill}):
        return True
    if not wait_quiet(node, views, 60):
        raise SystemExit('the node is not quiet')
    offset = log_offset(node)
    sampler = Sampler(scenario, node, views)
    sampler.start()
    names = list(node.daemons)
    victim, survivor = names[0], names[1]
    victim_instance = node.daemons[victim]['instance']
    tally = Tally()
    stop, pause = threading.Event(), threading.Event()
    lanes = []
    for d in names:
        for i in range(2):
            t = threading.Thread(target=lane, args=(node, scenario, tally, d, i, stop),
                                 kwargs={'pause': pause}, daemon=True)
            t.start()
            lanes.append((d, t))
    time.sleep(args.warmup)
    pause.set()
    settled_before = wait_pause_settled(node, views)
    before = quiesce_check(node, views, 'before the kill')
    scenario.record({'op': 'quiesce', **before, 'settled': settled_before})
    pause.clear()
    time.sleep(5)
    events = []
    killed_at = now_ms()
    if args.kill == 'daemon':
        reply = node.request('kill-daemon', victim)
        # What the dead daemon's database charges at its death: READY rows hold their claim
        # until the daemon comes back and settles them; nothing may discount them before.
        charged_at_kill = sorted(views.charged().get(victim_instance, set()))
        events.append({'kill': victim, 'reply': reply, 'charged_at_kill': charged_at_kill})
        # The survivor keeps working; the dead daemon's claims stay exactly as they were.
        time.sleep(args.outage)
        pause.set()
        wait_pause_settled_survivor(node, views, survivor)
        during = quiesce_check(node, views, 'victim dead')
        _, claims = views.claims()
        held = sorted(claims.get(victim_instance, set()))
        events.append({'victim_claims_during_outage': held})
        scenario.record({'op': 'quiesce', **during})
        reply = node.request('start-daemon', victim)
        events.append({'restart': victim, 'reply': reply})
        pause.clear()
    elif args.kill == 'helper':
        reply = node.request('kill-helper')
        events.append({'kill': 'helper', 'reply': reply})
        time.sleep(args.outage)
    else:
        census = node.census() or {}
        pid = census.get('ledger')
        if not pid:
            raise SystemExit('no L in the census')
        os.kill(pid, 9)
        events.append({'kill': 'L', 'pid': pid, 'unix_ms': now_ms()})
        end = time.monotonic() + 60
        replaced = None
        while time.monotonic() < end:
            c = node.census() or {}
            if c.get('ledger') and c['ledger'] != pid:
                replaced = c['ledger']
                break
            time.sleep(0.2)
        events.append({'replaced_by': replaced, 'unix_ms': now_ms()})
        time.sleep(args.outage)
    scenario.record({'op': 'events', 'events': events})
    time.sleep(args.warmup)
    pause.set()
    settled_after = wait_pause_settled(node, views)
    after = quiesce_check(node, views, 'after recovery')
    scenario.record({'op': 'quiesce', **after, 'settled': settled_after})
    stop.set()
    pause.clear()
    for _, t in lanes:
        t.join(timeout=400)
    failures = remove_all(node, list(tally.leftover), tally=tally)
    quiet = wait_quiet(node, views)
    totals, _ = views.claims()
    sampler.finish()
    health = {d: node.health(d) for d in names}
    victim_held = next((e['victim_claims_during_outage'] for e in events
                        if 'victim_claims_during_outage' in e), None)
    at_kill = next((e['charged_at_kill'] for e in events if 'charged_at_kill' in e), None)
    outcome = {
        'kill': args.kill, 'killed_unix_ms': killed_at, 'events': events,
        'before': before, 'after': after, 'settled': [settled_before, settled_after],
        'sessions_by_daemon': tally.sessions, 'refusals_by_daemon': tally.refusals_by_daemon,
        'op_failures': tally.op_failures, 'op_failure_samples': tally.op_failure_samples,
        'delete_failures': failures, 'quiet': quiet, 'claims_after': totals['slots'],
        'charged_after': views.charged_count(), 'claims_max': sampler.claims_max,
        'vector_violations': sampler.violations, 'health_after': health,
        'unaccounted': views.token_outcomes(),
        'faults': views.ledger_facts()['node_faults'],
        'latched': (node.census() or {}).get('latched'),
    }
    outcome['timings'] = timing_report(node, scenario, offset)
    survivor_sessions_after_kill = sum(
        1 for r in read_records(scenario)
        if r.get('op') == 'rm' and r.get('daemon') == survivor and r.get('ok')
        and r.get('end', 0) > killed_at)
    outcome['survivor_sessions_after_kill'] = survivor_sessions_after_kill
    checks = [
        check('claims match charged rows before the kill', not before['mismatch'],
              json.dumps(before['mismatch'])),
        check('claims match charged rows after recovery', not after['mismatch'],
              json.dumps(after['mismatch'])),
        check('the survivor keeps completing sessions', survivor_sessions_after_kill > 0,
              f'{survivor_sessions_after_kill} after the kill'),
        check('the node vector is never exceeded', not sampler.violations,
              '; '.join(sampler.violations[:3])),
        check('no node fault latched', outcome['faults'] == 0 and not outcome['latched'],
              f"faults {outcome['faults']}, latched {outcome['latched']}"),
        check('both daemons serve again', all(h.get('status') == 'serving' for h in health.values()),
              json.dumps({d: (h.get('status'), h.get('detail')) for d, h in health.items()})),
        check('every issued token has a durable outcome', not outcome['unaccounted'],
              json.dumps(outcome['unaccounted'])[:300]),
        check('no capacity leak', totals['slots'] == 0 and outcome['charged_after'] == 0,
              f"claims {totals['slots']}, charged {outcome['charged_after']}"),
    ]
    if args.kill == 'daemon':
        checks.append(check('nothing is discounted for the dead daemon',
                            victim_held is not None and at_kill is not None
                            and set(at_kill) <= set(victim_held),
                            f'charged at the kill {at_kill}, claimed during the outage '
                            f'{victim_held}'))
    if args.kill == 'L':
        replaced = next((e.get('replaced_by') for e in events if 'replaced_by' in e), None)
        checks.append(check('H replaces L', bool(replaced), f'new L {replaced}'))
    lines = [json.dumps(e) for e in events]
    lines.append(f"sessions {json.dumps(tally.sessions)}; refusals {json.dumps(tally.refusals_by_daemon)}")
    return scenario.finish(checks, outcome, lines)


def wait_pause_settled_survivor(node, views, survivor, seconds=240):
    """While a daemon is dead only the survivor's claims and rows can settle."""
    instance = node.daemons[survivor]['instance']
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        _, claims = views.claims()
        charged = views.charged()
        if not quiescent_mismatch({instance: claims.get(instance, set())},
                                  {instance: charged.get(instance, set())}):
            return True
        time.sleep(1)
    return False


def ledger_device():
    state = load_state()
    for item in state.get('made', []):
        if item['kind'] == 'loop':
            name = os.path.basename(item['target'])
            dev = read(f'/sys/block/{name}/dev')
            if dev:
                return dev.strip()
    return None


def set_io_max(rule):
    path = f'{CGROUP_ROOT}/system.slice/{NODE_UNIT}/io.max'
    with open(path, 'w') as f:
        f.write(rule)
    return read(path)


def run_s5(args, node, views):
    """Slow storage: io.max on the node unit's cgroup for the ledger's own loop device only,
    while one lane per daemon churns. Expect bounded Unknown and no early release."""
    scenario = Scenario(args.evidence, 's5', args.force)
    if not scenario.begin({'wiops': args.wiops, 'wbps': args.wbps}):
        return True
    if not wait_quiet(node, views, 60):
        raise SystemExit('the node is not quiet')
    device = ledger_device()
    if not device:
        raise SystemExit('no ledger loop device recorded')
    census = node.census() or {}
    l_cgroup = read(f"/proc/{census.get('ledger')}/cgroup") if census.get('ledger') else None
    offset = log_offset(node)
    sampler = Sampler(scenario, node, views)
    sampler.start()
    tally = Tally()
    stop, pause = threading.Event(), threading.Event()
    lanes = []
    for d in node.daemons:
        t = threading.Thread(target=lane, args=(node, scenario, tally, d, 0, stop),
                             kwargs={'pause': pause}, daemon=True)
        t.start()
        lanes.append(t)
    time.sleep(args.warmup)
    phases = []
    for label, rule in (('throttled', f'{device} wiops={args.wiops} wbps={args.wbps}'),
                        ('severe', f'{device} wiops=1 wbps={64 * 1024}')):
        applied = set_io_max(rule)
        phases.append({'phase': label, 'rule': rule, 'io.max': applied, 'unix_ms': now_ms()})
        scenario.record({'op': 'io.max', **phases[-1]})
        time.sleep(args.throttled if label == 'throttled' else args.severe)
    cleared = set_io_max(f'{device} rbps=max wbps=max riops=max wiops=max')
    phases.append({'phase': 'cleared', 'io.max': cleared, 'unix_ms': now_ms()})
    scenario.record({'op': 'io.max', **phases[-1]})
    time.sleep(args.warmup)
    pause.set()
    settled = wait_pause_settled(node, views)
    after = quiesce_check(node, views, 'after the throttle')
    scenario.record({'op': 'quiesce', **after, 'settled': settled})
    stop.set()
    pause.clear()
    for t in lanes:
        t.join(timeout=400)
    failures = remove_all(node, list(tally.leftover), tally=tally)
    quiet = wait_quiet(node, views)
    totals, _ = views.claims()
    sampler.finish()
    health = {d: node.health(d) for d in node.daemons}
    records = read_records(scenario)
    slow = [r for r in records if r.get('op') in ('create', 'exec', 'rm') and r.get('ms', 0) > 240_000]
    unknown_states = query_unsettled(views)
    outcome = {
        'device': device, 'ledger_cgroup': l_cgroup, 'phases': phases, 'after': after,
        'settled': settled, 'sessions_by_daemon': tally.sessions,
        'refusals_by_daemon': tally.refusals_by_daemon, 'op_failures': tally.op_failures,
        'op_failure_samples': tally.op_failure_samples, 'delete_failures': failures,
        'quiet': quiet, 'claims_after': totals['slots'], 'charged_after': views.charged_count(),
        'claims_max': sampler.claims_max, 'vector_violations': sampler.violations,
        'health_after': health, 'unsettled_rows': unknown_states,
        'unaccounted': views.token_outcomes(), 'faults': views.ledger_facts()['node_faults'],
        'latched': (node.census() or {}).get('latched'), 'calls_over_4_min': slow[:10],
    }
    outcome['timings'] = timing_report(node, scenario, offset)
    in_unit = bool(l_cgroup) and NODE_UNIT in l_cgroup
    checks = [
        check('the throttle reaches only the ledger\'s device, through L\'s own cgroup', in_unit,
              (l_cgroup or '').strip()),
        check('every call answers in bounded time', not slow, json.dumps(slow[:2])),
        check('no early release: claims match charged rows once settled', not after['mismatch'],
              json.dumps(after['mismatch'])),
        check('Unknown is bounded: no row stays unsettled', not unknown_states,
              json.dumps(unknown_states[:5])),
        check('a slow sync is not a fail-stop', outcome['faults'] == 0 and not outcome['latched']
              and all(h.get('status') == 'serving' for h in health.values()),
              json.dumps({'faults': outcome['faults'], 'latched': outcome['latched'],
                          **{d: (h.get('status'), h.get('detail')) for d, h in health.items()}})),
        check('the node vector is never exceeded', not sampler.violations,
              '; '.join(sampler.violations[:3])),
        check('every issued token has a durable outcome', not outcome['unaccounted'],
              json.dumps(outcome['unaccounted'])[:300]),
        check('no capacity leak', totals['slots'] == 0 and outcome['charged_after'] == 0,
              f"claims {totals['slots']}, charged {outcome['charged_after']}"),
    ]
    lines = [json.dumps(p) for p in phases]
    lines.append(f"sessions {json.dumps(tally.sessions)}; refusals {json.dumps(tally.refusals_by_daemon)};"
                 f" op failures {tally.op_failures}")
    return scenario.finish(checks, outcome, lines)


def query_unsettled(views):
    out = []
    for name in views.node.daemons:
        for row in query(views.db(name), "SELECT id, state FROM sandboxes WHERE state NOT IN "
                                         "('ready', 'deleted', 'failed', 'lost')"):
            out.append({'daemon': name, 'id': row[0], 'state': row[1]})
    return out


# ---------------------------------------------------------------------------------------
# Setup, teardown and inventory.
# ---------------------------------------------------------------------------------------

def load_state():
    text = read(STATE)
    return json.loads(text) if text else {}


def save_state(state):
    write_json(STATE, state)


def made(state, kind, target, **extra):
    """Records an item before it is made, so a crash still leaves it for teardown."""
    state.setdefault('made', []).append({'kind': kind, 'target': target, **extra})
    save_state(state)


def own_ancestry():
    """This process and its parents (sudo, the shell), whose command lines name this script."""
    pids, pid = set(), os.getpid()
    while pid > 1 and pid not in pids:
        pids.add(pid)
        try:
            with open(f'/proc/{pid}/stat') as f:
                pid = int(f.read().rsplit(')', 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            break
    return pids


def node_processes(pgrep_out, own):
    """The `pgrep -a` lines that are the node's: a VMM, a jailer, the node test, or anything
    running from WORK. This script's own chain is not one (its name says firecracker and its
    evidence path starts with WORK's text)."""
    found = []
    for line in pgrep_out.splitlines():
        pid, _, cmd = line.partition(' ')
        if not pid.isdigit() or int(pid) in own or 'firecracker-two-daemon-stress' in cmd:
            continue
        if '--config-file /config.json' in cmd or 'kilnd-lib-tests' in cmd or WORK + '/' in cmd:
            found.append(line)
    return found


def observe():
    """Everything of the node that could be left on the host."""
    paths = [p for p in NODE_PATHS + (WORK,) if os.path.lexists(p)]
    sockets = [p for p in ('/run/kilnd-fctest/kilnd.sock', '/run/kilnd-fctest2/kilnd.sock',
                           HELPER_ROOT + '/helper.sock') if os.path.lexists(p)]
    loops_left = [(n, b) for n, b in loops()
                  if b.startswith(WORK_BASE + '/') or b.startswith(WORK + '/')]
    mounts = [m['target'] for m in mountinfo()
              if m['target'].startswith(JAIL_BASE) or m['target'].startswith(LEDGER_MOUNT)
              or m['source'].startswith('kilnd-jail-')]
    out = subprocess.run(['pgrep', '-a', '-f', 'firecracker|jailer|kilnd-lib-tests'],
                         capture_output=True, text=True).stdout
    processes = node_processes(out, own_ancestry())
    return {'paths': paths, 'accounts': [a for a in ACCOUNTS if account_exists(a)],
            'units': {u: unit_state(u) for u in UNITS}, 'loops': loops_left,
            'mounts': mounts, 'processes': processes, 'sockets': sockets}


def cmd_setup(args):
    preflight(args)
    state = load_state()
    if state.get('setup_done'):
        if unit_state(NODE_UNIT) == 'active' and os.path.exists(os.path.join(NODE_DIR, 'node.json')):
            log('setup already done and the node is serving')
            return 0
        raise SystemExit('setup was done but the node is not serving: run teardown first')
    if state:
        raise SystemExit(f'a partial setup is recorded in {STATE}: run teardown first')
    left = inventory_problems(observe())
    if left:
        raise SystemExit('refusing: the host is not clean:\n  ' + '\n  '.join(left))
    ev = os.path.join(args.evidence, 'setup')
    os.makedirs(ev, exist_ok=True)
    os.makedirs(WORK, mode=0o711)
    os.chmod(WORK, 0o711)
    state = {'schema': 'm32-state/1', 'started_unix_ms': now_ms(), 'made': []}
    made(state, 'dir', WORK)
    for d in (BIN, ARTIFACTS, NODE_DIR):
        os.makedirs(d, mode=0o755)
    shas = {}
    for name in ('kilnd', 'kilndctl', 'kilnd-helper', 'kilnd-lib-tests'):
        source = os.path.join(args.bin, name)
        run(['install', '-m', '0755', '-o', 'root', '-g', 'root', source, os.path.join(BIN, name)])
        if name == 'kilnd-lib-tests':
            run(['strip', '--strip-debug', os.path.join(BIN, name)])
        shas[name] = sha256(os.path.join(BIN, name))
    inputs = {'jailer': (args.tools, 'jailer', '0555'), 'mkfs.xfs': (args.tools, 'mkfs.xfs', '0555'),
              'firecracker': (os.path.dirname(args.vmm), os.path.basename(args.vmm), '0555'),
              'Image': (args.guest, 'Image', '0444'),
              'rootfs.squashfs': (args.guest, 'rootfs.squashfs', '0444'),
              'kilnd-guest-broker': (args.guest, 'kilnd-guest-broker', '0444')}
    sources = {}
    for name, (directory, source, mode) in inputs.items():
        path = os.path.join(directory, source)
        sources[name] = sha256(path)
        run(['install', '-m', mode, '-o', 'root', '-g', 'root', path, os.path.join(ARTIFACTS, name)])
        shas['artifact:' + name] = sha256(os.path.join(ARTIFACTS, name))
    write_json(os.path.join(ev, 'binaries.json'), {'installed': shas, 'sources': sources})
    # The ledger's own filesystem: a sparse image here, a loop device with direct I/O, ext4,
    # mounted on /run (tmpfs), so nothing persists outside WORK across a reboot.
    with open(LEDGER_IMAGE, 'wb') as f:
        f.truncate(LEDGER_IMAGE_BYTES)
    device = run(['losetup', '--find', '--show', '--direct-io=on', LEDGER_IMAGE]).stdout.strip()
    made(state, 'loop', device, backing=LEDGER_IMAGE)
    run(['mkfs.ext4', '-q', '-F', '-L', 'kilnd-m32', device])
    made(state, 'dir', LEDGER_MOUNT)
    os.makedirs(LEDGER_MOUNT, mode=0o755)
    made(state, 'mount', LEDGER_MOUNT)
    run(['mount', '-o', 'nodev,nosuid,noexec', device, LEDGER_MOUNT])
    os.chmod(LEDGER_MOUNT, 0o755)
    # The node: one privileged test in its own transient unit, holding the helper and both
    # daemons (their accounts, units, state and enrollments) until teardown asks it to stop.
    for account in ACCOUNTS:
        made(state, 'account', account)
    for unit in UNITS[1:]:
        made(state, 'unit', unit)
    made(state, 'unit', NODE_UNIT)
    made(state, 'node', NODE_DIR)
    node_log = os.path.join(NODE_DIR, 'node.log')
    run(['systemd-run', '--unit', NODE_UNIT, '--collect', '--quiet',
         '--property=IOAccounting=yes', f'--property=StandardOutput=append:{node_log}',
         f'--property=StandardError=append:{node_log}', '--',
         'setpriv', f'--bounding-set={CAPS}', '--inh-caps=-all',
         'env', f'KILND_B4_ARTIFACTS={ARTIFACTS}', f'KILND_B6_BIN={BIN}',
         f'KILND_M32_NODE={NODE_DIR}', f'KILND_M32_HELPER_ROOT={HELPER_ROOT}', 'RUST_BACKTRACE=1',
         os.path.join(BIN, 'kilnd-lib-tests'), '--include-ignored', '--exact', NODE_TEST,
         '--test-threads=1', '--nocapture'])
    end = time.monotonic() + 300
    while not os.path.exists(os.path.join(NODE_DIR, 'node.json')):
        if unit_state(NODE_UNIT) not in ('active', 'activating') or time.monotonic() > end:
            shutil.copyfile(node_log, os.path.join(ev, 'node.log'))
            raise SystemExit('the node did not start; see node.log:\n'
                             + (read(node_log) or '')[-4000:])
        time.sleep(1)
    node = Node()
    state['instances'] = [d['instance'] for d in node.desc['daemons']]
    state['setup_done'] = True
    save_state(state)
    shutil.copyfile(os.path.join(NODE_DIR, 'node.json'), os.path.join(ev, 'node.json'))
    health = {n: node.health(n) for n in node.daemons}
    write_json(os.path.join(ev, 'health.json'), health)
    write_json(os.path.join(ev, 'state.json'), state)
    sync()
    log(f'setup: node serving with {", ".join(node.daemons)}; ledger on {device}')
    for name, h in health.items():
        log(f"  {name}: {h.get('status')} node {h.get('node_sandboxes')}/{h.get('node_sandboxes_max')}")
    return 0


def remove_tree(path):
    """Removes a tree only when nothing is mounted at or under it: rmtree would follow
    into a mount."""
    if not os.path.lexists(path):
        return
    under = [m['target'] for m in mountinfo()
             if m['target'] == path or m['target'].startswith(path.rstrip('/') + '/')]
    if under:
        log(f'not removing {path}: still mounted under it: {under}')
        return
    shutil.rmtree(path, ignore_errors=True)


def kill_cgroup(path):
    if not os.path.isdir(path):
        return
    for root, dirs, _ in os.walk(path, topdown=False):
        try:
            with open(os.path.join(root, 'cgroup.kill'), 'w') as f:
                f.write('1')
        except OSError:
            pass
    time.sleep(0.5)
    remove_cgroup_tree(path)


def remove_cgroup_tree(path):
    if not os.path.isdir(path):
        return
    for root, dirs, _ in os.walk(path, topdown=False):
        for d in dirs:
            try:
                os.rmdir(os.path.join(root, d))
            except OSError as e:
                log(f'cgroup {os.path.join(root, d)}: {e}')
    try:
        os.rmdir(path)
    except OSError as e:
        log(f'cgroup {path}: {e}')


def stop_node(ev):
    if unit_state(NODE_UNIT) in ('active', 'activating') and os.path.exists(
            os.path.join(NODE_DIR, 'node.json')):
        try:
            node = Node()
            if os.path.exists(node.desc['helper']['ledger']):
                # A byte-exact copy of the ledger for the evidence, through SQLite's backup.
                src = sqlite3.connect(f"file:{node.desc['helper']['ledger']}?mode=ro", uri=True)
                dst = sqlite3.connect(os.path.join(ev, 'ledger-copy.db'))
                src.backup(dst)
                dst.close()
                src.close()
            reply = node.request('stop', timeout=60)
            log(f'node: {json.dumps(reply.get("reply"))}')
        except (RuntimeError, sqlite3.Error, OSError) as e:
            log(f'node stop request: {e}')
        end = time.monotonic() + 300
        while unit_state(NODE_UNIT) in ('active', 'activating', 'deactivating'):
            if time.monotonic() > end:
                log('the node did not stop on request: stopping its unit')
                break
            time.sleep(1)
    run(['systemctl', 'stop', NODE_UNIT], check_rc=False)
    run(['systemctl', 'reset-failed', NODE_UNIT], check_rc=False)
    for name in ('final.json', 'dropped.json', 'node.json', 'node.log'):
        path = os.path.join(NODE_DIR, name)
        if os.path.exists(path):
            shutil.copyfile(path, os.path.join(ev, name))
    final = os.path.join(NODE_DIR, 'final')
    if os.path.isdir(final):
        remove_tree(os.path.join(ev, 'final'))
        shutil.copytree(final, os.path.join(ev, 'final'))


def cmd_teardown(args):
    if os.geteuid() != 0:
        raise SystemExit('run as root (sudo)')
    state = load_state()
    ev = os.path.join(args.evidence, 'teardown')
    os.makedirs(ev, exist_ok=True)
    if not state:
        log('nothing recorded: nothing to tear down')
        problems = inventory_problems(observe())
        return 1 if problems else 0
    write_json(os.path.join(ev, 'state.json'), state)
    plan = teardown_plan(state)
    write_json(os.path.join(ev, 'plan.json'), plan)
    done = []
    for kind, target in plan:
        if kind == 'stop-node':
            stop_node(ev)
        elif kind == 'stop-unit':
            run(['systemctl', 'stop', target], check_rc=False)
            run(['systemctl', 'reset-failed', target], check_rc=False)
        elif kind == 'kill-cgroup':
            kill_cgroup(target)
        elif kind == 'unmount-under':
            for m in sorted((m['target'] for m in mountinfo() if m['target'].startswith(target + '/')
                             or m['target'] == target), key=len, reverse=True):
                run(['umount', m], check_rc=False)
        elif kind == 'detach-loops-under':
            for name, backing in loops():
                if backing.startswith(target + '/'):
                    run(['losetup', '-d', f'/dev/{name}'], check_rc=False)
        elif kind == 'remove-account':
            if account_exists(target):
                run(['userdel', target], check_rc=False)
            run(['groupdel', target], check_rc=False)
        elif kind == 'remove-tree':
            remove_tree(target)
        elif kind == 'remove-cgroup-tree':
            remove_cgroup_tree(target)
        elif kind == 'unmount':
            if any(m['target'] == target for m in mountinfo()):
                run(['umount', target], check_rc=False)
        elif kind == 'detach-loop':
            name = os.path.basename(target)
            backing = read(f'/sys/block/{name}/loop/backing_file')
            # Only the device whose backing file is still the one recorded.
            if backing and backing.strip() == LEDGER_IMAGE:
                run(['losetup', '-d', target], check_rc=False)
        done.append([kind, target])
    write_json(os.path.join(ev, 'done.json'), done)
    problems = inventory_problems(observe())
    write_json(os.path.join(ev, 'left.json'), problems)
    final_text = read(os.path.join(ev, 'final.json'))
    checks = check_final(json.loads(final_text) if final_text else None)
    checks.append(check('nothing of the node is left', not problems, '; '.join(problems)))
    lines = ['# teardown', *format_checks(checks)]
    with open(os.path.join(ev, 'summary.txt'), 'w') as f:
        f.write('\n'.join(lines) + '\n')
    sync()
    print('\n'.join(lines), flush=True)
    return 0 if all(c['pass'] for c in checks) else 1


def cmd_inventory(args):
    if os.geteuid() != 0:
        raise SystemExit('run as root (sudo)')
    observed = observe()
    problems = inventory_problems(observed)
    ev = os.path.join(args.evidence, 'inventory')
    os.makedirs(ev, exist_ok=True)
    report = {'unix_ms': now_ms(), 'observed': observed, 'problems': problems,
              'all_loops': loops(), 'uptime_minutes': round(uptime_minutes(), 1)}
    live = subprocess.run(['kilndctl', 'health'], capture_output=True, text=True)
    report['live_health'] = parse_health(live.stdout)
    path = os.path.join(ev, f'inventory-{now_ms()}.json')
    write_json(path, report)
    sync()
    for p in problems:
        print(f'LEFT {p}')
    print(f"{'CLEAN' if not problems else 'NOT CLEAN'}: {len(problems)} item(s); live node "
          f"reservations {report['live_health'].get('node_sandboxes')}/"
          f"{report['live_health'].get('node_sandboxes_max')}; loops {report['all_loops']}")
    return 0 if not problems else 1


def cmd_scenario(args):
    preflight(args)
    if not load_state().get('setup_done'):
        raise SystemExit('run setup first')
    if unit_state(NODE_UNIT) != 'active':
        raise SystemExit(f'the node unit is {unit_state(NODE_UNIT)}')
    node = Node()
    views = Views(node)
    runner = {'s1': run_s1, 's2': run_s2, 's3': run_s3, 's4': run_s4, 's5': run_s5}[args.command]
    passed = runner(args, node, views)
    return 0 if passed else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description='M3-2 two-daemon Firecracker capacity stress')
    parser.add_argument('--evidence', required=True, help='evidence directory (created)')
    parser.add_argument('--ignore-uptime', action='store_true')
    parser.add_argument('--force', action='store_true', help='rerun a complete scenario')
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('setup')
    p.add_argument('--bin', required=True)
    home = os.path.expanduser('~' + os.environ.get('SUDO_USER', ''))
    p.add_argument('--tools', default=os.path.join(home, 'b4-build/out'))
    p.add_argument('--vmm', default=os.path.join(
        home, 'fc-spike/release-v1.17.0-aarch64/firecracker-v1.17.0-aarch64'))
    p.add_argument('--guest', default=os.path.join(home, 'kiln-guest-build/bundle-a'))
    p = sub.add_parser('s1')
    p.add_argument('--minutes', type=float, required=True)
    p.add_argument('--lanes', type=int, default=3, help='lanes per daemon')
    p.add_argument('--label', help='evidence subdirectory (default s1)')
    sub.add_parser('s2')
    p = sub.add_parser('s3')
    p.add_argument('--max-minutes', type=float, default=20)
    p = sub.add_parser('s4')
    p.add_argument('--kill', choices=('daemon', 'helper', 'L'), required=True)
    p.add_argument('--warmup', type=float, default=30)
    p.add_argument('--outage', type=float, default=30)
    p = sub.add_parser('s5')
    p.add_argument('--wiops', type=int, default=20)
    p.add_argument('--wbps', type=int, default=1 << 20)
    p.add_argument('--warmup', type=float, default=30)
    p.add_argument('--throttled', type=float, default=180)
    p.add_argument('--severe', type=float, default=60)
    sub.add_parser('inventory')
    sub.add_parser('teardown')
    args = parser.parse_args(argv)
    args.evidence = os.path.abspath(args.evidence)
    os.makedirs(args.evidence, exist_ok=True)
    if args.command == 'setup':
        return cmd_setup(args)
    if args.command == 'teardown':
        return cmd_teardown(args)
    if args.command == 'inventory':
        return cmd_inventory(args)
    return cmd_scenario(args)


if __name__ == '__main__':
    sys.exit(main())
