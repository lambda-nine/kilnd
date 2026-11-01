#!/usr/bin/env python3
"""Installed-service regressions for the deployment scripts, in the Lima VM, as root. This
stops every instance, repeatedly, so don't run it on a node you care about.

  sudo python3 -I scripts/deployment-regressions.py --bin-a DIR --bin-b DIR

DIR holds kilnd, kilnd-helper and kilndctl, and the two must be different builds. The node
must have kilnd installed from --bin-a, by scripts/install.sh, and no Firecracker policy or
ledger: this makes its own and removes them, with its accounts, whatever happens. It adds no
manifest or profile, so production Firecracker stays disabled throughout. It covers B3F-01,
B3F-02 and B3F-03 from reviews/2026-11-01-b3-final.md, including every way an upgrade can fail.
"""
import argparse
import glob
import hashlib
import json
import os
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
BIN = '/usr/local/bin'
KILND = BIN + '/kilnd'
HELPER = BIN + '/kilnd-helper'
POLICY = '/etc/kilnd/firecracker-node.json'
LEDGER = '/var/lib/kilnd-helper/firecracker'
HELPER_SOCKET = '/run/kilnd-helper/helper.sock'
HELPER_DROPIN = '/etc/systemd/system/kilnd-helper.service.d/50-firecracker-test.conf'
NAMES = ('t1', 't2', 't3')
# Until B7 a real kilnd@ daemon stops at startup reconciliation, then gives up, which says
# nothing about these scripts. For this test each runs the real image, in the real unit, as
# the real account, holding its attachment and state lock until stopped, as B7's will.
STAY_ATTACHED = '/run/systemd/system/kilnd@.service.d'
JOURNAL = '/var/lib/kilnd-helper/upgrade/journal.json'
STAGE = BIN + '/.kilnd-upgrade'
WINDOW_RECORD = '/run/kilnd-maintenance.window.json'
FAILED_DIR = '/var/lib/kilnd-helper/failed-upgrades'
SANDBOXES = []


def out(message):
    print(message, flush=True)


def passed(name, detail=''):
    out('PASS %s%s' % (name, ': ' + detail if detail else ''))


def sh(*argv, check=True, **kwargs):
    done = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, **kwargs)
    if check and done.returncode != 0:
        raise AssertionError('%s failed %d:\n%s\n%s' %
                             (' '.join(argv), done.returncode, done.stdout, done.stderr))
    return done


def script(*args, check=True, timeout=600):
    return sh(os.path.join(REPO, 'scripts', args[0]), *args[1:], check=check, timeout=timeout)


def active(unit):
    return sh('systemctl', 'is-active', unit, check=False).stdout.strip()


def load_state(unit):
    return sh('systemctl', 'show', '--property=LoadState', '--value', unit).stdout.strip()


def rows():
    """The ledger as root reads it, helper stopped: only ever called inside a stop."""
    return json.loads(sh(HELPER, 'enrollments').stdout)


def with_helper_stopped(action):
    """A plain look at the ledger for the tests, outside any transaction."""
    running = {u: active(u) in ('active', 'activating') for u in units()}
    sh('systemctl', 'stop', *running)
    try:
        for _ in range(100):
            try:
                return action()
            except AssertionError as error:
                if 'stop kilnd-helper' not in str(error):
                    raise
                time.sleep(0.1)
        raise AssertionError('the node lock stayed held')
    finally:
        for unit in ('kilnd-helper.socket', 'kilnd-helper.service', *running):
            if running.get(unit):
                # Until B7 a kilnd@ daemon stops at startup reconciliation, by design.
                sh('systemctl', 'start', '--no-block', unit)


def units():
    found = ['kilnd-helper.socket', 'kilnd-helper.service', 'kilnd.service']
    for name in NAMES:
        if os.path.exists('/var/lib/kilnd-' + name):
            found.append('kilnd@%s.service' % name)
    return found


def sha(path):
    with open(path, 'rb') as file:
        return hashlib.sha256(file.read()).hexdigest()


def image(path):
    meta = os.stat(path)
    return (meta.st_dev, meta.st_ino, meta.st_size, sha(path))


def row_image(row):
    e = row['executable']
    return (e['st_dev'], e['st_ino'], e['bytes'], e['sha256'])


def state_id(account, state):
    """What the instance's own database says, read as its own account."""
    code = ('import sqlite3,sys;print(sqlite3.connect(sys.argv[1]).execute('
            '"SELECT instance_id FROM daemon_identity").fetchone()[0])')
    entry = pwd.getpwnam(account)
    return subprocess.run(
        [sys.executable, '-I', '-c', code, state + '/kilnd.db'],
        user=entry.pw_uid, group=entry.pw_gid, extra_groups=[], cwd='/',
        capture_output=True, text=True, check=True,
    ).stdout.strip()


def snapshot_node():
    """Everything an upgrade or a window must leave as it found."""
    state = {
        'images': {i: image(os.path.join(BIN, i)) for i in ('kilnd', 'kilnd-helper', 'kilndctl')},
        'rows': with_helper_stopped(rows),
        'units': {u: active(u) in ('active', 'activating') for u in units()},
        'files': {},
    }
    for path in ('kilnd-helper.socket', 'kilnd-helper.service', 'kilnd.service', 'kilnd@.service'):
        state['files'][path] = sha('/etc/systemd/system/' + path)
    return state


def assert_same_node(before, what):
    # Wait out the moment between restart attempts of a kilnd@ daemon.
    deadline = time.monotonic() + 30
    while True:
        now = {u: active(u) in ('active', 'activating') for u in units()}
        if now == before['units'] or time.monotonic() > deadline:
            break
        time.sleep(0.2)
    assert now == before['units'], '%s: units %s, were %s' % (what, now, before['units'])
    after = {i: image(os.path.join(BIN, i)) for i in before['images']}
    assert after == before['images'], '%s: images changed' % what
    for path, digest in before['files'].items():
        assert sha('/etc/systemd/system/' + path) == digest, '%s: %s changed' % (what, path)
    assert with_helper_stopped(rows) == before['rows'], '%s: enrollments changed' % what
    assert not os.path.exists(JOURNAL) and not os.path.exists(STAGE), what + ': work left over'
    assert not os.path.exists(WINDOW_RECORD), what + ': a window left open'
    for unit in ('kilnd-helper.socket', 'kilnd-helper.service'):
        assert load_state(unit) == 'loaded', '%s: %s still %s' % (what, unit, load_state(unit))


def attach_proof(unit, state):
    """The real thing: a process of that unit, from the installed image, in the unit's own
    cgroup, attaches through the installed helper. ExecStartPre shares all of that with the
    main process, and this drop-in lives only in /run for the length of the check."""
    directory = '/run/systemd/system/%s.d' % unit
    os.makedirs(directory, exist_ok=True)
    with open(directory + '/90-check-attachment.conf', 'w') as file:
        file.write('[Service]\nExecStartPre=%s check-attachment --state-dir %s\n' % (KILND, state))
    sh('systemctl', 'stop', unit)
    sh('systemctl', 'daemon-reload')
    # Only what this start says counts, not anything an earlier one was still saying.
    tail = sh('journalctl', '-n', '1', '--show-cursor', '-o', 'cat', '--no-pager').stdout
    cursor = tail.strip().splitlines()[-1].split('cursor: ', 1)[1]
    try:
        sh('systemctl', 'start', '--no-block', unit)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            text = sh('journalctl', '-u', unit, '-o', 'cat', '--no-pager',
                      '--after-cursor=' + cursor).stdout
            for line in text.splitlines():
                if line.startswith('attached '):
                    return line
                if 'attach ' in line and 'kilnd failed' in line:
                    return 'REFUSED ' + line
            time.sleep(0.2)
        raise AssertionError('no attachment result from %s:\n%s' % (unit, text))
    finally:
        shutil.rmtree(directory)
        sh('systemctl', 'daemon-reload')


def provision_policy():
    os.makedirs('/etc/kilnd', mode=0o755, exist_ok=True)
    policy = {
        'schema': 'kilnd-firecracker-node-policy-v1',
        'node_id': os.urandom(16).hex(),
        'ledger_dir': LEDGER,
        'ceilings': {'slots': 3, 'memory_bytes': 3221225472, 'disk_bytes': 17179869184,
                     'host_cpu_millis': 3500, 'virtual_cpu_slots': 3, 'pids': 2048, 'host_pids': 128},
        'uid_range': {'first': 300000, 'last': 365535},
        'gid_range': {'first': 300000, 'last': 365535},
        'cid_range': {'first': 3, 'last': 65535},
        'profiles': [],
    }
    with open(POLICY, 'w') as file:
        json.dump(policy, file)
    os.chmod(POLICY, 0o644)
    sh(HELPER, '--firecracker-policy', POLICY, '--firecracker-init-ledger')
    os.makedirs(os.path.dirname(HELPER_DROPIN), exist_ok=True)
    with open(HELPER_DROPIN, 'w') as file:
        file.write('[Service]\nExecStart=\nExecStart=%s --firecracker-policy %s\n' % (HELPER, POLICY))
    sh('systemctl', 'daemon-reload')
    sh('systemctl', 'restart', 'kilnd-helper.service')


def stay_attached():
    os.makedirs(STAY_ATTACHED, exist_ok=True)
    with open(STAY_ATTACHED + '/90-stay-attached.conf', 'w') as file:
        file.write('[Service]\nExecStart=\nExecStart=%s check-attachment '
                   '--state-dir /var/lib/kilnd-%%i --hold\n' % KILND)
    sh('systemctl', 'daemon-reload')


def running_image(unit):
    """The image behind a unit's main process, by what the kernel still has open."""
    deadline = time.monotonic() + 30
    while True:
        pid = sh('systemctl', 'show', '--property=MainPID', '--value', unit).stdout.strip()
        try:
            path = os.readlink('/proc/%s/exe' % pid)
            meta = os.stat('/proc/%s/exe' % pid)
            # Until it execs, a starting unit's main process is still systemd.
            if 'systemd' not in path:
                return meta.st_dev, meta.st_ino, path
        except OSError:
            pass
        assert time.monotonic() < deadline, unit + ' has no main process'
        time.sleep(0.05)


def wait_active(*names):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if all(active(u) == 'active' for u in names):
            return
        time.sleep(0.1)
    raise AssertionError({u: active(u) for u in names})


def cleanup():
    """Whatever happened, the node goes back to one instance with no Firecracker group."""
    script('upgrade.sh', '--recover', check=False)
    for sandbox in SANDBOXES:
        sh(BIN + '/kilndctl', 'rm', sandbox, check=False)
    shutil.rmtree(STAY_ATTACHED, ignore_errors=True)
    for name in NAMES:
        unit = 'kilnd@%s.service' % name
        sh('systemctl', 'disable', '--now', unit, check=False)
        sh('systemctl', 'reset-failed', unit, check=False)
        sh('userdel', 'kilnd-' + name, check=False)
        sh('groupdel', 'kilnd-' + name, check=False)
        shutil.rmtree('/var/lib/kilnd-' + name, ignore_errors=True)
        shutil.rmtree('/var/lib/private/kilnd-' + name, ignore_errors=True)
        shutil.rmtree('/run/kilnd-' + name, ignore_errors=True)
    for path in (POLICY, HELPER_DROPIN):
        if os.path.exists(path):
            os.unlink(path)
    if os.path.isdir('/etc/kilnd') and not os.listdir('/etc/kilnd'):
        os.rmdir('/etc/kilnd')
    if os.path.isdir(os.path.dirname(HELPER_DROPIN)) and not os.listdir(os.path.dirname(HELPER_DROPIN)):
        os.rmdir(os.path.dirname(HELPER_DROPIN))
    shutil.rmtree(LEDGER, ignore_errors=True)
    shutil.rmtree(FAILED_DIR, ignore_errors=True)
    os.makedirs(LEDGER, mode=0o700, exist_ok=True)
    sh('systemctl', 'daemon-reload')
    sh('systemctl', 'restart', 'kilnd-helper.service', check=False)
    sh('systemctl', 'restart', 'kilnd.service', check=False)


HAMMER = r'''
import socket, sys, time
counts = {'connected': 0, 'unavailable': 0}
end = time.monotonic() + float(sys.argv[2])
while time.monotonic() < end:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(sys.argv[1])
        counts['connected'] += 1
    except OSError:
        counts['unavailable'] += 1
    s.close()
    time.sleep(0.002)
print(counts)
'''


def hammer(seconds, account='kilnd'):
    entry = pwd.getpwnam(account)
    groups = [g for g in os.getgrouplist(account, entry.pw_gid)]
    return subprocess.Popen(
        [sys.executable, '-I', '-c', HAMMER, HELPER_SOCKET, str(seconds)],
        user=entry.pw_uid, group=entry.pw_gid, extra_groups=groups, cwd='/',
        stdout=subprocess.PIPE, text=True,
    )


def test_01_identity(args):
    """B3F-01: init, then enroll that ID, then start."""
    out('--- B3F-01')
    usage = script('add-instance.sh', 't1', '1' * 32, check=False)
    assert usage.returncode == 2, 'an arbitrary instance ID must not be accepted'
    assert 'usage' in usage.stderr
    assert not os.path.exists('/var/lib/kilnd-t1')
    passed('add-instance accepts no instance ID')

    first = script('add-instance.sh', 't1').stdout.split()[0]
    second = script('add-instance.sh', 't2').stdout.split()[0]
    assert first != second
    enrolled = {r['unit']: r for r in with_helper_stopped(rows)}
    for name, instance in (('t1', first), ('t2', second)):
        unit = 'kilnd@%s.service' % name
        assert enrolled[unit]['instance_id'] == instance
        assert state_id('kilnd-' + name, '/var/lib/kilnd-' + name) == instance
        entry = pwd.getpwnam('kilnd-' + name)
        assert (enrolled[unit]['uid'], enrolled[unit]['gid']) == (entry.pw_uid, entry.pw_gid)
        meta = os.lstat('/var/lib/kilnd-' + name)
        assert (meta.st_uid, meta.st_mode & 0o777) == (entry.pw_uid, 0o700)
        meta = os.lstat('/var/lib/kilnd-%s/kilnd.db' % name)
        assert (meta.st_uid, meta.st_mode & 0o777) == (entry.pw_uid, 0o600)
    passed('two instances: enrolled ID == database ID, private to its own account', first + ' ' + second)

    wait_active('kilnd@t1.service', 'kilnd@t2.service')
    # Repeating is harmless and can't make a second identity.
    again = script('add-instance.sh', 't1').stdout.split()[0]
    assert again == first
    passed('add-instance repeated keeps the identity')

    # Root's half of init-state, against what a hostile or careless setup could arrange.
    def refused(state, account, why):
        done = sh(KILND, 'init-state', '--state-dir', state, '--account', account, check=False)
        assert done.returncode != 0 and why in done.stderr, '%s: %s' % (state, done.stderr)
    refused('/var/lib/kilnd-t1', 'root', 'refuses root')
    refused('/var/lib/kilnd-t1', 'kilnd-t2', 'belongs to another account')
    refused('/tmp/kilnd-init-state-probe', 'kilnd-t1', 'is not root')
    os.symlink('/etc', '/var/lib/kilnd-link')
    try:
        refused('/var/lib/kilnd-link', 'kilnd-t1', 'without following links')
    finally:
        os.unlink('/var/lib/kilnd-link')
    assert not os.path.exists('/tmp/kilnd-init-state-probe')
    passed('init-state as root refuses root, foreign state, untrusted parents and links')

    for unit, state in (('kilnd@t1.service', '/var/lib/kilnd-t1'), ('kilnd@t2.service', '/var/lib/kilnd-t2'),
                        ('kilnd.service', '/var/lib/kilnd')):
        proof = attach_proof(unit, state)
        assert proof.startswith('attached ' + enrolled[unit]['instance_id']), proof
        passed('attaches for real from its unit', '%s: %s' % (unit, proof))
    return first, second


def schema_of(account, state):
    code = ('import sqlite3,sys;print(sqlite3.connect(sys.argv[1]).execute('
            '"PRAGMA user_version").fetchone()[0])')
    entry = pwd.getpwnam(account)
    return int(subprocess.run(
        [sys.executable, '-I', '-c', code, state + '/kilnd.db'],
        user=entry.pw_uid, group=entry.pw_gid, extra_groups=[], cwd='/',
        capture_output=True, text=True, check=True,
    ).stdout.strip())


def sandbox_answers(sandbox, what):
    """Windows must not cost running work: the helper's KillMode=process has to survive them."""
    deadline = time.monotonic() + 30
    while True:
        done = sh(BIN + '/kilndctl', 'exec', sandbox, '--', '/bin/echo', 'alive', check=False)
        if done.returncode == 0 and 'alive' in done.stdout:
            return
        # The daemon may only just be coming back; the sandbox itself must not be gone.
        assert time.monotonic() < deadline, '%s: %s %s' % (what, done.stdout, done.stderr)
        time.sleep(0.5)


def test_02_activation(args, sandbox):
    """B3F-02: a hostile enrolled account connecting throughout can't stop enrollment."""
    out('--- B3F-02')
    # The PoC first, to prove the hammer is a real threat to the old sequence.
    sh('systemctl', 'stop', 'kilnd-helper.service')
    assert active('kilnd-helper.socket') == 'active'
    probe = hammer(1)
    probe.communicate()
    assert active('kilnd-helper.service') == 'active', 'the socket should have reactivated it'
    passed('PoC: stopping only the service is reactivated by one connection')

    before = {u: active(u) in ('active', 'activating') for u in units()}
    busy = hammer(45, 'kilnd-t1')
    started = time.monotonic()
    third = script('add-instance.sh', 't3').stdout.split()[0]
    took = time.monotonic() - started
    assert busy.poll() is None, 'the hammer must outlast the enrollment'
    assert with_helper_stopped(rows), 'nothing recorded'
    busy.send_signal(signal.SIGTERM)
    busy.wait()
    # A second one to count what it actually saw across a window.
    counter = hammer(20, 'kilnd-t1')
    time.sleep(1)
    script('add-instance.sh', 't3')
    report = counter.communicate()[0]
    counts = eval(report)  # pylint: disable=eval-used
    assert counts['unavailable'] > 0 and counts['connected'] > 0, report
    assert state_id('kilnd-t3', '/var/lib/kilnd-t3') == third
    for unit, was in before.items():
        if was:
            assert active(unit) in ('active', 'activating'), unit
    passed('enrollment completes under continuous connection', '%.1fs; %s' % (took, report.strip()))
    sandbox_answers(sandbox, 'after two enrollment windows')
    passed('a live sandbox survives the window', sandbox)

    # The window closes on a signal too, with exactly what was running.
    before = snapshot_node()
    hold = hammer(30, 'kilnd-t1')
    process = subprocess.Popen([sys.executable, '-I', os.path.join(REPO, 'scripts/kilnd-maintenance.py'),
                                'add-instance', 't3'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + 30
    while not os.path.exists(WINDOW_RECORD) and time.monotonic() < deadline and process.poll() is None:
        time.sleep(0.001)
    process.send_signal(signal.SIGTERM)
    process.communicate()
    hold.send_signal(signal.SIGTERM)
    hold.wait()
    assert_same_node(before, 'add-instance interrupted')
    passed('a signal during the window restores exactly the prior units')

    # SIGKILL leaves the record, and activation stays unavailable until recover.
    before = snapshot_node()
    process = subprocess.Popen([sys.executable, '-I', os.path.join(REPO, 'scripts/kilnd-maintenance.py'),
                                'add-instance', 't3'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 30
    while not os.path.exists(WINDOW_RECORD) and time.monotonic() < deadline and process.poll() is None:
        time.sleep(0.001)
    process.kill()
    process.wait()
    deadline = time.monotonic() + 30
    while load_state('kilnd-helper.socket') != 'masked' and time.monotonic() < deadline:
        time.sleep(0.05)
    # Killed in its first moments, the mask may not be down yet; a fresh mask is below.
    script('upgrade.sh', '--recover')
    assert_same_node(before, 'add-instance killed')
    passed('after SIGKILL, recover restores exactly the prior units')


def fake_build(directory, base, kilnd=None, helper=None):
    """A build with one image replaced by a script that fails where the test wants."""
    os.makedirs(directory, exist_ok=True)
    for name in ('kilnd', 'kilnd-helper', 'kilndctl'):
        shutil.copy2(os.path.join(base, name), os.path.join(directory, name))
    if kilnd or helper:
        os.makedirs(directory + '/real', exist_ok=True)
        os.chmod(directory, 0o755)
    for name, text in (('kilnd', kilnd), ('kilnd-helper', helper)):
        if text is None:
            continue
        real = directory + '/real/' + name
        shutil.copy2(os.path.join(base, name), real)
        with open(os.path.join(directory, name), 'w') as file:
            file.write(text.replace('REAL', real))
        os.chmod(os.path.join(directory, name), 0o755)
    return directory


def kill_slow_helper():
    """Its command dies with the process that ran it, as in a power failure."""
    sh('pkill', '-9', '-f', 'kilnd-helper refresh-enrollments', check=False)
    sh('pkill', '-9', '-x', 'sleep', check=False)


def expect_upgrade_refused_or_undone(build, code, what, before):
    done = script('upgrade.sh', build, check=False)
    assert done.returncode == code, '%s: exit %d, wanted %d\n%s' % (what, done.returncode, code, done.stderr)
    assert_same_node(before, what)
    return done.stderr


def test_03_upgrade(args, scratch, first, second, sandbox):
    """B3F-03: every instance moves together or none does."""
    out('--- B3F-03')
    a, b = args.bin_a, args.bin_b
    assert sha(a + '/kilnd') != sha(b + '/kilnd'), 'the two builds must differ'
    assert sha(KILND) == sha(a + '/kilnd')
    before = snapshot_node()
    version_a = sh(KILND, '--version').stdout.strip()

    # The negative control: the old installer's replacement really is refused attachment.
    moved = KILND + '.control'
    os.rename(KILND, moved)
    shutil.copy2(b + '/kilnd', KILND)
    os.chmod(KILND, 0o755)
    refused = attach_proof('kilnd@t1.service', '/var/lib/kilnd-t1')
    os.replace(moved, KILND)
    sh('systemctl', 'reset-failed', 'kilnd@t1.service', check=False)
    sh('systemctl', 'restart', 'kilnd@t1.service')
    wait_active('kilnd@t1.service')
    assert refused.startswith('REFUSED'), refused
    passed('control: a replaced image with no refresh is refused', refused[:140])
    assert_same_node(before, 'the control')
    old_running = {u: running_image(u) for u in ('kilnd.service', 'kilnd@t1.service', 'kilnd@t2.service', 'kilnd@t3.service')}
    old_inode = os.stat(KILND).st_ino
    for unit, seen in old_running.items():
        assert seen[1] == old_inode, unit

    # Refusals, with nothing replaced.
    broken = fake_build(scratch + '/broken-version', b, kilnd='#!/bin/sh\nexit 7\n')
    log = expect_upgrade_refused_or_undone(broken, 2, 'an image that cannot run', before)
    assert 'does not run' in log, log
    passed('refused before stopping anything: an image that cannot run')

    no_check = fake_build(scratch + '/no-check', b, helper=(
        '#!/bin/sh\ncase "$*" in *--check*) echo "the ledger refuses" >&2; exit 9 ;; esac\nexec REAL "$@"\n'))
    log = expect_upgrade_refused_or_undone(no_check, 2, 'a refused refresh check', before)
    assert 'the ledger refuses' in log, log
    passed('refused with nothing replaced: the ledger cannot be refreshed')

    # A hostile instance's state: nothing as root follows what it left, and the refusal
    # names it, so the operator can stop that one instance and upgrade the rest.
    planted = '/var/lib/kilnd-t3/kilnd.db-wal'
    entry = pwd.getpwnam('kilnd-t3')
    sh('systemctl', 'stop', 'kilnd@t3.service')
    os.symlink('/etc/shadow', planted)
    os.lchown(planted, entry.pw_uid, entry.pw_gid)
    sh('systemctl', 'start', '--no-block', 'kilnd@t3.service')
    done = script('upgrade.sh', b, check=False)
    assert done.returncode == 2 and 'kilnd-t3' in done.stderr, done.stderr
    os.unlink(planted)
    sh('systemctl', 'stop', 'kilnd@t3.service')
    sh('systemctl', 'reset-failed', 'kilnd@t3.service', check=False)
    sh('systemctl', 'start', 'kilnd@t3.service')
    assert_same_node(before, 'a link planted in an instance\'s state')
    passed('refused with nothing replaced: an instance\'s state holds a planted link')

    # Failures after replacing, each undone.
    no_refresh = fake_build(scratch + '/no-refresh', b, helper=(
        '#!/bin/sh\ncase "$1 $*" in refresh-enrollments*--check*) exec REAL "$@" ;; '
        'refresh-enrollments*) echo "refresh failed" >&2; exit 9 ;; esac\nexec REAL "$@"\n'))
    log = expect_upgrade_refused_or_undone(no_refresh, 1, 'a failed refresh', before)
    assert 'refresh failed' in log, log
    passed('undone: refresh fails after the images were replaced')

    no_init = fake_build(scratch + '/no-init', b, kilnd=(
        '#!/bin/sh\ncase "$1" in init-state) echo "cannot open state" >&2; exit 9 ;; esac\nexec REAL "$@"\n'))
    log = expect_upgrade_refused_or_undone(no_init, 1, 'a state it cannot open', before)
    assert 'cannot open state' in log, log
    passed('undone: the new image cannot open an instance\'s state')

    no_serve = fake_build(scratch + '/no-serve', b, kilnd=(
        '#!/bin/sh\ncase "$1" in init-state|--version) exec REAL "$@" ;; esac\nexit 9\n'))
    log = expect_upgrade_refused_or_undone(no_serve, 1, 'a daemon that will not stay up', before)
    assert 'did not stay up' in log, log
    passed('undone: the new daemon will not start, after every unit was restarted')

    # A new schema the old image couldn't open goes back, and what ran on it is kept.
    def schemas():
        return {u: schema_of(*s) for u, s in (
            ('kilnd.service', ('kilnd', '/var/lib/kilnd')),
            ('kilnd@t1.service', ('kilnd-t1', '/var/lib/kilnd-t1')),
            ('kilnd@t2.service', ('kilnd-t2', '/var/lib/kilnd-t2')),
            ('kilnd@t3.service', ('kilnd-t3', '/var/lib/kilnd-t3')))}
    original = schemas()
    bump = ('"$real" "$@" || exit $?\nsetpriv --reuid="$5" --regid="$5" --clear-groups %s -I -c '
            '"import sqlite3,sys;sqlite3.connect(sys.argv[1]).execute(\'PRAGMA user_version=99\')" '
            '"$3/kilnd.db"\n' % sys.executable)
    migrate_fail = fake_build(scratch + '/migrate-fail', b, kilnd=(
        '#!/bin/sh\nreal=REAL\ncase "$1" in init-state) ' + bump + 'exit 9 ;; esac\nexec "$real" "$@"\n'))
    expect_upgrade_refused_or_undone(migrate_fail, 1, 'a failed schema upgrade', before)
    assert schemas() == original
    assert not os.path.exists(FAILED_DIR), 'nothing had served, so nothing is kept'
    passed('undone: the first instance\'s schema upgrade fails, and that database goes back')

    migrate_serve = fake_build(scratch + '/migrate-serve', b, kilnd=(
        '#!/bin/sh\nreal=REAL\ncase "$1" in init-state) ' + bump + 'exit 0 ;; --version) exec "$real" "$@" ;; esac\nexit 9\n'))
    log = expect_upgrade_refused_or_undone(migrate_serve, 1, 'a schema upgrade, then no service', before)
    assert schemas() == original
    kept = glob.glob(FAILED_DIR + '/*/kilnd@t1.service/kilnd.db')
    assert kept and 'may have served' in log, log
    with open(kept[0], 'rb') as file:
        assert int.from_bytes(file.read(64)[60:64], 'big') == 99, 'that is the newer database'
    shutil.rmtree(FAILED_DIR)
    passed('undone: new schemas that may have served go back, and are kept for inspection')

    slow = fake_build(scratch + '/slow', b, helper=(
        '#!/bin/sh\ncase "$1 $*" in refresh-enrollments*--check*) exec REAL "$@" ;; '
        'refresh-enrollments*) touch %s/slow/at-refresh; sleep 60 ;; esac\nexec REAL "$@"\n' % scratch))
    for signal_number, name in ((signal.SIGTERM, 'SIGTERM'), (signal.SIGINT, 'SIGINT'), (signal.SIGHUP, 'SIGHUP')):
        marker = scratch + '/slow/at-refresh'
        if os.path.exists(marker):
            os.unlink(marker)
        process = subprocess.Popen(
            [sys.executable, '-I', os.path.join(REPO, 'scripts/kilnd-maintenance.py'), 'upgrade',
             '--bin-dir', slow], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 60
        while not os.path.exists(marker) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert os.path.exists(marker), 'the upgrade never reached the refresh'
        process.send_signal(signal_number)
        stderr = process.communicate(timeout=300)[1]
        assert process.returncode == 1, stderr
        assert_same_node(before, 'upgrade interrupted by ' + name)
        passed('undone: %s in the middle of the upgrade' % name)

    # SIGKILL leaves the journal; recover undoes it, and until then nothing can activate.
    marker = scratch + '/slow/at-refresh'
    os.unlink(marker)
    process = subprocess.Popen(
        [sys.executable, '-I', os.path.join(REPO, 'scripts/kilnd-maintenance.py'), 'upgrade',
         '--bin-dir', slow], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 60
    while not os.path.exists(marker) and time.monotonic() < deadline:
        time.sleep(0.05)
    process.kill()
    process.wait()
    kill_slow_helper()
    assert load_state('kilnd-helper.socket') == load_state('kilnd-helper.service') == 'masked'
    assert active('kilnd-helper.socket') != 'active' and not os.path.exists(HELPER_SOCKET)
    assert sha(KILND) != sha(a + '/kilnd'), 'it was killed after replacing'
    refused_start = sh('systemctl', 'start', 'kilnd.service', check=False)
    assert refused_start.returncode != 0, 'a daemon started during an interrupted upgrade'
    script('upgrade.sh', '--recover')
    assert_same_node(before, 'upgrade killed, then recovered')
    passed('undone: SIGKILL in the middle, then --recover; nothing could activate meanwhile')

    # A later upgrade finishes a killed one first, too, and two can't run at once.
    os.unlink(marker)
    process = subprocess.Popen(
        [sys.executable, '-I', os.path.join(REPO, 'scripts/kilnd-maintenance.py'), 'upgrade',
         '--bin-dir', slow], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 60
    while not os.path.exists(marker) and time.monotonic() < deadline:
        time.sleep(0.05)
    second_run = script('upgrade.sh', b, check=False)
    assert second_run.returncode == 2 and 'another maintenance command' in second_run.stderr, second_run.stderr
    passed('one maintenance command at a time')
    process.kill()
    process.wait()
    kill_slow_helper()

    # The real thing: A to B, with both instances and the default.
    busy = hammer(90, 'kilnd-t1')
    script('upgrade.sh', b)
    busy.send_signal(signal.SIGTERM)
    busy.wait()
    version_b = sh(KILND, '--version').stdout.strip()
    assert sha(KILND) == sha(b + '/kilnd') and sha(HELPER) == sha(b + '/kilnd-helper')
    after = with_helper_stopped(rows)
    wanted = image(KILND)
    assert len(after) == len(before['rows'])
    for old, new in zip(before['rows'], after):
        for field in ('instance_id', 'unit', 'cgroup', 'uid', 'gid'):
            assert old[field] == new[field], field
        assert row_image(new) == wanted, new['unit']
        assert row_image(old) != wanted
    assert {u: active(u) in ('active', 'activating') for u in units()} == before['units']
    wait_active('kilnd.service', 'kilnd@t1.service', 'kilnd@t2.service', 'kilnd@t3.service')
    # No instance stayed on the replaced image, which is what B3F-03 saw.
    for unit in old_running:
        dev, ino, path = running_image(unit)
        assert (dev, ino, path) == (wanted[0], wanted[1], KILND), '%s still runs %s' % (unit, path)
    passed('after the upgrade every daemon runs the new inode', 'inode %d -> %d' % (old_inode, wanted[1]))
    for unit, state in (('kilnd@t1.service', '/var/lib/kilnd-t1'), ('kilnd@t2.service', '/var/lib/kilnd-t2'),
                        ('kilnd@t3.service', '/var/lib/kilnd-t3'), ('kilnd.service', '/var/lib/kilnd')):
        proof = attach_proof(unit, state)
        assert proof.startswith('attached '), proof
        passed('after the upgrade: attaches from the new image', '%s: %s' % (unit, proof))
    assert sh(BIN + '/kilndctl', 'health', check=False).returncode == 0
    sandbox_answers(sandbox, 'after the upgrade')
    passed('a live sandbox survives the upgrade', sandbox)
    passed('upgrade %s -> %s, every enrollment refreshed with its binding intact' % (version_a, version_b),
           '%d enrollments' % len(after))

    # Only what was active comes back.
    sh('systemctl', 'stop', 'kilnd@t2.service')
    sh('systemctl', 'reset-failed', 'kilnd@t2.service', check=False)
    was_stopped = with_helper_stopped(rows)
    script('upgrade.sh', a)
    assert active('kilnd@t2.service') in ('inactive', 'failed'), 'it was stopped before the upgrade'
    wait_active('kilnd.service', 'kilnd@t1.service', 'kilnd@t3.service')
    assert sha(KILND) == sha(a + '/kilnd')
    refreshed = with_helper_stopped(rows)
    assert all(row_image(r) == image(KILND) for r in refreshed), 'a stopped instance stays enrolled'
    assert len(refreshed) == len(was_stopped)
    proof = attach_proof('kilnd@t2.service', '/var/lib/kilnd-t2')
    assert proof.startswith('attached '), proof
    sh('systemctl', 'stop', 'kilnd@t2.service')
    passed('upgrade B -> A restarts exactly the active units, and a stopped one is still enrolled')


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--bin-a', required=True)
    parser.add_argument('--bin-b', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        sys.exit('this needs root')
    if os.path.exists(POLICY) or (os.path.isdir(LEDGER) and os.listdir(LEDGER)):
        sys.exit('this node already has a Firecracker policy or ledger; it needs one with neither')
    scratch = tempfile.mkdtemp(prefix='kilnd-deployment-')
    os.chmod(scratch, 0o755)
    try:
        provision_policy()
        stay_attached()
        # The default instance enrolls by the same flow, with --enroll-default.
        done = sh(sys.executable, '-I', os.path.join(REPO, 'scripts/kilnd-maintenance.py'),
                  'upgrade', '--bin-dir', args.bin_a, '--enroll-default')
        out(done.stderr.strip())
        enrolled = with_helper_stopped(rows)
        assert [r['unit'] for r in enrolled] == ['kilnd.service'], enrolled
        assert enrolled[0]['instance_id'] == state_id('kilnd', '/var/lib/kilnd')
        passed('the default instance enrolled with its own durable ID', enrolled[0]['instance_id'])
        deadline = time.monotonic() + 30
        while sh(BIN + '/kilndctl', 'health', check=False).returncode != 0:
            assert time.monotonic() < deadline, 'kilnd never answered'
            time.sleep(0.2)
        sandbox = sh(BIN + '/kilndctl', 'create', '--image', 'alpine').stdout.split()[0]
        SANDBOXES.append(sandbox)
        sandbox_answers(sandbox, 'once created')
        first, second = test_01_identity(args)
        test_02_activation(args, sandbox)
        test_03_upgrade(args, scratch, first, second, sandbox)
    finally:
        cleanup()
        shutil.rmtree(scratch, ignore_errors=True)
    out('ALL PASS')


if __name__ == '__main__':
    main()
