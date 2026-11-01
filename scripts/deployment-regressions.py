#!/usr/bin/env python3
"""Installed-service regressions for the deployment scripts, in the Lima VM, as root. This
stops every instance, repeatedly, so don't run it on a node you care about.

  sudo python3 -I scripts/deployment-regressions.py --bin-a DIR --bin-b DIR

A reboot here is simulated, by clearing /run and starting units as boot would. A real one is
two steps, and the VM reboots between them, in the middle of an upgrade:

  sudo python3 -I scripts/deployment-regressions.py --bin-a DIR --bin-b DIR --reboot-arm POINT
  sudo python3 -I scripts/deployment-regressions.py --reboot-verify

POINT is `graceful`, a `systemctl reboot` while an upgrade waits at its refresh, or a step as
in CRASH_HARNESS, such as rename:3, at which the upgrade itself reboots with no sync at all.

DIR holds kilnd, kilnd-helper and kilndctl, and the two must be different builds. The node
must have kilnd installed from --bin-a, by scripts/install.sh, and no Firecracker policy or
ledger: this makes its own and removes them, with its accounts, whatever happens. It adds no
manifest or profile, so production Firecracker stays disabled throughout. It covers B3F-01,
B3F-02 and B3F-03 from reviews/2026-11-01-b3-final.md, including every way an upgrade can fail,
and B3D-01 and B3D-02 from reviews/2026-11-01-b3-deploy-recheck.md: a reboot at every step of a
maintenance command, and restores that fail.
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
WINDOW_RECORD = '/var/lib/kilnd-helper/maintenance.json'
LOCK = '/run/kilnd-maintenance.lock'
MASK_DIR = '/run/systemd/system.control'
GUARD = 'kilnd-maintenance-guard.service'
FINISH = 'kilnd-maintenance-finish.service'
MAINTENANCE = os.path.join(REPO, 'scripts/kilnd-maintenance.py')
RECOVERY_REQUIRED = 3
# Survives the reboot in a real reboot test, with what that test compares against afterwards.
REBOOT_DIR = '/var/lib/kilnd-reboot-test'
REBOOT_STAY_ATTACHED = '/etc/systemd/system/kilnd@.service.d/90-stay-attached.conf'
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


def binding(row):
    return tuple(row[k] for k in ('instance_id', 'unit', 'cgroup', 'uid', 'gid'))


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
    # A boot recovery a failed test left going would start what this is about to remove.
    sh('systemctl', 'stop', FINISH, check=False)
    script('upgrade.sh', '--recover', check=False)
    for sandbox in SANDBOXES:
        sh(BIN + '/kilndctl', 'rm', sandbox, check=False)
    shutil.rmtree(STAY_ATTACHED, ignore_errors=True)
    shutil.rmtree(os.path.dirname(REBOOT_STAY_ATTACHED), ignore_errors=True)
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


# The maintenance script, unchanged but for dying at exactly one step, as a power failure would:
# nothing it has not already made durable can be counted on. `reboot:` does it with a real
# reboot and no sync. fail-unmask: makes every unmask fail, with no crash at all.
CRASH_HARNESS = r"""
import importlib.util, os, signal, subprocess, sys, time
script, point = sys.argv[1], sys.argv[2]
sys.argv = [script, *sys.argv[3:]]
spec = importlib.util.spec_from_file_location('kilnd_maintenance', script)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
how, _, rest = point.partition('/')
if rest:
    point = rest
def die():
    if how == 'reboot':
        subprocess.run(['systemctl', 'reboot', '--force', '--force'])
        time.sleep(600)
    os.kill(os.getpid(), signal.SIGKILL)
def after(name, when=lambda *a, **k: True):
    real = getattr(m, name)
    def wrapped(*args, **kwargs):
        result = real(*args, **kwargs)
        if when(*args, **kwargs):
            die()
        return result
    setattr(m, name, wrapped)
def nth(number):
    seen = [0]
    def counted(*_args, **_kwargs):
        seen[0] += 1
        return seen[0] == int(number)
    return counted
kind, _, number = point.partition(':')
if kind == 'marker':
    after('write_json', lambda path, _v: path == m.WINDOW_RECORD)
elif kind == 'masked':
    after('mask_runtime')
elif kind == 'journal':
    after('write_json', lambda path, _v: path == m.JOURNAL)
elif kind == 'phase':
    after('set_phase', lambda _j, phase: phase == number)
elif kind == 'rename':
    after('rename_durably', nth(number))
elif kind == 'unit-file':
    after('install_file', lambda _s, destination, _m: destination in m.MANAGED_FILES.values())
elif kind == 'migrated':
    after('init_state', nth(number))
elif kind == 'settling':
    def dying(*_args, **_kwargs):
        die()
    m.settle = dying
elif kind == 'discarded':
    after('discard_transaction')
elif kind == 'enrolled':
    after('enroll')
elif kind == 'fail-unmask':
    def refuse(_units):
        raise RuntimeError('injected unmask failure')
    m.unmask_runtime = refuse
else:
    raise SystemExit('no such step: ' + point)
m.main()
"""


def harness(point, *argv, wait=True):
    command = [sys.executable, '-I', '-c', CRASH_HARNESS, MAINTENANCE, point, *argv]
    if not wait:
        return subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
    return subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                          timeout=600, check=False)


def crash(point, *argv):
    done = harness(point, *argv)
    assert done.returncode == -signal.SIGKILL, '%s: exit %d, never reached it:\n%s' % (
        point, done.returncode, done.stderr)
    assert os.path.exists(WINDOW_RECORD), point + ': no marker on disk'


def down_as_after_a_reboot():
    """Everything a reboot takes away: every process, every mask, the rest of /run."""
    names = [*units(), GUARD, FINISH]
    sh('systemctl', 'stop', *names, check=False)
    for path in glob.glob(MASK_DIR + '/kilnd-helper.*'):
        os.unlink(path)
    for path in (LOCK, HELPER_SOCKET):
        if os.path.lexists(path):
            os.unlink(path)
    sh('systemctl', 'daemon-reload')
    sh('systemctl', 'reset-failed', *names, check=False)
    for unit in names:
        assert active(unit) in ('inactive', 'failed'), unit + ' survived the reboot'
    assert load_state('kilnd-helper.socket') == load_state('kilnd-helper.service') == 'loaded'


def enabled_units():
    return [u for u in units() if sh('systemctl', 'is-enabled', u, check=False).stdout.strip() == 'enabled']


def monotonic_stamp(unit, prop):
    return int(sh('systemctl', 'show', '--property=' + prop, '--value', unit).stdout.strip() or 0)


def boot_as_after_a_reboot():
    """One transaction, as boot queues it. All that orders it is what the units declare, and
    while the guard runs nothing behind it may have got past."""
    sh('systemctl', 'start', '--no-block', *enabled_units(), FINISH)
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        guard = active(GUARD)
        if guard in ('active', 'failed'):
            return guard
        if guard == 'activating':
            for unit in units():
                state = active(unit)
                # It only counts if the guard was still running after that was seen.
                if state not in ('inactive', 'failed') and active(GUARD) == 'activating':
                    raise AssertionError('%s is %s behind the guard' % (unit, state))
        time.sleep(0.01)
    raise AssertionError('the guard never finished')


def guard_came_first():
    done = monotonic_stamp(GUARD, 'ExecMainExitTimestampMonotonic')
    assert done, 'the guard did not run'
    for unit in ('kilnd-helper.socket', 'kilnd.service'):
        started = monotonic_stamp(unit, 'ActiveEnterTimestampMonotonic')
        assert started >= done, '%s started %d, the guard finished %d' % (unit, started, done)


def wait_marker_gone():
    deadline = time.monotonic() + 180
    while (os.path.exists(WINDOW_RECORD) or active(FINISH) == 'activating') and time.monotonic() < deadline:
        time.sleep(0.1)
    assert not os.path.exists(WINDOW_RECORD), 'the marker is still there: ' + sh(
        'journalctl', '-u', FINISH, '-n', '20', '--no-pager', '-o', 'cat').stdout


def reboot_and_recover(what):
    down_as_after_a_reboot()
    guard = boot_as_after_a_reboot()
    assert guard == 'active', '%s: guard %s:\n%s' % (what, guard, sh(
        'journalctl', '-u', GUARD, '-n', '20', '--no-pager', '-o', 'cat').stdout)
    # Only now has boot's own start of each happened, and each stamp is this boot's.
    wait_marker_gone()
    guard_came_first()


def fail_start(unit):
    directory = '/run/systemd/system/%s.d' % unit
    os.makedirs(directory, exist_ok=True)
    with open(directory + '/90-fail-start.conf', 'w') as file:
        file.write('[Service]\nExecStartPre=/bin/false\n')
    sh('systemctl', 'daemon-reload')
    return directory


def expect_recovery_required(done, what, journal):
    assert done.returncode == RECOVERY_REQUIRED, '%s: exit %d, wanted %d:\n%s' % (
        what, done.returncode, RECOVERY_REQUIRED, done.stderr)
    assert os.path.exists(WINDOW_RECORD), what + ': the record went'
    assert os.path.exists(JOURNAL) == journal, what + ': journal'
    assert os.path.exists(STAGE) == journal, what + ': stage'


def test_04_failed_restores(args, scratch):
    """B3D-02: a restore that fails keeps what it needs, until a retry puts everything back."""
    out('--- B3D-02')
    before = snapshot_node()
    no_refresh = fake_build(scratch + '/no-refresh', args.bin_b, helper=(
        '#!/bin/sh\ncase "$1 $*" in refresh-enrollments*--check*) exec REAL "$@" ;; '
        'refresh-enrollments*) echo "refresh failed" >&2; exit 9 ;; esac\nexec REAL "$@"\n'))
    add = ('add-instance', 't3')
    upgrade = ('upgrade', '--bin-dir', no_refresh)
    for command, journal, name in ((add, False, 'add-instance'), (upgrade, True, 'upgrade rollback')):
        done = harness('fail-unmask', *command)
        expect_recovery_required(done, name + ', unmask', journal)
        assert 'injected unmask failure' in done.stderr, done.stderr
        assert load_state('kilnd-helper.socket') == 'masked', 'nothing lifted it, so nothing starts'
        script('upgrade.sh', '--recover')
        assert_same_node(before, name + ', unmask retried')
        passed('%s: an unmask failure keeps its record, and --recover finishes it' % name)
        for unit, what in (('kilnd-helper.service', 'helper'), ('kilnd.service', 'daemon')):
            directory = fail_start(unit)
            try:
                done = sh(sys.executable, '-I', MAINTENANCE, *command, check=False, timeout=600)
                expect_recovery_required(done, '%s, %s start' % (name, what), journal)
                assert unit in done.stderr, done.stderr
                record = json.load(open(WINDOW_RECORD, encoding='utf-8'))
                assert record['stage'] == 'restored', record
                # Still failing, and still kept.
                again = script('upgrade.sh', '--recover', check=False)
                expect_recovery_required(again, '%s, %s retried too early' % (name, what), journal)
            finally:
                shutil.rmtree(directory)
                sh('systemctl', 'daemon-reload')
            script('upgrade.sh', '--recover')
            assert_same_node(before, '%s, %s start retried' % (name, what))
            passed('%s: a %s start failure keeps its record, and --recover finishes it' % (name, what))


def test_05_reboot(args, scratch):
    """B3D-01: a reboot at any step, with the masks gone, opens nothing until recovery is done."""
    out('--- B3D-01')
    a, b = args.bin_a, args.bin_b
    for unit in (GUARD, FINISH):
        done = sh('systemd-analyze', 'verify', '/etc/systemd/system/' + unit, check=False)
        assert 'cycle' not in done.stderr + done.stdout, done.stderr
    passed('the guard and finish units verify, with no ordering cycle')
    # A unit that ran but isn't enabled comes back too: boot wouldn't, and the record says so.
    sh('systemctl', 'disable', 'kilnd@t3.service')
    # And one that's stopped and not enabled stays stopped. A stopped, enabled one starts, as at
    # any boot.
    sh('systemctl', 'disable', 'kilnd@t2.service')
    before = snapshot_node()
    assert before['units']['kilnd@t3.service']
    upgrade = ('upgrade', '--bin-dir', b)
    for point in ('marker:', 'masked:', 'journal:', 'phase:replacing', 'rename:1', 'rename:2', 'rename:3',
                  'rename:4', 'rename:5', 'rename:6', 'unit-file:', 'phase:refreshed', 'migrated:1',
                  'migrated:2', 'phase:starting', 'settling:'):
        crash(point, *upgrade)
        reboot_and_recover(point)
        assert_same_node(before, 'reboot at ' + point)
        passed('reboot at %s of an upgrade: nothing started before the guard, and all is back' % point)

    for point in ('phase:committed', 'discarded:'):
        crash(point, *upgrade)
        reboot_and_recover(point)
        assert sha(KILND) == sha(b + '/kilnd'), point + ': it had committed'
        assert not os.path.exists(JOURNAL) and not os.path.exists(STAGE)
        assert all(active(u) in ('active', 'activating') for u, was in before['units'].items() if was)
        # A new upgrade, so new inodes, with the same bindings and exactly the same units.
        script('upgrade.sh', a)
        assert sha(KILND) == sha(a + '/kilnd')
        after = snapshot_node()
        assert after['units'] == before['units'], after['units']
        assert [binding(r) for r in after['rows']] == [binding(r) for r in before['rows']]
        before = after
        passed('reboot at %s of an upgrade: it stays committed, and the marker goes last' % point)

    for point in ('marker:', 'masked:', 'enrolled:'):
        crash(point, 'add-instance', 't3')
        reboot_and_recover(point)
        assert_same_node(before, 'add-instance reboot at ' + point)
        passed('reboot at %s of add-instance: all is back' % point)

    # A schema the old image can't open: serving on it is prevented, and it goes back.
    bump = ('"$real" "$@" || exit $?\nsetpriv --reuid="$5" --regid="$5" --clear-groups %s -I -c '
            '"import sqlite3,sys;sqlite3.connect(sys.argv[1]).execute(\'PRAGMA user_version=99\')" '
            '"$3/kilnd.db"\n' % sys.executable)
    migrating = fake_build(scratch + '/migrate-reboot', b, kilnd=(
        '#!/bin/sh\nreal=REAL\ncase "$1" in init-state) ' + bump + 'exit 0 ;; --version) exec "$real" "$@" ;; esac\n'
        'exec "$real" "$@"\n'))
    wanted = schema_of('kilnd', '/var/lib/kilnd')
    crash('migrated:2', 'upgrade', '--bin-dir', migrating)
    assert schema_of('kilnd', '/var/lib/kilnd') == 99 or schema_of('kilnd-t1', '/var/lib/kilnd-t1') == 99
    reboot_and_recover('between migrations')
    assert schema_of('kilnd', '/var/lib/kilnd') == wanted
    assert schema_of('kilnd-t1', '/var/lib/kilnd-t1') == schema_of('kilnd-t2', '/var/lib/kilnd-t2')
    assert not os.path.exists(FAILED_DIR), 'nothing had served, so nothing is kept'
    assert_same_node(before, 'reboot between migrations')
    passed('reboot between two migrations: both go back, and nothing had served')
    crash('settling:', 'upgrade', '--bin-dir', migrating)
    reboot_and_recover('after migrating and starting')
    assert schema_of('kilnd', '/var/lib/kilnd') == wanted
    assert glob.glob(FAILED_DIR + '/*/*/kilnd.db'), 'what may have served is kept'
    shutil.rmtree(FAILED_DIR)
    assert_same_node(before, 'reboot once started')
    passed('reboot once started on a new schema: it goes back, and what it held is kept')

    # Recovery that can't finish: down it all stays, by the guard alone, until an operator's retry.
    no_restore = fake_build(scratch + '/no-restore', b, helper=(
        '#!/bin/sh\ncase "$1" in restore-enrollments) echo "restore failed" >&2; exit 9 ;; esac\n'
        'exec REAL "$@"\n'))
    crash('phase:refreshed', 'upgrade', '--bin-dir', no_restore)
    down_as_after_a_reboot()
    guard = boot_as_after_a_reboot()
    assert guard == 'failed', guard
    deadline = time.monotonic() + 30
    while active(FINISH) == 'activating' and time.monotonic() < deadline:
        time.sleep(0.1)
    time.sleep(1)
    for unit in units():
        assert active(unit) in ('inactive', 'failed'), '%s is %s with the guard failed' % (unit, active(unit))
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.connect(HELPER_SOCKET)
        raise AssertionError('the helper socket listens with the guard failed')
    except OSError:
        pass
    finally:
        probe.close()
    assert sh('systemctl', 'start', 'kilnd-helper.socket', check=False).returncode != 0
    assert sh('systemctl', 'start', 'kilnd.service', check=False).returncode != 0
    assert os.path.exists(WINDOW_RECORD) and os.path.exists(JOURNAL)
    passed('a guard that cannot recover fails, and the socket and every daemon stay down')
    shutil.copy2(a + '/kilnd-helper', STAGE + '/tool/kilnd-helper')
    script('upgrade.sh', '--recover')
    assert_same_node(before, 'recovered by hand after a failed guard')
    passed('--recover finishes it after a failed guard, and activation opens')

    # A unit that won't start at the end of a boot's recovery leaves the marker.
    crash('rename:3', *upgrade)
    directory = fail_start('kilnd.service')
    try:
        down_as_after_a_reboot()
        assert boot_as_after_a_reboot() == 'active'
        deadline = time.monotonic() + 120
        while active(FINISH) != 'failed' and time.monotonic() < deadline:
            time.sleep(0.2)
        assert active(FINISH) == 'failed', active(FINISH)
        assert os.path.exists(WINDOW_RECORD) and os.path.exists(JOURNAL), 'its retry state went'
    finally:
        shutil.rmtree(directory)
        sh('systemctl', 'daemon-reload')
    script('upgrade.sh', '--recover')
    assert_same_node(before, 'a failed start after a boot recovery')
    passed('a start that fails after boot recovery keeps the marker for --recover')

    # A node whose units are from before the guard is fenced before its first upgrade changes it.
    plain = {}
    for name in ('kilnd-helper.socket', 'kilnd-helper.service', 'kilnd.service', 'kilnd@.service'):
        path = '/etc/systemd/system/' + name
        with open(path, encoding='utf-8') as file:
            plain[path] = file.read()
        stripped = ''.join(l.replace(' ' + GUARD, '') for l in plain[path].splitlines(True)
                           if l != 'Requires=' + GUARD + '\n')
        assert GUARD not in stripped, name
        with open(path, 'w', encoding='utf-8') as file:
            file.write(stripped)
    sh('systemctl', 'daemon-reload')
    older = snapshot_node()
    crash('rename:3', *upgrade)
    shown = sh('systemctl', 'show', '--property=Requires,After', 'kilnd.service').stdout
    assert shown.count(GUARD) == 2, shown
    reboot_and_recover('a first upgrade from before the guard')
    assert_same_node(older, 'a first upgrade from before the guard')
    shown = sh('systemctl', 'show', '--property=Requires,After', 'kilnd.service').stdout
    assert shown.count(GUARD) == 2, 'its rollback took the guard away: ' + shown
    passed('reboot during a first upgrade from units older than the guard, and they keep it')
    for path, text in plain.items():
        with open(path, 'w', encoding='utf-8') as file:
            file.write(text)
    sh(sys.executable, '-I', MAINTENANCE, 'install-fence')
    assert not glob.glob('/etc/systemd/system/*.d/10-maintenance-guard.conf')
    sh('systemctl', 'daemon-reload')
    assert_same_node(before, 'units restored')


def reboot_arm(args):
    """Up to the point of rebooting, with what verification needs kept on disk."""
    point = args.reboot_arm
    if os.path.exists(POLICY) or (os.path.isdir(LEDGER) and os.listdir(LEDGER)):
        sys.exit('this node already has a Firecracker policy or ledger; it needs one with neither')
    shutil.rmtree(REBOOT_DIR, ignore_errors=True)
    os.makedirs(REBOOT_DIR, mode=0o755)
    assert sha(KILND) == sha(args.bin_a + '/kilnd')
    provision_policy()
    # In /etc this time, because /run won't still have it.
    os.makedirs(os.path.dirname(REBOOT_STAY_ATTACHED), exist_ok=True)
    with open(REBOOT_STAY_ATTACHED, 'w', encoding='utf-8') as file:
        file.write('[Service]\nExecStart=\nExecStart=%s check-attachment '
                   '--state-dir /var/lib/kilnd-%%i --hold\n' % KILND)
    sh('systemctl', 'daemon-reload')
    sh(sys.executable, '-I', MAINTENANCE, 'upgrade', '--bin-dir', args.bin_a, '--enroll-default')
    script('add-instance.sh', 't1')
    script('add-instance.sh', 't2')
    wait_active('kilnd.service', 'kilnd@t1.service', 'kilnd@t2.service')
    sh('systemctl', 'disable', 'kilnd@t2.service')  # Running, not enabled: the marker's to restore.
    before = snapshot_node()
    with open(REBOOT_DIR + '/before.json', 'w', encoding='utf-8') as file:
        json.dump({'node': before, 'point': point,
                   'boot': open('/proc/sys/kernel/random/boot_id', encoding='utf-8').read().strip()}, file)
    build = fake_build(REBOOT_DIR + '/build', args.bin_b, helper=(
        '#!/bin/sh\ncase "$1 $*" in refresh-enrollments*--check*) exec REAL "$@" ;; '
        'refresh-enrollments*) touch %s/at-refresh; sleep 600 ;; esac\nexec REAL "$@"\n' % REBOOT_DIR))
    os.sync()
    if point == 'graceful':
        sh('systemd-run', '--unit=kilnd-reboot-test-upgrade', '--collect', sys.executable, '-I', MAINTENANCE,
           'upgrade', '--bin-dir', build)
        deadline = time.monotonic() + 120
        while not os.path.exists(REBOOT_DIR + '/at-refresh'):
            assert time.monotonic() < deadline, 'the upgrade never reached the refresh'
            time.sleep(0.05)
        assert sha(KILND) != sha(args.bin_a + '/kilnd'), 'it should have replaced the images'
        out('at the refresh, images replaced, journal %s' % json.load(open(JOURNAL, encoding='utf-8'))['phase'])
        subprocess.Popen(['systemctl', 'reboot'], start_new_session=True)
        return
    # The harness reboots with no sync, at that step.
    harness('reboot/' + point, 'upgrade', '--bin-dir', args.bin_b, wait=True)
    raise AssertionError('still here after the step: ' + point)


def reboot_verify():
    with open(REBOOT_DIR + '/before.json', encoding='utf-8') as file:
        saved = json.load(file)
    before = saved['node']
    before['images'] = {name: tuple(identity) for name, identity in before['images'].items()}
    boot = open('/proc/sys/kernel/random/boot_id', encoding='utf-8').read().strip()
    assert boot != saved['boot'], 'this is the same boot'
    try:
        deadline = time.monotonic() + 300
        while active(GUARD) == 'activating' and time.monotonic() < deadline:
            time.sleep(0.2)
        guard_log = sh('journalctl', '-b', '-u', GUARD, '--no-pager', '-o', 'short-monotonic').stdout
        out(guard_log.strip())
        assert active(GUARD) == 'active', 'guard %s' % active(GUARD)
        wait_marker_gone()
        guard_came_first()
        passed('the guard ran this boot and finished before the socket and daemon started')
        finish_log = sh('journalctl', '-b', '-u', FINISH, '--no-pager', '-o', 'short-monotonic').stdout
        out(finish_log.strip())
        log = sh('journalctl', '-b', '--no-pager', '-o', 'cat').stdout
        assert 'ordering cycle' not in log.lower() or 'kilnd' not in log.lower().split('ordering cycle')[1][:200]
        before['units'] = {u: v for u, v in before['units'].items() if u in units()}
        assert_same_node(before, 'a real reboot at ' + saved['point'])
        deadline = time.monotonic() + 30
        while sh(BIN + '/kilndctl', 'health', check=False).returncode != 0:
            assert time.monotonic() < deadline, 'kilnd never answered'
            time.sleep(0.2)
        passed('a real reboot at %s: same images, enrollments, units and state' % saved['point'])
    finally:
        cleanup()
        shutil.rmtree(REBOOT_DIR, ignore_errors=True)
    out('ALL PASS')


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--bin-a')
    parser.add_argument('--bin-b')
    parser.add_argument('--reboot-arm')
    parser.add_argument('--reboot-verify', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        sys.exit('this needs root')
    if args.reboot_verify:
        reboot_verify()
        return
    if not args.bin_a or not args.bin_b:
        parser.error('--bin-a and --bin-b are required')
    if args.reboot_arm:
        reboot_arm(args)
        return
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
        test_04_failed_restores(args, scratch)
        test_05_reboot(args, scratch)
    finally:
        cleanup()
        shutil.rmtree(scratch, ignore_errors=True)
    out('ALL PASS')


if __name__ == '__main__':
    main()
