#!/usr/bin/env python3
"""Root's maintenance of a kilnd node. Each command is one transaction.

  add-instance NAME              scripts/add-instance.sh
  upgrade --bin-dir DIR          scripts/upgrade.sh, and scripts/install.sh when configured
  recover                        finishes whatever a killed or crashed command left
  needs-transaction              exit 0 if this node can only be changed by `upgrade`

Enrollment and refreshing need the node lock, which only a stopped helper leaves free,
and every enrolled instance may connect to the helper's socket. So activation is made
impossible first: both activation units are runtime-masked, then stopped along with every
daemon that requires them. A record of what was running lets the end of the window, a signal
or a later `recover` put back exactly that. See docs/setup.md.

File work inside an instance's state directory runs as that instance's account, because
root must not follow what a hostile instance left there.
"""
import argparse
import errno
import fcntl
import glob
import json
import os
import pwd
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

BIN = '/usr/local/bin'
IMAGES = ('kilnd', 'kilnd-helper', 'kilndctl')
SOCKET = 'kilnd-helper.socket'
SERVICE = 'kilnd-helper.service'
ACTIVATION = (SOCKET, SERVICE)
HELPER_SOCKET = '/run/kilnd-helper/helper.sock'
DEFAULT_POLICY = '/etc/kilnd/firecracker-node.json'
DEFAULT_LEDGER_DIR = '/var/lib/kilnd-helper/firecracker'
LOCK = '/run/kilnd-maintenance.lock'
WINDOW_RECORD = '/run/kilnd-maintenance.window.json'
# `systemctl mask --runtime` writes to /run/systemd/system, which /etc/systemd/system outranks,
# so it silently does nothing to a unit installed in /etc. This directory outranks /etc
# (systemd.unit(5)), and like the rest of /run it is gone after a reboot.
MASK_DIR = '/run/systemd/system.control'
# On disk, so a reboot in the middle can still be undone. The images move by rename, which
# keeps the inode enrollment names, so they stay on the installed images' filesystem.
TXN_DIR = '/var/lib/kilnd-helper/upgrade'
JOURNAL = TXN_DIR + '/journal.json'
FAILED_DIR = '/var/lib/kilnd-helper/failed-upgrades'
STAGE = BIN + '/.kilnd-upgrade'
MANAGED_FILES = {
    'kilnd-helper.socket': '/etc/systemd/system/kilnd-helper.socket',
    'kilnd-helper.service': '/etc/systemd/system/kilnd-helper.service',
    'kilnd.service': '/etc/systemd/system/kilnd.service',
    'kilnd@.service': '/etc/systemd/system/kilnd@.service',
    'kilnd-helper.conf': '/etc/tmpfiles.d/kilnd-helper.conf',
}
SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
# How long a restarted default daemon must stay up, and be given, before it counts.
SETTLE_SECONDS = 5
START_SECONDS = 60
PHASES = ('prepared', 'replacing', 'refreshed', 'starting', 'committed')


class Refused(Exception):
    """Nothing was replaced, and the node is as it was."""


class Interrupted(BaseException):
    """A signal, which unwinds like any failure and is not caught by `except Exception`."""


def log(message):
    try:
        print('kilnd-maintenance: ' + message, file=sys.stderr, flush=True)
    except OSError:
        pass


def raise_interrupted(number, _frame):
    raise Interrupted(signal.Signals(number).name)


def catch_signals():
    for number in SIGNALS:
        signal.signal(number, raise_interrupted)
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)


def hold_signals():
    """Nothing interrupts restoring the node. Children inherit this."""
    for number in SIGNALS:
        signal.signal(number, signal.SIG_IGN)


def run(argv, check=True):
    done = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={'PATH': PATH},
        cwd='/',
    )
    if check and done.returncode != 0:
        raise RuntimeError('%s: %s' % (' '.join(argv), done.stderr.strip() or done.returncode))
    return done


def systemctl(*args, check=True):
    return run(('systemctl', *args), check=check)


def unit_state(unit):
    fields = {}
    shown = systemctl(
        'show',
        '--property=LoadState,ActiveState,SubState,UnitFileState,NRestarts',
        unit,
        check=False,
    )
    for line in shown.stdout.splitlines():
        key, _, value = line.partition('=')
        fields[key] = value
    return fields


def is_masked(state):
    return state.get('LoadState') == 'masked'


def mask_runtime(units):
    os.makedirs(MASK_DIR, mode=0o755, exist_ok=True)
    for unit in units:
        path = os.path.join(MASK_DIR, unit)
        if not os.path.islink(path):
            os.symlink('/dev/null', path)
    systemctl('daemon-reload')
    for unit in units:
        if not is_masked(unit_state(unit)):
            raise RuntimeError('%s could not be masked' % unit)


def helper_listening():
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.connect(HELPER_SOCKET)
        return True
    except OSError:
        return False
    finally:
        probe.close()


def unmask_runtime(units):
    for unit in units:
        path = os.path.join(MASK_DIR, unit)
        if os.path.islink(path) and os.readlink(path) == '/dev/null':
            os.unlink(path)
    systemctl('daemon-reload')


def daemon_units():
    """Every configured instance: kilnd.service and kilnd@*, loaded or merely enabled."""
    found = set()
    listed = systemctl(
        'list-units', '--all', '--type=service', '--plain', '--no-legend', '--no-pager',
        'kilnd.service', 'kilnd@*.service', check=False,
    )
    for line in listed.stdout.splitlines():
        found.update(line.split()[:1])
    for link in glob.glob('/etc/systemd/system/*.wants/kilnd*.service'):
        found.add(os.path.basename(link))
    for path in ('/etc/systemd/system/kilnd.service',):
        if os.path.exists(path):
            found.add(os.path.basename(path))
    return sorted(u for u in found if re.fullmatch(r'kilnd(@[a-z0-9]+)?\.service', u))


def instance_of(unit):
    """A standard unit's state directory and account, or None for any other unit."""
    if unit == 'kilnd.service':
        return '/var/lib/kilnd', 'kilnd'
    match = re.fullmatch(r'kilnd@([a-z0-9]+)\.service', unit)
    if match:
        return '/var/lib/kilnd-' + match[1], 'kilnd-' + match[1]
    return None


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_atomic(path, text):
    temporary = '%s.%d.tmp' % (path, os.getpid())
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as file:
        file.write(text)
        file.flush()
        os.fsync(file.fileno())
    os.rename(temporary, path)
    fsync_dir(os.path.dirname(path))


def write_json(path, value):
    write_atomic(path, json.dumps(value, indent=1, sort_keys=True))


def read_json(path):
    with open(path) as file:
        return json.load(file)


def acquire_lock():
    """Maintenance is one command at a time. The kernel drops this when its holder dies, and
    a record it left then tells the next holder there is something to finish."""
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise Refused('another maintenance command is running') from None
    return fd


class Window:
    """The time activation is unavailable. Its record exists before anything changes."""

    def __init__(self):
        self.record = read_json(WINDOW_RECORD) if os.path.exists(WINDOW_RECORD) else None

    def open(self):
        if self.record is None:
            units = {}
            for unit in (*ACTIVATION, *daemon_units()):
                state = unit_state(unit)
                if state.get('LoadState') == 'not-found':
                    continue
                units[unit] = {
                    # A daemon between Restart= attempts is still one that was running.
                    'running': state.get('ActiveState') in ('active', 'activating', 'reloading'),
                    'masked': is_masked(state),
                }
            self.record = {'units': units}
            write_json(WINDOW_RECORD, self.record)
        self.enforce()

    def enforce(self):
        """From the first step on, neither a connection nor a Restart= can start anything:
        a masked socket can't be started, and everything Requires= it. The service is masked
        only once stopped, because masking a live unit discards its loaded settings, and the
        helper's KillMode=process is what keeps running sandboxes alive across its stop.
        Naming the dependents reaches any that are only between restarts."""
        units = self.record['units']
        if SOCKET in units and not units[SOCKET]['masked']:
            mask_runtime([SOCKET])
        names = [*(u for u in ACTIVATION if u in units),
                 *(u for u in units if u not in ACTIVATION)]
        if names:
            systemctl('stop', *names)
        for unit in names:
            active = unit_state(unit).get('ActiveState')
            if active not in ('inactive', 'failed'):
                raise RuntimeError('%s is still %s' % (unit, active))
        if SERVICE in units and not units[SERVICE]['masked']:
            mask_runtime([SERVICE])
        if helper_listening():
            raise RuntimeError('something still listens at ' + HELPER_SOCKET)
        # A masked socket unit no longer knows to remove its file. Starting it makes a new one.
        if os.path.lexists(HELPER_SOCKET):
            os.unlink(HELPER_SOCKET)

    def release(self):
        """Back to what was running: never more, and every unit whatever another's result."""
        errors = []
        units = self.record['units']
        try:
            unmask_runtime([u for u in ACTIVATION if u in units and not units[u]['masked']])
        except (OSError, RuntimeError) as error:
            errors.append('unmask: %s' % error)
        ordered = [*(u for u in ACTIVATION if u in units),
                   *(u for u in units if u not in ACTIVATION)]
        for unit in ordered:
            if not units[unit]['running']:
                continue
            # Refused activations while masked can leave the socket in a failed state.
            systemctl('reset-failed', unit, check=False)
            # Until B7 a kilnd@ daemon stops at startup reconciliation by design, and waiting
            # for it reports that. settle() decides what counts as coming back.
            block = () if unit in (*ACTIVATION, 'kilnd.service') else ('--no-block',)
            done = systemctl('start', *block, unit, check=False)
            if done.returncode != 0:
                errors.append('start %s: %s' % (unit, done.stderr.strip()))
        return errors

    def finish(self):
        if os.path.exists(WINDOW_RECORD):
            os.unlink(WINDOW_RECORD)
        self.record = None

    def running_daemons(self):
        units = self.record['units']
        return [u for u in units if u not in ACTIVATION and units[u]['running']]

    def close(self):
        """Ends a window whose work is over, with nothing able to interrupt it."""
        if self.record is None:
            return []
        hold_signals()
        try:
            errors = self.release()
            self.finish()
        finally:
            catch_signals()
        return errors


# What an instance's account does in its own state directory. It starts from this one
# file, sharing nothing with root but the descriptors named on its command line.
ACCOUNT_CHILD = r'''
import json, os, sqlite3, stat, sys
NAMES = ('kilnd.db', 'kilnd.db-wal', 'kilnd.db-shm', 'kilnd.db-journal')
op, state = sys.argv[1], sys.argv[2]
def path(name): return os.path.join(state, name)
def copy(source, destination):
    while True:
        chunk = os.read(source, 1 << 20)
        if not chunk:
            return
        while chunk:
            chunk = chunk[os.write(destination, chunk):]
def schema():
    if not os.path.lexists(path('kilnd.db')):
        return None
    if not stat.S_ISREG(os.lstat(path('kilnd.db')).st_mode):
        raise SystemExit('kilnd.db is not a regular file')
    db = sqlite3.connect(path('kilnd.db'), timeout=5)
    try:
        return db.execute('PRAGMA user_version').fetchone()[0]
    finally:
        db.close()
if op == 'snapshot':
    # One destination descriptor per name, in order. Nothing here follows a link or
    # blocks on a FIFO a hostile instance left behind.
    copied = []
    for name, destination in zip(NAMES, map(int, sys.argv[3:])):
        if name.endswith('-shm'):
            continue  # SQLite rebuilds it, and it means nothing without the live mapping.
        try:
            source = os.open(path(name), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            continue
        seen = os.fstat(source)
        if not stat.S_ISREG(seen.st_mode) or seen.st_nlink != 1 or seen.st_uid != os.getuid() \
                or seen.st_mode & 0o077:
            raise SystemExit(name + ' is not a private regular file')
        copy(source, destination)
        os.fsync(destination)
        copied.append(name)
    print(json.dumps({'copied': copied, 'schema': schema()}))
elif op == 'restore':
    # One source descriptor per name in the snapshot, in NAMES order.
    names = sys.argv[3].split(',') if sys.argv[3] else []
    for name in NAMES:
        if name not in names:
            try:
                os.unlink(path(name))
            except FileNotFoundError:
                pass
    for name, source in zip(names, map(int, sys.argv[4:])):
        temporary = path(name + '.restore')
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        destination = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        copy(source, destination)
        os.fsync(destination)
        os.close(destination)
        os.replace(temporary, path(name))
    fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
    os.fsync(fd)
elif op == 'schema':
    print(json.dumps({'schema': schema()}))
'''


def as_account(account, op, state, *args, fds=()):
    entry = pwd.getpwnam(account)
    done = subprocess.run(
        [sys.executable, '-I', '-c', ACCOUNT_CHILD, op, state, *map(str, args)],
        user=entry.pw_uid,
        group=entry.pw_gid,
        extra_groups=[],
        umask=0o077,
        pass_fds=fds,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={},
        cwd='/',
    )
    if done.returncode != 0:
        raise RuntimeError('%s in %s: %s' % (op, state, done.stderr.strip()[-400:]))
    return json.loads(done.stdout) if done.stdout.strip() else {}


CHILD_NAMES = ('kilnd.db', 'kilnd.db-wal', 'kilnd.db-shm', 'kilnd.db-journal')


def snapshot_state(account, state, destination):
    os.makedirs(destination, mode=0o700)
    fds = [
        os.open(os.path.join(destination, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        for name in CHILD_NAMES
    ]
    try:
        report = as_account(account, 'snapshot', state, *fds, fds=fds)
    finally:
        for fd in fds:
            os.close(fd)
    for name in CHILD_NAMES:
        if name not in report['copied']:
            os.unlink(os.path.join(destination, name))
    fsync_dir(destination)
    return report


def restore_state(account, state, source):
    names = [n for n in CHILD_NAMES if os.path.exists(os.path.join(source, n))]
    fds = [os.open(os.path.join(source, n), os.O_RDONLY) for n in names]
    try:
        as_account(account, 'restore', state, ','.join(names), *fds, fds=fds)
    finally:
        for fd in fds:
            os.close(fd)


def require_root():
    if os.geteuid() != 0:
        raise Refused('this needs root')


def ledger_files_exist():
    try:
        return any(not name.startswith('.') for name in os.listdir(DEFAULT_LEDGER_DIR))
    except FileNotFoundError:
        return False


def find_policy():
    """The policy the helper is configured with, or the default if one is installed."""
    shown = systemctl('show', '--property=ExecStart', '--value', SERVICE, check=False).stdout
    match = re.search(r'--firecracker-policy[= ](\S+)', shown)
    if match:
        return match[1]
    if os.path.exists(DEFAULT_POLICY):
        return DEFAULT_POLICY
    if ledger_files_exist():
        raise Refused('a Firecracker ledger exists, but no policy names it')
    return None


def needs_transaction():
    return find_policy() is not None or any(u != 'kilnd.service' for u in daemon_units())


def helper_rows(helper, policy):
    done = run((helper, 'enrollments', '--policy', policy))
    return json.loads(done.stdout)


def init_state(kilnd, state, account):
    done = run((kilnd, 'init-state', '--state-dir', state, '--account', account))
    instance = done.stdout.strip()
    if not re.fullmatch(r'[0-9a-f]{32}', instance):
        raise RuntimeError('init-state printed %r' % instance)
    return instance


def enroll(policy, instance, unit, account, cgroup=None):
    """A helper that has just stopped can hold the lock for a moment through a worker, but
    nothing can start another one now, so a short wait here always ends."""
    argv = ['kilnd-helper', 'enroll', '--policy', policy, '--instance', instance,
            '--unit', unit, '--user', account]
    if cgroup:
        argv += ['--cgroup', cgroup]
    argv[0] = os.path.join(BIN, 'kilnd-helper')
    deadline = time.monotonic() + 30
    while True:
        done = run(argv, check=False)
        if done.returncode == 0:
            log(done.stdout.strip())
            return
        if 'stop kilnd-helper' not in done.stderr or time.monotonic() > deadline:
            raise RuntimeError('enroll %s: %s' % (unit, done.stderr.strip()))
        time.sleep(0.2)


def install_file(source, destination, mode):
    temporary = destination + '.kilnd-new'
    shutil.copyfile(source, temporary)
    os.chmod(temporary, mode)
    fd = os.open(temporary, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(temporary, destination)


def provision_default(window, policy):
    """The default instance takes the flow every further one does: init, then enroll that
    ID. It runs only with no enrollment for kilnd.service, and adds nothing if it fails."""
    try:
        window.open()
        rows = helper_rows_retrying(os.path.join(BIN, 'kilnd-helper'), policy)
        if not any(row['unit'] == 'kilnd.service' for row in rows):
            instance = init_state(os.path.join(BIN, 'kilnd'), '/var/lib/kilnd', 'kilnd')
            enroll(policy, instance, 'kilnd.service', 'kilnd')
            log('default instance %s enrolled' % instance)
    finally:
        errors = window.close()
    if errors:
        raise RuntimeError('; '.join(errors))


def cmd_add_instance(args):
    name = args.name
    if not re.fullmatch(r'[a-z0-9]{1,16}', name):
        raise Refused('the name must be 1 to 16 lowercase letters and digits')
    lock = acquire_lock()
    finish_interrupted()
    for path in (os.path.join(BIN, 'kilnd'), os.path.join(BIN, 'kilnd-helper')):
        if not os.path.exists(path):
            raise Refused('run scripts/install.sh first')
    if run(('getent', 'group', 'kilnd-helper'), check=False).returncode != 0:
        raise Refused('run scripts/install.sh first')
    policy = find_policy()
    if policy is None:
        raise Refused('this node has no Firecracker policy; see docs/setup.md')
    user = 'kilnd-' + name
    unit = 'kilnd@%s.service' % name
    if run(('getent', 'group', user), check=False).returncode != 0:
        run(('groupadd', '--system', user))
    if run(('getent', 'passwd', user), check=False).returncode != 0:
        run(('useradd', '--system', '--gid', user, '--home-dir', '/nonexistent',
             '--shell', '/usr/sbin/nologin', user))
    install_file(os.path.join(args.deploy_dir, 'kilnd@.service'),
                 MANAGED_FILES['kilnd@.service'], 0o644)
    systemctl('daemon-reload')
    window = Window()
    try:
        window.open()
        instance = init_state(os.path.join(BIN, 'kilnd'), '/var/lib/' + user, user)
        # A template instance's cgroup sits in the slice systemd makes for that template.
        enroll(policy, instance, unit, user, cgroup='/system.slice/system-kilnd.slice/' + unit)
        # Only an enrolled account has any business reaching the helper's socket.
        run(('usermod', '-a', '-G', 'kilnd-helper', user))
    finally:
        errors = window.close()
    if errors:
        raise RuntimeError('; '.join(errors))
    systemctl('enable', '--quiet', unit)
    # Enrolled and enabled: whether it stays up says nothing about this command. See release.
    systemctl('start', '--no-block', unit)
    log('instance %s is %s, enrolled as %s' % (name, unit, instance))
    print(instance)
    os.close(lock)


def stage_images(bin_dir):
    """New images go through a root-only directory on the installed images' filesystem, so
    replacing them is a rename and a broken one is refused while everything is still up."""
    shutil.rmtree(STAGE, ignore_errors=True)
    for part in ('', '/new', '/old', '/tool'):
        os.mkdir(STAGE + part, 0o700)
    for image in IMAGES:
        source = os.path.join(bin_dir, image)
        meta = os.lstat(source)
        if not stat.S_ISREG(meta.st_mode):
            raise Refused(source + ' is not a regular file')
        install_file(source, os.path.join(STAGE, 'new', image), 0o755)
        fsync_dir(os.path.join(STAGE, 'new'))
        done = run((os.path.join(STAGE, 'new', image), '--version'), check=False)
        if done.returncode != 0:
            raise Refused('%s does not run: %s' % (source, done.stderr.strip()))
    # Outlives the rename, so a failure at any later point can still restore the ledger.
    install_file(os.path.join(STAGE, 'new/kilnd-helper'), os.path.join(STAGE, 'tool/kilnd-helper'), 0o755)


def image_identity(path):
    meta = os.stat(path)
    return meta.st_dev, meta.st_ino, meta.st_size


def row_image(row):
    image = row['executable']
    return image['st_dev'], image['st_ino'], image['bytes']


def binding(row):
    return tuple(row[k] for k in ('instance_id', 'unit', 'cgroup', 'uid', 'gid'))


def enrolled_instances(rows):
    """Where each enrollment's state lives. A hand-made binding can't be refreshed safely."""
    found = {}
    for row in rows:
        instance = instance_of(row['unit'])
        if instance is None:
            raise Refused('%s is enrolled, and this upgrade only knows kilnd.service and kilnd@*'
                          % row['unit'])
        try:
            entry = pwd.getpwnam(instance[1])
        except KeyError:
            raise Refused('%s is enrolled, but account %s is gone' % (row['unit'], instance[1])) from None
        if (entry.pw_uid, entry.pw_gid) != (row['uid'], row['gid']):
            raise Refused('%s is enrolled under another UID than %s now has'
                          % (row['unit'], instance[1]))
        found[row['unit']] = row['instance_id']
    return found


def cmd_upgrade(args):
    lock = acquire_lock()
    finish_interrupted()
    policy = find_policy()
    os.makedirs(os.path.dirname(TXN_DIR), mode=0o700, exist_ok=True)
    try:
        stage_images(args.bin_dir)
    except BaseException:
        shutil.rmtree(STAGE, ignore_errors=True)
        raise
    # Exists only with the stage complete, and always holds a journal before the window.
    os.mkdir(TXN_DIR, 0o700)
    window = Window()
    journal = None
    try:
        window.open()
        journal = {
            'phase': 'prepared',
            'policy': policy,
            'prior': window.record['units'],
            'started': False,
            'had_image': {i: os.path.exists(os.path.join(BIN, i)) for i in IMAGES},
            'files': {},
            'instances': {},
            'rows': None,
        }
        write_json(JOURNAL, journal)
        upgrade_transaction(args, journal, window)
    except BaseException as failure:
        if journal is None and os.path.exists(TXN_DIR):
            journal = {'phase': 'prepared', 'policy': policy, 'prior': (window.record or {}).get('units', {}),
                       'started': False, 'had_image': {}, 'files': {}, 'instances': {}, 'rows': None}
        complete = rollback(journal, window)
        if not complete:
            log('the rollback is incomplete: fix what it reported, then run scripts/upgrade.sh --recover')
            raise SystemExit(3) from failure
        if isinstance(failure, Refused):
            raise
        if isinstance(failure, Interrupted):
            log('interrupted by %s; the previous images and state are back' % failure)
            raise SystemExit(1) from failure
        log('the upgrade failed and was undone: %s' % failure)
        raise SystemExit(1) from failure
    # Committed. Past this point there is nothing to undo.
    hold_signals()
    shutil.rmtree(STAGE, ignore_errors=True)
    shutil.rmtree(TXN_DIR, ignore_errors=True)
    catch_signals()
    log('upgraded %d enrollments; %s running again' %
        (len(journal['rows'] or []), ', '.join(journal['restarted']) or 'nothing'))
    if args.enroll_default and policy is not None and not any(
            row['unit'] == 'kilnd.service' for row in journal['rows'] or []):
        provision_default(Window(), policy)
    os.close(lock)


def set_phase(journal, phase):
    journal['phase'] = phase
    write_json(JOURNAL, journal)


def upgrade_transaction(args, journal, window):
    policy = journal['policy']
    tool = os.path.join(STAGE, 'tool/kilnd-helper')
    new_kilnd = os.path.join(STAGE, 'new/kilnd')
    installed_kilnd = os.path.join(BIN, 'kilnd')
    # Everything that can refuse does so here, with nothing replaced.
    rows = []
    enrolled = {}
    if policy is not None:
        rows = helper_rows_retrying(tool, policy)
        enrolled = enrolled_instances(rows)
        run_refusing((tool, 'refresh-enrollments', '--check', '--policy', policy, '--kilnd', new_kilnd))
        write_json(TXN_DIR + '/enrollments.json', rows)
        journal['rows'] = rows
    running = window.running_daemons()
    for unit in running:
        instance = instance_of(unit)
        if instance is None:
            raise Refused('%s is running, and this upgrade only knows kilnd.service and kilnd@*' % unit)
        state, account = instance
        try:
            pwd.getpwnam(account)
        except KeyError:
            raise Refused('%s is running, but account %s is gone' % (unit, account)) from None
        if not os.path.isdir(state):
            if unit in enrolled:
                raise Refused('%s is enrolled, but %s is missing' % (unit, state))
            continue
        destination = os.path.join(TXN_DIR, 'state', unit)
        os.makedirs(os.path.dirname(destination), mode=0o700, exist_ok=True)
        try:
            report = snapshot_state(account, state, destination)
        except (OSError, RuntimeError) as error:
            raise Refused('cannot keep a copy of %s: %s' % (state, error)) from None
        journal['instances'][unit] = {
            'state': state,
            'account': account,
            'schema': report['schema'],
            'snapshot': destination,
        }
    os.mkdir(TXN_DIR + '/files', 0o700)
    for name, path in MANAGED_FILES.items():
        if not os.path.exists(os.path.join(args.deploy_dir, name)):
            raise Refused('%s is missing %s' % (args.deploy_dir, name))
        kept = None
        if os.path.exists(path):
            kept = os.path.join(TXN_DIR, 'files', name)
            shutil.copy2(path, kept)
        journal['files'][path] = kept
    set_phase(journal, 'replacing')

    for image in IMAGES:
        installed = os.path.join(BIN, image)
        if os.path.exists(installed):
            os.rename(installed, os.path.join(STAGE, 'old', image))
        os.rename(os.path.join(STAGE, 'new', image), installed)
    fsync_dir(BIN)
    fsync_dir(os.path.join(STAGE, 'old'))
    for name, path in MANAGED_FILES.items():
        install_file(os.path.join(args.deploy_dir, name), path, 0o644)
    systemctl('daemon-reload')
    run(('systemd-tmpfiles', '--create', MANAGED_FILES['kilnd-helper.conf']), check=False)

    if policy is not None:
        run((os.path.join(BIN, 'kilnd-helper'), 'refresh-enrollments', '--policy', policy,
             '--kilnd', installed_kilnd))
        refreshed = helper_rows(os.path.join(BIN, 'kilnd-helper'), policy)
        wanted = image_identity(installed_kilnd)
        if [binding(r) for r in refreshed] != [binding(r) for r in rows]:
            raise RuntimeError('refreshing changed an enrollment binding')
        stale = [r['unit'] for r in refreshed if row_image(r) != wanted]
        if stale:
            raise RuntimeError('refreshing left %s on another image' % ', '.join(stale))
    set_phase(journal, 'refreshed')

    # With every instance still down, the new image proves it can open each one's state.
    # Any schema upgrade happens here, before a client or a reconciliation can see it.
    for unit, kept in journal['instances'].items():
        instance = init_state(installed_kilnd, kept['state'], kept['account'])
        if unit in enrolled and enrolled[unit] != instance:
            raise RuntimeError('%s is enrolled as %s, but its state says %s'
                               % (unit, enrolled[unit], instance))

    journal['started'] = True
    set_phase(journal, 'starting')
    errors = window.release()
    if errors:
        raise RuntimeError('; '.join(errors))
    settle(running)
    journal['restarted'] = running
    set_phase(journal, 'committed')
    window.finish()


def helper_rows_retrying(helper, policy):
    """Refuses, rather than fails: this runs before anything is replaced."""
    deadline = time.monotonic() + 30
    while True:
        done = run((helper, 'enrollments', '--policy', policy), check=False)
        if done.returncode == 0:
            return json.loads(done.stdout)
        if 'stop kilnd-helper' not in done.stderr or time.monotonic() > deadline:
            raise Refused('cannot read the enrollments: ' + done.stderr.strip())
        time.sleep(0.2)


def run_refusing(argv):
    done = run(argv, check=False)
    if done.returncode != 0:
        raise Refused(done.stderr.strip() or 'refused')


def settle(running):
    """The default instance serves, so it must stay up and answer. A kilnd@ daemon stops at
    startup reconciliation by design until B7, then gives up, so its state proves nothing
    yet: its start was requested, init-state has already proved the image opens its state,
    and its enrollment was checked against the installed image. B7 must require those to
    stay up here too."""
    if 'kilnd.service' not in running:
        return
    deadline = time.monotonic() + START_SECONDS
    steady_since = None
    while True:
        state = unit_state('kilnd.service')
        if state.get('ActiveState') == 'active' and state.get('SubState') == 'running':
            restarts = state.get('NRestarts')
            if steady_since is None or steady_since[1] != restarts:
                steady_since = (time.monotonic(), restarts)
            elif time.monotonic() - steady_since[0] >= SETTLE_SECONDS:
                if run((os.path.join(BIN, 'kilndctl'), 'health'), check=False).returncode == 0:
                    return
        else:
            steady_since = None
        if time.monotonic() > deadline:
            raise RuntimeError('kilnd.service did not stay up: ' + json.dumps(state))
        time.sleep(0.25)


def rollback(journal, window):
    """Undoes an upgrade from whatever point it reached. Safe to repeat. A step that fails
    keeps the journal and the window so `recover` can try again; nothing unenrolled or
    half-installed starts in the meantime."""
    hold_signals()
    errors = []
    if journal is None:
        journal = {'phase': 'prepared', 'prior': (window.record or {}).get('units', {}),
                   'files': {}, 'instances': {}, 'rows': None, 'policy': None,
                   'had_image': {}, 'started': False}
    def attempt(what, action):
        try:
            action()
        except Exception as error:  # pylint: disable=broad-except
            errors.append('%s: %s' % (what, error))
            log('rollback: %s: %s' % (what, error))
    if window.record is None and journal.get('prior'):
        window.record = {'units': journal['prior']}
        attempt('record the window', lambda: write_json(WINDOW_RECORD, window.record))
    if window.record is not None:
        attempt('stop everything', window.enforce)
    phase = journal.get('phase', 'prepared')
    replaced = PHASES.index(phase) >= PHASES.index('replacing')
    if replaced:
        def restore_files():
            for path, kept in journal['files'].items():
                if kept is None:
                    if os.path.exists(path):
                        os.unlink(path)
                else:
                    temporary = path + '.kilnd-old'
                    shutil.copy2(kept, temporary)
                    os.rename(temporary, path)
            systemctl('daemon-reload')
        attempt('restore unit files', restore_files)

        def restore_images():
            for image in IMAGES:
                old = os.path.join(STAGE, 'old', image)
                installed = os.path.join(BIN, image)
                if os.path.exists(old):
                    os.replace(old, installed)
                elif not journal['had_image'].get(image, True) and os.path.exists(installed):
                    os.unlink(installed)
            fsync_dir(BIN)
        attempt('restore images', restore_images)

        if journal.get('rows') is not None and journal.get('policy'):
            def restore_ledger():
                run((os.path.join(STAGE, 'tool/kilnd-helper'), 'restore-enrollments',
                     '--policy', journal['policy'], '--snapshot', TXN_DIR + '/enrollments.json'))
            attempt('restore enrollments', restore_ledger)

        for unit, kept in journal['instances'].items():
            attempt('restore the state of ' + unit,
                    lambda u=unit, k=kept: restore_instance(u, k, journal.get('started')))
    if errors:
        return False
    errors.extend(window.release() if window.record is not None else [])
    if errors:
        for error in errors:
            log('rollback: ' + error)
    window.finish()
    shutil.rmtree(STAGE, ignore_errors=True)
    shutil.rmtree(TXN_DIR, ignore_errors=True)
    return True


def restore_instance(unit, kept, started):
    """Only a schema the old image can't open is put back. Otherwise the database in place
    is the newer truth, and replacing it could forget a reservation made since. If a daemon
    served in between, what it wrote is kept for inspection instead of being lost silently."""
    current = None
    try:
        current = as_account(kept['account'], 'schema', kept['state'])['schema']
    except (OSError, RuntimeError, KeyError) as error:
        log('rollback: reading %s: %s' % (kept['state'], error))
    if current == kept['schema']:
        return
    if started:
        os.makedirs(FAILED_DIR, mode=0o700, exist_ok=True)
        aside = tempfile.mkdtemp(prefix=time.strftime('%Y%m%dT%H%M%S-'), dir=FAILED_DIR)
        aside = os.path.join(aside, unit)
        snapshot_state(kept['account'], kept['state'], aside)
        log('%s had a newer schema, and may have served: what it held is in %s' % (unit, aside))
    restore_state(kept['account'], kept['state'], kept['snapshot'])


def finish_interrupted():
    """Whatever a killed command left, before anything new starts."""
    if os.path.exists(JOURNAL):
        journal = read_json(JOURNAL)
        window = Window()
        if journal['phase'] == 'committed':
            log('finishing a committed upgrade')
            window.finish()
            shutil.rmtree(STAGE, ignore_errors=True)
            shutil.rmtree(TXN_DIR, ignore_errors=True)
            return
        log('undoing an interrupted upgrade')
        complete = rollback(journal, window)
        catch_signals()
        if not complete:
            raise SystemExit(3)
        return
    if os.path.exists(TXN_DIR) or os.path.exists(STAGE):
        # Stopped before its journal existed, so nothing had been replaced.
        window = Window()
        if window.record is not None:
            log('restoring what was running before an interrupted upgrade')
            window.enforce()
            for error in window.close():
                log(error)
        shutil.rmtree(STAGE, ignore_errors=True)
        shutil.rmtree(TXN_DIR, ignore_errors=True)
        return
    window = Window()
    if window.record is not None:
        log('restoring what was running before an interrupted command')
        window.enforce()
        for error in window.close():
            log(error)


def cmd_recover(_args):
    lock = acquire_lock()
    finish_interrupted()
    log('nothing is left to recover')
    os.close(lock)


def main():
    repo = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest='command', required=True)
    add = commands.add_parser('add-instance')
    add.add_argument('name')
    add.add_argument('--deploy-dir', default=os.path.join(repo, 'deploy'))
    add.set_defaults(run=cmd_add_instance)
    upgrade = commands.add_parser('upgrade')
    upgrade.add_argument('--bin-dir', required=True)
    upgrade.add_argument('--deploy-dir', default=os.path.join(repo, 'deploy'))
    upgrade.add_argument('--enroll-default', action='store_true')
    upgrade.set_defaults(run=cmd_upgrade)
    commands.add_parser('recover').set_defaults(run=cmd_recover)
    commands.add_parser('needs-transaction').set_defaults(
        run=lambda _: sys.exit(0 if needs_transaction() else 1))
    args = parser.parse_args()
    os.umask(0o077)
    catch_signals()
    try:
        require_root()
        args.run(args)
    except Refused as refusal:
        log('refused, nothing changed: %s' % refusal)
        sys.exit(2)
    except Interrupted as interruption:
        log('interrupted by %s' % interruption)
        sys.exit(1)
    except (OSError, RuntimeError) as error:
        log(str(error))
        sys.exit(1)


if __name__ == '__main__':
    main()
