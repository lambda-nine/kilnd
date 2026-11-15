#!/usr/bin/env python3
"""Root's maintenance of a kilnd node. Each command is one transaction.

  add-instance NAME              scripts/add-instance.sh
  upgrade --bin-dir DIR          scripts/upgrade.sh, and scripts/install.sh when configured
  recover                        finishes whatever a killed or crashed command left
  recover --boot                 kilnd-maintenance-guard.service's half of that, at boot
  install-fence                  installs the boot guard, for scripts/install.sh
  needs-transaction              exit 0 if this node can only be changed by `upgrade`

  accept-artifacts               after reconciling an exit 3's checkpoint artifacts, starts kilnd

Exit status: 0 done, 1 failed and undone, 2 refused with nothing changed, 3 recovery required
or rolled back with changed checkpoint artifacts. Incomplete rollbacks keep a record for
`recover`. Changed artifacts keep one too, and kilnd stopped, until `accept-artifacts`.

Enrollment and refreshing need the node lock, which only a stopped helper leaves free,
and every enrolled instance may connect to the helper's socket. So activation is made
impossible first: both activation units are runtime-masked, then stopped along with every
daemon that requires them. A durable record of what was running exists before any of that. It
lets the end of the window, a signal or a later `recover` put back exactly that, and while it
exists after a reboot, which clears the masks, the boot guard keeps every unit down until the
node is whole again. See docs/setup.md.

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
# The persistent maintenance marker and the window's record, in one fsynced file. It is written
# before anything changes and removed last. Its stage is 'open' while anything may be half done,
# which keeps the boot guard failing, and 'restored' once only starting units is left.
WINDOW_RECORD = '/var/lib/kilnd-helper/maintenance.json'
# `systemctl mask --runtime` writes to /run/systemd/system, which /etc/systemd/system outranks,
# so it silently does nothing to a unit installed in /etc. This directory outranks /etc
# (systemd.unit(5)), and like the rest of /run it is gone after a reboot, when the boot guard
# (deploy/kilnd-maintenance-guard.service) takes over from it.
MASK_DIR = '/run/systemd/system.control'
# On disk, so a reboot in the middle can still be undone. The images move by rename, which
# keeps the inode enrollment names, so they stay on the installed images' filesystem.
TXN_DIR = '/var/lib/kilnd-helper/upgrade'
JOURNAL = TXN_DIR + '/journal.json'
FAILED_DIR = '/var/lib/kilnd-helper/failed-upgrades'
CHECKPOINTS_ROOT = '/var/lib/kiln/runs/.checkpoints'
REGISTRY_UID = 0
INSPECT_DIR = '/run'
# Where every standard instance keeps its state, whether or not a unit or enrollment names it.
STATE_PARENT = '/var/lib'
PROC = '/proc'
MOUNTINFO = '/proc/self/mountinfo'
STAGE = BIN + '/.kilnd-upgrade'
MANAGED_FILES = {
    'kilnd-helper.socket': '/etc/systemd/system/kilnd-helper.socket',
    'kilnd-helper.service': '/etc/systemd/system/kilnd-helper.service',
    'kilnd.service': '/etc/systemd/system/kilnd.service',
    'kilnd@.service': '/etc/systemd/system/kilnd@.service',
    'kilnd-helper.conf': '/etc/tmpfiles.d/kilnd-helper.conf',
}
# Not part of an upgrade's transaction: they go in before one starts, stay through its rollback,
# and are what recovers it. A unit installed by an older build gets the guard from a drop-in.
FENCE_DIR = '/usr/local/libexec/kilnd'
FENCE_TOOLS = ('kilnd-maintenance.py', 'upgrade.sh')
GUARD = 'kilnd-maintenance-guard.service'
FENCE_UNITS = (GUARD, 'kilnd-maintenance-finish.service')
GUARDED_UNITS = ('kilnd-helper.socket', 'kilnd-helper.service', 'kilnd.service', 'kilnd@.service')
UNIT_DIR = '/etc/systemd/system'
SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
# How long a restarted default daemon must stay up, and be given, before it counts.
SETTLE_SECONDS = 5
START_SECONDS = 60
PHASES = ('prepared', 'replacing', 'refreshed', 'starting', 'committed')
RECOVERY_REQUIRED = 3


class Refused(Exception):
    """Nothing was replaced, and the node is as it was."""


class RecoveryRequired(Exception):
    """Something could not be put back. Its record is kept, for `recover` to try again."""


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
    for unit in units:
        if is_masked(unit_state(unit)):
            raise RuntimeError('%s is still masked' % unit)


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
        return os.path.join(STATE_PARENT, 'kilnd'), 'kilnd'
    match = re.fullmatch(r'kilnd@([a-z0-9]+)\.service', unit)
    if match:
        return os.path.join(STATE_PARENT, 'kilnd-' + match[1]), 'kilnd-' + match[1]
    return None


def standard_instances():
    """Every standard state directory's unit, configured, enrolled or neither. The helper's own
    directory is not an instance's. A standard name that isn't a plain directory is refused."""
    found = []
    with os.scandir(STATE_PARENT) as entries:
        for entry in entries:
            if entry.name == 'kilnd':
                unit = 'kilnd.service'
            elif entry.name.startswith('kilnd-') and entry.name != 'kilnd-helper' \
                    and re.fullmatch(r'[a-z0-9]{1,16}', entry.name[6:]):
                unit = 'kilnd@%s.service' % entry.name[6:]
            else:
                continue
            if not entry.is_dir(follow_symlinks=False):
                raise Refused('%s is not a directory' % entry.path)
            found.append(unit)
    return sorted(found)


def holds_checkpoint_schema(state):
    """Whether a state directory root can't inspect as its account may hold checkpoints. Root
    reads only the database header, never through SQLite. Anything unclear counts as yes."""
    database = os.path.join(state, 'kilnd.db')
    if not os.path.lexists(database):
        return False
    try:
        fd = os.open(database, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return True  # a link, or nothing root can read
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return True
        header = os.read(fd, 100)
    finally:
        os.close(fd)
    # A WAL can carry a migration, or the whole database, that the main file doesn't show yet.
    wal = database + '-wal'
    if os.path.lexists(wal):
        meta = os.lstat(wal)
        if not stat.S_ISREG(meta.st_mode) or meta.st_size:
            return True
    if not header:
        return False
    if len(header) < 64 or not header.startswith(b'SQLite format 3\x00'):
        return True
    return int.from_bytes(header[60:64], 'big') >= 15


def account_processes(uid):
    """Every process with uid as its real, effective, saved or filesystem UID."""
    try:
        names = os.listdir(PROC)
    except OSError as error:
        raise Refused('cannot list processes in %s: %s' % (PROC, error)) from None
    found = []
    for name in names:
        if not name.isdigit():
            continue
        try:
            with open(os.path.join(PROC, name, 'status'), 'rb') as file:
                lines = file.read().splitlines()  # bytes: a process names itself
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError as error:
            raise Refused('cannot read %s/%s/status: %s' % (PROC, name, error)) from None
        uids = next((line.split()[1:5] for line in lines if line.startswith(b'Uid:')), None)
        if uids is None:
            raise Refused('%s/%s/status has no Uid line' % (PROC, name))
        if str(uid).encode() in uids:
            found.append(int(name))
    return sorted(found)


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


def make_private_dir(path):
    """A directory a reboot must still find, with the entry that names it durable too."""
    if not os.path.isdir(path):
        os.makedirs(path, mode=0o700, exist_ok=True)
        fsync_dir(os.path.dirname(path))


def make_public_dir(path):
    """Like any directory of the system's, whatever this process's own umask makes of it."""
    if not os.path.isdir(path):
        previous = os.umask(0o022)
        try:
            os.makedirs(path, mode=0o755, exist_ok=True)
        finally:
            os.umask(previous)
        fsync_dir(os.path.dirname(path))


def copy_durably(source, destination):
    temporary = destination + '.kilnd-copy'
    shutil.copy2(source, temporary)
    fd = os.open(temporary, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(temporary, destination)
    fsync_dir(os.path.dirname(destination))


def rename_durably(source, destination):
    os.rename(source, destination)
    fsync_dir(os.path.dirname(source))
    fsync_dir(os.path.dirname(destination))


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
    """The time activation is unavailable. Its record exists before anything changes, and
    outlasts the masks: whatever a failure or a reboot left, it says what to put back."""

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
            self.record = {'units': units, 'stage': 'open'}
            make_private_dir(os.path.dirname(WINDOW_RECORD))
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

    def require_down(self):
        """At boot the guard's ordering holds every unit back, and stopping them would cancel
        the starts boot has queued. This only proves that nothing got past it."""
        for unit in sorted({*self.record['units'], *ACTIVATION, *daemon_units()}):
            active = unit_state(unit).get('ActiveState')
            if active not in (None, '', 'inactive', 'failed'):
                raise RuntimeError('%s is %s during recovery' % (unit, active))
        if helper_listening():
            raise RuntimeError('something still listens at ' + HELPER_SOCKET)

    def mark_restored(self):
        """The node is whole. Only starting units is left, so the guard may let them start."""
        if self.record.get('stage') != 'restored':
            self.record['stage'] = 'restored'
            write_json(WINDOW_RECORD, self.record)

    def release(self, restored=True):
        """Back to what was running: never more, and every unit whatever another's result.
        restored=False is an upgrade starting its new images, which can still be undone."""
        errors = []
        units = self.record['units']
        if restored:
            try:
                self.mark_restored()
            except OSError as error:
                errors.append('record: %s' % error)
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
        """Last of all, and only with everything it recorded put back."""
        if os.path.exists(WINDOW_RECORD):
            os.unlink(WINDOW_RECORD)
            fsync_dir(os.path.dirname(WINDOW_RECORD))
        self.record = None

    def running_daemons(self):
        units = self.record['units']
        return [u for u in units if u not in ACTIVATION and units[u]['running']]

    def close(self):
        """Ends a window whose work is over, with nothing able to interrupt it. Any error keeps
        the record, and the masks it could not lift, for `recover` to try again."""
        if self.record is None:
            return []
        hold_signals()
        try:
            errors = self.release()
            if not errors:
                errors = settled(self.running_daemons())
            if not errors:
                self.finish()
        finally:
            catch_signals()
        return errors


def close_window(window):
    errors = window.close()
    if errors:
        for error in errors:
            log('restore: ' + error)
        raise RecoveryRequired('; '.join(errors))


# What an instance's account does in its own state directory. It starts from this one
# file, sharing nothing with root but the descriptors named on its command line.
ACCOUNT_CHILD = r'''
import json, os, sqlite3, stat, sys, tempfile
from urllib.parse import quote
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
    # One destination descriptor, for kilnd.db: one SQLite backup, which reads the database and
    # its WAL in one read transaction, so the copy is one snapshot whatever a writer does. Every
    # file SQLite will open is checked first: nothing here follows a link or blocks on a FIFO a
    # hostile instance left behind. A hot journal or any SQLite error fails the copy.
    destination = int(sys.argv[3])
    if not os.path.lexists(path('kilnd.db')):
        print(json.dumps({'copied': []}))
        raise SystemExit(0)
    for name in NAMES:
        try:
            source = os.open(path(name), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            continue
        seen = os.fstat(source)
        os.close(source)
        if not stat.S_ISREG(seen.st_mode) or seen.st_nlink != 1 or seen.st_uid != os.getuid() \
                or seen.st_mode & 0o077:
            raise SystemExit(name + ' is not a private regular file')
    src = sqlite3.connect('file:' + quote(path('kilnd.db')) + '?mode=ro', uri=True, timeout=5)
    try:
        if hasattr(sqlite3.Connection, 'serialize'):
            dst = sqlite3.connect(':memory:')
            # An in-memory destination can't change its page size during the backup.
            dst.execute('PRAGMA page_size = %d' % src.execute('PRAGMA page_size').fetchone()[0])
            src.backup(dst)
            data = dst.serialize()
            dst.close()
        else:
            with tempfile.TemporaryDirectory() as scratch:
                dst = sqlite3.connect(os.path.join(scratch, 'kilnd.db'))
                src.backup(dst)
                dst.close()
                with open(os.path.join(scratch, 'kilnd.db'), 'rb') as file:
                    data = file.read()
    finally:
        src.close()
    if data[:16] != b'SQLite format 3\x00':
        raise SystemExit('the copy of kilnd.db is not a database')
    while data:
        data = data[os.write(destination, data):]
    os.fsync(destination)
    print(json.dumps({'copied': ['kilnd.db']}))
elif op == 'restore':
    # One source descriptor per name in the snapshot, in NAMES order, never kilnd.db-shm.
    # Every file is staged and synced first, then what the snapshot lacks goes (and the shm
    # always), then the database and its WAL are renamed in. Root's journal marks the restore
    # until the directory is synced, so a crash anywhere in here is met by doing it all again.
    names = sys.argv[3].split(',') if sys.argv[3] else []
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
    for name in NAMES:
        if name not in names:
            try:
                os.unlink(path(name))
            except FileNotFoundError:
                pass
    for name in names:
        os.replace(path(name + '.restore'), path(name))
    fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
    os.fsync(fd)
elif op == 'checkpoints':
    # The copy of the snapshot root made, and holds open, in a directory only root can change:
    # never the live state, which another process of this account may have replaced since.
    held, seen = os.fstat(int(sys.argv[3])), os.lstat(path('kilnd.db'))
    if not stat.S_ISREG(held.st_mode) or (held.st_dev, held.st_ino) != (seen.st_dev, seen.st_ino):
        raise SystemExit('kilnd.db is not the snapshot root holds')
    result = {'instance': None, 'busy': []}
    db = sqlite3.connect('file:' + quote(path('kilnd.db')) + '?mode=ro', uri=True, timeout=5)
    try:
        result['schema'] = db.execute('PRAGMA user_version').fetchone()[0]
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        result['has_checkpoints'] = 'checkpoints' in tables
        if 'daemon_identity' in tables:
            row = db.execute('SELECT instance_id FROM daemon_identity WHERE id = 1').fetchone()
            result['instance'] = row[0] if row else None
        if result['schema'] >= 15 and 'checkpoints' in tables:
            # The early check. kilnd's BUSY_CHECKPOINTS_SQL, the same predicate (the store
            # tests run both), decides inside init-state's migration transaction.
            # BEGIN checkpoint-busy SQL
            sql = """SELECT c.id, CASE WHEN c.state IN ('capturing', 'deleting')
                THEN c.state ELSE 'fork pin' END AS kind FROM checkpoints AS c
                WHERE c.state IN ('capturing', 'deleting') OR EXISTS (
                    SELECT 1 FROM checkpoint_pins AS p
                    WHERE p.checkpoint_id = c.id AND p.released_at_ms IS NULL)
                ORDER BY c.id"""
            # END checkpoint-busy SQL
            result['busy'] = [{'id': r[0], 'kind': r[1]} for r in db.execute(sql)]
    finally:
        db.close()
    print(json.dumps(result))
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
    """kilnd.db as one SQLite snapshot, WAL included, made by the account. The upgrade's copy
    for its busy query and rollback, and a rollback's copy of what a newer schema held."""
    os.makedirs(destination, mode=0o700)
    target = os.path.join(destination, 'kilnd.db')
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        report = as_account(account, 'snapshot', state, fd, fds=(fd,))
    finally:
        os.close(fd)
    if 'kilnd.db' not in report['copied']:
        os.unlink(target)
    fsync_dir(destination)
    return report


def restore_state(account, state, source):
    """The snapshot's files in place of the live ones. An old journal's snapshot can hold a
    WAL; its shm is never restored, as SQLite rebuilds one."""
    names = [n for n in CHILD_NAMES
             if n != 'kilnd.db-shm' and os.path.exists(os.path.join(source, n))]
    fds = [os.open(os.path.join(source, n), os.O_RDONLY) for n in names]
    try:
        as_account(account, 'restore', state, ','.join(names), *fds, fds=fds)
    finally:
        for fd in fds:
            os.close(fd)


def inspect_snapshot(account, snapshot):
    """The busy query and identity read, parsed as the instance's account, from a copy of the
    snapshot in a directory of root's that the account may enter but not change. SQLite reads a
    WAL from a directory it can't write only with the -wal and -shm files already there."""
    if not os.path.exists(os.path.join(snapshot, 'kilnd.db')):
        return {'instance': None, 'busy': [], 'schema': None}
    gid = pwd.getpwnam(account).pw_gid
    query = tempfile.mkdtemp(prefix='kilnd-inspect.', dir=INSPECT_DIR)
    try:
        for name in ('kilnd.db', 'kilnd.db-wal', 'kilnd.db-shm'):
            target = os.path.join(query, name)
            if name != 'kilnd.db-shm' and os.path.exists(os.path.join(snapshot, name)):
                shutil.copyfile(os.path.join(snapshot, name), target)
            else:
                open(target, 'xb').close()
            os.chown(target, 0, gid)
            os.chmod(target, 0o440)
        os.chown(query, 0, gid)
        os.chmod(query, 0o750)
        fd = os.open(os.path.join(query, 'kilnd.db'), os.O_RDONLY | os.O_NOFOLLOW)
        try:
            return as_account(account, 'checkpoints', query, fd, fds=(fd,))
        finally:
            os.close(fd)
    finally:
        shutil.rmtree(query, ignore_errors=True)


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
    return (os.path.exists(WINDOW_RECORD) or os.path.exists(JOURNAL) or find_policy() is not None
            or any(u != 'kilnd.service' for u in daemon_units()))


def helper_rows(helper, policy):
    done = run((helper, 'enrollments', '--policy', policy))
    return json.loads(done.stdout)


BUSY_EXIT = 75  # kilnd init-state --refuse-busy-checkpoints found busy checkpoints


def init_state(kilnd, state, account, unit=None):
    """With unit, the upgrade's form: init-state refuses busy checkpoints itself, inside the
    migration's transaction, which is what keeps the upgrade off a busy row; the scans are
    only the early guard."""
    argv = (kilnd, 'init-state', '--state-dir', state, '--account', account)
    done = run(argv + ('--refuse-busy-checkpoints',) if unit else argv, check=not unit)
    if unit and done.returncode == BUSY_EXIT:
        busy = [line.split(' ', 2)[1:] for line in done.stdout.splitlines()
                if line.startswith('busy ') and line.count(' ') >= 2]
        raise RuntimeError('%s has %d busy checkpoints, so its state was not upgraded: %s'
                           % (unit, len(busy), ', '.join('%s (%s)' % (i, k) for i, k in busy[:5])))
    if unit and done.returncode != 0:
        raise RuntimeError('%s failed: %s' % (' '.join(argv), done.stderr.strip()))
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
    fsync_dir(os.path.dirname(destination))


def install_fence(deploy_dir):
    """The boot guard goes in before the first marker that needs it, as a copy of this script
    on root's own filesystem, so that a node can recover before anything else is mounted. An
    installed unit from before the guard gets the dependency from a drop-in, which stays through
    a rollback to that unit and goes once the unit carries it itself."""
    here = os.path.dirname(os.path.realpath(__file__))
    for name in FENCE_UNITS:
        if not os.path.exists(os.path.join(deploy_dir, name)):
            raise Refused('%s is missing %s' % (deploy_dir, name))
    for name in FENCE_TOOLS:
        if not os.path.exists(os.path.join(here, name)):
            raise Refused('%s is missing %s' % (here, name))
    make_private_dir(os.path.dirname(WINDOW_RECORD))
    make_public_dir(FENCE_DIR)
    for name in FENCE_TOOLS:
        if os.path.realpath(os.path.join(FENCE_DIR, name)) != os.path.join(here, name):
            install_file(os.path.join(here, name), os.path.join(FENCE_DIR, name), 0o755)
    fsync_dir(os.path.dirname(FENCE_DIR))
    for name in FENCE_UNITS:
        install_file(os.path.join(deploy_dir, name), os.path.join(UNIT_DIR, name), 0o644)
    for unit in GUARDED_UNITS:
        installed = os.path.join(UNIT_DIR, unit)
        directory = installed + '.d'
        dropin = os.path.join(directory, '10-maintenance-guard.conf')
        carries = False
        if os.path.exists(installed):
            with open(installed) as file:
                carries = GUARD in file.read()
        if os.path.exists(installed) and not carries:
            make_public_dir(directory)
            write_atomic(dropin, '[Unit]\nRequires=%s\nAfter=%s\n' % (GUARD, GUARD))
            os.chmod(dropin, 0o644)
            fsync_dir(UNIT_DIR)
        elif os.path.exists(dropin):
            os.unlink(dropin)
            fsync_dir(directory)
    systemctl('daemon-reload')
    systemctl('enable', '--quiet', *FENCE_UNITS)
    for target in ('sockets.target', 'multi-user.target'):
        wants = os.path.join(UNIT_DIR, target + '.wants')
        if os.path.isdir(wants):
            fsync_dir(wants)
    fsync_dir(UNIT_DIR)
    # With nothing to recover this passes at once, and stays active until the next boot, so a
    # window's own starts don't wait on it.
    systemctl('start', GUARD)


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
    except BaseException as failure:
        log('enrolling the default instance failed: %s' % failure)
        close_window(window)
        raise
    close_window(window)


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
    install_fence(args.deploy_dir)
    window = Window()
    try:
        window.open()
        if run(('getent', 'group', user), check=False).returncode != 0:
            run(('groupadd', '--system', user))
        if run(('getent', 'passwd', user), check=False).returncode != 0:
            run(('useradd', '--system', '--gid', user, '--home-dir', '/nonexistent',
                 '--shell', '/usr/sbin/nologin', user))
        install_file(os.path.join(args.deploy_dir, 'kilnd@.service'),
                     MANAGED_FILES['kilnd@.service'], 0o644)
        systemctl('daemon-reload')
        instance = init_state(os.path.join(BIN, 'kilnd'), '/var/lib/' + user, user)
        # A template instance's cgroup sits in the slice systemd makes for that template.
        enroll(policy, instance, unit, user, cgroup='/system.slice/system-kilnd.slice/' + unit)
        # Only an enrolled account has any business reaching the helper's socket.
        run(('usermod', '-a', '-G', 'kilnd-helper', user))
    except BaseException as failure:
        log('add-instance failed: %s' % failure)
        close_window(window)
        raise
    close_window(window)
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
        fsync_dir(os.path.dirname(STAGE + part))
    for image in IMAGES:
        source = os.path.join(bin_dir, image)
        meta = os.lstat(source)
        if not stat.S_ISREG(meta.st_mode):
            raise Refused(source + ' is not a regular file')
        install_file(source, os.path.join(STAGE, 'new', image), 0o755)
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
    make_private_dir(os.path.dirname(TXN_DIR))
    try:
        stage_images(args.bin_dir)
        install_fence(args.deploy_dir)
    except BaseException:
        shutil.rmtree(STAGE, ignore_errors=True)
        raise
    # Exists only with the stage complete, and always holds a journal before the window.
    os.mkdir(TXN_DIR, 0o700)
    fsync_dir(os.path.dirname(TXN_DIR))
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
        try:
            complete = rollback(journal, window)
        except RecoveryRequired:
            log('the upgrade failed: %s' % failure)
            raise
        if not complete:
            log('the upgrade failed: %s' % failure)
            raise RecoveryRequired('the rollback is incomplete: fix what it reported, '
                                   'then run scripts/upgrade.sh --recover') from failure
        if isinstance(failure, Refused):
            raise
        if isinstance(failure, Interrupted):
            log('interrupted by %s; the previous images and state are back' % failure)
            raise SystemExit(1) from failure
        log('the upgrade failed and was undone: %s' % failure)
        raise SystemExit(1) from failure
    # Committed, durably. Past this point there is nothing to undo, and the marker goes last.
    hold_signals()
    discard_transaction()
    window.finish()
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
    # Every configured or enrolled instance's checkpoints are checked, running or not, and so
    # are those of a standard state directory nothing names any more; only the running ones
    # are snapshotted for the rollback, migrated and started again.
    configured = {u for u in window.record['units'] if u not in ACTIVATION}
    for unit in sorted({*configured, *enrolled, *standard_instances()}):
        instance = instance_of(unit)
        if instance is None:
            if unit in running:
                raise Refused('%s is running, and this upgrade only knows kilnd.service and '
                              'kilnd@*' % unit)
            continue
        state, account = instance
        if unit not in running and not os.path.isdir(state):
            continue
        try:
            entry = pwd.getpwnam(account)
        except KeyError:
            if unit in configured or unit in enrolled:
                raise Refused('%s is %s, but account %s is gone' % (
                    unit, 'running' if unit in running else 'configured', account)) from None
            if holds_checkpoint_schema(state):
                raise Refused('%s holds kilnd state of schema 15 or later, but account %s is '
                              'gone, so it cannot be inspected safely; restore the account or '
                              'move the directory aside, and retry' % (state, account)) from None
            continue
        if not os.path.isdir(state):
            if unit in enrolled:
                raise Refused('%s is enrolled, but %s is missing' % (unit, state))
            continue
        # KillMode=process: a stopped unit doesn't prove that nothing of its account still runs,
        # and a surviving writer could change the state between the copy and the migration.
        # A guard, not a fence: nothing stops the account starting a process after a scan, so
        # it scans again before replacing and before starting, and init-state's own check is
        # what keeps the migration off a busy row.
        pids = account_processes(entry.pw_uid)
        if pids:
            raise Refused('%s is stopped, but %d processes still run as %s: pids %s; stop them '
                          'and retry' % (unit, len(pids), account, ', '.join(map(str, pids[:10]))))
        destination = os.path.join(TXN_DIR, 'state' if unit in running else 'inspected', unit)
        os.makedirs(os.path.dirname(destination), mode=0o700, exist_ok=True)
        try:
            snapshot_state(account, state, destination)
        except (OSError, RuntimeError) as error:
            raise Refused('cannot keep a copy of %s: %s' % (state, error)) from None
        try:
            checkpoints = inspect_snapshot(account, destination)
        except (OSError, RuntimeError) as error:
            raise Refused('cannot inspect the checkpoints of %s: %s' % (unit, error)) from None
        if checkpoints['busy']:
            busy = checkpoints['busy']
            raise Refused('%s has %d busy checkpoints: %s; start kilnd, let those checkpoints '
                          'settle (kilndctl checkpoint ls), and retry'
                          % (unit, len(busy), ', '.join('%s (%s)' % (c['id'], c['kind'])
                                                       for c in busy[:5])))
        identity, expected = checkpoints['instance'], enrolled.get(unit)
        if identity is not None and expected is not None and identity != expected:
            raise Refused('%s is enrolled as %s, but its state says %s'
                          % (unit, expected, identity))
        if unit not in running:
            continue
        # The identity comes from the snapshot or the enrollment, never from the live state.
        checkpointed = (checkpoints['schema'] or 0) >= 15 and checkpoints.get('has_checkpoints')
        if identity is None and checkpointed:
            if expected is not None:
                raise Refused('%s is enrolled as %s, but its state records no instance ID; '
                              'start kilnd once and retry' % (unit, expected))
            raise Refused('%s has checkpoint state but records no instance ID; start kilnd once '
                          'so it records one, then retry' % unit)
        identity = identity or expected
        kept = {'state': state, 'account': account, 'schema': checkpoints['schema'],
                'snapshot': destination, 'instance': identity}
        if identity is not None:
            # Without one the state is from before checkpoints, and has none to inventory.
            if not isinstance(identity, str) or not re.fullmatch(r'[0-9a-f]{32}', identity):
                raise Refused('%s has an invalid checkpoint instance ID' % unit)
            try:
                kept['checkpoints'] = checkpoint_inventory(identity)
            except OSError as error:
                raise Refused('cannot inventory the checkpoint artifacts of %s: %s'
                              % (unit, error)) from None
        journal['instances'][unit] = kept
    os.mkdir(TXN_DIR + '/files', 0o700)
    fsync_dir(TXN_DIR)
    if os.path.isdir(os.path.join(TXN_DIR, 'state')):
        fsync_dir(os.path.join(TXN_DIR, 'state'))
    for name, path in MANAGED_FILES.items():
        if not os.path.exists(os.path.join(args.deploy_dir, name)):
            raise Refused('%s is missing %s' % (args.deploy_dir, name))
        kept = None
        if os.path.exists(path):
            kept = os.path.join(TXN_DIR, 'files', name)
            copy_durably(path, kept)
        journal['files'][path] = kept
    require_quiet(journal, Refused)
    set_phase(journal, 'replacing')

    for image in IMAGES:
        installed = os.path.join(BIN, image)
        if os.path.exists(installed):
            rename_durably(installed, os.path.join(STAGE, 'old', image))
        rename_durably(os.path.join(STAGE, 'new', image), installed)
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
        instance = init_state(installed_kilnd, kept['state'], kept['account'], unit)
        if unit in enrolled and enrolled[unit] != instance:
            raise RuntimeError('%s is enrolled as %s, but its state says %s'
                               % (unit, enrolled[unit], instance))

    require_quiet(journal, RuntimeError)
    journal['started'] = True
    set_phase(journal, 'starting')
    errors = window.release(restored=False)
    if errors:
        raise RuntimeError('; '.join(errors))
    settle(running)
    journal['restarted'] = running
    set_phase(journal, 'committed')


def require_quiet(journal, error):
    """Each kept instance's account scanned again: Refused before anything is replaced, a
    RuntimeError that rolls back after."""
    for unit, kept in sorted(journal['instances'].items()):
        try:
            pids = account_processes(pwd.getpwnam(kept['account']).pw_uid)
        except (KeyError, Refused) as failure:
            raise error('cannot check that %s is quiet: %s' % (unit, failure)) from None
        if pids:
            raise error('%s is stopped, but %d processes started as %s during the upgrade: pids '
                        '%s; stop them and retry' % (unit, len(pids), kept['account'],
                                                     ', '.join(map(str, pids[:10]))))


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


def settled(running):
    """settle() for restoring what ran before, whose answer to Health was its own business."""
    try:
        settle(running, health=False)
    except RuntimeError as error:
        return [str(error)]
    return []


def settle(running, health=True):
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
                if not health:
                    return
                if run((os.path.join(BIN, 'kilndctl'), 'health'), check=False).returncode == 0:
                    return
        else:
            steady_since = None
        if time.monotonic() > deadline:
            raise RuntimeError('kilnd.service did not stay up: ' + json.dumps(state))
        time.sleep(0.25)


def discard_transaction():
    shutil.rmtree(STAGE, ignore_errors=True)
    shutil.rmtree(TXN_DIR, ignore_errors=True)
    fsync_dir(BIN)
    parent = os.path.dirname(TXN_DIR)
    if os.path.isdir(parent):
        fsync_dir(parent)


def mount_points():
    """Each mount point's stack of (major:minor, root), in mountinfo's order, the top last."""
    def decode(field):
        return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), field)
    mounts = {}
    with open(MOUNTINFO, 'rb') as file:
        lines = file.read().decode('utf-8', 'surrogateescape').splitlines()
    for line in lines:
        fields = line.split(' ')
        if len(fields) < 5 or not re.fullmatch(r'\d+:\d+', fields[2]):
            raise OSError(errno.EINVAL, 'cannot parse %s: %r' % (MOUNTINFO, line))
        mounts.setdefault(decode(fields[4]), []).append((fields[2], decode(fields[3])))
    return mounts


def checkpoint_inventory(instance):
    """The top level of the instance's registry directory, by name, type and inode. Root walks
    from / without following a link: every ancestor must be root's and writable by no one else,
    the registry and instance directories root's alone, and the only mount point on the way the
    whole filesystem the registry is on. An absent directory is empty."""
    mounts = mount_points()
    parts = CHECKPOINTS_ROOT.split('/')
    if not CHECKPOINTS_ROOT.startswith('/') or any(p in ('', '.', '..') for p in parts[1:]):
        raise OSError(errno.EINVAL, '%s is not a plain absolute path' % CHECKPOINTS_ROOT)
    components = [*parts[1:], instance]
    protected = len(components) - 2
    fds = [os.open('/', os.O_RDONLY | os.O_DIRECTORY)]
    try:
        try:
            anchor = os.fstat(fds[0])
            if anchor.st_uid not in (0, REGISTRY_UID) or anchor.st_mode & 0o022:
                raise OSError(errno.EPERM, "/ is not root's, or others can write it")
            mounted = None
            for index, component in enumerate(components):
                fds.append(os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                   dir_fd=fds[-1]))
                where = '/' + '/'.join(components[:index + 1])
                meta, above = os.fstat(fds[-1]), os.fstat(fds[-2])
                if index >= protected:
                    if meta.st_uid != REGISTRY_UID or meta.st_mode & 0o077:
                        raise OSError(errno.EPERM, '%s is not private to root' % component)
                elif meta.st_uid not in (0, REGISTRY_UID) or meta.st_mode & 0o022:
                    raise OSError(errno.EPERM, "%s is not root's, or others can write it" % where)
                if where in mounts:
                    device, root = mounts[where][-1]
                    if mounted is not None or index >= protected or root != '/' \
                            or device != '%d:%d' % (os.major(meta.st_dev), os.minor(meta.st_dev)):
                        raise OSError(errno.EXDEV, '%s is a mount point (bind mount?)' % where)
                    mounted = where
                elif meta.st_dev != above.st_dev:
                    raise OSError(errno.EXDEV, '%s is on another filesystem' % where)
        except FileNotFoundError:
            return []
        with os.scandir(fds[-1]) as entries:
            return sorted(({'name': e.name, 'type': stat.S_IFMT(e.stat(follow_symlinks=False).st_mode),
                            'st_ino': e.inode()} for e in entries), key=lambda e: e['name'])
    finally:
        for fd in fds:
            os.close(fd)


def compare_checkpoints(unit, kept, journal):
    """Names, types and inodes: a metadata change alone isn't a different artifact."""
    if 'checkpoints' not in kept:
        return  # Journals from before checkpoint inventories remain recoverable.
    old, new = ({e['name']: (e['type'], e['st_ino']) for e in entries or []}
                for entries in (kept['checkpoints'], checkpoint_inventory(kept['instance'])))
    changes = {'added': sorted(new.keys() - old.keys()), 'missing': sorted(old.keys() - new.keys()),
               'changed': sorted(n for n in old.keys() & new.keys() if old[n] != new[n])}
    if any(changes.values()):
        journal.setdefault('artifact_mismatch', {})[unit] = changes


def artifact_mismatch(journal):
    """Exit 3 with the record kept: kilnd stays stopped, through reboots, until an operator has
    reconciled the artifacts and runs accept-artifacts."""
    for unit, changes in journal['artifact_mismatch'].items():
        details = ', '.join('%s %s' % (kind, ', '.join(map(repr, names)))
                            for kind, names in changes.items() if names)
        log('rolled back, but the checkpoint artifacts of %s changed during the window: %s'
            % (unit, details))
    return RecoveryRequired('kilnd stays stopped until the checkpoint artifacts are reconciled; '
                            'then run kilnd-maintenance.py accept-artifacts (docs/checkpoints.md)')


def rollback(journal, window, boot=False):
    """Undoes an upgrade from whatever point it reached. Safe to repeat. Returns True only when
    the node is whole. A step that fails returns False and keeps the journal, the stage and the
    window, so `recover` can try again; nothing unenrolled or half-installed starts in the
    meantime. Once every file is back only starting units is left, and a retry does only that,
    without stopping what did come back. At boot those starts belong to boot, whose units can't
    run until the guard running this exits: kilnd-maintenance-finish.service does the rest."""
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
        window.record = {'units': journal['prior'], 'stage': 'open'}
        attempt('record the window', lambda: write_json(WINDOW_RECORD, window.record))
    if not journal.get('rolled_back'):
        if window.record is not None:
            attempt('stop everything', window.require_down if boot else window.enforce)
        phase = journal.get('phase', 'prepared')
        replaced = PHASES.index(phase) >= PHASES.index('replacing')
        if replaced:
            def restore_files():
                for path, kept in journal['files'].items():
                    if kept is None:
                        if os.path.exists(path):
                            os.unlink(path)
                            fsync_dir(os.path.dirname(path))
                    else:
                        copy_durably(kept, path)
                systemctl('daemon-reload')
            attempt('restore unit files', restore_files)

            def restore_images():
                for image in IMAGES:
                    old = os.path.join(STAGE, 'old', image)
                    installed = os.path.join(BIN, image)
                    if os.path.exists(old):
                        os.replace(old, installed)
                        fsync_dir(os.path.join(STAGE, 'old'))
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
                        lambda u=unit, k=kept: restore_instance(u, k, journal))
            # Only after every restore: the journal a restore's marker writes must never carry
            # a difference, which holds the node, while another instance is still unrestored.
            for unit, kept in journal['instances'].items():
                attempt('check the checkpoint artifacts of ' + unit,
                        lambda u=unit, k=kept: compare_checkpoints(u, k, journal))
        if errors:
            return False
        if os.path.isdir(TXN_DIR):
            journal['rolled_back'] = True
            attempt('record the rollback', lambda: write_json(JOURNAL, journal))
        if errors:
            return False
    if journal.get('artifact_mismatch'):
        raise artifact_mismatch(journal)
    if boot:
        if window.record is not None:
            attempt('record the rollback', window.mark_restored)
        return not errors
    if window.record is not None:
        errors.extend(window.release())
        if not errors:
            errors.extend(settled(window.running_daemons()))
    if errors:
        for error in errors:
            log('rollback: ' + error)
        return False
    discard_transaction()
    window.finish()
    return True


def restore_instance(unit, kept, journal):
    """Only a schema the old image can't open is put back. Otherwise the database in place
    is the newer truth, and replacing it could forget a reservation made since. If a daemon
    served in between, what it wrote is kept for inspection instead of being lost silently.
    Once a restore has begun, its durable marker makes every retry redo all of it: a live
    file restored beside one not yet restored is neither database, whatever its schema."""
    restoring = journal.setdefault('restoring', {})
    if not restoring.get(unit):
        current = None
        try:
            current = as_account(kept['account'], 'schema', kept['state'])['schema']
        except (OSError, RuntimeError, KeyError) as error:
            log('rollback: reading %s: %s' % (kept['state'], error))
        if current == kept['schema']:
            return
        if journal.get('started'):
            os.makedirs(FAILED_DIR, mode=0o700, exist_ok=True)
            aside = tempfile.mkdtemp(prefix=time.strftime('%Y%m%dT%H%M%S-'), dir=FAILED_DIR)
            aside = os.path.join(aside, unit)
            snapshot_state(kept['account'], kept['state'], aside)
            log('%s had a newer schema, and may have served: what it held is in %s' % (unit, aside))
        restoring[unit] = True
        write_json(JOURNAL, journal)
    restore_state(kept['account'], kept['state'], kept['snapshot'])
    del restoring[unit]
    write_json(JOURNAL, journal)


def finish_interrupted(boot=False):
    """Whatever a killed command left, before anything new starts. The record goes last, so a
    crash in here is met by the same steps. At boot nothing is stopped or started: see rollback."""
    if os.path.exists(JOURNAL):
        journal = read_json(JOURNAL)
        if journal.get('artifact_mismatch'):
            raise artifact_mismatch(journal)
        window = Window()
        if journal['phase'] == 'committed':
            log('finishing a committed upgrade')
            discard_transaction()
            if boot and window.record is not None:
                window.mark_restored()
            else:
                window.finish()
            return
        log('finishing the rollback of an upgrade' if journal.get('rolled_back')
            else 'undoing an interrupted upgrade')
        complete = rollback(journal, window, boot=boot)
        catch_signals()
        if not complete:
            raise RecoveryRequired('the rollback is incomplete: fix what it reported, '
                                   'then run scripts/upgrade.sh --recover')
        return
    # Stopped before its journal existed, so nothing had been replaced.
    interrupted_upgrade = os.path.exists(TXN_DIR) or os.path.exists(STAGE)
    window = Window()
    if window.record is None:
        if interrupted_upgrade:
            discard_transaction()
        return
    log('restoring what was running before an interrupted %s'
        % ('upgrade' if interrupted_upgrade else 'command'))
    if boot:
        window.require_down()
        if interrupted_upgrade:
            discard_transaction()
        window.mark_restored()
        return
    if window.record.get('stage') != 'restored':
        window.enforce()
    if interrupted_upgrade:
        discard_transaction()
    close_window(window)


def activation_safe():
    """Whether units may start with what this node holds: true of a transaction that committed
    or was undone, and of a record with only starting units left."""
    if os.path.exists(JOURNAL):
        journal = read_json(JOURNAL)
        if journal['phase'] != 'committed' and not journal.get('rolled_back') \
                or journal.get('artifact_mismatch'):
            return False
    record = read_json(WINDOW_RECORD) if os.path.exists(WINDOW_RECORD) else None
    return record is None or record.get('stage') == 'restored'


def cmd_recover(args):
    """At boot it refuses a live command's lock as anything else does, which keeps units down."""
    if args.boot and activation_safe():
        return
    lock = acquire_lock()
    finish_interrupted(boot=args.boot)
    log('the rest starts with the node' if args.boot and os.path.exists(WINDOW_RECORD)
        else 'nothing is left to recover')
    os.close(lock)


def cmd_accept_artifacts(_args):
    """The operator's word that the listed artifacts are reconciled: the record goes, durably,
    and then the rest of the rollback starts what was running."""
    lock = acquire_lock()
    journal = read_json(JOURNAL) if os.path.exists(JOURNAL) else {}
    if not journal.get('artifact_mismatch'):
        raise Refused('no checkpoint artifact difference is recorded')
    artifact_mismatch(journal)
    del journal['artifact_mismatch']
    write_json(JOURNAL, journal)
    finish_interrupted()
    log('accepted the checkpoint artifacts; kilnd is running again')
    os.close(lock)


def cmd_install_fence(args):
    lock = acquire_lock()
    finish_interrupted()
    install_fence(args.deploy_dir)
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
    recover = commands.add_parser('recover')
    recover.add_argument('--boot', action='store_true')
    recover.set_defaults(run=cmd_recover)
    fence = commands.add_parser('install-fence')
    fence.add_argument('--deploy-dir', default=os.path.join(repo, 'deploy'))
    fence.set_defaults(run=cmd_install_fence)
    commands.add_parser('accept-artifacts').set_defaults(run=cmd_accept_artifacts)
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
    except RecoveryRequired as required:
        log('recovery required: %s' % required)
        sys.exit(RECOVERY_REQUIRED)
    except Interrupted as interruption:
        log('interrupted by %s' % interruption)
        sys.exit(1)
    except ValueError as error:
        log('recovery required: unreadable record: %s' % error)
        sys.exit(RECOVERY_REQUIRED)
    except (OSError, RuntimeError) as error:
        log(str(error))
        sys.exit(1)


if __name__ == '__main__':
    main()
