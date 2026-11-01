#!/usr/bin/env python3
"""Root's maintenance of a kilnd node. Each command is one transaction.

  add-instance NAME              scripts/add-instance.sh
  recover                        finishes whatever a killed or crashed command left

Enrollment and refreshing need the node lock, which only a stopped helper leaves free,
and every enrolled instance may connect to the helper's socket. So activation is made
impossible first: both activation units are runtime-masked, then stopped along with every
daemon that requires them. A record of what was running lets the end of the window, a signal
or a later `recover` put back exactly that. See docs/setup.md.
"""
import argparse
import fcntl
import glob
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time

BIN = '/usr/local/bin'
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
SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'


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
    with open(source, 'rb') as reader, open(temporary, 'wb') as writer:
        writer.write(reader.read())
    os.chmod(temporary, mode)
    fd = os.open(temporary, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(temporary, destination)


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
                 '/etc/systemd/system/kilnd@.service', 0o644)
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


def finish_interrupted():
    """Whatever a killed command left, before anything new starts."""
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
    commands.add_parser('recover').set_defaults(run=cmd_recover)
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
