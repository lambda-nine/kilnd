#!/usr/bin/env python3
"""The maintenance script's recovery logic, with systemd and the kilnd images faked and every
path in a temporary directory, so it runs anywhere, unprivileged, in CI too:

  python3 -I scripts/kilnd-maintenance-tests.py

A crash here is a forked child killing itself at an exact step, and a reboot is clearing /run
and every unit's state. scripts/deployment-regressions.py does the same against real units.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
from contextlib import closing

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(HERE)
GUARD = 'kilnd-maintenance-guard.service'
HELD = ('kilnd-helper.socket', 'kilnd-helper.service', 'kilnd.service')
INSTANCE = 'kilnd@t1.service'
CRASHED = 137


def load():
    spec = importlib.util.spec_from_file_location(
        'kilnd_maintenance', os.path.join(HERE, 'kilnd-maintenance.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def done(returncode=0, stdout='', stderr=''):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def ancestry(path):
    """/ and every directory down to path, which has no links in it."""
    parts = path.strip('/').split('/') if path != '/' else []
    return ['/', *('/' + '/'.join(parts[:n]) for n in range(1, len(parts) + 1))]


def device_changes(path):
    """The directories on the way to path that are on another device than their parent."""
    chain = ancestry(path)
    return [b for a, b in zip(chain, chain[1:]) if os.lstat(a).st_dev != os.lstat(b).st_dev]


def safe_base():
    """A scratch base the registry walk accepts: macOS's temporary directory is behind the /var
    link, and Linux's /tmp is 1777, so the first candidate whose every ancestor is the test's
    own or root's, writable by no one else, with at most one change of device."""
    for base in (tempfile.gettempdir(), os.path.expanduser('~'), REPO):
        base = os.path.realpath(base)
        metas = [os.lstat(p) for p in ancestry(base)]
        if all(m.st_uid in (0, os.getuid()) and not m.st_mode & 0o022 for m in metas) \
                and len(device_changes(base)) <= 1:
            return base
    raise AssertionError('no scratch base the registry walk accepts')


def mountinfo_line(number, path, meta, root='/', fstype='fake', options='rw', device=None):
    return '%d 1 %s %s %s rw shared:1 - %s fake %s\n' % (
        number, device or '%d:%d' % (os.major(meta.st_dev), os.minor(meta.st_dev)), root, path,
        fstype, options)


def write_mountinfo(path, root, extra=()):
    """/ and the mount point of root's filesystem, if that isn't /'s, as /proc would list them."""
    lines = [mountinfo_line(1, '/', os.lstat('/'))]
    for point in device_changes(root):
        lines.append(mountinfo_line(2, point, os.lstat(point)))
    with open(path, 'w') as file:
        file.write(''.join([*lines, *extra]))


class World:
    """One fake node on disk, so it survives the child that crashes on it."""

    def __init__(self, root):
        self.root = root
        self.m = load()
        self.faults = {'start': set(), 'flap': set(), 'unmask': 0, 'refresh': False,
                       'restore': False, 'init': False, 'migrate': False}
        self.calls = []
        m = self.m
        self.run_dir = root + '/run'
        self.lib = root + '/var/lib/kilnd-helper'
        self.etc = root + '/etc/systemd/system'
        self.deploy = root + '/deploy'
        self.new = root + '/build'
        for path in (self.run_dir, root + '/var/lib', self.etc, self.deploy, self.new,
                     root + '/bin', root + '/tmpfiles', root + '/libexec', root + '/proc'):
            os.makedirs(path)
        for path in (root + '/var', root + '/var/lib'):
            os.chmod(path, 0o755)  # ancestors of the registry, whatever the umask
        m.STATE_PARENT = root + '/var/lib'
        m.PROC = root + '/proc'
        m.MOUNTINFO = root + '/mountinfo'
        write_mountinfo(m.MOUNTINFO, root)
        m.BIN = root + '/bin'
        m.STAGE = m.BIN + '/.kilnd-upgrade'
        m.LOCK = self.run_dir + '/lock'
        m.MASK_DIR = self.run_dir + '/system.control'
        m.HELPER_SOCKET = self.run_dir + '/helper.sock'
        m.WINDOW_RECORD = self.lib + '/maintenance.json'
        m.TXN_DIR = self.lib + '/upgrade'
        m.JOURNAL = m.TXN_DIR + '/journal.json'
        m.FAILED_DIR = self.lib + '/failed-upgrades'
        m.CHECKPOINTS_ROOT = root + '/var/lib/checkpoints'
        m.REGISTRY_UID = os.getuid()
        m.INSPECT_DIR = self.run_dir
        m.UNIT_DIR = self.etc
        m.FENCE_DIR = root + '/libexec/kilnd'
        m.SETTLE_SECONDS = 0
        m.START_SECONDS = 1
        m.MANAGED_FILES = {
            name: (root + '/tmpfiles/' + name if name.endswith('.conf') else self.etc + '/' + name)
            for name in m.MANAGED_FILES
        }
        for name, path in m.MANAGED_FILES.items():
            with open(os.path.join(self.deploy, name), 'w') as file:
                file.write('new ' + name)
            with open(path, 'w') as file:
                file.write('old ' + name)
        for image in m.IMAGES:
            with open(os.path.join(m.BIN, image), 'w') as file:
                file.write('old ' + image)
            with open(os.path.join(self.new, image), 'w') as file:
                file.write('new ' + image)
        self.state = {}
        for unit, name in (('kilnd.service', 'default'), (INSTANCE, 't1')):
            self.state[unit] = root + '/state-' + name
            os.makedirs(self.state[unit])
            self.write_schema(unit, 7)
        self.save_units({u: True for u in (*HELD, INSTANCE)})
        self.save_rows([self.row(u) for u in self.state])
        m.systemctl = self.systemctl
        m.run = self.run
        m.as_account = self.as_account
        self.real_snapshot_state = m.snapshot_state
        self.real_restore_state = m.restore_state
        self.real_standard_instances = getattr(m, 'standard_instances', None)
        m.snapshot_state = self.snapshot_state
        m.standard_instances = lambda: sorted(self.state)
        m.restore_state = self.restore_state
        m.instance_of = lambda unit: (self.state[unit], unit) if unit in self.state else None
        m.pwd = types.SimpleNamespace(
            getpwnam=lambda _account: types.SimpleNamespace(pw_uid=1000, pw_gid=1000))
        m.find_policy = lambda: 'policy.json'
        m.install_fence = lambda _deploy: self.calls.append(('fence',))
        real_lock = m.acquire_lock
        self.lock = [None]

        def acquire():
            # A command that ends here isn't a process that exits, and that's what frees it.
            if self.lock[0] is not None:
                os.close(self.lock[0])
            self.lock[0] = None
            self.lock[0] = real_lock()
            return self.lock[0]
        m.acquire_lock = acquire
        real_close = os.close

        def close(fd):
            if fd == self.lock[0]:
                self.lock[0] = None
            real_close(fd)
        m.os = types.SimpleNamespace(**{k: getattr(os, k) for k in dir(os) if not k.startswith('__')})
        m.os.close = close
        m.os.chown = lambda *_args, **_kwargs: None  # root's chown to the account's group
        real_unmask = m.unmask_runtime

        def unmask(units):
            if self.faults['unmask']:
                self.faults['unmask'] -= 1
                raise RuntimeError('injected unmask failure')
            real_unmask(units)
        m.unmask_runtime = unmask

    def row(self, unit):
        meta = os.stat(os.path.join(self.m.BIN, 'kilnd'))
        return {'instance_id': self.identity(unit), 'unit': unit, 'cgroup': '/' + unit, 'uid': 1000, 'gid': 1000,
                'executable': {'st_dev': meta.st_dev, 'st_ino': meta.st_ino, 'bytes': meta.st_size}}

    @staticmethod
    def identity(unit):
        return hashlib.md5(unit.encode()).hexdigest()

    def load_units(self):
        with open(self.root + '/units.json') as file:
            return json.load(file)

    def save_units(self, units):
        with open(self.root + '/units.json', 'w') as file:
            json.dump(units, file)

    def load_rows(self):
        with open(self.root + '/rows.json') as file:
            return json.load(file)

    def save_rows(self, rows):
        with open(self.root + '/rows.json', 'w') as file:
            json.dump(rows, file)

    def write_schema(self, unit, schema):
        with open(self.state[unit] + '/kilnd.db', 'w') as file:
            file.write(str(schema))

    def schema(self, unit):
        with open(self.state[unit] + '/kilnd.db') as file:
            return int(file.read())

    def masked(self, unit):
        return os.path.islink(os.path.join(self.m.MASK_DIR, unit))

    def systemctl(self, *args, check=True):
        self.calls.append(args)
        verb = args[0]
        units = self.load_units()
        result = done()
        if verb == 'show':
            unit = args[-1]
            if unit not in units:
                return done(stdout='LoadState=not-found\n')
            active = units[unit]
            return done(stdout='LoadState=%s\nActiveState=%s\nSubState=%s\nNRestarts=0\n' % (
                'masked' if self.masked(unit) else 'loaded',
                'active' if active else 'inactive',
                'running' if active else 'dead'))
        if verb == 'list-units':
            return done(stdout=''.join('%s loaded\n' % u for u in units
                                       if u.startswith('kilnd') and u not in HELD[:2]))
        if verb == 'stop':
            for unit in args[1:]:
                units[unit] = False
        if verb == 'start':
            unit = args[-1]
            if self.masked(unit):
                result = done(1, stderr='%s is masked' % unit)
            elif unit in self.faults['start']:
                result = done(1, stderr='injected start failure of ' + unit)
            else:
                units[unit] = unit not in self.faults['flap']
        self.save_units(units)
        if check and result.returncode != 0:
            raise RuntimeError(result.stderr)
        return result

    def run(self, argv, check=True):
        self.calls.append(('run', *argv))
        name, args = os.path.basename(argv[0]), list(argv[1:])
        result = done()
        if args[:1] == ['--version'] or name == 'kilndctl':
            pass
        elif name == 'kilnd-helper' and args[0] == 'enrollments':
            result = done(stdout=json.dumps(self.load_rows()))
        elif name == 'kilnd-helper' and args[0] == 'refresh-enrollments' and '--check' not in args:
            if self.faults['refresh']:
                result = done(1, stderr='injected refresh failure')
            else:
                self.save_rows([{**row, 'executable': self.row(row['unit'])['executable']}
                                for row in self.load_rows()])
        elif name == 'kilnd-helper' and args[0] == 'restore-enrollments':
            if self.faults['restore']:
                result = done(1, stderr='injected restore failure')
            else:
                with open(args[args.index('--snapshot') + 1]) as file:
                    self.save_rows(json.load(file))
        elif name == 'kilnd-helper' and args[0] == 'enroll':
            unit = args[args.index('--unit') + 1]
            self.save_rows([*self.load_rows(), {**self.row('kilnd.service'), 'unit': unit,
                                                'instance_id': 'f' * 32}])
        elif name == 'kilnd' and args[0] == 'init-state':
            state = args[args.index('--state-dir') + 1]
            units = [u for u, path in self.state.items() if path == state]
            if self.faults['init']:
                result = done(1, stderr='injected init failure')
            elif units and self.faults['migrate']:
                self.write_schema(units[0], 99)
            if not self.faults['init']:
                result = done(stdout=self.identity(units[0] if units else 'new') + '\n')
        if check and result.returncode != 0:
            raise RuntimeError(result.stderr)
        return result

    def as_account(self, _account, op, state, *_args, **_kwargs):
        with open(state + '/kilnd.db') as file:
            schema = int(file.read())
        if op == 'checkpoints':
            return {'instance': None, 'busy': [], 'schema': schema}
        return {'schema': schema}

    def snapshot_state(self, _account, state, destination):
        os.makedirs(destination, mode=0o700)
        shutil.copy(state + '/kilnd.db', destination + '/kilnd.db')
        return self.as_account(None, None, state) | {'copied': ['kilnd.db']}

    def restore_state(self, _account, state, source):
        shutil.copy(source + '/kilnd.db', state + '/kilnd.db')

    def upgrade_args(self):
        return argparse.Namespace(bin_dir=self.new, deploy_dir=self.deploy, enroll_default=False)

    def add_args(self):
        return argparse.Namespace(name='t2', deploy_dir=self.deploy)

    def reset_to_old(self):
        """Back to the old node, with the images' inodes as enrollment last saw them."""
        m = self.m
        for image in m.IMAGES:
            with open(os.path.join(m.BIN, image), 'w') as file:
                file.write('old ' + image)
            with open(os.path.join(self.new, image), 'w') as file:
                file.write('new ' + image)
        for name, path in m.MANAGED_FILES.items():
            with open(path, 'w') as file:
                file.write('old ' + name)
        self.save_rows([self.row(u) for u in self.state])

    def images(self):
        contents = {}
        for image in self.m.IMAGES:
            path = os.path.join(self.m.BIN, image)
            if os.path.exists(path):
                with open(path) as file:
                    contents[image] = file.read().split()[0]
            else:
                contents[image] = None
        return contents

    def reboot(self):
        """What a reboot leaves: nothing running, and nothing in /run."""
        if self.lock[0] is not None:
            os.close(self.lock[0])
            self.lock[0] = None
        shutil.rmtree(self.run_dir)
        os.makedirs(self.run_dir)
        self.save_units({u: False for u in self.load_units()})
        self.calls.clear()

    def boot(self):
        """Guard, then what's enabled, then the finish unit, in the order systemd puts them."""
        self.m.cmd_recover(argparse.Namespace(boot=True))
        verbs = {c[0] for c in self.calls}
        assert not verbs & {'start', 'stop', 'restart'}, 'the guard would wait on what waits on it'
        units = self.load_units()
        for unit in HELD:
            units[unit] = unit not in self.faults['start']
        self.save_units(units)
        if os.path.exists(self.m.WINDOW_RECORD):
            self.m.cmd_recover(argparse.Namespace(boot=False))

    def crash_at(self, point, action):
        """Runs a command in a child, which kills itself at that step as power would."""
        pid = os.fork()
        if pid == 0:
            status = 1
            try:
                self.arm(point)
                action()
                status = 0
            except BaseException as error:  # pylint: disable=broad-except
                print('child stopped:', repr(error))
            os._exit(status)
        return os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])

    def arm(self, point):
        m = self.m

        def die():
            os._exit(CRASHED)

        def after(name, when=lambda *_a, **_k: True):
            real = getattr(m, name)

            def wrapped(*args, **kwargs):
                result = real(*args, **kwargs)
                if when(*args, **kwargs):
                    die()
                return result
            setattr(m, name, wrapped)

        def before(name):
            def wrapped(*_args, **_kwargs):
                die()
            setattr(m, name, wrapped)

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
            seen = [0]

            def counted(_source, _destination):
                seen[0] += 1
                return seen[0] == int(number)
            after('rename_durably', counted)
        elif kind == 'unit-file':
            after('install_file', lambda _s, destination, _m: destination.startswith(self.etc))
        elif kind == 'migrated':
            seen = [0]

            def counted(*_args, **_kwargs):
                seen[0] += 1
                return seen[0] == int(number)
            after('init_state', counted)
        elif kind == 'settling':
            before('settle')
        elif kind == 'discarded':
            after('discard_transaction')
        elif kind == 'enrolled':
            after('enroll')
        else:
            raise AssertionError(point)


class Case(unittest.TestCase):
    world = World

    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix='kilnd-maint-', dir=safe_base())
        self.addCleanup(shutil.rmtree, self.scratch, ignore_errors=True)
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            self.addCleanup(signal.signal, number, signal.getsignal(number))
        self.addCleanup(signal.signal, signal.SIGPIPE, signal.getsignal(signal.SIGPIPE))
        self.w = self.world(self.scratch)
        self.m = self.w.m
        self.before_rows = self.w.load_rows()
        self.m.log = lambda _message: None

    def assert_prior(self, what=''):
        w, m = self.w, self.m
        self.assertEqual(w.images(), {i: 'old' for i in m.IMAGES}, what)
        self.assertEqual(w.load_rows(), self.before_rows, what)
        self.assertEqual(w.schema('kilnd.service'), 7, what)
        self.assertEqual(w.schema(INSTANCE), 7, what)
        for name, path in m.MANAGED_FILES.items():
            with open(path) as file:
                self.assertEqual(file.read(), 'old ' + name, what)
        self.assert_clean(what)

    def assert_clean(self, what=''):
        w, m = self.w, self.m
        for path in (m.WINDOW_RECORD, m.TXN_DIR, m.STAGE):
            self.assertFalse(os.path.exists(path), '%s: %s remains' % (what, path))
        self.assertFalse(w.masked('kilnd-helper.socket'), what)
        self.assertFalse(w.masked('kilnd-helper.service'), what)
        self.assertEqual(w.load_units(), {u: True for u in (*HELD, INSTANCE)}, what)

    def assert_recovery_kept(self, journal=False):
        m = self.m
        self.assertTrue(os.path.exists(m.WINDOW_RECORD), 'the record is the retry state')
        self.assertEqual(os.path.exists(m.JOURNAL), journal)
        self.assertEqual(os.path.exists(m.STAGE), journal)


class CheckpointWorld(World):
    """Real SQLite state and account queries, with the same fake services and images."""

    def write_schema(self, unit, schema):
        # SQLite on macOS cannot safely be reused after fork; migrations run in a fresh
        # process, as the real init-state does, including in crash_at's child.
        subprocess.run([sys.executable, '-I', '-c',
                        'import os, sqlite3, sys; '
                        'db = sqlite3.connect(sys.argv[1]); '
                        'db.execute("PRAGMA user_version = " + sys.argv[2]); '
                        'db.close(); os.chmod(sys.argv[1], 0o600)',
                        self.state[unit] + '/kilnd.db', str(schema)], check=True)

    def schema(self, unit):
        return self.as_account(None, 'schema', self.state[unit])['schema']

    def run(self, argv, check=True):
        """init-state's upgrade form refuses busy rows of the live state, by the script's own
        predicate (the Rust store tests prove init-state's is the same), in a fresh process."""
        if os.path.basename(argv[0]) != 'kilnd' or '--refuse-busy-checkpoints' not in argv:
            return super().run(argv, check)
        sql = self.m.ACCOUNT_CHILD.split('# BEGIN checkpoint-busy SQL')[1] \
            .split('# END checkpoint-busy SQL')[0].strip()[len('sql = """'):-len('"""')]
        state = argv[argv.index('--state-dir') + 1]
        found = subprocess.run([sys.executable, '-I', '-c', """if 1:
            import json, sqlite3, sys
            db = sqlite3.connect(sys.argv[1])
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master")}
            rows = db.execute(sys.argv[2]).fetchall() if 'checkpoints' in tables else []
            print(json.dumps(rows))
            """, state + '/kilnd.db', sql], capture_output=True, text=True, check=True)
        busy = json.loads(found.stdout)
        if not busy:
            return super().run(argv, check)
        self.calls.append(('run', *argv))
        result = done(self.m.BUSY_EXIT, stdout=''.join('busy %s %s\n' % tuple(r) for r in busy),
                      stderr='%d busy checkpoints' % len(busy))
        if check:
            raise RuntimeError(result.stderr)
        return result

    def as_account(self, _account, op, state, *args, fds=()):
        # Run the real account code unprivileged; only the UID switch is faked.
        result = subprocess.run([sys.executable, '-I', '-c', self.m.ACCOUNT_CHILD,
                                 op or 'schema', state, *map(str, args)], pass_fds=fds,
                                capture_output=True, text=True, check=False)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or 'exit %d' % result.returncode)
        return json.loads(result.stdout) if result.stdout.strip() else {}


class Checkpoints(Case):
    world = CheckpointWorld

    def setUp(self):
        super().setUp()
        self.messages = []
        self.m.log = self.messages.append
        for unit in self.w.state:
            self.w.write_schema(unit, 16)
            with closing(sqlite3.connect(self.w.state[unit] + '/kilnd.db')) as db, db:
                db.executescript("""
                    CREATE TABLE daemon_identity (id INTEGER PRIMARY KEY, instance_id TEXT);
                    CREATE TABLE checkpoints (id TEXT PRIMARY KEY, state TEXT);
                    CREATE TABLE checkpoint_pins (checkpoint_id TEXT, released_at_ms INTEGER);
                """)
                db.execute('INSERT INTO daemon_identity VALUES (1, ?)', (self.w.identity(unit),))

    def checkpoint(self, state, number=1, pin=False, released=False, unit='kilnd.service'):
        identity = 'cp-%032x' % number
        with closing(sqlite3.connect(self.w.state[unit] + '/kilnd.db')) as db, db:
            db.execute('INSERT INTO checkpoints VALUES (?, ?)', (identity, state))
            if pin:
                db.execute('INSERT INTO checkpoint_pins VALUES (?, ?)',
                           (identity, 1 if released else None))
        return identity

    def artifact_dir(self, unit='kilnd.service'):
        """The registry and the instance's directory as kiln makes them: 0700, the owner's."""
        root = self.m.CHECKPOINTS_ROOT
        if not os.path.isdir(root):
            os.mkdir(root, 0o700)
        path = os.path.join(root, self.w.identity(unit))
        if not os.path.isdir(path):
            os.mkdir(path, 0o700)
        return path

    def upgrade(self, code=None, held=False):
        with mock.patch.object(sys, 'argv', ['kilnd-maintenance', 'upgrade', '--bin-dir',
                                            self.w.new, '--deploy-dir', self.w.deploy]):
            self.m.require_root = lambda: None
            if code is None:
                self.m.main()
            else:
                with self.assertRaises(SystemExit) as caught:
                    self.m.main()
                self.assertEqual(caught.exception.code, code)
        if held:
            self.assert_held()
        else:
            self.assert_clean()
        if code is not None:
            self.assertEqual(self.w.images(), {i: 'old' for i in self.m.IMAGES})
            self.assertEqual(self.w.load_rows(), self.before_rows)
            for unit in self.w.state:
                self.assertEqual(self.w.schema(unit), 16)
            for name, path in self.m.MANAGED_FILES.items():
                with open(path) as file:
                    self.assertEqual(file.read(), 'old ' + name)

    def command(self, *argv):
        with mock.patch.object(sys, 'argv', ['kilnd-maintenance', *argv]):
            self.m.require_root = lambda: None
            with self.assertRaises(SystemExit) as caught:
                self.m.main()
        return caught.exception.code

    def assert_held(self):
        """An artifact difference: rolled back, with its record kept and every unit down."""
        journal = self.m.read_json(self.m.JOURNAL)
        self.assertTrue(journal['rolled_back'])
        self.assertTrue(journal['artifact_mismatch'])
        self.assertTrue(os.path.exists(self.m.WINDOW_RECORD))
        self.assertEqual(self.w.load_units(), {u: False for u in (*HELD, INSTANCE)})
        self.assertFalse(self.m.activation_safe(), 'the boot guard keeps them down')
        self.assertEqual(self.w.images(), {i: 'old' for i in self.m.IMAGES})

    def accept(self):
        self.messages.clear()
        with mock.patch.object(sys, 'argv', ['kilnd-maintenance', 'accept-artifacts']):
            self.m.require_root = lambda: None
            self.m.main()
        self.assert_clean()
        self.assertEqual(self.w.images(), {i: 'old' for i in self.m.IMAGES})

    def busy(self, state, pin=False):
        identity = self.checkpoint(state, pin=pin)
        self.upgrade(2)
        message = '\n'.join(self.messages)
        self.assertIn('kilnd.service has 1 busy checkpoints: ' + identity, message)
        self.assertIn('fork pin' if pin else state, message)
        self.assertIn('start kilnd, let those checkpoints settle (kilndctl checkpoint ls), and retry',
                      message)
        self.assertFalse([c for c in self.w.calls if c[0] == 'run'
                          and 'restore-enrollments' in c])

    def test_capturing_refuses(self):
        self.busy('capturing')

    def test_deleting_refuses(self):
        self.busy('deleting')

    def test_live_pin_refuses(self):
        self.busy('ready', pin=True)

    def test_busy_message_limits_ids_and_counts_all(self):
        ids = [self.checkpoint('capturing', n) for n in range(7)]
        self.upgrade(2)
        message = '\n'.join(self.messages)
        self.assertIn('has 7 busy checkpoints', message)
        for identity in ids[:5]:
            self.assertIn(identity, message)
        for identity in ids[5:]:
            self.assertNotIn(identity, message)

    def stop_instance(self):
        units = self.w.load_units()
        units[INSTANCE] = False
        self.w.save_units(units)

    def test_stopped_instance_with_busy_checkpoint_refuses(self):
        """H1: a configured instance that isn't running still has its checkpoints checked."""
        self.stop_instance()
        identity = self.checkpoint('capturing', unit=INSTANCE)
        self.assertEqual(self.command('upgrade', '--bin-dir', self.w.new,
                                      '--deploy-dir', self.w.deploy), 2)
        self.assertIn(INSTANCE + ' has 1 busy checkpoints: ' + identity, '\n'.join(self.messages))
        self.assertEqual(self.w.images(), {i: 'old' for i in self.m.IMAGES})
        self.assertFalse(self.w.load_units()[INSTANCE], 'still stopped')
        for path in (self.m.WINDOW_RECORD, self.m.TXN_DIR, self.m.STAGE):
            self.assertFalse(os.path.exists(path))

    def test_stopped_instance_is_checked_but_not_taken_over(self):
        self.stop_instance()
        self.checkpoint('ready', unit=INSTANCE)
        real_phase, captured = self.m.set_phase, []

        def phase(journal, name):
            real_phase(journal, name)
            if name == 'replacing':
                captured.append(self.m.read_json(self.m.JOURNAL)['instances'])
        self.m.set_phase = phase
        with mock.patch.object(sys, 'argv', ['kilnd-maintenance', 'upgrade', '--bin-dir',
                                            self.w.new, '--deploy-dir', self.w.deploy]):
            self.m.require_root = lambda: None
            self.m.main()
        self.assertEqual(list(captured[0]), ['kilnd.service'])
        self.assertFalse(self.w.load_units()[INSTANCE])
        self.assertEqual(self.w.images(), {i: 'new' for i in self.m.IMAGES})

    def make_db(self, path, identity, busy=None):
        with closing(sqlite3.connect(path)) as db, db:
            db.executescript("""
                PRAGMA user_version = 16;
                CREATE TABLE daemon_identity (id INTEGER PRIMARY KEY, instance_id TEXT);
                CREATE TABLE checkpoints (id TEXT PRIMARY KEY, state TEXT);
                CREATE TABLE checkpoint_pins (checkpoint_id TEXT, released_at_ms INTEGER);
            """)
            db.execute('INSERT INTO daemon_identity VALUES (1, ?)', (identity,))
            if busy:
                db.execute('INSERT INTO checkpoints VALUES (?, ?)', ('cp-' + 'a' * 32, busy))
        os.chmod(path, 0o600)

    def swap_after_snapshot(self, identity):
        """What another process of the account can do once root has its snapshot."""
        real = self.m.snapshot_state
        state = self.w.state['kilnd.service']

        def snapshot(account, where, destination):
            report = real(account, where, destination)
            if where == state:
                self.make_db(state + '/replacement.db', identity)
                os.replace(state + '/replacement.db', state + '/kilnd.db')
            return report
        self.m.snapshot_state = snapshot

    def test_busy_row_in_the_snapshot_refuses_after_a_swap(self):
        """H2: the query reads the snapshot root holds, not the state pathname."""
        identity = self.checkpoint('capturing')
        self.swap_after_snapshot('2' * 32)
        self.assertEqual(self.command('upgrade', '--bin-dir', self.w.new,
                                      '--deploy-dir', self.w.deploy), 2)
        self.assertIn('kilnd.service has 1 busy checkpoints: ' + identity, '\n'.join(self.messages))

    def test_snapshot_identity_is_journaled_after_a_swap(self):
        self.swap_after_snapshot('2' * 32)
        real_phase, captured = self.m.set_phase, []

        def phase(journal, name):
            real_phase(journal, name)
            if name == 'replacing':
                captured.append(self.m.read_json(self.m.JOURNAL)['instances'])
        self.m.set_phase = phase
        self.upgrade()
        self.assertEqual(captured[0]['kilnd.service']['instance'], self.w.identity('kilnd.service'))

    def test_identity_other_than_the_enrollment_refuses(self):
        with closing(sqlite3.connect(self.w.state['kilnd.service'] + '/kilnd.db')) as db, db:
            db.execute('UPDATE daemon_identity SET instance_id = ?', ('3' * 32,))
        self.upgrade(2)
        self.assertIn('kilnd.service is enrolled as %s, but its state says %s'
                      % (self.w.identity('kilnd.service'), '3' * 32), '\n'.join(self.messages))

    def test_query_reads_rows_still_in_the_snapshot_wal(self):
        live = self.scratch + '/live'
        os.mkdir(live, 0o700)
        db = sqlite3.connect(live + '/kilnd.db', isolation_level=None)
        db.execute('PRAGMA journal_mode = WAL')
        db.execute('PRAGMA wal_autocheckpoint = 0')
        db.execute('PRAGMA user_version = 16')
        db.executescript("""
            CREATE TABLE daemon_identity (id INTEGER PRIMARY KEY, instance_id TEXT);
            CREATE TABLE checkpoints (id TEXT PRIMARY KEY, state TEXT);
            CREATE TABLE checkpoint_pins (checkpoint_id TEXT, released_at_ms INTEGER);
        """)
        db.execute("INSERT INTO daemon_identity VALUES (1, ?)", ('4' * 32,))
        db.execute("INSERT INTO checkpoints VALUES ('cp-wal', 'capturing')")
        snapshot = self.scratch + '/snapshot'
        os.mkdir(snapshot, 0o700)
        for name in ('kilnd.db', 'kilnd.db-wal'):
            shutil.copyfile(live + '/' + name, snapshot + '/' + name)
        db.close()
        self.assertGreater(os.path.getsize(snapshot + '/kilnd.db-wal'), 0)
        before = sorted((n, os.stat(snapshot + '/' + n).st_mtime_ns) for n in os.listdir(snapshot))
        checked = self.m.inspect_snapshot('kilnd', snapshot)
        self.assertEqual(checked, {'instance': '4' * 32, 'schema': 16, 'has_checkpoints': True,
                                   'busy': [{'id': 'cp-wal', 'kind': 'capturing'}]})
        after = sorted((n, os.stat(snapshot + '/' + n).st_mtime_ns) for n in os.listdir(snapshot))
        self.assertEqual(before, after, 'the snapshot itself is never opened by SQLite')
        self.assertEqual([n for n in os.listdir(self.w.run_dir) if n.startswith('kilnd-inspect.')],
                         [], 'the private copy is removed')

    def test_account_query_needs_the_held_snapshot(self):
        state = self.w.state['kilnd.service']
        with self.assertRaises(RuntimeError):
            self.w.as_account(None, 'checkpoints', state)
        other = os.open(self.w.state[INSTANCE] + '/kilnd.db', os.O_RDONLY)
        try:
            with self.assertRaisesRegex(RuntimeError, 'not the snapshot root holds'):
                self.w.as_account(None, 'checkpoints', state, other, fds=(other,))
        finally:
            os.close(other)

    def test_account_snapshot_does_not_follow_db_links(self):
        state = self.w.state['kilnd.service']
        path = state + '/kilnd.db'
        os.rename(path, path + '.real')
        os.symlink(path + '.real', path)
        destination = os.open(self.scratch + '/copy', os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            with self.assertRaisesRegex(RuntimeError, 'private regular file|Errno'):
                self.w.as_account(None, 'snapshot', state, destination, fds=(destination,))
        finally:
            os.close(destination)

    def test_schema14_without_checkpoint_tables_proceeds(self):
        for unit in self.w.state:
            self.w.write_schema(unit, 14)
            with closing(sqlite3.connect(self.w.state[unit] + '/kilnd.db')) as db, db:
                db.executescript('DROP TABLE checkpoints; DROP TABLE checkpoint_pins;')
        self.upgrade()

    def test_missing_checkpoint_table_proceeds(self):
        for unit in self.w.state:
            with closing(sqlite3.connect(self.w.state[unit] + '/kilnd.db')) as db, db:
                db.executescript('DROP TABLE checkpoints; DROP TABLE checkpoint_pins;')
        self.upgrade()

    def test_idle_checkpoints_inventory_is_journaled(self):
        for n, state in enumerate(('ready', 'deleted', 'failed', 'quarantined')):
            self.checkpoint(state, n, pin=state == 'ready', released=True)
        directory = self.artifact_dir()
        os.mkdir(directory + '/cp-b')
        with open(directory + '/cp-a', 'w') as file:
            file.write('immutable')
        os.symlink('/does-not-exist', directory + '/cp-link')
        real_phase = self.m.set_phase
        captured = []

        def phase(journal, name):
            real_phase(journal, name)
            if name == 'replacing':
                captured.append(self.m.read_json(self.m.JOURNAL)['instances'])
        self.m.set_phase = phase
        self.upgrade()
        kept = captured[0]['kilnd.service']
        self.assertEqual(kept['instance'], self.w.identity('kilnd.service'))
        self.assertEqual(captured[0][INSTANCE]['checkpoints'], [], 'absent is empty')
        self.assertEqual([e['name'] for e in kept['checkpoints']], ['cp-a', 'cp-b', 'cp-link'])
        for entry in kept['checkpoints']:
            meta = os.lstat(directory + '/' + entry['name'])
            self.assertEqual(entry, {'name': entry['name'], 'type': stat.S_IFMT(meta.st_mode),
                                     'st_ino': meta.st_ino})

    def fail_after_start(self, change):
        real_settle = self.m.settle
        self.w.faults['migrate'] = True

        def settle(running, health=True):
            if health:
                self.assertTrue(all(self.w.load_units().values()))
                change()
                raise RuntimeError('injected failure after start')
            return real_settle(running, health=health)
        self.m.settle = settle

    def test_rollback_added_artifact_keeps_kilnd_down_until_accepted(self):
        """H4: exit 3 fails closed by itself, across later commands and a reboot."""
        directory = self.artifact_dir()
        self.fail_after_start(lambda: os.mkdir(directory + '/cp-new'))
        self.upgrade(3, held=True)
        message = '\n'.join(self.messages)
        self.assertIn("added 'cp-new'", message)
        self.assertIn('kilnd-maintenance.py accept-artifacts', message)
        self.assertTrue(os.path.isdir(directory + '/cp-new'), 'never swept')
        for argv in (('recover',), ('upgrade', '--bin-dir', self.w.new, '--deploy-dir',
                                    self.w.deploy), ('add-instance', 't2')):
            self.messages.clear()
            self.assertEqual(self.command(*argv), 3, argv)
            self.assertIn("added 'cp-new'", '\n'.join(self.messages))
            self.assert_held()
        self.w.reboot()
        with self.assertRaises(self.m.RecoveryRequired):
            self.m.cmd_recover(argparse.Namespace(boot=True))
        self.assertEqual(self.w.load_units(), {u: False for u in (*HELD, INSTANCE)})
        self.assert_held()
        self.accept()
        self.assertIn("added 'cp-new'", '\n'.join(self.messages), 'accept prints the listing')
        self.assertEqual(self.command('accept-artifacts'), 2, 'nothing left to accept')

    def test_rollback_missing_artifact_is_exit3_and_held(self):
        directory = self.artifact_dir()
        os.mkdir(directory + '/cp-old')
        self.fail_after_start(lambda: os.rmdir(directory + '/cp-old'))
        self.upgrade(3, held=True)
        self.assertIn("missing 'cp-old'", '\n'.join(self.messages))
        self.accept()

    def test_rollback_replaced_artifact_is_exit3_and_held(self):
        directory = self.artifact_dir()
        os.mkdir(directory + '/cp-old')
        os.mkdir(directory + '/cp-spare')

        def replace():
            os.rmdir(directory + '/cp-old')
            os.rename(directory + '/cp-spare', directory + '/cp-old')
            os.mkdir(directory + '/cp-spare')
        self.fail_after_start(replace)
        self.upgrade(3, held=True)
        self.assertIn("changed 'cp-old'", '\n'.join(self.messages))

    def test_rollback_changed_mtime_alone_is_exit1(self):
        directory = self.artifact_dir()
        os.mkdir(directory + '/cp-old')
        meta = os.stat(directory + '/cp-old')
        self.fail_after_start(lambda: os.utime(directory + '/cp-old',
                                             ns=(meta.st_atime_ns, meta.st_mtime_ns + 1)))
        self.upgrade(1)
        self.assertFalse(any('checkpoint artifacts' in m for m in self.messages))

    def test_rollback_unchanged_inventory_is_exit1(self):
        os.mkdir(self.artifact_dir() + '/cp-old')
        self.fail_after_start(lambda: None)
        self.upgrade(1)
        self.assertFalse(any('checkpoint artifacts' in m for m in self.messages))

    def test_rollback_empty_directory_appeared_is_exit1(self):
        self.fail_after_start(self.artifact_dir)
        self.upgrade(1)
        self.assertFalse(any('checkpoint artifacts' in m for m in self.messages))

    def test_boot_rollback_with_artifact_difference_keeps_units_down(self):
        directory = self.artifact_dir()
        self.w.faults['migrate'] = True
        self.assertEqual(self.w.crash_at('settling:', lambda: self.m.cmd_upgrade(self.w.upgrade_args())),
                         CRASHED)
        os.mkdir(directory + '/cp-new')
        self.w.reboot()
        with self.assertRaises(self.m.RecoveryRequired):
            self.m.cmd_recover(argparse.Namespace(boot=True))
        self.assertIn("added 'cp-new'", '\n'.join(self.messages))
        self.assert_held()
        self.assertEqual(self.command('recover'), 3)
        self.assert_held()
        self.accept()

    def test_recover_after_a_killed_upgrade_with_artifact_difference_is_exit3(self):
        directory = self.artifact_dir()
        self.w.faults['migrate'] = True
        self.assertEqual(self.w.crash_at('settling:', lambda: self.m.cmd_upgrade(self.w.upgrade_args())),
                         CRASHED)
        os.mkdir(directory + '/cp-new')
        self.assertEqual(self.command('recover'), 3)
        self.assertIn("added 'cp-new'", '\n'.join(self.messages))
        self.assert_held()
        self.assertEqual(self.command('recover'), 3)
        self.accept()

    def test_a_crash_restoring_a_later_instance_is_finished_before_the_hold(self):
        """Every instance is restored before any artifact is compared, so the journal a
        restore's marker writes never carries a difference found for an earlier instance:
        that would hold the node (exit 3) with a later instance's state half restored."""
        directory = self.artifact_dir()
        self.fail_after_start(lambda: os.mkdir(directory + '/cp-new'))
        real = self.m.restore_state

        def restore(account, state, source):
            if state == self.w.state[INSTANCE]:
                os._exit(CRASHED)
            return real(account, state, source)
        self.m.restore_state = restore
        self.assertEqual(self.w.crash_at('enrolled:', lambda: self.m.cmd_upgrade(
            self.w.upgrade_args())), CRASHED)
        self.m.restore_state = real
        self.assertEqual(self.w.schema(INSTANCE), 99, 'killed before its restore')
        self.assertEqual(self.command('recover'), 3)
        self.assertEqual(self.w.schema(INSTANCE), 16, 'restored before the hold')
        self.assertIn("added 'cp-new'", '\n'.join(self.messages))
        self.assert_held()
        self.accept()

    def test_old_journal_without_inventories_recovers(self):
        directory = self.artifact_dir()
        self.w.faults['migrate'] = True
        self.assertEqual(self.w.crash_at('settling:', lambda: self.m.cmd_upgrade(self.w.upgrade_args())),
                         CRASHED)
        journal = self.m.read_json(self.m.JOURNAL)
        for kept in journal['instances'].values():
            del kept['checkpoints']
        self.m.write_json(self.m.JOURNAL, journal)
        os.mkdir(directory + '/cp-new')
        self.m.cmd_recover(argparse.Namespace(boot=False))
        self.assert_clean()
        self.assertEqual(self.w.images(), {i: 'old' for i in self.m.IMAGES})

    def test_inventory_does_not_follow_instance_link(self):
        directory = self.artifact_dir()
        os.rmdir(directory)
        os.symlink(self.scratch, directory)
        with self.assertRaises(OSError):
            self.m.checkpoint_inventory(self.w.identity('kilnd.service'))

    def test_inventory_does_not_follow_a_registry_link(self):
        """H3: no component of the walk follows a link, the registry itself included."""
        outside = self.scratch + '/outside'
        instance = self.w.identity('kilnd.service')
        os.makedirs(outside + '/' + instance, 0o700)
        os.chmod(outside, 0o700)
        with open(outside + '/' + instance + '/outside-sentinel', 'w') as file:
            file.write('outside')
        os.symlink(outside, self.m.CHECKPOINTS_ROOT)
        with self.assertRaises(OSError):
            self.m.checkpoint_inventory(instance)
        self.upgrade(2)
        self.assertIn('cannot inventory the checkpoint artifacts of kilnd.service',
                      '\n'.join(self.messages))

    def test_inventory_refuses_a_registry_not_private_to_root(self):
        instance = self.w.identity('kilnd.service')
        directory = self.artifact_dir()
        for path in (self.m.CHECKPOINTS_ROOT, directory):
            os.chmod(path, 0o755)
            with self.assertRaisesRegex(OSError, 'not private to root'):
                self.m.checkpoint_inventory(instance)
            os.chmod(path, 0o700)
        for path in (self.m.CHECKPOINTS_ROOT, directory):
            self.fake_fstat(path, uid=os.getuid() + 1)
            with self.assertRaisesRegex(OSError, 'not private to root'):
                self.m.checkpoint_inventory(instance)
            self.m.os.fstat = os.fstat

    def fake_fstat(self, path, uid=None, dev=None, ino=None):
        """os.fstat as the walk sees it, with path's owner, device or inode changed."""
        inode = os.stat(path).st_ino

        def fstat(fd):
            meta = os.fstat(fd)
            if meta.st_ino != inode:
                return meta
            fields = list(meta[:10])
            fields[4] = fields[4] if uid is None else uid
            fields[2] = fields[2] if dev is None else dev
            fields[1] = fields[1] if ino is None else ino
            return os.stat_result(fields)
        self.m.os.fstat = fstat

    def test_inventory_refuses_another_filesystem(self):
        directory = self.artifact_dir()
        inode = os.stat(directory).st_ino
        real = os.fstat

        def fstat(fd):
            meta = real(fd)
            if meta.st_ino != inode:
                return meta
            fields = list(meta[:10])
            fields[2] += 1
            return os.stat_result(fields)
        self.m.os.fstat = fstat
        with self.assertRaisesRegex(OSError, 'another filesystem'):
            self.m.checkpoint_inventory(self.w.identity('kilnd.service'))


    def journal_at_replacing(self):
        """The journal's instances as replacing begins, and the init-state runs before then."""
        real_phase, captured = self.m.set_phase, {}

        def phase(journal, name):
            real_phase(journal, name)
            if name == 'replacing':
                captured['instances'] = self.m.read_json(self.m.JOURNAL)['instances']
                captured['init'] = len([c for c in self.w.calls
                                        if c[:1] == ('run',) and 'init-state' in c])
        self.m.set_phase = phase
        return captured

    def orphan(self, identity=None, busy=None):
        """A standard state directory no unit or enrollment names."""
        unit = 'kilnd@orphan.service'
        state = self.scratch + '/state-orphan'
        os.mkdir(state, 0o700)
        self.w.state[unit] = state
        self.make_db(state + '/kilnd.db', identity or self.w.identity(unit), busy)
        return unit, state

    def test_orphan_state_with_busy_checkpoint_refuses(self):
        """Recheck H1: a busy state directory with no unit or enrollment is still checked."""
        unit, state = self.orphan(busy='capturing')
        self.assertNotIn(unit, self.w.load_units())
        self.assertNotIn(unit, [r['unit'] for r in self.w.load_rows()])
        self.upgrade(2)
        self.assertIn(unit + ' has 1 busy checkpoints: cp-' + 'a' * 32 + ' (capturing)',
                      '\n'.join(self.messages))
        with closing(sqlite3.connect(state + '/kilnd.db')) as db:
            self.assertEqual(db.execute('SELECT id, state FROM checkpoints').fetchall(),
                             [('cp-' + 'a' * 32, 'capturing')])

    def test_standard_instances_lists_only_standard_state_dirs(self):
        parent = self.scratch + '/lib'
        for name in ('kilnd', 'kilnd-a1', 'kilnd-helper', 'kilnd-Bad', 'kilnd-x.y', 'kiln',
                     'kilnd-' + 'b' * 17):
            os.makedirs(parent + '/' + name)
        open(parent + '/kilnd-f1', 'w').close()
        self.m.STATE_PARENT = parent
        standard = self.w.real_standard_instances
        with self.assertRaisesRegex(self.m.Refused, 'kilnd-f1 is not a directory'):
            standard()
        os.unlink(parent + '/kilnd-f1')
        self.assertEqual(standard(), ['kilnd.service', 'kilnd@a1.service'])
        self.assertEqual(self.m.instance_of.__name__, '<lambda>', 'the world fakes it')
        os.symlink(parent + '/kilnd-a1', parent + '/kilnd-l1')
        with self.assertRaisesRegex(self.m.Refused, 'kilnd-l1 is not a directory'):
            standard()

    def without_account(self, unit):
        real = self.m.pwd.getpwnam

        def getpwnam(account):
            if account == unit:
                raise KeyError(account)
            return real(account)
        self.m.pwd = types.SimpleNamespace(getpwnam=getpwnam)

    def test_orphan_without_account_refuses_checkpoint_schema(self):
        unit, state = self.orphan()
        self.without_account(unit)
        self.upgrade(2)
        self.assertIn('%s holds kilnd state of schema 15 or later, but account %s is gone'
                      % (state, unit), '\n'.join(self.messages))
        # From before checkpoints, it holds nothing the upgrade could break.
        os.unlink(state + '/kilnd.db')
        with closing(sqlite3.connect(state + '/kilnd.db')) as db:
            db.execute('PRAGMA user_version = 14')
            db.execute('CREATE TABLE t (x)')
        self.upgrade()
        self.assertEqual(self.w.images(), {i: 'new' for i in self.m.IMAGES})

    def test_holds_checkpoint_schema_reads_only_the_header(self):
        state = self.scratch + '/header'
        os.mkdir(state)
        held = self.m.holds_checkpoint_schema
        self.assertFalse(held(state), 'no database')
        open(state + '/kilnd.db', 'w').close()
        self.assertFalse(held(state), 'empty')
        with open(state + '/kilnd.db', 'wb') as file:
            file.write(b'not a database' * 10)
        self.assertTrue(held(state), 'unreadable counts as yes')
        os.unlink(state + '/kilnd.db')
        for version, expected in ((14, False), (15, True), (16, True)):
            with closing(sqlite3.connect(state + '/kilnd.db')) as db:
                db.execute('PRAGMA user_version = %d' % version)
                db.execute('CREATE TABLE IF NOT EXISTS t (x)')
            self.assertEqual(held(state), expected, version)
        with open(state + '/kilnd.db-wal', 'wb') as file:
            file.write(b'w')
        self.assertTrue(held(state), 'a WAL may carry a migration')
        os.unlink(state + '/kilnd.db-wal')
        os.symlink('/dev/null', state + '/kilnd.db-wal')
        self.assertTrue(held(state), 'a WAL that is not a file')
        os.unlink(state + '/kilnd.db-wal')
        os.rename(state + '/kilnd.db', state + '/real.db')
        os.symlink(state + '/real.db', state + '/kilnd.db')
        self.assertTrue(held(state), 'a link')
        os.unlink(state + '/kilnd.db')
        os.mkfifo(state + '/kilnd.db')
        self.assertTrue(held(state), 'a FIFO, without blocking on it')

    def fake_process(self, pid, uids, status=None):
        os.makedirs('%s/%d' % (self.m.PROC, pid))
        with open('%s/%d/status' % (self.m.PROC, pid), 'wb') as file:
            file.write(status if status is not None else
                       b'Name:\t\xffkilnd\nUid:\t%s\nGid:\t1000\t1000\t1000\t1000\n'
                       % '\t'.join(map(str, uids)).encode())

    def test_process_of_the_account_with_saved_uid_refuses(self):
        """Recheck H2: a stopped unit doesn't prove its account has no writer left."""
        os.makedirs(self.m.PROC + '/self')
        self.fake_process(77, (1001, 1001, 1001, 1001))
        self.fake_process(4242, (1001, 1001, 1000, 1001))
        self.upgrade(2)
        message = '\n'.join(self.messages)
        self.assertIn('kilnd.service is stopped, but 1 processes still run as kilnd.service: '
                      'pids 4242; stop them and retry', message)

    def test_process_of_the_account_with_real_uid_refuses(self):
        self.fake_process(4242, (1000, 1001, 1001, 1001))
        self.upgrade(2)
        self.assertIn('pids 4242', '\n'.join(self.messages))

    def test_unreadable_process_table_refuses(self):
        os.rmdir(self.m.PROC)
        self.upgrade(2)
        self.assertIn('cannot list processes in ' + self.m.PROC, '\n'.join(self.messages))
        os.mkdir(self.m.PROC)
        self.fake_process(4243, (), status=b'Name:\tkilnd\nGid:\t0\t0\t0\t0\n')
        self.upgrade(2)
        self.assertIn('4243/status has no Uid line', '\n'.join(self.messages))

    def appears_after_the_last_snapshot(self, exits):
        """Recheck 2 H1: once the last instance is copied, a job of its account starts and
        commits a busy row; with exits, it is gone again before the next scan."""
        state, real = self.w.state[INSTANCE], self.m.snapshot_state

        def snapshot(account, where, destination):
            report = real(account, where, destination)
            if where == state:
                self.fake_process(4242, (1000, 1000, 1000, 1000))
                with closing(sqlite3.connect(state + '/kilnd.db')) as db, db:
                    db.execute("INSERT INTO checkpoints VALUES ('cp-race', 'capturing')")
                if exits:
                    shutil.rmtree(self.m.PROC + '/4242')
            return report
        self.m.snapshot_state = snapshot
        return state

    def assert_race_row_kept(self, state):
        with closing(sqlite3.connect(state + '/kilnd.db')) as db:
            self.assertEqual(db.execute('SELECT id, state FROM checkpoints').fetchall(),
                             [('cp-race', 'capturing')])

    def test_process_started_after_the_scan_is_seen_before_replacing(self):
        state = self.appears_after_the_last_snapshot(exits=False)
        self.upgrade(2)
        # Every fake account is UID 1000, so the first kept instance's scan is the one to see it.
        self.assertIn('kilnd.service is stopped, but 1 processes started as kilnd.service '
                      'during the upgrade: pids 4242; stop them and retry', '\n'.join(self.messages))
        self.assertFalse([c for c in self.w.calls if c[:1] == ('run',) and 'init-state' in c])
        self.assert_race_row_kept(state)

    def test_busy_row_committed_after_the_last_scan_is_refused_by_init_state(self):
        """No scan sees a job that has already exited: init-state's check in the migration's
        own transaction is what refuses, and the upgrade rolls back over nothing."""
        state = self.appears_after_the_last_snapshot(exits=True)
        self.upgrade(1)
        self.assertIn('the upgrade failed and was undone: kilnd@t1.service has 1 busy '
                      'checkpoints, so its state was not upgraded: cp-race (capturing)',
                      '\n'.join(self.messages))
        self.assert_race_row_kept(state)
        refused = [c for c in self.w.calls if c[:1] == ('run',) and 'init-state' in c]
        self.assertTrue(refused and all('--refuse-busy-checkpoints' in c for c in refused))

    def test_process_started_after_replacing_rolls_back_before_the_start(self):
        real = self.m.init_state

        def init_state(*args):
            instance = real(*args)
            if args[-1] == INSTANCE:
                self.fake_process(4242, (1000, 1000, 1000, 1000))
            return instance
        self.m.init_state = init_state
        self.upgrade(1)
        self.assertIn('the upgrade failed and was undone: kilnd.service is stopped, but 1 '
                      'processes started as kilnd.service during the upgrade: pids 4242',
                      '\n'.join(self.messages))

    def test_add_instance_keeps_the_plain_init_state(self):
        self.assertEqual(self.m.init_state('kilnd', self.w.state['kilnd.service'], 'kilnd'),
                         self.w.identity('kilnd.service'))
        self.assertNotIn('--refuse-busy-checkpoints', self.w.calls[-1])

    def wal_only_busy_row(self):
        """The default instance's state in WAL mode, a busy row only in its WAL, its writer open."""
        state = self.w.state['kilnd.service']
        db = sqlite3.connect(state + '/kilnd.db', isolation_level=None)
        self.addCleanup(db.close)
        db.executescript('PRAGMA journal_mode = WAL; PRAGMA wal_autocheckpoint = 0;')
        db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        db.execute("INSERT INTO checkpoints VALUES ('cp-wal-only', 'capturing')")
        for name in ('kilnd.db-wal', 'kilnd.db-shm'):
            os.chmod(state + '/' + name, 0o600)
        self.assertEqual(self.immutable_rows(state + '/kilnd.db'), [], 'only in the WAL')
        return state

    @staticmethod
    def immutable_rows(path):
        """The checkpoints in that one file, whatever WAL lies beside it."""
        with closing(sqlite3.connect('file:%s?immutable=1' % path, uri=True)) as db:
            return db.execute('SELECT id, state FROM checkpoints').fetchall()

    def test_snapshot_is_one_sqlite_copy_of_db_and_wal(self):
        state = self.wal_only_busy_row()
        destination = self.scratch + '/snapshot'
        self.w.real_snapshot_state('kilnd', state, destination)
        self.assertEqual(os.listdir(destination), ['kilnd.db'])
        self.assertEqual(self.immutable_rows(destination + '/kilnd.db'),
                         [('cp-wal-only', 'capturing')])
        self.assertEqual(stat.S_IMODE(os.stat(destination + '/kilnd.db').st_mode), 0o600)

    def test_snapshot_of_absent_state_copies_nothing(self):
        state = self.scratch + '/empty'
        os.mkdir(state, 0o700)
        report = self.w.real_snapshot_state('kilnd', state, self.scratch + '/snapshot')
        self.assertEqual(report, {'copied': []})
        self.assertEqual(os.listdir(self.scratch + '/snapshot'), [])

    def test_checkpointing_the_wal_after_the_copy_still_refuses(self):
        """Recheck H2's race: a surviving writer checkpoints the WAL into the main file just
        after the copy first writes to root's descriptor. The copy must already be whole."""
        state = self.wal_only_busy_row()
        self.m.snapshot_state = self.w.real_snapshot_state
        racing = r"""
import os as _os, sqlite3 as _sqlite3, sys as _sys
_fsync, _raced = _os.fsync, []
def _racing_fsync(fd):
    _fsync(fd)
    if _sys.argv[1] == 'snapshot' and not _raced:
        _raced.append(fd)
        cx = _sqlite3.connect(_os.path.join(_sys.argv[2], 'kilnd.db'))
        cx.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        cx.close()
_os.fsync = _racing_fsync
"""
        self.m.ACCOUNT_CHILD = racing + self.m.ACCOUNT_CHILD
        self.upgrade(2)
        self.assertEqual(os.path.getsize(state + '/kilnd.db-wal'), 0, 'the race happened')
        self.assertEqual(self.immutable_rows(state + '/kilnd.db'), [('cp-wal-only', 'capturing')])
        self.assertIn('kilnd.service has 1 busy checkpoints: cp-wal-only (capturing)',
                      '\n'.join(self.messages))

    def test_snapshot_refuses_a_hot_journal(self):
        """A writer killed mid-transaction leaves a hot journal and a half-written database,
        which only a rollback the read-only copy can't make would undo: the copy is refused."""
        state = self.scratch + '/hot'
        os.mkdir(state, 0o700)
        subprocess.run([sys.executable, '-I', '-c', """if 1:
            import os, sqlite3, sys
            path = sys.argv[1] + '/kilnd.db'
            db = sqlite3.connect(path)
            db.execute('CREATE TABLE checkpoints (id TEXT PRIMARY KEY, state TEXT)')
            db.executemany('INSERT INTO checkpoints VALUES (?, ?)',
                           [('cp-%04d' % n + 'x' * 400, 'ready') for n in range(3000)])
            db.commit()
            db.close()
            os.chmod(path, 0o600)
            db = sqlite3.connect(path, isolation_level=None)
            db.execute('PRAGMA cache_size = 5')
            db.execute('PRAGMA cache_spill = 1')
            db.execute('BEGIN')
            db.execute("UPDATE checkpoints SET state = 'capturing' || hex(randomblob(8))")
            os._exit(0)
            """, state], check=True)
        self.assertGreater(os.path.getsize(state + '/kilnd.db-journal'), 0)
        with closing(sqlite3.connect('file:%s/kilnd.db?immutable=1' % state, uri=True)) as db:
            self.assertIn('capturing', {r[0][:9] for r in db.execute('SELECT state FROM checkpoints')},
                          'the main file alone is half-written')
        with self.assertRaisesRegex(RuntimeError, 'readonly'):
            self.w.real_snapshot_state('kilnd', state, self.scratch + '/snapshot')

    @staticmethod
    def wal_database(directory, schema, prefix):
        """A database whose second committed row is only in its WAL, its writer gone."""
        os.mkdir(directory, 0o700)
        subprocess.run([sys.executable, '-I', '-c', """if 1:
            import os, sqlite3, sys
            path, schema, prefix = sys.argv[1:]
            db = sqlite3.connect(path + '/kilnd.db', isolation_level=None)
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('PRAGMA wal_autocheckpoint=0')
            db.execute('PRAGMA user_version=' + schema)
            db.execute('CREATE TABLE payload (value TEXT)')
            db.execute('INSERT INTO payload VALUES (?)', (prefix + '-main',))
            db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            db.execute('INSERT INTO payload VALUES (?)', (prefix + '-wal',))
            for name in ('kilnd.db', 'kilnd.db-wal', 'kilnd.db-shm'):
                os.chmod(path + '/' + name, 0o600)
            os._exit(0)
            """, directory, str(schema), prefix], check=True)

    @staticmethod
    def payload(state):
        with closing(sqlite3.connect(state + '/kilnd.db')) as db:
            return db.execute('SELECT value FROM payload ORDER BY rowid').fetchall()

    def crashing_child(self, step):
        """The account child, killed just after its step'th unlink, fsync or rename."""
        return ('import os as _os\n'
                '_steps = [0]\n'
                'def _step(real):\n'
                '    def wrapped(*args, **kwargs):\n'
                '        try:\n'
                '            return real(*args, **kwargs)\n'
                '        finally:\n'
                '            _steps[0] += 1\n'
                '            if _steps[0] == %d:\n'
                '                _os._exit(97)\n'
                '    return wrapped\n'
                '_os.unlink, _os.fsync, _os.replace = map(_step, (_os.unlink, _os.fsync, _os.replace))\n'
                % step) + self.m.ACCOUNT_CHILD

    def restore_crash_matrix(self, legacy):
        """Recheck 2 H2: kill the restore after each of its steps, then retry from the journal;
        every retry gives the snapshot's rows. legacy is an old journal's DB+WAL snapshot."""
        m, child = self.m, self.m.ACCOUNT_CHILD
        m.restore_state = self.w.real_restore_state
        os.makedirs(m.TXN_DIR, exist_ok=True)
        snapshot, live = self.scratch + '/old-snapshot', self.scratch + '/live'
        self.wal_database(self.scratch + '/old', 15, 'old')
        if legacy:
            shutil.copytree(self.scratch + '/old', snapshot)
        else:
            self.w.real_snapshot_state('unused', self.scratch + '/old', snapshot)
        self.assertEqual(sorted(os.listdir(snapshot)),
                         ['kilnd.db', 'kilnd.db-shm', 'kilnd.db-wal'] if legacy else ['kilnd.db'])
        self.wal_database(self.scratch + '/new', 16, 'new')
        kept = {'account': 'unused', 'state': live, 'schema': 15, 'snapshot': snapshot}
        step, crashed = 0, True
        while crashed:
            shutil.rmtree(live, ignore_errors=True)
            shutil.copytree(self.scratch + '/new', live)
            journal = {'started': False, 'instances': {'kilnd.service': kept}}
            m.write_json(m.JOURNAL, journal)
            real = m.restore_state
            if step:
                m.ACCOUNT_CHILD = self.crashing_child(step)
            else:
                # The marker is durable before the child starts: a crash there is redone too.
                m.restore_state = mock.Mock(side_effect=RuntimeError('killed before the child'))
            crashed = True
            try:
                m.restore_instance('kilnd.service', kept, journal)
                crashed = False
            except RuntimeError:
                pass
            finally:
                m.ACCOUNT_CHILD, m.restore_state = child, real
            if crashed:
                journal = m.read_json(m.JOURNAL)
                self.assertTrue(journal['restoring']['kilnd.service'], 'step %d' % step)
                m.restore_instance('kilnd.service', kept, journal)
            self.assertEqual(self.payload(live), [('old-main',), ('old-wal',)], 'step %d' % step)
            self.assertEqual(m.read_json(m.JOURNAL)['restoring'], {}, 'step %d' % step)
            self.assertFalse([n for n in os.listdir(live) if n.endswith('.restore')])
            step += 1
        self.assertGreater(step, 5)

    def test_a_legacy_wal_restore_killed_after_any_step_is_redone(self):
        self.restore_crash_matrix(legacy=True)

    def test_a_single_file_restore_killed_after_any_step_is_redone(self):
        self.restore_crash_matrix(legacy=False)

    def test_a_restore_after_serving_sets_the_newer_state_aside_once(self):
        m, child = self.m, self.m.ACCOUNT_CHILD
        m.restore_state = self.w.real_restore_state
        m.snapshot_state = self.w.real_snapshot_state
        os.makedirs(m.TXN_DIR, exist_ok=True)
        self.wal_database(self.scratch + '/old', 15, 'old')
        self.wal_database(self.scratch + '/live', 16, 'new')
        kept = {'account': 'unused', 'state': self.scratch + '/live', 'schema': 15,
                'snapshot': self.scratch + '/old'}
        journal = {'started': True, 'instances': {'kilnd.service': kept}}
        m.write_json(m.JOURNAL, journal)
        m.ACCOUNT_CHILD = self.crashing_child(5)
        with self.assertRaises(RuntimeError):
            m.restore_instance('kilnd.service', kept, journal)
        m.ACCOUNT_CHILD = child
        m.restore_instance('kilnd.service', kept, m.read_json(m.JOURNAL))
        self.assertEqual(self.payload(kept['state']), [('old-main',), ('old-wal',)])
        aside = os.listdir(m.FAILED_DIR)
        self.assertEqual(len(aside), 1, 'the redo copies nothing aside')
        self.assertEqual(self.payload(os.path.join(m.FAILED_DIR, aside[0], 'kilnd.service')),
                         [('new-main',), ('new-wal',)])

    def forget_identity(self, unit='kilnd.service'):
        with closing(sqlite3.connect(self.w.state[unit] + '/kilnd.db')) as db, db:
            db.execute('DELETE FROM daemon_identity')

    def unenroll(self):
        self.w.save_rows([])
        self.before_rows = []

    def test_snapshot_identity_matching_the_enrollment_is_journaled(self):
        captured = self.journal_at_replacing()
        self.upgrade()
        self.assertEqual(captured['instances']['kilnd.service']['instance'],
                         self.w.identity('kilnd.service'))
        self.assertEqual(captured['init'], 0, 'no init-state before the replacement')

    def test_snapshot_identity_without_enrollment_is_journaled(self):
        self.unenroll()
        captured = self.journal_at_replacing()
        self.upgrade()
        for unit in ('kilnd.service', INSTANCE):
            self.assertEqual(captured['instances'][unit]['instance'], self.w.identity(unit))
            self.assertIn('checkpoints', captured['instances'][unit])
        self.assertEqual(captured['init'], 0, 'no init-state before the replacement')

    def test_no_identity_and_no_enrollment_with_checkpoints_refuses(self):
        """Recheck H3: the identity is never read from the live state, which may be another."""
        self.unenroll()
        self.forget_identity()
        steered = '2' * 32
        self.swap_after_snapshot(steered)
        os.mkdir(self.m.CHECKPOINTS_ROOT, 0o700)
        os.mkdir(self.m.CHECKPOINTS_ROOT + '/' + steered, 0o700)
        open(self.m.CHECKPOINTS_ROOT + '/' + steered + '/outside-sentinel', 'w').close()
        inventoried = []
        real_inventory = self.m.checkpoint_inventory
        self.m.checkpoint_inventory = lambda i: inventoried.append(i) or real_inventory(i)
        self.assertEqual(self.command('upgrade', '--bin-dir', self.w.new,
                                      '--deploy-dir', self.w.deploy), 2)
        self.assertIn('kilnd.service has checkpoint state but records no instance ID; start '
                      'kilnd once so it records one, then retry', '\n'.join(self.messages))
        self.assertEqual(inventoried, [])
        self.assertFalse([c for c in self.w.calls if c[:1] == ('run',) and 'init-state' in c])
        self.assertEqual(self.w.images(), {i: 'old' for i in self.m.IMAGES})

    def test_no_identity_with_enrollment_and_checkpoints_refuses(self):
        self.forget_identity()
        self.upgrade(2)
        self.assertIn('kilnd.service is enrolled as %s, but its state records no instance ID; '
                      'start kilnd once and retry' % self.w.identity('kilnd.service'),
                      '\n'.join(self.messages))

    def test_no_identity_before_checkpoints_proceeds_without_inventory(self):
        self.unenroll()
        self.w.write_schema('kilnd.service', 14)
        with closing(sqlite3.connect(self.w.state['kilnd.service'] + '/kilnd.db')) as db, db:
            db.executescript('DROP TABLE checkpoints; DROP TABLE checkpoint_pins; '
                             'DROP TABLE daemon_identity;')
        captured = self.journal_at_replacing()
        self.upgrade()
        kept = captured['instances']['kilnd.service']
        self.assertIsNone(kept['instance'])
        self.assertNotIn('checkpoints', kept, 'nothing to inventory, or compare after a rollback')
        self.assertEqual(captured['init'], 0, 'no init-state before the replacement')
        self.assertEqual(self.w.images(), {i: 'new' for i in self.m.IMAGES})

    def test_inventory_does_not_follow_an_ancestor_link(self):
        """Recheck H4: the walk starts at /, so no component above the registry is followed."""
        instance = self.w.identity('kilnd.service')
        outside = self.scratch + '/outside'
        os.makedirs(outside + '/runs/.checkpoints/' + instance, 0o700)
        os.chmod(outside, 0o755)
        os.chmod(outside + '/runs', 0o755)
        open(outside + '/runs/.checkpoints/' + instance + '/outside-sentinel', 'w').close()
        os.symlink(outside, self.scratch + '/kiln')
        self.m.CHECKPOINTS_ROOT = self.scratch + '/kiln/runs/.checkpoints'
        with self.assertRaises(OSError):
            self.m.checkpoint_inventory(instance)
        self.upgrade(2)
        self.assertIn('cannot inventory the checkpoint artifacts of kilnd.service',
                      '\n'.join(self.messages))

    def mounts(self, *extra):
        """/ and at most the scratch filesystem's own mount point, then extra lines."""
        write_mountinfo(self.m.MOUNTINFO, self.scratch, extra)

    def mount_at(self, path, root='/', number=9, **line):
        return mountinfo_line(number, path.replace(' ', '\\040'), os.stat(path), root, **line)

    def btrfs_var(self, root='/@var', subvol='/@var', ino=256, fstype='btrfs'):
        """scratch/var as a Btrfs subvolume mounted by itself: stat gives a subvolume its own
        device, never mountinfo's, so the line's device is another one."""
        var = self.scratch + '/var'
        self.fake_fstat(var, ino=ino)
        self.mounts(self.mount_at(var, root=root, fstype=fstype, device='0:9999', options=(
            'rw,relatime,ssd,space_cache=v2,subvolid=257' + (',subvol=' + subvol if subvol else ''))))

    def test_an_empty_flag_off_node_on_a_btrfs_subvolume_upgrades(self):
        """Recheck 2 H4: /var a Btrfs subvolume rooted at /@var, no checkpoint rows, no
        registry. The upgrade proceeds as it would on any other filesystem."""
        self.assertFalse(os.path.exists(self.m.CHECKPOINTS_ROOT))
        self.btrfs_var()
        self.upgrade()
        self.assertEqual(self.w.images(), {i: 'new' for i in self.m.IMAGES})

    def test_inventory_reads_a_registry_on_a_btrfs_subvolume(self):
        os.mkdir(self.artifact_dir() + '/cp-a')
        self.btrfs_var()
        self.assertEqual([e['name'] for e in self.m.checkpoint_inventory(
            self.w.identity('kilnd.service'))], ['cp-a'])

    def test_inventory_refuses_what_only_looks_like_a_btrfs_subvolume(self):
        instance = self.w.identity('kilnd.service')
        self.artifact_dir()
        for what, shape in (
                ('a btrfs bind mount of a subdirectory', dict(root='/@var/sub')),
                ('a btrfs root with no subvol=', dict(subvol=None)),
                ('a btrfs subvol= other than the root', dict(subvol='/@other')),
                ('a btrfs root that is not a subvolume root', dict(ino=257)),
                ('an ext4 bind mount', dict(root='/sub', subvol=None, fstype='ext4')),
                ('a subvol= on another filesystem', dict(fstype='ext4'))):
            self.btrfs_var(**shape)
            with self.assertRaisesRegex(OSError, 'var is a mount point', msg=what):
                self.m.checkpoint_inventory(instance)
        self.upgrade(2)
        self.assertIn('cannot inventory the checkpoint artifacts of kilnd.service',
                      '\n'.join(self.messages))

    def test_inventory_refuses_a_bind_mount_on_the_way(self):
        instance = self.w.identity('kilnd.service')
        self.artifact_dir()
        ancestor = self.scratch + '/var'
        self.mounts(self.mount_at(ancestor, root='/elsewhere'))
        with self.assertRaisesRegex(OSError, 'var is a mount point'):
            self.m.checkpoint_inventory(instance)
        # The top of a stack is what the path reaches.
        self.mounts(self.mount_at(ancestor), self.mount_at(ancestor, root='/elsewhere'))
        with self.assertRaisesRegex(OSError, 'var is a mount point'):
            self.m.checkpoint_inventory(instance)
        self.upgrade(2)
        self.assertIn('cannot inventory the checkpoint artifacts of kilnd.service',
                      '\n'.join(self.messages))

    def test_inventory_allows_one_whole_filesystem_mount_among_the_ancestors(self):
        instance = self.w.identity('kilnd.service')
        os.mkdir(self.artifact_dir() + '/cp-a')
        changes = device_changes(self.scratch)
        point = changes[0] if changes else self.scratch + '/var'
        lines = [mountinfo_line(1, '/', os.lstat('/')), self.mount_at(point)]
        with open(self.m.MOUNTINFO, 'w') as file:
            file.write(''.join(lines))
        self.assertEqual([e['name'] for e in self.m.checkpoint_inventory(instance)], ['cp-a'])
        for second in (self.scratch + '/var/lib', self.m.CHECKPOINTS_ROOT,
                       self.m.CHECKPOINTS_ROOT + '/' + instance):
            with open(self.m.MOUNTINFO, 'w') as file:
                file.write(''.join([*lines, self.mount_at(second)]))
            with self.assertRaisesRegex(OSError, 'is a mount point', msg=second):
                self.m.checkpoint_inventory(instance)

    def test_inventory_refuses_a_group_writable_ancestor(self):
        self.artifact_dir()
        os.chmod(self.scratch + '/var/lib', 0o775)
        with self.assertRaisesRegex(OSError, "var/lib is not root's, or others can write it"):
            self.m.checkpoint_inventory(self.w.identity('kilnd.service'))

    def test_inventory_refuses_an_ancestor_of_another_owner(self):
        self.artifact_dir()
        self.fake_fstat(self.scratch + '/var', uid=os.getuid() + 1)
        with self.assertRaisesRegex(OSError, "var is not root's, or others can write it"):
            self.m.checkpoint_inventory(self.w.identity('kilnd.service'))

    def test_inventory_refuses_without_mountinfo(self):
        self.artifact_dir()
        instance = self.w.identity('kilnd.service')
        self.m.MOUNTINFO = self.scratch + '/no-mountinfo'
        with self.assertRaises(FileNotFoundError):
            self.m.checkpoint_inventory(instance)
        self.upgrade(2)
        self.assertIn('cannot inventory the checkpoint artifacts of kilnd.service',
                      '\n'.join(self.messages))
        self.m.MOUNTINFO = self.scratch + '/mountinfo'
        with open(self.m.MOUNTINFO, 'w') as file:
            file.write('1 0 garbage\n')
        with self.assertRaisesRegex(OSError, 'cannot parse'):
            self.m.checkpoint_inventory(instance)

    def test_inventory_refuses_a_registry_path_that_is_not_plain(self):
        for root in ('var/lib/kiln/runs/.checkpoints', self.scratch + '/var/../var/lib/checkpoints',
                     self.scratch + '//var/lib/checkpoints', self.scratch + '/./var/lib/checkpoints'):
            self.m.CHECKPOINTS_ROOT = root
            with self.assertRaisesRegex(OSError, 'not a plain absolute path', msg=root):
                self.m.checkpoint_inventory(self.w.identity('kilnd.service'))


class Restore(Case):
    """B3D-02: a restore that fails keeps what it needs to try again."""

    def clear(self):
        self.w.faults.update(start=set(), flap=set(), unmask=0, refresh=False, restore=False)

    def retry(self):
        self.m.cmd_recover(argparse.Namespace(boot=False))

    def injected(self):
        return (('unmask', lambda: self.w.faults.update(unmask=2)),
                ('helper start', lambda: self.w.faults['start'].add('kilnd-helper.service')),
                ('helper socket start', lambda: self.w.faults['start'].add('kilnd-helper.socket')),
                ('daemon start', lambda: self.w.faults['start'].add('kilnd.service')),
                ('daemon that dies', lambda: self.w.faults['flap'].add('kilnd.service')))

    def test_close_keeps_the_record(self):
        for name, inject in self.injected():
            with self.subTest(name):
                window = self.m.Window()
                window.open()
                inject()
                errors = window.close()
                self.assertTrue(errors)
                self.assertTrue(os.path.exists(self.m.WINDOW_RECORD))
                self.assertEqual(self.m.read_json(self.m.WINDOW_RECORD)['stage'], 'restored')
                self.clear()
                self.retry()
                self.assert_clean(name)

    def test_add_instance_requires_recovery(self):
        for name, inject in self.injected():
            with self.subTest(name):
                self.w.save_rows(self.before_rows)
                real_enroll = self.m.enroll

                def faulty_enroll(*args, **kwargs):
                    inject()
                    return real_enroll(*args, **kwargs)
                self.m.enroll = faulty_enroll
                with self.assertRaises(self.m.RecoveryRequired):
                    self.m.cmd_add_instance(self.w.add_args())
                self.m.enroll = real_enroll
                self.assert_recovery_kept()
                self.clear()
                self.retry()
                self.assert_clean(name)
                self.assertFalse(os.path.exists(self.m.WINDOW_RECORD))

    def test_add_instance_failure_with_a_failed_restore_says_so(self):
        real_enroll = self.m.enroll

        def failing(*_args, **_kwargs):
            self.w.faults['start'].add('kilnd.service')
            raise RuntimeError('enrollment failed')
        self.m.enroll = failing
        with self.assertRaises(self.m.RecoveryRequired):
            self.m.cmd_add_instance(self.w.add_args())
        self.m.enroll = real_enroll
        self.assert_recovery_kept()

    def test_upgrade_rollback_requires_recovery(self):
        for name, inject in self.injected():
            with self.subTest(name):
                self.w.faults['refresh'] = True
                inject()
                with self.assertRaises(self.m.RecoveryRequired):
                    self.m.cmd_upgrade(self.w.upgrade_args())
                self.assert_recovery_kept(journal=True)
                self.assertTrue(self.m.read_json(self.m.JOURNAL)['rolled_back'])
                self.assertEqual(self.w.images(), {i: 'old' for i in self.m.IMAGES})
                # A second failure keeps it all, and nothing new can begin in the meantime.
                with self.assertRaises(self.m.RecoveryRequired):
                    self.m.cmd_upgrade(self.w.upgrade_args())
                self.assert_recovery_kept(journal=True)
                self.clear()
                self.w.calls.clear()
                self.retry()
                self.assert_prior(name)
                self.assertFalse([c for c in self.w.calls if c[0] == 'stop'],
                                 'a retry must not stop what did come back')

    def test_failed_file_restore_keeps_everything_and_leaves_units_down(self):
        self.w.faults.update(refresh=True, restore=True)
        with self.assertRaises(self.m.RecoveryRequired):
            self.m.cmd_upgrade(self.w.upgrade_args())
        self.assert_recovery_kept(journal=True)
        self.assertFalse(self.m.read_json(self.m.JOURNAL).get('rolled_back'))
        self.assertEqual(self.m.read_json(self.m.WINDOW_RECORD)['stage'], 'open')
        self.assertFalse(any(self.w.load_units().values()))
        self.assertFalse(self.m.activation_safe())
        self.clear()
        self.retry()
        self.assert_prior()

    def test_exit_status_is_distinct(self):
        self.w.faults['refresh'] = True
        self.w.faults['start'].add('kilnd.service')
        self.m.require_root = lambda: None
        self.m.sys.argv = ['kilnd-maintenance', 'upgrade', '--bin-dir', self.w.new,
                           '--deploy-dir', self.w.deploy]
        with self.assertRaises(SystemExit) as caught:
            self.m.main()
        self.assertEqual(caught.exception.code, 3)
        self.assertEqual(self.m.RECOVERY_REQUIRED, 3)

    def test_success_leaves_no_record(self):
        self.m.cmd_upgrade(self.w.upgrade_args())
        self.assert_clean()
        self.assertEqual(self.w.images(), {i: 'new' for i in self.m.IMAGES})


class Reboot(Case):
    """B3D-01: a reboot at any step comes back whole, with nothing having started early."""

    UNDONE = ('marker:', 'masked:', 'journal:', 'phase:replacing', 'rename:1', 'rename:2',
              'rename:3', 'rename:4', 'rename:5', 'rename:6', 'unit-file:', 'phase:refreshed',
              'migrated:1', 'migrated:2', 'phase:starting', 'settling:')
    KEPT = ('phase:committed', 'discarded:')

    def test_marker_comes_before_anything(self):
        order = []
        real_write, real_mask = self.m.write_json, self.m.mask_runtime
        self.m.write_json = lambda path, value: (order.append(path), real_write(path, value))[1]
        self.m.mask_runtime = lambda units: (order.append('mask'), real_mask(units))[1]
        self.m.cmd_upgrade(self.w.upgrade_args())
        self.assertEqual(order[0], self.m.WINDOW_RECORD)
        self.assertEqual(self.w.calls[0], ('run', self.w.calls[0][1], '--version'))
        fence = self.w.calls.index(('fence',))
        first_change = next(i for i, c in enumerate(self.w.calls) if c[0] in ('stop', 'daemon-reload'))
        self.assertLess(fence, first_change)

    def test_every_phase_is_undone(self):
        for point in self.UNDONE:
            with self.subTest(point):
                self.w.faults['migrate'] = True
                self.assertEqual(self.w.crash_at(
                    point, lambda: self.m.cmd_upgrade(self.w.upgrade_args())), CRASHED, point)
                self.assertTrue(os.path.exists(self.m.WINDOW_RECORD))
                self.w.reboot()
                self.assertFalse(self.m.activation_safe() and point != 'marker:', point)
                self.w.boot()
                self.assert_prior(point)

    def test_a_crash_that_served_keeps_what_it_held(self):
        self.w.faults['migrate'] = True
        self.assertEqual(self.w.crash_at(
            'settling:', lambda: self.m.cmd_upgrade(self.w.upgrade_args())), CRASHED)
        self.w.reboot()
        self.w.boot()
        self.assert_prior()
        kept = os.listdir(self.m.FAILED_DIR)
        self.assertTrue(kept, 'a daemon may have served on the newer schema')

    def test_a_crash_before_serving_keeps_nothing(self):
        self.w.faults['migrate'] = True
        self.assertEqual(self.w.crash_at(
            'migrated:2', lambda: self.m.cmd_upgrade(self.w.upgrade_args())), CRASHED)
        self.w.reboot()
        self.w.boot()
        self.assert_prior()
        self.assertFalse(os.path.exists(self.m.FAILED_DIR))

    def test_after_commit_stays_committed(self):
        for point in self.KEPT:
            with self.subTest(point):
                self.assertEqual(self.w.crash_at(
                    point, lambda: self.m.cmd_upgrade(self.w.upgrade_args())), CRASHED, point)
                self.w.reboot()
                self.w.boot()
                self.assert_clean(point)
                self.assertEqual(self.w.images(), {i: 'new' for i in self.m.IMAGES})
                self.w.reset_to_old()

    def test_add_instance_windows(self):
        for point in ('marker:', 'masked:', 'enrolled:'):
            with self.subTest(point):
                self.assertEqual(self.w.crash_at(
                    point, lambda: self.m.cmd_add_instance(self.w.add_args())), CRASHED, point)
                self.assertTrue(os.path.exists(self.m.WINDOW_RECORD))
                self.w.reboot()
                self.w.boot()
                self.assert_clean(point)

    def test_a_unit_running_but_not_enabled_still_comes_back(self):
        self.assertEqual(self.w.crash_at(
            'rename:3', lambda: self.m.cmd_upgrade(self.w.upgrade_args())), CRASHED)
        self.w.reboot()
        self.m.cmd_recover(argparse.Namespace(boot=True))
        # Boot starts only what's enabled, and INSTANCE isn't. The marker is still there for it.
        units = self.w.load_units()
        for unit in HELD:
            units[unit] = True
        self.w.save_units(units)
        self.assertEqual(self.m.read_json(self.m.WINDOW_RECORD)['stage'], 'restored')
        self.assertTrue(os.path.exists(self.m.JOURNAL))
        self.m.cmd_recover(argparse.Namespace(boot=False))
        self.assert_prior()

    def test_guard_fails_closed_when_it_cannot_restore(self):
        self.assertEqual(self.w.crash_at(
            'phase:refreshed', lambda: self.m.cmd_upgrade(self.w.upgrade_args())), CRASHED)
        self.w.reboot()
        self.w.faults['restore'] = True
        with self.assertRaises(self.m.RecoveryRequired):
            self.m.cmd_recover(argparse.Namespace(boot=True))
        self.assertFalse(self.m.activation_safe())
        self.assertEqual(self.m.read_json(self.m.WINDOW_RECORD)['stage'], 'open')
        self.assertFalse(any(self.w.load_units().values()))
        self.assertFalse([c for c in self.w.calls if c[0] in ('start', 'stop')])
        self.w.faults['restore'] = False
        self.m.cmd_recover(argparse.Namespace(boot=False))
        self.assert_prior()

    def test_guard_refuses_while_a_command_holds_the_lock(self):
        window = self.m.Window()
        window.open()
        lock = os.open(self.m.LOCK, os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, lock)
        fcntl.flock(lock, fcntl.LOCK_EX)
        with self.assertRaises(self.m.Refused):
            self.m.cmd_recover(argparse.Namespace(boot=True))

    def test_guard_refuses_anything_past_its_ordering(self):
        window = self.m.Window()
        window.open()
        self.w.reboot()
        units = self.w.load_units()
        units['kilnd.service'] = True
        self.w.save_units(units)
        with self.assertRaises(RuntimeError):
            self.m.cmd_recover(argparse.Namespace(boot=True))
        self.assertTrue(os.path.exists(self.m.WINDOW_RECORD))

    def test_guard_passes_with_nothing_to_do(self):
        self.m.cmd_recover(argparse.Namespace(boot=True))
        self.assertEqual(self.w.calls, [])

    def test_a_boot_start_failure_keeps_the_marker(self):
        self.assertEqual(self.w.crash_at(
            'rename:3', lambda: self.m.cmd_upgrade(self.w.upgrade_args())), CRASHED)
        self.w.reboot()
        self.m.cmd_recover(argparse.Namespace(boot=True))
        self.w.faults['start'].add('kilnd.service')
        with self.assertRaises(self.m.RecoveryRequired):
            self.m.cmd_recover(argparse.Namespace(boot=False))
        self.assertTrue(os.path.exists(self.m.WINDOW_RECORD))
        self.assertTrue(os.path.exists(self.m.JOURNAL))
        self.w.reboot()
        self.w.faults['start'].clear()
        self.w.boot()
        self.assert_prior()

    def test_needs_transaction_sees_a_marker(self):
        self.m.find_policy = lambda: None
        self.w.save_units({u: True for u in HELD})
        self.assertFalse(self.m.needs_transaction())
        self.m.Window().open()
        self.assertTrue(self.m.needs_transaction())


class Fence(unittest.TestCase):
    """The units themselves, and installing them onto a node from before them."""

    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix='kilnd-fence-')
        self.addCleanup(shutil.rmtree, self.scratch, ignore_errors=True)
        self.w = World(self.scratch)

    @staticmethod
    def unit(name):
        with open(os.path.join(REPO, 'deploy', name)) as file:
            lines = [line.strip() for line in file if not line.startswith('#')]
        return lines

    def directive(self, name, key):
        found = []
        for line in self.unit(name):
            if line.startswith(key + '='):
                found.extend(line.split('=', 1)[1].split())
        return found

    def test_every_activation_unit_requires_and_follows_the_guard(self):
        for name in self.w.m.GUARDED_UNITS:
            self.assertIn(GUARD, self.directive(name, 'Requires'), name)
            self.assertIn(GUARD, self.directive(name, 'After'), name)

    def test_guard_is_early_and_stays_passed(self):
        before = self.directive(GUARD, 'Before')
        for name in ('kilnd-helper.socket', 'kilnd-helper.service', 'kilnd.service', 'sockets.target'):
            self.assertIn(name, before)
        self.assertEqual(self.directive(GUARD, 'DefaultDependencies'), ['no'])
        self.assertEqual(self.directive(GUARD, 'Type'), ['oneshot'])
        self.assertEqual(self.directive(GUARD, 'RemainAfterExit'), ['yes'])
        self.assertEqual(sorted(self.directive(GUARD, 'WantedBy')), ['multi-user.target', 'sockets.target'])
        self.assertEqual(self.directive(GUARD, 'ExecStart'),
                         ['/usr/local/libexec/kilnd/upgrade.sh', '--recover', '--boot'])

    def test_marker_path_matches_the_units(self):
        finish = 'kilnd-maintenance-finish.service'
        self.assertEqual(self.directive(finish, 'ConditionPathExists'),
                         ['/var/lib/kilnd-helper/maintenance.json'])
        self.assertEqual(load().WINDOW_RECORD, '/var/lib/kilnd-helper/maintenance.json')

    def install(self):
        m = load()
        m.systemctl = self.w.systemctl
        for name in ('BIN', 'UNIT_DIR', 'FENCE_DIR', 'WINDOW_RECORD'):
            setattr(m, name, getattr(self.w.m, name))
        deploy = os.path.join(REPO, 'deploy')
        return m, deploy

    def test_a_node_from_before_the_guard_gets_it_from_a_drop_in(self):
        m, deploy = self.install()
        with open(self.w.etc + '/kilnd.service', 'w') as file:
            file.write('[Unit]\nDescription=older\n')
        m.install_fence(deploy)
        dropin = self.w.etc + '/kilnd.service.d/10-maintenance-guard.conf'
        with open(dropin) as file:
            text = file.read()
        self.assertIn('Requires=' + GUARD, text)
        self.assertIn('After=' + GUARD, text)
        self.assertTrue(os.access(m.FENCE_DIR + '/kilnd-maintenance.py', os.X_OK))
        self.assertTrue(os.access(m.FENCE_DIR + '/upgrade.sh', os.X_OK))
        self.assertIn(('enable', '--quiet', *m.FENCE_UNITS), self.w.calls)
        self.assertIn(('start', GUARD), self.w.calls)
        # And once the unit carries the dependency itself, the drop-in goes.
        shutil.copy(os.path.join(deploy, 'kilnd.service'), self.w.etc + '/kilnd.service')
        m.install_fence(deploy)
        self.assertFalse(os.path.exists(dropin))

    def test_no_template_means_no_drop_in(self):
        m, deploy = self.install()
        os.unlink(self.w.etc + '/kilnd@.service')
        m.install_fence(deploy)
        self.assertFalse(os.path.exists(self.w.etc + '/kilnd@.service.d'))

    def test_an_incomplete_deploy_directory_is_refused(self):
        m, _deploy = self.install()
        with self.assertRaises(m.Refused):
            m.install_fence(self.w.deploy)


if __name__ == '__main__':
    unittest.main(verbosity=1)
