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
                     root + '/bin', root + '/tmpfiles', root + '/libexec'):
            os.makedirs(path)
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
        m.snapshot_state = self.snapshot_state
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
        if op == 'checkpoints':
            return {'instance': None, 'busy': []}
        with open(state + '/kilnd.db') as file:
            return {'schema': int(file.read())}

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

            def counted(*_args):
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
        self.scratch = tempfile.mkdtemp(prefix='kilnd-maint-')
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

    def as_account(self, _account, op, state, *_args, **_kwargs):
        # Run the real account code unprivileged; only the UID switch is faked.
        result = subprocess.run([sys.executable, '-I', '-c', self.m.ACCOUNT_CHILD,
                                 op or 'schema', state], capture_output=True, text=True, check=False)
        if result.returncode:
            raise RuntimeError(result.stderr.strip())
        return json.loads(result.stdout)


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
        path = os.path.join(self.m.CHECKPOINTS_ROOT, self.w.identity(unit))
        os.makedirs(path, exist_ok=True)
        return path

    def upgrade(self, code=None):
        with mock.patch.object(sys, 'argv', ['kilnd-maintenance', 'upgrade', '--bin-dir',
                                            self.w.new, '--deploy-dir', self.w.deploy]):
            self.m.require_root = lambda: None
            if code is None:
                self.m.main()
            else:
                with self.assertRaises(SystemExit) as caught:
                    self.m.main()
                self.assertEqual(caught.exception.code, code)
        self.assert_clean()
        if code is not None:
            self.assertEqual(self.w.images(), {i: 'old' for i in self.m.IMAGES})
            self.assertEqual(self.w.load_rows(), self.before_rows)
            for unit in self.w.state:
                self.assertEqual(self.w.schema(unit), 16)
            for name, path in self.m.MANAGED_FILES.items():
                with open(path) as file:
                    self.assertEqual(file.read(), 'old ' + name)

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
        self.assertIsNone(captured[0][INSTANCE]['checkpoints'])
        self.assertEqual([e['name'] for e in kept['checkpoints']], ['cp-a', 'cp-b', 'cp-link'])
        for entry in kept['checkpoints']:
            meta = os.lstat(directory + '/' + entry['name'])
            self.assertEqual(entry, {'name': entry['name'], 'type': stat.S_IFMT(meta.st_mode),
                                     'st_ino': meta.st_ino, 'st_mtime_ns': meta.st_mtime_ns})

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

    def test_rollback_added_artifact_is_exit3_and_complete(self):
        directory = self.artifact_dir()
        self.fail_after_start(lambda: os.mkdir(directory + '/cp-new'))
        self.upgrade(3)
        self.assertIn("added 'cp-new'", '\n'.join(self.messages))
        self.assertIn('see docs/checkpoints.md', '\n'.join(self.messages))
        self.assertTrue(os.path.isdir(directory + '/cp-new'), 'never swept')

    def test_rollback_missing_artifact_is_exit3_and_complete(self):
        directory = self.artifact_dir()
        os.mkdir(directory + '/cp-old')
        self.fail_after_start(lambda: os.rmdir(directory + '/cp-old'))
        self.upgrade(3)
        self.assertIn("missing 'cp-old'", '\n'.join(self.messages))

    def test_rollback_changed_artifact_is_exit3_and_complete(self):
        directory = self.artifact_dir()
        os.mkdir(directory + '/cp-old')
        meta = os.stat(directory + '/cp-old')
        self.fail_after_start(lambda: os.utime(directory + '/cp-old',
                                             ns=(meta.st_atime_ns, meta.st_mtime_ns + 1)))
        self.upgrade(3)
        self.assertIn("changed 'cp-old'", '\n'.join(self.messages))

    def test_rollback_unchanged_inventory_is_exit1(self):
        os.mkdir(self.artifact_dir() + '/cp-old')
        self.fail_after_start(lambda: None)
        self.upgrade(1)
        self.assertFalse(any('checkpoint artifacts' in m for m in self.messages))

    def test_rollback_empty_directory_appeared_is_exit3(self):
        directory = os.path.join(self.m.CHECKPOINTS_ROOT, self.w.identity('kilnd.service'))
        self.fail_after_start(lambda: os.makedirs(directory))
        self.upgrade(3)
        self.assertIn("changed '<directory>'", '\n'.join(self.messages))

    def test_boot_rollback_logs_artifact_difference(self):
        directory = self.artifact_dir()
        self.w.faults['migrate'] = True
        self.assertEqual(self.w.crash_at('settling:', lambda: self.m.cmd_upgrade(self.w.upgrade_args())),
                         CRASHED)
        os.mkdir(directory + '/cp-new')
        self.w.reboot()
        self.m.cmd_recover(argparse.Namespace(boot=True))
        self.assertIn("added 'cp-new'", '\n'.join(self.messages))
        self.assertEqual(self.m.read_json(self.m.WINDOW_RECORD)['stage'], 'restored')
        self.messages.clear()
        with self.assertRaises(SystemExit) as caught:
            self.m.cmd_recover(argparse.Namespace(boot=False))
        self.assertEqual(caught.exception.code, 3, 'the first command after boot reports it')
        self.assertIn("added 'cp-new'", '\n'.join(self.messages))
        self.m.cmd_recover(argparse.Namespace(boot=False))
        self.assert_clean()
        self.assertEqual(self.w.images(), {i: 'old' for i in self.m.IMAGES})

    def test_recover_after_a_killed_upgrade_with_artifact_difference_is_exit3(self):
        directory = self.artifact_dir()
        self.w.faults['migrate'] = True
        self.assertEqual(self.w.crash_at('settling:', lambda: self.m.cmd_upgrade(self.w.upgrade_args())),
                         CRASHED)
        os.mkdir(directory + '/cp-new')
        with self.assertRaises(SystemExit) as caught:
            self.m.cmd_recover(argparse.Namespace(boot=False))
        self.assertEqual(caught.exception.code, 3)
        self.assertIn("added 'cp-new'", '\n'.join(self.messages))
        self.assert_clean()
        self.assertEqual(self.w.images(), {i: 'old' for i in self.m.IMAGES})
        self.m.cmd_recover(argparse.Namespace(boot=False))

    def test_account_reads_are_readonly_and_do_not_follow_db_links(self):
        state = self.w.state['kilnd.service']
        path = state + '/kilnd.db'
        before = os.stat(path)
        self.w.as_account(None, 'checkpoints', state)
        after = os.stat(path)
        self.assertEqual((before.st_mtime_ns, before.st_size), (after.st_mtime_ns, after.st_size))
        os.rename(path, path + '.real')
        os.symlink(path + '.real', path)
        with self.assertRaises(RuntimeError):
            self.w.as_account(None, 'checkpoints', state)

    def test_inventory_does_not_follow_instance_link(self):
        directory = self.artifact_dir()
        os.rmdir(directory)
        os.symlink(self.scratch, directory)
        with self.assertRaises(OSError):
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
