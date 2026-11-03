#!/usr/bin/env python3
"""Removes everything scripts/b4-vm-tests.sh's privileged tests may own, then fails if
anything remains: VMMs, loop devices backed in the work tree, mounts under the jail
base, cgroups, store objects, bundles and test directories. Run as root in the VM.
Only the B4 test namespaces are touched; nothing else is killed or detached.

Since B6 it also removes the isolated Firecracker test deployment the session test makes
(deploy/firecracker-test/deployment.json): its transient kilnd unit, account, state
directory and test helper root. Production's kilnd, its account and /var/lib/kilnd are
never touched."""
import json
import os
import shutil
import signal
import subprocess
import sys
import time

JAIL_BASE = '/var/lib/kilnd-helper/jails'
WORK_BASE = '/var/lib/kilnd-helper/work'
CGROUP = '/sys/fs/cgroup/kilnd-firecracker'
OPT = '/opt/kilnd'
DEPLOYMENT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'deploy',
                          'firecracker-test', 'deployment.json')


def test_deployment():
    with open(DEPLOYMENT) as f:
        deployment = json.load(f)
    if deployment.get('deployment') != 'isolated-test':
        raise SystemExit('not the isolated test deployment')
    kilnd = deployment['kilnd']
    for value in (kilnd['account'], kilnd['unit'], kilnd['state_dir'],
                  deployment['helper']['root']):
        if value in ('kilnd', 'kilnd.service', '/var/lib/kilnd', '/run/kilnd-helper'):
            raise SystemExit(f'refusing a production name: {value}')
    return kilnd['unit'], kilnd['account'], kilnd['state_dir'], deployment['helper']['root']


def account_exists(name):
    return subprocess.run(['id', name], capture_output=True).returncode == 0


def remove_test_deployment():
    unit, account, state_dir, helper_root = test_deployment()
    subprocess.run(['systemctl', 'stop', unit], capture_output=True)
    subprocess.run(['systemctl', 'reset-failed', unit], capture_output=True)
    shutil.rmtree(state_dir, ignore_errors=True)
    shutil.rmtree(helper_root, ignore_errors=True)
    if account_exists(account):
        subprocess.run(['userdel', account], check=False)
    subprocess.run(['groupdel', account], capture_output=True)
    problems = []
    state = subprocess.run(['systemctl', 'is-active', unit], capture_output=True,
                           text=True).stdout.strip()
    if state in ('active', 'activating', 'deactivating'):
        problems.append(f'unit {unit} {state}')
    if account_exists(account):
        problems.append(f'account {account}')
    for path in (state_dir, helper_root):
        if os.path.exists(path):
            problems.append(f'path {path}')
    return problems


def mounts():
    entries = []
    with open('/proc/self/mountinfo') as f:
        for line in f:
            fields = line.split(' ')
            entries.append(fields[4].replace('\\040', ' '))
    return entries


def cgroup_dirs():
    found = []
    for root, dirs, _ in os.walk(CGROUP, topdown=False):
        for d in dirs:
            found.append(os.path.join(root, d))
    return found


def kill_cgroups():
    if not os.path.isdir(CGROUP):
        return
    for path in cgroup_dirs() + [CGROUP]:
        try:
            with open(os.path.join(path, 'cgroup.kill'), 'w') as f:
                f.write('1')
        except OSError:
            pass
    time.sleep(0.5)
    for path in cgroup_dirs():
        try:
            os.rmdir(path)
        except OSError as error:
            print(f'cgroup {path}: {error}', file=sys.stderr)
    try:
        os.rmdir(CGROUP)
    except OSError as error:
        print(f'cgroup {CGROUP}: {error}', file=sys.stderr)


def loops():
    found = []
    for name in os.listdir('/sys/block'):
        if not name.startswith('loop'):
            continue
        try:
            with open(f'/sys/block/{name}/loop/backing_file') as f:
                backing = f.read().strip()
        except OSError:
            continue
        if backing.startswith(WORK_BASE + '/'):
            found.append((name, backing))
    return found


def main():
    # The daemon goes first: it is a helper client and must not race the teardown.
    deployment_problems = remove_test_deployment()
    kill_cgroups()
    for mount in sorted((m for m in mounts() if m.startswith(JAIL_BASE)), key=len, reverse=True):
        subprocess.run(['umount', mount], check=False)
    for name, _ in loops():
        subprocess.run(['losetup', '-d', f'/dev/{name}'], check=False)
    time.sleep(0.2)
    for path in [JAIL_BASE, WORK_BASE, OPT]:
        shutil.rmtree(path, ignore_errors=True)
    problems = list(deployment_problems)
    problems += [f'mount {m}' for m in mounts() if m.startswith(JAIL_BASE)]
    problems += [f'loop {n} -> {b}' for n, b in loops()]
    if os.path.exists(CGROUP):
        problems.append(f'cgroup {CGROUP}')
    for path in [JAIL_BASE, WORK_BASE, OPT]:
        if os.path.exists(path):
            problems.append(f'path {path}')
    out = subprocess.run(['pgrep', '-a', '-f', 'firecracker'], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if '--config-file /config.json' in line:
            problems.append(f'vmm {line}')
    if problems:
        print('B4 cleanup left resources behind:', *problems, sep='\n  ', file=sys.stderr)
        return 1
    print('B4 cleanup: no owned VMM, loop, mount, cgroup or file remains, and no B6 test '
          'deployment unit, account or directory')
    return 0


if __name__ == '__main__':
    sys.exit(main())
