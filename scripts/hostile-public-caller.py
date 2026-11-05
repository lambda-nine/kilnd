#!/usr/bin/env python3
"""B6-BI-03's real-daemon regression: a hostile public caller cannot starve Health or
cleanup (Phase 1b B7 milestone 2).

Daybreak's PoC (reviews/poc-b6/public-connection-starvation.py) held 64 idle Unix
sockets that never sent the HTTP/2 preface and so took every connection slot; a new
Health, Get or Delete connection was then closed before authorization. This runs the
same attack against a real, running kilnd, harder: the hostile UID keeps all 64 open
for the whole victim phase, reconnecting each one the daemon closes. It passes only if

  - Health, GetSandbox and DeleteSandbox from another UID each succeed within their
    deadlines while the attack runs;
  - every hostile socket is closed by the daemon: those over the UID's share at
    accept, the admitted ones at the HTTP/2 preface deadline, and none outlives that
    deadline plus a small slack;
  - and the attack did hold slots (some socket stayed open until about the deadline),
    so the victim's success is not the attacker failing to connect.

Run as root in the VM. The hostile caller is --hostile-user (default nobody) with the
socket's group as its one supplementary group, so it passes the socket's filesystem
gate exactly as a permitted public caller would; the victim runs kilndctl as root.

    sudo python3 -I scripts/hostile-public-caller.py --socket /run/kilnd/kilnd.sock \\
        --kilndctl /usr/local/bin/kilndctl

Without --sandbox it creates one sandbox first (as the victim) and deletes it in the
victim phase. The last line is `B7 hostile: {json}`; the exit status is 0 on pass.
"""
import argparse
import json
import os
import pwd
import selectors
import socket
import subprocess
import sys
import time


def hold(args):
    """The hostile child: keep --count sockets open until stdin closes, reconnecting
    each one the daemon closes, then wait for the rest to be closed."""
    sel = selectors.DefaultSelector()
    opened = {}
    lifetimes = []
    failures = 0
    total = 0

    def connect():
        nonlocal failures, total
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            s.connect(args.socket)
        except OSError:
            failures += 1
            s.close()
            return
        s.setblocking(False)
        opened[s.fileno()] = (s, time.monotonic())
        sel.register(s, selectors.EVENT_READ)
        total += 1

    for _ in range(args.count):
        connect()
    print(json.dumps({'event': 'connected', 'count': len(opened)}), flush=True)
    os.set_blocking(0, False)
    sel.register(0, selectors.EVENT_READ)
    stopping = False
    end = None
    while True:
        if stopping and not opened:
            break
        if end is not None and time.monotonic() > end:
            break
        for key, _ in sel.select(timeout=0.05):
            if key.fd == 0:
                try:
                    data = os.read(0, 4096)
                except BlockingIOError:
                    continue
                if not data:
                    stopping = True
                    end = time.monotonic() + args.drain_seconds
                    sel.unregister(0)
                continue
            s, since = opened[key.fd]
            try:
                data = s.recv(4096)
            except BlockingIOError:
                continue
            except OSError:
                data = b''
            if data:
                # The server's own HTTP/2 settings; the attacker never answers.
                continue
            lifetimes.append(round(time.monotonic() - since, 3))
            sel.unregister(s)
            del opened[key.fd]
            s.close()
            if not stopping:
                connect()
    print(json.dumps({
        'event': 'done',
        'opened': total,
        'connect_failures': failures,
        'closed_by_daemon': len(lifetimes),
        'open_at_end': len(opened),
        'longest_s': max(lifetimes, default=0),
        'held_to_deadline': sum(1 for t in lifetimes if t >= args.held_floor),
    }), flush=True)
    return 0


def drop_to(user, extra_gid):
    account = pwd.getpwnam(user)

    def credentials():
        os.setgroups([extra_gid])
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
    return credentials


def ctl(args, *command, limit):
    started = time.monotonic()
    try:
        p = subprocess.run([args.kilndctl, '--socket', args.socket, *command],
                           capture_output=True, text=True, timeout=limit)
        code, out, err = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        code, out, err = 'timeout', '', f'no answer in {limit} s'
    return {'command': command[0], 'exit': code, 'seconds': round(time.monotonic() - started, 3),
            'limit': limit, 'stdout': out.strip()[-400:], 'stderr': err.strip()[-400:]}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest='mode')
    h = sub.add_parser('hold')
    h.add_argument('--socket', required=True)
    h.add_argument('--count', type=int, required=True)
    h.add_argument('--drain-seconds', type=float, required=True)
    h.add_argument('--held-floor', type=float, required=True)
    parser.add_argument('--socket', default='/run/kilnd/kilnd.sock')
    parser.add_argument('--kilndctl', default='kilndctl')
    parser.add_argument('--hostile-user', default='nobody')
    parser.add_argument('--connections', type=int, default=64)
    parser.add_argument('--sandbox', help='an existing sandbox the victim may Get and Delete')
    parser.add_argument('--preface-timeout', type=float, default=5.0,
                        help="the daemon's --connection-preface-timeout-ms, in seconds")
    parser.add_argument('--attack-seconds', type=float, default=8.0,
                        help='how long the attack runs before the victim calls')
    parser.add_argument('--delete-limit', type=float, default=60.0)
    args = parser.parse_args()
    if args.mode == 'hold':
        return hold(args)
    if os.geteuid() != 0:
        print('run as root: the hostile caller is another UID', file=sys.stderr)
        return 2

    result = {'socket': args.socket, 'hostile_user': args.hostile_user,
              'connections': args.connections, 'preface_timeout_s': args.preface_timeout}
    baseline = ctl(args, 'health', limit=5)
    if baseline['exit'] != 0:
        print(f'FAIL: baseline Health failed: {baseline}', file=sys.stderr)
        return 1
    sandbox = args.sandbox
    if sandbox is None:
        created = ctl(args, 'create', '--net', 'none', limit=120)
        if created['exit'] != 0:
            print(f'FAIL: could not create the victim sandbox: {created}', file=sys.stderr)
            return 1
        sandbox = created['stdout'].split()[-1]
    result['sandbox'] = sandbox

    slack = 3.0
    child = subprocess.Popen(
        [sys.executable, '-I', os.path.abspath(__file__), 'hold', '--socket', args.socket,
         '--count', str(args.connections),
         '--drain-seconds', str(args.preface_timeout + 10),
         '--held-floor', str(args.preface_timeout * 0.8)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        preexec_fn=drop_to(args.hostile_user, os.stat(args.socket).st_gid))
    try:
        first = json.loads(child.stdout.readline())
        result['hostile_connected'] = first['count']
        # Let the attack settle into its steady state: the admitted sockets held, the
        # rest reconnecting as fast as the daemon closes them.
        time.sleep(args.attack_seconds)
        victim = [
            ctl(args, 'health', limit=5),
            ctl(args, 'get', sandbox, limit=5),
            ctl(args, 'rm', sandbox, limit=args.delete_limit),
        ]
        result['victim'] = victim
        child.stdin.close()
        done = json.loads(child.stdout.readline())
        child.wait(timeout=30)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
    result['hostile'] = done
    result['after'] = ctl(args, 'health', limit=5)

    failures = []
    if result['hostile_connected'] != args.connections:
        failures.append(f"the hostile caller connected only {result['hostile_connected']}")
    for call in victim + [result['after']]:
        if call['exit'] != 0:
            failures.append(f"{call['command']} failed: {call['exit']} {call['stderr']}")
    if done['open_at_end'] != 0:
        failures.append(f"{done['open_at_end']} hostile sockets were never closed")
    if done['longest_s'] > args.preface_timeout + slack:
        failures.append(f"a hostile socket lived {done['longest_s']} s, past the deadline")
    if done['held_to_deadline'] == 0:
        failures.append('no hostile socket held a slot until the deadline: no attack')
    result['passed'] = not failures
    result['failures'] = failures
    print('B7 hostile: ' + json.dumps(result, sort_keys=True))
    for failure in failures:
        print(f'FAIL: {failure}', file=sys.stderr)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
