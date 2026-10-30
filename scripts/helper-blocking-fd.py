#!/usr/bin/env python3
"""PH0-1: hostile descriptor flags/backpressure cannot stall the root helper.

Run as kilnd against the installed service. Derived from the Daybreak Phase 0
PoC; both the legacy descriptor injection and the v3 handoff are exercised.
No sandbox is needed for the stdin/deadline attack.
"""
import array
import fcntl
import json
import os
import socket
import struct
import time

HELPER = '/run/kilnd-helper/helper.sock'


def request(operation, timeout_ms=1000, passed=(), version=3):
    control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    control.settimeout(4)
    control.connect(HELPER)
    rights = [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
               array.array('i', [s.fileno() for s in passed]))] if passed else []
    control.sendmsg([b'K'], rights)
    body = json.dumps(dict(version=version, timeout_ms=timeout_ms,
                           deadline_ns=time.monotonic_ns() + timeout_ms * 1_000_000,
                           operation={'kiln': operation})).encode()
    control.sendall(struct.pack('!I', len(body)) + body)
    return control


def handoff(control, count):
    marker, ancillary, flags, _ = control.recvmsg(1, socket.CMSG_SPACE(3 * 4))
    assert marker == b'K' and flags == 0, (marker, flags)
    descriptors = []
    for level, kind, data in ancillary:
        assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
        values = array.array('i'); values.frombytes(data)
        descriptors.extend(values)
    assert len(descriptors) == count, descriptors
    if count:
        control.sendall(b'K')
    return [socket.socket(fileno=fd) for fd in descriptors]


def exact(control, n):
    result = b''
    while len(result) < n:
        part = control.recv(n - len(result))
        assert part, 'short control reply'
        result += part
    return result


def probe():
    started = time.monotonic()
    with request('ls') as control:
        handoff(control, 0)
        size = struct.unpack('!I', exact(control, 4))[0]
        result = json.loads(exact(control, size))
        assert 'listed' in result, result
        assert control.recv(1) == b''
    assert time.monotonic() - started < 1, 'independent request stalled'


def call(operation):
    with request(operation, timeout_ms=120_000) as control:
        control.settimeout(125)
        handoff(control, 0)
        size = struct.unpack('!I', exact(control, 4))[0]
        result = json.loads(exact(control, size))
        assert control.recv(1) == b''
        return result


def output_backpressure():
    # Use a directly managed fixture so the test leaves no API history rows.
    result = call({'create': {'spec': dict(image='alpine', memory_bytes=64 << 20,
        cpu_millis=1000, pids=64, disk_bytes=16 << 20, network='none',
        read_only_root=False, writable_paths=[], labels={})}})
    assert 'created' in result, result
    backend = result['created']
    try:
        operation = {'exec': dict(id=backend, stdin_bytes=0, max_output=1 << 20,
            argv=['sh', '-c', 'head -c 1048576 /dev/zero; head -c 1048576 /dev/zero >&2'])}
        with request(operation, timeout_ms=10_000) as control:
            peers = handoff(control, 3)
            try:
                for peer in peers:
                    flags = fcntl.fcntl(peer, fcntl.F_GETFL)
                    fcntl.fcntl(peer, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
                peers[0].shutdown(socket.SHUT_WR)
                end = time.monotonic() + 8
                while True:
                    try:
                        assert peers[1].recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT), 'missing output'
                        break
                    except BlockingIOError:
                        assert time.monotonic() < end, 'execution never produced output'
                        time.sleep(.01)
                probe()
                # Never drain either output. The transfer timer must still fire.
                control.settimeout(3)
                assert control.recv(1) == b'', 'backpressure must not claim successful transfer'
                probe()
            finally:
                for peer in peers:
                    peer.close()
    finally:
        assert call({'rm': {'id': backend}}) == 'removed'


def main():
    assert os.geteuid() != 0, 'run as kilnd, not root'
    operation = {'exec': {'id': 'abcd', 'argv': ['true'],
                          'stdin_bytes': 32, 'max_output': 1024}}
    # The old injection is refused, for both the old and current version.
    pairs = [socket.socketpair() for _ in range(3)]
    try:
        for version in (1, 2, 3):
            with request(operation, passed=[p[0] for p in pairs], version=version) as control:
                try:
                    assert control.recv(1) == b''
                except ConnectionResetError:
                    pass
            probe()
    finally:
        for pair in pairs:
            for endpoint in pair:
                endpoint.close()

    # Repeat with the v3 endpoints after SCM_RIGHTS receipt. None is the
    # helper's own open file description. Hold stdin open beyond its deadline.
    for cancel in (False, True):
        with request(operation, timeout_ms=600) as control:
            peers = handoff(control, 3)
            try:
                for peer in peers:
                    flags = fcntl.fcntl(peer, fcntl.F_GETFL)
                    assert flags & os.O_NONBLOCK
                    fcntl.fcntl(peer, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
                peers[0].sendall(b'A' * 32)
                probe()
                started = time.monotonic()
                if cancel:
                    control.sendall(b'\x01')
                control.settimeout(1.2)
                assert control.recv(1) == b'', 'stdin failure must not claim success'
                assert time.monotonic() - started < (0.5 if cancel else 1.1)
                probe()
            finally:
                for peer in peers:
                    peer.close()
    output_backpressure()
    print('PASS PH0-1: injection rejected; mutated flags, listener, deadline, cancellation and output-backpressure progress')


if __name__ == '__main__':
    main()
