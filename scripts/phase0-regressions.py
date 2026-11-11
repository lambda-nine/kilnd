#!/usr/bin/env python3
"""Privileged installed-service checks. Run as root in the shared kiln VM."""
import array
import grp
import json
import os
import pwd
import re
import socket
import stat
import struct
import subprocess
import time

assert os.geteuid() == 0, 'run with sudo python3 -I scripts/phase0-regressions.py'
KILND = pwd.getpwnam('kilnd')
USERS = [f'kilnd-check-{os.getpid()}-{n}' for n in (1, 2)]
IDS = []
UNITS = []
STATE = f'kilnd-retention-{os.getpid()}'
SOCKET = f'/run/{STATE}/kilnd.sock'

def run(args, *, uid=None, ok=True, input=None, env=None):
    def credentials():
        account = pwd.getpwnam(uid)
        # The account's real groups: its supplementary kilnd-helper is what reaches the socket.
        os.setgroups(os.getgrouplist(account.pw_name, account.pw_gid))
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
    p = subprocess.run(args, text=True, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=180, preexec_fn=credentials if uid else None, env=env)
    if ok:
        assert p.returncode == 0, (args, p.returncode, p.stdout, p.stderr)
    return p

def ctl(*args, uid=None, aux=False, ok=True, env=None):
    return run(['kilndctl', *(['--socket', SOCKET] if aux else []), *args], uid=uid, ok=ok, env=env)

def eventually(check, seconds=20):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if check():
            return
        time.sleep(.1)
    raise AssertionError('condition did not become true')

def missing(*args, uid=None, aux=False):
    p = ctl(*args, uid=uid, aux=aux, ok=False)
    assert p.returncode != 0 and 'notfound' in (p.stdout + p.stderr).lower().replace('_', ''), (args, p)
    assert 'permissiondenied' not in (p.stdout + p.stderr).lower().replace('_', '')
    return True

def execute(id, word, *, aux=False):
    p = ctl('exec', '--verbose', id, '--', 'printf', word, aux=aux)
    assert p.stdout == word, p
    return re.search(r'ex-[0-9a-f]{16}', p.stderr)[0]

def helper_probe(payload, *, uid, marker=b'K', descriptors=(), size=None):
    # All inputs are synthetic; the UID switch is performed in an isolated child.
    source = r'''
import array, json, os, socket, struct, sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(4)
s.connect('/run/kilnd-helper/helper.sock')
message=bytes.fromhex(sys.argv[1]); marker=bytes.fromhex(sys.argv[2]); n=int(sys.argv[3])
fds=[os.open('/dev/null',os.O_RDONLY) for _ in range(n)]
anc=[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',fds))] if fds else []
try:
    s.sendmsg([marker],anc)
    s.sendall(struct.pack('>I',int(sys.argv[4]))+message)
    result=s.recv(1)
    assert result==b'', repr(result)
except (BrokenPipeError, ConnectionResetError): pass
finally:
    for fd in fds: os.close(fd)
'''
    run(['python3', '-I', '-c', source, payload.hex(), marker.hex(), str(len(descriptors)), str(size if size is not None else len(payload))], uid=uid)

def start_aux(suffix, zero=False, expect_integrity_failure=False, retain=False):
    unit=f'{STATE}-{suffix}'
    UNITS.append(unit)
    run(['systemd-run', '--quiet', '--unit', unit, '--property=User=kilnd', '--property=Group=kilnd',
         '--property=NoNewPrivileges=yes', '--property=CapabilityBoundingSet=',
         f'--property=StateDirectory={STATE}', '--property=StateDirectoryMode=0700',
         f'--property=RuntimeDirectory={STATE}', '--property=RuntimeDirectoryMode=0750',
         '/usr/local/bin/kilnd', '--socket', SOCKET, '--state-dir', f'/var/lib/{STATE}',
         '--execution-max-count', '1000' if retain else '0' if zero else '1',
         '--deleted-sandbox-max-count', '1000' if retain else '0' if zero else '1',
         '--prune-interval-secs', '1', '--output-storage', 'full' if retain else 'metadata'])
    if expect_integrity_failure:
        eventually(lambda: run(['systemctl', 'is-failed', unit], ok=False).stdout.strip() == 'failed')
        diagnostic = run(['journalctl', '-u', unit, '--no-pager']).stdout
        assert 'degraded accounting: reservation integrity mismatch' in diagnostic, diagnostic
    else:
        eventually(lambda: ctl('health', aux=True, ok=False).returncode == 0)
    return unit

try:
    print('1. Daemon UID/capabilities and private files', flush=True)
    pid=run(['systemctl','show','-p','MainPID','--value','kilnd']).stdout.strip()
    status=dict(line.split(':',1) for line in open(f'/proc/{pid}/status') if ':' in line)
    assert [int(v) for v in status['Uid'].split()] == [KILND.pw_uid]*4
    for field in ('CapEff','CapPrm','CapInh','CapAmb','CapBnd'):
        assert int(status[field].strip(),16)==0, (field,status[field])
    for path, mode in [('/var/lib/kilnd',0o700),('/var/lib/kilnd/kilnd.db',0o600),('/run/kilnd',0o750),('/run/kilnd/kilnd.sock',0o660)]:
        m=os.lstat(path); assert m.st_uid==KILND.pw_uid and stat.S_IMODE(m.st_mode)==mode, (path,m)
    for path, mode in [('/run/kilnd-helper',0o750),('/run/kilnd-helper/helper.sock',0o660)]:
        m=os.lstat(path); assert m.st_uid==0 and m.st_gid==grp.getgrnam('kilnd-helper').gr_gid and stat.S_IMODE(m.st_mode)==mode, (path,m)
    print('2. Different real peer UIDs cannot see or mutate ownership', flush=True)
    for user in USERS:
        run(['useradd','--system','--gid','kilnd','--groups','kilnd-helper','--home-dir','/nonexistent','--shell','/usr/sbin/nologin',user])
    id=ctl('create','--memory','64M','--disk','16M',uid=USERS[0]).stdout.strip(); IDS.append(id)
    p=ctl('exec','--verbose',id,'--','printf','owner-output',uid=USERS[0]); assert p.stdout=='owner-output'
    ex=re.search(r'ex-[0-9a-f]{16}',p.stderr)[0]
    for args in [('get',id),('exec',id,'--','true'),('rm',id),('execution',ex)]:
        missing(*args,uid=USERS[1])
    assert id not in ctl('ls','--all',uid=USERS[1]).stdout
    assert id in ctl('ls','--all',uid=USERS[0]).stdout and id in ctl('ls','--all').stdout
    assert ctl('execution',ex,uid=USERS[0]).stdout=='owner-output'
    ctl('rm',id,uid=USERS[0]); IDS.remove(id)
    # The helper's inherited family filter must permit both network setup and
    # libc DNS resolution. AF_UNIX/AF_NETLINK alone breaks hostname allowlists.
    for network in (['--net','full'], ['--allow','example.com:443']):
        assert ctl('run','--memory','64M','--disk','16M',*network,'--','printf','network-ok').stdout=='network-ok'
    print('3. Helper rejects group members, root and malformed service-UID requests', flush=True)
    helper_pid=run(['systemctl','show','-p','MainPID','--value','kilnd-helper']).stdout.strip()
    helper_status=dict(line.split(':',1) for line in open(f'/proc/{helper_pid}/status') if ':' in line)
    assert int(helper_status['NoNewPrivs'])==1
    assert int(helper_status['Seccomp'])==2, helper_status['Seccomp']
    families=run(['systemctl','show','-p','RestrictAddressFamilies','--value','kilnd-helper']).stdout.split()
    assert set(families)=={'AF_UNIX','AF_NETLINK','AF_INET'}, families
    # Phase 0's set plus B4's CAP_SETPCAP (8), CAP_SYS_CHROOT (18) and CAP_MKNOD (27) for the
    # Firecracker jailer. Only S keeps those three: kiln children and L/P/M/K drop them.
    for field in ('CapEff','CapPrm','CapBnd'):
        assert int(helper_status[field].strip(),16)==0x2010eb|1<<8|1<<18|1<<27, (field,helper_status[field])
    assert int(helper_status['CapAmb'].strip(),16)==0x80, helper_status['CapAmb']
    before=len(os.listdir(f'/proc/{helper_pid}/fd'))
    valid={'version':3,'timeout_ms':1000,'deadline_ns':time.monotonic_ns()+1_000_000_000,'operation':{'kiln':'ls'}}
    body=json.dumps(valid).encode()
    helper_probe(body,uid=USERS[0]); helper_probe(body,uid='root')
    for _ in range(16):
        helper_probe(b'{}',uid='kilnd',marker=b'X')
        helper_probe(b'',uid='kilnd',size=(2<<20)+1)
        req={**valid,'deadline_ns':time.monotonic_ns()+1_000_000_000,'operation':{'kiln':{'rm':{'id':'../escape'}}}}
        helper_probe(json.dumps(req).encode(),uid='kilnd')
        req['operation']={'kiln':{'exec':{'id':'abcd','argv':['true'],'stdin_bytes':0,'max_output':0}}}
        helper_probe(json.dumps(req).encode(),uid='kilnd')
        req['operation']['kiln']['exec']['max_output']=1024
        helper_probe(json.dumps(req).encode(),uid='kilnd',descriptors=(1,2,3))
        helper_probe(json.dumps(req).encode(),uid='kilnd',descriptors=(1,2,3,4))
    assert run(['systemctl','show','-p','MainPID','--value','kilnd-helper']).stdout.strip()==helper_pid
    eventually(lambda: len(os.listdir(f'/proc/{helper_pid}/fd')) <= before+1)
    ctl('health')
    run(['python3','-I',os.path.join(os.path.dirname(__file__),'helper-blocking-fd.py')],uid='kilnd')
    print('4. Periodic retention and metadata output', flush=True)
    first=start_aux('first')
    sb=ctl('create','--memory','64M','--disk','16M',aux=True).stdout.strip(); IDS.append(sb)
    old=execute(sb,'secret-history',aux=True)
    assert ctl('execution',old,aux=True).stdout==''
    newest=execute(sb,'latest',aux=True)
    eventually(lambda: ctl('execution',old,aux=True,ok=False).returncode!=0)
    ctl('execution',newest,aux=True)
    p=subprocess.Popen(['kilndctl','--socket',SOCKET,'exec','--verbose',sb,'--','sleep','3'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    def running():
        m=re.search(r'(ex-[0-9a-f]{16})\s+running',ctl('get',sb,aux=True).stdout)
        return m[1] if m else None
    eventually(running)
    pending=running(); time.sleep(1.2)
    ctl('execution',pending,aux=True)
    p.communicate(timeout=10); assert p.returncode==0
    ctl('rm',sb,aux=True); IDS.remove(sb)
    sb2=ctl('create','--memory','64M','--disk','16M',aux=True).stdout.strip(); IDS.append(sb2)
    ctl('rm',sb2,aux=True); IDS.remove(sb2)
    eventually(lambda: ctl('get',sb,aux=True,ok=False).returncode!=0)
    live=ctl('create','--memory','64M','--disk','16M',aux=True).stdout.strip(); IDS.append(live)
    live_ex=execute(live,'live',aux=True)
    run(['systemctl','stop',first])
    print('5. Startup prune retains charged rows and deletes eligible history', flush=True)
    seed=r'''
import sqlite3,sys
c=sqlite3.connect(sys.argv[1])
# Preserve the genuine Store-produced marker and membership. A raw SQL insert
# cannot update membership authority; startup must refuse this fixture.
backup=sqlite3.connect(sys.argv[1]+'.fixture-backup')
c.backup(backup); backup.close()
c.execute("PRAGMA foreign_keys=ON")
c.execute("""INSERT INTO sandboxes (id,backend,state,spec,created_at_ms,updated_at_ms,list_seq,owner_uid,
    accounting_kind,reserved_memory_bytes,reserved_disk_bytes,reserved_pids,reserved_host_cpu_millis,
    reserved_virtual_cpu_slots,reserved_host_pids,host_spec_sha256,guest_exec_spec_sha256)
    SELECT 'sb-1111111111111111',backend,'failed',spec,0,0,(SELECT MAX(list_seq)+1 FROM sandboxes),0,
    'legacy',reserved_memory_bytes,reserved_disk_bytes,reserved_pids,reserved_host_cpu_millis,
    reserved_virtual_cpu_slots,reserved_host_pids,host_spec_sha256,guest_exec_spec_sha256
    FROM sandboxes WHERE id=?""", (sys.argv[2],))
c.execute('UPDATE history_sequence SET value=(SELECT MAX(list_seq) FROM sandboxes)')
c.commit()
'''
    run(['python3','-I','-c',seed,f'/var/lib/{STATE}/kilnd.db',live],uid='kilnd')
    start_aux('startup-invalid', zero=True, expect_integrity_failure=True)
    restore=r'''
import os,sqlite3,sys
backup=sqlite3.connect(sys.argv[1]+'.fixture-backup')
dest=sqlite3.connect(sys.argv[1]); backup.backup(dest)
dest.close(); backup.close(); os.unlink(sys.argv[1]+'.fixture-backup')
'''
    run(['python3','-I','-c',restore,f'/var/lib/{STATE}/kilnd.db'],uid='kilnd')
    start_aux('startup',zero=True)
    missing('get',sb2,aux=True); missing('execution',live_ex,aux=True)
    ctl('get',live,aux=True); missing('get','sb-1111111111111111',aux=True)
    assert 'sandboxes 1/' in ctl('health',aux=True).stdout
    ctl('rm',live,aux=True); IDS.remove(live)
    print('6. Exec env canary: no value in argv, root environ, logs, responses or history', flush=True)
    # API additions M3b, design 4.2 and its L1 test: a secret-looking value sent as default
    # env and as Exec env reaches the workload and nothing else. kilndctl takes both by
    # name from its own environment, so no command line here carries them either. History
    # is the auxiliary daemon's database, queried with SQL after it stops: logical columns
    # only; WAL and free pages are deliberately not checked.
    canary_started = time.time()
    run(['systemctl', 'stop', f'{STATE}-startup'])
    # Full retention and output, so a leak into history cannot be pruned away first.
    unit = start_aux('canary', retain=True)
    features = ctl('health', aux=True).stdout
    secret_default = f'CANARY-{os.urandom(8).hex()}'
    secret_exec = f'CANARY-{os.urandom(8).hex()}'
    secrets = (secret_default, secret_exec)
    caller = {**os.environ, 'KILND_CANARY_DEFAULT': secret_default, 'KILND_CANARY_EXEC': secret_exec}
    if 'exec_env' not in features.split():
        # A kiln without exec options (bit 0x20): kilndctl refuses before sending.
        refused = ctl('create', '--default-env', 'KILND_CANARY_DEFAULT', aux=True, ok=False, uid=USERS[0], env=caller)
        assert refused.returncode != 0 and 'sandbox_default_env' in refused.stderr, refused
        print('   SKIP positive checks: the installed kiln lacks exec options (bit 0x20)', flush=True)
    else:
        sb = ctl('create', '--memory', '64M', '--disk', '16M', '--default-env', 'KILND_CANARY_DEFAULT',
                 aux=True, uid=USERS[0], env=caller).stdout.strip(); IDS.append(sb)
        # The workload proves it got both values by their digests, so neither is on any
        # argv, including the execution's own (which history keeps).
        digest = lambda value: __import__('hashlib').sha256(value.encode()).hexdigest()
        args = ['kilndctl', '--socket', SOCKET, 'exec', '--verbose', '--cwd', '/workspace',
                '--env', 'KILND_CANARY_EXEC', sb, '--', 'sh', '-c',
                'h() { printf %s "$1" | sha256sum | cut -d" " -f1; }; '
                '[ "$(h "$KILND_CANARY_EXEC")" = "$1" ] && [ "$(h "$KILND_CANARY_DEFAULT")" = "$2" ] '
                '&& [ "$(pwd)" = /workspace ] && sleep 3 && printf canary-ok',
                'x', digest(secret_exec), digest(secret_default)]
        account = pwd.getpwnam(USERS[0])
        def as_caller():
            os.setgroups(os.getgrouplist(account.pw_name, account.pw_gid)); os.setgid(account.pw_gid); os.setuid(account.pw_uid)
        child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                 env=caller, preexec_fn=as_caller)
        # Every process's argv, and the environment of every root or kilnd process (the
        # helper, the kiln CLI, PID 1 and the daemon), while the command runs. The
        # workload's own environment holds the values by design; it is not root's.
        scanned = 0
        deadline = time.monotonic() + 2.5
        while time.monotonic() < deadline:
            for entry in os.listdir('/proc'):
                if not entry.isdigit():
                    continue
                try:
                    cmdline = open(f'/proc/{entry}/cmdline', 'rb').read()
                    uid = os.stat(f'/proc/{entry}').st_uid
                    environ = open(f'/proc/{entry}/environ', 'rb').read() if uid in (0, KILND.pw_uid) else b''
                except (FileNotFoundError, ProcessLookupError, PermissionError):
                    continue
                scanned += 1
                for secret in secrets:
                    assert secret.encode() not in cmdline, (entry, cmdline)
                    assert secret.encode() not in environ, (entry, 'environ')
            time.sleep(.2)
        out, err = child.communicate(timeout=30)
        assert child.returncode == 0 and out == 'canary-ok', (child.returncode, out, err)
        assert scanned > 0
        ex = re.search(r'ex-[0-9a-f]{16}', err)[0]
        shown = ctl('get', sb, aux=True).stdout + ctl('ls', '--all', aux=True).stdout
        shown += ctl('execution', ex, aux=True).stdout + ctl('execution', ex, aux=True).stderr
        assert 'KILND_CANARY_DEFAULT' in shown and 'KILND_CANARY_EXEC' in shown, shown
        # A cwd the sandbox cannot enter is a typed failure, never "/".
        missing_cwd = ctl('exec', '--cwd', '/var/lib/kilnd-helper', sb, '--', 'true', aux=True, ok=False)
        assert missing_cwd.returncode == 125 and 'cwd_not_found' in missing_cwd.stderr, missing_cwd
        shown += missing_cwd.stdout + missing_cwd.stderr
        # The kiln CLI refuses an unsealed or non-memfd options descriptor before any exec byte.
        backend = re.search(r'backend:\s+kiln\s+(\S+)', ctl('get', sb, aux=True).stdout)[1]
        for kind in ('file', 'unsealed-memfd'):
            if kind == 'file':
                options = os.open('/tmp', os.O_RDWR | os.O_TMPFILE, 0o600)
            else:
                options = os.memfd_create('kilnd-test-options', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            os.write(options, bytes.fromhex('4b494c4e4f50540001000000180000000000000000000000'))
            pairs = [socket.socketpair() for _ in range(4)]
            fds = [pair[1].fileno() for pair in pairs] + [options]
            p = subprocess.run(['kiln', 'exec', '--protocol=1', f'--status-fd={fds[0]}', f'--stdin-fd={fds[1]}',
                                f'--stdout-fd={fds[2]}', f'--stderr-fd={fds[3]}', f'--exec-options-fd={fds[4]}',
                                backend, '--', 'touch', '/workspace/options-ran'],
                               pass_fds=fds, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            for pair in pairs:
                pair[1].close()
            frame = b''
            while chunk := pairs[0][0].recv(4096):
                frame += chunk
            for pair in pairs:
                pair[0].close()
            os.close(options)
            # Outcome 2 (runtime failure), cleanup 1 (no child started), kind 1
            # (InvalidRequest), stage 1 (Validate).
            assert p.returncode != 0 and frame[16] == 2 and frame[18] == 1, (kind, p, frame.hex())
            assert struct.unpack('<HH', frame[24:28]) == (1, 1), (kind, frame.hex())
        assert ctl('exec', sb, '--', 'sh', '-c', 'test ! -e /workspace/options-ran', aux=True).returncode == 0
        ctl('rm', sb, aux=True); IDS.remove(sb)
        for secret in secrets:
            assert secret not in shown
    run(['systemctl', 'stop', unit])
    logs = run(['journalctl', '--no-pager', '--since', f'@{int(canary_started)}', '-u', unit, '-u', 'kilnd-helper']).stdout
    history = r'''
import sqlite3,sys
c=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True)
hits=[]
for (t,) in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
    cur=c.execute(f'SELECT * FROM "{t}"'); cols=[d[0] for d in cur.description]
    for row in cur:
        for col,v in zip(cols,row):
            b=v.encode() if isinstance(v,str) else v if isinstance(v,bytes) else b''
            if any(s.encode() in b for s in sys.argv[2:]): hits.append(f'{t}.{col}')
print(sorted(set(hits)))
'''
    hits = run(['python3', '-I', '-c', history, f'/var/lib/{STATE}/kilnd.db', *secrets], uid='kilnd').stdout.strip()
    assert hits == '[]', hits
    for secret in secrets:
        assert secret not in logs, 'journal'
    print('PASS Phase 0',flush=True)
finally:
    for id in IDS:
        ctl('rm',id,aux=True,ok=False); ctl('rm',id,ok=False)
    for unit in UNITS:
        run(['systemctl','stop',unit],ok=False)
        run(['systemctl','reset-failed',unit],ok=False)
    run(['rm','-rf',f'/var/lib/{STATE}',f'/run/{STATE}'],ok=False)
    for user in USERS:
        run(['userdel',user],ok=False)
