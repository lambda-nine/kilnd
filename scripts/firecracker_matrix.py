"""Shared runner for B6's real-chain scenario scripts (firecracker-regressions.py and
firecracker-crash-matrix.py). Run in the kiln Lima VM as your user, under the shared VM
lock, with the inputs scripts/b4-vm-tests.sh documents. It runs the named privileged
tests through b4-vm-tests.sh (which builds, installs the test helper image and the
daemon, and always runs scripts/b4-vm-cleanup.py), collects each test's `B6 matrix:` (or B7) line
and libtest result, and writes matrix.json and matrix.md. It fails if any expected
scenario is missing, failed or produced no matrix line. Nothing here touches the installed
kilnd, its database or production paths."""
import argparse
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
# The kiln VM freezes at about 2 h 02 min of uptime (Nov 3, 2026); a phase must start
# fresh enough to finish before that.
MAX_UPTIME_MINUTES = 90


def uptime_minutes():
    with open('/proc/uptime') as f:
        return float(f.read().split()[0]) / 60


def run(title, prefix, scenarios, argv=None):
    parser = argparse.ArgumentParser(description=title)
    parser.add_argument('--evidence', required=True,
                        help='directory for the transcripts, logs and matrix (created)')
    parser.add_argument('--only', action='append', default=[],
                        help='run only these test names (repeatable); the matrix then '
                             'checks only those')
    parser.add_argument('--ignore-uptime', action='store_true',
                        help='skip the 90-minute VM uptime check')
    args = parser.parse_args(argv)
    if not args.ignore_uptime and uptime_minutes() > MAX_UPTIME_MINUTES:
        print(f'VM uptime is {uptime_minutes():.0f} min: restart the kiln VM first '
              f'(it freezes near 122 min)', file=sys.stderr)
        return 2
    expected = [s for s in scenarios if not args.only or s in args.only]
    unknown = [s for s in args.only if s not in scenarios]
    if unknown:
        print(f'unknown scenarios: {unknown}', file=sys.stderr)
        return 2
    evidence = os.path.abspath(args.evidence)
    os.makedirs(evidence, exist_ok=True)
    log_path = os.path.join(evidence, 'tests.log')
    results = {}
    started = time.time()
    # One b4-vm-tests.sh run per scenario: each gets a clean host from the cleanup
    # script, and a failure cannot leave state for the next.
    with open(log_path, 'w') as log:
        for name in expected:
            env = dict(os.environ, B6_EVIDENCE=evidence)
            t0 = time.time()
            proc = subprocess.run([os.path.join(HERE, 'b4-vm-tests.sh'), name], cwd=ROOT,
                                  env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  text=True)
            log.write(f'===== {name} =====\n{proc.stdout}\n')
            log.flush()
            passed = (proc.returncode == 0
                      and re.search(r'^test result: ok\. 1 passed', proc.stdout, re.M)
                      is not None)
            lines = [json.loads(m) for m in re.findall(r'^B[67] matrix: (\{.*\})$', proc.stdout,
                                                         re.M)]
            results[name] = {
                'passed': passed and len(lines) == 1,
                'exit': proc.returncode,
                'seconds': round(time.time() - t0, 1),
                'matrix': lines[0] if lines else None,
                'evidence': [l for l in proc.stdout.splitlines()
                             if l.startswith(('B6 evidence:', 'B5 evidence:'))],
            }
            print(f"{'PASS' if results[name]['passed'] else 'FAIL'} {name} "
                  f"({results[name]['seconds']} s)", flush=True)
    failed = [n for n, r in results.items() if not r['passed']]
    summary = {
        'title': title,
        'prefix': prefix,
        # The VM mounts the Mac's checkout under another owner, so git needs this to
        # read it at all.
        'commit': subprocess.run(['git', '-c', f'safe.directory={ROOT}', 'rev-parse', 'HEAD'],
                                 cwd=ROOT, capture_output=True, text=True).stdout.strip(),
        'started_unix': int(started),
        'seconds': round(time.time() - started, 1),
        'scenarios': results,
        'failed': failed,
    }
    with open(os.path.join(evidence, 'matrix.json'), 'w') as f:
        json.dump(summary, f, indent=2)
    with open(os.path.join(evidence, 'matrix.md'), 'w') as f:
        f.write(f'# {title}\n\nCommit `{summary["commit"]}`, {summary["seconds"]} s.\n\n')
        f.write('| Scenario | Result | Outcome |\n|---|---|---|\n')
        for name, r in results.items():
            m = r['matrix'] or {}
            outcome = json.dumps(m.get('outcome'), sort_keys=True).replace('|', '/')
            f.write(f"| {m.get('scenario', name)} | {'pass' if r['passed'] else 'FAIL'} "
                    f"({r['seconds']} s) | `{outcome}` |\n")
    print(f'{len(results) - len(failed)}/{len(results)} passed; '
          f'matrix in {evidence}/matrix.md')
    return 1 if failed else 0
