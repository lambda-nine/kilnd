#!/usr/bin/env python3
"""Validate ledger references against Cargo/libtest registries and the suite's own run,
never source text: every compiled test ran, and every ledger test passed."""
import json
import re
import sys
from pathlib import Path

IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
PATH = IDENT + r"(?:::" + IDENT + r")*"
DOCTEST = re.compile(r"\S+\.rs - .+ \(line \d+\)(?: - [^:]+)?: test")
SUMMARY = re.compile(r"(\d+) tests?, (\d+) benchmarks?")
# Library, binary and doctest targets have distinct identities.
RUN = re.compile(r"Running (unittests \S+|tests/\S+) \(.*[/\\]deps/(" + IDENT + r")-[0-9a-f]+\)")

NOISE = re.compile(r"(?:Compiling|Finished) .+|Blocking waiting for file lock on (?:build directory|package cache)")
# libtest's default output (C6a recheck 1 HIGH 5): one group per binary, several per
# Doc-tests header, each test named once with its result.
GROUP = re.compile(r"running (\d+) tests?")
RESULT = re.compile(r"test (.+) \.\.\. (ok|ignored(?:, .+)?)")
SLOW = re.compile(r"test (.+) has been running for over \d+ seconds")
DONE = re.compile(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; "
                  r"(\d+) filtered out; finished in \d+(?:\.\d+)?s")

def binary(running, doc):
    return (running[2] + ("::bin" if running[1].startswith("unittests ")
            and running[1] != "unittests src/lib.rs" else "")) if running else doc[1] + "::doc"

def executed(text, errors):
    """Each test's result in the suite's own run, by the registry's names."""
    results, binaries, current, group, nested = {}, {}, None, None, 0
    for line in text.splitlines():
        line = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
        running, doc = RUN.fullmatch(line), re.fullmatch(r"Doc-tests (" + IDENT + r")", line)
        if running or doc:
            if group is not None or (current is not None and not binaries[current]):
                errors.append(f"unfinished run: {current}")
            current, group = binary(running, doc), None
            if current in binaries:
                errors.append(f"duplicate binary name in the run: {current}")
            binaries[current] = 0
        elif group is not None and nested and (RESULT.fullmatch(line) or SLOW.fullmatch(line)):
            pass  # A test's own child test binary, its stdout inherited: never a result.
        elif group is not None and (GROUP.fullmatch(line) or (nested and DONE.fullmatch(line))):
            nested += 1 if GROUP.fullmatch(line) else -1
        elif current is not None and group is None and (start := GROUP.fullmatch(line)):
            if binaries[current] and not current.endswith("::doc"):
                errors.append(f"a second test group: {current}")
            group = [int(start[1]), 0, 0]  # announced, passed, ignored
        elif group is not None and (result := RESULT.fullmatch(line)):
            name = current + "::" + result[1]
            if name in results:
                errors.append(f"ran twice: {name}")
            results[name] = "ok" if result[2] == "ok" else "ignored"
            group[1 if result[2] == "ok" else 2] += 1
        elif group is not None and SLOW.fullmatch(line):
            pass
        elif group is not None and (summary := DONE.fullmatch(line)):
            passed, failed, ignored, measured, filtered = map(int, summary.groups())
            if (passed, ignored, failed, measured, filtered) != (group[1], group[2], 0, 0, 0) \
                    or group[0] != group[1] + group[2]:
                errors.append(f"invalid or filtered run: {current}: {line}")
            group = None
            binaries[current] += 1
        elif line and not (current is None and NOISE.fullmatch(line)):
            errors.append(f"unparsable run line: {line}")
    if group is not None or nested or not binaries or not all(binaries.values()):
        errors.append("incomplete or empty run")
    return results, set(binaries)

def registry(text, errors):
    tests, binaries, current, count, doc_group = set(), set(), None, 0, None
    for line in text.splitlines():
        line = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()  # Cargo color, including CI.
        running, doc = RUN.fullmatch(line), re.fullmatch(r"Doc-tests (" + IDENT + r")", line)
        # Rustdoc lists merged and standalone doctests as separate groups under one header.
        if current is None and doc_group and (DOCTEST.fullmatch(line) or SUMMARY.fullmatch(line)):
            current, count = doc_group, 0
        if running or doc:
            if current is not None:
                errors.append(f"unfinished binary: {current}")
            current = binary(running, doc)
            if current in binaries:
                errors.append(f"duplicate binary name: {current}")
            binaries.add(current)
            count, doc_group = 0, None
        elif current is not None and (re.fullmatch(PATH + r": test", line) or (
                current.endswith("::doc") and DOCTEST.fullmatch(line))):
            name = current + "::" + line[:-6]
            if name in tests:
                errors.append(f"duplicate test: {name}")
            tests.add(name)
            count += 1
        elif current is not None and (summary := SUMMARY.fullmatch(line)):
            if count != int(summary[1]) or int(summary[2]):
                errors.append(f"invalid registry count: {current}: {line}")
            doc_group, current = current if current.endswith("::doc") else None, None
        elif line and not (current is None and NOISE.fullmatch(line)):
            errors.append(f"unparsable registry line: {line}")
    if current is not None or not binaries:
        errors.append("incomplete or empty registry")
    return tests, binaries

def check(ledger, run, listing, ignored_listing, linux):
    errors = []
    tests, binaries = registry(listing, errors)
    ignored, ignored_binaries = registry(ignored_listing, errors)
    if not tests or binaries != ignored_binaries or not ignored <= tests:
        errors.append("empty or inconsistent compiled registries")
    results, run_binaries = executed(run, errors)
    if run_binaries != binaries:
        errors.append("the run and the registry name different binaries")
    for name in sorted(tests | results.keys()):
        expected = None if name not in tests else "ignored" if name in ignored else "ok"
        if results.get(name) != expected:
            errors.append(f"{name}: " + ("listed but not run" if name not in results else
                          "ran but not listed" if expected is None else
                          f"{results[name]} in the run, but the registry says {expected}"))
    for section in ("crash_points", "cases", "findings"):
        for row in ledger[section]:
            for kind in ("mac", "vm"):
                for name in row.get(kind, []) if isinstance(row.get(kind), list) else []:
                    valid = results.get(name) == "ok" and name not in ignored if kind == "mac" else (
                        name in ignored or (not linux and name not in tests))
                    if not valid:
                        errors.append(f"{row['id']}: {kind} {name}: " + (
                            "missing, ignored or not run" if kind == "mac" else "must be compiled and ignored on Linux; absent or ignored elsewhere"))
    return errors

def run_of(listing, ignored_listing):
    """The run a listing's suite prints when every test ran: libtest's lines for each group."""
    ignored, out, names = registry(ignored_listing, []), [], []
    current = None
    for line in listing.splitlines():
        if (running := RUN.fullmatch(line)) or (doc := re.fullmatch(r"Doc-tests (" + IDENT + r")", line)):
            current = binary(running, None if running else doc)
            out.append(line)
        elif line.endswith(": test"):
            names.append(line[:-6])
        elif SUMMARY.fullmatch(line):
            out.append(f"running {len(names)} tests")
            skipped = [n for n in names if current + "::" + n in ignored[0]]
            out += [f"test {n} ... " + ("ignored" if n in skipped else "ok") for n in names]
            out.append(f"test result: ok. {len(names) - len(skipped)} passed; 0 failed; {len(skipped)} "
                       "ignored; 0 measured; 0 filtered out; finished in 0.01s")
            names = []
    return "\n".join(out) + "\n"

def self_test():
    header = "Running unittests src/lib.rs (target/debug/deps/kilnd-012abc)\n"
    present, empty = header + "a::b: test\n1 test, 0 benchmarks\n", header + "0 tests, 0 benchmarks\n"
    ledger = {"crash_points": [{"id": "case", "mac": ["kilnd::a::b"]}], "cases": [], "findings": []}
    ok = lambda listing, ignored, linux=True: not check(ledger, run_of(listing, ignored), listing, ignored, linux)
    bad = lambda listing, ignored, run=None, linux=True: bool(check(
        ledger, run_of(listing, ignored) if run is None else run, listing, ignored, linux))
    assert ok(present, empty)  # passing
    assert not check(ledger, "\x1b[1;32m" + run_of(present, empty), "\x1b[1;32m" + present + "\x1b[0m", empty, True)
    assert ok(present + empty.replace("src/lib.rs", "src/main.rs"),
              empty + empty.replace("src/lib.rs", "src/main.rs"))
    doc = ("Doc-tests kilnd\nsrc/sys.rs - sys::f (line 9): test\n1 test, 0 benchmarks\n"  # merged, then
           "src/a.rs - g (line 2) - compile fail: test\nsrc/a.rs - h (line 5): test\n2 tests, 0 benchmarks\n")
    doc_ignored = empty + "Doc-tests kilnd\n" + "0 tests, 0 benchmarks\n" * 2
    assert ok(present + doc, doc_ignored)
    assert bad(present + doc + "src/a.rs - x (line 1): test\n", empty)  # unfinished group
    assert bad(present.replace("a::b", "src/a.rs - g (line 2)"), empty)  # not a doctest binary
    for listing, ignored in [(empty, empty), (present, present),  # cfg-disabled, ignored
                             (present.replace("a::b", "a::renamed"), empty),
                             (present + empty, empty), (present + "garbage\n", empty)]:
        assert bad(listing, ignored)
    # The run itself (C6a recheck 1 HIGH 5): listed but skipped, filtered, ignored, absent.
    run = run_of(present, empty)
    skipped = run.replace("running 1 tests\ntest a::b ... ok\n", "running 0 tests\n").replace(
        "1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out", "0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out")
    assert skipped != run and bad(present, empty, skipped)
    assert bad(present, empty, run.replace("0 filtered out", "1 filtered out"))
    assert bad(present, empty, run.replace("... ok", "... ignored").replace("1 passed; 0 failed; 0 ignored", "0 passed; 0 failed; 1 ignored"))
    assert bad(present, empty, "")  # a run with no output
    assert bad(present, empty, run.replace("test a::b ... ok\n", "test a::b ... ok\ntest a::b ... ok\n"))
    assert bad(present, empty, run + run_of(empty.replace("src/lib.rs", "src/main.rs"), empty))  # extra binary
    assert bad(present, empty, run + "garbage\n")
    assert bad(present, empty, run + "running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n")
    assert not check(ledger, run.replace("test a::b ... ok", "test a::b has been running for over 60 seconds\ntest a::b ... ok"),
                     present, empty, True)  # a slow test
    child = ("running 1 test\ntest a::b ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; "
             "0 measured; 9 filtered out; finished in 0.00s\n")
    assert not check(ledger, run.replace("test a::b ... ok\n", child + "test a::b ... ok\n"), present, empty, True)
    assert bad(present, empty, skipped.replace("running 0 tests\n", "running 0 tests\n" + child))  # a child is no run
    assert bad(present, empty, run.replace("test a::b ... ok\n", "test a::b ... ok\nrunning 1 test\n"))  # unclosed
    two = header + "a::b: test\na::c: test\n2 tests, 0 benchmarks\n"
    two_ignored = header + "a::c: test\n1 test, 0 benchmarks\n"
    assert ok(two, two_ignored)
    assert not check(ledger, run_of(two, two_ignored).replace("a::c ... ignored", "a::c ... ignored, needs root"), two, two_ignored, True)
    assert bad(two, two_ignored, run_of(two, empty.replace("0 tests", "0 tests")))  # c ran, but is ignored
    ledger["crash_points"][0] = {"id": "vm", "vm": ["kilnd::vm::case"]}
    assert ok(present, empty, False) and bad(present, empty, linux=True)
    vm = present.replace("a::b", "vm::case")
    assert bad(vm, empty, linux=False) and ok(vm, vm, True)
    print("checkpoint ledger checker self-test: passed")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        ledger_path, run_path, listing_path, ignored_path, target = sys.argv[1:]
        errors = check(json.loads(Path(ledger_path).read_text()), Path(run_path).read_text(),
                       Path(listing_path).read_text(), Path(ignored_path).read_text(), target == "Linux")
        for error in errors:
            print("checkpoint ledger: " + error, file=sys.stderr)
        if errors:
            sys.exit(1)
        print("checkpoint ledger: run and compiled registry check passed (" + target + ")")
