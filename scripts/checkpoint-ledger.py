#!/usr/bin/env python3
"""Validate ledger references against Cargo/libtest registries, never source text."""
import json
import re
import sys
from pathlib import Path

IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
PATH = IDENT + r"(?:::" + IDENT + r")*"
# Library, binary and doctest targets have distinct identities.
RUN = re.compile(r"Running (unittests \S+|tests/\S+) \(.*[/\\]deps/(" + IDENT + r")-[0-9a-f]+\)")

def registry(text, errors):
    tests, binaries, current, count = set(), set(), None, 0
    for line in text.splitlines():
        line = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()  # Cargo color, including CI.
        running, doc = RUN.fullmatch(line), re.fullmatch(r"Doc-tests (" + IDENT + r")", line)
        if running or doc:
            if current is not None:
                errors.append(f"unfinished binary: {current}")
            current = (running[2] + ("::bin" if running[1].startswith("unittests ")
                       and running[1] != "unittests src/lib.rs" else "")) if running else doc[1] + "::doc"
            if current in binaries:
                errors.append(f"duplicate binary name: {current}")
            binaries.add(current)
            count = 0
        elif current is not None and re.fullmatch(PATH + r": test", line):
            name = current + "::" + line[:-6]
            if name in tests:
                errors.append(f"duplicate test: {name}")
            tests.add(name)
            count += 1
        elif current is not None and (summary := re.fullmatch(r"(\d+) tests?, (\d+) benchmarks?", line)):
            if count != int(summary[1]) or int(summary[2]):
                errors.append(f"invalid registry count: {current}: {line}")
            current = None
        elif line and not (current is None and re.fullmatch(r"(?:(?:Compiling|Finished) .+|Blocking waiting for file lock on (?:build directory|package cache))", line)):
            errors.append(f"unparsable registry line: {line}")
    if current is not None or not binaries:
        errors.append("incomplete or empty registry")
    return tests, binaries

def check(ledger, listing, ignored_listing, linux):
    errors = []
    tests, binaries = registry(listing, errors)
    ignored, ignored_binaries = registry(ignored_listing, errors)
    if not tests or binaries != ignored_binaries or not ignored <= tests:
        errors.append("empty or inconsistent compiled registries")
    for section in ("crash_points", "cases", "findings"):
        for row in ledger[section]:
            for kind in ("mac", "vm"):
                for name in row.get(kind, []) if isinstance(row.get(kind), list) else []:
                    valid = name in tests - ignored if kind == "mac" else (
                        name in ignored or (not linux and name not in tests))
                    if not valid:
                        errors.append(f"{row['id']}: {kind} {name}: " + (
                            "missing or ignored" if kind == "mac" else "must be compiled and ignored on Linux; absent or ignored elsewhere"))
    return errors

def self_test():
    header = "Running unittests src/lib.rs (target/debug/deps/kilnd-012abc)\n"
    present, empty = header + "a::b: test\n1 test, 0 benchmarks\n", header + "0 tests, 0 benchmarks\n"
    ledger = {"crash_points": [{"id": "case", "mac": ["kilnd::a::b"]}], "cases": [], "findings": []}
    assert not check(ledger, present, empty, True)  # passing
    assert not check(ledger, "\x1b[1;32m" + present + "\x1b[0m", empty, True)  # CI color
    assert not check(ledger, present + empty.replace("src/lib.rs", "src/main.rs"),
                     empty + empty.replace("src/lib.rs", "src/main.rs"), True)
    for listing, ignored in [(empty, empty), (present, present),  # cfg-disabled, ignored
                             (present.replace("a::b", "a::renamed"), empty),
                             (present + empty, empty), (present + "garbage\n", empty)]:
        assert check(ledger, listing, ignored, True)
    ledger["crash_points"][0] = {"id": "vm", "vm": ["kilnd::vm::case"]}
    assert not check(ledger, present, empty, False) and check(ledger, present, empty, True)
    vm = present.replace("a::b", "vm::case")
    assert check(ledger, vm, empty, False) and not check(ledger, vm, vm, True)
    print("checkpoint ledger checker self-test: passed")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        ledger_path, listing_path, ignored_path, target = sys.argv[1:]
        errors = check(json.loads(Path(ledger_path).read_text()), Path(listing_path).read_text(),
                       Path(ignored_path).read_text(), target == "Linux")
        for error in errors:
            print("checkpoint ledger: " + error, file=sys.stderr)
        if errors:
            sys.exit(1)
        print("checkpoint ledger: compiled registry check passed (" + target + ")")
