#!/usr/bin/env python3
"""Drafts and checks dependency-gate.json's per-package reviews (design section 7.1).

    python3 -I scripts/dependency-gate-review.py           # report what needs review
    python3 -I scripts/dependency-gate-review.py --write   # also draft missing entries

Every package in Cargo.lock outside the workspace needs an entry under `packages`, keyed
`name@version`, pinned to Cargo.lock's checksum and to the features cargo resolves for it
in any supported build profile (`profiles`: `cargo metadata --locked` with exactly the
profile's flags, as scripts/build.sh passes them, the union over the profiles), with its
kind (from the union of the profiles' dependency graphs; a direct dependency's from the
manifests), a capability and a justification. One name@version from two sources (two
registries, say) cannot be reviewed under one key: the script refuses it, as the gate does.
This script
reports new, stale and changed packages. With --write it adds a draft for each new one:
the checksum, features and kind filled in, and `capability` and `why` left empty, so
proven::tests::dependency_gate fails until a person reviews the package and writes them.
It never changes an existing review. The gate test is the authority; this only drafts.
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def lock_packages(text):
    """Cargo.lock's [[package]] tables: name, version, source and checksum."""
    out = []
    for block in text.split("[[package]]")[1:]:
        package = {}
        for line in block.splitlines():
            key, sep, value = line.partition(" = ")
            if sep and key in ("name", "version", "source", "checksum"):
                package[key] = value.strip().strip('"')
        out.append(package)
    return out


def duplicate_identities(keys):
    seen, out = set(), set()
    for key in keys:
        (out if key in seen else seen).add(key)
    return sorted(out)


def metadata(features):
    command = ["cargo", "metadata", "--format-version", "1", "--locked",
               "--manifest-path", str(ROOT / "Cargo.toml")]
    if features:
        command += ["--features", ",".join(features)]
    out = subprocess.run(command, check=True, capture_output=True, text=True, cwd=ROOT).stdout
    return json.loads(out)


def union(metas):
    """The profiles' resolves as one: every package, each node's features and edges
    merged (edges by package, with every kind any profile gives them)."""
    packages, nodes, members = {}, {}, set()
    for meta in metas:
        keys = [f'{p["name"]}@{p["version"]}' for p in meta["packages"]]
        for key in duplicate_identities(keys):
            sys.exit(f"cargo metadata resolves two packages with the same identity {key}: "
                     "the gate keys every review by name@version and does not support one "
                     "name and version from two sources; resolve one")
        packages.update({p["id"]: p for p in meta["packages"]})
        members.update(meta["workspace_members"])
        for node in meta["resolve"]["nodes"]:
            merged = nodes.setdefault(node["id"], {"id": node["id"], "features": set(), "deps": {}})
            merged["features"].update(node["features"])
            for dep in node["deps"]:
                kinds = merged["deps"].setdefault(dep["pkg"], set())
                kinds.update(k["kind"] for k in dep["dep_kinds"])
    return {
        "packages": list(packages.values()),
        "workspace_members": sorted(members),
        "resolve": {"nodes": [
            {"id": n["id"], "features": sorted(n["features"]),
             "deps": [{"pkg": pkg, "dep_kinds": [{"kind": k} for k in kinds]}
                      for pkg, kinds in n["deps"].items()]}
            for n in nodes.values()]},
    }


def kinds(meta):
    """The gate's kinds: runtime through normal edges (a proc macro is build-time),
    build-only through build edges, dev-only through dev edges; a direct dependency's
    kind is its manifest kind."""
    packages = {p["id"]: p for p in meta["packages"]}
    key = {i: f'{p["name"]}@{p["version"]}' for i, p in packages.items()}
    members = set(meta["workspace_members"])
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    proc_macro = {i for i, p in packages.items()
                  if any("proc-macro" in t["kind"] for t in p["targets"])}

    def edges(node):
        for dep in node["deps"]:
            yield dep["pkg"], {k["kind"] for k in dep["dep_kinds"]}

    runtime, build, dev, direct = set(), set(), set(), {}
    for member in members:
        for dep, ks in edges(nodes[member]):
            if dep in members:
                continue
            if None in ks:
                (build if dep in proc_macro else runtime).add(dep)
                direct[dep] = "runtime"
            if "build" in ks:
                build.add(dep)
                direct.setdefault(dep, "build-only")
                if direct[dep] == "dev-only":
                    direct[dep] = "build-only"
            if "dev" in ks:
                dev.add(dep)
                direct.setdefault(dep, "dev-only")
    changed = True
    while changed:
        before = (len(runtime), len(build), len(dev))
        for i in list(runtime):
            for dep, ks in edges(nodes[i]):
                if None in ks:
                    (build if dep in proc_macro else runtime).add(dep)
                if "build" in ks:
                    build.add(dep)
        for group in (build, dev):
            for i in list(group):
                group.update(dep for dep, _ in edges(nodes[i]))
        changed = before != (len(runtime), len(build), len(dev))
    out = {}
    for i in packages:
        if i in members:
            continue
        if i in direct:
            out[key[i]] = direct[i]
        elif i in runtime:
            out[key[i]] = "runtime"
        elif i in build:
            out[key[i]] = "build-only"
        elif i in dev:
            out[key[i]] = "dev-only"
    features = {key[n["id"]]: sorted(n["features"]) for n in meta["resolve"]["nodes"]}
    return out, features


def main():
    write = "--write" in sys.argv[1:]
    packages = lock_packages((ROOT / "Cargo.lock").read_text())
    for key in duplicate_identities(f'{p["name"]}@{p["version"]}' for p in packages):
        sys.exit(f"Cargo.lock locks two packages with the same identity {key}: the gate keys "
                 "every review by name@version and does not support one name and version "
                 "from two sources; resolve one")
    locked = {f'{p["name"]}@{p["version"]}': p for p in packages if "source" in p}
    gate_path = ROOT / "dependency-gate.json"
    gate = json.loads(gate_path.read_text())
    profiles = gate.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        sys.exit("dependency-gate.json has no `profiles` (the supported builds) to resolve")
    kind, features = kinds(union(metadata(p.get("features") or []) for p in profiles.values()))
    entries = gate.setdefault("packages", {})
    problems = 0
    for key in sorted(set(entries) - set(locked)):
        print(f"stale: {key} is no longer in Cargo.lock; drop its entry")
        problems += 1
    for key, package in sorted(locked.items()):
        entry = entries.get(key)
        if entry is None:
            print(f"new: {key} ({kind.get(key, '?')}) needs a review")
            problems += 1
            if write:
                entries[key] = {
                    "checksum": package.get("checksum"),
                    "features": features.get(key, []),
                    "kind": kind.get(key),
                    "capability": None,
                    "why": "",
                }
            continue
        if entry.get("checksum") != package.get("checksum"):
            print(f"changed: {key}'s checksum is now {package.get('checksum')}: review the new source")
            problems += 1
        if sorted(entry.get("features") or []) != features.get(key, []):
            print(f"changed: {key}'s features are now {features.get(key, [])}: review the change")
            problems += 1
        if entry.get("kind") != kind.get(key):
            print(f"changed: {key}'s kind is now {kind.get(key)}")
            problems += 1
    if write:
        gate["packages"] = dict(sorted(entries.items()))
        gate_path.write_text(json.dumps(gate, indent=2, ensure_ascii=False) + "\n")
    print(f"{len(locked)} locked packages, {problems} to review")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
