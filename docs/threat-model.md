# kilnd threat boundaries

kilnd is a control plane for **experimental, shared-kernel** sandboxes. This
file says what it protects, what it trusts, and what it doesn't try to do.

## Trust levels

| Who | Trusted with |
|-----|--------------|
| root on the host | everything |
| members of the `kilnd` group | full use of the API: create, run any command in, and delete any sandbox kilnd manages. Treat membership as near-root on a dev box. |
| code inside a sandbox | nothing on the host. It is contained by kiln (namespaces, cgroups, seccomp, Landlock, nftables), not by kilnd. |
| other local users | nothing. They can't reach the socket. |

## Boundaries kilnd enforces

- **Socket access.** `/run/kilnd` is `root:kilnd 0750` and the socket
  `root:kilnd 0660` (or root-only with `--socket-group ''`). kilnd refuses a
  socket directory it doesn't own and won't replace anything at the socket
  path except a stale socket. Each connection's uid, gid and pid are logged
  from `SO_PEERCRED`. There is no per-call authorization beyond this.
- **No shell injection into the host.** kiln is spawned with an argument
  vector. Flag values use `--flag=value`, the command follows `--`, and
  images, allowlist entries, paths, labels and IDs are validated before use.
  The environment is cleared except for a fixed `PATH`. Inside the sandbox,
  argv is exec'd directly; `sh -c` happens only when the caller asks for it.
- **Bounded resource use by callers.** Caps on active sandboxes, sandbox
  limits, exec timeout, argv, stdin and stored output keep one client from
  filling memory, disk or the database with a single request.
- **State integrity.** The database directory is root-only 0700. kilnd
  refuses one writable by group or others, and refuses a schema newer than
  it understands.
- **No orphaned work.** `kiln exec` clients die with kilnd
  (`PR_SET_PDEATHSIG`), and kiln then kills their commands. Interrupted
  executions are recorded as such.

## What it relies on kiln for

Isolation itself: namespaces, the user-ID shift, seccomp denylist, Landlock,
cgroup limits, XFS quotas and network policy. kiln's known limits apply in
full; see kiln's README and SECURITY.md. In particular, all sandboxes share
one host UID range, seccomp is a denylist, and a kernel bug reachable from a
sandbox compromises the host.

## Known gaps

- **Output is stored as-is.** Up to 1 MiB of each stream per execution goes
  into SQLite. Secrets a command prints are persisted (root-only) until the
  database is pruned, and there is no retention yet.
- **The database grows without bound.** Deleted sandboxes and every
  execution are kept for history.
- **kiln's own errors and command output share stderr.** When `kiln exec`
  fails (exit 125), its message is mixed into the captured stderr. A command
  that itself exits 125 is reported as a backend failure.
- **A crash during `kiln create`** can leave a kiln sandbox kilnd never
  recorded. Reconciliation logs it as unmanaged but doesn't remove it, since
  it can't tell it from one an operator made with the CLI. Remove it with
  `kiln rm`.
- **Group members are not isolated from each other.** Any member can exec in
  or delete any sandbox. Per-caller ownership belongs to the harness layer or
  a later API version.
- **No API authentication beyond Unix permissions,** and no TLS, by design:
  the socket is local. Remote access would need an authenticated proxy.
- **kilnd runs as root,** because kiln does. A bug in kilnd's request handling
  is a bug in a root process; the attack surface is the socket, reachable
  only by root and the `kilnd` group.
