# Security policy

## Supported versions

kilnd has no releases yet. Security fixes go to the `main` branch only.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub:
<https://github.com/lambda-nine/kilnd/security/advisories/new>

Please don't open a public issue, pull request or discussion for a
vulnerability. Include what you can of:

- the kilnd commit and the installed kiln commit, host distribution and
  kernel version (`uname -r`)
- the backend (kiln, or a Firecracker test deployment) and the flags used
- what a caller, a sandbox or another local user could do that it shouldn't,
  and the steps to reproduce it

kilnd is maintained by one person. Responses are best effort, with no
guaranteed response or fix time. When a fix is ready, it is disclosed through
the same advisory, with credit if you want it.

## Scope

In scope:

- the `kilnd.v1` gRPC API and `kilndctl`: per-caller ownership, validation,
  admission bounds and resource budgets
- the root `kilnd-helper`, its peer checks and the typed helper protocol
- daemon state: the SQLite database, state and socket paths, locks,
  reconciliation and history retention
- the hardened systemd units and install scripts under `deploy/` and
  `scripts/`
- the Firecracker backend (`kilnd-helper` firecracker modules, the guest
  broker and its protocol), as test-deployment code

Out of scope here (report them to the repository that owns them):

- escapes from a kiln sandbox: [kiln](https://github.com/lambda-nine/kiln)
- the guest image, its kernel and init:
  [kiln-guest](https://github.com/lambda-nine/kiln-guest)
- Firecracker itself: report upstream

## Security boundary today

kilnd is **experimental software** and is **not a boundary for hostile
multi-tenant workloads.**

- **kiln is the isolation.** kilnd only controls kiln sandboxes, and kiln is
  experimental, shared-kernel isolation: a kernel bug reachable from inside a
  sandbox can compromise the host.
- **The `kilnd` group is near-root on a dev box.** Members can see and
  control only their own sandboxes, but those sandboxes share one kernel.
  There is no tenant fairness or per-user quota; callers share one set of
  node budgets.
- **The Firecracker backend is disabled for production.** `--backend
  firecracker` and `--firecracker-test-deployment` exist only in a build with
  the non-default `firecracker-test-deployment` cargo feature; release and
  installed builds refuse both. A feature build runs only as an isolated test
  deployment with its own account, group and unit. Enabling it for
  production still needs an approved guest bundle and a reviewed, pinned
  jailer build, so microVM isolation is not available for real workloads.
- **Reviewed, not audited.** The design and code have had adversarial reviews
  by AI models. No professional security audit has been done.
- **One tested environment.** Ubuntu 24.04 with Linux 6.8 or newer, in kiln's
  Lima VM on Apple silicon. CI runs the unprivileged checks on Ubuntu 24.04
  x86_64.

[docs/threat-model.md](docs/threat-model.md) lists what kilnd trusts,
enforces and leaves open.
