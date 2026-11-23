# Changelog

Notable changes to kilnd. Versions follow [Semantic Versioning](https://semver.org/);
before 1.0, any minor release may change the CLI or on-disk layout. The
`kilnd.v1` API only gains fields and RPCs.

## Unreleased

- Health no longer stays SERVING when kilnd can't read its checkpoint statistics. It
  still leaves the `checkpoints` block out and logs `read checkpoint counts`, and now also
  reports DEGRADED (SHUTTING_DOWN still wins) with `checkpoint counts unreadable: <why>` in
  `detail`, on one line of at most 512 bytes (control characters and Unicode's line and
  paragraph separators become spaces). Before, the block just vanished, which read
  like "no checkpoint state". No API change: Health still has no field of its own for the
  checkpoint maintenance state.

- Health's `detail` now names a pending checkpoint barrier: `a checkpoint barrier is
  pending: new sandboxes (forks included) and captures are refused until a complete, clean
  checkpoint inventory clears it`. Before, a barrier alone showed only `backend resources
  no row explains block CreateSandbox until reconciled`, which now appears only when that
  is the cause. The status is unchanged: either block keeps Health DEGRADED. The sentence
  comes from the flag kilnd already holds, with no extra store read.

- kilnd-helper logs exactly one startup line for its checkpoint group:
  `kilnd-helper: checkpoint group: enabled`, `... off (flag)` without
  `--enable-checkpoints`, or `... failed: <why>`. Before, it logged only the failure (as
  `checkpoint group disabled: <why>`), and a helper started without the flag said
  nothing. The opt-in steps in `docs/setup.md` and `docs/checkpoints.md` now check for the
  `enabled` line. Nothing else changes.

- An execution whose sandbox's cgroup went away after the command started, as when an OOM
  kill takes the whole sandbox with it, now fails its cleanup with `the sandbox's cgroup
  went away after the command started`, plus `(the sandbox ran out of memory)` when the
  sandbox cgroup's `memory.events` showed `oom_kill` above 0 before it went. It used to
  say `kiln 3b42552 or later is required`, which now appears only when the sandbox's cgroup
  is there but never had the `exec` cleanup barrier. A `memory.events` that can't be read
  only leaves the hint out. The verdict (CLEANUP_FAILED, the sandbox unusable) is
  unchanged.

- kilnd-helper's create timing lines can no longer run into each other. When journald's
  socket took only part of a line and the newline that ends the fragment hit `EAGAIN`
  too, the next line was appended to the fragment: both were unreadable, and `dropped`
  counted one. Now the helper remembers the open fragment. The next line first sends the
  newline; if that fails again, that line is dropped too and counted, and once it goes
  through, the line follows it. Every unreadable line is counted in `dropped`. Still never
  blocking, retrying in a loop or buffering lines.

- kilnd-helper now times every Firecracker create step by step, from Preflight through
  BOOTING to READY, and logs one `create timing v1` line per create once it ends: H's, L's,
  M's and P's work, each supervisor step and each journal record's round trip, carried in
  the records the supervisor already sends. `kilnd-helper create-timings` prints a
  waterfall for one allocation or the last N, or a per-step p50/p95/max summary, from the
  helper's log. The line holds the allocation ID, which kilnd already logs as the backend
  ID, so one create can be picked out. No boot nonce, token key, work UUID, instance or
  sandbox ID, leased uid, gid or cid, path or refusal reason is logged. A READY line is
  written once the supervisor's last step (READY's own journal round trip) has arrived,
  after the helper answered it; refusals carry the worker's steps up to the refusal. The
  helper never waits to write a line: journald's socket gets non-blocking sends, at most
  three per line, and a line it can't take whole, or any line when standard error isn't a
  socket, is dropped and counted in the next line's `dropped` (see the next entry for a
  line the socket takes only part of). The journal, the ledger schema and every create's
  behaviour are unchanged.

- An unkeyed create that named no image and no writable paths, which kiln's preflight
  refused (exit 124), now fails `UNAVAILABLE` with the typed reason
  `default_image_unavailable`, naming the node's default image and the FAILED,
  uncharged row. kilnd supplied that image, so the node is at fault, not the caller.
  It was `INVALID_ARGUMENT`. A caller's own image, and the default image with writable
  paths (kiln's walk judges those against the image), still answer `INVALID_ARGUMENT`;
  keyed creates still return OK with the settled row. One case stays ambiguous: a
  broken default image together with the caller's writable paths still answers
  `INVALID_ARGUMENT`, because kiln's exit status doesn't say which it refused. The
  `CreateSandbox` comment in the proto says so (comments only).

- kilnd now ignores unknown fields in kilnd-helper's replies, so a newer helper that adds
  an optional field to a reply works with this daemon. Before, the daemon refused the
  whole reply: a real preflight refusal from a newer helper surfaced as INTERNAL and its
  create stayed charged. An unknown reply variant or a missing field still fails, and
  requests to the helper stay strict, as do types also used in a request, a stored
  format or root's policy. Two table-driven tests hold the line at every boundary: each
  reply-only struct and struct variant takes a new field, and each request, stored,
  journalled, policy and plan type refuses one, wherever it is decoded. A third test
  checks both lists against the types the source declares.

- The root VM test of `kilnd release-ambiguous` (`ambig_vm_floors_paths_and_audited_release`)
  now runs another account's processes through the successful release: a copy of sleep
  named `kiln`, the same through a link named `\xff`, one under a path longer than
  `PATH_MAX`, and the configured kiln itself. It checks that root's runs of the
  `\xff` link and of the long path refuse with exit 75, that the checkpoint helper's
  process table reads the same node, and that the audit row's operator uid is the
  login uid.

- Tests now pin the release scan's byte reads of `/proc/PID/status` and `stat`, over a
  fake procfs whose command names aren't UTF-8 and, on Linux, from inside a thread
  whose kernel name isn't (a std thread named 14 ASCII bytes and `€`), and the
  `loginuid` read behind the audit's operator uid. Only the parsers were pinned.
  Behaviour is unchanged.

- Delete's refusal of an ambiguous reservation now tells the operator to stop both
  kilnd and kilnd-helper (and `kilnd-helper.socket`) before `kilnd release-ambiguous`.
  It said "with kilnd stopped", and the release refuses with exit 75 while
  kilnd-helper serves.

- kilnd-helper's checkpoint group no longer retains every checkpoint removal while
  any process on the node has a command name that isn't UTF-8. Its process scan read
  every process's `/proc/PID/stat` as text, so one such process (a sandbox's
  `prctl(PR_SET_NAME)` is enough) failed the scan: every removal was retained with
  "the process table could not be read" and every inspection was incomplete. It reads
  `stat` as bytes now, through the parser the release's scan uses.

- `kilnd release-ambiguous` no longer fails its process scan with exit 69, naming
  nothing, over a process whose executable it can't read. Any account or sandbox can
  run one: the kernel can't render an executable's path longer than `PATH_MAX`
  (ENAMETOOLONG), and root may not open an image on another user's FUSE mount. Such
  a process now counts as possibly kiln if it holds root by any uid, named with the
  error (exit 75), and is ignored otherwise.

- `kilnd release-ambiguous` no longer counts another account's process running the
  configured kiln as a kiln process. Its process scan counted the configured image
  whoever ran it, so any local account could keep the release refused (exit 75) with
  `/usr/local/bin/kiln ls & kill -STOP $!`. Another account's process can't create a
  run in kiln's root-only runs directory, whatever it runs, so a process now counts
  only if it holds root by any uid, by the image rule as by the name rule. The scan
  reads the uids first, so it never opens another account's executable, and a match
  by image is read again like one by name. setup.md and threat-model.md say what
  counts.

- `kilnd release-ambiguous` reads the executable of a root process named `kiln` again
  after its uids, and counts the process only if both reads agree. A process that
  exec'd between the two reads was judged by one executable's name and another's
  uids; it is now judged afresh by the new executable, and one whose executable
  differs on every read counts after three reads.

- A `kilnd release-ambiguous` refusal cuts each process it names to 1 KiB, marked `…`.
  The 64-name cap didn't bound the scan's reply: JSON writes a control byte as six, so
  64 executables under long paths of control bytes took the reply past its 1 MiB cap,
  and the release refused with exit 69 and named none. A compile-time check now pins
  the bound. setup.md says so.

- `kilnd release-ambiguous` no longer fails its process scan with exit 69 over a
  command name that isn't UTF-8. It read `/proc/PID/stat`, and `/proc/PID/status` for a
  process whose executable is named `kiln`, as text, and both carry the kernel's
  command name, whose bytes the process sets (`prctl(PR_SET_NAME)`, or an executable
  run through a link of that name). So one such kiln process, or a process a kiln
  process descends from, made every release fail. Both files are now read as bytes,
  and only the fields the scan uses are parsed as text.

- Host tests now pin both halves of the helper's side of the release fence, which only
  the root VM test did: `ServeLock::hold_while`, which kilnd-helper now serves under,
  holds the serving lock from before the serve starts until it has returned, the
  groups' shutdown included; and a listener error still waits for every request the
  helper accepted before the serve returns. kilnd-helper's behaviour is unchanged.

- setup.md's release steps no longer suggest stopping `kilnd@NAME` for a further
  instance: the release serves kiln to the `kilnd` account alone and refuses any other
  instance's state directory, so following the hint paused every instance for a
  release that was always refused. It now says only the default instance's rows can be
  released.

- `kilnd release-ambiguous` records the administrator who ran it as the audit row's
  operator uid: the audit login uid (`/proc/self/loginuid`, which sudo leaves as the
  login set it) when it is set, else sudo's `SUDO_UID`, else the real uid. It recorded
  the real uid, which under `sudo` (the documented invocation) or a root login is 0
  whoever released.

- `kilnd release-ambiguous` no longer counts another account's binary named `kiln` as a
  kiln process. Its process scan counted any executable of that name, so any local
  account could keep the release refused (exit 75) with `cp /bin/sleep ~/kiln; ~/kiln
  86400`, and a few hundred such processes under long paths took the scan's reply past
  its 1 MiB cap, so the release refused with exit 69 and named none. A name-only match
  now counts only if the process holds root by any uid on `/proc/PID/status`'s `Uid:`
  line; the configured kiln image counts whoever runs it, as before. A refusal names
  the first 64 processes and how many there were in all, and the scan's reply between
  the command's two halves carries that count. setup.md says a listed process may be
  any account's, and that stopping it is the operator's call.

- Bring the docs in step with the code. setup.md's upgrade notes name schema 17 as the
  current one and give its rollback, and the release command's section gives the
  `--reason` bound and exit 64; the README and the threat model say an ambiguous row has
  an operator release and that kilnd-helper is stopped for it; the validation contract
  says the floors and the mounted-filesystem paths go unchecked only by a kiln older than
  the next release. The proto's comments give CreateSandbox's `INVALID_ARGUMENT` for a
  backend preflight refusal of a create not from a checkpoint, the resource floors and
  maxima, the refused writable paths and the operator release in the reservation rules;
  architecture.md's status table scopes that row the same way. Comments only; no
  behaviour changes.

- A create kiln refuses before allocating anything (its trusted exit 124: a writable path
  whose parent in the image is a symlink or a regular file, a missing image, or any other
  check kiln's create preflight makes) is now answered `INVALID_ARGUMENT`, not
  `INTERNAL`: the caller's input, not a node fault. The message still names the row
  (`create sandbox sb-…: kiln create failed (exit status: 124): …`, kiln's reason
  summarised as before), and the row is unchanged: `FAILED`, definitely not created and
  uncharged. kiln has one exit status for every preflight refusal, so a missing image
  gets the same code. A keyed create still answers `OK` with its settled `FAILED` row,
  on the original call and every retry. The capability gate, a create that expired
  before kiln ran, a create from a checkpoint (its refusals stay typed) and every
  failure after allocation keep their codes. kilnd-helper carries the fact as an
  optional `preflight_refused` on its create error reply, omitted when false; upgrade
  daemon and helper together, as always. `scripts/smoke.sh`'s two
  unmanaged kiln creates and `scripts/helper-blocking-fd.py`'s fixture ask for kiln's
  64 MiB disk floor, and the ambiguous-create VM test forces its ambiguous row with
  kiln's own post-preflight trigger, an empty image directory.

- `kilnd release-ambiguous` now fences the helper, not just the daemon. The state lock
  proved no daemon of the instance ran, but a create the separate root helper had
  accepted could outlive the daemon, and kiln's shim outlives its CLI and creates its
  run directory afterwards, so a run could appear after the proof's runs-directory read
  and the release still commit. Every serving `kilnd-helper` now holds a serving lock
  (`--serve-lock`, default `/var/lib/kilnd-helper/helper.lock`) until every request it
  accepted has settled, and exits rather than serve while it is held. The release takes
  it as root before anything else (exit 75 while a helper serves; stop
  `kilnd-helper.socket` and `kilnd-helper` first), holds it until after the commit, and
  serves kiln to itself meanwhile: it forks, and the root half is the node's only helper,
  for the `kilnd` account alone (authenticated by peer UID), on a private abstract
  socket. Before reading the runs directory it scans every process twice and refuses
  (exit 75, naming each pid and executable) any kiln process that isn't a published
  sandbox's shim, a descendant of one or a kiln node service; a hand-run kiln command
  other than the node-service subcommands (`dns`, `network-setup`, `metrics`,
  `metrics-collect`) counts too. `--helper-socket` is gone,
  `--helper-lock` and `--kiln` are new, and the state directory must be the `kilnd`
  account's. The docs no longer claim a caller can't make an ambiguous reservation on
  purpose: a writable path whose parent in the image is a symlink or a regular file
  still makes one with a kiln older than the next release.

- A source sandbox held in DELETING behind an interrupted capture no longer names
  another uid's checkpoint in its stored reason. When root captured someone else's
  sandbox, its owner saw root's checkpoint ID, which is `NOT_FOUND` to them; the
  reason now says "held until an interrupted capture's storage is proved absent"
  unless the owner owns the checkpoint too. The log keeps the ID.

- Add `kilnd release-ambiguous`, the operator's release of an ambiguous reservation:
  a `FAILED` create with no backend ID, which kilnd keeps charged because it can't
  prove the create left nothing, so enough of them blocked a node for every uid with
  no recovery. As root with the instance stopped, it takes the state lock (exit 75
  while held), runs the startup reconciliation pass, and needs a second complete
  inventory and kiln's runs directory, read by its entries since `kiln ls` skips a
  run directory without `shim.pid`, to hold nothing a live row doesn't own (exit 69
  otherwise, naming what to remove). Schema 17 records the release as one
  append-only `operator_releases` row (owner, charges, operator uid, time, reason,
  inventory SHA-256) whose insert alone can tag the row `operator_attested`; Delete
  and a keyed retry then treat the row as after a create that allocated nothing. Each
  start logs how many releases the database holds. See `docs/setup.md`, "Releasing an
  ambiguous reservation". Older binaries refuse schema 17.

- Cap each per-sandbox maximum at its node budget. The compiled maxima (8 GiB memory,
  4096 pids, 32 GiB disk) exceeded the default node budgets (3 GiB, 2048, 16 GiB), and
  startup checked only the defaults against them. The effective maximum for memory,
  pids and disk is now the smaller of the two, computed and logged once at startup and
  used for every check; a request above it is `INVALID_ARGUMENT` before anything is
  charged, where it was `RESOURCE_EXHAUSTED`. A maximum can still equal a whole budget;
  the operator release below is the recovery if such a create ends ambiguous.

- Refuse writable paths over the filesystems kiln mounts itself: `/proc`, `/sys` and
  everything under them, and anything under `/dev` except `/dev/shm`. kiln's preflight
  accepted them, then its shim failed setup after allocation (kiln mounts procfs,
  cgroup2 and a host-root-owned `/dev` tmpfs there), so the create became an ambiguous
  reservation, charged forever. They are now `INVALID_ARGUMENT` before anything is
  charged, in kilnd, the root helper and the validator the broker protocol shares; the
  check is component-wise, so `/procx`, `/system` and `/dev/shm/x` stay valid. Request
  digests are unchanged.

- Refuse create and fork limits below what kiln can start. kiln checks none of them
  before it allocates, so a create with `cpu_millis` 1-9 (kiln writes a cgroup quota
  below 1 ms, which the kernel refuses) failed in kiln's shim after allocation and was
  recorded as an ambiguous reservation, charged forever. An explicit value below 10
  CPU millis, 32 MiB memory, 16 pids or 64 MiB disk is now `INVALID_ARGUMENT` before
  anything is charged or kiln is called, in kilnd and again in the root helper; 0
  still selects the default, and startup refuses a default below a floor. A create
  from a checkpoint takes its limits from the request and gets the same floors. The
  privileged regression scripts and the kiln integration tests now create with 64 MiB
  of disk instead of 16 MiB.

- Remove dead code: the guest broker's unused `tempfile` dev-dependency, seven items
  nothing references (`KilnWorkers::with_runs_root`, `DEFAULT_EXEC_STORE`,
  `DISPATCHED_ROLES`, `HELPER_STATE`, `open_work_dir`, `SandboxState::is_active`,
  `Store::record_sandbox_image_identity`), the lock's never-read path field and two
  dead-code allows that no longer suppress anything. No behaviour changes.

- Tighten the flaky-test fixes after an adversarial review (test-only).
  `execs_in_one_sandbox_run_one_at_a_time` sampled the backend once while the first exec
  was held, so a second exec let through after a short lock wait still passed; the fake
  backend now keeps its peak concurrent executions and an enter/leave log per sandbox,
  and the test asserts, after both finish, a peak of one and the first leaving before the
  second enters. The `short_tempdir()` helpers create every directory atomically at 0700
  (their `/tmp` fallback was group- or world-reachable under a 0002 or 0000 umask) and
  budget the resolved as well as the spelled `TMPDIR` length, so a short alias to a long
  path falls back too. On macOS's default `TMPDIR` (`/var/folders/...`, which resolves under
  `/private`) that means the helpers now use `/tmp`. Two socket tests assert the exact
  regular-file and live-listener refusals instead of any error. No behaviour changes.

- Make the tests pass under a long `TMPDIR` (test-only). Tests that bind a Unix socket
  in a temporary directory now make it with a `short_tempdir()` helper (one for kilnd's
  unit tests, one for its integration tests, one in kilndctl's transport tests), which
  falls back to `/tmp` when `TMPDIR` would leave the socket path too long for `sun_path`;
  51 tests failed with a 132-byte `TMPDIR`. The executable-table mode test gives its
  object the caller's group before `chmod 02555` and checks the mode took, since macOS
  silently drops setgid on a file whose group (`wheel` under `/tmp`) the owner is not in.
  No behaviour changes.

- Make four manager tests independent of machine load (test-only). Three tests ran 20
  and 50 ms exec timeouts on the wall clock, which a loaded machine could spend before
  the execution started (`DeadlineExceeded` instead of a timed-out execution); they now run
  on paused time. `execs_in_one_sandbox_run_one_at_a_time` polled for its 100 ms first exec
  to be running and spun forever if it missed it; the first exec is now held in the fake
  backend until the second is queued behind it. Three tests that put a state directory or
  socket in a fresh temporary directory now make it 0700, so a umask of 0002 no longer has
  the ancestor checks refuse it. No behaviour changes.

- Health's `ApiLimits.checkpoint.request_retention_ms` reports the configured
  `--create-request-retention-secs`, which is what prunes capture request records, in
  place of a fixed one day. It now matches `ApiLimits.create_request_retention_ms`; with
  the default retention the value is unchanged.

- Bring the docs in step with the code. The README lists ExecStream and the four
  checkpoint RPCs, every check `CLAUDE.md` asks for (the deployment regressions and their
  real-reboot steps included), and the helper socket's
  `kilnd-helper` group; architecture, the helper protocol and the threat model describe B6
  (the manager consumes READY; `--backend firecracker` only in a
  `firecracker-test-deployment` build), the helper's `checkpoint` group, seven kiln verbs,
  `WORKSPACE_CHECKPOINT` in the dynamic feature set and checkpoint ownership; the limits
  table gains every daemon flag it lacked; setup has the feature-profile checks, the expiry
  and idempotent-create regressions, the B5 and B6 VM suites (B5's with both test-guest variables) and
  their target directories, `kilndctl ls` in place of a nonexistent `kilndctl list`, and the current schema (16); the
  roadmap marks the landed control-plane features; and the validation contract adds
  checkpoint IDs, the capture `request_id` and `from_checkpoint`. The B7 design's link to
  section 16 uses its GitHub anchor, setup spreads the typed-termination history over
  schemas 3 to 5, and validation and architecture call the 256 KiB argv limit fixed in
  code rather than configurable. Setup's steps for moving the default instance to
  Firecracker first leave no checkpoint state with the node still serving (the feature flag
  off, which refuses only captures and forks, until checkpoint List is refused), then hold a
  manual admission fence (creators stopped and the socket root-only through a last-sorting
  drop-in that replaces `--socket-group` with `''`, since kilnd has no drain mode) from before
  the drain until the first Health check under Firecracker, rollback included; under it they
  wait out in-flight kiln creates, drain every kiln row as root (a non-root `kilndctl ls` sees
  only its own rows), check the checkpoint refusal again and list as root once more as the last
  check before the switch, with a reload and restart after every drop-in edit; validation names the three spec fields a fork must match and
  its disk minimum, and says the fork's own network, limits, labels, default env and
  expiry apply; and `CheckpointLimits.request_retention_ms` is described as the node's
  current prune policy, which a release or a lower retention can shorten. No behaviour
  changes.

- Document workspace checkpoints as a supported opt-in. With rollout-gate criteria 1-8
  met, `--enable-workspace-checkpoints` is no longer described as testing only: it is
  supported on a node that passes the gate's per-node criteria 9 (Health lists
  `workspace_checkpoint`) and 10 (the helper's kiln is a clean build of the gated kiln
  commit, or of a later one with criteria 2-4 rerun on it, built with
  `KILN_BUILD_COMMIT` unset and proved by a build record whose sha256 matches the
  installed binary; the version line alone is not proof). `docs/setup.md` has the opt-in
  steps (the helper's checkpoint group first, checked on the running process's command
  line, then kilnd's flag), how to turn it back off (the helper's group and a compatible
  kiln stay until, with kilnd's flag off, `kilndctl checkpoint ls` is refused
  `UNIMPLEMENTED backend_unsupported:workspace_checkpoint`, or the next kilnd start
  blocks new sandboxes; Health's `checkpoints:` block is not the check), and the
  measured limits. The feature stays off by default; no behaviour, flag, limit, API or schema
  changes.

- Delete a sandbox whose kiln shim died. When a shim crashed or was killed out of
  band, kiln lists its run `stale` and kilnd's removal could not prove the backend
  gone, so Delete answered Internal and left the sandbox DELETING and charged until
  root ran `kiln gc` by hand. Delete, expiry and create cleanup now collect exactly
  that run with a scoped `kiln gc` when kiln lists it once as stale, then prove it
  absent and release the reservation. Every other failure still keeps the sandbox
  DELETING and charged.

- Record the passing C6b fix-round-1 crash, reboot, hostile and client VM reruns
  in the rollout gate. Its adversarial recheck remains pending; workspace
  checkpoints stay off by default and for testing only.

- Checkpoint acceptance on real kiln (C6b). A VM harness runs the daemon and the root
  helper as SIGKILLable children of the test binary, with a test-only relay between them
  that holds a named helper operation or its reply, and
  `scripts/checkpoint-crash-matrix.py` runs each scenario alone with host checks before
  and after: the crash matrix V1–V17 (a real reboot for V14), the hostile-content set and
  two-uid callers, the rewind, best-of-N and eval-reset fixtures byte for byte, the kiln
  half of the legacy check and the performance harness. The acceptance ledger names them
  in place of every planned slot; `docs/checkpoint-performance.md` reports the numbers
  with their conditions, and `docs/checkpoint-rollout-gate.md` has each criterion's
  evidence. The feature stays off by default and for testing only.
- Quarantine a checkpoint whose restore proves it corrupt after allocating (C6b V16).
  kiln's shim checks each object's digest after the new sandbox is allocated, so a
  corrupted artifact came back as an ambiguous restore, and only a restore that
  allocated nothing quarantined. The fork failed `checkpoint_corrupt` but the
  checkpoint stayed `ready`, so every later fork was admitted, allocated and failed the
  same way. A corrupt verdict now quarantines the checkpoint whichever way the restore
  ended, charge kept, and the next fork is refused before admission.
- Hold the checkpoint VM acceptance oracles to what the ledger and rollout gate claim
  (C6b review, test-only): exec output carried losslessly so non-UTF-8 names compare
  byte for byte, directory mtimes included; the direct-`kiln exec` busy refusal and the
  pin's release only by ABSENT required rather than recorded; every scenario's end
  checked for unexpected runs and artifacts before any cleanup, with root cleanup a
  fallback that fails a passing scenario; ledger rows that named tests which never
  construct their case now record the kiln test that does, or the gap; and a regression
  for the C6b V16 quarantine on restart.
- Refuse `CARGO_PROFILE_*` variables in `build.sh`, the environment's form of the
  already refused `[profile]` table, so a reviewed build's debug assertions, optimization
  and overflow checks are the workspace's own.
- Accept Cargo's legacy top-level `token = "..."` in `$CARGO_HOME/credentials` and
  `credentials.toml` again (C6b review). The C6a recheck allowlist knew only the
  `[registry]` table form, so an existing legacy credentials file stopped every
  `build.sh` run. A legacy root `token` string is accepted alongside valid `registry` and
  `registries` credential tables. Every other top-level key and a non-string
  `token` are refused.
- Check `$CARGO_HOME`'s credentials files too (C6a recheck 4). Cargo 1.88 can merge
  `credentials` or `credentials.toml` as general configuration during an authenticated
  registry lookup, so a `[target]` runner there reached the bless writer. `build.sh` now
  allows in them only `token`, `credential-provider`, `secret-key` and
  `secret-key-subject` under `[registry]` and `[registries.NAME]`, read with `tomllib` or
  refused unread. Its comment on the config allowlist now names the trusted-toolchain
  boundary instead of claiming those settings change nothing.
- Refuse a checkpoint inventory whose mount identity can't be read (C6a recheck 4). The
  walk caught `FileNotFoundError` around all of it, so a missing `/proc/self/fdinfo` entry
  for a nested Btrfs subvolume's descriptor read as an absent registry and an empty
  inventory. Only an absent path component now means empty; any failure to read a
  descriptor's `mnt_id` refuses.
- Accept ordinary mount layouts below the registry's path (C6a recheck 3). The inventory
  walk allowed one mount point on the way and refused any other change of device, so a
  separately mounted `/var` with another filesystem lower down, or a Btrfs subvolume
  nested in `/var`'s and not mounted by itself, kept an empty flag-off node from
  upgrading. Any number of whole-filesystem or Btrfs self-mounts may now sit above the
  registry, and a device change with no mount entry is accepted as a nested subvolume when
  it is inode 256 on the parent's own Btrfs mount. Bind mounts of a subtree, and any mount
  at the registry or instance directory, are still refused.
- Allow only known-safe Cargo configuration keys, and refuse aliases (C6a recheck 3).
  `build.sh` checked `$CARGO_HOME`'s config against a list of denied tables, so Cargo
  1.99's `include` could bring in an `[env]` that ran the bless writer, and a
  `CARGO_ALIAS_CLIPPY` could replace the lint gate. The config may now set only `http`,
  `net`, `registry`, `registries`, `term`, `cargo-new` and `source`, and any
  `CARGO_ALIAS_*` variable is refused.
- Read a Btrfs `subvol=` path whole (C6a recheck 3 HIGH 2). The mountinfo parser split
  the options at every comma, so a subvolume with a comma in its name (`/@var,archive`)
  looked like a bind mount and an empty flag-off node refused to upgrade. Btrfs prints
  `subvol=` last with commas literal, so the path is now everything after the first
  `subvol=` in the superblock options (or the mount options if those have none).
- Keep stopped instances in the upgrade (C6a recheck 3 HIGH 1). A stopped instance was
  inspected once and forgotten, so an account job that made one of its checkpoints busy
  after that inspection and exited went unseen. The journal now keeps every inspected
  stopped instance, both account rescans cover it, and with the new images installed,
  just before the units start, a fresh snapshot of it is inspected again; a busy row or a
  changed ID rolls the upgrade back. Its state is still never migrated or restored.
- Accept a Btrfs subvolume on the registry's path (C6a recheck 2 HIGH 4). The inventory's
  mount check took a separately mounted subvolume (`/var` rooted at `/@var`) for a bind
  mount and refused even an empty flag-off node. A `btrfs` mount whose root is exactly its
  `subvol=` path, at a subvolume root, now counts as a whole filesystem; a Btrfs mount
  rooted below its subvolume and any other non-`/` root are still refused.
- Resolve `build.sh`'s paths before checking them (C6a recheck 2 HIGH 3). A relative
  `CARGO_HOME` was checked from the caller's directory but read by cargo from the
  repository, so its `[env]` could bless goldens. `build.sh` now changes to the repository
  first, resolves `CARGO_HOME`, `RUSTUP_HOME`, a toolchain path, `CARGO` and
  `CARGO_TARGET_DIR` to absolute paths and exports them, and refuses a relative `HOME` and a
  set `RUSTDOC` or `CLIPPY_CONF_DIR`.
- Make the rollback's state restore crash-consistent (C6a recheck 2 HIGH 2). The journal
  marks an instance's restore before it touches the live state and clears the mark only
  after the directory is synced; a retry that finds it redoes the whole restore rather than
  trusting the live schema. The account stages and syncs every file before it removes the
  sidecars the snapshot lacks and renames the database, then its WAL, in.
- Close the upgrade's quiescence race (C6a recheck 2 HIGH 1). `kilnd init-state` gains
  `--refuse-busy-checkpoints`, which only the upgrade passes: it checks for busy
  checkpoints inside the migration's own IMMEDIATE transaction (or, at the current schema,
  one of its own) and exits 75 with nothing committed if it finds any, so the upgrade
  rolls back instead of migrating over a row a late account job wrote. The process scan,
  now a documented guard rather than a fence, also runs again before the images are
  replaced and before the units start.
- Fix the C6a recheck's maintenance findings (four HIGH). The upgrade's checkpoint check
  also covers every standard state directory (`/var/lib/kilnd`, `/var/lib/kilnd-<name>`)
  that no unit or enrollment names, and refuses one whose account is gone if it may hold
  checkpoint state. Before each copy it refuses while any process still runs as the
  instance's account (`KillMode=process` leaves them). The account now takes one SQLite
  backup of its database and WAL, the rollback snapshot included, instead of copying the
  files one by one. The instance ID comes only from that snapshot or the enrollment, never
  the live state; checkpoint state without one is refused until kilnd has run once. The
  artifact inventory walks from `/` without following links, requires root-owned ancestors
  no one else can write, and refuses bind mounts and any mount point other than one whole
  filesystem's root, or an unreadable `/proc/self/mountinfo`.
- Pin the checkpoint wire contract's field numbers by hand (C6a recheck 1 HIGH). A table
  of every field of every checkpoint message, `NodeResourceStats`, the checkpoint fields
  of `RuntimeCapabilities`, `ApiLimits`, `AdmissionStats`, `Sandbox` and
  `CreateSandboxRequest`, `Feature` 9 and the checkpoint enums (name, number, type,
  label) is checked against `kilnd.proto` by a parser that refuses anything unexpected in
  those blocks; nothing blesses it. The wire golden gains `NodeResourceStats`, its two
  checkpoints differ in their booleans so swapped tags change the bytes, and the
  previous client's expectations are literals covering limits, stats and node
  resources too.
- Close the checkpoint acceptance gates (C6a recheck 1, two HIGH). `scripts/build.sh`
  refuses, before cargo runs, a `.cargo/config` or `.cargo/config.toml` in the workspace
  or a parent directory (other than `$CARGO_HOME`'s own), a `$CARGO_HOME` config with
  `[env]`, a target runner or linker, or a `build` key it does not override, and any
  `CARGO_TARGET_*_RUNNER`, `CARGO_TARGET_*_LINKER`, `CARGO_BUILD_*` or `CARGO_ENV_*`
  variable, and passes a pass-through runner for every target; the workspace-config check
  moved here from a test a runner could skip. A full-suite test runs the suite once with
  its libtest output kept, and the ledger check requires every compiled test in that run
  (`ok`, or `ignored` as listed), none filtered out, and every ledger test `ok`. The
  checkpoint goldens are never written by the suite: only the ignored
  `bless_checkpoint_contract` test does, run by name with
  `KILND_BLESS_CHECKPOINT_CONTRACT=1`, which `build.sh` refuses outright. New
  `scripts/build-config-regressions.sh`, run by the gate regressions.
- `kilndctl run` calls a command finished only when the daemon's execution record shows
  it ran to its end (EXITED, or TIMED_OUT). A FAILED, CANCELED or INTERRUPTED record
  followed by a failed cleanup says "Exec reported FAILED (kilndctl exit 125), but
  cleanup failed"; exit codes are unchanged (C6a recheck 1 LOW).
- Fix the C6a adversarial review's maintenance findings (four HIGH). The upgrade's
  checkpoint check now covers every configured or enrolled instance, stopped ones too; it
  reads root's snapshot through a copy the instance's account can read but not change,
  never the live database, and refuses a database identity other than the enrollment's.
  The artifact inventory opens every registry component without following a link and
  refuses one not private to root or on another filesystem; it compares names, types and
  inodes only, and an absent instance directory is an empty one. A rollback that finds
  the artifacts changed keeps its record and every unit down, through `recover`, other
  commands and reboots, until `kilnd-maintenance.py accept-artifacts`.
- Check the checkpoint acceptance ledger against the compiled tests (C6a adversarial
  review, two HIGH). A full `scripts/build.sh PROFILE test` lists each profile's compiled
  tests after the suite passes and refuses a ledger name that is missing or ignored
  (VM names must be compiled and ignored on Linux); the source-text scan is gone. The
  required case and finding IDs are pinned in order, so deleting or renaming one fails.
- Pin the checkpoint messages' protobuf encoding (C6a adversarial review, two HIGH).
  `tests/data/checkpoint-wire.json` holds the wire bytes of every checkpoint message and of
  a fork's create request, and a previous client with its field numbers written by hand
  reads and writes them, so renumbering a field fails. The contract golden records the
  fixture clock's times as exact offsets (`<clock+N>`) and checks each published deadline
  against its policy. `KILND_BLESS_CHECKPOINT_CONTRACT=1` refuses to bless while `CI` is
  set.
- `kilndctl run` no longer calls a deadline it mapped to exit 124 a finished command when
  cleanup then fails: it says "Exec returned kilndctl exit 124, but cleanup failed", and
  keeps "the command finished" for an exit the daemon's execution record confirmed.
- Add milestone C6a of workspace checkpoints: acceptance groundwork. The feature stays
  off by default and testing only. `scripts/upgrade.sh` refuses (exit 2, nothing changed)
  while any checkpoint is capturing or deleting or a fork is still restoring from one, and
  records each instance's checkpoint artifact inventory beside its database snapshot; a
  rollback whose artifacts no longer match restores everything but keeps kilnd stopped and
  exits 3, listing what was added, missing or changed, until `kilnd-maintenance.py
  accept-artifacts`. New `docs/checkpoints.md`
  covers states, cleanup, backup and restore, upgrade and rollback; a draft
  `docs/checkpoint-rollout-gate.md` lists the criteria for enabling the feature. Tests add
  rewind, best-of-four and eval-reset client fixtures through the API, harness contract
  goldens (`KILND_BLESS_CHECKPOINT_CONTRACT=1` regenerates them), a ledger tying every
  design crash point, acceptance case and review finding to its tests, a two-thread race
  of supervisor exits, and lowered budgets over existing charges.
- Fix `kilndctl run` reporting "nothing was sent" after Exec reached the daemon. When
  the connection was lost during Exec, the cleanup Delete's error replaced Exec's
  "outcome unknown". Exec's result or error now always comes first; a failed Delete
  follows on its own line, naming the sandbox that may remain.
- Fix three findings of the C5b-2 adversarial review (one HIGH, one MEDIUM, one LOW).
  `kilndctl` uses one connection per command and never reconnects, so a feature check
  always covers the request that needs it; a lost connection fails the command, saying
  whether the request was sent, and `create --from-checkpoint` also fails, keeping the
  sandbox, if the answer does not name the checkpoint. Checkpoint removal, expiry and
  startup cleanup no longer depend on the probes only new work needs (XFS, project
  quotas, registry trust, free space): the helper's `capabilities` reply gains an
  optional `removal_supported`, and with an older helper removal keeps its previous gate.
  Health's checkpoint stats count a charge whose release evidence was quarantined, as
  node accounting does.
- Add milestone C5b-2 of workspace checkpoints: discovery and capacity. With
  `--enable-workspace-checkpoints`, Health lists `FEATURE_WORKSPACE_CHECKPOINT` with
  `RuntimeCapabilities.checkpoint` and `ApiLimits.checkpoint` only while the root
  helper's checkpoint probes pass (the CLI's leases, listing and removal; XFS with
  project quotas at kiln's runs; a trusted image registry; the checkpoint format; known
  free space on runs and its loop backing), and withdraws them when one fails; Firecracker
  never lists them. Health reports `CheckpointStats` and
  `checkpoint_reserved_disk_bytes` while checkpoints are on or any exist. New
  `--checkpoint-headroom-bytes` (default 1 GiB): a capture or create from a checkpoint is
  refused `checkpoint_quota` unless that much stays free after it and every other
  admitted one, and `checkpoint_io` when free space is unknown. A capture's size limit
  is rounded down to 512 bytes. The helper's checkpoint `capabilities` reply gains an
  optional `storage` field. New `kilndctl create --from-checkpoint`, refused unless Health
  lists the feature, and checkpoint lines in `kilndctl health`. The flag stays testing
  only; with it off, Health and every RPC are unchanged.
- Fix three checkpoint API defects (C5b-1 adversarial review: two MEDIUM, one LOW). A
  create from a checkpoint whose caller leaves before its row commits is no operation;
  ListCheckpoints pages search the owner's or source's index instead of the node's
  history; `kilndctl checkpoint ls` works against any `--max-list-page-size` and takes
  `--page-size`.
- Add milestone C5a-2 of workspace checkpoints: create a sandbox from a checkpoint
  (fork), reachable only from Rust (`CreateRequest.from_checkpoint`) and off unless
  `Limits::checkpoints` is set. The preflight refuses before any allocation, a
  Firecracker backend first (`backend_unsupported:workspace_checkpoint`, before
  prepare); a foreign checkpoint is `NotFound`. One transaction commits the CREATING row,
  its reservation, a version 2 key record (`kilnd.v1.create-request.2`; version 1 digests
  are unchanged), the provenance, the checkpoint's image identity and the read-pin; the
  helper's `Restore` then makes the backend before READY. A reader's `complete` or
  `not_started` evidence releases the pin; otherwise the checkpoint's removal does.
  Checkpoint Delete and expiry fail running forks before READY; a fork supervisor that
  loses its reader arms the checkpoint barrier, whose pass settles orphaned readers.
  The helper no longer counts a restored sandbox's init (forked from its shim, with the
  shim's arguments) as a reader, so a checkpoint can be removed while its forks run.
- Harden checkpoint forks (C5a-2 adversarial review: three HIGH, two MEDIUM). A fork's
  final restore outcome is durable before its pin is released: `Created` records the
  exact backend on the row, `NotCreated` fails it definitely and releases the
  reservation; startup settles interrupted forks from that row or the helper's record
  before the legacy CREATING rule, compensating a restored backend instead of reporting
  it unmanaged. The allocation barrier's admission is now atomic with the reservation of
  every create and capture. The helper's untracked-worker scan parses kiln's exact
  command grammar (never past `--`) and requires the trusted kiln executable with a
  stable start time, so an Exec's arguments can no longer pose as a checkpoint reader.
  Stored fork failures keep their `checkpoint_*` token, and a restore that proves the
  artifact corrupt quarantines the checkpoint.
- Settle checkpoint forks from their rows (C5a-2 adversarial review recheck: one HIGH,
  three MEDIUM, one LOW). Startup and every barrier pass settle each CREATING fork no
  supervisor owns from its reader's record even after the checkpoint's Delete or expiry
  released its pin, and allocation stays blocked until each is settled; a fork with a
  recorded backend is compensated, never failed beside it; a failed settlement write
  keeps allocation blocked; an interrupted fork's stored failure keeps its
  `checkpoint_*` token; and the helper's worker scan follows kiln's full command grammar
  (required options and capture's source, no repeats, nothing after `--` where kiln takes
  nothing, empty words kept).
- Close the C5a-2 recheck-2 follow-ups (two MEDIUM, two LOW). Startup leaves every
  CREATING fork that row-driven settlement kept for the barrier's pass alone, with or
  without a recorded backend ID, so a fork whose compensation failed never becomes READY
  at startup. A fork whose backend-ID or READY write fails stores, returns and replays
  `checkpoint_io: …` for keyed retries. The helper's worker scan now matches kiln's clap
  grammar on three more edges: `--require-exec-protocol` takes clap's signed form (`-0`),
  an empty `--writable` path is refused, and a non-UTF-8 word is refused except in a
  `--writable` path. New direct tests cover capture's required `--generation` and
  `--max-bytes` and the retention rule that keeps a CREATING fork's checkpoint and pin.
- Add milestone C5b-1 of workspace checkpoints: the API. New RPCs `CheckpointSandbox`,
  `GetCheckpoint`, `ListCheckpoints` and `DeleteCheckpoint`; `CreateSandboxRequest.
  from_checkpoint` (field 5) and `Sandbox.from_checkpoint` / `checkpoint_content_sha256`
  (20/21); and, defined but not yet filled, `FEATURE_WORKSPACE_CHECKPOINT = 9`,
  `ApiLimits.checkpoint`, `AdmissionStats.checkpoints` (`CheckpointStats`, with `expired`
  as field 26 beyond the design's appendix) and `NodeResourceStats.
  checkpoint_reserved_disk_bytes`. Every refusal is typed, with design 7.3's code. A
  keyed fork's digest is version 2; version 1 digests are unchanged. List pages are
  newest first with caller- and filter-bound continuations. New `kilndctl checkpoint
  create|get|ls|rm`. **`--enable-workspace-checkpoints` (default off) is for testing
  only:** this release advertises nothing and runs no free-space headroom check before a
  capture or fork; discovery, Health's checkpoint stats and the headroom check come next.
  With the flag off and no checkpoint state, every checkpoint RPC is refused
  `backend_unsupported:workspace_checkpoint` before any store query; existing
  checkpoints stay readable and deletable. The exit check's ownership read now shares
  one lock with the leaving supervisor's removal, for any runtime.
- Harden the checkpoint engine (C5a-1 adversarial review: eight HIGH, one MEDIUM).
  Delete and expiry hand removal to a supervisor before awaiting, so a departed caller
  never strands a charged row; existing checkpoints are expired, removed, rebased and
  reconciled with the feature off, and their keys answered; capture keys from an
  earlier boot get a fresh retention window at startup; a transient Inspect failure
  keeps a READY checkpoint and blocks instead of quarantining it; the startup barrier
  blocks on a failed capability probe and on tracked helper activity no row explains,
  and retries until clean with no restart; shutdown removes a running capture before
  releasing its source; a caller that leaves before C1 allocates nothing.
- Close three variants the checkpoint engine's recheck found: any durable checkpoint
  state makes a failed helper session block allocation until a clean retry; presence
  falls again when the last row and key are pruned (recounted under the lock C1's insert
  takes), restoring the no-query path with the feature off; startup and Delete never
  remove a source an interrupted capture may still read, the capture's removal re-drives
  the source's delete, and shutdown stops draining after 240 s.
- Close the checkpoint engine's sixth recheck with one rule: a checkpoint pass (at
  startup or in the barrier's retry) is clean only if every charged row is sealed (READY
  or QUARANTINED) or a capture running in this process, so such a pass, a restart's
  included, keeps allocation blocked beside a dead or failed capture or a DELETING row
  until its removal proves ABSENT (a pass rule, not a lifetime rule: see the ninth
  round below); a removal that finds an artifact it
  cannot prove its row's arms the durable barrier and its retry, and that retry's clean
  pass reopens allocation without a restart; a stale clean verdict cannot clear a later
  arm.
- Close the checkpoint engine's seventh recheck: a barrier pass's verdict is tied to a
  state epoch taken with its snapshot of rows and live captures, and moved by every
  capture failure, intent into DELETING and retryable removal, so a capture that fails
  or a row deleted while the pass awaits the helper refuses the stale clear; the retry
  passes again promptly.
- Close the checkpoint engine's invariant ruling: the pass rule above governs what a
  pass may call clean, and after a clean clear Create may run beside a failed capture or
  a DELETING row while this process owns its cleanup and its charge stays counted.
  Losing that ownership arms the barrier: a capture failure that cannot be recorded, and
  any capture or removal supervisor that ends (a panic included) leaving a charged
  unsealed or DELETING row no other supervisor owns, outside shutdown. The barrier's pass
  then records the dead capture and resumes its removal.
- Close the checkpoint engine's fifth recheck: the barrier's marker is written ahead,
  before any checkpoint helper pass at startup or in the retry, so a crash after a
  blocking verdict cannot lose it; a backend without checkpoints keeps an outstanding
  marker and stays blocked until a checkpoint backend's clean inventory clears it; and a
  removal that found an artifact it cannot prove its row's keeps allocation blocked
  across a restart until a removal proves it absent.
- Close the checkpoint engine's fourth recheck with schema 16: a blocked checkpoint
  barrier writes a durable marker (`checkpoint_barrier`, one row) that only a complete
  clean inventory deletes, so a restart reconciles again even with the feature off and
  no checkpoint rows. Older binaries refuse schema 16.
- Close the checkpoint engine's third recheck: while the checkpoint barrier is blocked,
  retention keeps every checkpoint row and capture key, so a restart before a clean
  inventory still reconciles instead of admitting allocations beside an unexplained
  artifact.
- Close the checkpoint engine's second recheck: pruning the last row no longer clears a
  blocked barrier without a clean inventory, and startup keeps its retry running; a
  capture canceled by checkpoint Delete (D1) keeps its source held until ABSENT, and
  that ABSENT re-drives the source's delete; every shutdown phase ends by the 240 s
  limit, whatever `--shutdown-grace-secs` says.
- Add milestone C5a of workspace checkpoints, the daemon's engine, reachable only from
  Rust and off unless `Limits::checkpoints` is set: supervised capture (source gate
  against Exec, Delete and both expiries; READY only with the capture's own COMPLETE
  evidence; every failure removed and proved absent before the source is released),
  the D1-D3 removal shared by Delete, expiry and failed captures (busy and unavailable
  retried; a generation mismatch or corrupt artifact keeps its charge and blocks
  allocation), checkpoint expiry with the Get CAS and the cross-boot rebase, startup
  reconciliation against the helper's inventory, capture keys with their own digest,
  design 7.3's typed reasons, and the Firecracker refusal before any helper call or
  allocation. The root helper's checkpoint group gains `source`, which reads a run's own
  `image` and `layout` records (no-follow, 4 KiB, strict) so the daemon can record a
  source's image identity once at its first capture. No RPC, flag or Health field yet.
- Bind every stored checkpoint fact to the helper epoch and boot its dispatch was
  recorded under (checkpoint C4 adversarial review, HIGH 1): COMPLETE to the capture's,
  ABSENT to the latest removal's, a reader's end to its pin's. Evidence about the right
  nonce from another helper process or boot no longer seals READY, releases a charge or
  releases a pin, in the typed paths, the SQL triggers or the audits.
- Add milestone C4 of workspace checkpoints, the daemon's store: schema 15 with every
  table and column the feature needs (checkpoints, helper evidence, fork pins, capture
  keys, trigger-kept counts and membership aggregates; fork provenance and image
  identity on sandboxes; a create request digest version). A checkpoint is charged R,
  then its sealed S, until ABSENT evidence of its own removal is stored, in the same
  node disk budget sandbox reservations use, and admission checks every per-checkpoint,
  per-uid and node cap in one transaction. Triggers refuse tampering through ordinary
  SQL; every accounting decision audits the rows it depends on, and a mismatch refuses
  capture and sandbox Create without freeing capacity. The migration audits schema 14's
  membership first and changes no existing row, digest or charge. The feature stays
  off: no RPC, Health field or command uses the store yet. Older binaries refuse schema
  15; rollback restores a backup with its matching artifacts.
- Take back a fresh removal's tombstone when kiln answers `checkpoint_busy` too, not
  only on a generation mismatch (checkpoint C3 adversarial recheck, LOW L1): a busy
  removal naming the wrong generation removed nothing, but its tombstone refused the
  real generation's operations until pruning.
- Fix the checkpoint C3 adversarial review findings. **H1 (HIGH):** a helper that had
  forgotten an artifact (idle pruning, or a new epoch) removed another generation's
  published artifact and sealed ABSENT for the generation it was asked about. Removal now
  passes `--generation` to kiln, which refuses another generation
  (`checkpoint_generation_mismatch`) and removes nothing; the absence check reads
  generations from staging and removal names; a kiln without generation-checked removal
  is unsupported and its usage error is a typed failure. **M1 (MEDIUM):** removal waited
  for a cleanup slot instead of refusing; it now reserves one at admission, or answers
  `workers` with no state changed, and holds it until it settles.
- Add milestone C3 of workspace checkpoints, the root helper's side: a checkpoint group
  in the helper protocol (capabilities, capture, restore, inspect, remove, inventory,
  acknowledge), off unless `kilnd-helper --enable-checkpoints`. It supervises kiln's
  capture and fork workers on fixed copy and cleanup lanes with no queue, holds reader
  leases and exclusive captures until each worker is reaped, tombstones an artifact
  before removing it, and certifies COMPLETE, ABSENT and reader-ended evidence (canonical,
  bounded, ID'd, bound to the artifact, nonce and helper epoch). A new helper epoch
  refuses the old one's requests, and any process still naming an artifact blocks its
  absence. The runtime adapter checks every reply. No RPC, Health field or feature
  changes.
- Fix the M4 recheck finding (LOW M4-R1): the smallest accepted
  `--exec-stream-buffer-bytes` did not hold two chunks once deque slots were charged.
  The minimum is now two chunks with their overhead plus the eight slots a drained
  queue keeps (65,984 bytes for 32 KiB chunks); regressions cover a fresh queue and a
  drain and refill.
- Fix the M4 break-it finding (MEDIUM M4-B1): the ExecStream live queue charged an
  entry's logical length, so coalescing let `Vec` growth hold up to about twice
  `--exec-stream-buffer-bytes` of payload capacity. The queue now charges allocated
  capacity (growth geometric up to one chunk, or exact when only that fits), the
  64-byte per-entry overhead and every deque slot, and shrinks the deque after a
  drain; a regression and a churn test check the charge never drifts or passes the
  bound. The break-it's own controls are adopted as tests (a continuously readable
  live socket does not monopolize the runtime; unread finished streams hold no
  permit and keep their whole row), and a fault hook now covers the post-publication
  row-read failure.
- Add milestone 4 of the kilnd API additions: `rpc ExecStream`, Exec with live
  output, additive within `kilnd.v1`; every existing request and response is
  byte-identical. The request wraps an `ExecRequest` and runs the same validation,
  gates, sandbox checks and admission as Exec, in the same order, plus a stream permit
  (`--max-exec-streams` 16, `--max-exec-streams-per-uid` 8; startup refuses a per-uid
  cap at or above the node's and a node cap at or above `--max-concurrent-execs`);
  refusals before the execution row are RPC errors with no message
  (`backend_unsupported:exec_stream`, `exec_stream_limit`). After the row the stream
  carries `ExecStarted` (seq 0), `OutputChunk`s of at most `--exec-stream-chunk-bytes`
  (32 KiB) at the capture reader's offsets and `OutputGap`s before the next chunk,
  then one `ExecFinished` whose execution is GetExecution's row byte for byte, with
  per-stream `LiveDelivery`; a tail gap is exact only when the capture total is.
  `kilnd-exec-core`'s capture readers gain a `LiveTap` that observes each read after
  counting it and can never block or alter capture. The helper's kiln `exec` gains
  `live` (omitted when false) and a fourth descriptor, a `SOCK_SEQPACKET` socket on
  which it sends `[stream u8][offset u64be][bytes]` messages with `MSG_DONTWAIT`,
  dropping on `EAGAIN`; its `features` reply gains `exec_stream`, which proves
  `FEATURE_EXEC_STREAM` (Linux only). kilnd's per-execution queue is bounded by
  `--exec-stream-buffer-bytes` (256 KiB) and drops what does not fit. Dropping the
  stream cancels like Exec (`CLIENT_DISCONNECTED`); a client that only stops reading
  loses live bytes, and every permit is released when the final message is handed to
  the transport. Stream timeouts default to 30 minutes, at most
  `--max-stream-timeout-secs` (2 h), within a 4-hour helper ceiling for live execs
  (unary stays at 1 h), one deadline fixed on arrival. Schema 14 adds
  `executions.mode` (`unary`, `stream`), returned as `Execution.mode`.
  `AdmissionStats` fills fields 18-20 and `ApiLimits` the stream limits. Firecracker
  refuses ExecStream before anything is allocated. kilndctl gains `exec --stream`,
  `kilndctl execution` shows the mode and `kilndctl health` the stream counts; the
  integration test runs a real long ExecStream and `admission_stress` a 16-stream,
  three-uid resource phase.

- Add milestone 3b of the kilnd API additions: exec cwd and env, additive within
  `kilnd.v1`; with none of the new fields set an Exec runs exactly as before, through
  kiln's operation 4. `ExecRequest.cwd` and `ExecRequest.env`, and
  `CreateSandboxRequest.default_env` for sandbox-wide defaults (the request wins by
  name), reach kiln's operation 5 (kiln `5cada84`, capability bit `0x20`). Validation
  in kilnd, again in the root helper at the code ceilings and again in kiln: a cwd is
  absolute, at most 4,096 bytes, without NUL and not normalized; an env list has at
  most 64 entries, names `[A-Za-z_][A-Za-z0-9_]*` of at most 128 bytes given once,
  values of at most 4,096 bytes without NUL and at most 32,768 bytes in all, for the
  request, the defaults and their merge (`--max-exec-cwd-bytes` and
  `--max-exec-env-*` may lower each). The helper's kiln `exec` request gains `cwd` and
  `env`, omitted when empty so other requests stay byte-identical; it writes kiln's
  options frame into a memfd sealed with exactly `F_SEAL_SEAL|SHRINK|GROW|WRITE`
  (`MFD_EXEC` under `vm.memfd_noexec=1`; under 2 it proves no options) and passes
  only its descriptor number, so no value reaches a host command line. A new helper
  `features` probe proves `EXEC_CWD`, `EXEC_ENV` and `SANDBOX_DEFAULT_ENV` from the
  installed CLI's bit `0x20`; an unproven option is `UNIMPLEMENTED
  backend_unsupported:<feature>` before any row, ticket, prepare or helper call
  (Firecracker proves none), and a sandbox whose PID 1 did not advertise the bit at
  `READY` (recorded once in `sandboxes.exec_features`; null on older rows) is
  `FAILED_PRECONDITION sandbox_unsupported:<feature>` before an execution row. After an
  operator downgrade the per-exec probes refuse with no child started
  (`exec_options_unsupported`); kiln's own probe of a busy PID 1 is the retryable
  `exec_options_unconfirmed`. A cwd that cannot be entered is a `FAILED` execution with
  `RUNTIME_STAGE_CWD` (14), the errno name (`ENOENT`, ...) as `native_code` and
  `cwd_not_found`, never a fallback to `/`. History keeps `Execution.cwd`, `env_names`
  and `env_sha256` (SHA-256 over `kilnd.v1.exec-env.1`, a zero byte and each override
  sorted by name as `u32be len, name, u32be len, value`: an integrity fingerprint, not
  confidentiality), and `Sandbox.default_env_names` and `default_env_sha256`; the
  default values are plaintext in `sandboxes.default_env` while the sandbox is live and
  set to null in the statement that makes it `FAILED` or `DELETED`. Values are kept out
  of `Debug`, errors and logs; a canary test checks logs, every response and every
  logical database column. The create request digest now covers `default_env`
  (goldens added). Schema 13 adds the columns and their triggers. kilndctl gains
  `exec --cwd DIR --env NAME[=VALUE]` and `create --default-env NAME[=VALUE]` (a bare
  `NAME` passes kilndctl's own value), refused unless Health lists the feature.
- Fix the M3b break-it findings. A create with `default_env` whose new sandbox's
  post-create feature probe failed, or answered without bit `0x20`, came back `READY`
  with `exec_features` null, refusing every Exec; it now removes the backend, settles
  `FAILED` (reservation released, defaults cleared) and fails `UNAVAILABLE
  sandbox_feature_probe_failed`, retryable, and a keyed create stores that `FAILED`
  row. A `grpc-timeout` header kilnd's strict parser rejects, such as tonic's
  accepted `+300m`, is now `INVALID_ARGUMENT invalid_grpc_timeout` before dispatch
  rather than an untyped `CANCELLED` that skipped the typed deadline. The helper's log
  of a malformed request frame names only the parse category and position, never
  serde's text, which quoted the frame's values.
- Fix the M2 recheck's MEDIUM 1: a `grpc-timeout` in request trailers replaced the
  deadline the create handler reparsed from merged metadata, so a waiting keyed retry
  got tonic's untyped `Timeout expired` instead of `create_in_flight`. The interceptor
  now captures the headers' timeout with their arrival, and only that counts.
- Exec refuses a lost conditional execution insert whose reload shows the sandbox
  `READY` again with its own retryable token, `execution_start_raced`
  (`FAILED_PRECONDITION`), instead of the overloaded `sandbox_not_ready`.
- Docs: an expired sandbox passes through `DELETING` before `DELETED`; kiln `5cada84`
  is the tested companion for exec options and `e48f0e7` stays the minimum for
  everything else.

- Fix the break-it findings on API additions milestone 2. HIGH 1: a create
  request record's retention anchor was read before its admitting transaction began,
  so a pause before the commit (suspend, `SIGSTOP`, a stall) shortened the guaranteed
  window; the review's PoC freed a key 58 min 33.6 s early and created a second
  sandbox. The record now commits unanchored and unprunable, and a second
  transaction anchors it from `CLOCK_BOOTTIME` read under its write lock, after the
  commit; a record left unanchored by a crash or error is anchored later by the next
  prune or the startup rebase, never earlier. A trigger refuses an anchored insert
  and un-anchoring. MEDIUM 1: the `create_in_flight` deadline ran from when the
  handler started, after the request body was decoded, while tonic's own
  `grpc-timeout` runs from the headers, so a late body turned the typed
  `DEADLINE_EXCEEDED` into tonic's untyped `CANCELLED`; an interceptor now stamps
  header arrival and the deadline runs from it. MEDIUM 2: every accounting decision
  rehashed all retained history, so quota fill was quadratic and keyed admission at
  32,768 records took seconds; schema 12 replaces the membership marker (verified
  during the upgrade) with O(1)-updatable aggregates, the request quota reads
  trigger-kept counters, and each decision checks only the charged and recently
  released rows, through a partial index; write decisions settle the releases they
  verified. The first decision after any other connection commits (SQLite's
  `data_version`), startup and every prune verify everything, including that settled
  and live rows add up and every fenced release's evidence; a failed prune latches
  admission off. Admission cost no longer grows with retained history or releases
  between prunes (4,096/32,768-record and create/delete-cycle tests check it; at the
  default caps the review's 32-way last-slot race took 0.04 s on the installed daemon,
  from 5.19 s). Each finding has a regression.
- Add milestone 2 of the kilnd API additions: idempotent create, additive within
  `kilnd.v1`; a client that sets none of the new fields gets exactly the earlier
  behavior. `CreateSandboxRequest.request_id` (1-64 printable ASCII bytes, scoped to
  the caller's uid, echoed as `Sandbox.request_id`) makes a create retryable: the
  original and every retry with an equal request digest return `OK` with the same
  sandbox in whatever state it settled, `FAILED` and `DELETED` included. A different
  request under the key is `ALREADY_EXISTS request_id_conflict`; a retry while the
  original runs waits for it within its own gRPC deadline, else
  `DEADLINE_EXCEEDED create_in_flight`; a CREATING record with no live create is
  `UNAVAILABLE create_unsettled`, never a fresh create. The digest is SHA-256 over
  `kilnd.v1.create-request.1`, a zero byte and the canonical JSON of the request as
  sent; `crates/kilnd/tests/data/create-request-digests.json` holds shared goldens.
  An in-flight map, consulted first, lives until the create and its compensation have
  fully finished. A cancel-safe pending slot before `prepare` and a recount in the
  admitting transaction enforce `--max-create-requests-per-uid` (4,096) and
  `--max-create-requests` (32,768) as `RESOURCE_EXHAUSTED request_id_quota`; the
  record commits with the `CREATING` row. Records are kept at least
  `--create-request-retention-secs` (a day) measured on `CLOCK_BOOTTIME` plus 0.1 %,
  get a fresh window after a reboot (one startup rebase), are never pruned while their
  sandbox is live or charged, and pin their row against ordinary retention, so a
  wall-clock step cannot free a key early (the break-it design review HIGH 1).
  `DeleteSandboxRequest.release_request_id` drops a record only in the transaction
  that sees the row `DELETED`, through the prune-safe path, shown as
  `Sandbox.request_id_released`; the client takes the duplicate risk after it. Health
  lists the static features `IDEMPOTENT_CREATE` and `REQUEST_ID_RELEASE`, reports the
  node and caller record counts in `AdmissionStats` (fields 21-25), retries answered
  and releases in `LifecycleStats`, and the retention in `ApiLimits`. On legacy kiln a
  create crashed before its backend ID was published stays an ambiguous, charged
  `FAILED` that every retry returns (documented). Schema 12 adds `create_requests`
  and the sandbox's `request_id` and `request_id_released_at_ms`, with triggers.
  `kilndctl` gains `create --request-id` and `rm --release-request-id`, refused
  unless Health lists the feature, and shows request IDs and record counts;
  `scripts/idempotent-create-regressions.sh` checks keyed creates, release and a
  daemon killed mid-create against the installed daemon. The docs now say an
  expired sandbox leaves the default listing only once its removal reaches
  `DELETED`.
- Add milestone 1 of the kilnd API additions for the harness: capability discovery,
  typed refusal reasons and sandbox expiry, all additive within `kilnd.v1`; a client
  that sets none of the new fields gets exactly the earlier behavior.
  `Health.runtime_capabilities` gains `features` (static `SANDBOX_EXPIRY` and
  `TYPED_REASONS`, plus a fail-closed dynamic set that only a fresh successful backend
  probe publishes) and `ApiLimits`, and `HealthResponse.lifecycle` reports expiries
  and pending or failed expiry deletes. Not-ready refusals of Exec and the new
  `RenewSandbox` carry a `kilnd-reason` trailer and start their message with the same
  token; codes are unchanged. `CreateSandboxRequest.expiry` sets a maximum lifetime
  (from the first READY) and an idle timeout (from the last execution start or finish,
  or Renew; paused while an execution runs or an admitted Exec is queued); an absent
  policy never expires, and only a present policy's zero fields take the new
  `--default-sandbox-*-secs` flags. Expiry runs through the ordinary delete path,
  recorded as `Sandbox.deletion_reason`; a lifetime expiry cancels the running
  execution with `Execution.cancel_reason = SANDBOX_EXPIRED_LIFETIME`. Deadlines are
  `CLOCK_BOOTTIME`, survive daemon restarts exactly, are rebased once after a reboot
  and get a 60-second idle grace after startup. An indexed timer queue holds one
  entry per durable reservation; idle expiry and Exec admission share a per-slot
  admission gate, so an admitted Exec is never refused by a concurrent idle expiry
  (the break-it design recheck MEDIUM 1), and the queue bound is stated as
  `max(--max-sandboxes, reservations at startup)` (LOW 1). Schema 11 adds the policy,
  anchors, `activity_seq`, `deletion_reason` and `cancel_reason` with their
  triggers. An execution row is now inserted only while its sandbox is still READY.
  `kilndctl` gains `create --max-lifetime/--idle-timeout/--expiry-defaults`, `renew`,
  and shows features, expiry and reasons; `scripts/expiry-regressions.sh` checks real
  deadlines under the installed daemon.
  The milestone 1 break-it fixes: an expiry removal task now exists only while
  it holds one of the `--max-concurrent-expiry-deletes` permits; a due delete without
  one waits as a flag on its bounded pending entry, and each returned permit starts
  the next. A client Delete of an expiry-owned row joins that removal under the same
  permit instead of running a fifth removal, and leaves no waiter behind (HIGH 1).
  Schema 11 stores the expiry intent's anchors, so a restart no longer resets the
  stale-delete age Health reports, and a reboot rebases it (MEDIUM 1). Startup's
  terminal publications of interrupted and concluded executions record finish
  activity, before the rebase in a way that keeps both anchors in one boot
  (MEDIUM 2). The schema 11 upgrade audits a schema 10 membership marker before any
  change and never rewrites it, so a mismatch refuses startup and rolls back
  (MEDIUM 3). `kilndctl create` with an expiry option and `kilndctl renew` require a
  `SERVING` Health that lists `SANDBOX_EXPIRY` first, so an older daemon can no longer
  silently create a sandbox that never expires (MEDIUM 4). A duration above
  `i64::MAX` ms is refused as `INVALID_ARGUMENT` before preparation even with no node
  maximum (LOW 1). `scripts/expiry-regressions.sh` no longer loses created IDs to a
  command substitution: its `create` runs only in the main shell and refuses a subshell,
  and a forced-failure self-test checks its EXIT cleanup (LOW 2). A new step races
  client Deletes against a mass lifetime expiry past the four permits.

- Close the integrated B7 break-it recheck 2 (design section 15, *B7 integrated recheck 2*).
  The dependency gate reads a `#[path]` emitted by nested `cfg_attr`s at any depth
  (`#[cfg_attr(a, cfg_attr(b, path = "..."))]`), and every `path` a `cfg_attr` emits rather
  than the first, each as a conditional source edge beside the module's ordinary location.
  `scripts/dependency-gate-regressions.sh` adds the PoC as case 11. The jailer patch's
  copyright line is now Stephen Estrada; its pinned digest is updated, and the jailer it
  builds is unchanged.

- Close the integrated B7 break-it recheck (design section 15, *B7 integrated recheck*, and
  section 16.10, *Integrated recheck: the transferred hold*). A fault-bearing ledger call
  that ends because the ledger process died no longer lifts its hold on forward effects:
  the hold moves to a barrier for that ledger generation and lifts only after a
  replacement's Handover has imported its latch state, so Create's final boundary and an
  Exec past EXEC_INTENT refuse at their deadlines while no replacement has handed over.
  Health reports `transferred_holds`. The dependency gate follows ordinary out-of-line
  `mod name;` declarations from every scanned file (`name.rs` or `name/mod.rs`, inline
  modules nesting), so a child module under an otherwise unscanned `tests/` directory is
  read. The Firecracker runtime publishes a READY session only under the same
  terminal-aware claim as its digest, and a complete List prunes stale sessions too.

- Integrate B7 milestones 1 and 2 (`phase1b/b7-integrated`) and close the milestone 2
  recheck 3 findings (design section 15, *Recheck 3* and *B7 milestones 1 and 2
  integrated*). `scripts/build.sh` runs cargo in a closed compiler environment: it
  refuses a nonempty `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `CARGO_BUILD_RUSTFLAGS`,
  `RUSTDOCFLAGS`, `CARGO_TARGET_*_RUSTFLAGS`, `CARGO_PROFILE_*_RUSTFLAGS`, `RUSTC`,
  `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`, `CARGO_BUILD_RUSTC*`, `RUSTC_BOOTSTRAP`,
  `CARGO_UNSTABLE_*` and `CLIPPY_ARGS`, sets empty encoded flags itself (so no Cargo config
  file supplies any) and resets `build.rustflags` and the target tables; Clippy's
  arguments are its fixed `-D warnings -D clippy::disallowed_methods`, and a caller's tail
  is refused. New `--crt-static` (with `--target`) replaces `b4-vm-tests.sh`'s exported
  `RUSTFLAGS`. Every workspace crate has a build script that refuses a `--cfg`, `-Z` or
  response-file compiler flag, raw builds included. The dependency gate scans each
  scanned package's whole directory (build scripts and binaries included; unreached
  `tests/`, `benches/` and `examples/` files excepted) and follows literal `#[path]` and
  `include!` edges; an edge outside the package refuses it, and one it cannot follow is
  an `unresolved source edge` needing a reviewed exception. Ten new exceptions (37) and
  seven packages moved from groups to their own justifications. The raw-build policy
  test reads every Markdown, shell, Python and workflow file; `CLAUDE.md` and the test
  deployment's README use `build.sh` profiles. The regression script adds the break-it reviewer's
  compiler-cfg and `#[path]` PoCs. The VM test library build's optimized dependencies are
  now the `vm-test` Cargo profile.

- Fix the B7 milestone 1 recheck residuals (design section 16.10, "Recheck residuals").
  A lost answer to a fault-bearing ledger request (its deadline or cancellation dropped the
  helper's wait) is consumed when it arrives and its fault imported, and forward effects are
  held until then. Under the latch the ledger process serves only an explicit allowlist:
  supervisor resource intents, forward phases and a new check before every guest-broker
  Initialize are refused, and the helper acknowledges only teardown. A stale Inspect reply no
  longer relearns a forgotten digest, and a complete List drops digests of allocations the
  helper no longer holds. VMM adoption waits out, within its bound, only a seccomp filter not
  yet installed. A missing or unreadable `/sys/block` makes the offline inventory unknown. The
  console-flood test guest floods only after Initialize.
- Fix the B7 milestone 1 break-it findings (design section 16.10). A replacement ledger
  process now hands its latch state (fault rows, fail-stop marker, in-memory latch) to the
  helper together with the token key, and the helper latches before publishing it, so a
  fail-stop survives a ledger process that died before its `SyncFailed` reached the helper;
  the ledger process itself refuses C2 admission, PREPARING, `spawn_intent` and EXEC_INTENT
  under its own latch. Create rechecks the latch immediately before releasing the
  supervisor, and Exec after EXEC_INTENT and before dispatch (retiring the VM). The offline
  inventory walks jail directories, jail mounts, loop devices, VMM and supervisor
  processes, cgroups and work files node-wide, and any orphan blocks `clear-node-faults`.
  The daemon's per-allocation digest cache is learned at Create, forgotten at every terminal
  answer and capped at 5,120 entries (Preflight answers `RESOURCE_EXHAUSTED` at the cap; new
  `RuntimeError::Exhausted`). RTC-10's delete triggers check the child rows explicitly, so
  they hold with `foreign_keys` off; schema-2 development ledgers provisioned before this
  change must be re-provisioned.
- Build Phase 1b B7 milestone 1, retired-token compaction (design section 16, RTC-1 to
  RTC-18; as built in section 16.9). The helper issues every Firecracker allocation token
  (seq and an HMAC-SHA-256 tag under a per-node key); node ledger schema 2 keeps an exact
  issue pointer and a watermark per instance, and a compactor deletes only absent, released,
  settled rows below it on its own lane, behind SQL triggers, so a node admits sessions
  indefinitely. Group schema 2: Preflight issues the token, Inspect and Remove carry the
  plan digest, Gc takes digest-bearing targets all or nothing, AttachInstance reports the
  daemon's highest verified token. Compacted tokens answer a synthesized receipt for the
  caller's digest. Reserved per-slot headroom shares, per-window never-admitted quotas,
  bounded checkpoints. A verified future token or any failed ledger commit fail-stops
  forward effects node-wide until root's new `kilnd-helper offline-inventory` and
  `clear-node-faults`; `ledger-stats` reports. The Runtime trait takes `PrepareContext` and
  a typed `RemoveTarget`; Firecracker refuses a legacy target before any wire call. The
  measured per-token bound is 20 KiB, the fence allowance 128 MiB, delete batches 16 tokens.
  Schema 1 ledgers must be re-provisioned. Production Firecracker stays disabled.
- Fix a B4 launch race the B7 real-chain run found: the supervisor could observe the VMM
  before its exec, when the ptrace-read check still refuses it, and refused a few
  launches in a hundred under load. It now waits out that refusal, bounded, and refusal
  reasons name their launch step. The VM test build optimizes dependencies so a real
  helper meets its wire deadlines.
- Phase 1b B7 milestone 2 recheck 2 (design section 15, *Recheck 2*): the dependency
  gate's guarantee now covers builds made through the one supported entry point, new
  `scripts/build.sh PROFILE COMMAND`. `dependency-gate.json` gains `profiles` (`default`,
  `firecracker-test-deployment`), each a set of workspace features; `build.sh` runs cargo
  with `--locked` and only its profile's features, and refuses `--features`/`-F` (so
  `tokio/full`-style dependency selectors), `--all-features`, `--no-default-features`,
  `--manifest-path`, `--config` and `-Z`. The gate resolves every profile with exactly
  those flags instead of one `--all-features` resolve, so a package or feature any profile
  builds must be locked and reviewed, and kinds come from the union of the profiles' graphs.
  CI, `scripts/install.sh`, the VM scripts and the setup instructions build through it, and
  a test refuses a raw cargo build there; a raw `cargo build` with other feature flags is
  outside the guarantee. The subtree scan now flags every occurrence of a sink identifier
  (`LocalFile::set_len(self, 0)`, a function value, a `use` list, a definition), not only
  `.name(` calls, resolves `type` aliases in the impl check and flags an alias of std's or
  Tokio's file or process types itself; exceptions are labelled by identifier (27, five
  new). One `name@version` from two sources is refused by the gate and the drafter. The
  authoritative `the_dependency_gate_holds` always checks its own workspace; the
  regression script uses the ignored `regression_fixture_gate` instead of
  `KILND_DEPENDENCY_GATE_ROOT`, and adds the break-it reviewer's feature-injection, type-alias UFCS,
  two-registry and root-override cases.
- Phase 1b B7 milestone 2 recheck, HIGH-1 (design section 15, *HIGH-1 recheck*):
  the dependency gate now fails closed on review. `dependency-gate.json` reviews every
  package in `Cargo.lock` (144: direct and transitive), each keyed `name@version` and
  pinned to its lock checksum and resolved features, with a kind, a capability and a
  written justification (shared ones only for packages the test proves name no file,
  process, libc or Tokio fs/process path). A new package, version, checksum or feature set
  fails until reviewed; new `scripts/dependency-gate-review.py` drafts the mechanical
  fields. For every package declared `none`, `network` or `no_destructive_api`, the
  source of its whole runtime subtree, read from cargo's own resolve, is scanned for
  curated destructive method names whatever the receiver (`.set_len(`, `.truncate(`,
  `.remove_file(`, `.kill(` and the rest), disallowed paths and trait impls on std's and
  Tokio's file and process types. Each hit needs a `sink_exceptions` entry scoped to
  package, version and feature set (22 today). This refuses the break-it reviewer's extension-trait
  `method-wrapper` and the re-exporting `outer-wrapper`/`inner-wrapper`. The claim is
  narrowed to what the gate guarantees, and identifying a destructive API stays the
  reviewer's job. `scripts/dependency-gate-regressions.sh` runs the recheck PoCs, a
  version bump and an exception's scope through the actual loader, cargo and clippy.
- Phase 1b B7 milestone 2 break-it corrections (design section 15, *B7 milestone 2
  break-it corrections*). Ingress: kilnd refuses to start unless one UID's connection
  share is strictly below the general pool and, with its reserved slot, below
  `--max-connections`, its RPC share strictly below `--max-concurrent-rpcs`, and at
  least one reserved connection and one cleanup permit exist (the break-it reviewer's accepted
  `33/1/32` let one UID hold every slot); UID 0 keeps one connection slot and one
  Health/cleanup RPC permit beyond the budget; the design and threat model now call the
  reserve first-come and bounded per UID. Dependency gate: `dependency-gate.json`
  records a reviewed kind and capability for every direct dependency instead of
  inferring capability from `Cargo.lock`, a destructive-capable one lists its
  destructive paths for `clippy.toml`, build-only and dev-only kinds are checked against
  the lock graph, and two backstops catch a mistaken `none` (the break-it reviewer's `fs-err`
  wrapper). `clippy.toml` gains `std::fs::copy`, `tokio::fs::copy`, `CommandExt::exec`
  and every locked libc function matching the destructive patterns (`creat`, `execl`,
  `popen`, `sigqueue`, `mount`, `truncate64` and the rest), with completeness tests that
  read libc and `tokio::fs` from the pinned sources. New
  `scripts/dependency-gate-regressions.sh` (also a CI job).
- Phase 1b B7 milestone 2: the hardening follow-ups (design section 15, *B7 milestone
  2*). Ingress fairness (B6-BI-03): 4 of the 64 connection slots are held back for
  Health, GetSandbox and DeleteSandbox (one per UID; a connection on one serves nothing
  else), one UID holds at most 32 general slots and 32 ordinary RPCs, Get and Delete
  fall back to a 4-permit cleanup lane (one per UID), and a connection that has not sent
  the HTTP/2 preface within 5 s is closed. New flags `--reserved-connections`,
  `--max-connections-per-uid`, `--connection-preface-timeout-ms`,
  `--max-concurrent-rpcs-per-uid` and `--max-concurrent-cleanup`; new
  `scripts/hostile-public-caller.py` (64 idle sockets from one UID, Health, Get and
  Delete from another), also run on the Firecracker chain by
  `scripts/firecracker-regressions.py`. B4 recheck 6: a socket filesystem without file
  handles (`EOPNOTSUPP`) is refused instead of falling back to an all-zero handle;
  `dependency-gate.json` and a new gate test check every dependency that can wrap
  system calls against `Cargo.lock` and `clippy.toml`; the private procfs root is made
  once under a mutex; `sys::read_dir_fd` lists a fresh `openat(fd, ".")` description, so
  the caller's offset is untouched. B6 recheck: the unprivileged procfs component walk
  refuses a component on another mount; the isolated test deployment's schema 2 names
  the unit's exact cgroup (`kilnd.cgroup`); the capacity crash scenario runs both settle
  paths on every run. Debug and test builds compile `sha2` at opt-level 3, so the debug
  test helper hashes its 71 MiB image in under a second instead of about 14 s on the VM.
- Design the Phase 1b retired-token compaction for B7 (design section 16): today's node
  ledger admits 12,287 sessions in its lifetime and an instance stops after 384 post-C1
  refusals; helper-issued sequence tokens with a per-instance durable watermark remove
  both limits without trusting clocks or daemon state. Design only; no code changes.
- Revise the retired-token compaction design for the break-it design review (section 16.8):
  Inspect, Remove and each Gc target carry the plan digest, the issue pointer is persisted
  exactly, L alone classifies tokens, compaction and admission headroom get guaranteed
  shares (RTC-17, RTC-18), and ledger restore is stated as outside the fault model with a
  mandatory offline inventory. Design only; no code changes.
- Revise it again for the break-it recheck (section 16.8): the rollback detector accepts only
  a helper-issued token whose tag verifies, and its durable latch refuses every forward
  effect node-wide until a root offline clear; the issue pointer is a high-water mark, not
  a delivery record; watermark checkpoints are bounded per pass; section 9.1's Runtime
  listing is the B7 contract; every policy slot's headroom share is reserved. Design only;
  no code changes.

- Phase 1b B6 break-it corrections (break-it review, November 3). B6-BI-01: `--backend
  firecracker` and `--firecracker-test-deployment` exist only in a build with the new
  non-default `firecracker-test-deployment` cargo feature; a default (release, installed)
  build refuses both at argument parsing. A feature build selects the isolated test
  deployment only when this process's real, effective and saved UIDs are the manifest
  account's (`getpwnam`, never root or `kilnd`), the resolved `--socket-group` is the
  manifest group (never `kilnd`), and its own cgroup, read beneath `sys::procfs`, ends in
  the manifest unit; any mismatch is refused, by name, before state is opened. Where
  systemd's `RestrictSUIDSGID=` refuses `openat2` with `ENOSYS`, an unprivileged
  `sys::procfs::open` walks the path one `O_NOFOLLOW` component at a time on procfs. New
  `scripts/test-deployment-gate-regressions.sh` (release, feature and root modes) and a CI
  feature job. B6-BI-04: the crash matrix gains a helper restart while Create polls for
  READY and a daemon death mid-Remove (11 scenarios), and the capacity scenario accepts a
  failed Create's own receipt-backed settlement. `scripts/b4-vm-tests.sh` builds the test
  daemon with the feature.

- Phase 1b B6 milestone 2. `Store::open` no longer opens and closes descriptors to the
  database or its sidecars (it `fstatat`s them and creates a new database itself, 0600,
  before SQLite opens it): a close dropped SQLite's own POSIX locks, so another process's
  connection could unlink the live WAL and a crash then lost committed state. Exec on a
  session that can never run a command again (fenced, stopped, unsupervised after a helper
  restart) is refused as not reusable, so the daemon quarantines it. B5-R1: every ledger
  wait in the fence is bounded by the request's deadline and the pending flush is
  cancel-safe. B5-R2: exactly eight settled cleanup-worker rows are kept. New
  `scripts/firecracker-crash-matrix.py` and `scripts/firecracker-regressions.py` run the
  global-ledger crash matrix and section 10's attacks through real daemons and kilndctl.

- Phase 1b B6 milestone 1: the first whole Firecracker session through the public API.
  `FirecrackerRuntime` now follows Create to the helper's journaled READY and sends
  Validate, Exec, Remove and Gc by exact allocation token with the journaled boot and
  inner sandbox; a token's absence fence removes an admitted allocation first. kilnd
  gains `--backend firecracker`, accepted only with `--firecracker-test-deployment`
  naming `deploy/firecracker-test/deployment.json` at its exact non-production paths;
  the production helper still serves no profile. The privileged
  `b6_linux_root_a_whole_session_through_kilnd_and_kilndctl` runs the real daemon in its
  own enrolled unit and drives it with `kilndctl`.

- Phase 1b B5 break-it corrections (break-it review, November 3). The ledger compacts settled
  execution rows into one `exec_history` summary in the settling transaction, caps stop
  reasons and settled cleanup workers per allocation, and answers an oversized reply with
  `oversized` instead of exiting; Exec polls cancellation, the deadline and the session
  watch beside a bounded BUSY write, and any unanswered journal write retires the VM; a
  worker `Endpoint` write that fails after any byte poisons the connection, and S reports
  such a job as dispatch-uncertain; relay failures carry their reach and only local ones
  restore READY; one control operation per allocation (`control_busy`), late probe
  failures still retire; a Result for another inner sandbox, a wrong broker digest or
  missing kiln features retire the VM; capture facts are unknown without a Result and
  count delivered bytes when forwarding stops. The guest broker answers Probe idle only
  for a live persistent sandbox. Remove's ledger calls are bounded by its deadline.

- Phase 1b B5 milestone 2. New `kilnd-guest-broker` crate: the guest broker baked into
  kiln-guest (pinned there at kilnd `fb9034d`, broker `d4eb4cac`), started by `/init` as
  guest root and never restarted, listening on vsock 5252 for the host only, with one
  persistent kiln sandbox per VM driven through `kilnd-exec-core`. The protocol crate gains
  the `KID1` identity and `/init` bootstrap codec and `SharedBudget`, and folds in milestone
  1's break-it findings (poisoned readers and writers, linear duplicate-key checks). The
  helper's S forks a broker relay R (relay cgroup leaf and UID/GID, no capabilities), which
  parses every guest byte, read at most 4 MiB/s per connection, and a console drainer D
  (rate-metered, drains to EOF); READY is journaled only after a matching Hello and
  Initialize. New `validate` and `exec` Firecracker operations, `present_ready` Inspect and
  `ready` List: EXEC_INTENT is durable before any byte is sent, and any interruption after
  dispatch stops the VM. Ledger phases `ready`, `exec_intent` and `busy`, resource kinds
  `broker` and `exec` (schema 1 unchanged). Production Firecracker stays disabled.
- Phase 1b B5 milestone 1. kilnd's direct-kiln process, status, capture and validation code
  moved unchanged into the new `kilnd-exec-core` crate, which kilnd re-exports from the old
  paths (`scripts/b5-move-audit.py` proves the move token by token). New
  `kilnd-broker-protocol` crate: the strict `KGB1` broker protocol version 1 codec (36-byte
  header, sixteen kinds, per-direction sequences, strict JSON, field bounds, cumulative frame,
  wire and payload budgets charged before any payload byte, per-connection order and
  deadline-bounded stream I/O) with unit, property and stream-adversary tests. No broker,
  host module or image change yet; production Firecracker stays disabled.

- Phase 1b B4 recheck 5 corrections. The cgroup proof enumerates children from the retained
  descriptor (`getdents64` on a duplicate), and a proven unmount resolves its name from the
  held parent descriptor (a thread's own working directory), so a mount over the helper's
  `/proc/self/fd` can no longer hide a replacement or redirect an unmount. Process,
  boot-ID and mount-table reads go beneath a private, never-attached procfs instance. The
  API socket is identified by device, inode, birth time and file handle (inode generation)
  through its directory descriptor, so an inode-reused replacement is never unlinked. `LoopInfo64` is opaque and
  only a slot this process configured can have autoclear cleared; `process::run` starts
  only the verified kiln CLI with typed arguments. `clippy.toml` also disallows truncation,
  whole-file overwrite, `fallocate`, `prctl`, `ptrace` and `process_vm_*`; new CI tests
  reject unapproved build scripts, generated `include!`s and `/proc/` or `cgroup.` paths
  outside the approved modules.

- Phase 1b B4 recheck 4 corrections. `executable::publish_object` copies into an unnamed
  `O_TMPFILE` inode, checks it through its descriptor and links that descriptor, then
  re-reads the name; there is no temporary name to replace or unlink. The destructive-action
  gate is now semantic: `clippy.toml` disallows the raw signal, removal, rename, unmount,
  `ioctl`, `syscall` and subprocess functions (calls and function values alike), and only
  `proven.rs`, the new typed wrapper module `crate::sys` and six named subprocess and socket
  functions may allow them; a CI test rejects any other allow, lint-group silencer, foreign
  declaration or inline assembly. `cgroup.kill` is written only inside `proven.rs`, and the
  generic cgroup writer takes a `ControlFile` that cannot name it. CI runs clippy on 1.88
  and 1.99.

- Phase 1b B4 recheck 3 corrections. Every destructive helper action (signals,
  `cgroup.kill`, cgroup and directory `rmdir`, file `unlink`, `umount2`, `LOOP_CLR_FD`) now
  requires a proof type from the new `helper/firecracker/proven.rs` that the resource is a
  durable journaled generation from the current boot; a CI test fails on any such call
  elsewhere. Process identities and stop targets carry a validated boot ID (an older row
  without one is never signaled and stays charged), and an unreadable host boot ID is an
  error. `cgroup.kill` proves the whole `vm` subtree first, so a replaced child is Replaced
  with no signal. Intents are journaled before the cgroup tree, directories and files; the
  directories' generations right after `mkdir`; work files are created unlinked and linked
  only once journaled. An object present with no journaled generation is Unknown, never
  deleted by its name. Remove reloads the journal after its stop fence. New ledger resource
  kinds `intent`, `work_dir` and `jail_dir`; the ledger keeps schema 1.

- Phase 1b B4 recheck 2 corrections. A journaled loop slot rebound to another backing file
  is Unknown and charged, not NotOurs; NotOurs remains only for an intent-only slot. Cleanup's
  leftover check and the absence observation read each journaled slot by major and minor, and
  cleanup journals `loop_released` once a generation is gone so a later binding of the slot
  is not mistaken for a replacement. The cgroup identity records the boot ID and every node's
  inode; a tree recorded in another boot, or a replaced child, is refused. Work-directory
  files add their `statx` birth time, so a replacement reusing the inode number is refused;
  a filesystem without `STATX_BTIME` refuses the launch. The ledger keeps schema 1: a B4
  ledger must be provisioned again.
- Phase 1b B4 recheck corrections. Teardown identity now comes from kernel IDs never reused
  within a boot, journaled with the boot ID: the jail tmpfs's and every bind's
  `STATX_MNT_ID_UNIQUE` (Linux 6.8+, no fallback), taken from the detached mount descriptor
  and journaled before it is attached, and the loop attachment's `BLKGETDISKSEQ`. Cleanup
  requires the journaled ID at the path, or on the loop descriptor, immediately before each
  unmount or `LOOP_CLR_FD`; the old tuple, source and marker are secondary. An unjournaled
  bind is Unknown, never inferred from its name. Loops attach with autoclear until their
  generation is journaled. The tool build stages privately and gates on the published
  digests. The formatter's `retained_fd` evidence waits for exit status 0. UID 0 without
  `CAP_SETPCAP` no longer takes the `NoNewPrivs` fallback and exits 76.
- Phase 1b B4 break-it corrections. Cleanup acts only on exact journaled identity: each jail
  tmpfs gets an allocation-specific source and a root-only nonce marker, journaled before it
  is mounted, and is built detached and attached whole. Its binds are journaled, and every
  mount is re-verified just before its unmount. Loop detach requires the full recorded tuple,
  block size included, on the descriptor that issues `LOOP_CLR_FD`. Mismatches are refused
  and stay charged. Helper workers and kiln children verify the launch-capability drop in
  every set and exit on any failure. The tool build pins its sysroot debs
  (`deploy/firecracker/mkfs-sysroot.lock`), the patch and both output digests. The
  formatter's tuple is recorded as inferred from its retained descriptor
  (`observation = retained_fd`) after a confirmed exec, not as observed. The ledger keeps
  schema 1: a B4 ledger must be provisioned again.
- Phase 1b B4: real Firecracker host lifecycle in `kilnd-helper`, test-approved only. S
  creates the allocation's cgroup tree, a fully preallocated XFS work disk exposed through a
  fixed-size loop device with discard disabled, and a bounded private tmpfs jail with
  read-only artifact binds; it launches the patched jailer (`deploy/firecracker/`, built by
  `scripts/build-phase1b-tools.sh`) by retained descriptor through a bootstrap gate, verifies
  the jailer's and VMM's actual images and the VMM's zero capability masks, hardens the jail
  and journals BOOTING. New helper operations `stop`, `remove` and `gc`; Remove releases only
  through the ABSENT fence after the real absence observation. The helper unit gains
  `CAP_MKNOD`, `CAP_SYS_CHROOT` and `CAP_SETPCAP`, which only S and its jailer keep, and write
  access to loop devices' sysfs queue settings. The node ledger gains phases and an
  append-only `resource_events` table (schema still 1: a B3 ledger must be provisioned
  again). Production still serves no profile and nothing reports READY. New: root
  regressions in `scripts/b4-vm-tests.sh`.
- Phase 1b B3 deployment: interrupted maintenance is fenced across a reboot and retried after a
  failed restore. Each command now writes `/var/lib/kilnd-helper/maintenance.json`, fsynced,
  before anything changes, and removes it last. `kilnd-maintenance-guard.service` runs
  `upgrade.sh --recover --boot` before the helper socket and every kilnd unit, which `Requires=`
  it, so a node comes back whole or stays down, and `kilnd-maintenance-finish.service` finishes
  the starts. Any error restoring a unit keeps the record, and an upgrade's journal and stage, and
  exits 3 until `--recover` succeeds. New: `scripts/kilnd-maintenance-tests.py`, also in CI, and
  reboot and failed-restore regressions in `scripts/deployment-regressions.py`.
- Phase 1b B3 deployment: `kilnd init-state` creates an instance's private state as its own
  account and prints its durable ID, which `scripts/add-instance.sh <name>` and the default
  instance's install then enroll before the unit starts; add-instance no longer takes an ID.
  Enrollment runs with activation masked, so no connection can bring the helper back, and
  restores exactly what was running, on a signal too. `scripts/upgrade.sh`, which
  `scripts/install.sh` runs on a configured node, replaces the images, refreshes every
  enrollment in one ledger transaction and restarts what was running, or puts everything back.
  New: `kilnd check-attachment`, `kilnd-helper enrollments`, `refresh-enrollments` and
  `restore-enrollments`, and `scripts/deployment-regressions.py`.
- Phase 1b B3: each enrolled Firecracker instance runs under its own Unix account, recorded
  by `kilnd-helper enroll --user` and refused if shared, root, the helper's or in a VM
  identity range, with `deploy/kilnd@.service` and `scripts/add-instance.sh`. Attachment
  requires that account, so instance isolation no longer depends on Yama. Allocation identity
  and every ledger row a claim or fence writes are keyed by (instance, allocation ID), and
  attach queues by the peer's kernel-reported UID, so one instance can no longer pre-fence
  another's token or fill its attach queue. The helper socket's group is now `kilnd-helper`,
  and enrolled accounts get no kiln requests. Earlier B3 ledgers must be provisioned again.
- Phase 1b B3: add the typed Firecracker helper group (disabled by default), approved
  plan verification, the root node ledger with durable claims and permanent absence
  fences, protected retained-descriptor executable handling, and fixed L/P/S/M/K worker
  processes. Fake resources only, under test; no VM launch, no READY reply, and every
  profile refused by the production gate. Kiln wire bytes are unchanged, except that a
  peer vanishing before its credentials can be read no longer ends the helper's listener.
  The helper's connection budget splits: 128 framing slots, then 60 normal and 4 reserved
  recovery operation slots after classification, so silent clients cannot occupy dispatch.
- Close the B3 break-it findings. Root enrolls Firecracker instances with `kilnd-helper
  enroll`, and attachment proves the peer's UID, unit cgroup and kilnd image; the database
  UUID authenticates nothing. Enrollment is bounded by policy, with one attachment slot per
  instance. Token gates follow the durable lookup and are partitioned by instance. Workers
  are never published without their journal row. Attachment needs Linux 6.5 or later.
- Add a durable per-instance quota on fences for tokens the ledger never admitted, so an
  attested instance can't grow the root ledger with random IDs. At the quota the fence
  fails closed and the charge stays. Fences for admitted tokens are never refused by it.

- Close B2 recheck findings in schema 10: audit release receipts in trusted Rust
  reads, retain invalid releases as charged/quarantined, degrade Health and refuse
  admission. Detect missing reservation membership with an atomic SHA-256 marker.
  Verify private kilnd ownership/modes at install/startup; document that hostile
  connections (including disabled triggers/spoofed validators) have file authority
  and are outside SQL guards. The B3/B4 root node ledger is authoritative and never
  frees node resources without its own ABSENT receipt. Mark the SQL validator
  innocuous and set/verify trusted_schema=OFF on every Store connection.

- Harden B2 accounting in schema 9: reject conflicts on every unique key before
  SQLite can replace-delete charged rows or fences, even with defensive pragmas
  off. Validate canonical typed AbsentFenced bytes and their column bindings in
  an SQL trigger; refuse an upgrade containing malformed schema-8 evidence.

- Phase 1b B2: add runtime preflight, typed receipts, execution dispositions and
  schema 8's stored reservation vectors and immutable release evidence, enforced in
  SQL; quarantine a kiln sandbox whose cleanup cannot be confirmed. Additive
  `kilnd.v1` fields. The fake models the absence-fenced backend; none is selectable.
- Serialize descriptor creation with fork on non-Linux hosts, where close-on-exec
  isn't atomic and a sibling child could hold a capture pipe past the drain grace.

- Fix B1's Python/Rust JSON mismatch with a production strict parser, ASCII
  canonicalizer and shared mutation/Unicode corpus; bind complete host specs
  including labels separately from guest execution specs, and isolate fixtures
  in test-only schemas/types with no production override.

- Freeze the Phase 1b `offline-768-v1` guest and launch contract (schema 2) as golden
  fixtures shared with kiln-guest, with an independent Rust check of its plan, digests
  and identity block. Fixtures only: production stays disabled without the broker.

- Bind the Phase 1b design's complete helper executable chain to verified inodes,
  add replacement-race gates, and record Stephen's October 31 design decisions.

- Specify the Phase 1b Firecracker runtime and guest broker design, including
  approved launch contracts, durable recovery, resource reservations and build gates.
- Address the Phase 1b design review with mandatory absence fences, node-global
  admission, live supervisor monitoring, bounded jail/I/O/workers and stronger gates.

- Isolate the lock CLOEXEC regression in a dedicated child so unrelated parallel
  forks cannot transiently retain its lock and cause a false inheritance failure.

- Remove unneeded AF_INET6 from the helper's supported IPv4-resolver deployment;
  retain AF_INET for hostname allowlists and AF_NETLINK for networking/nft, and
  assert the exact installed address-family set in the lifecycle regression.

- Honor non-Exec helper wire deadlines and cancellation through create, remove,
  list and scoped GC, capped by their internal limits; share the remaining
  removal budget with absence probes and preserve ambiguous create evidence.
  Wire-level regressions cover timeout without client cancellation and child reaping.

- Fix the helper stdio handoff ordering race on macOS: private protocol v3
  retains sent endpoints until recvmsg receipt, preventing premature output EOF
  and helper EPIPE. A deterministic regression forces send-before-receive;
  daemon and helper must be upgraded together.

- Fix PH0-1 root-helper availability: private protocol v2 creates stdio pairs in
  the helper and passes only peer endpoints to kilnd, rejecting all inbound
  descriptors. Per-syscall nonblocking socket I/O protects deadlines and the
  listener against mutable flags and backpressure; Linux regressions exercise
  flag mutation, stalled stdin and cancellation. Upgrade daemon/helper together.
- Preserve IPv4 host DNS resolution for hostname allowlists under the
  restored address-family filter; exercise full-network and hostname Create/Exec.
- Restore PH0-2 helper systemd address-family, personality, realtime and
  kernel-log filters with ambient CAP_SETUID for UID-map setup. Installed
  regressions require Seccomp 2 and exact effective/bounding capability masks.
- Clarify PH0-3: API page tokens are bounded plaintext cursors whose global
  sequence gaps can reveal cross-caller insertion counts; they are not opaque.

- Add startup/periodic age and count retention with reservation protection and full/metadata/none output storage.

- Run kilnd as its unprivileged system account with no capabilities; isolate
  validated kiln operations in a root socket-activated helper. Pass Exec stdio
  as descriptors, authenticate both peers, preserve cleanup evidence, and
  harden both systemd services. See docs/helper-protocol.md.

- Add durable per-caller ownership. Create records the connection's
  kernel-reported uid as an immutable `Sandbox.owner_uid` (field 10). Get, Exec,
  Delete, GetExecution and List are limited to the owner and root; a foreign
  sandbox or execution returns `NOT_FOUND` exactly like a missing one, and a
  connection without credentials gets `UNAUTHENTICATED`. Schema 7 assigns every
  existing row to root, so group members lose access to sandboxes created before
  the upgrade. List filtering happens in SQLite before limits, watermark and
  continuation. Page tokens are now `v2` and bound to the caller's uid, so
  `v1` tokens held across the upgrade fail with `INVALID_ARGUMENT`; restart the
  listing. Older binaries refuse schema 7. Node budgets stay shared: there are
  no per-user quotas yet.

- Stop definite pre-allocation create failures from permanently consuming node
  budgets. `Runtime::create` now returns a typed `CreateFailure`; ordinary errors
  convert to `AllocationAmbiguous` and only an explicit constructor claims
  `DefinitelyNotCreated`. The kiln adapter claims it only when its pre-create
  capability gate fails, or for direct-child exit status 124 with empty stdout
  and complete output EOF. Schema 5 adds a durable `create_certainty` written
  atomically with `FAILED`; every historical row stays ambiguous. Definite rows
  are uncharged and Delete retires them with no backend call; a failed durable
  update, panic, crash or other error stays charged across restart. The installed
  CLI must now advertise capability feature `0x10` (kiln `e48f0e785ad484d0b2947897f6d48d0756059d7e`);
  live PID 1 instances need only the execution bits. Privileged suites cover
  real missing-image and private-allowlist preflight failures and a real
  post-allocation failure.

- Collapse nested runtime conditionals using let chains supported by Rust 1.88,
  keeping strict Clippy clean on both MSRV 1.88 and Rust 1.99.

- Preserve containment regression coverage from `review/exec-tree-containment`:
  timeout readiness, normal leader exit with nohup/setsid descendants, raw CLI
  stdout/stderr EOF, private output EOF, graceful shutdown and abrupt daemon
  death. The smoke uses the current API for durable outcome checks.

- Make detached-child cancellation coverage wait for a marker written after
  successful setsid and live child creation. Verify both workload streams
  reach EOF, descendants disappear, and the sandbox remains reusable.

- Reject exec-capable CLIs lacking scoped `gc ID...` before reconciliation and
  workload launch, including on an empty database. A complete, bounded
  `gc --help` usage check supplements v1 capability frames without global GC.
  Minimum companion kiln is `40d9aa5003205d4c171e1b3eca61e9868064e98b`;
  the previously advertised `711440db3167` is insufficient. Privileged suites
  pass with tested kiln `46d84bdfe13e331f047e70e38848f7d74bcd2872`
  (`review/breakit-fixes`), now pinned in setup and the quick start.

- Recheck compensated history on every Delete state reload, including after
  waiting for create compensation. Queued deletion cannot remove a replacement
  using the old backend ID or temporarily reserve compensated history again.

- Require exact-backend absence evidence after both successful and failed
  removal, including failed-publication compensation. A live direct probe or
  surviving cgroup keeps the row and its reservation retryable. Ambiguous
  no-ID creates remain charged even with an empty listing; clearing them needs
  authoritative resource reconciliation, which is not currently supported.
  Store comments and operator guidance describe that retained-capacity limit.

- Add atomic, durable node-wide sandbox budgets for retained count, requested
  memory, PIDs and disk. Create now checks all four sums and inserts
  `CREATING` in one SQLite transaction; reservations survive cancellation,
  panic, reconciliation and restart, and release only after proven backend
  absence plus a durable terminal transition. LOST and ambiguous failed
  creates remain charged, compensated creates recover capacity, and lowered
  limits degrade Health while preserving Get/List/Delete for cleanup. Health,
  kilndctl, CLI defaults, operator guidance and bounded real-runtime stress now
  expose and verify the reservation contract.

- Close backend subprocess inheritance gaps: every launcher now captures the
  parent PID before spawn, arms `PR_SET_PDEATHSIG`, and rechecks the parent
  before exec so death during the post-fork window cannot release an
  unsupervised client. Backend children also restore default HUP, INT, QUIT,
  TERM and PIPE dispositions instead of preserving an ignored signal across
  exec.

- Harden persistent state setup: validate trusted path ancestors, require an
  exact private state directory, resolve and validate every nested symlink hop
  descriptor-relatively, acquire its lock relative to the pinned directory,
  open SQLite with no-follow semantics, reject foreign-owned, permissive,
  symlinked, non-regular or hard-linked database and sidecar entries, and
  reject socket-parent aliases of state before permission changes or
  reconciliation.

- Define and enforce one API/backend validation contract for IDs, image and
  path fields, allowlists, labels and literal argv. Root writable/allowlist
  entries, malformed path components, empty `argv[0]`, NUL and excessive
  count/byte sizes now fail as client errors before persistence or backend
  work; Unicode/newline and flag-like argv remain literal. kilnd also proves
  accepted argv fits kiln's 1 MiB encoded transport frame.

- Scope startup garbage collection to stale backend IDs recorded by kilnd,
  preserving unmanaged live and stale sandboxes across reconciliation and
  shutdown. Restart interruption now updates only executions joined to the
  active backend's sandboxes.

- Concurrent `DeleteSandbox` calls now share one serialized backend removal.
  Delete reloads durable state after acquiring the sandbox lock, treats an
  existing `DELETED` row as immutable success, and uses conditional state
  transitions so stale results cannot rewrite deletion timestamps or move a
  terminal row back to `DELETING`. Interrupted removals remain retryable on
  either side of the backend side effect.

- Output accounting now distinguishes an exact EOF-proven byte total from an
  observed lower bound when capture settlement stops early. Truncation records
  only bytes actually discarded by the retention bound and remains stable in
  metadata-only reads. The additive v1 API exposes total certainty, schema 4
  preserves it, and v1/v2/v3 rows migrate as unknown rather than inheriting an
  unsupported exactness claim. GetSandbox projects persisted output metadata
  without fetching BLOBs; an isolated Linux regression measures the advertised
  100 executions with two 1 MiB streams each.

- Startup reconciliation now fails closed on truncated, partial, duplicate or
  contradictory backend listings. Omitted managed sandboxes require a direct
  negative probe and absent cgroup before becoming `LOST`; exact backends that
  provably reappear recover to `READY`. Reconciliation validates all evidence
  before changing durable state and remains idempotent across restarts.

- Adds backend-neutral typed command termination and runtime diagnostics to
  executions, the additive v1 API, schema 3, and kilndctl. Private machine
  stdio/status sockets preserve binary evidence through failures, cleanup,
  cancellation and reader panics; real exits 125/126/127 remain command results.
  Strict capability validation gates startup, live sandboxes, Health and Exec;
  create requires protocol 1. Requires persistent-exec v1 first supplied by kiln
  `f3da4b5319566de4912ed617caf81d4eb8e50b6f`, with follow-up
  `711440db3167cdf3a90d3aad44623ce56c2d01b1`, based on `3b42552`.
  v1/v2 stores migrate through v3 with unknown historical typed values before
  output accounting advances them to v4; older binaries refuse the current
  schema. Migration can precede startup capability failure.
  Late status settlement preserves runtime failure/cleanup precedence over
  cancellation, sandbox absence requires a bounded successful list observation,
  signal numbers use uint32 on the API, and persisted native codes are bounded.
  Presence observations require verified EOF on both CLI streams; bounded
  control-command drainage retains completion/error evidence and the original
  cancellation/deadline budget, preventing late inherited writers from implying absence.

- Adds finite connection/stream/message and RPC admission bounds, global and
  per-sandbox Exec capacity with aggregate stdin permits, and queue-inclusive
  absolute deadlines while preserving daemon-owned cleanup and publication.
  Health exposes admission use/rejections and coalesces cached backend probes
  with timeout and panic recovery. List gains bounded stable pagination with
  opaque tokens, explicit legacy overflow errors and incremental CLI output;
  SQLite schema v2 preserves legacy list order on migration. GetSandbox reads
  execution metadata without fetching output BLOBs. New startup flags validate
  capacity relationships before state or socket side effects. Health probe
  timeout ownership now lasts through child reaping, idle sandbox admission
  slots are reclaimed, and a dedicated Linux child harness measures FD/RSS
  recovery under slow connections, queued stdin and concurrent Health.

- `CreateSandbox` work is daemon-owned after acceptance: client cancellation
  no longer strands `CREATING` rows or live unrecorded backends, failed state
  publication is compensated and retryable, and shutdown drains accepted
  creates before exit.
- Recorded executions are daemon-owned: disconnecting an `Exec` caller
  requests cancellation without dropping cleanup or finalization, queued
  disconnected calls are discarded, terminal writes retry while retaining
  ownership, and shutdown drains execution supervisors even after the
  transport reply deadline.
- Requires kiln at or after `3b42552` for per-execution cgroup teardown and
  cumulative runtime hardening.
- Startup now locks both the state and socket directories before
  reconciliation, refuses live socket owners, replaces only positively stale
  sockets on Linux, and conditionally removes only the socket inode this
  instance bound. Ambiguous platforms fail closed. Duplicate starts cannot
  interrupt active daemon-owned work.

- Prepare the repository for public visibility (documentation only): add
  `SECURITY.md` with private vulnerability reporting, scope and the statement
  that the Firecracker backend is disabled for production; open the README
  with status, the four Lambda IX repositories and a quickstart; clone over
  HTTPS in `docs/setup.md`; drop a host name and a local account name from
  the setup guide and design document.

## 0.1.0 - 2026-10-13

First vertical slice.

- `kilnd`: gRPC `kilnd.v1` (Health, CreateSandbox, GetSandbox, ListSandboxes,
  DeleteSandbox, Exec, GetExecution) on a root:kilnd Unix socket.
- Runtime adapter trait with a kiln CLI backend (argv only, cleared
  environment) and an in-memory fake for tests.
- SQLite state for sandboxes and executions, with bounded output.
- Startup reconciliation with `kiln gc` and `kiln ls`.
- Exec timeouts that stop the command inside the sandbox, per-sandbox exec
  ordering, graceful shutdown, structured text or JSON logs.
- `kilndctl` client, systemd unit, install, integration and smoke scripts.
- Requires kiln at or after `3736329`.
