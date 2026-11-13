# Changelog

Notable changes to kilnd. Versions follow [Semantic Versioning](https://semver.org/);
before 1.0, any minor release may change the CLI or on-disk layout. The
`kilnd.v1` API only gains fields and RPCs.

## Unreleased

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
