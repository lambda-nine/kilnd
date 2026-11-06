# Roadmap

This milestone is the runtime control plane. Each step below builds on the
one before and keeps the rule that the harness talks to sandboxes only
through the kilnd API. Product-specific code stays
in the products that consume the harness.

## Phase 0: control-plane privilege gate (done)

- [x] **(a) Retention:** startup/periodic age and count limits for terminal
  executions and deleted/uncharged failed sandbox history; full/metadata/none
  output storage. Charged and unfinished rows are protected.
- [x] **(b) Per-caller ownership:** durable kernel peer UID, additive
  `Sandbox.owner_uid`, owner/root authorization and filtered pagination.
- [x] **(c) Privilege split:** unprivileged kilnd with no capabilities, behind
  the typed root helper, descriptor stdio and hardened systemd services.

The root surface and remaining trusted code are described in the
[helper protocol](helper-protocol.md) and [threat model](threat-model.md).

## 1. Control-plane features (next)

- **Streaming exec:** a server-streaming `ExecStream` for long commands and
  live output, alongside the bounded unary `Exec`.
- **Idempotent create:** a client request ID so a retried `CreateSandbox`
  doesn't make a second sandbox.
- **Exec options:** working directory and environment. These need kiln
  support first.
- **Sandbox TTLs:** delete idle sandboxes after a limit, so a crashed client
  can't hold capacity forever.
- **Metrics:** request and execution counters and latencies next to kiln's
  `/metrics`.

## 2. Sandbox pool

Both kiln papers name a pool of pre-created sandboxes as the next startup
win. kilnd keeps N ready sandboxes per spec, and `CreateSandbox` hands one
out when the spec matches, then refills in the background. It needs a
`pooled` state, reconciliation for pooled sandboxes, and measurements taken
the way kiln's benchmarks are (every claim names its condition).

## 3. Harness: tool registry

A separate crate or service that talks to kilnd over `kilnd.v1`:

- tools as typed schemas: `exec`, `read_file`, `write_file`, `list_dir`,
  `diff` (from the overlay upper layer), each mapped to one or more kilnd
  calls;
- per-tool limits (timeout, output size, network policy);
- an audit log that links each tool call to its kilnd execution ID.

## 4. Harness: Anthropic provider and agent loop

- An Anthropic Messages API client with tool use: model choice, token
  budgets, prompt caching and retries with backoff.
- The loop: model → tool calls → kilnd → results → model, with step and
  cost limits, cancellation, and one sandbox per session (delete on exit).
- API keys from the vault or environment, never from sandbox output.
- A credential broker outside tool sandboxes, so tools can make authorized
  requests without seeing provider credentials. No regex output redaction.

## 5. Harness: memory

- Session transcripts and tool results stored next to kilnd's run records.
- Long-term memory: summaries and retrieved notes per user or project, with
  explicit write and forget operations.
- First consumer: a downstream product, through the harness API, not through code
  in this repository.

## 6. Beyond one node

- A Firecracker backend behind the same `Runtime` trait, for workloads that
  need a VM boundary.
- kilnd as a DaemonSet with a Go operator and Sandbox CRD on k3s, as in kiln's
  ARCHITECTURE.md.
- An authenticated remote API (mTLS or a token-checking proxy). The local
  socket stays.
