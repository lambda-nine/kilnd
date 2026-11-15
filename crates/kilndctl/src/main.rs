//! kilndctl: a small command-line client for the kilnd v1 API.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use kilnd_api::v1 as pb;
use pb::kilnd_service_client::KilndServiceClient;
use tokio::net::UnixStream;
use tonic::codegen::http;
use tonic::transport::Uri;

/// Exit code when kilnd or the sandbox couldn't run the command, as with
/// `kiln exec` and `docker exec`.
const EXIT_FAILED: u8 = 125;
/// Exit code when the command timed out, as with coreutils `timeout`.
const EXIT_TIMED_OUT: u8 = 124;
const MAX_STDIN: u64 = 1 << 20;

#[derive(Parser)]
#[command(version, about = "Talk to kilnd over its Unix socket")]
struct Cli {
    /// kilnd's API socket.
    #[arg(
        long,
        env = "KILND_SOCKET",
        default_value = "/run/kilnd/kilnd.sock",
        global = true
    )]
    socket: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show whether kilnd and its backend are serving.
    Health,
    /// Create a sandbox and print its ID.
    Create(CreateArgs),
    /// Show a sandbox and its recent executions.
    Get {
        id: String,
        /// How many recent executions to show.
        #[arg(long, default_value_t = 10)]
        executions: u32,
    },
    /// List sandboxes.
    Ls {
        /// Include deleted sandboxes.
        #[arg(long)]
        all: bool,
    },
    /// Run a command in a sandbox. Its output goes to stdout and stderr and
    /// kilndctl exits with its code (124 on timeout, 125 if it couldn't run).
    Exec {
        #[command(flatten)]
        opts: ExecOpts,
        id: String,
        /// Program and arguments, after `--`.
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        argv: Vec<String>,
    },
    /// Show one execution, with its output.
    Execution { id: String },
    /// Delete a sandbox.
    Rm {
        id: String,
        /// If the sandbox ends DELETED, also give up its create request ID, so a later
        /// create with that ID makes a new sandbox. Irreversible; use it only when no
        /// retry of that create is pending. Needs a kilnd that lists request_id_release.
        #[arg(long)]
        release_request_id: bool,
    },
    /// Record activity on a ready sandbox, restarting its idle timeout.
    Renew { id: String },
    /// Workspace checkpoints: capture a sandbox's files, show, list and delete them.
    /// Needs a kilnd started with --enable-workspace-checkpoints (testing only for now).
    #[command(subcommand)]
    Checkpoint(CheckpointCommand),
    /// Create a sandbox, run one command in it, and delete it.
    Run {
        #[command(flatten)]
        create: CreateArgs,
        #[command(flatten)]
        opts: ExecOpts,
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        argv: Vec<String>,
    },
}

#[derive(Subcommand)]
enum CheckpointCommand {
    /// Capture a ready sandbox's workspace (its writes over the image) and print the
    /// checkpoint's ID. Fails at once if a command is running or waiting in it.
    Create {
        sandbox: String,
        /// Delete the checkpoint this long after it became ready, like 2h or 7d (10s to
        /// 7d). kilnd's default (24h) if omitted; a checkpoint always expires.
        #[arg(long, value_name = "DURATION")]
        max_lifetime: Option<String>,
        /// Delete it after this long without a get or a create from it, like 30m (10s to
        /// 24h). kilnd's default (1h) if omitted.
        #[arg(long, value_name = "DURATION")]
        idle_timeout: Option<String>,
        /// The most it may hold, like 512M; the sandbox's disk limit or kilnd's
        /// per-checkpoint limit, whichever is less, if omitted.
        #[arg(long, value_name = "SIZE")]
        max_size: Option<String>,
        /// Make the capture idempotent: retrying with the same ID and options returns the
        /// same checkpoint, in whatever state it settled. 1-64 printable ASCII characters
        /// without spaces, private to your uid and separate from create request IDs.
        #[arg(long, value_name = "ID")]
        request_id: Option<String>,
    },
    /// Show a checkpoint. Showing a ready checkpoint restarts its idle timeout.
    Get { id: String },
    /// List checkpoints, newest first.
    Ls {
        /// Only checkpoints captured from this sandbox.
        #[arg(long, value_name = "SANDBOX")]
        sandbox: Option<String>,
        /// Checkpoints per request, 1 to 1000. Without it kilndctl asks for 100 and
        /// halves that while kilnd's own --max-list-page-size is lower.
        #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..=1000))]
        page_size: Option<u32>,
    },
    /// Delete a checkpoint. Sandboxes created from it are not affected.
    Rm {
        id: String,
        /// If the checkpoint ends DELETED, also give up its capture request ID, so a later
        /// capture with that ID makes a new checkpoint. Irreversible.
        #[arg(long)]
        release_request_id: bool,
    },
}

#[derive(Args)]
struct CreateArgs {
    /// Image name; kilnd's default if omitted.
    #[arg(long)]
    image: Option<String>,
    /// Memory limit, like 256M or 2G.
    #[arg(long)]
    memory: Option<String>,
    /// CPU limit in cores, like 0.5 or 2.
    #[arg(long)]
    cpus: Option<String>,
    /// Maximum processes and threads.
    #[arg(long)]
    pids: Option<u32>,
    /// Disk limit, like 1G.
    #[arg(long)]
    disk: Option<String>,
    /// Network: none or full. --allow selects an allowlist instead.
    #[arg(long, value_enum)]
    net: Option<Net>,
    /// Allowed destination HOST[:PORT] or IP[/PREFIX][:PORT] (repeatable).
    #[arg(long, value_name = "DEST")]
    allow: Vec<String>,
    /// Deny writes outside scratch paths and --writable paths.
    #[arg(long)]
    read_only: bool,
    /// Extra writable absolute path with --read-only (repeatable).
    #[arg(long, value_name = "PATH", requires = "read_only")]
    writable: Vec<String>,
    /// Label KEY=VALUE (repeatable).
    #[arg(long, value_name = "KEY=VALUE")]
    label: Vec<String>,
    /// Delete the sandbox this long after it became ready, like 30m or 2h (at least
    /// 10s). Needs a kilnd that lists sandbox_expiry.
    #[arg(long, value_name = "DURATION")]
    max_lifetime: Option<String>,
    /// Delete the sandbox after this long without activity (an execution starting or
    /// finishing, or `kilndctl renew`), like 10m (at least 10s).
    #[arg(long, value_name = "DURATION")]
    idle_timeout: Option<String>,
    /// Send an expiry policy, using kilnd's defaults for any of --max-lifetime and
    /// --idle-timeout not given. Without these flags the sandbox never expires.
    #[arg(long)]
    expiry_defaults: bool,
    /// Make the create idempotent: retrying with the same ID and options returns the
    /// same sandbox, in whatever state it settled. 1-64 printable ASCII characters
    /// without spaces, private to your uid. Needs a kilnd that lists idempotent_create.
    #[arg(long, value_name = "ID")]
    request_id: Option<String>,
    /// Default environment variable for every command in the sandbox, NAME=VALUE, or
    /// NAME to pass kilndctl's own value without putting it on a command line
    /// (repeatable). kilnd keeps the values while the sandbox lives and never shows
    /// them. Needs a kilnd that lists sandbox_default_env.
    #[arg(long, value_name = "NAME[=VALUE]")]
    default_env: Vec<String>,
    /// Start from a checkpoint's workspace (see `kilndctl checkpoint`). The image,
    /// --read-only and --writable must match the checkpoint's, and --disk must hold it.
    /// Needs a kilnd that lists workspace_checkpoint.
    #[arg(long, value_name = "CHECKPOINT")]
    from_checkpoint: Option<String>,
}

#[derive(Args)]
struct ExecOpts {
    /// Timeout like 30s, 500ms or 2m; kilnd's default if omitted.
    #[arg(long)]
    timeout: Option<String>,
    /// Send kilndctl's standard input to the command (at most 1 MiB).
    #[arg(long)]
    stdin: bool,
    /// Print the execution's ID and state to stderr.
    #[arg(long, short)]
    verbose: bool,
    /// The command's working directory inside the sandbox, an absolute path. Needs a
    /// kilnd that lists exec_cwd.
    #[arg(long, value_name = "DIR")]
    cwd: Option<String>,
    /// Environment variable for the command, NAME=VALUE, or NAME to pass kilndctl's own
    /// value without putting it on a command line (repeatable). Needs a kilnd that
    /// lists exec_env.
    #[arg(long = "env", value_name = "NAME[=VALUE]")]
    env: Vec<String>,
    /// Stream the command's output as it runs (ExecStream). Live output is lossy: bytes
    /// a slow terminal could not take are reported on stderr as gaps, and the command
    /// is never slowed. The timeout uses kilnd's stream limits. Needs a kilnd that
    /// lists exec_stream.
    #[arg(long)]
    stream: bool,
}

/// `--env NAME=VALUE`, or `NAME` for this process's own value of NAME.
fn parse_env(entries: &[String]) -> Result<Vec<pb::EnvVar>> {
    entries
        .iter()
        .map(|entry| match entry.split_once('=') {
            Some((name, value)) => Ok(pb::EnvVar {
                name: name.into(),
                value: value.into(),
            }),
            None => {
                let value = std::env::var(entry)
                    .with_context(|| format!("--env {entry}: kilndctl's environment has no such UTF-8 variable"))?;
                Ok(pb::EnvVar {
                    name: entry.clone(),
                    value,
                })
            }
        })
        .collect()
}

#[derive(Clone, Copy, ValueEnum)]
enum Net {
    None,
    Full,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    match runtime.block_on(run(cli)) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("kilndctl: {e:#}");
            ExitCode::from(1)
        }
    }
}

async fn run(cli: Cli) -> Result<u8> {
    let mut client = connect(cli.socket.clone()).await?;
    match cli.command {
        Command::Health => {
            let h = client
                .health(pb::HealthRequest {})
                .await
                .map_err(rpc)?
                .into_inner();
            let status = pb::health_response::Status::try_from(h.status)
                .map(|s| s.as_str_name())
                .unwrap_or("UNKNOWN");
            println!(
                "status:             {}",
                status.trim_start_matches("STATUS_").to_lowercase()
            );
            println!("version:            {}", h.version);
            println!("backend:            {} {}", h.backend, h.backend_version);
            println!("started:            {}", time(h.started_at_unix_ms));
            println!("active sandboxes:   {}", h.active_sandboxes);
            println!("running executions: {}", h.running_executions);
            if let Some(resources) = h.node_resources {
                println!(
                    "node reservations:   sandboxes {}/{}, memory {}/{} bytes, pids {}/{}, disk {}/{} bytes",
                    resources.reserved_sandboxes,
                    resources.max_sandboxes,
                    resources.reserved_memory_bytes,
                    resources.max_memory_bytes,
                    resources.reserved_pids,
                    resources.max_pids,
                    resources.reserved_disk_bytes,
                    resources.max_disk_bytes
                );
                println!(
                    "host reservations:   cpu {}/{} millis, vcpus {}/{}, host pids {}/{}",
                    resources.reserved_host_cpu_millis,
                    resources.max_host_cpu_millis,
                    resources.reserved_virtual_cpu_slots,
                    resources.max_virtual_cpu_slots,
                    resources.reserved_host_pids,
                    resources.max_host_pids
                );
                println!(
                    "accounting:          {}{}",
                    accounting_status(resources.accounting_status),
                    if resources.accounting_generation == 0 {
                        String::new()
                    } else {
                        format!(" (generation {})", resources.accounting_generation)
                    }
                );
                println!("rejected creates:   {}", resources.rejected_creates);
            }
            if let Some(capabilities) = &h.runtime_capabilities {
                let features: Vec<String> = capabilities
                    .features
                    .iter()
                    .map(|&f| feature_name(f))
                    .collect();
                println!(
                    "features:           {}",
                    if features.is_empty() {
                        "-".to_string()
                    } else {
                        features.join(" ")
                    }
                );
            }
            if let Some(l) = &h.lifecycle {
                println!(
                    "expiry:             {} idle, {} lifetime, {} pending deletes, {} failed attempts",
                    l.expired_idle,
                    l.expired_lifetime,
                    l.pending_expiry_deletes,
                    l.failed_expiry_deletes
                );
            }
            let keyed = h.runtime_capabilities.as_ref().is_some_and(|c| {
                c.features
                    .contains(&(pb::Feature::IdempotentCreate as i32))
            });
            if let (true, Some(a)) = (keyed, &h.admission) {
                println!(
                    "create requests:    node {}/{}, yours {}/{}, {} refused at a cap",
                    a.current_create_requests,
                    a.max_create_requests,
                    a.caller_create_requests,
                    a.max_create_requests_per_uid,
                    a.rejected_create_requests
                );
                if let Some(l) = &h.lifecycle {
                    println!(
                        "                    {} retries answered, {} IDs released",
                        l.create_retries_answered, l.request_ids_released
                    );
                }
            }
            print_checkpoint_health(&h);
            let streams = h
                .runtime_capabilities
                .as_ref()
                .is_some_and(|c| c.features.contains(&(pb::Feature::ExecStream as i32)));
            if let (true, Some(a)) = (streams, &h.admission) {
                println!(
                    "exec streams:       {}/{}, {} refused at a cap",
                    a.current_exec_streams, a.max_exec_streams, a.rejected_exec_streams
                );
            }
            if let Some(capabilities) = h.runtime_capabilities {
                println!(
                    "interruption:        {}",
                    if capabilities.interruption_preserves_session {
                        "preserves the sandbox"
                    } else {
                        "retires the sandbox"
                    }
                );
            }
            if !h.detail.is_empty() {
                println!("detail:             {}", h.detail);
            }
            Ok(if h.status == pb::health_response::Status::Serving as i32 {
                0
            } else {
                1
            })
        }
        Command::Create(args) => {
            let sandbox = create(&mut client, args).await?;
            println!("{}", sandbox.id);
            Ok(0)
        }
        Command::Get { id, executions } => {
            let r = client
                .get_sandbox(pb::GetSandboxRequest {
                    id,
                    execution_limit: executions,
                })
                .await
                .map_err(rpc)?
                .into_inner();
            print_sandbox(&r.sandbox.context("response has no sandbox")?);
            if !r.recent_executions.is_empty() {
                println!("executions:");
                println!(
                    "  {:<19}  {:<11}  {:>4}  {:>8}  {:<20}  ARGV",
                    "ID", "STATE", "EXIT", "STDOUT", "STARTED"
                );
                for e in &r.recent_executions {
                    println!(
                        "  {:<19}  {:<11}  {:>4}  {:>8}  {:<20}  {}",
                        e.id,
                        execution_state(e.state),
                        e.exit_code
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "-".into()),
                        output_total(e.stdout.as_ref()),
                        time(e.started_at_unix_ms),
                        shell_words(&e.argv)
                    );
                }
            }
            Ok(0)
        }
        Command::Ls { all } => {
            println!(
                "{:<19}  {:<8}  {:<7}  {:<22}  {:<20}  IMAGE",
                "ID", "STATE", "BACKEND", "BACKEND ID", "CREATED"
            );
            let mut page_token = String::new();
            loop {
                let r = client
                    .list_sandboxes(list_request(all, page_token))
                    .await
                    .map_err(rpc)?
                    .into_inner();
                for s in &r.sandboxes {
                    println!(
                        "{:<19}  {:<8}  {:<7}  {:<22}  {:<20}  {}",
                        s.id,
                        sandbox_state(s.state),
                        s.backend,
                        if s.backend_id.is_empty() {
                            "-"
                        } else {
                            &s.backend_id
                        },
                        time(s.created_at_unix_ms),
                        s.spec.as_ref().map(|s| s.image.as_str()).unwrap_or("")
                    );
                }
                page_token = r.next_page_token;
                if page_token.is_empty() {
                    break;
                }
            }
            Ok(0)
        }
        Command::Exec { opts, id, argv } => exec(&mut client, id, argv, &opts).await,
        Command::Execution { id } => {
            let e = client
                .get_execution(pb::GetExecutionRequest { id })
                .await
                .map_err(rpc)?
                .into_inner()
                .execution
                .context("response has no execution")?;
            write_execution_streams(
                &e,
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            )?;
            eprintln!("id:       {}", e.id);
            eprintln!("sandbox:  {}", e.sandbox_id);
            eprintln!("argv:     {}", shell_words(&e.argv));
            if !e.cwd.is_empty() {
                eprintln!("cwd:      {}", e.cwd);
            }
            if !e.env_names.is_empty() {
                eprintln!("env:      {} (sha256 {})", e.env_names.join(" "), e.env_sha256);
            }
            eprintln!("state:    {}", execution_state(e.state));
            if let Some(code) = e.exit_code {
                eprintln!("exit:     {code}");
            }
            if !e.failure_reason.is_empty() {
                eprintln!("reason:   {}", e.failure_reason);
            }
            if e.cancel_reason != pb::CancelReason::Unspecified as i32 {
                eprintln!("canceled: {}", cancel_reason(e.cancel_reason));
            }
            if e.mode != pb::ExecutionMode::Unspecified as i32 {
                eprintln!("mode:     {}", execution_mode(e.mode));
            }
            eprintln!("reusable: {}", sandbox_reusable(e.sandbox_reusable));
            eprintln!("cleanup:  {}", cleanup_evidence(e.cleanup_evidence));
            eprintln!("started:  {}", time(e.started_at_unix_ms));
            eprintln!("finished: {}", time(e.finished_at_unix_ms));
            eprintln!("timeout:  {} ms", e.timeout_ms);
            for (name, out) in [("stdout", &e.stdout), ("stderr", &e.stderr)] {
                let out = out.clone().unwrap_or_default();
                let retained = if out.truncated {
                    format!(", first {} kept", out.data.len())
                } else {
                    String::new()
                };
                let total = if out.total_bytes_known {
                    format!("{} bytes", out.total_bytes)
                } else {
                    format!("at least {} bytes; exact total unknown", out.total_bytes)
                };
                eprintln!("{name}:   {total}{retained}");
            }
            Ok(0)
        }
        Command::Renew { id } => {
            require_feature(&mut client, pb::Feature::SandboxExpiry, "renew").await?;
            let s = client
                .renew_sandbox(pb::RenewSandboxRequest { id })
                .await
                .map_err(rpc)?
                .into_inner()
                .sandbox
                .context("response has no sandbox")?;
            println!("{} {}", s.id, sandbox_state(s.state));
            Ok(0)
        }
        Command::Rm {
            id,
            release_request_id,
        } => {
            if release_request_id {
                // An older daemon would ignore the flag and keep the record.
                require_feature(
                    &mut client,
                    pb::Feature::RequestIdRelease,
                    "--release-request-id",
                )
                .await?;
            }
            let s = client
                .delete_sandbox(pb::DeleteSandboxRequest {
                    id,
                    release_request_id,
                })
                .await
                .map_err(rpc)?
                .into_inner()
                .sandbox
                .context("response has no sandbox")?;
            println!("{} {}", s.id, sandbox_state(s.state));
            Ok(0)
        }
        Command::Checkpoint(command) => checkpoint(&mut client, command).await,
        Command::Run {
            create: args,
            opts,
            argv,
        } => {
            let sandbox = create(&mut client, args).await?;
            if opts.verbose {
                eprintln!(
                    "kilndctl: sandbox {} ({} {})",
                    sandbox.id, sandbox.backend, sandbox.backend_id
                );
            }
            let result = exec(&mut client, sandbox.id.clone(), argv, &opts).await;
            client
                .delete_sandbox(pb::DeleteSandboxRequest {
                    id: sandbox.id,
                    release_request_id: false,
                })
                .await
                .map_err(rpc)?;
            result
        }
    }
}

fn list_request(include_deleted: bool, page_token: String) -> pb::ListSandboxesRequest {
    pb::ListSandboxesRequest {
        include_deleted,
        // Let the daemon choose a default that is never above its configured
        // maximum. A hard-coded client page size would fail against a server
        // intentionally configured with a smaller limit.
        page_size: Some(0),
        page_token,
    }
}

/// kilndctl's client: every request of one command on one connection.
type Client = KilndServiceClient<OneConnection>;

/// A request the lost connection never carried.
const LOST_UNSENT: &str = "connection to kilnd was lost; nothing was sent";
/// A request the lost connection carried, whose answer never came.
const LOST_UNKNOWN: &str =
    "connection to kilnd was lost after the request was sent; outcome unknown";

/// The one HTTP/2 connection a command uses (C5b-2 adversarial review HIGH 1). A
/// feature check answers for the daemon on the connection that asked it, so a request
/// that needs the feature must ride that connection: tonic's `Channel` would dial
/// again after the daemon is replaced, perhaps by an older one that ignores the field.
/// This one never dials again. A lost connection fails each later request, saying
/// whether it was written.
#[derive(Clone)]
struct OneConnection(http2::SendRequest<tonic::body::Body>);

type ReplyBody =
    http_body_util::combinators::MapErr<hyper::body::Incoming, fn(hyper::Error) -> tonic::Status>;

impl tower::Service<http::Request<tonic::body::Body>> for OneConnection {
    type Response = http::Response<ReplyBody>;
    type Error = tonic::Status;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, tonic::Status>> + Send>,
    >;

    /// HTTP/2 multiplexes; a closed connection is found when the request is handed to
    /// it, which says whether it was taken.
    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), tonic::Status>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
        let reply = self.0.try_send_request(request);
        Box::pin(async move {
            match reply.await {
                Ok(reply) => Ok(
                    reply.map(|body| http_body_util::BodyExt::map_err(body, lost as fn(_) -> _))
                ),
                Err(e) if e.message().is_some() => Err(tonic::Status::unavailable(format!(
                    "{LOST_UNSENT} ({})",
                    e.error()
                ))),
                Err(e) => Err(lost(e.into_error())),
            }
        })
    }
}

/// The connection failed once the request had been handed to it.
fn lost(e: hyper::Error) -> tonic::Status {
    tonic::Status::unknown(format!("{LOST_UNKNOWN} ({e})"))
}

async fn connect(path: PathBuf) -> Result<Client> {
    let shown = path.display().to_string();
    let stream = UnixStream::connect(&path)
        .await
        .with_context(|| format!("connect to {shown}"))?;
    let (send, connection) = http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .handshake(TokioIo::new(stream))
        .await
        .with_context(|| format!("connect to {shown}"))?;
    // Ends with the connection; nothing dials again.
    tokio::spawn(connection);
    // The URI is required by the API but unused: the connection is the socket.
    Ok(KilndServiceClient::with_origin(
        OneConnection(send),
        Uri::from_static("http://kilnd.invalid"),
    )
    .max_decoding_message_size(64 << 20))
}

async fn create(client: &mut Client, a: CreateArgs) -> Result<pb::Sandbox> {
    let labels = a
        .label
        .iter()
        .map(|l| {
            l.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .context("labels are KEY=VALUE")
        })
        .collect::<Result<_>>()?;
    let mode = match (a.net, a.allow.is_empty()) {
        (None | Some(Net::None), true) => pb::NetworkMode::None,
        (Some(Net::Full), true) => pb::NetworkMode::Full,
        (None, false) => pb::NetworkMode::Allowlist,
        (Some(_), false) => bail!("--allow can't be combined with --net"),
    };
    let lifetime = a
        .max_lifetime
        .as_deref()
        .map(parse_long_duration_ms)
        .transpose()?;
    let idle = a
        .idle_timeout
        .as_deref()
        .map(parse_long_duration_ms)
        .transpose()?;
    let expiry =
        (a.expiry_defaults || lifetime.is_some() || idle.is_some()).then(|| pb::ExpiryPolicy {
            max_lifetime_ms: lifetime.unwrap_or(0),
            idle_timeout_ms: idle.unwrap_or(0),
        });
    if expiry.is_some() {
        // An older daemon ignores the unknown field and creates a sandbox that never
        // expires, so discover first and send nothing it would not honor.
        require_feature(
            client,
            pb::Feature::SandboxExpiry,
            "--max-lifetime, --idle-timeout or --expiry-defaults",
        )
        .await?;
    }
    let default_env = parse_env(&a.default_env)?;
    if !default_env.is_empty() {
        // An older daemon would ignore it and run every command without it.
        require_feature(client, pb::Feature::SandboxDefaultEnv, "--default-env").await?;
    }
    let from_checkpoint = a.from_checkpoint.unwrap_or_default();
    if !from_checkpoint.is_empty() {
        // An older daemon ignores from_checkpoint and would create an empty sandbox.
        require_feature(
            client,
            pb::Feature::WorkspaceCheckpoint,
            "--from-checkpoint",
        )
        .await?;
    }
    let request_id = a.request_id.unwrap_or_default();
    if !request_id.is_empty() {
        // An older daemon ignores request_id and would create a second sandbox on a
        // retry, so discover first.
        require_feature(client, pb::Feature::IdempotentCreate, "--request-id").await?;
    }
    let spec = pb::SandboxSpec {
        image: a.image.unwrap_or_default(),
        limits: Some(pb::ResourceLimits {
            memory_bytes: a
                .memory
                .as_deref()
                .map(parse_size)
                .transpose()?
                .unwrap_or(0),
            cpu_millis: a.cpus.as_deref().map(parse_cpus).transpose()?.unwrap_or(0),
            pids: a.pids.unwrap_or(0),
            disk_bytes: a.disk.as_deref().map(parse_size).transpose()?.unwrap_or(0),
        }),
        network: Some(pb::NetworkPolicy {
            mode: mode.into(),
            allow: a.allow,
        }),
        read_only_root: a.read_only,
        writable_paths: a.writable,
        labels,
    };
    let sandbox = client
        .create_sandbox(pb::CreateSandboxRequest {
            default_env,
            spec: Some(spec),
            expiry,
            request_id,
            from_checkpoint: from_checkpoint.clone(),
        })
        .await
        .map_err(rpc)?
        .into_inner()
        .sandbox
        .context("response has no sandbox")?;
    // Defence in depth: the sandbox must say it was restored from the checkpoint asked
    // for. Nothing is deleted on the caller's behalf.
    if sandbox.from_checkpoint != from_checkpoint {
        bail!(
            "warning: kilnd created sandbox {} but ignored --from-checkpoint {from_checkpoint} (the sandbox reports {:?}); it was not deleted: remove it with `kilndctl rm {}`",
            sandbox.id,
            sandbox.from_checkpoint,
            sandbox.id
        );
    }
    Ok(sandbox)
}

/// The capture request `checkpoint create` sends.
fn capture_request(
    sandbox: String,
    max_lifetime: Option<&str>,
    idle_timeout: Option<&str>,
    max_size: Option<&str>,
    request_id: Option<String>,
) -> Result<pb::CheckpointSandboxRequest> {
    Ok(pb::CheckpointSandboxRequest {
        sandbox_id: sandbox,
        request_id: request_id.unwrap_or_default(),
        // Always sent: a checkpoint's expiry is required, and zero fields take
        // kilnd's defaults.
        expiry: Some(pb::ExpiryPolicy {
            max_lifetime_ms: max_lifetime.map(parse_long_duration_ms).transpose()?.unwrap_or(0),
            idle_timeout_ms: idle_timeout.map(parse_long_duration_ms).transpose()?.unwrap_or(0),
        }),
        max_size_bytes: max_size.map(parse_size).transpose()?.unwrap_or(0),
    })
}

/// `kilndctl checkpoint ...`. The checkpoint RPCs need no feature check before they are
/// sent: a kilnd without them answers UNIMPLEMENTED, and no field is silently dropped.
async fn checkpoint(client: &mut Client, command: CheckpointCommand) -> Result<u8> {
    match command {
        CheckpointCommand::Create {
            sandbox,
            max_lifetime,
            idle_timeout,
            max_size,
            request_id,
        } => {
            let request = capture_request(
                sandbox,
                max_lifetime.as_deref(),
                idle_timeout.as_deref(),
                max_size.as_deref(),
                request_id,
            )?;
            let c = client
                .checkpoint_sandbox(request)
                .await
                .map_err(rpc)?
                .into_inner()
                .checkpoint
                .context("response has no checkpoint")?;
            println!("{}", c.id);
            // A keyed retry answers with the settled checkpoint, whatever its state.
            if c.state != pb::CheckpointState::Ready as i32 {
                eprintln!(
                    "kilndctl: checkpoint {} is {}{}",
                    c.id,
                    checkpoint_state(c.state),
                    if c.failure_reason.is_empty() {
                        String::new()
                    } else {
                        format!(": {}", c.failure_reason)
                    }
                );
                return Ok(1);
            }
            Ok(0)
        }
        CheckpointCommand::Get { id } => {
            let c = client
                .get_checkpoint(pb::GetCheckpointRequest { id })
                .await
                .map_err(rpc)?
                .into_inner()
                .checkpoint
                .context("response has no checkpoint")?;
            print_checkpoint(&c);
            Ok(0)
        }
        CheckpointCommand::Ls { sandbox, page_size } => {
            println!(
                "{:<35}  {:<11}  {:<19}  {:>9}  {:<20}  EXPIRES",
                "ID", "STATE", "SANDBOX", "SIZE", "CREATED"
            );
            let mut pages = PageSize::new(page_size);
            let mut page_token = String::new();
            loop {
                let r = match client
                    .list_checkpoints(pb::ListCheckpointsRequest {
                        sandbox_id: sandbox.clone().unwrap_or_default(),
                        page_size: pages.size,
                        page_token: page_token.clone(),
                    })
                    .await
                {
                    Ok(r) => r.into_inner(),
                    Err(s) if pages.shrink(&s) => continue,
                    Err(s) => return Err(rpc(s)),
                };
                pages.answered = true;
                for c in &r.checkpoints {
                    println!(
                        "{:<35}  {:<11}  {:<19}  {:>9}  {:<20}  {}",
                        c.id,
                        checkpoint_state(c.state),
                        c.sandbox_id,
                        size_mib(c.size_bytes),
                        time(c.created_at_unix_ms),
                        time(next_expiry(c))
                    );
                }
                page_token = r.next_page_token;
                if page_token.is_empty() {
                    break;
                }
            }
            Ok(0)
        }
        CheckpointCommand::Rm {
            id,
            release_request_id,
        } => {
            let c = client
                .delete_checkpoint(pb::DeleteCheckpointRequest {
                    id,
                    release_request_id,
                })
                .await
                .map_err(rpc)?
                .into_inner()
                .checkpoint
                .context("response has no checkpoint")?;
            println!("{} {}", c.id, checkpoint_state(c.state));
            Ok(0)
        }
    }
}

/// The sooner of a checkpoint's two deadlines, or 0.
fn next_expiry(c: &pb::Checkpoint) -> i64 {
    let e = c.expiry.unwrap_or_default();
    match (e.lifetime_expires_at_unix_ms, e.idle_expires_at_unix_ms) {
        (0, idle) => idle,
        (lifetime, 0) => lifetime,
        (lifetime, idle) => lifetime.min(idle),
    }
}

/// A byte count as whole MiB, rounded up, or `-` for none.
/// Health's checkpoint lines: the stats whenever kilnd reports them (also while the
/// feature is withdrawn, for cleanup), the limits only while it is listed.
fn print_checkpoint_health(h: &pb::HealthResponse) {
    if let Some(c) = h.admission.as_ref().and_then(|a| a.checkpoints) {
        println!(
            "checkpoints:        node {}/{}, {}/{} bytes; yours {}/{}, {}/{} bytes; {} deleting",
            c.current_count,
            c.max_count,
            c.reserved_bytes,
            c.max_bytes,
            c.caller_count,
            c.max_count_per_uid,
            c.caller_reserved_bytes,
            c.max_bytes_per_uid,
            c.pending_deletes
        );
        println!(
            "                    workers {}/{} (yours {}/{}), cleanup {}/{}, records {}/{} (yours {}/{}), request records {}/{} (yours {}/{})",
            c.current_workers,
            c.max_workers,
            c.caller_workers,
            c.max_workers_per_uid,
            c.current_cleanup_workers,
            c.max_cleanup_workers,
            c.current_records,
            c.max_records,
            c.caller_records,
            c.max_records_per_uid,
            c.request_records,
            c.max_request_records,
            c.caller_request_records,
            c.max_request_records_per_uid
        );
        println!(
            "                    {} captures and {} forks refused, {} expired",
            c.rejected_captures, c.rejected_forks, c.expired
        );
    }
    let limits = h
        .runtime_capabilities
        .as_ref()
        .and_then(|c| c.limits.as_ref())
        .and_then(|l| l.checkpoint.as_ref());
    if let Some(l) = limits {
        println!(
            "checkpoint limits:  {} bytes each; lifetime {} (at most {}), idle {} (at most {})",
            l.max_size_bytes,
            duration_text(l.default_lifetime_ms),
            duration_text(l.max_lifetime_ms),
            duration_text(l.default_idle_ms),
            duration_text(l.max_idle_ms)
        );
    }
}

/// Whole days, hours, minutes or seconds, else milliseconds.
fn duration_text(ms: u64) -> String {
    for (unit, size) in [
        ("d", 86_400_000),
        ("h", 3_600_000),
        ("m", 60_000),
        ("s", 1000),
    ] {
        if ms != 0 && ms.is_multiple_of(size) {
            return format!("{}{unit}", ms / size);
        }
    }
    format!("{ms}ms")
}

fn size_mib(bytes: u64) -> String {
    if bytes == 0 {
        "-".into()
    } else {
        format!("{} MiB", bytes.div_ceil(1 << 20))
    }
}

fn print_checkpoint(c: &pb::Checkpoint) {
    println!("id:         {}", c.id);
    println!("state:      {}", checkpoint_state(c.state));
    println!("sandbox:    {}", c.sandbox_id);
    println!("owner:      {}", c.owner_uid);
    println!("created:    {}", time(c.created_at_unix_ms));
    if c.ready_at_unix_ms != 0 {
        println!("ready:      {}", time(c.ready_at_unix_ms));
    }
    if !c.failure_reason.is_empty() {
        println!("reason:     {}", c.failure_reason);
    }
    if c.deletion_reason != pb::DeletionReason::Unspecified as i32 {
        println!("deleted by: {}", deletion_reason(c.deletion_reason));
    }
    if !c.request_id.is_empty() {
        println!(
            "request id: {}{}",
            c.request_id,
            if c.request_id_released {
                " (released)"
            } else {
                ""
            }
        );
    }
    println!(
        "size:       {} bytes charged (at most {}), {} logical, {} allocated",
        c.size_bytes, c.max_size_bytes, c.logical_bytes, c.allocated_bytes
    );
    if !c.content_sha256.is_empty() {
        println!("content:    sha256 {}", c.content_sha256);
    }
    println!("image:      {} (sha256 {})", c.image, c.image_content_sha256);
    if c.read_only_root {
        println!("read-only:  yes, writable {}", c.writable_paths.join(" "));
    }
    println!("excluded:   {}", c.excluded_paths.join(" "));
    println!("format:     {}", c.format_version);
    if let Some(e) = &c.expiry {
        let policy = e.effective.unwrap_or_default();
        println!(
            "expiry:     lifetime {} s, idle {} s",
            policy.max_lifetime_ms / 1000,
            policy.idle_timeout_ms / 1000
        );
        if e.lifetime_expires_at_unix_ms != 0 {
            println!(
                "expires:    {} (lifetime)",
                time(e.lifetime_expires_at_unix_ms)
            );
        }
        if e.idle_paused {
            println!("idle:       paused while a sandbox is being created from it");
        } else if e.idle_expires_at_unix_ms != 0 {
            println!("expires:    {} (idle)", time(e.idle_expires_at_unix_ms));
        }
        if e.last_activity_at_unix_ms != 0 {
            println!("activity:   {}", time(e.last_activity_at_unix_ms));
        }
    }
}

fn checkpoint_state(v: i32) -> String {
    pb::CheckpointState::try_from(v)
        .map(|s| {
            s.as_str_name()
                .trim_start_matches("CHECKPOINT_STATE_")
                .to_lowercase()
        })
        .unwrap_or_else(|_| format!("unknown({v})"))
}

/// Design section 1: a client uses a feature only from a fresh SERVING Health
/// response that advertises it. Asked right before the request that needs it.
async fn require_feature(client: &mut Client, feature: pb::Feature, what: &str) -> Result<()> {
    let health = client
        .health(pb::HealthRequest {})
        .await
        .map_err(rpc)?
        .into_inner();
    check_feature(&health, feature, what)
}

fn check_feature(health: &pb::HealthResponse, feature: pb::Feature, what: &str) -> Result<()> {
    let name = feature_name(feature as i32);
    if health.status != pb::health_response::Status::Serving as i32 {
        let status = pb::health_response::Status::try_from(health.status)
            .map(|s| s.as_str_name().trim_start_matches("STATUS_").to_lowercase())
            .unwrap_or_else(|_| format!("unknown({})", health.status));
        bail!(
            "kilnd is {status}, not serving, so its features are unproven; refusing to send {what} (needs {name}): {}",
            health.detail
        );
    }
    let advertised = health
        .runtime_capabilities
        .as_ref()
        .is_some_and(|c| c.features.contains(&(feature as i32)));
    if !advertised {
        bail!(
            "this kilnd (version {}) does not advertise {name}; refusing to send {what}, which it would ignore or refuse",
            health.version
        );
    }
    Ok(())
}

async fn exec(client: &mut Client, id: String, argv: Vec<String>, opts: &ExecOpts) -> Result<u8> {
    let mut stdin = Vec::new();
    if opts.stdin {
        std::io::stdin()
            .take(MAX_STDIN + 1)
            .read_to_end(&mut stdin)?;
        if stdin.len() as u64 > MAX_STDIN {
            bail!("stdin is larger than {MAX_STDIN} bytes");
        }
    }
    let timeout_ms = opts
        .timeout
        .as_deref()
        .map(parse_duration_ms)
        .transpose()?
        .unwrap_or(0);
    let cwd = opts.cwd.clone().unwrap_or_default();
    if !cwd.is_empty() {
        // An older daemon would ignore it and run the command in "/".
        require_feature(client, pb::Feature::ExecCwd, "--cwd").await?;
    }
    let env = parse_env(&opts.env)?;
    if !env.is_empty() {
        require_feature(client, pb::Feature::ExecEnv, "--env").await?;
    }
    let request = pb::ExecRequest {
        cwd,
        env,
        sandbox_id: id,
        argv,
        stdin,
        timeout_ms,
    };
    if opts.stream {
        // An older daemon answers UNIMPLEMENTED, but say why before sending anything.
        require_feature(client, pb::Feature::ExecStream, "--stream").await?;
        return exec_streamed(client, request, opts).await;
    }
    let response = client.exec(request).await;
    let response = match response {
        Ok(response) => response,
        Err(status) if status.code() == tonic::Code::DeadlineExceeded => {
            eprintln!("kilndctl: deadline_exceeded: {}", status.message());
            return Ok(EXIT_TIMED_OUT);
        }
        Err(status) => return Err(rpc(status)),
    };
    let e = response
        .into_inner()
        .execution
        .context("response has no execution")?;
    write_execution_streams(
        &e,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    )?;
    Ok(report_execution(&e, opts))
}

/// `exec --stream`: live bytes as they come, gaps on stderr, then the same report and
/// exit code as a unary Exec. The final retained output is not printed again.
async fn exec_streamed(
    client: &mut Client,
    request: pb::ExecRequest,
    opts: &ExecOpts,
) -> Result<u8> {
    use pb::exec_stream_response::Event;
    let response = client
        .exec_stream(pb::ExecStreamRequest {
            exec: Some(request),
        })
        .await;
    let mut stream = match response {
        Ok(response) => response.into_inner(),
        Err(status) if status.code() == tonic::Code::DeadlineExceeded => {
            eprintln!("kilndctl: deadline_exceeded: {}", status.message());
            return Ok(EXIT_TIMED_OUT);
        }
        Err(status) => return Err(rpc(status)),
    };
    let mut next_seq = 0u64;
    while let Some(message) = stream.message().await.map_err(rpc)? {
        if message.seq != next_seq {
            bail!(
                "stream message {} arrived where {next_seq} was due",
                message.seq
            );
        }
        next_seq += 1;
        match message.event.context("stream message has no event")? {
            Event::Started(started) => {
                if opts.verbose {
                    eprintln!("kilndctl: execution {} started", started.execution_id);
                }
            }
            Event::Chunk(chunk) => {
                if chunk.stream == pb::OutputStream::Stderr as i32 {
                    let mut err = std::io::stderr().lock();
                    err.write_all(&chunk.data)?;
                    err.flush()?;
                } else {
                    let mut out = std::io::stdout().lock();
                    out.write_all(&chunk.data)?;
                    out.flush()?;
                }
            }
            Event::Gap(gap) => {
                let name = if gap.stream == pb::OutputStream::Stderr as i32 {
                    "stderr"
                } else {
                    "stdout"
                };
                eprintln!(
                    "kilndctl: live {name} lost {}{} bytes at offset {}",
                    if gap.dropped_bytes_known {
                        ""
                    } else {
                        "at least "
                    },
                    gap.dropped_bytes,
                    gap.offset
                );
            }
            Event::Finished(finished) => {
                let e = finished
                    .execution
                    .context("ExecFinished has no execution")?;
                // The bytes went out live; only the notes and the outcome remain. The
                // retained prefix is not printed again, so its truncation is no news;
                // an unknown total still is.
                let notes_only = |o: &Option<pb::Output>| {
                    o.as_ref().map(|o| pb::Output {
                        data: Vec::new(),
                        truncated: false,
                        ..o.clone()
                    })
                };
                write_execution_streams(
                    &pb::Execution {
                        stdout: notes_only(&e.stdout),
                        stderr: notes_only(&e.stderr),
                        ..e.clone()
                    },
                    &mut std::io::sink(),
                    &mut std::io::stderr().lock(),
                )?;
                return Ok(report_execution(&e, opts));
            }
        }
    }
    bail!("the stream ended without ExecFinished; see kilndctl execution for its outcome")
}

fn report_execution(e: &pb::Execution, opts: &ExecOpts) -> u8 {
    let state = pb::ExecutionState::try_from(e.state).unwrap_or(pb::ExecutionState::Unspecified);
    if opts.verbose || state != pb::ExecutionState::Exited {
        let reason = if e.failure_reason.is_empty() {
            String::new()
        } else {
            format!(": {}", e.failure_reason)
        };
        eprintln!(
            "kilndctl: execution {} {}{reason}",
            e.id,
            execution_state(e.state)
        );
    }
    match state {
        pb::ExecutionState::Exited => e.exit_code.unwrap_or(1).clamp(0, 255) as u8,
        pb::ExecutionState::TimedOut => EXIT_TIMED_OUT,
        _ => EXIT_FAILED,
    }
}

fn write_execution_streams(
    e: &pb::Execution,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> std::io::Result<()> {
    let empty = pb::Output::default();
    let out = e.stdout.as_ref().unwrap_or(&empty);
    let err = e.stderr.as_ref().unwrap_or(&empty);
    stdout.write_all(&out.data)?;
    stdout.flush()?;
    stderr.write_all(&err.data)?;
    stderr.flush()?;
    if let Some(pb::command_status::Termination::Signal(signal)) = e
        .command_status
        .as_ref()
        .and_then(|s| s.termination.as_ref())
    {
        writeln!(
            stderr,
            "kilndctl: terminated by signal {}{}",
            signal.number,
            if signal.core_dumped {
                " (core dumped)"
            } else {
                ""
            }
        )?;
    }
    if let Some(d) = &e.runtime_error {
        writeln!(
            stderr,
            "kilndctl: runtime {:?}/{:?}: {}{}{}",
            pb::RuntimeErrorKind::try_from(d.kind).unwrap_or_default(),
            pb::RuntimeStage::try_from(d.stage).unwrap_or_default(),
            d.message,
            d.native_code
                .as_ref()
                .map(|c| format!(" ({c})"))
                .unwrap_or_default(),
            if d.message_truncated {
                " [truncated]"
            } else {
                ""
            }
        )?;
    }
    for (name, o) in [("stdout", out), ("stderr", err)] {
        if o.truncated {
            if o.total_bytes_known {
                writeln!(
                    stderr,
                    "kilndctl: {name} truncated: kept {} of {} bytes",
                    o.data.len(),
                    o.total_bytes
                )?;
            } else {
                writeln!(
                    stderr,
                    "kilndctl: {name} truncated: kept {} of at least {} observed bytes; exact total unknown",
                    o.data.len(),
                    o.total_bytes
                )?;
            }
        } else if !o.total_bytes_known {
            writeln!(
                stderr,
                "kilndctl: {name} capture incomplete after {} observed bytes; exact total unknown",
                o.total_bytes
            )?;
        }
    }
    stderr.flush()
}

fn output_total(output: Option<&pb::Output>) -> String {
    match output {
        None => "0".into(),
        Some(output) if output.total_bytes_known => output.total_bytes.to_string(),
        Some(output) => format!(">={}", output.total_bytes),
    }
}

fn print_sandbox(s: &pb::Sandbox) {
    println!("id:         {}", s.id);
    println!("state:      {}", sandbox_state(s.state));
    println!("backend:    {} {}", s.backend, s.backend_id);
    println!("created:    {}", time(s.created_at_unix_ms));
    println!("updated:    {}", time(s.updated_at_unix_ms));
    if s.deleted_at_unix_ms != 0 {
        println!("deleted:    {}", time(s.deleted_at_unix_ms));
    }
    if !s.failure_reason.is_empty() {
        println!("reason:     {}", s.failure_reason);
    }
    if s.deletion_reason != pb::DeletionReason::Unspecified as i32 {
        println!("deleted by: {}", deletion_reason(s.deletion_reason));
    }
    if !s.request_id.is_empty() {
        println!(
            "request id: {}{}",
            s.request_id,
            if s.request_id_released {
                " (released)"
            } else {
                ""
            }
        );
    }
    if !s.from_checkpoint.is_empty() {
        println!(
            "from:       {} (sha256 {})",
            s.from_checkpoint, s.checkpoint_content_sha256
        );
    }
    if !s.default_env_names.is_empty() {
        println!(
            "env:        {} (sha256 {})",
            s.default_env_names.join(" "),
            s.default_env_sha256
        );
    }
    if let Some(e) = &s.expiry {
        let policy = e.effective.unwrap_or_default();
        if policy.max_lifetime_ms != 0 || policy.idle_timeout_ms != 0 {
            let limit = |ms: u64| {
                if ms == 0 {
                    "never".to_string()
                } else {
                    format!("{} s", ms / 1000)
                }
            };
            println!(
                "expiry:     lifetime {}, idle {}",
                limit(policy.max_lifetime_ms),
                limit(policy.idle_timeout_ms)
            );
            if e.lifetime_expires_at_unix_ms != 0 {
                println!(
                    "expires:    {} (lifetime)",
                    time(e.lifetime_expires_at_unix_ms)
                );
            }
            if e.idle_paused {
                println!("idle:       paused while an execution runs or waits");
            } else if e.idle_expires_at_unix_ms != 0 {
                println!("expires:    {} (idle)", time(e.idle_expires_at_unix_ms));
            }
        }
        if e.last_activity_at_unix_ms != 0 {
            println!("activity:   {}", time(e.last_activity_at_unix_ms));
        }
    }
    if let Some(r) = &s.reservation {
        println!(
            "reserved:   memory {} MiB, disk {} MiB, pids {}, host cpu {} millis, vcpus {}, host pids {}",
            r.memory_bytes >> 20,
            r.disk_bytes >> 20,
            r.pids,
            r.host_cpu_millis,
            r.virtual_cpu_slots,
            r.host_pids
        );
    }
    if !s.runtime_profile.is_empty() {
        println!("profile:    {}", s.runtime_profile);
    }
    if !s.runtime_artifact_digest.is_empty() {
        println!("artifact:   {}", s.runtime_artifact_digest);
    }
    if let Some(spec) = &s.spec {
        let l = spec.limits.unwrap_or_default();
        println!("image:      {}", spec.image);
        println!(
            "limits:     memory {} MiB, cpu {}.{:03}, pids {}, disk {} MiB",
            l.memory_bytes >> 20,
            l.cpu_millis / 1000,
            l.cpu_millis % 1000,
            l.pids,
            l.disk_bytes >> 20
        );
        let net = spec.network.clone().unwrap_or_default();
        let mode = pb::NetworkMode::try_from(net.mode)
            .map(|m| m.as_str_name())
            .unwrap_or("UNKNOWN");
        println!(
            "network:    {} {}",
            mode.trim_start_matches("NETWORK_MODE_").to_lowercase(),
            net.allow.join(" ")
        );
        if spec.read_only_root {
            println!(
                "read-only:  yes, writable {}",
                spec.writable_paths.join(" ")
            );
        }
        let mut labels: Vec<_> = spec
            .labels
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        labels.sort();
        if !labels.is_empty() {
            println!("labels:     {}", labels.join(" "));
        }
    }
}

fn feature_name(v: i32) -> String {
    pb::Feature::try_from(v)
        .map(|f| {
            f.as_str_name()
                .trim_start_matches("FEATURE_")
                .to_lowercase()
        })
        .unwrap_or_else(|_| format!("unknown({v})"))
}

fn deletion_reason(v: i32) -> String {
    pb::DeletionReason::try_from(v)
        .map(|r| {
            r.as_str_name()
                .trim_start_matches("DELETION_REASON_")
                .to_lowercase()
        })
        .unwrap_or_else(|_| format!("unknown({v})"))
}

fn execution_mode(v: i32) -> String {
    pb::ExecutionMode::try_from(v)
        .map(|m| {
            m.as_str_name()
                .trim_start_matches("EXECUTION_MODE_")
                .to_lowercase()
        })
        .unwrap_or_else(|_| format!("unknown({v})"))
}

fn cancel_reason(v: i32) -> String {
    pb::CancelReason::try_from(v)
        .map(|r| {
            r.as_str_name()
                .trim_start_matches("CANCEL_REASON_")
                .to_lowercase()
        })
        .unwrap_or_else(|_| format!("unknown({v})"))
}

fn sandbox_state(v: i32) -> String {
    pb::SandboxState::try_from(v)
        .map(|s| {
            s.as_str_name()
                .trim_start_matches("SANDBOX_STATE_")
                .to_lowercase()
        })
        .unwrap_or_else(|_| format!("unknown({v})"))
}

fn execution_state(v: i32) -> String {
    pb::ExecutionState::try_from(v)
        .map(|s| {
            s.as_str_name()
                .trim_start_matches("EXECUTION_STATE_")
                .to_lowercase()
        })
        .unwrap_or_else(|_| format!("unknown({v})"))
}

fn accounting_status(v: i32) -> String {
    pb::NodeAccountingStatus::try_from(v)
        .map(|s| {
            s.as_str_name()
                .trim_start_matches("NODE_ACCOUNTING_STATUS_")
                .to_lowercase()
        })
        .unwrap_or_else(|_| format!("unknown({v})"))
}

fn cleanup_evidence(v: i32) -> String {
    pb::CleanupEvidence::try_from(v)
        .map(|s| {
            s.as_str_name()
                .trim_start_matches("CLEANUP_EVIDENCE_")
                .to_lowercase()
        })
        .unwrap_or_else(|_| format!("unknown({v})"))
}

fn sandbox_reusable(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}

/// `checkpoint ls`'s page size. kilnd refuses a page above its `--max-list-page-size`
/// (1 to 1,000), which Health does not advertise, and `page_size` 0 asks for the whole
/// list or `RESOURCE_EXHAUSTED`. So without `--page-size` it starts at 100 and halves
/// on kilnd's exact page-cap refusal, only before the first page, never below 1.
struct PageSize {
    size: u32,
    explicit: bool,
    answered: bool,
}

impl PageSize {
    fn new(explicit: Option<u32>) -> Self {
        Self {
            size: explicit.unwrap_or(100),
            explicit: explicit.is_some(),
            answered: false,
        }
    }

    /// Whether to retry the refused request with a smaller page.
    fn shrink(&mut self, refusal: &tonic::Status) -> bool {
        if self.explicit
            || self.answered
            || self.size <= 1
            || refusal.code() != tonic::Code::InvalidArgument
            || refusal.message() != kilnd_api::PAGE_SIZE_EXCEEDS_MAXIMUM
        {
            return false;
        }
        self.size /= 2;
        true
    }
}

fn rpc(s: tonic::Status) -> anyhow::Error {
    anyhow::anyhow!(
        "{}: {}",
        format!("{:?}", s.code()).to_lowercase(),
        s.message()
    )
}

/// `512M`, `2G`, `65536`.
fn parse_size(s: &str) -> Result<u64> {
    let (num, mult) = match s.char_indices().last() {
        Some((i, 'K' | 'k')) => (&s[..i], 1u64 << 10),
        Some((i, 'M' | 'm')) => (&s[..i], 1 << 20),
        Some((i, 'G' | 'g')) => (&s[..i], 1 << 30),
        _ => (s, 1),
    };
    let n: u64 = num.parse().with_context(|| format!("invalid size {s:?}"))?;
    n.checked_mul(mult)
        .with_context(|| format!("size {s:?} is too large"))
}

/// `0.5` → 500 thousandths of a core.
fn parse_cpus(s: &str) -> Result<u32> {
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    let bad = || anyhow::anyhow!("invalid --cpus {s:?}: expected a number like 0.5 or 2");
    if frac.len() > 3 || (whole.is_empty() && frac.is_empty()) {
        return Err(bad());
    }
    let whole: u32 = if whole.is_empty() {
        0
    } else {
        whole.parse().map_err(|_| bad())?
    };
    let frac: u32 = if frac.is_empty() {
        0
    } else {
        format!("{frac:0<3}").parse().map_err(|_| bad())?
    };
    let millis = whole
        .checked_mul(1000)
        .and_then(|w| w.checked_add(frac))
        .ok_or_else(bad)?;
    if millis == 0 {
        return Err(bad());
    }
    Ok(millis)
}

/// `500ms`, `30s`, `2m`, or plain seconds.
fn parse_duration_ms(s: &str) -> Result<u32> {
    let (num, mult) = if let Some(n) = s.strip_suffix("ms") {
        (n, 1)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1000)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60_000)
    } else {
        (s, 1000)
    };
    let n: u32 = num
        .parse()
        .with_context(|| format!("invalid duration {s:?}"))?;
    n.checked_mul(mult)
        .filter(|&ms| ms > 0)
        .with_context(|| format!("invalid duration {s:?}"))
}

/// `90s`, `30m`, `2h`, `7d`, `500ms`, or plain seconds, as milliseconds.
fn parse_long_duration_ms(s: &str) -> Result<u64> {
    let (num, mult) = if let Some(n) = s.strip_suffix("ms") {
        (n, 1)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1000)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60_000)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3_600_000)
    } else if let Some(n) = s.strip_suffix('d') {
        (n, 86_400_000)
    } else {
        (s, 1000)
    };
    let n: u64 = num
        .parse()
        .with_context(|| format!("invalid duration {s:?}"))?;
    n.checked_mul(mult)
        .filter(|&ms| ms > 0)
        .with_context(|| format!("invalid duration {s:?}"))
}

/// An argv as a shell would need it typed, for display only.
fn shell_words(argv: &[String]) -> String {
    argv.iter()
        .map(|a| {
            if !a.is_empty()
                && a.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_./=:,+@%".contains(c))
            {
                a.clone()
            } else {
                format!("'{}'", a.replace('\'', r"'\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Unix milliseconds as `2026-10-13 22:41:05Z` (UTC).
fn time(ms: i64) -> String {
    if ms <= 0 {
        return "-".into();
    }
    let secs = ms.div_euclid(1000);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod transport_tests;

#[cfg(test)]
mod tests {
    use super::*;

    /// `create --from-checkpoint` needs a SERVING Health that lists
    /// workspace_checkpoint: an older daemon would ignore field 5 and create an empty
    /// sandbox.
    #[test]
    fn create_from_a_checkpoint_needs_the_feature() {
        let cli = Cli::try_parse_from([
            "kilndctl",
            "create",
            "--from-checkpoint",
            "cp-0123456789abcdef0123456789abcdef",
        ])
        .unwrap();
        let Command::Create(args) = cli.command else {
            panic!("not create");
        };
        assert_eq!(
            args.from_checkpoint.as_deref(),
            Some("cp-0123456789abcdef0123456789abcdef")
        );
        let serving = pb::health_response::Status::Serving as i32;
        let health = |features: Vec<i32>, status: i32| pb::HealthResponse {
            status,
            version: "0.1.0".into(),
            runtime_capabilities: Some(pb::RuntimeCapabilities {
                features,
                ..Default::default()
            }),
            ..Default::default()
        };
        let older = health(vec![pb::Feature::SandboxExpiry as i32], serving);
        let error = check_feature(
            &older,
            pb::Feature::WorkspaceCheckpoint,
            "--from-checkpoint",
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("does not advertise workspace_checkpoint"),
            "{error}"
        );
        let listed = vec![pb::Feature::WorkspaceCheckpoint as i32];
        check_feature(
            &health(listed.clone(), serving),
            pb::Feature::WorkspaceCheckpoint,
            "x",
        )
        .unwrap();
        let degraded = pb::health_response::Status::Degraded as i32;
        assert!(
            check_feature(
                &health(listed, degraded),
                pb::Feature::WorkspaceCheckpoint,
                "x"
            )
            .is_err()
        );
        assert_eq!(duration_text(86_400_000), "1d");
        assert_eq!(duration_text(3_600_000), "1h");
        assert_eq!(duration_text(90_000), "90s");
        assert_eq!(duration_text(1500), "1500ms");
    }

    /// C5b-1 adversarial review LOW: `checkpoint ls` against every valid page cap. The
    /// daemon's side of the refusal is pinned by kilnd's own test of the same constant.
    #[test]
    fn checkpoint_ls_finds_a_page_under_any_valid_cap() {
        let cap_refusal = || tonic::Status::invalid_argument(kilnd_api::PAGE_SIZE_EXCEEDS_MAXIMUM);
        for cap in 1..=1000u32 {
            let mut pages = PageSize::new(None);
            let mut tries = 1;
            while pages.size > cap {
                assert!(pages.shrink(&cap_refusal()), "cap {cap}");
                tries += 1;
            }
            assert!(
                pages.size >= 1 && tries <= 8,
                "cap {cap}: {} after {tries}",
                pages.size
            );
        }
        // Any other refusal, a later page, or an explicit size is returned as is.
        let mut pages = PageSize::new(None);
        assert!(!pages.shrink(&tonic::Status::invalid_argument("page_token is invalid")));
        assert!(!pages.shrink(&tonic::Status::resource_exhausted(
            kilnd_api::PAGE_SIZE_EXCEEDS_MAXIMUM
        )));
        pages.answered = true;
        assert!(!pages.shrink(&cap_refusal()));
        let mut pages = PageSize::new(Some(7));
        assert_eq!(pages.size, 7);
        assert!(!pages.shrink(&cap_refusal()));
        let mut pages = PageSize::new(None);
        pages.size = 1;
        assert!(!pages.shrink(&cap_refusal()), "never 0");
        let cli = Cli::try_parse_from(["kilndctl", "checkpoint", "ls", "--page-size", "1000"]);
        assert!(cli.is_ok());
        for bad in ["0", "1001"] {
            let cli = Cli::try_parse_from(["kilndctl", "checkpoint", "ls", "--page-size", bad]);
            assert!(cli.is_err(), "--page-size {bad}");
        }
    }

    #[test]
    fn checkpoint_commands_parse_and_a_capture_always_sends_an_expiry() {
        let cli = Cli::try_parse_from([
            "kilndctl",
            "checkpoint",
            "create",
            "sb-0123456789abcdef",
            "--max-lifetime",
            "2h",
            "--max-size",
            "512M",
            "--request-id",
            "k1",
        ])
        .unwrap();
        let Command::Checkpoint(CheckpointCommand::Create {
            sandbox,
            max_lifetime,
            idle_timeout,
            max_size,
            request_id,
        }) = cli.command
        else {
            panic!("not checkpoint create");
        };
        let r = capture_request(
            sandbox,
            max_lifetime.as_deref(),
            idle_timeout.as_deref(),
            max_size.as_deref(),
            request_id,
        )
        .unwrap();
        assert_eq!(r.sandbox_id, "sb-0123456789abcdef");
        assert_eq!(r.request_id, "k1");
        assert_eq!(r.max_size_bytes, 512 << 20);
        let e = r.expiry.unwrap();
        assert_eq!((e.max_lifetime_ms, e.idle_timeout_ms), (7_200_000, 0));
        // No flags: still an (empty) policy, so kilnd's finite defaults apply.
        let r = capture_request("sb-0123456789abcdef".into(), None, None, None, None).unwrap();
        assert_eq!(r.expiry, Some(pb::ExpiryPolicy::default()));
        assert_eq!((r.max_size_bytes, r.request_id.as_str()), (0, ""));
        assert!(capture_request("s".into(), Some("soon"), None, None, None).is_err());
        for argv in [
            &["kilndctl", "checkpoint", "get", "cp-0"][..],
            &["kilndctl", "checkpoint", "ls"],
            &["kilndctl", "checkpoint", "ls", "--sandbox", "sb-0123456789abcdef"],
            &["kilndctl", "checkpoint", "rm", "cp-0", "--release-request-id"],
        ] {
            assert!(Cli::try_parse_from(argv).is_ok(), "{argv:?}");
        }
        assert!(Cli::try_parse_from(["kilndctl", "checkpoint", "create"]).is_err());
        assert_eq!(checkpoint_state(pb::CheckpointState::Quarantined as i32), "quarantined");
        assert_eq!(size_mib(0), "-");
        assert_eq!(size_mib(1), "1 MiB");
        let mut c = pb::Checkpoint::default();
        assert_eq!(next_expiry(&c), 0);
        c.expiry = Some(pb::CheckpointExpiryStatus {
            lifetime_expires_at_unix_ms: 50,
            idle_expires_at_unix_ms: 20,
            ..Default::default()
        });
        assert_eq!(next_expiry(&c), 20);
    }

    #[test]
    fn env_flags_take_values_or_inherit_them_and_parse_with_run() {
        // SAFETY: a test-only variable no other test reads.
        unsafe { std::env::set_var("KILNDCTL_TEST_INHERITED", "from-env") };
        let env = parse_env(&[
            "A=1".into(),
            "B=".into(),
            "C=x=y".into(),
            "KILNDCTL_TEST_INHERITED".into(),
        ])
        .unwrap();
        let pairs: Vec<_> = env.iter().map(|e| (e.name.as_str(), e.value.as_str())).collect();
        assert_eq!(
            pairs,
            [("A", "1"), ("B", ""), ("C", "x=y"), ("KILNDCTL_TEST_INHERITED", "from-env")]
        );
        assert!(parse_env(&["KILNDCTL_TEST_UNSET_VARIABLE".into()]).is_err());
        // run takes both a sandbox --default-env and a command --env.
        let cli = Cli::try_parse_from([
            "kilndctl", "run", "--default-env", "D=1", "--env", "E=2", "--cwd", "/w", "--", "env",
        ])
        .unwrap();
        let Command::Run { create, opts, argv } = cli.command else {
            panic!("not run");
        };
        assert_eq!(create.default_env, ["D=1"]);
        assert_eq!(opts.env, ["E=2"]);
        assert_eq!(opts.cwd.as_deref(), Some("/w"));
        assert_eq!(argv, ["env"]);
        assert!(!opts.stream);
    }

    #[test]
    fn exec_stream_flag_parses_and_modes_print_by_name() {
        let cli = Cli::try_parse_from([
            "kilndctl",
            "exec",
            "--stream",
            "--timeout",
            "2m",
            "sb-0000000000000000",
            "--",
            "make",
            "-j8",
        ])
        .unwrap();
        let Command::Exec { opts, id, argv } = cli.command else {
            panic!("not exec");
        };
        assert!(opts.stream);
        assert_eq!(opts.timeout.as_deref(), Some("2m"));
        assert_eq!(id, "sb-0000000000000000");
        assert_eq!(argv, ["make", "-j8"]);
        assert_eq!(execution_mode(pb::ExecutionMode::Stream as i32), "stream");
        assert_eq!(execution_mode(pb::ExecutionMode::Unary as i32), "unary");
        assert_eq!(execution_mode(9), "unknown(9)");
    }

    #[test]
    fn every_state_writes_binary_captures_before_typed_diagnostics() {
        for state in [
            pb::ExecutionState::Running,
            pb::ExecutionState::Exited,
            pb::ExecutionState::TimedOut,
            pb::ExecutionState::Canceled,
            pb::ExecutionState::Failed,
            pb::ExecutionState::Interrupted,
        ] {
            let e = pb::Execution {
                state: state as i32,
                stdout: Some(pb::Output {
                    data: b"\0\xffout".to_vec(),
                    total_bytes: 99,
                    truncated: true,
                    total_bytes_known: false,
                }),
                stderr: Some(pb::Output {
                    data: b"\0\xfeerr".to_vec(),
                    total_bytes: 5,
                    truncated: false,
                    total_bytes_known: true,
                }),
                command_status: Some(pb::CommandStatus {
                    termination: Some(pb::command_status::Termination::Signal(pb::SignalStatus {
                        number: 15,
                        core_dumped: true,
                    })),
                }),
                runtime_error: Some(pb::RuntimeDiagnostic {
                    kind: pb::RuntimeErrorKind::Io as i32,
                    stage: pb::RuntimeStage::Capture as i32,
                    message: "lost reader".into(),
                    native_code: Some("errno:5".into()),
                    message_truncated: false,
                }),
                ..Default::default()
            };
            let (mut out, mut err) = (Vec::new(), Vec::new());
            write_execution_streams(&e, &mut out, &mut err).unwrap();
            assert_eq!(out, b"\0\xffout");
            assert!(err.starts_with(b"\0\xfeerrkilndctl: terminated by signal 15 (core dumped)\n"));
            let diagnostics = String::from_utf8_lossy(&err[5..]);
            assert!(diagnostics.contains("runtime Io/Capture: lost reader (errno:5)"));
            assert!(diagnostics.contains(
                "stdout truncated: kept 5 of at least 99 observed bytes; exact total unknown"
            ));
        }
    }

    #[test]
    fn parses_sizes() {
        assert_eq!(parse_size("512M").unwrap(), 512 << 20);
        assert_eq!(parse_size("2g").unwrap(), 2 << 30);
        assert_eq!(parse_size("4096").unwrap(), 4096);
        assert!(parse_size("1T").is_err());
        assert!(parse_size("99999999999999G").is_err());
    }

    #[test]
    fn parses_cpus_without_floats() {
        assert_eq!(parse_cpus("0.5").unwrap(), 500);
        assert_eq!(parse_cpus("2").unwrap(), 2000);
        assert_eq!(parse_cpus("1.25").unwrap(), 1250);
        assert_eq!(parse_cpus(".1").unwrap(), 100);
        for bad in ["0", "", ".", "1.2345", "-1", "x"] {
            assert!(parse_cpus(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn parses_long_durations_and_sends_expiry_only_when_asked() {
        assert_eq!(parse_long_duration_ms("90s").unwrap(), 90_000);
        assert_eq!(parse_long_duration_ms("2h").unwrap(), 7_200_000);
        assert_eq!(parse_long_duration_ms("7d").unwrap(), 604_800_000);
        assert_eq!(parse_long_duration_ms("15").unwrap(), 15_000);
        assert!(parse_long_duration_ms("0s").is_err());
        assert!(parse_long_duration_ms("x").is_err());
        let cli = Cli::try_parse_from(["kilndctl", "create"]).unwrap();
        let Command::Create(args) = cli.command else {
            panic!("create")
        };
        assert!(
            !args.expiry_defaults && args.max_lifetime.is_none() && args.idle_timeout.is_none()
        );
        let cli = Cli::try_parse_from(["kilndctl", "create", "--idle-timeout", "10m"]).unwrap();
        let Command::Create(args) = cli.command else {
            panic!("create")
        };
        assert_eq!(args.idle_timeout.as_deref(), Some("10m"));
    }

    /// Break-it MEDIUM 4: expiry and Renew need a SERVING Health that advertises
    /// SANDBOX_EXPIRY. A 0547a0c daemon's Health has capabilities but no features.
    #[test]
    fn expiry_requires_a_serving_daemon_that_advertises_it() {
        let serving = pb::health_response::Status::Serving as i32;
        let old_daemon = pb::HealthResponse {
            status: serving,
            version: "0.1.0".into(),
            runtime_capabilities: Some(pb::RuntimeCapabilities {
                interruption_preserves_session: false,
                ..Default::default()
            }),
            ..Default::default()
        };
        let error = check_feature(&old_daemon, pb::Feature::SandboxExpiry, "--max-lifetime")
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not advertise sandbox_expiry"), "{error}");
        let no_capabilities = pb::HealthResponse {
            status: serving,
            ..Default::default()
        };
        assert!(check_feature(&no_capabilities, pb::Feature::SandboxExpiry, "renew").is_err());
        let current = pb::HealthResponse {
            status: serving,
            runtime_capabilities: Some(pb::RuntimeCapabilities {
                features: vec![
                    pb::Feature::SandboxExpiry as i32,
                    pb::Feature::TypedReasons as i32,
                ],
                ..Default::default()
            }),
            ..Default::default()
        };
        check_feature(&current, pb::Feature::SandboxExpiry, "--max-lifetime").unwrap();
        assert!(check_feature(&current, pb::Feature::ExecEnv, "--env").is_err());
        // M2: an M1 daemon lists neither request-ID feature, so both options refuse.
        let error = check_feature(&current, pb::Feature::IdempotentCreate, "--request-id")
            .unwrap_err()
            .to_string();
        assert!(error.contains("idempotent_create"), "{error}");
        assert!(
            check_feature(&current, pb::Feature::RequestIdRelease, "--release-request-id")
                .is_err()
        );
        let m2 = pb::HealthResponse {
            runtime_capabilities: Some(pb::RuntimeCapabilities {
                features: vec![
                    pb::Feature::IdempotentCreate as i32,
                    pb::Feature::RequestIdRelease as i32,
                ],
                ..Default::default()
            }),
            ..current.clone()
        };
        check_feature(&m2, pb::Feature::IdempotentCreate, "--request-id").unwrap();
        check_feature(&m2, pb::Feature::RequestIdRelease, "--release-request-id").unwrap();
        for status in [
            pb::health_response::Status::Degraded,
            pb::health_response::Status::ShuttingDown,
            pb::health_response::Status::Unspecified,
        ] {
            let not_serving = pb::HealthResponse {
                status: status as i32,
                ..current.clone()
            };
            let error = check_feature(&not_serving, pb::Feature::SandboxExpiry, "renew")
                .unwrap_err()
                .to_string();
            assert!(error.contains("not serving"), "{error}");
        }
    }

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration_ms("500ms").unwrap(), 500);
        assert_eq!(parse_duration_ms("30s").unwrap(), 30_000);
        assert_eq!(parse_duration_ms("2m").unwrap(), 120_000);
        assert_eq!(parse_duration_ms("5").unwrap(), 5000);
        assert!(parse_duration_ms("0s").is_err());
        assert!(parse_duration_ms("soon").is_err());
    }

    #[test]
    fn formats_times_in_utc() {
        assert_eq!(time(0), "-");
        assert_eq!(time(1_760_409_665_000), "2025-10-14 02:41:05Z");
        assert_eq!(time(951_782_400_000), "2000-02-29 00:00:00Z");
    }

    #[test]
    fn quotes_argv_for_display() {
        let argv = ["sh", "-c", "echo 'hi' > /tmp/x", ""].map(String::from);
        assert_eq!(shell_words(&argv), r#"sh -c 'echo '\''hi'\'' > /tmp/x' ''"#);
    }

    #[test]
    fn list_uses_the_servers_bounded_page_default() {
        assert_eq!(
            list_request(true, "next".into()),
            pb::ListSandboxesRequest {
                include_deleted: true,
                page_size: Some(0),
                page_token: "next".into(),
            }
        );
    }

    #[test]
    fn additive_evidence_displays_every_value() {
        assert_eq!(sandbox_reusable(None), "unknown");
        assert_eq!(sandbox_reusable(Some(false)), "no");
        assert_eq!(
            cleanup_evidence(pb::CleanupEvidence::Unknown as i32),
            "unknown"
        );
        assert_eq!(
            cleanup_evidence(pb::CleanupEvidence::SandboxStopped as i32),
            "sandbox_stopped"
        );
        assert_eq!(
            accounting_status(pb::NodeAccountingStatus::Unavailable as i32),
            "unavailable"
        );
        assert_eq!(
            sandbox_state(pb::SandboxState::Quarantined as i32),
            "quarantined"
        );
    }

    #[test]
    fn deadline_errors_use_the_timeout_exit_code() {
        assert_eq!(EXIT_TIMED_OUT, 124);
        assert_eq!(
            tonic::Status::deadline_exceeded("queued").code(),
            tonic::Code::DeadlineExceeded
        );
    }
}
