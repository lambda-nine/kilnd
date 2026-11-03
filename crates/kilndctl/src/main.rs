//! kilndctl: a small command-line client for the kilnd v1 API.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use hyper_util::rt::TokioIo;
use kilnd_api::v1 as pb;
use pb::kilnd_service_client::KilndServiceClient;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

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
    Rm { id: String },
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
            eprintln!("state:    {}", execution_state(e.state));
            if let Some(code) = e.exit_code {
                eprintln!("exit:     {code}");
            }
            if !e.failure_reason.is_empty() {
                eprintln!("reason:   {}", e.failure_reason);
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
        Command::Rm { id } => {
            let s = client
                .delete_sandbox(pb::DeleteSandboxRequest { id })
                .await
                .map_err(rpc)?
                .into_inner()
                .sandbox
                .context("response has no sandbox")?;
            println!("{} {}", s.id, sandbox_state(s.state));
            Ok(0)
        }
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
                .delete_sandbox(pb::DeleteSandboxRequest { id: sandbox.id })
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

async fn connect(path: PathBuf) -> Result<KilndServiceClient<Channel>> {
    let shown = path.display().to_string();
    // The URI is required by the API but unused: every connection goes to
    // the socket.
    let channel = Endpoint::try_from("http://kilnd.invalid")?
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?)) }
        }))
        .await
        .with_context(|| format!("connect to {shown}"))?;
    Ok(KilndServiceClient::new(channel).max_decoding_message_size(64 << 20))
}

async fn create(client: &mut KilndServiceClient<Channel>, a: CreateArgs) -> Result<pb::Sandbox> {
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
    client
        .create_sandbox(pb::CreateSandboxRequest { spec: Some(spec) })
        .await
        .map_err(rpc)?
        .into_inner()
        .sandbox
        .context("response has no sandbox")
}

async fn exec(
    client: &mut KilndServiceClient<Channel>,
    id: String,
    argv: Vec<String>,
    opts: &ExecOpts,
) -> Result<u8> {
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
    let response = client
        .exec(pb::ExecRequest {
            sandbox_id: id,
            argv,
            stdin,
            timeout_ms,
        })
        .await;
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
    Ok(match state {
        pb::ExecutionState::Exited => e.exit_code.unwrap_or(1).clamp(0, 255) as u8,
        pb::ExecutionState::TimedOut => EXIT_TIMED_OUT,
        _ => EXIT_FAILED,
    })
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
mod tests {
    use super::*;

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
