//! kilndctl's one-connection transport against scripted daemons on a real Unix socket
//! (C5b-2 adversarial review HIGH 1): a feature check holds only for the connection
//! that asked it, so a command never dials a second daemon, and Create's answer must
//! carry the checkpoint it was asked to restore.

use super::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

/// What a scripted daemon saw: its generation and the RPC, with Create's field 5.
type Seen = (usize, &'static str, String);

#[derive(Clone)]
struct Daemon {
    generation: usize,
    /// Lists `workspace_checkpoint` in Health.
    advertises: bool,
    /// Create answers with the requested provenance (a capable daemon), or with none
    /// (an older one that ignored field 5).
    honors_checkpoint: bool,
    /// Health starts this generation's graceful shutdown before it answers: the daemon
    /// is replaced right after the feature check.
    stop_after_health: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    /// Create drops the connection without answering: the request was sent.
    drop_in_create: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    /// Exec drops the connection without answering: the request was sent.
    drop_in_exec: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    seen: mpsc::UnboundedSender<Seen>,
}

type Reply<T> = Result<tonic::Response<T>, tonic::Status>;

fn unused<T>() -> Reply<T> {
    Err(tonic::Status::unimplemented("not used by this test"))
}

#[tonic::async_trait]
impl pb::kilnd_service_server::KilndService for Daemon {
    async fn health(&self, _: tonic::Request<pb::HealthRequest>) -> Reply<pb::HealthResponse> {
        let _ = self.seen.send((self.generation, "health", String::new()));
        let stop = self.stop_after_health.lock().unwrap().take();
        if let Some(stop) = stop {
            let _ = stop.send(());
            // The GOAWAY goes out before the answer.
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok(tonic::Response::new(pb::HealthResponse {
            status: pb::health_response::Status::Serving as i32,
            version: format!("generation {}", self.generation),
            runtime_capabilities: Some(pb::RuntimeCapabilities {
                features: self
                    .advertises
                    .then_some(pb::Feature::WorkspaceCheckpoint as i32)
                    .into_iter()
                    .collect(),
                ..Default::default()
            }),
            ..Default::default()
        }))
    }

    async fn create_sandbox(
        &self,
        request: tonic::Request<pb::CreateSandboxRequest>,
    ) -> Reply<pb::CreateSandboxResponse> {
        let request = request.into_inner();
        let _ = self
            .seen
            .send((self.generation, "create", request.from_checkpoint.clone()));
        let drop_now = self.drop_in_create.lock().unwrap().take();
        if let Some(drop_now) = drop_now {
            let _ = drop_now.send(());
            std::future::pending::<()>().await;
        }
        Ok(tonic::Response::new(pb::CreateSandboxResponse {
            sandbox: Some(pb::Sandbox {
                id: format!("sb-000000000000000{}", self.generation),
                from_checkpoint: if self.honors_checkpoint {
                    request.from_checkpoint
                } else {
                    String::new()
                },
                ..Default::default()
            }),
        }))
    }

    async fn delete_sandbox(
        &self,
        _: tonic::Request<pb::DeleteSandboxRequest>,
    ) -> Reply<pb::DeleteSandboxResponse> {
        let _ = self.seen.send((self.generation, "delete", String::new()));
        unused()
    }

    async fn get_sandbox(
        &self,
        _: tonic::Request<pb::GetSandboxRequest>,
    ) -> Reply<pb::GetSandboxResponse> {
        unused()
    }
    async fn list_sandboxes(
        &self,
        _: tonic::Request<pb::ListSandboxesRequest>,
    ) -> Reply<pb::ListSandboxesResponse> {
        unused()
    }
    async fn renew_sandbox(
        &self,
        _: tonic::Request<pb::RenewSandboxRequest>,
    ) -> Reply<pb::RenewSandboxResponse> {
        unused()
    }
    async fn exec(&self, _: tonic::Request<pb::ExecRequest>) -> Reply<pb::ExecResponse> {
        let _ = self.seen.send((self.generation, "exec", String::new()));
        let drop_now = self.drop_in_exec.lock().unwrap().take();
        if let Some(drop_now) = drop_now {
            let _ = drop_now.send(());
            std::future::pending::<()>().await;
        }
        unused()
    }
    async fn get_execution(
        &self,
        _: tonic::Request<pb::GetExecutionRequest>,
    ) -> Reply<pb::GetExecutionResponse> {
        unused()
    }
    async fn checkpoint_sandbox(
        &self,
        _: tonic::Request<pb::CheckpointSandboxRequest>,
    ) -> Reply<pb::CheckpointSandboxResponse> {
        unused()
    }
    async fn get_checkpoint(
        &self,
        _: tonic::Request<pb::GetCheckpointRequest>,
    ) -> Reply<pb::GetCheckpointResponse> {
        unused()
    }
    async fn list_checkpoints(
        &self,
        _: tonic::Request<pb::ListCheckpointsRequest>,
    ) -> Reply<pb::ListCheckpointsResponse> {
        unused()
    }
    async fn delete_checkpoint(
        &self,
        _: tonic::Request<pb::DeleteCheckpointRequest>,
    ) -> Reply<pb::DeleteCheckpointResponse> {
        unused()
    }

    type ExecStreamStream =
        tokio_stream::wrappers::ReceiverStream<Result<pb::ExecStreamResponse, tonic::Status>>;

    async fn exec_stream(
        &self,
        _: tonic::Request<pb::ExecStreamRequest>,
    ) -> Reply<Self::ExecStreamStream> {
        unused()
    }
}

/// Scripted daemons behind one socket path, one per accepted connection in order, as
/// a restart would replace them. Connections beyond the script are counted and closed.
struct Socket {
    _dir: tempfile::TempDir,
    path: PathBuf,
    accepted: Arc<std::sync::atomic::AtomicUsize>,
    seen: mpsc::UnboundedReceiver<Seen>,
    acceptor: tokio::task::JoinHandle<()>,
}

impl Socket {
    /// `script(seen)` builds the daemons, each told where to report.
    fn serve(
        script: impl FnOnce(mpsc::UnboundedSender<Seen>) -> Vec<(Daemon, oneshot::Receiver<()>)>,
    ) -> Self {
        use std::sync::atomic::{AtomicUsize, Ordering};
        // Removed with the directory when the socket is dropped.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kilnd.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let (tx, seen) = mpsc::unbounded_channel();
        let mut daemons = script(tx).into_iter();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&accepted);
        let acceptor = tokio::spawn(async move {
            // tonic runs each connection in a task of its own, so the client's socket
            // is relayed to it by a task here: aborting the acceptor drops the relays
            // and with them every client connection, as a daemon's death would.
            let mut relays = tokio::task::JoinSet::new();
            loop {
                let Ok((mut client, _)) = listener.accept().await else {
                    return;
                };
                count.fetch_add(1, Ordering::SeqCst);
                let Some((daemon, stop)) = daemons.next() else {
                    drop(client);
                    continue;
                };
                let (mut relay, stream) = tokio::net::UnixStream::pair().unwrap();
                relays.spawn(async move {
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut relay).await;
                });
                tokio::spawn(async move {
                    let _ = tonic::transport::Server::builder()
                        .add_service(pb::kilnd_service_server::KilndServiceServer::new(daemon))
                        .serve_with_incoming_shutdown(
                            // One connection, and then no end: a finished incoming
                            // stream would shut the server down.
                            tokio_stream::StreamExt::chain(
                                tokio_stream::iter([Ok::<_, std::io::Error>(stream)]),
                                tokio_stream::pending(),
                            ),
                            async {
                                // A dropped sender never stops it.
                                if stop.await.is_err() {
                                    std::future::pending::<()>().await;
                                }
                            },
                        )
                        .await;
                });
            }
        });
        Self {
            _dir: dir,
            path,
            accepted,
            seen,
            acceptor,
        }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn seen(&mut self) -> Vec<Seen> {
        let mut all = Vec::new();
        while let Ok(s) = self.seen.try_recv() {
            all.push(s);
        }
        all
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        self.acceptor.abort();
    }
}

fn daemon(generation: usize, seen: &mpsc::UnboundedSender<Seen>) -> Daemon {
    Daemon {
        generation,
        advertises: true,
        honors_checkpoint: true,
        stop_after_health: Arc::default(),
        drop_in_create: Arc::default(),
        drop_in_exec: Arc::default(),
        seen: seen.clone(),
    }
}

const CHECKPOINT: &str = "cp-0123456789abcdef0123456789abcdef";

fn from_checkpoint() -> CreateArgs {
    let cli = Cli::try_parse_from(["kilndctl", "create", "--from-checkpoint", CHECKPOINT]).unwrap();
    let Command::Create(args) = cli.command else {
        panic!("not create");
    };
    args
}

/// The review's two-generation PoC through the public `create` path. Generation 1
/// advertises checkpoints, answers Health and is replaced at once by generation 2, an
/// older daemon that would ignore field 5 and make an empty sandbox. Create never
/// reaches generation 2: the command fails, saying nothing was sent, and no second
/// connection is ever made.
#[tokio::test]
async fn a_replaced_daemon_never_receives_a_checked_create() {
    let (stop_tx, stop_rx) = oneshot::channel();
    let mut socket = Socket::serve(|seen| {
        let first = Daemon {
            stop_after_health: Arc::new(Mutex::new(Some(stop_tx))),
            ..daemon(1, &seen)
        };
        let second = Daemon {
            advertises: false,
            honors_checkpoint: false,
            ..daemon(2, &seen)
        };
        vec![(first, stop_rx), (second, oneshot::channel().1)]
    });
    let mut client = connect(socket.path.clone()).await.unwrap();
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        create(&mut client, from_checkpoint()),
    )
    .await
    .expect("create finished")
    .expect_err("Create must not cross a reconnect")
    .to_string();
    // Give a reconnecting client every chance to reach generation 2.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let seen = socket.seen();
    assert!(
        !seen.iter().any(|(generation, ..)| *generation == 2),
        "generation 2 was reached: {seen:?}"
    );
    assert_eq!(seen, vec![(1, "health", String::new())]);
    assert_eq!(socket.accepted(), 1, "kilndctl dialed again");
    assert!(error.contains(LOST_UNSENT), "{error}");
}

/// The ordinary path: Health then Create on the one connection, the daemon honoring
/// the checkpoint.
#[tokio::test]
async fn health_then_create_share_one_connection() {
    let mut socket = Socket::serve(|seen| vec![(daemon(1, &seen), oneshot::channel().1)]);
    let mut client = connect(socket.path.clone()).await.unwrap();
    let sandbox = create(&mut client, from_checkpoint()).await.unwrap();
    assert_eq!(sandbox.id, "sb-0000000000000001");
    assert_eq!(sandbox.from_checkpoint, CHECKPOINT);
    assert_eq!(
        socket.seen(),
        vec![
            (1, "health", String::new()),
            (1, "create", CHECKPOINT.to_string())
        ]
    );
    assert_eq!(socket.accepted(), 1);
}

/// Defence in depth: a daemon that advertised checkpoints but answered Create with
/// another provenance (or none) fails the command, naming the sandbox, which is kept.
#[tokio::test]
async fn a_create_that_ignored_the_checkpoint_fails_and_keeps_the_sandbox() {
    let mut socket = Socket::serve(|seen| {
        let ignores = Daemon {
            honors_checkpoint: false,
            ..daemon(1, &seen)
        };
        vec![(ignores, oneshot::channel().1)]
    });
    let mut client = connect(socket.path.clone()).await.unwrap();
    let error = create(&mut client, from_checkpoint())
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("sb-0000000000000001") && error.contains("ignored --from-checkpoint"),
        "{error}"
    );
    assert!(error.contains("was not deleted"), "{error}");
    let seen = socket.seen();
    assert!(!seen.iter().any(|(_, rpc, _)| *rpc == "delete"), "{seen:?}");
}

/// A connection lost after Create was written: the outcome is unknown, and nothing is
/// retried.
#[tokio::test]
async fn a_connection_lost_after_create_was_sent_reports_an_unknown_outcome() {
    let (dropped_tx, dropped_rx) = oneshot::channel();
    let mut socket = Socket::serve(|seen| {
        let first = Daemon {
            drop_in_create: Arc::new(Mutex::new(Some(dropped_tx))),
            ..daemon(1, &seen)
        };
        vec![
            (first, oneshot::channel().1),
            (daemon(2, &seen), oneshot::channel().1),
        ]
    });
    let mut client = connect(socket.path.clone()).await.unwrap();
    // Model the daemon dying mid-request: once Create arrives, every connection closes.
    let acceptor = std::mem::replace(&mut socket.acceptor, tokio::spawn(async {}));
    let killer = tokio::spawn(async move {
        let _ = dropped_rx.await;
        acceptor.abort();
    });
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        create(&mut client, from_checkpoint()),
    )
    .await
    .expect("create finished")
    .unwrap_err()
    .to_string();
    killer.await.unwrap();
    assert!(error.contains(LOST_UNKNOWN), "{error}");
    let seen = socket.seen();
    assert_eq!(
        seen.iter().filter(|(_, rpc, _)| *rpc == "create").count(),
        1,
        "{seen:?}"
    );
    assert_eq!(socket.accepted(), 1);
}

/// `run` with the daemon gone once Exec arrived (C5b-2 recheck MEDIUM): Exec's outcome
/// is unknown and stays the reported error. The cleanup Delete finds the connection
/// closed; its failure follows on a line of its own, naming the sandbox, and nothing
/// claims the command was never sent.
#[tokio::test]
async fn run_keeps_an_unknown_exec_outcome_when_cleanup_finds_the_connection_lost() {
    let (dropped_tx, dropped_rx) = oneshot::channel();
    let mut socket = Socket::serve(|seen| {
        let first = Daemon {
            drop_in_exec: Arc::new(Mutex::new(Some(dropped_tx))),
            ..daemon(1, &seen)
        };
        vec![
            (first, oneshot::channel().1),
            (daemon(2, &seen), oneshot::channel().1),
        ]
    });
    let cli = Cli::try_parse_from([
        "kilndctl",
        "--socket",
        socket.path.to_str().unwrap(),
        "run",
        "--",
        "/bin/true",
    ])
    .unwrap();
    // Once Exec arrives, model a daemon exit that closes the connection.
    let acceptor = std::mem::replace(&mut socket.acceptor, tokio::spawn(async {}));
    let killer = tokio::spawn(async move {
        let _ = dropped_rx.await;
        acceptor.abort();
    });
    let error = tokio::time::timeout(Duration::from_secs(5), run(cli))
        .await
        .expect("run finished")
        .unwrap_err();
    let error = format!("{error:#}");
    killer.await.unwrap();
    let seen = socket.seen();
    assert_eq!(
        seen,
        vec![(1, "create", String::new()), (1, "exec", String::new())]
    );
    assert_eq!(socket.accepted(), 1, "kilndctl dialed again");
    assert!(!error.contains("nothing was sent"), "{error}");
    let (primary, cleanup) = error.split_once('\n').expect("a cleanup line");
    assert!(primary.contains(LOST_UNKNOWN), "{error}");
    assert!(
        cleanup.contains("sb-0000000000000001")
            && cleanup.contains("before Delete was sent")
            && cleanup.contains("kilndctl rm sb-0000000000000001"),
        "{error}"
    );
}
