//! API additions M3b (design 4.2, 8 and L1): a secret-looking value sent as a
//! sandbox's default_env and as an Exec's env, over the real socket, never appears in a
//! log line, in a response other than the command's own output, or in any logical
//! column of the database file except `sandboxes.default_env` while its sandbox is
//! live. One test in its own binary, so its process-wide log subscriber sees every
//! line the daemon writes and no parallel test can race its installation. WAL and
//! free pages are deliberately not read: the design promises no byte erasure.
// Approved (design 7.1): test fixtures, an integration-test crate. They create and
// remove their own scratch directories directly.
#![allow(clippy::disallowed_methods)]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use kilnd::manager::{Feature, Limits, Manager};
use kilnd::runtime::fake::FakeRuntime;
use kilnd::store::Store;
use kilnd_api::v1 as pb;
use pb::kilnd_service_client::KilndServiceClient;
use prost::Message;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

const DEFAULT_CANARY: &str = "CANARY-default-c0ffee";
const EXEC_CANARY: &str = "CANARY-exec-5eed42";

#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl Write for Logs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

fn assert_clean(what: &str, bytes: &[u8]) {
    for canary in [DEFAULT_CANARY, EXEC_CANARY] {
        assert!(!contains(bytes, canary), "{what} contains {canary}");
    }
}

async fn client(path: PathBuf) -> KilndServiceClient<Channel> {
    let channel = Endpoint::try_from("http://kilnd.invalid")
        .unwrap()
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?)) }
        }))
        .await
        .unwrap();
    KilndServiceClient::new(channel)
}

fn env(pairs: &[(&str, &str)]) -> Vec<pb::EnvVar> {
    pairs
        .iter()
        .map(|(n, v)| pb::EnvVar {
            name: n.to_string(),
            value: v.to_string(),
        })
        .collect()
}

/// Every `table.column` in the database file whose text or bytes contain `needle`,
/// with the row's `id` where the table has one.
fn columns_containing(db: &Path, needle: &str) -> Vec<String> {
    let conn =
        rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    let mut hits = Vec::new();
    for table in tables {
        let mut stmt = conn.prepare(&format!("SELECT * FROM \"{table}\"")).unwrap();
        let columns: Vec<String> = stmt.column_names().iter().map(|c| c.to_string()).collect();
        let id = columns.iter().position(|c| c == "id");
        let mut rows = stmt.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            let row_id = id
                .and_then(|i| row.get::<_, String>(i).ok())
                .map(|id| format!(" {id}"))
                .unwrap_or_default();
            for (i, column) in columns.iter().enumerate() {
                if let rusqlite::types::ValueRef::Text(b) | rusqlite::types::ValueRef::Blob(b) =
                    row.get_ref(i).unwrap()
                    && contains(b, needle)
                {
                    hits.push(format!("{table}.{column}{row_id}"));
                }
            }
        }
    }
    hits.sort();
    hits.dedup();
    hits
}

#[tokio::test]
async fn secret_values_stay_out_of_logs_responses_and_history() {
    let logs = Logs::default();
    let writer = logs.clone();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish(),
    )
    .unwrap();

    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = tmp.path().join("run/kilnd.sock");
    let state = tmp.path().join("state");
    let db = state.join("kilnd.db");
    let fake = FakeRuntime::default();
    fake.state().proven_features = Ok(vec![
        Feature::ExecCwd,
        Feature::ExecEnv,
        Feature::SandboxDefaultEnv,
    ]);
    let manager = Arc::new(Manager::new(
        fake.clone(),
        Store::open(&state).unwrap(),
        Limits::default(),
    ));
    let listener = kilnd::server::bind(&socket, None).await.unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(kilnd::server::serve(
        manager,
        listener,
        async {
            let _ = stop_rx.await;
        },
        Duration::from_millis(200),
    ));
    let mut c = client(socket).await;
    let mut seen: Vec<(String, Vec<u8>)> = Vec::new();

    let health = c.health(pb::HealthRequest {}).await.unwrap().into_inner();
    let features = &health.runtime_capabilities.as_ref().unwrap().features;
    assert!(features.contains(&(pb::Feature::SandboxDefaultEnv as i32)));
    let sandbox = c
        .create_sandbox(pb::CreateSandboxRequest {
            request_id: "canary".into(),
            default_env: env(&[("API_TOKEN", DEFAULT_CANARY)]),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    seen.push(("CreateSandbox".into(), sandbox.encode_to_vec()));
    let sandbox = sandbox.sandbox.unwrap();
    assert_eq!(
        columns_containing(&db, DEFAULT_CANARY),
        ["sandboxes.default_env ".to_string() + &sandbox.id]
    );

    let mut execution_ids = Vec::new();
    for (argv, cwd) in [("true", "/workspace"), ("pwd", "/missing"), ("env", "")] {
        let response = c
            .exec(pb::ExecRequest {
                sandbox_id: sandbox.id.clone(),
                argv: vec![argv.into()],
                cwd: cwd.into(),
                env: env(&[("SESSION", EXEC_CANARY)]),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        let e = response.execution.clone().unwrap();
        execution_ids.push(e.id.clone());
        if argv == "env" {
            // The workload's own output carries the values: that is what it asked
            // for, and the one place they may appear.
            let out = e.stdout.as_ref().unwrap();
            assert!(contains(&out.data, EXEC_CANARY) && contains(&out.data, DEFAULT_CANARY));
            let mut scrubbed = e.clone();
            scrubbed.stdout = None;
            seen.push(("Exec env (output removed)".into(), scrubbed.encode_to_vec()));
        } else {
            seen.push((format!("Exec {argv}"), response.encode_to_vec()));
        }
    }
    let invalid = c
        .exec(pb::ExecRequest {
            sandbox_id: sandbox.id.clone(),
            argv: vec!["true".into()],
            env: env(&[("SESSION", &format!("{EXEC_CANARY}\0"))]),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(invalid.code(), tonic::Code::InvalidArgument);
    seen.push(("invalid Exec".into(), invalid.message().as_bytes().to_vec()));
    // Only the `env` command's own retained output holds the value (the design's
    // exclusion: workload output that echoes it is the workload's).
    let echoed = format!("executions.stdout {}", execution_ids[2]);
    assert_eq!(columns_containing(&db, EXEC_CANARY), std::slice::from_ref(&echoed));
    assert_eq!(
        columns_containing(&db, DEFAULT_CANARY),
        [
            echoed.clone(),
            "sandboxes.default_env ".to_string() + &sandbox.id
        ]
    );

    for id in &execution_ids {
        let got = c
            .get_execution(pb::GetExecutionRequest { id: id.clone() })
            .await
            .unwrap()
            .into_inner();
        let mut got = got.execution.unwrap();
        if got.argv == ["env"] {
            got.stdout = None;
        }
        seen.push(("GetExecution".into(), got.encode_to_vec()));
    }
    let listed = c
        .list_sandboxes(pb::ListSandboxesRequest {
            include_deleted: true,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    seen.push(("ListSandboxes".into(), listed.encode_to_vec()));
    let deleted = c
        .delete_sandbox(pb::DeleteSandboxRequest {
            id: sandbox.id.clone(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    seen.push(("DeleteSandbox".into(), deleted.encode_to_vec()));
    let got = c
        .get_sandbox(pb::GetSandboxRequest {
            id: sandbox.id.clone(),
            execution_limit: 100,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        got.sandbox.as_ref().unwrap().default_env_names,
        ["API_TOKEN"]
    );
    for e in &got.recent_executions {
        assert_eq!(e.env_names, ["API_TOKEN", "SESSION"]);
    }
    seen.push(("GetSandbox after delete".into(), got.encode_to_vec()));
    drop(c);
    stop_tx.send(()).unwrap();
    server.await.unwrap().unwrap();

    for (what, bytes) in &seen {
        assert_clean(what, bytes);
    }
    // After DELETED, the default is cleared: only that same output row remains.
    for canary in [DEFAULT_CANARY, EXEC_CANARY] {
        assert_eq!(
            columns_containing(&db, canary),
            std::slice::from_ref(&echoed),
            "{canary}"
        );
    }
    let logs = logs.0.lock().unwrap().clone();
    for line in [
        "creating sandbox",
        "exec started",
        "exec finished",
        "sandbox deleted",
    ] {
        assert!(contains(&logs, line), "the capture missed {line:?}");
    }
    assert_clean("logs", &logs);
}
