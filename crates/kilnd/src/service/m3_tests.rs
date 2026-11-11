//! API additions M3b at the gRPC boundary (design 4, 4.2 and 8): cwd and env round
//! trips, ApiLimits, typed refusals, and the secret canary. A value sent as
//! default_env or env must never appear in a response other than the command's own
//! output, in `Debug`, in a log line (tests/exec_env_canary.rs), or in any logical
//! store column but
//! `sandboxes.default_env` while its sandbox is live (L1: SQL only; WAL and free pages
//! are deliberately not checked, and this design promises no byte erasure).

use std::sync::Arc;

use pb::kilnd_service_server::KilndService;
use prost::Message;

use super::*;
use crate::admission::ConnectionLane;
use crate::expiry::ManualClock;
use crate::manager::{Feature, Limits};
use crate::runtime::fake::FakeRuntime;
use crate::store::Store;

const DEFAULT_CANARY: &str = "CANARY-default-7f3a9c";
const EXEC_CANARY: &str = "CANARY-exec-91be20";

fn as_uid<T>(message: T, uid: u32) -> Request<T> {
    let mut request = Request::new(message);
    request.extensions_mut().insert(PeerIdentity {
        uid: Some(uid),
        lane: ConnectionLane::General,
    });
    request
}

fn reason(status: &Status) -> Option<&str> {
    status
        .metadata()
        .get(REASON_KEY)
        .map(|v| v.to_str().unwrap())
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

async fn service(proven: bool) -> (FakeRuntime, Arc<Manager<FakeRuntime>>, Service<FakeRuntime>) {
    let fake = FakeRuntime::default();
    if proven {
        fake.state().proven_features = Ok(vec![
            Feature::ExecCwd,
            Feature::ExecEnv,
            Feature::SandboxDefaultEnv,
        ]);
    }
    let manager = Arc::new(Manager::with_clock(
        fake.clone(),
        Store::open_in_memory().unwrap(),
        Limits {
            max_node_memory_bytes: 1 << 40,
            ..Limits::default()
        },
        Arc::new(ManualClock::default()),
    ));
    let s = Service::new(manager.clone());
    s.health(as_uid(pb::HealthRequest {}, 1000)).await.unwrap();
    (fake, manager, s)
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

#[tokio::test]
async fn health_lists_option_features_and_their_limits_only_when_proven() {
    let (_, _, s) = service(false).await;
    let h = s
        .health(as_uid(pb::HealthRequest {}, 1000))
        .await
        .unwrap()
        .into_inner();
    let caps = h.runtime_capabilities.unwrap();
    assert!(!caps.features.contains(&(pb::Feature::ExecEnv as i32)));
    let limits = caps.limits.unwrap();
    assert_eq!(
        (
            limits.max_cwd_bytes,
            limits.max_env_entries,
            limits.max_env_total_bytes
        ),
        (0, 0, 0)
    );
    let (_, _, s) = service(true).await;
    let h = s
        .health(as_uid(pb::HealthRequest {}, 1000))
        .await
        .unwrap()
        .into_inner();
    let caps = h.runtime_capabilities.unwrap();
    for f in [
        pb::Feature::ExecCwd,
        pb::Feature::ExecEnv,
        pb::Feature::SandboxDefaultEnv,
    ] {
        assert!(caps.features.contains(&(f as i32)), "{f:?}");
    }
    let limits = caps.limits.unwrap();
    assert_eq!(
        (
            limits.max_cwd_bytes,
            limits.max_env_entries,
            limits.max_env_name_bytes,
            limits.max_env_value_bytes,
            limits.max_env_total_bytes
        ),
        (4096, 64, 128, 4096, 32_768)
    );
}

#[tokio::test]
async fn refusals_are_typed_with_their_codes() {
    let (_, manager, s) = service(false).await;
    let refused = s
        .create_sandbox(as_uid(
            pb::CreateSandboxRequest {
                default_env: env(&[("A", "1")]),
                ..Default::default()
            },
            1000,
        ))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::Unimplemented);
    assert_eq!(
        reason(&refused),
        Some("backend_unsupported:sandbox_default_env")
    );
    assert!(
        refused
            .message()
            .starts_with("backend_unsupported:sandbox_default_env: ")
    );
    let sandbox = s
        .create_sandbox(as_uid(pb::CreateSandboxRequest::default(), 1000))
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    let refused = s
        .exec(as_uid(
            pb::ExecRequest {
                sandbox_id: sandbox.id.clone(),
                argv: vec!["true".into()],
                cwd: "/w".into(),
                ..Default::default()
            },
            1000,
        ))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::Unimplemented);
    assert_eq!(reason(&refused), Some("backend_unsupported:exec_cwd"));
    // execution_start_raced shares sandbox_not_ready's code.
    manager
        .store_for_test()
        .lose_execution_starts
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let raced = s
        .exec(as_uid(
            pb::ExecRequest {
                sandbox_id: sandbox.id.clone(),
                argv: vec!["true".into()],
                ..Default::default()
            },
            1000,
        ))
        .await
        .unwrap_err();
    assert_eq!(raced.code(), tonic::Code::FailedPrecondition);
    assert_eq!(reason(&raced), Some("execution_start_raced"));
}

#[tokio::test]
async fn cwd_failures_round_trip_as_runtime_stage_cwd() {
    let (_, _, s) = service(true).await;
    let sandbox = s
        .create_sandbox(as_uid(pb::CreateSandboxRequest::default(), 1000))
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    let e = s
        .exec(as_uid(
            pb::ExecRequest {
                sandbox_id: sandbox.id,
                argv: vec!["pwd".into()],
                cwd: "/missing".into(),
                ..Default::default()
            },
            1000,
        ))
        .await
        .unwrap()
        .into_inner()
        .execution
        .unwrap();
    assert_eq!(e.state, pb::ExecutionState::Failed as i32);
    let d = e.runtime_error.unwrap();
    assert_eq!(d.kind, pb::RuntimeErrorKind::LaunchFailed as i32);
    assert_eq!(d.stage, pb::RuntimeStage::Cwd as i32);
    assert_eq!(d.native_code.as_deref(), Some("ENOENT"));
    assert!(e.failure_reason.starts_with("cwd_not_found"));
    assert_eq!(e.cwd, "/missing");
    assert_eq!(e.sandbox_reusable, Some(true));
}

#[tokio::test]
async fn secret_canaries_never_leave_their_documented_column() {
    let (fake, manager, s) = service(true).await;
    let store = manager.store_for_test();
    let mut responses: Vec<(String, Vec<u8>)> = Vec::new();
    let mut record = |what: &str, bytes: Vec<u8>, debug: String| {
        responses.push((what.to_string(), bytes));
        responses.push((format!("{what} Debug"), debug.into_bytes()));
    };

    let create = pb::CreateSandboxRequest {
        request_id: "canary-create".into(),
        default_env: env(&[("API_TOKEN", DEFAULT_CANARY), ("PATH", "/opt/bin:/usr/bin")]),
        ..Default::default()
    };
    // The manager's own request types redact values.
    let converted = create_request(
        create.spec.clone().unwrap_or_default(),
        None,
        create.default_env.clone(),
    )
    .unwrap();
    assert_clean("CreateRequest Debug", format!("{converted:?}").as_bytes());
    let created = s
        .create_sandbox(as_uid(create.clone(), 1000))
        .await
        .unwrap()
        .into_inner();
    record(
        "CreateSandbox",
        created.encode_to_vec(),
        format!("{created:?}"),
    );
    let sandbox = created.sandbox.unwrap();
    assert_eq!(sandbox.default_env_names, ["API_TOKEN", "PATH"]);
    assert_eq!(sandbox.default_env_sha256.len(), 64);
    // A keyed retry answers the same row; its digest covers the values, not a copy.
    let retry = s
        .create_sandbox(as_uid(create, 1000))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(retry.sandbox.as_ref().unwrap().id, sandbox.id);
    record(
        "CreateSandbox retry",
        retry.encode_to_vec(),
        format!("{retry:?}"),
    );
    // While live, the default value is in sandboxes.default_env and nowhere else.
    assert_eq!(
        store.columns_containing_for_test(DEFAULT_CANARY.as_bytes()),
        ["sandboxes.default_env"]
    );

    let exec = |argv: &[&str], cwd: &str, pairs: &[(&str, &str)]| pb::ExecRequest {
        sandbox_id: sandbox.id.clone(),
        argv: argv.iter().map(|a| a.to_string()).collect(),
        cwd: cwd.into(),
        env: env(pairs),
        ..Default::default()
    };
    for (argv, cwd) in [(&["true"][..], "/workspace"), (&["pwd"], "/missing")] {
        let request = exec(argv, cwd, &[("SESSION", EXEC_CANARY), ("MODE", "x")]);
        let converted = ExecRequest {
            sandbox_id: request.sandbox_id.clone(),
            argv: request.argv.clone(),
            stdin: vec![],
            timeout_ms: 0,
            cwd: request.cwd.clone(),
            env: env_vars(request.env.clone()),
        };
        assert_clean(
            "ExecRequest env Debug",
            format!("{:?}", converted.env).as_bytes(),
        );
        let response = s.exec(as_uid(request, 1000)).await.unwrap().into_inner();
        let e = response.execution.as_ref().unwrap();
        assert_eq!(e.env_names, ["API_TOKEN", "MODE", "PATH", "SESSION"]);
        assert_eq!(e.env_sha256.len(), 64);
        record("Exec", response.encode_to_vec(), format!("{response:?}"));
        let got = s
            .get_execution(as_uid(pb::GetExecutionRequest { id: e.id.clone() }, 1000))
            .await
            .unwrap()
            .into_inner();
        record("GetExecution", got.encode_to_vec(), format!("{got:?}"));
    }
    // The backend got the values, merged; that is the one place they go.
    let delivered = fake.state().exec_options[0].env.clone();
    assert!(delivered.iter().any(|e| e.value == EXEC_CANARY));
    assert!(delivered.iter().any(|e| e.value == DEFAULT_CANARY));
    assert_clean(
        "delivered options Debug",
        format!("{delivered:?}").as_bytes(),
    );
    // Invalid values are refused without being quoted.
    for bad in [format!("{EXEC_CANARY}\0"), EXEC_CANARY.repeat(300)] {
        let status = s
            .exec(as_uid(exec(&["true"], "", &[("SESSION", &bad)]), 1000))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        record(
            "invalid Exec",
            status.message().as_bytes().to_vec(),
            format!("{status:?}"),
        );
    }
    let status = s
        .exec(as_uid(exec(&["true"], "", &[(EXEC_CANARY, "x")]), 1000))
        .await
        .unwrap_err();
    record(
        "invalid name",
        status.message().as_bytes().to_vec(),
        format!("{status:?}"),
    );
    assert!(
        store
            .columns_containing_for_test(EXEC_CANARY.as_bytes())
            .is_empty()
    );

    let got = s
        .get_sandbox(as_uid(
            pb::GetSandboxRequest {
                id: sandbox.id.clone(),
                execution_limit: 100,
            },
            1000,
        ))
        .await
        .unwrap()
        .into_inner();
    record("GetSandbox", got.encode_to_vec(), format!("{got:?}"));
    let listed = s
        .list_sandboxes(as_uid(
            pb::ListSandboxesRequest {
                include_deleted: true,
                ..Default::default()
            },
            1000,
        ))
        .await
        .unwrap()
        .into_inner();
    record(
        "ListSandboxes",
        listed.encode_to_vec(),
        format!("{listed:?}"),
    );
    let health = s
        .health(as_uid(pb::HealthRequest {}, 1000))
        .await
        .unwrap()
        .into_inner();
    record("Health", health.encode_to_vec(), format!("{health:?}"));
    let deleted = s
        .delete_sandbox(as_uid(
            pb::DeleteSandboxRequest {
                id: sandbox.id.clone(),
                ..Default::default()
            },
            1000,
        ))
        .await
        .unwrap()
        .into_inner();
    record(
        "DeleteSandbox",
        deleted.encode_to_vec(),
        format!("{deleted:?}"),
    );
    let after = s
        .get_sandbox(as_uid(
            pb::GetSandboxRequest {
                id: sandbox.id.clone(),
                execution_limit: 100,
            },
            1000,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        after.sandbox.as_ref().unwrap().default_env_names,
        ["API_TOKEN", "PATH"]
    );
    record(
        "GetSandbox after delete",
        after.encode_to_vec(),
        format!("{after:?}"),
    );

    for (what, bytes) in &responses {
        assert_clean(what, bytes);
    }
    // After DELETED, no logical column holds either value.
    for canary in [DEFAULT_CANARY, EXEC_CANARY] {
        assert!(
            store
                .columns_containing_for_test(canary.as_bytes())
                .is_empty(),
            "{canary}"
        );
    }
    // Log lines are checked in tests/exec_env_canary.rs, under a process-wide
    // subscriber that tests running in parallel cannot race.
}
