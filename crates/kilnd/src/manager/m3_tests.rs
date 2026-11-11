//! API additions M3b (design sections 4, 6 and 8): exec cwd and env, a sandbox's
//! default env, the feature and sandbox gates, history's names and hash, and the
//! retryable execution_start_raced refusal, driven by the fake runtime.

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::exec_env::{EnvVar, env_sha256};
use crate::expiry::ManualClock;
use crate::runtime::fake::{FakeEvidenceMode, FakeRuntime};

const OPTION_FEATURES: [Feature; 3] = [
    Feature::ExecCwd,
    Feature::ExecEnv,
    Feature::SandboxDefaultEnv,
];

fn limits() -> Limits {
    Limits {
        max_node_memory_bytes: 1 << 40,
        max_node_pids: 1 << 20,
        max_node_disk_bytes: 1 << 50,
        health_success_cache: Duration::from_millis(1),
        health_failure_cache: Duration::from_millis(1),
        ..Limits::default()
    }
}

fn manager_on(fake: FakeRuntime, limits: Limits) -> Arc<Manager<FakeRuntime>> {
    Arc::new(Manager::with_clock(
        fake,
        Store::open_in_memory().unwrap(),
        limits,
        Arc::new(ManualClock::default()),
    ))
}

/// A manager whose backend has proven exec options in a Health probe.
async fn proven_with(limits: Limits) -> (Arc<Manager<FakeRuntime>>, FakeRuntime) {
    let fake = FakeRuntime::default();
    fake.state().proven_features = Ok(OPTION_FEATURES.to_vec());
    let m = manager_on(fake.clone(), limits);
    assert!(m.health().await.unwrap().serving);
    for feature in OPTION_FEATURES {
        assert!(m.has_feature(feature));
    }
    (m, fake)
}

async fn proven() -> (Arc<Manager<FakeRuntime>>, FakeRuntime) {
    proven_with(limits()).await
}

fn env(pairs: &[(&str, &str)]) -> Vec<EnvVar> {
    pairs.iter().map(|(n, v)| EnvVar::new(*n, *v)).collect()
}

fn with_default_env(pairs: &[(&str, &str)]) -> CreateRequest {
    CreateRequest {
        default_env: env(pairs),
        ..CreateRequest::default()
    }
}

fn exec_req(id: &str, argv: &[&str], cwd: &str, pairs: &[(&str, &str)]) -> ExecRequest {
    ExecRequest {
        sandbox_id: id.into(),
        argv: argv.iter().map(|s| s.to_string()).collect(),
        stdin: vec![],
        timeout_ms: 0,
        cwd: cwd.into(),
        env: env(pairs),
    }
}

fn reason(error: &Error) -> Option<&'static str> {
    match error {
        Error::FailedPrecondition(r) | Error::Refused(_, r) => r.reason(),
        _ => None,
    }
}

fn execution_rows(m: &Manager<FakeRuntime>) -> i64 {
    m.store
        .query_for_test("SELECT count(*) FROM executions", [])
        .unwrap()
}

fn sandbox_rows(m: &Manager<FakeRuntime>) -> i64 {
    m.store
        .query_for_test("SELECT count(*) FROM sandboxes", [])
        .unwrap()
}

fn stored_default_env(m: &Manager<FakeRuntime>, id: &str) -> Option<String> {
    m.store
        .query_for_test("SELECT default_env FROM sandboxes WHERE id = ?1", [id])
        .unwrap()
}

/// Nothing allocated (design 8): no new execution row, no ticket, no backend call.
fn assert_nothing_ran(m: &Manager<FakeRuntime>, fake: &FakeRuntime, rows_before: i64) {
    assert_eq!(execution_rows(m), rows_before);
    assert_eq!(m.admission.snapshot().execs.current, 0);
    assert!(fake.state().exec_calls.is_empty());
}

#[tokio::test]
async fn options_reach_the_backend_merged_and_history_keeps_names_and_hash() {
    let (m, fake) = proven().await;
    let sandbox = m
        .create(with_default_env(&[
            ("PATH", "/opt/bin"),
            ("MODE", "d"),
            ("Z", "z"),
        ]))
        .await
        .unwrap();
    assert_eq!(sandbox.lifecycle.default_env_names, ["MODE", "PATH", "Z"]);
    assert_eq!(
        sandbox.lifecycle.default_env_sha256,
        env_sha256(&env(&[("PATH", "/opt/bin"), ("MODE", "d"), ("Z", "z")]))
    );
    assert_eq!(sandbox.lifecycle.exec_features, Some(0x3f));
    let e = m
        .exec(exec_req(
            &sandbox.id,
            &["env"],
            "/workspace",
            &[("MODE", "r"), ("A", "")],
        ))
        .await
        .unwrap();
    assert_eq!(e.state, ExecutionState::Exited);
    // The request wins by name; the merge is sorted by name bytes.
    let effective = env(&[("A", ""), ("MODE", "r"), ("PATH", "/opt/bin"), ("Z", "z")]);
    assert_eq!(
        fake.state().exec_options,
        [crate::exec_env::ExecOptions {
            cwd: Some("/workspace".into()),
            env: effective.clone(),
        }]
    );
    // The fake prints kiln's operation 5 environment: base overlaid by the overrides.
    assert_eq!(
        String::from_utf8(e.stdout.data.clone()).unwrap(),
        "A=\nHOME=/root\nMODE=r\nPATH=/opt/bin\nTERM=xterm\nZ=z\n"
    );
    assert_eq!(e.cwd.as_deref(), Some("/workspace"));
    assert_eq!(e.env_names, ["A", "MODE", "PATH", "Z"]);
    assert_eq!(e.env_sha256, env_sha256(&effective));
    let stored = m.execution(&e.id).unwrap();
    assert_eq!(
        (&stored.cwd, &stored.env_names, &stored.env_sha256),
        (&e.cwd, &e.env_names, &e.env_sha256)
    );
    // Defaults apply with no request options at all.
    let plain = m
        .exec(exec_req(&sandbox.id, &["env"], "", &[]))
        .await
        .unwrap();
    assert_eq!(plain.cwd, None);
    assert_eq!(plain.env_names, ["MODE", "PATH", "Z"]);
    assert_eq!(plain.env_sha256, sandbox.lifecycle.default_env_sha256);
}

#[tokio::test]
async fn an_empty_request_on_a_sandbox_without_defaults_is_todays_operation_4() {
    let (m, fake) = proven().await;
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    assert!(sandbox.lifecycle.default_env_names.is_empty());
    let e = m
        .exec(exec_req(&sandbox.id, &["env"], "", &[]))
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8(e.stdout.data.clone()).unwrap(),
        "HOME=/root\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nTERM=xterm\n"
    );
    assert!(fake.state().exec_options[0].is_empty());
    assert_eq!((e.cwd, e.env_names, e.env_sha256), (None, vec![], None));
    // So is one on a backend with no exec options at all, with no gate in the way.
    let fake = FakeRuntime::default();
    let m = manager_on(fake.clone(), limits());
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    m.exec(exec_req(&sandbox.id, &["echo", "x"], "", &[]))
        .await
        .unwrap();
    assert!(fake.state().exec_options[0].is_empty());
}

#[tokio::test]
async fn unproven_options_are_refused_first_in_feature_order_with_nothing_allocated() {
    // No Health probe has proven anything yet: the dynamic set starts empty.
    let fake = FakeRuntime::default();
    fake.state().proven_features = Ok(OPTION_FEATURES.to_vec());
    let m = manager_on(fake.clone(), limits());
    let created_before = fake.state().created.len();
    let error = m.create(with_default_env(&[("A", "1")])).await.unwrap_err();
    assert!(
        matches!(error, Error::Refused(RefusalCode::Unimplemented, _)),
        "{error:?}"
    );
    assert_eq!(
        reason(&error),
        Some("backend_unsupported:sandbox_default_env")
    );
    assert_eq!(sandbox_rows(&m), 0);
    assert_eq!(fake.state().created.len(), created_before);
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    for (cwd, pairs, expected) in [
        ("/w", &[("A", "1")][..], "backend_unsupported:exec_cwd"),
        ("/w", &[], "backend_unsupported:exec_cwd"),
        ("", &[("A", "1")], "backend_unsupported:exec_env"),
        // Even an invalid value is refused by the gate, not by validation.
        ("relative", &[("1A", "x")], "backend_unsupported:exec_cwd"),
    ] {
        let error = m
            .exec(exec_req(&sandbox.id, &["true"], cwd, pairs))
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::Refused(RefusalCode::Unimplemented, _)),
            "{error:?}"
        );
        assert_eq!(reason(&error), Some(expected));
        assert_nothing_ran(&m, &fake, 0);
    }
    // A fresh probe proves them; a failed one withdraws them and the gates follow.
    m.health().await.unwrap();
    m.exec(exec_req(&sandbox.id, &["true"], "/w", &[]))
        .await
        .unwrap();
    fake.state().proven_features = Err("older kiln".into());
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert!(!m.health().await.unwrap().serving);
    let error = m
        .exec(exec_req(&sandbox.id, &["true"], "/w", &[]))
        .await
        .unwrap_err();
    assert_eq!(reason(&error), Some("backend_unsupported:exec_cwd"));
}

#[tokio::test]
async fn an_operator_downgrade_never_runs_without_the_defaults() {
    let (m, fake) = proven().await;
    let sandbox = m.create(with_default_env(&[("A", "1")])).await.unwrap();
    // The installed CLI lost exec options: Health withdraws them, and even a plain
    // Exec on a sandbox with default env is refused, not run without it.
    fake.state().proven_features = Ok(Vec::new());
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert!(m.health().await.unwrap().serving);
    let error = m
        .exec(exec_req(&sandbox.id, &["true"], "", &[]))
        .await
        .unwrap_err();
    assert_eq!(reason(&error), Some("backend_unsupported:exec_env"));
    assert_nothing_ran(&m, &fake, 0);
}

#[tokio::test]
async fn a_sandbox_without_the_exec_options_bit_is_refused_before_any_row() {
    let (m, fake) = proven().await;
    for recorded in [Some(0x1f), None] {
        fake.state().create_exec_features = recorded;
        let sandbox = m.create(CreateRequest::default()).await.unwrap();
        assert_eq!(sandbox.lifecycle.exec_features, recorded);
        for (cwd, pairs, expected) in [
            ("/w", &[("A", "1")][..], "sandbox_unsupported:exec_cwd"),
            ("", &[("A", "1")], "sandbox_unsupported:exec_env"),
        ] {
            let error = m
                .exec(exec_req(&sandbox.id, &["true"], cwd, pairs))
                .await
                .unwrap_err();
            assert!(matches!(error, Error::FailedPrecondition(_)), "{error:?}");
            assert_eq!(reason(&error), Some(expected));
            assert_nothing_ran(&m, &fake, 0);
        }
        // Plain Exec still works on it, exactly as before.
        m.exec(exec_req(&sandbox.id, &["true"], "", &[]))
            .await
            .unwrap();
        fake.state().exec_calls.clear();
        m.store
            .execute_for_test("DELETE FROM executions WHERE sandbox_id = ?1", &sandbox.id)
            .unwrap();
    }
    // A sandbox with defaults whose runtime lacks the bit is never READY (break-it
    // M3b MEDIUM)...
    fake.state().create_exec_features = Some(0x1f);
    let error = m.create(with_default_env(&[("A", "1")])).await.unwrap_err();
    assert_eq!(reason(&error), Some("sandbox_feature_probe_failed"));
    // ...and a row that somehow had defaults without the bit would refuse every Exec.
    // (The store records the bits once, so the row is altered in memory only.)
    fake.state().create_exec_features = Some(0x3f);
    let mut sandbox = m.create(with_default_env(&[("A", "1")])).await.unwrap();
    sandbox.lifecycle.exec_features = Some(0x1f);
    let Err(error) = m.resolve_exec_options(&exec_req(&sandbox.id, &["true"], "", &[]), &sandbox)
    else {
        panic!("options resolved for a sandbox without bit 0x20");
    };
    assert_eq!(reason(&error), Some("sandbox_unsupported:exec_env"));
}

#[tokio::test]
async fn every_bound_one_past_it_and_lowered_flags_are_invalid_arguments() {
    let (m, fake) = proven_with(Limits {
        max_exec_cwd_bytes: 8,
        exec_env: crate::exec_env::EnvLimits {
            max_entries: 2,
            max_name_bytes: 4,
            max_value_bytes: 4,
            max_total_bytes: 16,
        },
        ..limits()
    })
    .await;
    let sandbox = m
        .create(with_default_env(&[("D1", "dd"), ("D2", "dd")]))
        .await
        .unwrap();
    m.exec(exec_req(
        &sandbox.id,
        &["true"],
        "/1234567",
        &[("D1", "xxxx")],
    ))
    .await
    .unwrap();
    for (cwd, pairs) in [
        ("/12345678", &[][..]),
        ("w", &[]),
        ("/a\0", &[]),
        ("", &[("NAME5", "")]),
        ("", &[("A", "12345")]),
        ("", &[("A", "1"), ("A", "1")]),
        ("", &[("1A", "")]),
        ("", &[("A", "\0")]),
        // Valid alone, but the merge has three entries.
        ("", &[("A", "")]),
        ("", &[("A", ""), ("B", ""), ("C", "")]),
    ] {
        let error = m
            .exec(exec_req(&sandbox.id, &["true"], cwd, pairs))
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::InvalidArgument(_)),
            "{cwd:?} {pairs:?}: {error:?}"
        );
    }
    assert_eq!(fake.state().exec_calls.len(), 1);
    // The same bounds apply to a create's default env, before any row.
    let rows = sandbox_rows(&m);
    for pairs in [
        &[("A", ""), ("B", ""), ("C", "")][..],
        &[("NAME5", "")],
        &[("A", "12345")],
        &[("A", ""), ("A", "")],
        &[("ABCD", "1234"), ("EFGH", "1234")],
    ] {
        let error = m.create(with_default_env(pairs)).await.unwrap_err();
        assert!(
            matches!(error, Error::InvalidArgument(_)),
            "{pairs:?}: {error:?}"
        );
    }
    assert_eq!(sandbox_rows(&m), rows);
}

#[tokio::test]
async fn a_missing_cwd_is_a_typed_failed_execution_and_the_sandbox_stays_usable() {
    let (m, _) = proven().await;
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    let e = m
        .exec(exec_req(&sandbox.id, &["pwd"], "/missing/dir", &[]))
        .await
        .unwrap();
    assert_eq!(e.state, ExecutionState::Failed);
    let d = e.runtime_error.as_ref().unwrap();
    assert_eq!(
        (d.kind, d.stage),
        (RuntimeErrorKind::LaunchFailed, RuntimeStage::Cwd)
    );
    assert_eq!(d.native_code.as_deref(), Some("ENOENT"));
    assert!(
        e.failure_reason
            .as_deref()
            .unwrap()
            .starts_with("cwd_not_found: "),
        "{e:?}"
    );
    assert_eq!(e.cleanup_evidence, CleanupEvidence::RuntimeDrained);
    assert_eq!(e.sandbox_reusable, Some(true));
    assert_eq!(e.cwd.as_deref(), Some("/missing/dir"));
    let next = m
        .exec(exec_req(&sandbox.id, &["pwd"], "/workspace", &[]))
        .await
        .unwrap();
    assert_eq!(next.stdout.data, b"/workspace\n");
}

#[test]
fn exec_option_outcomes_carry_their_tokens() {
    let d = |kind, stage| RuntimeDiagnostic::new(kind, stage, "msg");
    use RuntimeErrorKind as K;
    use RuntimeStage as S;
    for (kind, stage, with, expected) in [
        (K::LaunchFailed, S::Cwd, true, "cwd_not_found: msg"),
        (
            K::Unavailable,
            S::Handshake,
            true,
            "exec_options_unconfirmed: msg",
        ),
        (
            K::Incompatible,
            S::Handshake,
            true,
            "exec_options_unsupported: msg",
        ),
        (
            K::Unavailable,
            S::Prepare,
            true,
            "exec_options_unavailable: msg",
        ),
        // Without options every outcome reads as before.
        (K::Unavailable, S::Handshake, false, "msg"),
        (K::Incompatible, S::Handshake, false, "msg"),
        (K::LaunchFailed, S::Exec, true, "msg"),
    ] {
        assert_eq!(exec_failure_reason(&d(kind, stage), with), expected);
    }
}

#[tokio::test]
async fn default_env_values_are_cleared_at_failed_and_deleted_and_never_return() {
    let (m, fake) = proven().await;
    let sandbox = m.create(with_default_env(&[("A", "1")])).await.unwrap();
    assert!(stored_default_env(&m, &sandbox.id).is_some());
    let deleted = m.delete(&sandbox.id).await.unwrap();
    assert_eq!(deleted.state, SandboxState::Deleted);
    assert_eq!(stored_default_env(&m, &sandbox.id), None);
    // Names and digest stay for history.
    assert_eq!(deleted.lifecycle.default_env_names, ["A"]);
    assert!(deleted.lifecycle.default_env_sha256.is_some());
    // A failed create clears them in the statement that fails it.
    fake.state().fail_create = Some("backend refused".into());
    m.create(with_default_env(&[("A", "1")])).await.unwrap_err();
    let failed = m
        .list(true)
        .unwrap()
        .into_iter()
        .find(|s| s.state == SandboxState::Failed)
        .unwrap();
    assert_eq!(stored_default_env(&m, &failed.id), None);
    fake.state().fail_create = None;
    fake.state().fail_create_definitely = Some("preflight refused".into());
    m.create(with_default_env(&[("A", "1")])).await.unwrap_err();
    let values: i64 = m
        .store
        .query_for_test(
            "SELECT count(*) FROM sandboxes WHERE default_env IS NOT NULL",
            [],
        )
        .unwrap();
    assert_eq!(values, 0);
}

fn failure_reason_of(m: &Manager<FakeRuntime>, id: &str) -> String {
    m.store
        .query_for_test("SELECT failure_reason FROM sandboxes WHERE id = ?1", [id])
        .unwrap()
}

fn legacy_release_of(m: &Manager<FakeRuntime>, id: &str) -> Option<String> {
    m.store
        .query_for_test("SELECT legacy_release FROM sandboxes WHERE id = ?1", [id])
        .unwrap()
}

/// The only row: its ID, after a create that left no other.
fn only_row(m: &Manager<FakeRuntime>) -> Sandbox {
    let rows = m.list(true).unwrap();
    assert_eq!(rows.len(), 1, "{rows:?}");
    rows.into_iter().next().unwrap()
}

/// Break-it M3b MEDIUM: a create with a default env whose new sandbox's post-create
/// probe fails, or answers without bit 0x20, is never READY. Its backend is removed,
/// its reservation released and its defaults cleared, and it answers with a typed,
/// retryable refusal. Without the check it came back READY with `exec_features`
/// NULL, refusing every Exec as `sandbox_unsupported:exec_env` until deleted.
#[tokio::test]
async fn a_default_env_create_without_per_sandbox_proof_fails_and_is_compensated() {
    for bits in [None, Some(0x1f)] {
        let (m, fake) = proven().await;
        fake.state().create_exec_features = bits;
        let error = m
            .create(with_default_env(&[("SECRET", "value")]))
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::Refused(RefusalCode::Unavailable, _)),
            "{error:?}"
        );
        assert_eq!(reason(&error), Some("sandbox_feature_probe_failed"));
        assert!(!error.to_string().contains("value"), "{error}");
        let row = only_row(&m);
        assert_eq!(row.state, SandboxState::Failed);
        assert_eq!(fake.state().removed, [row.backend_id.clone().unwrap()]);
        assert!(fake.state().sandboxes.is_empty());
        let recorded = failure_reason_of(&m, &row.id);
        assert!(
            recorded.starts_with("sandbox_feature_probe_failed: ")
                && recorded.ends_with("; backend removed"),
            "{recorded}"
        );
        assert_eq!(
            legacy_release_of(&m, &row.id).as_deref(),
            Some("compensated")
        );
        assert_eq!(stored_default_env(&m, &row.id), None);
        assert_eq!(row.lifecycle.default_env_names, ["SECRET"]);
        // Retryable: once the probe answers, the same create is READY and usable.
        fake.state().create_exec_features = Some(0x3f);
        let sandbox = m
            .create(with_default_env(&[("SECRET", "value")]))
            .await
            .unwrap();
        assert_eq!(sandbox.state, SandboxState::Ready);
        assert_eq!(sandbox.lifecycle.exec_features, Some(0x3f));
        let e = m
            .exec(exec_req(&sandbox.id, &["true"], "", &[]))
            .await
            .unwrap();
        assert_eq!(e.state, ExecutionState::Exited);
    }
}

/// A create without a default env keeps today's behaviour: a failed probe records no
/// bits and the sandbox is READY for operation-4 Execs.
#[tokio::test]
async fn a_create_without_default_env_is_ready_whatever_its_probe_answered() {
    let (m, fake) = proven().await;
    fake.state().create_exec_features = None;
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    assert_eq!(sandbox.state, SandboxState::Ready);
    assert_eq!(sandbox.lifecycle.exec_features, None);
    assert!(fake.state().removed.is_empty());
    let e = m
        .exec(exec_req(&sandbox.id, &["true"], "", &[]))
        .await
        .unwrap();
    assert_eq!(e.state, ExecutionState::Exited);
}

/// A removal that fails leaves the row DELETING and charged (Delete or reconciliation
/// retries it), and the create still answers with the typed refusal, never READY.
#[tokio::test]
async fn an_unproven_default_env_create_whose_removal_fails_stays_deleting() {
    let (m, fake) = proven().await;
    fake.state().create_exec_features = None;
    fake.state().fail_remove = true;
    let error = m.create(with_default_env(&[("A", "1")])).await.unwrap_err();
    assert_eq!(reason(&error), Some("sandbox_feature_probe_failed"));
    let row = only_row(&m);
    assert_eq!(row.state, SandboxState::Deleting);
    assert!(
        failure_reason_of(&m, &row.id).contains("; cleanup failed: "),
        "{row:?}"
    );
    assert_eq!(legacy_release_of(&m, &row.id), None);
    fake.state().fail_remove = false;
    assert_eq!(
        m.delete(&row.id).await.unwrap().state,
        SandboxState::Deleted
    );
    assert_eq!(stored_default_env(&m, &row.id), None);
}

/// The keyed create (design 3.1) stores the failure like any settled one: the
/// original and every retry answer OK with the same FAILED row, and nothing reruns.
#[tokio::test]
async fn a_keyed_default_env_create_without_proof_settles_failed_for_every_retry() {
    let (m, fake) = proven().await;
    fake.state().create_exec_features = None;
    let digest = crate::idempotency::request_digest(&pb_request(&[("A", "1")]));
    let key = || CreateKey {
        request_id: "k".into(),
        sha256: digest,
    };
    let first = m
        .create_keyed(Ok(with_default_env(&[("A", "1")])), 0, key(), None)
        .await
        .unwrap();
    assert_eq!(first.state, SandboxState::Failed);
    assert!(
        first
            .failure_reason
            .as_deref()
            .is_some_and(|r| r.starts_with("sandbox_feature_probe_failed: ")),
        "{first:?}"
    );
    assert_eq!(stored_default_env(&m, &first.id), None);
    fake.state().create_exec_features = Some(0x3f);
    let retry = m
        .create_keyed(Ok(with_default_env(&[("A", "1")])), 0, key(), None)
        .await
        .unwrap();
    assert_eq!(retry.id, first.id);
    assert_eq!(retry.state, SandboxState::Failed);
    assert_eq!(retry.failure_reason, first.failure_reason);
    assert_eq!(fake.state().created.len(), 1, "the retry created nothing");
}

/// The fenced path holds the same rule if a fenced backend ever proved the default
/// env feature: an allocation without per-sandbox proof settles FAILED by its token.
#[tokio::test]
async fn a_fenced_default_env_create_without_proof_is_never_ready() {
    let fake = FakeRuntime::fenced();
    let m = manager_on(fake.clone(), limits());
    m.health().await.unwrap();
    m.dynamic_features.lock().unwrap().0 = OPTION_FEATURES.to_vec();
    let error = m.create(with_default_env(&[("A", "1")])).await.unwrap_err();
    assert!(
        matches!(error, Error::Refused(RefusalCode::Unavailable, _)),
        "{error:?}"
    );
    assert_eq!(reason(&error), Some("sandbox_feature_probe_failed"));
    let row = only_row(&m);
    assert_eq!(row.state, SandboxState::Failed);
    assert!(
        row.failure_reason
            .as_deref()
            .is_some_and(|r| r.starts_with("sandbox_feature_probe_failed: ")),
        "{row:?}"
    );
    assert_eq!(fake.state().removed.len(), 1);
    assert_eq!(stored_default_env(&m, &row.id), None);
}

#[tokio::test]
async fn a_lost_start_race_is_execution_start_raced_and_retryable() {
    let (m, fake) = proven().await;
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    m.store
        .lose_execution_starts
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let error = m
        .exec(exec_req(&sandbox.id, &["true"], "", &[]))
        .await
        .unwrap_err();
    assert!(matches!(error, Error::FailedPrecondition(_)), "{error:?}");
    assert_eq!(reason(&error), Some("execution_start_raced"));
    assert!(
        error.to_string().starts_with("execution_start_raced: "),
        "{error}"
    );
    assert_nothing_ran(&m, &fake, 0);
    // The retry runs.
    let e = m
        .exec(exec_req(&sandbox.id, &["true"], "", &[]))
        .await
        .unwrap();
    assert_eq!(e.state, ExecutionState::Exited);
}

#[tokio::test]
async fn firecracker_refuses_every_option_before_prepare_or_any_row() {
    let fake = FakeRuntime::fenced();
    assert_eq!(fake.state().mode, FakeEvidenceMode::Fenced);
    let m = manager_on(fake.clone(), limits());
    // Its probe proves no exec options, so Health lists none.
    m.health().await.unwrap();
    for feature in OPTION_FEATURES {
        assert!(!m.has_feature(feature));
    }
    let error = m.create(with_default_env(&[("A", "1")])).await.unwrap_err();
    assert_eq!(
        reason(&error),
        Some("backend_unsupported:sandbox_default_env")
    );
    assert_eq!(fake.state().fenced.prepare_calls, 0, "no token issued");
    assert_eq!(sandbox_rows(&m), 0);
    let sandbox = m.create(CreateRequest::default()).await.unwrap();
    let prepared = fake.state().fenced.prepare_calls;
    let error = m
        .exec(exec_req(&sandbox.id, &["true"], "", &[("A", "1")]))
        .await
        .unwrap_err();
    assert_eq!(reason(&error), Some("backend_unsupported:exec_env"));
    assert_eq!(fake.state().fenced.prepare_calls, prepared);
    assert_nothing_ran(&m, &fake, 0);
}

#[tokio::test]
async fn keyed_creates_gate_and_hash_the_default_env() {
    let (m, _) = proven().await;
    let key = |sha256| CreateKey {
        request_id: "k".into(),
        sha256,
    };
    let request = |pairs: &[(&str, &str)]| pb_request(pairs);
    let digest = crate::idempotency::request_digest(&request(&[("A", "1")]));
    assert_ne!(
        digest,
        crate::idempotency::request_digest(&request(&[("A", "2")]))
    );
    assert_eq!(
        digest,
        crate::idempotency::request_digest(&request(&[("A", "1")]))
    );
    let first = m
        .create_keyed(Ok(with_default_env(&[("A", "1")])), 0, key(digest), None)
        .await
        .unwrap();
    assert_eq!(first.lifecycle.default_env_names, ["A"]);
    let retry = m
        .create_keyed(Ok(with_default_env(&[("A", "1")])), 0, key(digest), None)
        .await
        .unwrap();
    assert_eq!(retry.id, first.id);
    // Withdrawn features refuse a fresh keyed create at step 4, not a retry.
    m.dynamic_features.lock().unwrap().0.clear();
    let retry = m
        .create_keyed(Ok(with_default_env(&[("A", "1")])), 0, key(digest), None)
        .await
        .unwrap();
    assert_eq!(retry.id, first.id);
    let fresh = CreateKey {
        request_id: "other".into(),
        sha256: digest,
    };
    let error = m
        .create_keyed(Ok(with_default_env(&[("A", "1")])), 0, fresh, None)
        .await
        .unwrap_err();
    assert_eq!(
        reason(&error),
        Some("backend_unsupported:sandbox_default_env")
    );
}

fn pb_request(pairs: &[(&str, &str)]) -> kilnd_api::v1::CreateSandboxRequest {
    kilnd_api::v1::CreateSandboxRequest {
        request_id: "k".into(),
        default_env: pairs
            .iter()
            .map(|(n, v)| kilnd_api::v1::EnvVar {
                name: n.to_string(),
                value: v.to_string(),
            })
            .collect(),
        ..Default::default()
    }
}
