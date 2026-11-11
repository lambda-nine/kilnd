//! API additions M1 at the gRPC boundary: discovery, typed reasons, expiry fields,
//! RenewSandbox, and old clients that set none of them.

use std::sync::Arc;
use std::time::Duration;

use pb::kilnd_service_server::KilndService;

use super::*;
use crate::admission::ConnectionLane;
use crate::expiry::{Clock, ExpiryLimits, ManualClock};
use crate::manager::Limits;
use crate::model::SandboxDisposition;
use crate::runtime::fake::{FakeGate, FakeRuntime};
use crate::store::Store;

fn as_uid<T>(message: T, uid: u32) -> Request<T> {
    let mut request = Request::new(message);
    request.extensions_mut().insert(PeerIdentity {
        uid: Some(uid),
        lane: ConnectionLane::General,
    });
    request
}

fn service(
    limits: Limits,
) -> (
    FakeRuntime,
    Arc<Manager<FakeRuntime>>,
    Service<FakeRuntime>,
    ManualClock,
) {
    let fake = FakeRuntime::default();
    let clock = ManualClock::default();
    let manager = Arc::new(Manager::with_clock(
        fake.clone(),
        Store::open_in_memory().unwrap(),
        Limits {
            max_node_memory_bytes: 1 << 40,
            expiry: ExpiryLimits {
                restart_grace: Duration::ZERO,
                ..limits.expiry
            },
            ..limits
        },
        Arc::new(clock.clone()),
    ));
    (fake, manager.clone(), Service::new(manager), clock)
}

async fn create(s: &Service<FakeRuntime>, expiry: Option<pb::ExpiryPolicy>) -> pb::Sandbox {
    s.create_sandbox(as_uid(
        pb::CreateSandboxRequest { request_id: String::new(), spec: None, expiry },
        1000,
    ))
    .await
    .unwrap()
    .into_inner()
    .sandbox
    .unwrap()
}

fn exec(id: &str) -> pb::ExecRequest {
    pb::ExecRequest {
        sandbox_id: id.into(),
        argv: vec!["echo".into(), "x".into()],
        ..Default::default()
    }
}

fn trailer(status: &Status) -> Option<&str> {
    status
        .metadata()
        .get(REASON_KEY)
        .map(|value| value.to_str().unwrap())
}

/// What a refusal must leave behind: nothing at all.
struct Footprint {
    sandboxes: usize,
    executions: usize,
    exec_calls: usize,
    created: usize,
}

fn footprint(fake: &FakeRuntime, m: &Manager<FakeRuntime>) -> Footprint {
    let sandboxes = m.list(true).unwrap();
    let executions = sandboxes
        .iter()
        .map(|s| m.get(&s.id, 100).unwrap().1.len())
        .sum();
    let state = fake.state();
    Footprint {
        sandboxes: sandboxes.len(),
        executions,
        exec_calls: state.exec_calls.len(),
        created: state.created.len(),
    }
}

fn assert_nothing_allocated(before: &Footprint, fake: &FakeRuntime, m: &Manager<FakeRuntime>) {
    let after = footprint(fake, m);
    assert_eq!(after.sandboxes, before.sandboxes, "sandbox rows");
    assert_eq!(after.executions, before.executions, "execution rows");
    assert_eq!(after.exec_calls, before.exec_calls, "backend exec calls");
    assert_eq!(after.created, before.created, "backend creates");
    assert_eq!(m.admission().snapshot().execs.current, 0, "Exec tickets");
}

#[tokio::test]
async fn health_lists_static_features_and_every_m1_limit() {
    let (_, _, s, _) = service(Limits::default());
    let health = s
        .health(as_uid(pb::HealthRequest {}, 1000))
        .await
        .unwrap()
        .into_inner();
    let caps = health.runtime_capabilities.unwrap();
    assert_eq!(
        caps.features,
        vec![
            pb::Feature::SandboxExpiry as i32,
            pb::Feature::IdempotentCreate as i32,
            pb::Feature::TypedReasons as i32,
            pb::Feature::RequestIdRelease as i32
        ]
    );
    let limits = caps.limits.unwrap();
    assert_eq!(limits.max_sandbox_lifetime_ms, 7 * 86_400_000);
    assert_eq!(limits.max_sandbox_idle_ms, 86_400_000);
    assert_eq!(limits.default_sandbox_lifetime_ms, 0);
    assert_eq!(limits.default_sandbox_idle_ms, 0);
    assert_eq!(limits.min_sandbox_lifetime_ms, 10_000);
    assert_eq!(limits.min_sandbox_idle_ms, 10_000);
    assert_eq!(limits.default_exec_timeout_ms, 60_000);
    assert_eq!(limits.max_exec_timeout_ms, 3_600_000);
    assert_eq!(limits.max_output_bytes, 1 << 20);
    // Milestone 2 lists idempotent create, so its retention is advertised.
    assert_eq!(limits.create_request_retention_ms, 86_400_000);
    // Features this daemon does not list have zero limits.
    assert_eq!(limits.max_env_entries, 0);
    assert_eq!(limits.max_stream_timeout_ms, 0);
    let lifecycle = health.lifecycle.unwrap();
    assert_eq!(lifecycle, pb::LifecycleStats::default());
}

#[tokio::test]
async fn every_not_ready_refusal_is_typed_keeps_its_code_and_allocates_nothing() {
    let (fake, m, s, _) = service(Limits::default());
    // CREATING.
    let gate = FakeGate::default();
    fake.state().create_before_allocation = Some(gate.clone());
    let creating = tokio::spawn({
        let m = m.clone();
        async move { m.create_owned(Default::default(), 1000).await }
    });
    gate.entered().await;
    let creating_id = m.list(true).unwrap()[0].id.clone();
    let mut cases = vec![(creating_id.clone(), "sandbox_not_ready", "creating")];
    // FAILED (compensated, so it reads as history).
    let failed = m.create_owned(Default::default(), 1000).await;
    assert!(failed.is_ok());
    let failed = failed.unwrap();
    m.store_set_state_for_test(&failed.id, SandboxState::Failed);
    cases.push((failed.id.clone(), "sandbox_failed", "failed"));
    // LOST and QUARANTINED.
    for (disposition, token, state) in [
        (SandboxDisposition::Stopped, "sandbox_lost", "lost"),
        (
            SandboxDisposition::Quarantined,
            "sandbox_quarantined",
            "quarantined",
        ),
    ] {
        let sandbox = m.create_owned(Default::default(), 1000).await.unwrap();
        m.store_retire_for_test(&sandbox.id, disposition);
        cases.push((sandbox.id, token, state));
    }
    // Requested delete.
    let deleted = m.create_owned(Default::default(), 1000).await.unwrap();
    m.delete(&deleted.id).await.unwrap();
    cases.push((deleted.id.clone(), "sandbox_deleted", "deleted"));
    for (id, token, state) in &cases {
        let before = footprint(&fake, &m);
        let refused = s.exec(as_uid(exec(id), 1000)).await.unwrap_err();
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition, "{token}");
        assert_eq!(trailer(&refused), Some(*token));
        // Only the prefix is new: the rest is today's message, unchanged.
        assert_eq!(
            refused.message(),
            format!("{token}: sandbox {id} is {state}, not ready")
        );
        assert_nothing_allocated(&before, &fake, &m);
        let refused = s
            .renew_sandbox(as_uid(pb::RenewSandboxRequest { id: id.clone() }, 1000))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
        assert_eq!(trailer(&refused), Some(*token));
        assert_nothing_allocated(&before, &fake, &m);
    }
    gate.release();
    creating.await.unwrap().unwrap();
}

#[tokio::test]
async fn expiry_refusals_name_the_deletion_reason() {
    let (fake, m, s, clock) = service(Limits::default());
    let idle = create(
        &s,
        Some(pb::ExpiryPolicy {
            max_lifetime_ms: 0,
            idle_timeout_ms: 10_000,
        }),
    )
    .await;
    let lifetime = create(
        &s,
        Some(pb::ExpiryPolicy {
            max_lifetime_ms: 10_000,
            idle_timeout_ms: 0,
        }),
    )
    .await;
    m.rebuild_expiry().unwrap();
    clock.advance(10_000);
    m.expire_due();
    for _ in 0..200 {
        tokio::task::yield_now().await;
    }
    for (sandbox, token, reason) in [
        (&idle, "expired_idle", pb::DeletionReason::ExpiredIdle),
        (
            &lifetime,
            "expired_lifetime",
            pb::DeletionReason::ExpiredLifetime,
        ),
    ] {
        let before = footprint(&fake, &m);
        let refused = s.exec(as_uid(exec(&sandbox.id), 1000)).await.unwrap_err();
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
        assert_eq!(trailer(&refused), Some(token));
        assert!(refused.message().starts_with(&format!("{token}: ")));
        assert_nothing_allocated(&before, &fake, &m);
        let got = s
            .get_sandbox(as_uid(
                pb::GetSandboxRequest {
                    id: sandbox.id.clone(),
                    execution_limit: 0,
                },
                1000,
            ))
            .await
            .unwrap()
            .into_inner()
            .sandbox
            .unwrap();
        assert_eq!(got.state, pb::SandboxState::Deleted as i32);
        assert_eq!(got.deletion_reason, reason as i32);
    }
    // Absence by listing works unchanged.
    let listed = s
        .list_sandboxes(as_uid(
            pb::ListSandboxesRequest {
                include_deleted: false,
                page_size: Some(0),
                page_token: String::new(),
            },
            1000,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(listed.sandboxes.is_empty());
    let health = s
        .health(as_uid(pb::HealthRequest {}, 1000))
        .await
        .unwrap()
        .into_inner()
        .lifecycle
        .unwrap();
    assert_eq!((health.expired_idle, health.expired_lifetime), (1, 1));
}

#[tokio::test]
async fn a_foreign_or_unknown_id_stays_not_found_without_a_trailer() {
    let (_, _, s, _) = service(Limits::default());
    let mine = create(&s, None).await;
    for (id, uid) in [
        (mine.id.clone(), 2000),
        ("sb-0000000000000001".into(), 1000),
    ] {
        for refused in [
            s.renew_sandbox(as_uid(pb::RenewSandboxRequest { id: id.clone() }, uid))
                .await
                .unwrap_err(),
            s.exec(as_uid(exec(&id), uid)).await.unwrap_err(),
        ] {
            assert_eq!(refused.code(), tonic::Code::NotFound);
            assert_eq!(trailer(&refused), None);
        }
    }
    // Root may renew anyone's sandbox, as it may Get it.
    let renewed = s
        .renew_sandbox(as_uid(
            pb::RenewSandboxRequest {
                id: mine.id.clone(),
            },
            0,
        ))
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    assert_eq!(renewed.id, mine.id);
}

#[tokio::test]
async fn create_reports_the_effective_policy_and_both_deadlines() {
    let (_, m, s, clock) = service(Limits {
        expiry: ExpiryLimits {
            default_idle_ms: 600_000,
            ..ExpiryLimits::default()
        },
        ..Limits::default()
    });
    m.rebuild_expiry().unwrap();
    let sandbox = create(
        &s,
        Some(pb::ExpiryPolicy {
            max_lifetime_ms: 3_600_000,
            idle_timeout_ms: 0,
        }),
    )
    .await;
    let expiry = sandbox.expiry.unwrap();
    assert_eq!(
        expiry.effective,
        Some(pb::ExpiryPolicy {
            max_lifetime_ms: 3_600_000,
            idle_timeout_ms: 600_000,
        })
    );
    let now = clock.wall_ms();
    assert_eq!(expiry.lifetime_expires_at_unix_ms, now + 3_600_000);
    assert_eq!(expiry.idle_expires_at_unix_ms, now + 600_000);
    assert_eq!(expiry.last_activity_at_unix_ms, now);
    assert!(!expiry.idle_paused);
    let refused = s
        .create_sandbox(as_uid(
            pb::CreateSandboxRequest { request_id: String::new(),
                spec: None,
                expiry: Some(pb::ExpiryPolicy {
                    max_lifetime_ms: 9_999,
                    idle_timeout_ms: 0,
                }),
            },
            1000,
        ))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::InvalidArgument);
}

/// An old client sets none of the new fields. It gets exactly 0547a0c's behavior:
/// no expiry whatever the node defaults, the same codes, and messages that differ
/// only by a reason prefix on the typed refusals.
#[tokio::test]
async fn an_old_client_sees_no_behavior_change() {
    let (fake, m, s, clock) = service(Limits {
        expiry: ExpiryLimits {
            default_lifetime_ms: 10_000,
            default_idle_ms: 10_000,
            ..ExpiryLimits::default()
        },
        ..Limits::default()
    });
    m.rebuild_expiry().unwrap();
    let old = s
        .create_sandbox(as_uid(pb::CreateSandboxRequest::default(), 1000))
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    let expiry = old.expiry.unwrap();
    assert_eq!(expiry.effective, Some(pb::ExpiryPolicy::default()));
    assert_eq!(expiry.lifetime_expires_at_unix_ms, 0);
    assert_eq!(expiry.idle_expires_at_unix_ms, 0);
    clock.advance(30 * 86_400_000);
    m.expire_due();
    let execution = s
        .exec(as_uid(exec(&old.id), 1000))
        .await
        .unwrap()
        .into_inner()
        .execution
        .unwrap();
    assert_eq!(execution.state, pb::ExecutionState::Exited as i32);
    assert_eq!(
        execution.cancel_reason,
        pb::CancelReason::Unspecified as i32
    );
    assert_eq!(fake.state().removed.len(), 0);
    let deleted = s
        .delete_sandbox(as_uid(
            pb::DeleteSandboxRequest { release_request_id: false, id: old.id.clone() },
            1000,
        ))
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    assert_eq!(deleted.state, pb::SandboxState::Deleted as i32);
    assert_eq!(
        deleted.deletion_reason,
        pb::DeletionReason::Requested as i32
    );
    let refused = s.exec(as_uid(exec(&old.id), 1000)).await.unwrap_err();
    assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        refused.message().strip_prefix("sandbox_deleted: ").unwrap(),
        format!("sandbox {} is deleted, not ready", old.id)
    );
    // Untyped refusals keep their exact message and carry no trailer.
    let invalid = s
        .exec(as_uid(
            pb::ExecRequest {
                sandbox_id: "nope".into(),
                ..exec("")
            },
            1000,
        ))
        .await
        .unwrap_err();
    assert_eq!(invalid.code(), tonic::Code::InvalidArgument);
    assert_eq!(trailer(&invalid), None);
}

#[tokio::test]
async fn renew_returns_the_sandbox_with_its_moved_idle_deadline() {
    let (_, m, s, clock) = service(Limits::default());
    m.rebuild_expiry().unwrap();
    let sandbox = create(
        &s,
        Some(pb::ExpiryPolicy {
            max_lifetime_ms: 0,
            idle_timeout_ms: 60_000,
        }),
    )
    .await;
    clock.advance(30_000);
    let renewed = s
        .renew_sandbox(as_uid(pb::RenewSandboxRequest { id: sandbox.id }, 1000))
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    let expiry = renewed.expiry.unwrap();
    assert_eq!(expiry.last_activity_at_unix_ms, clock.wall_ms());
    assert_eq!(expiry.idle_expires_at_unix_ms, clock.wall_ms() + 60_000);
}
