//! M3-2 finding F3 at the daemon: a refusal after a fenced backend's preparation issued
//! its token, before any row names it, fences that token best effort, so the issued
//! sequence has a durable outcome. The fake issues tokens as the helper does.

use std::sync::Arc;

use super::*;
use crate::runtime::fake::{FakeGate, FakeRuntime};

/// Two Creates race for the daemon budget's last reservation. Both pass any pre-check;
/// the one whose preparation finishes second is refused by the accepting transaction,
/// after its token was issued, and that token is fenced (never admitted).
#[tokio::test]
async fn a_budget_refusal_after_preparation_fences_its_token() {
    let fake = FakeRuntime::fenced();
    let m = Arc::new(Manager::new(
        fake.clone(),
        Store::open_in_memory().unwrap(),
        Limits {
            // Room for one offline-768-v1 reservation (896 MiB), not two.
            max_node_memory_bytes: 1024 * 1024 * 1024,
            ..Limits::default()
        },
    ));
    let gate = FakeGate::default();
    fake.state().fenced.prepare_gate = Some(gate.clone());
    let late = {
        let m = m.clone();
        tokio::spawn(async move { m.create(CreateRequest::default()).await })
    };
    gate.entered().await;
    let first = m.create(CreateRequest::default()).await.unwrap();
    assert_eq!(first.state, SandboxState::Ready);
    gate.release();
    let error = late.await.unwrap().unwrap_err();
    assert!(
        error.to_string().contains("memory bytes budget exhausted"),
        "{error}"
    );
    assert_eq!(
        m.list(true).unwrap().len(),
        1,
        "no row for the refused create"
    );
    // The refused create's token is seq 1, issued before the first create's.
    let first_token = first.accounting.allocation.as_ref().unwrap().allocation_id;
    for _ in 0..200 {
        if !fake.state().fenced.fences.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let state = fake.state();
    assert_eq!(state.fenced.issued, 2);
    let fenced: Vec<_> = state.fenced.fences.keys().copied().collect();
    assert_eq!(fenced.len(), 1, "{fenced:?}");
    assert_ne!(fenced[0], first_token);
    assert_eq!(&fenced[0].as_bytes()[..8], &1u64.to_be_bytes());
    assert!(!state.fenced.allocations.contains_key(&fenced[0]));
}

/// The default path is unchanged: a legacy plan has no token to fence, and a refused
/// legacy create calls no fence.
#[tokio::test]
async fn a_legacy_budget_refusal_fences_nothing() {
    let fake = FakeRuntime::default();
    let m = Arc::new(Manager::new(
        fake.clone(),
        Store::open_in_memory().unwrap(),
        Limits {
            max_sandboxes: 1,
            ..Limits::default()
        },
    ));
    m.create(CreateRequest::default()).await.unwrap();
    let error = m.create(CreateRequest::default()).await.unwrap_err();
    assert!(error.to_string().contains("budget exhausted"), "{error}");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(fake.state().fenced.fence_calls, 0);
}

/// Option A, the documented instant: a Create is refused if the node budget is full when
/// the pre-check reads it, before any Preflight. That refusal is final: it issues no
/// token and prepares nothing, and a Delete that lands afterwards doesn't rescue it (the
/// client may retry). Without a prediction the accepting transaction decides alone, so a
/// Delete during the preparation admits the identical request with exactly one charge.
#[tokio::test]
async fn an_early_budget_refusal_is_final_and_the_commit_only_path_admits() {
    let fake = FakeRuntime::fenced();
    let m = Arc::new(Manager::new(
        fake.clone(),
        Store::open_in_memory().unwrap(),
        Limits {
            max_sandboxes: 1,
            ..Limits::default()
        },
    ));
    let existing = m.create(CreateRequest::default()).await.unwrap();
    let predicted = crate::firecracker::offline_768_v1_reservation(&existing.spec).unwrap();
    assert_eq!(existing.accounting.reservation, predicted);

    // Predicted: refused at the pre-check, before any Preflight or token.
    fake.state().fenced.predict_reservation = true;
    let (prepared, issued) = {
        let state = fake.state();
        (state.fenced.prepare_calls, state.fenced.issued)
    };
    let error = m.create(CreateRequest::default()).await.unwrap_err();
    assert!(
        error.to_string().contains("sandboxes budget exhausted"),
        "{error}"
    );
    assert_eq!(fake.state().fenced.prepare_calls, prepared, "nothing prepared");
    assert_eq!(fake.state().fenced.issued, issued, "no token issued");
    assert_eq!(m.list(true).unwrap().len(), 1, "no row for the refusal");
    // The control: prediction off, a Delete lands during the gated preparation.
    fake.state().fenced.predict_reservation = false;
    let gate = FakeGate::default();
    fake.state().fenced.prepare_gate = Some(gate.clone());
    let pending = {
        let m = m.clone();
        tokio::spawn(async move { m.create(CreateRequest::default()).await })
    };
    gate.entered().await;
    let deleted = m.delete(&existing.id).await.unwrap();
    assert!(!deleted.is_charged());
    gate.release();
    let next = pending.await.unwrap().unwrap();
    assert_eq!(next.state, SandboxState::Ready);
    assert_eq!(next.accounting.reservation, predicted);
    assert_eq!(m.store.sandbox_resources().unwrap().sandboxes, 1);
    // The early refusal stayed a refusal: only the original and the control have rows.
    let ids: BTreeSet<String> = m.list(true).unwrap().into_iter().map(|s| s.id).collect();
    assert_eq!(ids, BTreeSet::from([existing.id, next.id]));
}
