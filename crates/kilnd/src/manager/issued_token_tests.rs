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
