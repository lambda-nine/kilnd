//! `kilnd release-ambiguous` against the fake backend: an ambiguous reservation is
//! released only after reconcile, a complete second inventory and kiln's runs
//! directory all come back clean, with its audit row; every refusal leaves the row
//! charged and writes nothing.

use std::ffi::OsString;
use std::sync::Arc;

use super::*;
use crate::model::{Digest, LegacyRelease, ReservationRelease};
use crate::runtime::fake::{FakeGate, FakeRuntime};

type M = Arc<Manager<FakeRuntime>>;

/// kiln's runs directory as a list of names.
struct Runs(Vec<&'static str>);

impl RunsDirectory for Runs {
    fn entries(&self) -> anyhow::Result<Vec<OsString>> {
        Ok(self.0.iter().map(OsString::from).collect())
    }
}

struct UnreadableRuns;

impl RunsDirectory for UnreadableRuns {
    fn entries(&self) -> anyhow::Result<Vec<OsString>> {
        anyhow::bail!("Permission denied (os error 13)")
    }
}

/// A node with room for exactly one sandbox, the shape a single stuck reservation
/// fills.
fn one_slot() -> (M, FakeRuntime) {
    manager_with_slots(1)
}

fn manager_with_slots(max_sandboxes: u32) -> (M, FakeRuntime) {
    let fake = FakeRuntime::default();
    let m = Manager::new(
        fake.clone(),
        Store::open_in_memory().unwrap(),
        Limits {
            max_sandboxes,
            ..Limits::default()
        },
    );
    (Arc::new(m), fake)
}

/// An ambiguous FAILED create of `uid`'s, as kiln's exit 1 after allocation leaves it.
async fn ambiguous(m: &M, fake: &FakeRuntime, uid: u32) -> Sandbox {
    fake.state().fail_create = Some("kiln exited 1 after allocating".into());
    m.create_owned(CreateRequest::default(), uid)
        .await
        .unwrap_err();
    fake.state().fail_create = None;
    let row = m
        .store
        .sandboxes(true)
        .unwrap()
        .into_iter()
        .filter(|s| s.owner_uid == uid)
        .max_by_key(|s| s.created_at_ms)
        .unwrap();
    assert_eq!(row.state, SandboxState::Failed);
    assert!(row.backend_id.is_none());
    assert_eq!(row.create_certainty, CreateCertainty::AllocationAmbiguous);
    assert!(row.is_charged());
    row
}

fn request(id: &str) -> ReleaseRequest<'_> {
    ReleaseRequest {
        sandbox_id: id,
        reason: "kiln create exited 1; runs directory checked by hand",
        operator_uid: 0,
    }
}

async fn reserved_sandboxes(m: &M) -> u64 {
    m.health().await.unwrap().node_resources.reserved.sandboxes
}

/// A refusal changed nothing: the row is charged, unreleased and unaudited.
async fn still_charged(m: &M, id: &str, reserved: u64) {
    let row = m.store.sandbox(id).unwrap().unwrap();
    assert!(row.is_charged(), "{id} was released");
    assert_eq!(row.accounting.release, ReservationRelease::Charged);
    assert_eq!(m.store.operator_release_count().unwrap(), 0);
    assert_eq!(reserved_sandboxes(m).await, reserved);
}

#[tokio::test]
async fn a_proved_release_frees_the_node_for_another_uid() {
    let (m, fake) = one_slot();
    let stuck = ambiguous(&m, &fake, 1000).await;
    // The one reservation blocks every uid, not just its owner.
    let blocked = m
        .create_owned(CreateRequest::default(), 2000)
        .await
        .unwrap_err();
    assert!(
        matches!(blocked, Error::ResourceExhausted(_)),
        "{blocked:?}"
    );

    let proved = m
        .release_ambiguous(request(&stuck.id), &Runs(vec![KILN_RUNS_RESERVED]))
        .await
        .unwrap();
    assert_eq!(proved.sandbox_id, stuck.id);
    assert_eq!(proved.released.owner_uid, 1000);
    assert_eq!(proved.released.reservation, stuck.accounting.reservation);
    assert_eq!(proved.inventory_sha256.len(), 64);
    let line = crate::release_ambiguous::released_line(&proved);
    assert!(
        line.starts_with(&format!(
            "released {} owner_uid=1000 sandboxes=1 ",
            stuck.id
        )),
        "{line}"
    );

    let row = m.store.sandbox(&stuck.id).unwrap().unwrap();
    assert_eq!(row.state, SandboxState::Failed);
    assert_eq!(
        row.accounting.release,
        ReservationRelease::Legacy(LegacyRelease::OperatorAttested)
    );
    assert_eq!(m.store.operator_release_count().unwrap(), 1);
    assert_eq!(reserved_sandboxes(&m).await, 0);

    // Another uid's create now fits, and the released row deletes like any FAILED
    // row whose create allocated nothing.
    let fresh = m
        .create_owned(CreateRequest::default(), 2000)
        .await
        .unwrap();
    assert_eq!(fresh.state, SandboxState::Ready);
    let deleted = m.delete(&stuck.id).await.unwrap();
    assert_eq!(deleted.state, SandboxState::Deleted);
    assert_eq!(fake.state().removed, Vec::<String>::new());
}

#[tokio::test]
async fn a_run_a_live_row_owns_is_explained() {
    let (m, fake) = manager_with_slots(2);
    let live = m
        .create_owned(CreateRequest::default(), 1000)
        .await
        .unwrap();
    let stuck = ambiguous(&m, &fake, 1000).await;
    let backend = live.backend_id.clone().unwrap();
    let runs = Runs(vec![
        Box::leak(backend.into_boxed_str()),
        KILN_RUNS_RESERVED,
    ]);
    m.release_ambiguous(request(&stuck.id), &runs)
        .await
        .unwrap();
    assert!(!m.store.sandbox(&stuck.id).unwrap().unwrap().is_charged());
}

#[tokio::test]
async fn an_unexplained_run_refuses_and_names_it() {
    let (m, fake) = one_slot();
    let stuck = ambiguous(&m, &fake, 1000).await;
    for status in [BackendStatus::Running, BackendStatus::Stale] {
        let stray = fake.insert(status);
        let refusal = m
            .release_ambiguous(request(&stuck.id), &Runs(vec![]))
            .await
            .unwrap_err();
        match &refusal {
            ReleaseRefusal::UnexplainedRuns(ids) => assert_eq!(ids, std::slice::from_ref(&stray)),
            other => panic!("{status:?}: {other:?}"),
        }
        assert!(refusal.to_string().contains("kiln gc ID"), "{refusal}");
        assert_eq!(
            crate::release_ambiguous::refusal_exit(&refusal),
            crate::release_ambiguous::EXIT_NOT_PROVED
        );
        still_charged(&m, &stuck.id, 1).await;
        fake.state().sandboxes.remove(&stray);
    }
}

#[tokio::test]
async fn a_reappearing_id_of_a_compensated_row_is_unexplained() {
    let (m, fake) = manager_with_slots(2);
    let stuck = ambiguous(&m, &fake, 1000).await;
    let reappeared = fake.insert(BackendStatus::Running);
    let mut compensated = stuck.clone();
    compensated.id = new_id("sb");
    compensated.backend_id = Some(reappeared.clone());
    compensated.failure_reason = Some("prior compensation proved this ID absent".into());
    m.store.insert_sandbox(&compensated).unwrap();
    let refusal = m
        .release_ambiguous(request(&stuck.id), &Runs(vec![]))
        .await
        .unwrap_err();
    assert!(
        matches!(&refusal, ReleaseRefusal::UnexplainedRuns(ids) if ids == &[reappeared]),
        "{refusal:?}"
    );
    still_charged(&m, &stuck.id, 1).await;
}

#[tokio::test]
async fn a_listing_error_partial_listing_or_deadline_refuses() {
    let (m, fake) = one_slot();
    let stuck = ambiguous(&m, &fake, 1000).await;
    type BreakIt = fn(&FakeRuntime);
    let cases: [(&str, BreakIt); 4] = [
        ("listing error", |f| f.state().fail_list = true),
        ("partial listing", |f| f.state().list_incomplete = true),
        ("backend unavailable", |f| f.state().unavailable = true),
        ("duplicated record", |f| {
            let id = f.insert(BackendStatus::Running);
            f.state().listed_twice.push(id);
        }),
    ];
    for (name, break_it) in cases {
        break_it(&fake);
        let refusal = m
            .release_ambiguous(request(&stuck.id), &Runs(vec![]))
            .await
            .unwrap_err();
        assert!(
            matches!(refusal, ReleaseRefusal::Inventory(_)),
            "{name}: {refusal:?}"
        );
        still_charged(&m, &stuck.id, 1).await;
        let mut s = fake.state();
        s.fail_list = false;
        s.list_incomplete = false;
        s.unavailable = false;
        s.listed_twice.clear();
        s.sandboxes.clear();
    }
}

#[tokio::test]
async fn a_backend_that_misses_its_deadline_refuses() {
    let fake = FakeRuntime::default();
    let m: M = Arc::new(Manager::new(
        fake.clone(),
        Store::open_in_memory().unwrap(),
        Limits {
            max_sandboxes: 1,
            health_probe_timeout: std::time::Duration::from_millis(50),
            ..Limits::default()
        },
    ));
    let stuck = ambiguous(&m, &fake, 1000).await;
    // Never released: the version probe runs into reconcile's own deadline.
    fake.state().version_gate = Some(FakeGate::default());
    let refusal = m
        .release_ambiguous(request(&stuck.id), &Runs(vec![]))
        .await
        .unwrap_err();
    assert!(
        matches!(&refusal, ReleaseRefusal::Inventory(e) if e.contains("timed out")),
        "{refusal:?}"
    );
    still_charged(&m, &stuck.id, 1).await;
}

#[tokio::test]
async fn a_run_directory_kilns_listing_skips_refuses() {
    let (m, fake) = one_slot();
    let stuck = ambiguous(&m, &fake, 1000).await;
    // A create that died before shim.pid leaves a directory `kiln ls` never lists.
    for stray in ["0123456789abcdef", ".removing-x", ".staging-x"] {
        let refusal = m
            .release_ambiguous(request(&stuck.id), &Runs(vec![KILN_RUNS_RESERVED, stray]))
            .await
            .unwrap_err();
        assert!(
            matches!(&refusal, ReleaseRefusal::UnexplainedRunDirectories(names) if names == &[stray.to_string()]),
            "{stray}: {refusal:?}"
        );
        assert!(refusal.to_string().contains(stray), "{refusal}");
        still_charged(&m, &stuck.id, 1).await;
    }
    let refusal = m
        .release_ambiguous(request(&stuck.id), &UnreadableRuns)
        .await
        .unwrap_err();
    assert!(
        matches!(refusal, ReleaseRefusal::Inventory(_)),
        "{refusal:?}"
    );
    still_charged(&m, &stuck.id, 1).await;
}

#[tokio::test]
async fn only_a_charged_ambiguous_failed_row_without_a_backend_is_eligible() {
    let (m, fake) = manager_with_slots(8);
    let stuck = ambiguous(&m, &fake, 1000).await;
    let refused = |refusal: ReleaseRefusal, needle: &str| {
        assert!(refusal.is_ineligible(), "{refusal:?}");
        assert_eq!(
            crate::release_ambiguous::refusal_exit(&refusal),
            crate::release_ambiguous::EXIT_INELIGIBLE
        );
        assert!(refusal.to_string().contains(needle), "{refusal}");
    };

    // Unknown.
    let unknown = new_id("sb");
    let r = m.release_ambiguous(request(&unknown), &Runs(vec![])).await;
    refused(r.unwrap_err(), "no such sandbox");

    // A live row with a backend ID, and a FAILED one whose ID compensation proved gone.
    let live = m
        .create_owned(CreateRequest::default(), 1000)
        .await
        .unwrap();
    let r = m.release_ambiguous(request(&live.id), &Runs(vec![])).await;
    refused(r.unwrap_err(), "READY");
    let mut compensated = stuck.clone();
    compensated.id = new_id("sb");
    compensated.backend_id = Some("f00d-gone".into());
    m.store.insert_sandbox(&compensated).unwrap();
    let r = m
        .release_ambiguous(request(&compensated.id), &Runs(vec![]))
        .await;
    refused(r.unwrap_err(), "backend ID f00d-gone");

    // A create proved not created is already released.
    fake.state().fail_create_definitely = Some("image missing".into());
    m.create_owned(CreateRequest::default(), 1000)
        .await
        .unwrap_err();
    fake.state().fail_create_definitely = None;
    let definite = m
        .store
        .sandboxes(true)
        .unwrap()
        .into_iter()
        .find(|s| s.create_certainty == CreateCertainty::DefinitelyNotCreated)
        .unwrap();
    let r = m
        .release_ambiguous(request(&definite.id), &Runs(vec![]))
        .await;
    refused(r.unwrap_err(), "definitely not created");

    // A bad reason.
    let reserved = reserved_sandboxes(&m).await;
    for reason in ["", "   ", "tab\there", "line\nbreak", &"x".repeat(513)] {
        let r = m
            .release_ambiguous(
                ReleaseRequest {
                    reason,
                    ..request(&stuck.id)
                },
                &Runs(vec![]),
            )
            .await;
        assert!(r.unwrap_err().is_ineligible(), "{reason:?}");
    }
    still_charged(&m, &stuck.id, reserved).await;

    // Released once; a second release is refused and writes no second audit row.
    m.release_ambiguous(request(&stuck.id), &Runs(vec![]))
        .await
        .unwrap();
    let r = m.release_ambiguous(request(&stuck.id), &Runs(vec![])).await;
    refused(r.unwrap_err(), "already released");
    assert_eq!(m.store.operator_release_count().unwrap(), 1);
}

#[tokio::test]
async fn a_fenced_row_is_never_eligible() {
    let (m, fake) = one_slot();
    let mut row = ambiguous(&m, &fake, 1000).await;
    assert_eq!(crate::store::operator_release_refusal(&row), None);
    // The same facts on an absence-fenced allocation: only its receipt releases it.
    row.accounting.regime = crate::model::AccountingRegime::AbsenceFenced;
    let why = crate::store::operator_release_refusal(&row).unwrap();
    assert!(why.contains("absence-fenced"), "{why}");
}

#[tokio::test]
async fn a_keyed_retry_after_the_release_answers_as_after_a_definite_failure() {
    let (m, fake) = manager_with_slots(4);
    let key = |id: &str| CreateKey {
        request_id: id.into(),
        sha256: Digest::parse(&"ab".repeat(32)).unwrap(),
    };
    // A keyed create answers with its FAILED row rather than an error.
    fake.state().fail_create = Some("kiln exited 1 after allocating".into());
    let first = m
        .create_keyed(Ok(CreateRequest::default()), 1000, key("ambiguous"), None)
        .await
        .unwrap();
    assert_eq!(first.state, SandboxState::Failed);
    fake.state().fail_create = None;
    fake.state().fail_create_definitely = Some("image missing".into());
    m.create_keyed(Ok(CreateRequest::default()), 1000, key("definite"), None)
        .await
        .unwrap();
    fake.state().fail_create_definitely = None;

    let ambiguous = m
        .create_keyed(Ok(CreateRequest::default()), 1000, key("ambiguous"), None)
        .await
        .unwrap();
    assert!(ambiguous.is_charged());
    m.release_ambiguous(request(&ambiguous.id), &Runs(vec![]))
        .await
        .unwrap();

    let created = fake.state().created.len();
    let after_release = m
        .create_keyed(Ok(CreateRequest::default()), 1000, key("ambiguous"), None)
        .await
        .unwrap();
    let after_definite = m
        .create_keyed(Ok(CreateRequest::default()), 1000, key("definite"), None)
        .await
        .unwrap();
    // Both answer with their recorded FAILED row, uncharged, and create nothing.
    for answered in [&after_release, &after_definite] {
        assert_eq!(answered.state, SandboxState::Failed);
        assert!(!answered.is_charged());
        assert!(answered.backend_id.is_none());
    }
    assert_eq!(after_release.id, ambiguous.id);
    assert_eq!(fake.state().created.len(), created);
    // And both records are released the same way: Delete, then the key.
    for row in [&after_release, &after_definite] {
        let deleted = m.delete_releasing(&row.id, true).await.unwrap();
        assert_eq!(deleted.state, SandboxState::Deleted);
        assert!(deleted.lifecycle.request_id_released_at_ms.is_some());
    }
    let retried = m
        .create_keyed(Ok(CreateRequest::default()), 1000, key("ambiguous"), None)
        .await
        .unwrap();
    assert_ne!(retried.id, ambiguous.id);
    assert_eq!(retried.state, SandboxState::Ready);
}
