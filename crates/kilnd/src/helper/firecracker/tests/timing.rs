//! M3-1's create timings through the real H and L, P and S processes (fake effects): one
//! timing line per create once it ends, with H's, L's, M's and P's steps, and a report
//! that carries no secret of the create it describes.
use super::*;
use crate::helper::firecracker::timing::{self, Outcome, Select};

/// As reconciliation would: a busy node's observation slot leaves the token charged and
/// ambiguous, never absent, until a later attempt proves it.
async fn fence_retrying(
    runtime: &FirecrackerRuntime,
    context: &CreateContext,
    plan: &PreparedCreate,
) -> FencedAbsence {
    for attempt in 0.. {
        match runtime
            .fence_absent(context, &plan.plan_digest(), deadline(20), &no_cancel())
            .await
        {
            Ok(receipt) => return fenced(receipt),
            Err(error) if attempt < 500 => {
                let _ = error;
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(error) => panic!("{error}"),
        }
    }
    unreachable!()
}

/// Whether `text` holds `number` as a whole number, not inside a longer one.
fn holds_number(text: &str, number: u64) -> bool {
    let needle = number.to_string();
    text.match_indices(&needle).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + needle.len()..].chars().next();
        !before.is_some_and(|c| c.is_ascii_digit()) && !after.is_some_and(|c| c.is_ascii_digit())
    })
}

async fn timing_line(fixture: &Fixture, allocation: Id128) -> String {
    let end = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(line) = fixture.log().lines().find(|line| {
            line.contains(timing::LINE_PREFIX) && line.contains(&allocation.to_string())
        }) {
            return line.to_string();
        }
        assert!(
            std::time::Instant::now() < end,
            "no timing line for {allocation}:\n{}",
            fixture.log()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The steps every accepted create times before S's gate opens, in this order: a
/// round trip's own row comes before the steps its worker timed inside it.
const ACCEPTED: &[&str] = &[
    "h.preflight.slot",
    "l.issue",
    "p.preflight",
    "p.preflight.walk",
    "p.preflight.manifest_read",
    "p.preflight.manifest_verify",
    "p.preflight.list",
    "p.preflight.table",
    "p.preflight.plan",
    "h.preflight.reply",
    "h.create.call",
    "h.create.serial",
    "l.lookup",
    "p.revalidate",
    "p.revalidate.verify_plan",
    "p.revalidate.walk",
    "p.revalidate.manifest_read",
    "p.revalidate.manifest_verify",
    "p.revalidate.list",
    "p.revalidate.table",
    "l.admit",
    "h.effects_check",
    "h.spawn_s",
    "m.watch",
    "l.record_worker",
    "l.preparing",
    "h.prep_lease",
    "h.open_gate",
];

#[tokio::test]
async fn m3_a_create_logs_one_timing_line_whose_report_holds_no_secret() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let (context, plan) = issued(&runtime, instance).await;
    create_accepted(&fixture, &runtime, &context, &plan).await;
    // A duplicate Create of the same token is answered, but not timed again.
    let replayed = raw_create(&fixture, &context, epoch_of(&runtime).await, &plan).await;
    assert!(
        matches!(replayed, CreateReply::Accepted { replay: true, .. }),
        "{replayed:?}"
    );
    assert!(
        !fixture.log().contains(timing::LINE_PREFIX),
        "nothing is logged while the create is open"
    );
    fence_retrying(&runtime, &context, &plan).await;
    let line = timing_line(&fixture, context.allocation_id).await;
    assert_eq!(
        fixture.log().matches(timing::LINE_PREFIX).count(),
        1,
        "one line per create"
    );

    let records = timing::read_records(
        fixture.log().as_bytes(),
        Select::Allocation(context.allocation_id),
    )
    .unwrap();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    // Fake effects never reach READY: the fence ends the timeline.
    assert_eq!(record.outcome, Outcome::Absent);
    let names: Vec<&str> = record.steps.iter().map(|s| s.name.as_str()).collect();
    let mut at = 0;
    for wanted in ACCEPTED {
        let found = names[at..]
            .iter()
            .position(|name| name == wanted)
            .unwrap_or_else(|| panic!("{wanted} missing or out of order: {names:?}"));
        at += found + 1;
    }
    assert!(
        names.iter().any(|n| n.starts_with("p.preflight.hash.")),
        "{names:?}"
    );
    assert!(
        names.iter().any(|n| n.starts_with("p.revalidate.hash.")),
        "{names:?}"
    );
    assert_eq!(
        names.iter().filter(|n| **n == "h.create.call").count(),
        1,
        "the duplicate Create added nothing"
    );
    for step in &record.steps {
        assert!(step.end_ns >= step.start_ns, "{step:?}");
        assert!(
            step.end_ns < 60_000_000_000,
            "an offset from the Preflight: {step:?}"
        );
    }
    // P's own steps sit inside its round trip.
    let span = |name: &str| {
        record
            .steps
            .iter()
            .find(|s| s.name.as_str() == name)
            .unwrap()
    };
    let preflight = span("p.preflight");
    let walk = span("p.preflight.walk");
    assert!(walk.start_ns >= preflight.start_ns && walk.end_ns <= preflight.end_ns);

    let report = timing::report(
        fixture.log().as_bytes(),
        Select::Allocation(context.allocation_id),
        false,
    )
    .unwrap();
    assert!(report.contains("gap.daemon"), "{report}");
    assert!(report.contains("outcome absent"), "{report}");
    let summary = timing::report(fixture.log().as_bytes(), Select::Last(10), true).unwrap();
    assert!(summary.starts_with("creates 1\n"), "{summary}");

    // Plan section 10.3: no boot nonce, work UUID, token key, identity or other ID but
    // the allocation's reaches the line or either report.
    let document = crate::firecracker::strict_json(plan.backend_plan()).unwrap();
    let subs = &document["substitutions"];
    let nonce = subs["boot_nonce"].as_str().unwrap().to_string();
    let work_uuid = subs["work_uuid"].as_str().unwrap().to_string();
    assert_eq!(nonce.len(), 64);
    let key: String = fixture
        .read(|view| view.query_row("SELECT lower(hex(key)) FROM token_key", [], |r| r.get(0)));
    assert_eq!(key.len(), 64);
    let identities: Vec<u64> = ["uid", "gid", "relay_uid", "relay_gid"]
        .iter()
        .map(|name| subs[name]["value"].as_u64().unwrap())
        .chain([subs["cid"].as_u64().unwrap()])
        .collect();
    for text in [&line, &report, &summary] {
        let lower = text.to_lowercase();
        for secret in [
            nonce.as_str(),
            &nonce[..16],
            work_uuid.as_str(),
            &work_uuid.replace('-', ""),
            key.as_str(),
            &key[..16],
            &instance.to_string(),
            &context.sandbox_id,
        ] {
            assert!(
                !lower.contains(&secret.to_lowercase()),
                "{secret} in:\n{text}"
            );
        }
        for identity in &identities {
            assert!(
                !holds_number(text, *identity),
                "identity {identity} in:\n{text}"
            );
        }
    }
}

/// Preflight's refusal after the token is issued ends its timeline at once.
#[tokio::test]
async fn m3_a_preflight_refused_after_issue_ends_its_timeline() {
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    fixture.fault("H.preflight.drop_public_reply");
    assert!(
        runtime
            .prepare(&prep(instance), &spec(), deadline(10), &no_cancel())
            .await
            .is_err()
    );
    let end = std::time::Instant::now() + Duration::from_secs(20);
    let record = loop {
        let records = timing::read_records(fixture.log().as_bytes(), Select::Last(5)).unwrap();
        if let Some(record) = records.into_iter().next() {
            break record;
        }
        assert!(std::time::Instant::now() < end, "{}", fixture.log());
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(record.outcome, Outcome::PreflightRefused);
    let names: Vec<&str> = record.steps.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names[..2], ["h.preflight.slot", "l.issue"], "{names:?}");
    assert!(names.contains(&"p.preflight"), "{names:?}");
    assert!(!names.contains(&"h.preflight.reply"), "{names:?}");
}
