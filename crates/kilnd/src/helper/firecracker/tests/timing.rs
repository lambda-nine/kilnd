//! M3-1's create timings through the real H and L, P and S processes (fake effects): one
//! timing line per create once it ends, with H's, L's, M's and P's steps, and a report
//! that carries no secret of the create it describes.
use super::*;
use crate::helper::firecracker::timing::{self, Outcome, Select};
use crate::helper::firecracker::workers::SupervisorEvent;

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

/// A node config with no profile, for a supervisor link this test drives alone.
fn bare_config(root: &Path) -> NodeConfig {
    let walk = walk_for(root);
    let node_id = Id128::random();
    NodeConfig {
        node_id,
        ledger: LedgerConfig {
            directory: root.join("ledger"),
            policy: walk.clone(),
            node_id,
            ceilings: NodeCeilings::default(),
            shared: SharedReserve::default(),
            max_enrolled: DEFAULT_MAX_ENROLLED,
            compaction: CompactionPolicy::default(),
        },
        ranges: IdentityRanges::default(),
        profiles: Vec::new(),
        walk,
        gate: ManifestGate::TestApproved,
        observation: ObservationBackend::FakeDirectory(root.join("fake")),
        timings: Timings::default(),
        helper_image: None,
        // SAFETY: geteuid has no preconditions.
        helper_uid: unsafe { libc::geteuid() },
        max_enrolled: DEFAULT_MAX_ENROLLED,
        test: TestInjection::default(),
    }
}

/// What H saw from one supervisor link: each event, and for a record the moment H sent
/// its answer.
struct Seen {
    event: SupervisorEvent,
    answered_ns: Option<u64>,
}

/// Runs `drive` on a real `Link` whose H is a thread here that answers every record.
fn through_link(drive: impl FnOnce(&mut super::super::supervisor::Link<'_>)) -> Vec<Seen> {
    use super::super::workers::{Endpoint, Received, SupervisorCommand, SupervisorContext};
    let temp = tempfile::tempdir().unwrap();
    let (s_end, h_end) = std::os::unix::net::UnixStream::pair().unwrap();
    let (watch, _monitor) = std::os::unix::net::UnixStream::pair().unwrap();
    let helper = std::thread::spawn(move || {
        let mut h = Endpoint::new(h_end);
        let mut seen = Vec::new();
        loop {
            match h.receive::<SupervisorEvent>(Duration::from_millis(20)) {
                Ok(Received::Message { body, .. }) => {
                    let answered_ns = if let SupervisorEvent::Record { seq, .. } = &body {
                        let at = timing::now();
                        h.send(
                            0,
                            &SupervisorCommand::Recorded { seq: *seq, ok: true },
                            Duration::from_secs(1),
                        )
                        .unwrap();
                        Some(at)
                    } else {
                        None
                    };
                    seen.push(Seen {
                        event: body,
                        answered_ns,
                    });
                }
                Ok(Received::Idle) => {}
                Ok(Received::Closed) | Err(_) => return seen,
            }
        }
    });
    let mut context = SupervisorContext {
        config: Arc::new(bare_config(temp.path())),
        instance: Id128::random(),
        allocation: Id128::random(),
        profile: PROFILE.into(),
        control: Endpoint::new(s_end),
        watch,
        descriptors: None,
    };
    {
        let mut link = super::super::supervisor::Link::new(&mut context, u64::MAX);
        drive(&mut link);
    }
    drop(context);
    helper.join().unwrap()
}

fn names(steps: &[timing::Step]) -> Vec<&'static str> {
    steps.iter().map(|s| s.name.as_str()).collect()
}

/// M3-1 follow-up: S's frames carry S's steps. A record carries the steps finished before
/// it; READY's own step stays open until H answers, and comes on `Ready`, which S sends
/// only after that answer. A refusal and an expiry carry the step they stopped in.
#[test]
fn m3_s_frames_carry_its_steps_and_readys_tail_follows_the_answer() {
    use super::super::supervisor::{Abort, SupervisorRecord};
    let seen = through_link(|link| {
        link.step("cgroup").unwrap();
        link.step("join").unwrap();
        link.record(SupervisorRecord::Initialize).unwrap();
        link.step("broker_ready").unwrap();
        link.record_ready().unwrap();
        link.report_ready("boot".into(), "inner".into());
    });
    let [first, ready_record, ready] = &seen[..] else {
        panic!("three frames");
    };
    let SupervisorEvent::Record { steps, .. } = &first.event else {
        panic!("{:?}", first.event);
    };
    assert_eq!(names(steps), ["s.cgroup"], "the open step stays for later");
    let SupervisorEvent::Record { steps, record, .. } = &ready_record.event else {
        panic!("{:?}", ready_record.event);
    };
    assert!(
        matches!(record, SupervisorRecord::Phase { to, .. } if to == "ready"),
        "{record:?}"
    );
    assert_eq!(names(steps), ["s.join", "s.broker_ready"]);
    let SupervisorEvent::Ready { steps, .. } = &ready.event else {
        panic!("{:?}", ready.event);
    };
    assert_eq!(names(steps), [timing::READY_TAIL]);
    let tail = steps[0];
    assert_eq!(tail.records, 1, "{tail:?}");
    assert!(
        tail.end_ns >= ready_record.answered_ns.unwrap(),
        "READY's step ends at H's answer: {tail:?}"
    );

    for (abort, step) in [
        (Abort::Refused("no".into()), "s.loop"),
        (Abort::Expired, "s.mkfs"),
    ] {
        let expired = matches!(abort, Abort::Expired);
        let seen = through_link(move |link| {
            link.step(step.strip_prefix("s.").unwrap()).unwrap();
            link.report_abort(abort);
        });
        let steps = match &seen[..] {
            [Seen {
                event: SupervisorEvent::LaunchRefused { steps, .. },
                ..
            }] if !expired => steps,
            [Seen {
                event: SupervisorEvent::SetupExpired { steps },
                ..
            }] if expired => steps,
            other => panic!("{:?}", other.iter().map(|s| &s.event).collect::<Vec<_>>()),
        };
        assert_eq!(names(steps), [step]);
    }
}

/// The only timing record so far, once it is logged.
async fn only_record(fixture: &Fixture) -> timing::Record {
    let end = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let records = timing::read_records(fixture.log().as_bytes(), Select::Last(5)).unwrap();
        if let Some(record) = records.into_iter().next() {
            return record;
        }
        assert!(std::time::Instant::now() < end, "{}", fixture.log());
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// M3-1 follow-up: P's refusals carry P's clock, up to the step that refused, as its
/// successful replies do. A changed artifact refuses at its hash.
#[tokio::test]
async fn m3_a_p_refusals_carry_ps_steps() {
    let altered = |fixture: &Fixture| {
        let path = fixture.root.join("bundle").join("rootfs.squashfs");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut changed = std::fs::read(&path).unwrap();
        changed.push(b' ');
        std::fs::write(&path, &changed).unwrap();
    };
    // Preflight: refused after its token was issued.
    let fixture = Fixture::new(NodeOptions::default()).await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    altered(&fixture);
    assert!(
        runtime
            .prepare(&prep(instance), &spec(), deadline(10), &no_cancel())
            .await
            .is_err()
    );
    let record = only_record(&fixture).await;
    assert_eq!(record.outcome, Outcome::PreflightRefused);
    let named = names(&record.steps);
    for wanted in ["p.preflight", "p.preflight.walk", "p.preflight.hash.rootfs"] {
        assert!(named.contains(&wanted), "{wanted}: {named:?}");
    }
    assert!(!named.contains(&"p.preflight.table"), "{named:?}");

    // Revalidation: rejected at Create.
    let fixture = Fixture::new(NodeOptions::default()).await;
    let runtime = fixture.runtime(instance, Id128::random());
    let (context, plan) = issued(&runtime, instance).await;
    altered(&fixture);
    let reply = raw_create(&fixture, &context, epoch_of(&runtime).await, &plan).await;
    assert_eq!(class_of(&reply), AmbiguousClass::CatalogMismatch);
    let record = only_record(&fixture).await;
    assert_eq!(record.outcome, Outcome::Rejected);
    let named = names(&record.steps);
    for wanted in [
        "p.revalidate",
        "p.revalidate.verify_plan",
        "p.revalidate.walk",
        "p.revalidate.hash.rootfs",
    ] {
        assert!(named.contains(&wanted), "{wanted}: {named:?}");
    }
    assert!(!named.contains(&"p.revalidate.table"), "{named:?}");
}

/// M3-1 follow-up: through the real H, L and a supervisor that journals READY through a
/// real `Link` (fake effects otherwise), the line is written once S's last step has
/// arrived, after H answered READY: complete, with `s.journal_ready` ending no earlier
/// than H's own handling of the READY record.
#[tokio::test]
async fn m3_a_ready_line_waits_for_the_supervisors_last_step() {
    let fixture = Fixture::new(NodeOptions {
        effects: vec!["ready".into()],
        ..NodeOptions::default()
    })
    .await;
    let instance = Id128::random();
    let runtime = fixture.runtime(instance, Id128::random());
    let (context, plan) = issued(&runtime, instance).await;
    create_accepted(&fixture, &runtime, &context, &plan).await;
    timing_line(&fixture, context.allocation_id).await;
    let records = timing::read_records(
        fixture.log().as_bytes(),
        Select::Allocation(context.allocation_id),
    )
    .unwrap();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(
        (record.outcome, record.incomplete),
        (Outcome::Ready, false),
        "{record:?}"
    );
    let step = |name: &str| {
        record
            .steps
            .iter()
            .find(|s| s.name.as_str() == name)
            .unwrap_or_else(|| panic!("{name} missing: {:?}", names(&record.steps)))
    };
    let committed = step(timing::READY_RECORD);
    let tail = step(timing::READY_TAIL);
    step("s.broker_ready");
    step(timing::BOOTING_RECORD);
    assert!(
        tail.end_ns >= committed.end_ns && tail.records == 1,
        "READY's step ends at H's answer: {tail:?} {committed:?}"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        fixture.log().matches(timing::LINE_PREFIX).count(),
        1,
        "one line per create"
    );
}
