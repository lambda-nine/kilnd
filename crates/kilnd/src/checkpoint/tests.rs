use super::wire::*;
use super::*;

pub(crate) const INSTANCE: &str = "00112233445566778899aabbccddeeff";
pub(crate) const CHECKPOINT: &str = "cp-0123456789abcdef0123456789abcdef";
const DIGEST: &str = "a4a64bb84cfc3abc7a7604ebcafccea446513ab0f2265036c677eda37c8ed3ba";
const BINDING: &str = "bc29aba1f548315a45d64dc0734e38365b6310f3b6b994135b9db85533537138";
const IMAGE: &str = "3630d63e00000000000000000000000000000000000000000000000000000000";

pub(crate) fn target() -> ArtifactTarget {
    ArtifactTarget {
        instance: Id128::parse(INSTANCE).unwrap(),
        checkpoint: CheckpointId::parse(CHECKPOINT).unwrap(),
        generation: 1,
    }
}

pub(crate) fn binding() -> CaptureBinding {
    CaptureBinding {
        target: target(),
        operation: Id128::parse("0000000000000000000000000000c0de").unwrap(),
        source: "0123456789abcdef".into(),
        limit_bytes: 1 << 30,
    }
}

/// kiln's record for `target()` with these charge figures.
pub(crate) fn record_text(generation: u64, limit: u64) -> String {
    format!(
        "kiln-checkpoint-record 1\ninstance {INSTANCE}\ncheckpoint {CHECKPOINT}\ngeneration {generation}\n\
         content-sha256 {DIGEST}\nbinding-sha256 {BINDING}\nimage alpine\nimage-sha256 {IMAGE}\n\
         entries 3\nlogical-bytes 4096\nallocated-bytes 65536\ncharge-bytes 98304\nlimit-bytes {limit}\n"
    )
}

pub(crate) fn content() -> Digest {
    Digest::parse(DIGEST).unwrap()
}

fn complete_evidence() -> Evidence {
    let b = binding();
    let record = ArtifactRecord::parse(&record_text(1, b.limit_bytes)).unwrap();
    Evidence {
        version: EVIDENCE_VERSION,
        instance: b.target.instance,
        checkpoint: b.target.checkpoint.clone(),
        generation: 1,
        operation: b.operation,
        helper_epoch: Id128::parse("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap(),
        boot_id: Id128::parse("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap(),
        fact: Fact::Complete(Box::new(CompleteFact {
            source: b.source,
            content_sha256: record.content_sha256,
            binding_sha256: record.binding_sha256,
            image: record.image,
            image_sha256: record.image_sha256,
            entries: record.entries,
            logical_bytes: record.logical_bytes,
            allocated_bytes: record.allocated_bytes,
            charge_bytes: record.charge_bytes,
            limit_bytes: record.limit_bytes,
        })),
    }
}

#[test]
fn checkpoint_ids_have_one_spelling() {
    assert!(CheckpointId::parse(CHECKPOINT).is_ok());
    for bad in [
        "",
        "cp-",
        "cp-0123456789ABCDEF0123456789abcdef",
        "cp-0123456789abcdef0123456789abcde",
        "cp-0123456789abcdef0123456789abcdef0",
        "sb-0123456789abcdef0123456789abcdef",
        "cp-../../../../../../../../../../etc",
        "CP-0123456789abcdef0123456789abcdef",
    ] {
        assert!(CheckpointId::parse(bad).is_err(), "{bad}");
        assert!(serde_json::from_value::<CheckpointId>(bad.into()).is_err());
    }
    assert!(CheckpointId::parse(CheckpointId::random().as_str()).is_ok());
}

#[test]
fn bindings_validate_their_bounds() {
    assert!(binding().validate().is_ok());
    let mut b = binding();
    b.target.generation = 0;
    assert!(b.validate().is_err());
    for limit in [0, MIN_LIMIT_BYTES - 1, MAX_LIMIT_BYTES + 1] {
        let mut b = binding();
        b.limit_bytes = limit;
        assert!(b.validate().is_err(), "{limit}");
    }
    for source in ["", "../x", "ab cd", "-0123"] {
        let mut b = binding();
        b.source = source.into();
        assert!(b.validate().is_err(), "{source}");
    }
}

#[test]
fn the_kiln_record_parser_is_strict() {
    let text = record_text(1, 1 << 30);
    let record = ArtifactRecord::parse(&text).unwrap();
    assert!(record.names(&target()));
    assert_eq!(record.charge_bytes, 98304);
    let mut other = target();
    other.generation = 2;
    assert!(!record.names(&other));
    let mutations: Vec<String> = vec![
        text.trim_end().to_string(),
        format!("{text}extra 1\n"),
        text.replace("generation 1", "generation 01"),
        text.replace("generation 1", "generation 0"),
        text.replace("entries 3", "entries 0"),
        text.replace("entries 3", "entries +3"),
        text.replace("charge-bytes 98304", "charge-bytes 0"),
        text.replace("charge-bytes 98304", "charge-bytes 2000000000"),
        text.replace("allocated-bytes 65536", "allocated-bytes 99999"),
        text.replace("content-sha256 a4", "content-sha256 A4"),
        text.replace("image alpine", "image ../alpine"),
        text.replace("instance ", "instance  "),
        text.replace("kiln-checkpoint-record 1", "kiln-checkpoint-record 2"),
        text.replace("logical-bytes", "logical_bytes"),
        text.replace(
            "\nentries 3\nlogical-bytes 4096",
            "\nlogical-bytes 4096\nentries 3",
        ),
        text.replace("limit-bytes 1073741824", "limit-bytes 18446744073709551616"),
    ];
    for bad in mutations {
        assert!(ArtifactRecord::parse(&bad).is_err(), "{bad:?}");
    }
}

#[test]
fn failure_records_keep_only_known_tokens() {
    let parse = |t: &str| parse_failure(t);
    assert_eq!(
        parse("kiln-checkpoint-failure 1\nreason checkpoint_busy\ndetail held\n").unwrap(),
        (Reason::Busy, "held".into())
    );
    assert_eq!(
        parse(
            "kiln-checkpoint-failure 1\nreason sandbox_unsupported:workspace_checkpoint\ndetail \n"
        )
        .unwrap(),
        (Reason::SandboxUnsupported, String::new())
    );
    // An unknown token never becomes a more specific class.
    assert_eq!(
        parse("kiln-checkpoint-failure 1\nreason checkpoint_new_thing\ndetail x\n")
            .unwrap()
            .0,
        Reason::Io
    );
    let long = format!(
        "kiln-checkpoint-failure 1\nreason checkpoint_io\ndetail {}\x07\n",
        "x".repeat(600)
    );
    assert_eq!(parse(&long).unwrap().1.chars().count(), 512);
    for bad in [
        "",
        "kiln-checkpoint-failure 1\nreason checkpoint_io\n",
        "kiln-checkpoint-failure 1\nreason checkpoint_io\ndetail x",
        "kiln-checkpoint-failure 1\nreason checkpoint_io\ndetail x\nmore\n",
        "kiln-checkpoint-failure 2\nreason checkpoint_io\ndetail x\n",
    ] {
        assert!(parse(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn reasons_serialize_as_their_tokens() {
    for reason in Reason::ALL {
        let json = serde_json::to_value(reason).unwrap();
        assert_eq!(json, serde_json::Value::from(reason.token()));
        assert_eq!(Reason::from_token(reason.token()), Some(reason));
        assert_eq!(serde_json::from_value::<Reason>(json).unwrap(), reason);
    }
    assert_eq!(Reason::from_token("checkpoint_busy "), None);
}

/// The evidence golden: C4 stores these bytes and this ID, and must reproduce both.
#[test]
fn evidence_is_canonical_bounded_and_identified() {
    let sealed = complete_evidence().seal().unwrap();
    let bytes = sealed.evidence.canonical_bytes().unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(text.starts_with(
        r#"{"version":1,"instance":"00112233445566778899aabbccddeeff","checkpoint":"cp-0123456789abcdef0123456789abcdef","generation":1,"#
    ));
    assert_eq!(sealed.id.to_string(), EVIDENCE_GOLDEN_ID, "{text}");
    let mut input = b"kilnd.checkpoint-evidence.1\0".to_vec();
    input.extend_from_slice(&bytes);
    assert_eq!(sealed.id, Digest::of(&input));
    // Stored bytes decode only exactly.
    assert_eq!(SealedEvidence::decode(&bytes, sealed.id).unwrap(), sealed);
    let spaced = text.replacen(',', ", ", 1);
    assert!(SealedEvidence::decode(spaced.as_bytes(), sealed.id).is_err());
    assert!(SealedEvidence::decode(&bytes, Digest::of(b"other")).is_err());
    let unknown = text.replacen('{', r#"{"extra":1,"#, 1);
    assert!(SealedEvidence::decode(unknown.as_bytes(), sealed.id).is_err());
    assert!(SealedEvidence::decode(&vec![b' '; MAX_EVIDENCE_BYTES + 1], sealed.id).is_err());
    // A forged fact under the original ID is refused.
    let mut forged = sealed.clone();
    if let Fact::Complete(fact) = &mut forged.evidence.fact {
        fact.charge_bytes = 1;
    }
    assert!(forged.verify_complete(&binding()).is_err());
}

/// Reproduced by an independent Python encoder (`hashlib.sha256(domain + b"\0" + bytes)`).
const EVIDENCE_GOLDEN_ID: &str = "6c415b9f3ff66060f95e95e69539d5694f96eec0c8d772e09dd3450fc80c178e";

#[test]
fn evidence_is_accepted_only_for_what_was_dispatched() {
    let b = binding();
    let sealed = complete_evidence().seal().unwrap();
    assert!(sealed.verify_complete(&b).is_ok());
    let mut other = b.clone();
    other.target.generation = 2;
    assert!(sealed.verify_complete(&other).is_err());
    let mut other = b.clone();
    other.operation = Id128::random();
    assert!(sealed.verify_complete(&other).is_err());
    let mut other = b.clone();
    other.source = "fedcba9876543210".into();
    assert!(sealed.verify_complete(&other).is_err());
    let mut other = b.clone();
    other.limit_bytes = 2 << 30;
    assert!(sealed.verify_complete(&other).is_err());
    let mut other = b.clone();
    other.target.checkpoint = CheckpointId::random();
    assert!(sealed.verify_complete(&other).is_err());
    let mut other = b.clone();
    other.target.instance = Id128::random();
    assert!(sealed.verify_complete(&other).is_err());
    // The right artifact and nonce, the wrong kind of fact.
    for kind in ["absent", "reader_ended"] {
        assert!(
            sealed
                .verify(&Expected {
                    target: &b.target,
                    operation: b.operation,
                    kind,
                })
                .is_err()
        );
    }
    // COMPLETE outside kiln's invariants is refused even when correctly sealed.
    let mut bad = complete_evidence();
    if let Fact::Complete(fact) = &mut bad.fact {
        fact.charge_bytes = fact.limit_bytes + 1;
    }
    assert!(bad.seal().unwrap().verify_complete(&b).is_err());
}

fn epoch() -> Id128 {
    Id128::parse("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap()
}

#[test]
fn replies_are_checked_against_their_requests() {
    let b = binding();
    let capture = CheckpointOperation::Capture { binding: b.clone() };
    let complete = CheckpointResponse::Captured(Box::new(CaptureReply::Complete {
        evidence: complete_evidence().seal().unwrap(),
    }));
    assert!(complete.check(&capture, Some(epoch())).is_ok());
    // Another epoch, another binding, another kind of reply.
    assert!(complete.check(&capture, Some(Id128::random())).is_err());
    let mut other = b.clone();
    other.operation = Id128::random();
    assert!(
        complete
            .check(
                &CheckpointOperation::Capture { binding: other },
                Some(epoch())
            )
            .is_err()
    );
    let remove = CheckpointOperation::Remove {
        target: target(),
        operation: b.operation,
    };
    assert!(complete.check(&remove, Some(epoch())).is_err());
    // Absent evidence must be absence about this removal's nonce.
    let absent = |operation| {
        let mut e = complete_evidence();
        e.operation = operation;
        e.fact = Fact::Absent { existed: true };
        CheckpointResponse::Removed(Box::new(RemoveReply::Absent {
            evidence: e.seal().unwrap(),
        }))
    };
    assert!(absent(b.operation).check(&remove, Some(epoch())).is_ok());
    assert!(
        absent(Id128::random())
            .check(&remove, Some(epoch()))
            .is_err()
    );
    // A restore's evidence must agree with its outcome.
    let reader = Id128::random();
    let restore = CheckpointOperation::Restore {
        target: target(),
        content_sha256: content(),
        reader,
        spec: serde_json::from_value(serde_json::json!({
            "image": "alpine", "memory_bytes": 1, "cpu_millis": 1, "pids": 1, "disk_bytes": 1,
            "network": "none", "read_only_root": false, "writable_paths": [], "labels": {}
        }))
        .unwrap(),
    };
    let ended = |copy| {
        let mut e = complete_evidence();
        e.operation = reader;
        e.fact = Fact::ReaderEnded { copy };
        e.seal().unwrap()
    };
    let created = |copy| {
        CheckpointResponse::Restored(Box::new(RestoreReply::Created {
            backend_id: "0123456789abcdef".into(),
            evidence: ended(copy),
        }))
    };
    assert!(
        created(CopyOutcome::Complete)
            .check(&restore, Some(epoch()))
            .is_ok()
    );
    assert!(
        created(CopyOutcome::Unknown)
            .check(&restore, Some(epoch()))
            .is_err()
    );
    let not_created = CheckpointResponse::Restored(Box::new(RestoreReply::NotCreated {
        reason: Reason::SpecMismatch,
        detail: String::new(),
        evidence: ended(CopyOutcome::Complete),
    }));
    assert!(not_created.check(&restore, Some(epoch())).is_err());
    // Errors are typed answers, and pass.
    let busy = CheckpointResponse::Error(CheckpointError::new(CheckpointErrorKind::Busy, "x"));
    assert!(busy.check(&restore, Some(epoch())).is_ok());
    // An inspection replays a settled operation only about its own nonce.
    let inspect = |operation| CheckpointOperation::Inspect {
        target: target(),
        verify: false,
        operation,
    };
    let inspected = |state| {
        CheckpointResponse::Inspected(Box::new(ArtifactInspectReply {
            helper_epoch: epoch(),
            artifact: ArtifactView::NotListed,
            activity: Activity::default(),
            operation: state,
        }))
    };
    let settled = inspected(Some(OperationState::Settled(Box::new(complete.clone()))));
    assert!(
        settled
            .check(&inspect(Some(b.operation)), Some(epoch()))
            .is_ok()
    );
    assert!(
        settled
            .check(&inspect(Some(Id128::random())), Some(epoch()))
            .is_err()
    );
    assert!(settled.check(&inspect(None), Some(epoch())).is_err());
    let pending = inspected(Some(OperationState::Settled(Box::new(
        CheckpointResponse::Captured(Box::new(CaptureReply::Pending)),
    ))));
    assert!(
        pending
            .check(&inspect(Some(b.operation)), Some(epoch()))
            .is_err()
    );
    assert!(
        inspected(None)
            .check(&inspect(Some(b.operation)), Some(epoch()))
            .is_err()
    );
}
