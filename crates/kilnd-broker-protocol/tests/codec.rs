//! One unit test per rejection the codec makes (design 5.2, 5.3, 5.6), plus golden
//! encodings and the cross-check of the spec digest against B1's shared fixtures.

mod common;

use common::*;
use kilnd_broker_protocol::budget::{Budget, ExchangeBudget, ExecBudget, HostBudget};
use kilnd_broker_protocol::exchange::{GuestConnection, GuestEvent, HostConnection, HostEvent};
use kilnd_broker_protocol::message::*;
use kilnd_broker_protocol::types::*;
use kilnd_broker_protocol::*;

struct Free;
impl Budget for Free {
    fn admit(&mut self, _: &Header) -> Result<()> {
        Ok(())
    }
}

fn header(kind: Kind, len: u32, seq: u32) -> Header {
    Header {
        kind,
        payload_len: len,
        request_id: Id128([0x11; 16]),
        sequence: seq,
    }
}

fn raw(kind: Kind, len: u32) -> [u8; HEADER_LEN] {
    header(kind, len, 0).encode()
}

fn frame(kind: Kind, id: Id128, seq: u32, message: &Message) -> Frame {
    let payload = message.encode_payload().unwrap();
    Frame {
        header: Header {
            kind,
            payload_len: payload.len() as u32,
            request_id: id,
            sequence: seq,
        },
        payload,
    }
}

fn decode_one(direction: Direction, bytes: &[u8]) -> Result<Frame> {
    let mut decoder = FrameDecoder::new(direction);
    let mut at = 0;
    loop {
        let (used, frame) = decoder.feed(&bytes[at..], &mut Free)?;
        at += used;
        if let Some(frame) = frame {
            return Ok(frame);
        }
        if at == bytes.len() {
            decoder.finish()?;
            panic!("no frame and no error");
        }
    }
}

// ---- header ---------------------------------------------------------------------

#[test]
fn golden_header_bytes() {
    let h = Header {
        kind: Kind::Exec,
        payload_len: 0x0102_0304,
        request_id: Id128([0xab; 16]),
        sequence: 7,
    };
    let bytes = h.encode();
    assert_eq!(&bytes[..4], b"KGB1");
    assert_eq!(&bytes[4..8], &[0, 1, 0, 7]);
    assert_eq!(&bytes[8..12], &[0, 0, 0, 0]);
    assert_eq!(&bytes[12..16], &[1, 2, 3, 4]);
    assert_eq!(&bytes[16..32], &[0xab; 16]);
    assert_eq!(&bytes[32..36], &[0, 0, 0, 7]);
    assert_eq!(HEADER_LEN, 36);
}

#[test]
fn rejects_bad_magic_first() {
    let mut b = raw(Kind::Hello, 0);
    b[0] = b'X';
    b[4] = 9; // a bad version too: magic is checked first
    assert!(matches!(
        Header::parse(&b, Direction::HostToGuest),
        Err(ProtocolError::BadMagic(_))
    ));
}

#[test]
fn rejects_unsupported_versions() {
    for version in [0u16, 2, 0xffff] {
        let mut b = raw(Kind::Hello, 0);
        b[4..6].copy_from_slice(&version.to_be_bytes());
        assert_eq!(
            Header::parse(&b, Direction::HostToGuest),
            Err(ProtocolError::UnsupportedVersion(version))
        );
    }
}

#[test]
fn rejects_unknown_flags() {
    for flags in [1u32, 0x8000_0000, u32::MAX] {
        let mut b = raw(Kind::Hello, 0);
        b[8..12].copy_from_slice(&flags.to_be_bytes());
        assert_eq!(
            Header::parse(&b, Direction::HostToGuest),
            Err(ProtocolError::UnknownFlags(flags))
        );
    }
}

#[test]
fn rejects_unknown_kinds() {
    for kind in [0u16, 17, 0x100, 0xffff] {
        let mut b = raw(Kind::Hello, 0);
        b[6..8].copy_from_slice(&kind.to_be_bytes());
        assert_eq!(
            Header::parse(&b, Direction::HostToGuest),
            Err(ProtocolError::UnknownKind(kind))
        );
    }
    for kind in Kind::ALL {
        assert_eq!(Kind::from_u16(kind as u16), Ok(kind));
    }
}

#[test]
fn rejects_every_kind_travelling_the_wrong_way() {
    for kind in Kind::ALL {
        let wrong = match kind.direction() {
            Direction::HostToGuest => Direction::GuestToHost,
            Direction::GuestToHost => Direction::HostToGuest,
        };
        assert_eq!(
            Header::parse(&raw(kind, 0), wrong),
            Err(ProtocolError::WrongDirection {
                kind,
                direction: wrong
            })
        );
        assert!(Header::parse(&raw(kind, 0), kind.direction()).is_ok());
    }
}

#[test]
fn payload_bounds_per_kind_and_direction() {
    for kind in Kind::ALL {
        let max = kind.max_payload();
        let expected = if kind.is_data() {
            64 * 1024
        } else if kind.direction() == Direction::HostToGuest {
            384 * 1024
        } else {
            64 * 1024
        };
        assert_eq!(max, expected, "{kind:?}");
        assert!(Header::parse(&raw(kind, max), kind.direction()).is_ok());
        for len in [max + 1, u32::MAX] {
            assert_eq!(
                Header::parse(&raw(kind, len), kind.direction()),
                Err(ProtocolError::PayloadTooLarge { kind, len, max })
            );
        }
    }
}

// ---- strict JSON -----------------------------------------------------------------

fn nested(depth: usize, open: &str, close: &str) -> String {
    format!("{}1{}", open.repeat(depth), close.repeat(depth))
}

#[test]
fn json_depth_is_at_most_eight() {
    assert_eq!(json::check(nested(8, "[", "]").as_bytes()), Ok(()));
    assert_eq!(
        json::check(nested(9, "[", "]").as_bytes()),
        Err(ProtocolError::JsonDepth)
    );
    let objects = |d: usize| format!("{}1{}", "{\"a\":".repeat(d), "}".repeat(d));
    assert_eq!(json::check(objects(8).as_bytes()), Ok(()));
    assert_eq!(
        json::check(objects(9).as_bytes()),
        Err(ProtocolError::JsonDepth)
    );
    // A deep payload is refused before serde, which would recurse 128 levels.
    assert_eq!(
        json::check(nested(100_000, "[", "]").as_bytes()),
        Err(ProtocolError::JsonDepth)
    );
}

#[test]
fn json_floats_and_negative_zero_are_refused() {
    for text in [
        "1.0",
        "1e3",
        "1E3",
        "0.5",
        "-0",
        "-0.0",
        "[1,2.5]",
        "{\"a\":1e-1}",
    ] {
        assert_eq!(
            json::check(text.as_bytes()),
            Err(ProtocolError::JsonFloat),
            "{text}"
        );
    }
    for text in ["0", "-1", "18446744073709551615", "[0,-7]"] {
        assert_eq!(json::check(text.as_bytes()), Ok(()), "{text}");
    }
}

#[test]
fn json_duplicate_keys_are_refused_at_every_level_and_after_unescaping() {
    for text in [
        r#"{"a":1,"a":2}"#,
        r#"{"x":{"a":1,"a":1}}"#,
        r#"[{"a":1,"b":{"c":[{"d":1,"d":1}]}}]"#,
        r#"{"a":1,"\u0061":2}"#,
        r#"{"é":1,"\u00e9":2}"#,
    ] {
        assert_eq!(
            json::check(text.as_bytes()),
            Err(ProtocolError::JsonDuplicateKey),
            "{text}"
        );
    }
}

#[test]
fn json_syntax_errors() {
    for text in [
        "",
        " ",
        "{",
        "{\"a\"}",
        "{\"a\":}",
        "[1,]",
        "{\"a\":1,}",
        "01",
        "+1",
        "--1",
        "tru",
        "nul",
        "\"\\x\"",
        "\"\\u12\"",
        "\"\\ud800\"",
        "\"\\udc00\"",
        "\"\\ud800\\u0041\"",
        "\"a\u{1}b\"",
        "1 2",
        "{} x",
        "\u{feff}{}",
        "'a'",
    ] {
        assert!(
            matches!(
                json::check(text.as_bytes()),
                Err(ProtocolError::JsonSyntax(_))
            ),
            "{text:?}"
        );
    }
    assert_eq!(json::check(b"\"\\ud834\\udd1e\""), Ok(()));
    assert_eq!(json::check(b" {\"a\" : [ true , false , null ] } "), Ok(()));
}

#[test]
fn json_must_be_utf8() {
    assert_eq!(json::check(b"\"\xff\""), Err(ProtocolError::Utf8));
    assert_eq!(json::check(b"\"\xc3\""), Err(ProtocolError::Utf8));
}

#[test]
fn unknown_missing_and_mistyped_fields_are_schema_errors() {
    let mut rng = Rng::new(3);
    let good = json::to_vec(&Accepted { token: rng.id() });
    assert!(Message::decode(Kind::Accepted, good.clone()).is_ok());
    let cases = [
        r#"{"token":"00000000000000000000000000000000","extra":1}"#.to_string(),
        r#"{}"#.to_string(),
        r#"{"token":5}"#.to_string(),
        r#"[]"#.to_string(),
        r#"{"token":"0000000000000000000000000000000G"}"#.to_string(),
        r#"{"token":"0000000000000000000000000000000A"}"#.to_string(),
        r#"{"token":"000000000000000000000000000000"}"#.to_string(),
    ];
    for case in cases {
        assert!(
            matches!(
                Message::decode(Kind::Accepted, case.clone().into_bytes()),
                Err(ProtocolError::Schema(_))
            ),
            "{case}"
        );
    }
    // A nested struct variant refuses unknown fields too.
    let result = result(&mut rng, Id128([1; 16]));
    let mut value: serde_json::Value = serde_json::from_slice(&json::to_vec(&result)).unwrap();
    value["termination"] = serde_json::json!({"exited": {"code": 0, "extra": 1}});
    assert!(matches!(
        Message::decode(Kind::Result, serde_json::to_vec(&value).unwrap()),
        Err(ProtocolError::Schema(_))
    ));
}

#[test]
fn schema_messages_are_bounded() {
    let long = "k".repeat(10_000);
    let payload = format!(r#"{{"token":"00000000000000000000000000000000","{long}":1}}"#);
    match Message::decode(Kind::Accepted, payload.into_bytes()) {
        Err(ProtocolError::Schema(message)) => assert!(message.len() <= 256),
        other => panic!("{other:?}"),
    }
}

// ---- field bounds ----------------------------------------------------------------

fn sample_exec() -> Exec {
    Exec {
        token: Id128([7; 16]),
        execution_id: ExecutionId::new("ex-0123456789abcdef").unwrap(),
        argv: vec!["true".into()],
        stdin_bytes: 0,
        max_output: 1024,
        remaining_ms: 1000,
    }
}

#[test]
fn exec_field_bounds() {
    let ok = sample_exec();
    assert!(ok.validate().is_ok());
    let check = |f: fn(&mut Exec), expected: ProtocolError| {
        let mut e = sample_exec();
        f(&mut e);
        assert_eq!(e.validate(), Err(expected.clone()));
        // The same refusal on decode and on encode.
        let payload = json::to_vec(&e);
        assert_eq!(Message::decode(Kind::Exec, payload), Err(expected.clone()));
        assert_eq!(Message::Exec(e).encode_payload(), Err(expected));
    };
    check(
        |e| e.argv = vec!["a".into(); 4097],
        ProtocolError::FieldBound("argv count"),
    );
    check(|e| e.argv = Vec::new(), ProtocolError::InvalidField("argv"));
    check(
        |e| e.argv = vec![String::new()],
        ProtocolError::InvalidField("argv"),
    );
    check(
        |e| e.argv = vec!["a\0b".into()],
        ProtocolError::InvalidField("argv"),
    );
    check(
        |e| e.argv = vec!["a".repeat(256 * 1024)],
        ProtocolError::InvalidField("argv"),
    );
    check(
        |e| e.stdin_bytes = 1024 * 1024 + 1,
        ProtocolError::FieldBound("stdin_bytes"),
    );
    check(
        |e| e.max_output = 1024 * 1024 + 1,
        ProtocolError::FieldBound("max_output"),
    );
    check(
        |e| e.remaining_ms = 0,
        ProtocolError::FieldBound("remaining_ms"),
    );
    check(
        |e| e.remaining_ms = 3_600_001,
        ProtocolError::FieldBound("remaining_ms"),
    );
    let mut edge = sample_exec();
    edge.argv = vec!["a".into(); 4096];
    edge.stdin_bytes = 1024 * 1024;
    edge.max_output = 1024 * 1024;
    edge.remaining_ms = 3_600_000;
    assert!(edge.validate().is_ok());
}

#[test]
fn argv_within_256_kib_can_still_exceed_the_encoded_384_kib_bound() {
    // Every control character escapes to six bytes in JSON.
    let mut e = sample_exec();
    e.argv = vec!["p".into(), "\u{1}".repeat(100 * 1024)];
    assert!(e.validate().is_ok());
    let payload = Message::Exec(e).encode_payload().unwrap();
    assert!(payload.len() > 384 * 1024);
    assert!(matches!(
        encode_frame(Kind::Exec, Id128([7; 16]), 0, &payload),
        Err(ProtocolError::PayloadTooLarge {
            kind: Kind::Exec,
            ..
        })
    ));
}

#[test]
fn identifier_shapes() {
    assert!(Id128::parse(&"a".repeat(32)).is_some());
    for bad in [
        "",
        &"A".repeat(32),
        &"a".repeat(31),
        &"a".repeat(33),
        &"g".repeat(32),
    ] {
        assert!(Id128::parse(bad).is_none(), "{bad}");
    }
    assert!(Hex32::parse(&"0".repeat(64)).is_some());
    assert!(Hex32::parse(&"0".repeat(63)).is_none());
    assert!(SandboxId::new("sb-0123456789abcdef").is_some());
    for bad in [
        "sb-0123456789abcde",
        "sb-0123456789ABCDEF",
        "ex-0123456789abcdef",
        "sb_0123456789abcdef",
    ] {
        assert!(SandboxId::new(bad).is_none(), "{bad}");
    }
    assert!(ExecutionId::new("ex-0123456789abcdef").is_some());
    assert!(ExecutionId::new("sb-0123456789abcdef").is_none());
    assert!(BootId::new("0f8e2c1a-1b2c-3d4e-5f60-718293a4b5c6").is_some());
    assert!(BootId::new("0F8E2C1A-1B2C-3D4E-5F60-718293A4B5C6").is_none());
    assert!(BootId::new("0f8e2c1a1b2c3d4e5f60718293a4b5c6").is_none());
    assert!(WorkUuid::new("51b8e65e-23b9-4eba-a21c-7c1cce2c5f94").is_some());
    assert!(WorkUuid::new("51b8e65e-23b9-1eba-a21c-7c1cce2c5f94").is_none());
    assert!(WorkUuid::new("51b8e65e-23b9-4eba-c21c-7c1cce2c5f94").is_none());
    assert!(InnerId::new("18de453339a8cc89-3762").is_some());
    for bad in ["", "-18de", "18de 1", &"a".repeat(65), "xyz"] {
        assert!(InnerId::new(bad).is_none(), "{bad}");
    }
}

#[test]
fn wire_text_is_at_most_2048_bytes_and_narrows_on_a_boundary() {
    assert!(WireText::new("x".repeat(2048)).is_some());
    assert!(WireText::new("x".repeat(2049)).is_none());
    let (text, cut) = WireText::narrow(&format!("{}é", "x".repeat(2047)));
    assert!(cut);
    assert_eq!(text.as_str().len(), 2047);
    let payload = format!(
        r#"{{"code":"internal","state":"faulted","message":"{}"}}"#,
        "x".repeat(2049)
    );
    assert!(matches!(
        Message::decode(Kind::Error, payload.into_bytes()),
        Err(ProtocolError::Schema(_))
    ));
}

#[test]
fn result_facts_and_termination_bounds() {
    let mut rng = Rng::new(9);
    let base = result(&mut rng, Id128([2; 16]));
    let mut r = base.clone();
    r.stdout = CaptureFacts {
        kept: 5,
        total: 4,
        total_known: true,
        truncated: false,
    };
    assert_eq!(
        r.validate(),
        Err(ProtocolError::InvalidField("capture facts"))
    );
    r.stdout = CaptureFacts {
        kept: 4,
        total: 9,
        total_known: false,
        truncated: false,
    };
    assert_eq!(
        r.validate(),
        Err(ProtocolError::InvalidField("capture truncation"))
    );
    r.stdout = CaptureFacts {
        kept: 1024 * 1024 + 1,
        total: 1024 * 1024 + 1,
        total_known: true,
        truncated: false,
    };
    assert_eq!(
        r.validate(),
        Err(ProtocolError::InvalidField("capture facts"))
    );
    let mut r = base.clone();
    r.stdout = CaptureFacts {
        kept: 0,
        total: 0,
        total_known: true,
        truncated: false,
    };
    r.stderr = r.stdout;
    for (termination, ok) in [
        (Termination::Exited { code: 0 }, true),
        (Termination::Exited { code: 255 }, true),
        (Termination::Exited { code: 256 }, false),
        (Termination::Exited { code: -1 }, false),
        (
            Termination::Signaled {
                signal: 15,
                core_dumped: false,
            },
            true,
        ),
        (
            Termination::Signaled {
                signal: 0,
                core_dumped: false,
            },
            false,
        ),
        (
            Termination::Signaled {
                signal: 65,
                core_dumped: true,
            },
            false,
        ),
    ] {
        r.termination = Some(termination);
        assert_eq!(r.validate().is_ok(), ok, "{termination:?}");
    }
    // 124..127 and signal 15 keep their identity, distinct from exit 143.
    let exit143 = Termination::Exited { code: 143 };
    let sigterm = Termination::Signaled {
        signal: 15,
        core_dumped: false,
    };
    assert_ne!(json::to_vec(&exit143), json::to_vec(&sigterm));
}

#[test]
fn protocol_version_is_checked_in_hello_and_reply() {
    let mut rng = Rng::new(4);
    let mut h = hello(&mut rng, Channel::Control);
    h.protocol = 2;
    assert_eq!(
        Message::decode(Kind::Hello, json::to_vec(&h)),
        Err(ProtocolError::InvalidField("protocol"))
    );
    let mut r = hello_reply(&mut rng, h.challenge);
    r.protocol = 0;
    assert_eq!(
        Message::decode(Kind::HelloReply, json::to_vec(&r)),
        Err(ProtocolError::InvalidField("protocol"))
    );
}

#[test]
fn spec_validation_matches_b1() {
    let mut rng = Rng::new(5);
    let good = spec(&mut rng);
    assert!(good.validate().is_ok());
    let mutations: [fn(&mut GuestExecSpec); 9] = [
        |s| s.image = "debian".into(),
        |s| s.network = "full".into(),
        |s| s.memory_bytes = 0,
        |s| s.memory_bytes = 512 * 1024 * 1024 + 1,
        |s| s.cpu_millis = 1001,
        |s| s.pids = 0,
        |s| s.disk_bytes = 0,
        |s| {
            s.read_only_root = false;
            s.writable_paths = vec!["/a".into()];
        },
        |s| {
            s.read_only_root = true;
            s.writable_paths = vec!["/a".into(), "/a".into()];
        },
    ];
    for mutate in mutations {
        let mut s = good.clone();
        mutate(&mut s);
        assert!(s.validate().is_err(), "{s:?}");
    }
    let mut s = good.clone();
    s.read_only_root = true;
    s.writable_paths = vec!["/a/../b".into()];
    assert!(s.validate().is_err());
}

#[test]
fn spec_digest_matches_the_shared_b1_fixture() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../kilnd/tests/fixtures/firecracker");
    let subs: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("substitutions.json")).unwrap()).unwrap();
    let spec: GuestExecSpec = serde_json::from_value(subs["inner_spec"].clone()).unwrap();
    let block = std::fs::read(root.join("identity.bin")).unwrap();
    assert_eq!(&block[..4], b"KID1");
    let len = u32::from_be_bytes(block[4..8].try_into().unwrap()) as usize;
    let record: GuestIdentity = json::from_slice(&block[8..8 + len]).unwrap();
    assert_eq!(spec.sha256(), record.guest_exec_spec_sha256);
    assert_eq!(
        spec.sha256().to_string(),
        "24efdf3fc3f1f3a34a8100f6c894d0d117239ccc51ffa1ef7866f3775d71c0a2"
    );
    // Non-ASCII paths use B1's lowercase \u escapes.
    let mut wide = spec.clone();
    wide.read_only_root = true;
    wide.writable_paths = vec!["/é𝄞".into()];
    assert!(
        String::from_utf8(wide.canonical_json())
            .unwrap()
            .contains(r#"["/\u00e9\ud834\udd1e"]"#)
    );
}

// ---- frames, sequences and budgets --------------------------------------------------

#[test]
fn every_message_round_trips_through_a_frame() {
    let mut rng = Rng::new(11);
    for kind in Kind::ALL {
        let message = message(&mut rng, kind);
        let id = rng.id();
        let bytes = encode_frame(kind, id, 0, &message.encode_payload().unwrap()).unwrap();
        let frame = decode_one(kind.direction(), &bytes).unwrap();
        assert_eq!(frame.request_id(), id);
        assert_eq!(frame.message().unwrap(), message, "{kind:?}");
    }
}

#[test]
fn sequence_must_count_from_zero_without_gaps() {
    let bytes = encode_frame(Kind::Stdout, Id128::default(), 1, b"x").unwrap();
    assert_eq!(
        decode_one(Direction::GuestToHost, &bytes),
        Err(ProtocolError::Sequence {
            expected: 0,
            got: 1
        })
    );
    let mut decoder = FrameDecoder::new(Direction::GuestToHost);
    let first = encode_frame(Kind::Stdout, Id128::default(), 0, b"").unwrap();
    assert!(decoder.feed(&first, &mut Free).unwrap().1.is_some());
    // A duplicated frame repeats its sequence number.
    assert_eq!(
        decoder.feed(&first, &mut Free),
        Err(ProtocolError::Sequence {
            expected: 1,
            got: 0
        })
    );
}

#[test]
fn sequence_overflow_is_an_error_not_a_wrap() {
    let mut decoder =
        FrameDecoder::with_sequence(Direction::GuestToHost, Sequence::starting_at(u32::MAX));
    let last = encode_frame(Kind::Stdout, Id128::default(), u32::MAX, b"").unwrap();
    assert!(decoder.feed(&last, &mut Free).unwrap().1.is_some());
    let wrapped = encode_frame(Kind::Stdout, Id128::default(), 0, b"").unwrap();
    assert_eq!(
        decoder.feed(&wrapped, &mut Free),
        Err(ProtocolError::SequenceOverflow)
    );
    let mut sequence = Sequence::starting_at(u32::MAX);
    assert_eq!(sequence.take(), Ok(u32::MAX));
    assert_eq!(sequence.take(), Err(ProtocolError::SequenceOverflow));
}

#[test]
fn an_oversized_length_allocates_nothing() {
    let mut decoder = FrameDecoder::new(Direction::GuestToHost);
    let header = raw(Kind::Stdout, u32::MAX);
    let error = decoder.feed(&header, &mut Free).unwrap_err();
    assert!(matches!(error, ProtocolError::PayloadTooLarge { .. }));
    assert_eq!(decoder.held(), HEADER_LEN);
    // A failed decoder stays failed.
    assert_eq!(decoder.feed(b"x", &mut Free), Err(error));
}

#[test]
fn the_budget_is_charged_before_any_payload_byte() {
    let mut budget = ExecBudget::new(10, 10);
    let mut decoder = FrameDecoder::new(Direction::GuestToHost);
    let bytes = encode_frame(Kind::Stdout, Id128::default(), 0, &[0; 11]).unwrap();
    // Feed only the header: refusal comes before the body exists.
    assert_eq!(
        decoder.feed(&bytes[..HEADER_LEN], &mut budget),
        Err(ProtocolError::Budget(BudgetKind::Stdout))
    );
    assert_eq!(decoder.held(), HEADER_LEN);
}

#[test]
fn premature_eof_in_header_and_payload() {
    let bytes = encode_frame(Kind::Stdout, Id128::default(), 0, b"hello").unwrap();
    let mut decoder = FrameDecoder::new(Direction::GuestToHost);
    decoder.feed(&bytes[..10], &mut Free).unwrap();
    assert_eq!(
        decoder.finish(),
        Err(ProtocolError::PrematureEof {
            part: FramePart::Header,
            got: 10,
            need: 36
        })
    );
    let mut decoder = FrameDecoder::new(Direction::GuestToHost);
    // One feed never crosses from a header into its payload.
    assert_eq!(decoder.feed(&bytes[..38], &mut Free).unwrap(), (36, None));
    assert_eq!(decoder.feed(&bytes[36..38], &mut Free).unwrap(), (2, None));
    assert_eq!(
        decoder.finish(),
        Err(ProtocolError::PrematureEof {
            part: FramePart::Payload,
            got: 2,
            need: 5
        })
    );
}

fn admit_n(budget: &mut dyn Budget, kind: Kind, len: u32, n: u32) -> Result<()> {
    for i in 0..n {
        budget.admit(&header(kind, len, i))?;
    }
    Ok(())
}

#[test]
fn exec_budget_counts_frames_wire_and_each_payload_class() {
    let mut b = ExecBudget::new(1024 * 1024, 1024 * 1024);
    assert_eq!(admit_n(&mut b, Kind::Stdout, 0, 128), Ok(()));
    assert_eq!(
        b.admit(&header(Kind::Stdout, 0, 0)),
        Err(ProtocolError::Budget(BudgetKind::Frames))
    );
    let mut b = ExecBudget::new(100, 50);
    assert_eq!(b.admit(&header(Kind::Stdout, 100, 0)), Ok(()));
    assert_eq!(
        b.admit(&header(Kind::Stdout, 1, 0)),
        Err(ProtocolError::Budget(BudgetKind::Stdout))
    );
    assert_eq!(b.admit(&header(Kind::Stderr, 50, 0)), Ok(()));
    assert_eq!(
        b.admit(&header(Kind::Stderr, 1, 0)),
        Err(ProtocolError::Budget(BudgetKind::Stderr))
    );
    assert_eq!(admit_n(&mut b, Kind::Result, 32 * 1024, 2), Ok(()));
    assert_eq!(
        b.admit(&header(Kind::CancelAck, 1, 0)),
        Err(ProtocolError::Budget(BudgetKind::Control))
    );
    // A refused frame charges nothing.
    assert_eq!(b.frames(), 4);
    let b = ExecBudget::new(u64::MAX, u64::MAX);
    assert_eq!(b.max_wire(), 2 * 1024 * 1024 + 64 * 1024 + 128 * 36);
}

#[test]
fn exchange_budget_is_64_kib_and_16_frames() {
    let mut b = ExchangeBudget::default();
    assert_eq!(admit_n(&mut b, Kind::ProbeReply, 0, 16), Ok(()));
    assert_eq!(
        b.admit(&header(Kind::ProbeReply, 0, 0)),
        Err(ProtocolError::Budget(BudgetKind::Frames))
    );
    let mut b = ExchangeBudget::default();
    assert_eq!(b.admit(&header(Kind::HelloReply, 64 * 1024, 0)), Ok(()));
    assert_eq!(
        b.admit(&header(Kind::Ready, 1, 0)),
        Err(ProtocolError::Budget(BudgetKind::Control))
    );
}

#[test]
fn host_budget_bounds_stdin_and_frames() {
    let mut b = HostBudget::default();
    assert_eq!(admit_n(&mut b, Kind::Stdin, 64 * 1024, 16), Ok(()));
    assert_eq!(
        b.admit(&header(Kind::Stdin, 1, 0)),
        Err(ProtocolError::Budget(BudgetKind::Stdin))
    );
    let mut b = HostBudget::default();
    assert_eq!(admit_n(&mut b, Kind::Stdin, 1, 1027), Ok(()));
    assert_eq!(
        b.admit(&header(Kind::StdinEnd, 1, 0)),
        Err(ProtocolError::Budget(BudgetKind::Frames))
    );
}

// ---- exchanges -------------------------------------------------------------------

struct HostSide {
    conn: HostConnection,
    hello_id: Id128,
    challenge: Hex32,
    seq: u32,
    rng: Rng,
}

impl HostSide {
    fn new(channel: Channel) -> Self {
        let mut rng = Rng::new(21);
        let h = hello(&mut rng, channel);
        let hello_id = rng.id();
        Self {
            conn: HostConnection::new(hello_id, &h),
            hello_id,
            challenge: h.challenge,
            seq: 0,
            rng,
        }
    }
    fn recv(&mut self, id: Id128, message: Message) -> Result<HostEvent> {
        let f = frame(message.kind(), id, self.seq, &message);
        self.seq += 1;
        self.conn.received(f)
    }
    fn identify(&mut self) {
        let reply = hello_reply(&mut self.rng, self.challenge);
        let id = self.hello_id;
        assert!(matches!(
            self.recv(id, Message::HelloReply(Box::new(reply))),
            Ok(HostEvent::HelloReply(_))
        ));
    }
}

fn probe() -> Message {
    let mut rng = Rng::new(31);
    Message::Probe(Probe {
        boot_id: rng.boot_id(),
        inner_id: rng.inner_id(),
    })
}

fn probe_reply() -> Message {
    let mut rng = Rng::new(32);
    Message::ProbeReply(ProbeReply {
        boot_id: rng.boot_id(),
        inner_id: rng.inner_id(),
        state: BrokerState::Idle,
        active: None,
    })
}

#[test]
fn host_control_happy_path_and_terminal_rules() {
    let mut h = HostSide::new(Channel::Control);
    h.identify();
    let rid = Id128([5; 16]);
    h.conn.sending(rid, &probe()).unwrap();
    assert!(matches!(
        h.recv(rid, probe_reply()),
        Ok(HostEvent::Reply(_))
    ));
    assert_eq!(h.conn.eof(), Ok(()));
    assert_eq!(
        h.recv(rid, probe_reply()),
        Err(ProtocolError::DuplicateTerminal)
    );
}

#[test]
fn host_refuses_unsolicited_and_misaddressed_replies() {
    let mut h = HostSide::new(Channel::Control);
    // Before HelloReply: wrong kind, and a HelloReply under a foreign request ID.
    let id = h.hello_id;
    assert!(matches!(
        h.recv(id, probe_reply()),
        Err(ProtocolError::UnexpectedKind { .. })
    ));
    let mut h = HostSide::new(Channel::Control);
    let reply = hello_reply(&mut h.rng, h.challenge);
    assert_eq!(
        h.recv(Id128([9; 16]), Message::HelloReply(Box::new(reply))),
        Err(ProtocolError::RequestId)
    );
    // A stale challenge.
    let mut h = HostSide::new(Channel::Control);
    let reply = hello_reply(&mut h.rng, Hex32([0; 32]));
    let id = h.hello_id;
    assert_eq!(
        h.recv(id, Message::HelloReply(Box::new(reply))),
        Err(ProtocolError::InvalidField("challenge echo"))
    );
    // Identified, but no request yet: any reply is unsolicited.
    let mut h = HostSide::new(Channel::Control);
    h.identify();
    assert!(matches!(
        h.recv(Id128([5; 16]), probe_reply()),
        Err(ProtocolError::UnexpectedKind { .. })
    ));
    // The wrong reply kind, and the right one under another request ID.
    let mut h = HostSide::new(Channel::Control);
    h.identify();
    h.conn.sending(Id128([5; 16]), &probe()).unwrap();
    assert!(matches!(
        h.recv(
            Id128([5; 16]),
            Message::CancelAck(CancelAck {
                token: Id128([5; 16]),
                active: true
            })
        ),
        Err(ProtocolError::UnexpectedKind { .. })
    ));
    let mut h = HostSide::new(Channel::Control);
    h.identify();
    h.conn.sending(Id128([5; 16]), &probe()).unwrap();
    assert_eq!(
        h.recv(Id128([6; 16]), probe_reply()),
        Err(ProtocolError::RequestId)
    );
    assert_eq!(h.conn.eof(), Err(ProtocolError::EofBeforeTerminal));
}

#[test]
fn cancel_ack_must_name_the_canceled_token() {
    let mut h = HostSide::new(Channel::Control);
    h.identify();
    let rid = Id128([5; 16]);
    let token = Id128([8; 16]);
    h.conn
        .sending(
            rid,
            &Message::Cancel(Cancel {
                token,
                reason: CancelReason::Timeout,
            }),
        )
        .unwrap();
    assert_eq!(
        h.recv(
            rid,
            Message::CancelAck(CancelAck {
                token: Id128([9; 16]),
                active: true
            })
        ),
        Err(ProtocolError::InvalidField("cancel token"))
    );
}

#[test]
fn host_sends_only_in_order() {
    let mut h = HostSide::new(Channel::Control);
    assert!(h.conn.sending(Id128([5; 16]), &probe()).is_err());
    h.identify();
    h.conn.sending(Id128([5; 16]), &probe()).unwrap();
    assert!(h.conn.sending(Id128([6; 16]), &probe()).is_err());
    let mut h = HostSide::new(Channel::Control);
    h.identify();
    let exec = Message::Exec(sample_exec());
    assert!(h.conn.sending(Id128([7; 16]), &exec).is_err());
}

fn exec_host(stdin: u64, max_output: u64) -> (HostSide, Id128) {
    let mut h = HostSide::new(Channel::Exec);
    h.identify();
    let mut e = sample_exec();
    e.stdin_bytes = stdin;
    e.max_output = max_output;
    let token = e.token;
    assert_eq!(
        h.conn.sending(Id128([1; 16]), &Message::Exec(e.clone())),
        Err(ProtocolError::RequestId)
    );
    h.conn.sending(token, &Message::Exec(e)).unwrap();
    (h, token)
}

fn facts_of(kept: u64) -> CaptureFacts {
    CaptureFacts {
        kept,
        total: kept,
        total_known: true,
        truncated: false,
    }
}

fn exec_result(token: Id128, out: u64, err: u64) -> Message {
    Message::Result(Box::new(ExecResult {
        token,
        finish: Finish::Completed,
        termination: Some(Termination::Exited { code: 0 }),
        diagnostic: None,
        stdout: facts_of(out),
        stderr: facts_of(err),
        cleanup: Cleanup::GuestCgroupDrained,
        inner_id: InnerId::new("18de453339a8cc89-3762").unwrap(),
    }))
}

fn accepted_with_stdin(h: &mut HostSide, token: Id128, stdin: &[u8]) {
    assert_eq!(
        h.recv(token, Message::Accepted(Accepted { token })),
        Ok(HostEvent::Accepted)
    );
    if !stdin.is_empty() {
        h.conn
            .sending_stdin(token, &Message::Stdin(stdin.to_vec()))
            .unwrap();
    }
    h.conn
        .sending_stdin(
            token,
            &Message::StdinEnd(StdinEnd {
                token,
                total: stdin.len() as u64,
            }),
        )
        .unwrap();
}

#[test]
fn host_exec_happy_path() {
    let (mut h, token) = exec_host(3, 100);
    accepted_with_stdin(&mut h, token, b"abc");
    assert!(matches!(
        h.recv(token, Message::Stdout(b"out".to_vec())),
        Ok(HostEvent::Stdout(_))
    ));
    assert!(matches!(
        h.recv(token, Message::Stdout(Vec::new())),
        Ok(HostEvent::Stdout(_))
    ));
    assert!(matches!(
        h.recv(token, Message::Stderr(b"e".to_vec())),
        Ok(HostEvent::Stderr(_))
    ));
    assert!(matches!(
        h.recv(token, exec_result(token, 3, 1)),
        Ok(HostEvent::Result(_))
    ));
    assert_eq!(h.conn.eof(), Ok(()));
}

#[test]
fn host_exec_order_and_totals() {
    // Output before StdinEnd.
    let (mut h, token) = exec_host(3, 100);
    assert_eq!(
        h.recv(token, Message::Accepted(Accepted { token })),
        Ok(HostEvent::Accepted)
    );
    assert!(matches!(
        h.recv(token, Message::Stdout(b"x".to_vec())),
        Err(ProtocolError::UnexpectedKind { .. })
    ));
    // Stdout after Stderr.
    let (mut h, token) = exec_host(0, 100);
    accepted_with_stdin(&mut h, token, b"");
    h.recv(token, Message::Stderr(b"e".to_vec())).unwrap();
    assert!(matches!(
        h.recv(token, Message::Stdout(b"o".to_vec())),
        Err(ProtocolError::UnexpectedKind { .. })
    ));
    // Totals that disagree with the Result.
    let (mut h, token) = exec_host(0, 100);
    accepted_with_stdin(&mut h, token, b"");
    h.recv(token, Message::Stdout(b"oo".to_vec())).unwrap();
    assert_eq!(
        h.recv(token, exec_result(token, 1, 0)),
        Err(ProtocolError::CaptureMismatch)
    );
    // More than the negotiated retained prefix.
    let (mut h, token) = exec_host(0, 2);
    accepted_with_stdin(&mut h, token, b"");
    assert_eq!(
        h.recv(token, Message::Stdout(b"ooo".to_vec())),
        Err(ProtocolError::CaptureMismatch)
    );
    // Output after Result, a second Result, a foreign token.
    let (mut h, token) = exec_host(0, 100);
    accepted_with_stdin(&mut h, token, b"");
    h.recv(token, exec_result(token, 0, 0)).unwrap();
    assert_eq!(
        h.recv(token, Message::Stdout(b"late".to_vec())),
        Err(ProtocolError::TrailingBytes)
    );
    let (mut h, token) = exec_host(0, 100);
    accepted_with_stdin(&mut h, token, b"");
    h.recv(token, exec_result(token, 0, 0)).unwrap();
    assert_eq!(
        h.recv(token, exec_result(token, 0, 0)),
        Err(ProtocolError::DuplicateTerminal)
    );
    let (mut h, token) = exec_host(0, 100);
    accepted_with_stdin(&mut h, token, b"");
    assert_eq!(
        h.recv(token, exec_result(Id128([3; 16]), 0, 0)),
        Err(ProtocolError::InvalidField("result token"))
    );
    assert_eq!(
        h.recv(Id128([3; 16]), exec_result(token, 0, 0)),
        Err(ProtocolError::RequestId)
    );
    // Accepted for another token; EOF before the Result.
    let (mut h, token) = exec_host(0, 100);
    assert_eq!(
        h.recv(
            token,
            Message::Accepted(Accepted {
                token: Id128([4; 16])
            })
        ),
        Err(ProtocolError::InvalidField("accepted token"))
    );
    assert_eq!(h.conn.eof(), Err(ProtocolError::EofBeforeTerminal));
}

#[test]
fn host_exec_error_is_terminal_and_never_success() {
    let (mut h, token) = exec_host(0, 100);
    let refusal = Message::Error(ErrorReply {
        code: ErrorCode::Admission,
        state: BrokerState::Executing,
        message: WireText::new("busy").unwrap(),
    });
    assert!(matches!(
        h.recv(token, refusal.clone()),
        Ok(HostEvent::Error(_))
    ));
    assert_eq!(
        h.recv(token, refusal),
        Err(ProtocolError::DuplicateTerminal)
    );
}

#[test]
fn host_stdin_must_match_its_declaration() {
    let (mut h, token) = exec_host(3, 100);
    // Before Accepted.
    assert!(
        h.conn
            .sending_stdin(token, &Message::Stdin(b"a".to_vec()))
            .is_err()
    );
    h.recv(token, Message::Accepted(Accepted { token }))
        .unwrap();
    assert_eq!(
        h.conn.sending_stdin(token, &Message::Stdin(Vec::new())),
        Err(ProtocolError::EmptyData)
    );
    assert_eq!(
        h.conn
            .sending_stdin(token, &Message::Stdin(b"abcd".to_vec())),
        Err(ProtocolError::StdinLength {
            declared: 3,
            got: 4
        })
    );
    h.conn
        .sending_stdin(token, &Message::Stdin(b"ab".to_vec()))
        .unwrap();
    assert!(
        h.conn
            .sending_stdin(token, &Message::StdinEnd(StdinEnd { token, total: 3 }))
            .is_err()
    );
}

fn guest_feed(
    conn: &mut GuestConnection,
    id: Id128,
    seq: u32,
    message: Message,
) -> Result<GuestEvent> {
    conn.received(frame(message.kind(), id, seq, &message))
}

#[test]
fn guest_connection_order() {
    let mut rng = Rng::new(41);
    // Nothing before Hello.
    let mut g = GuestConnection::default();
    assert!(matches!(
        guest_feed(&mut g, Id128([1; 16]), 0, probe()),
        Err(ProtocolError::UnexpectedKind { .. })
    ));
    // Control: one request, then nothing.
    let mut g = GuestConnection::default();
    guest_feed(
        &mut g,
        Id128([1; 16]),
        0,
        Message::Hello(hello(&mut rng, Channel::Control)),
    )
    .unwrap();
    assert!(matches!(
        guest_feed(&mut g, Id128([2; 16]), 1, Message::Exec(sample_exec())),
        Err(ProtocolError::UnexpectedKind { .. })
    ));
    let mut g = GuestConnection::default();
    guest_feed(
        &mut g,
        Id128([1; 16]),
        0,
        Message::Hello(hello(&mut rng, Channel::Control)),
    )
    .unwrap();
    assert!(matches!(
        guest_feed(
            &mut g,
            Id128([1; 16]),
            1,
            Message::Hello(hello(&mut rng, Channel::Control))
        ),
        Err(ProtocolError::UnexpectedKind { .. })
    ));
    let mut g = GuestConnection::default();
    guest_feed(
        &mut g,
        Id128([1; 16]),
        0,
        Message::Hello(hello(&mut rng, Channel::Control)),
    )
    .unwrap();
    assert!(matches!(
        guest_feed(&mut g, Id128([2; 16]), 1, probe()),
        Ok(GuestEvent::Request(_))
    ));
    assert_eq!(g.request_id(), Some(Id128([2; 16])));
    assert_eq!(
        guest_feed(&mut g, Id128([2; 16]), 2, probe()),
        Err(ProtocolError::TrailingBytes)
    );
    // Exec channel: no control request; Exec's request ID is its token.
    let mut g = GuestConnection::default();
    guest_feed(
        &mut g,
        Id128([1; 16]),
        0,
        Message::Hello(hello(&mut rng, Channel::Exec)),
    )
    .unwrap();
    assert!(matches!(
        guest_feed(&mut g, Id128([2; 16]), 1, probe()),
        Err(ProtocolError::UnexpectedKind { .. })
    ));
    let mut g = GuestConnection::default();
    guest_feed(
        &mut g,
        Id128([1; 16]),
        0,
        Message::Hello(hello(&mut rng, Channel::Exec)),
    )
    .unwrap();
    assert_eq!(
        guest_feed(&mut g, Id128([2; 16]), 1, Message::Exec(sample_exec())),
        Err(ProtocolError::RequestId)
    );
    assert_eq!(g.eof(), Err(ProtocolError::EofBeforeTerminal));
}

fn guest_exec(stdin: u64) -> (GuestConnection, Id128) {
    let mut rng = Rng::new(42);
    let mut g = GuestConnection::default();
    guest_feed(
        &mut g,
        Id128([1; 16]),
        0,
        Message::Hello(hello(&mut rng, Channel::Exec)),
    )
    .unwrap();
    let mut e = sample_exec();
    e.stdin_bytes = stdin;
    let token = e.token;
    assert!(matches!(
        guest_feed(&mut g, token, 1, Message::Exec(e)),
        Ok(GuestEvent::Exec(_))
    ));
    (g, token)
}

#[test]
fn guest_stdin_exactly_as_declared() {
    let (mut g, token) = guest_exec(3);
    assert_eq!(
        guest_feed(&mut g, token, 2, Message::Stdin(Vec::new())),
        Err(ProtocolError::EmptyData)
    );
    let (mut g, token) = guest_exec(3);
    assert_eq!(
        guest_feed(&mut g, token, 2, Message::Stdin(b"abcd".to_vec())),
        Err(ProtocolError::StdinLength {
            declared: 3,
            got: 4
        })
    );
    let (mut g, token) = guest_exec(3);
    guest_feed(&mut g, token, 2, Message::Stdin(b"ab".to_vec())).unwrap();
    assert_eq!(
        guest_feed(
            &mut g,
            token,
            3,
            Message::StdinEnd(StdinEnd { token, total: 3 })
        ),
        Err(ProtocolError::StdinLength {
            declared: 3,
            got: 2
        })
    );
    let (mut g, token) = guest_exec(3);
    guest_feed(&mut g, token, 2, Message::Stdin(b"abc".to_vec())).unwrap();
    assert_eq!(
        guest_feed(
            &mut g,
            token,
            3,
            Message::StdinEnd(StdinEnd { token, total: 2 })
        ),
        Err(ProtocolError::StdinLength {
            declared: 3,
            got: 3
        })
    );
    let (mut g, token) = guest_exec(3);
    assert_eq!(
        guest_feed(&mut g, Id128([9; 16]), 2, Message::Stdin(b"a".to_vec())),
        Err(ProtocolError::RequestId)
    );
    let (mut g, token2) = guest_exec(0);
    let _ = token;
    assert_eq!(
        guest_feed(
            &mut g,
            token2,
            2,
            Message::StdinEnd(StdinEnd {
                token: token2,
                total: 0
            })
        ),
        Ok(GuestEvent::StdinEnd)
    );
    assert_eq!(g.eof(), Ok(()));
    assert_eq!(
        guest_feed(&mut g, token2, 3, Message::Stdin(b"x".to_vec())),
        Err(ProtocolError::TrailingBytes)
    );
}

#[test]
fn the_shared_identity_block_parses_and_re_encodes_byte_for_byte() {
    use kilnd_broker_protocol::identity::*;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../kilnd/tests/fixtures/firecracker");
    let block = std::fs::read(root.join("identity.bin")).unwrap();
    let identity = parse_block(&block).unwrap();
    assert_eq!(identity.block(), block);
    // Every mutation is refused: magic, length, padding, a non-canonical record.
    let mut bad = block.clone();
    bad[0] = b'X';
    assert!(parse_block(&bad).is_err());
    let mut bad = block.clone();
    bad[7] ^= 1;
    assert!(parse_block(&bad).is_err());
    let mut bad = block.clone();
    bad[4095] = 1;
    assert!(parse_block(&bad).is_err());
    assert!(parse_block(&block[..4095]).is_err());
    let len = u32::from_be_bytes(block[4..8].try_into().unwrap()) as usize;
    let mut spaced = block[8..8 + len].to_vec();
    spaced.insert(1, b' ');
    let mut bad = b"KID1".to_vec();
    bad.extend_from_slice(&(spaced.len() as u32).to_be_bytes());
    bad.extend_from_slice(&spaced);
    bad.resize(4096, 0);
    assert_eq!(
        parse_block(&bad),
        Err(ProtocolError::InvalidField("identity is not canonical"))
    );
    // The bootstrap record appends KGH1 and the seven-bit mask.
    let mut boot = block.clone();
    boot.extend_from_slice(b"KGH1");
    boot.extend_from_slice(&0x7fu32.to_be_bytes());
    let (parsed, mask) = parse_bootstrap(&boot).unwrap();
    assert_eq!(parsed, identity);
    assert!(hardening_from_mask(mask).all());
    assert!(!hardening_from_mask(0x3f).all());
    boot[4096 + 7] = 0xff;
    assert!(parse_bootstrap(&boot).is_err());
}
