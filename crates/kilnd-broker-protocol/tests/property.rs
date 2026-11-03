//! Property tests with a deterministic generator (design 10.1, "broker framing fuzz/
//! property tests"): round trips through every chunking, truncation at every header
//! and payload boundary, oversized and mutated headers, duplicated frames, arbitrary
//! bytes and mutated JSON. Each property runs from fixed seeds, so a failure names its
//! seed and reproduces exactly. Memory stays bounded throughout.

mod common;

use common::*;
use kilnd_broker_protocol::budget::{Budget, ExecBudget};
use kilnd_broker_protocol::*;

struct Free;
impl Budget for Free {
    fn admit(&mut self, _: &Header) -> Result<()> {
        Ok(())
    }
}

const SEEDS: u64 = 64;
const PER_SEED: usize = 40;

/// Feeds `bytes` in random chunks; returns every frame and the final state.
fn feed_chunks(
    rng: &mut Rng,
    decoder: &mut FrameDecoder,
    bytes: &[u8],
    budget: &mut dyn Budget,
) -> Result<Vec<Frame>> {
    let mut frames = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let chunk = 1 + rng.below(70_000) as usize;
        let end = (at + chunk).min(bytes.len());
        let mut slice = &bytes[at..end];
        while !slice.is_empty() {
            let (used, frame) = decoder.feed(slice, budget)?;
            assert!(used > 0 && used <= slice.len());
            // Never holds more than a header and the payload received so far.
            assert!(decoder.held() <= HEADER_LEN + 2 * (384 * 1024));
            slice = &slice[used..];
            at += used;
            frames.extend(frame);
        }
    }
    Ok(frames)
}

#[test]
fn random_messages_round_trip_through_random_chunking() {
    for seed in 1..=SEEDS {
        let mut rng = Rng::new(seed);
        for direction in [Direction::HostToGuest, Direction::GuestToHost] {
            let kinds: Vec<Kind> = Kind::ALL
                .into_iter()
                .filter(|k| k.direction() == direction)
                .collect();
            let mut stream = Vec::new();
            let mut expected = Vec::new();
            for seq in 0..PER_SEED as u32 {
                let kind = kinds[rng.below(kinds.len() as u64) as usize];
                let message = message(&mut rng, kind);
                let id = rng.id();
                let payload = message.encode_payload().unwrap();
                stream.extend(encode_frame(kind, id, seq, &payload).unwrap());
                expected.push((id, message));
            }
            let mut decoder = FrameDecoder::new(direction);
            let frames = feed_chunks(&mut rng, &mut decoder, &stream, &mut Free)
                .unwrap_or_else(|e| panic!("seed {seed}: {e}"));
            assert!(decoder.at_boundary());
            assert_eq!(frames.len(), expected.len(), "seed {seed}");
            for (frame, (id, message)) in frames.into_iter().zip(expected) {
                assert_eq!(frame.request_id(), id, "seed {seed}");
                assert_eq!(frame.into_message().unwrap(), message, "seed {seed}");
            }
        }
    }
}

#[test]
fn truncation_at_every_boundary_is_premature_eof() {
    let mut rng = Rng::new(77);
    for kind in Kind::ALL {
        let message = message(&mut rng, kind);
        let payload = message.encode_payload().unwrap();
        let bytes = encode_frame(kind, rng.id(), 0, &payload).unwrap();
        // Every header cut, and payload cuts at the edges and at random points.
        let mut cuts: Vec<usize> = (1..=HEADER_LEN).collect();
        cuts.extend([bytes.len() - 1, HEADER_LEN + 1]);
        cuts.extend((0..64).map(|_| HEADER_LEN + rng.below(payload.len() as u64) as usize));
        for cut in cuts.into_iter().filter(|c| *c < bytes.len()) {
            let mut decoder = FrameDecoder::new(kind.direction());
            let frames = feed_chunks(&mut rng, &mut decoder, &bytes[..cut], &mut Free).unwrap();
            assert!(frames.is_empty() || (cut == HEADER_LEN && payload.is_empty()));
            let expected = if cut < HEADER_LEN {
                ProtocolError::PrematureEof {
                    part: FramePart::Header,
                    got: cut,
                    need: HEADER_LEN,
                }
            } else {
                ProtocolError::PrematureEof {
                    part: FramePart::Payload,
                    got: cut - HEADER_LEN,
                    need: payload.len(),
                }
            };
            if cut == HEADER_LEN && payload.is_empty() {
                continue;
            }
            assert_eq!(decoder.finish(), Err(expected), "{kind:?} cut {cut}");
        }
    }
}

#[test]
fn every_oversized_length_is_refused_from_the_header_alone() {
    let mut rng = Rng::new(5);
    for _ in 0..10_000 {
        let kind = Kind::ALL[rng.below(16) as usize];
        let max = kind.max_payload();
        let len = max + 1 + rng.below(u64::from(u32::MAX - max)) as u32;
        let header = Header {
            kind,
            payload_len: len,
            request_id: rng.id(),
            sequence: 0,
        }
        .encode();
        let mut decoder = FrameDecoder::new(kind.direction());
        assert_eq!(
            decoder.feed(&header, &mut Free),
            Err(ProtocolError::PayloadTooLarge { kind, len, max })
        );
        assert_eq!(decoder.held(), HEADER_LEN);
    }
}

#[test]
fn duplicated_frames_break_the_sequence() {
    let mut rng = Rng::new(6);
    for _ in 0..500 {
        let kind = Kind::ALL[rng.below(16) as usize];
        let message = message(&mut rng, kind);
        let bytes = encode_frame(kind, rng.id(), 0, &message.encode_payload().unwrap()).unwrap();
        let mut stream = bytes.clone();
        stream.extend(&bytes);
        let mut decoder = FrameDecoder::new(kind.direction());
        let result = feed_chunks(&mut rng, &mut decoder, &stream, &mut Free);
        assert_eq!(
            result,
            Err(ProtocolError::Sequence {
                expected: 1,
                got: 0
            })
        );
    }
}

#[test]
fn mutated_headers_never_panic_and_fail_typed() {
    let mut rng = Rng::new(8);
    for _ in 0..20_000 {
        let kind = Kind::ALL[rng.below(16) as usize];
        let mut header = Header {
            kind,
            payload_len: rng.below(u64::from(kind.max_payload()) + 1) as u32,
            request_id: rng.id(),
            sequence: 0,
        }
        .encode();
        // Flip 1..4 random bytes of the magic, version, kind, flags or length.
        for _ in 0..1 + rng.below(4) {
            let at = rng.below(16) as usize;
            header[at] ^= 1 + rng.below(255) as u8;
        }
        match Header::parse(&header, kind.direction()) {
            Ok(parsed) => {
                // Only a still-valid kind in this direction, under its bound.
                assert_eq!(parsed.kind.direction(), kind.direction());
                assert!(parsed.payload_len <= parsed.kind.max_payload());
            }
            Err(
                ProtocolError::BadMagic(_)
                | ProtocolError::UnsupportedVersion(_)
                | ProtocolError::UnknownFlags(_)
                | ProtocolError::UnknownKind(_)
                | ProtocolError::WrongDirection { .. }
                | ProtocolError::PayloadTooLarge { .. },
            ) => {}
            Err(other) => panic!("untyped header failure {other:?}"),
        }
    }
}

#[test]
fn arbitrary_bytes_never_panic_and_hold_bounded_memory() {
    for seed in 1..=SEEDS {
        let mut rng = Rng::new(seed * 7919);
        for direction in [Direction::HostToGuest, Direction::GuestToHost] {
            // Sometimes a valid prefix, so decoding gets past the header.
            let mut bytes = Vec::new();
            if rng.bool() {
                let kinds: Vec<Kind> = Kind::ALL
                    .into_iter()
                    .filter(|k| k.direction() == direction)
                    .collect();
                let kind = kinds[rng.below(kinds.len() as u64) as usize];
                let m = message(&mut rng, kind);
                bytes = encode_frame(kind, rng.id(), 0, &m.encode_payload().unwrap()).unwrap();
            }
            let noise = rng.below(4096) as usize;
            bytes.extend(rng.bytes(noise));
            let mut decoder = FrameDecoder::new(direction);
            let mut budget = ExecBudget::new(1024 * 1024, 1024 * 1024);
            if let Ok(frames) = feed_chunks(&mut rng, &mut decoder, &bytes, &mut budget) {
                for frame in frames {
                    let _ = frame.into_message();
                }
            }
            assert!(decoder.held() <= HEADER_LEN + 2 * 384 * 1024);
        }
    }
}

#[test]
fn mutated_json_payloads_never_panic_and_never_decode_wrongly() {
    let mut rng = Rng::new(12);
    for _ in 0..4000 {
        let kind = loop {
            let k = Kind::ALL[rng.below(16) as usize];
            if !k.is_data() {
                break k;
            }
        };
        let original = message(&mut rng, kind);
        let mut payload = original.encode_payload().unwrap();
        let edits = 1 + rng.below(3);
        for _ in 0..edits {
            if payload.is_empty() {
                break;
            }
            let at = rng.below(payload.len() as u64) as usize;
            match rng.below(4) {
                0 => payload[at] = rng.next_u64() as u8,
                1 => {
                    payload.remove(at);
                }
                2 => {
                    let pool = b"{}[],:\"\\e.-01";
                    payload.insert(at, pool[rng.below(pool.len() as u64) as usize]);
                }
                _ => payload.truncate(at),
            }
        }
        if let Ok(decoded) = Message::decode(kind, payload.clone()) {
            // Whatever decodes is itself valid and re-encodes to strict JSON.
            let again = decoded.encode_payload().unwrap();
            assert_eq!(json::check(&again), Ok(()));
            assert_eq!(Message::decode(kind, again).unwrap(), decoded);
        }
    }
}

#[test]
fn deep_nesting_and_huge_strings_stay_bounded() {
    // The deepest and largest control payloads the header permits decode without
    // recursion or allocation beyond the payload itself.
    let deep = format!(
        "{}{}",
        "[".repeat(384 * 1024 / 2),
        "]".repeat(384 * 1024 / 2)
    );
    assert_eq!(
        Message::decode(Kind::Probe, deep.into_bytes()),
        Err(ProtocolError::JsonDepth)
    );
    let long = format!("\"{}\"", "a".repeat(384 * 1024 - 2));
    assert!(matches!(
        Message::decode(Kind::Probe, long.into_bytes()),
        Err(ProtocolError::Schema(_))
    ));
}
