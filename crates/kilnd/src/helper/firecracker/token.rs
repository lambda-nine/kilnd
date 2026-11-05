//! B7's helper-issued allocation tokens (design section 16.5, RTC-1, RTC-3 and RTC-8).
//!
//! A Firecracker allocation ID is `seq ‖ tag`: the instance's issue sequence as eight
//! big-endian bytes, then the first eight bytes of HMAC-SHA-256(K, "kilnd-fc-token-v1" ‖
//! node_id ‖ instance_id ‖ seq), where both IDs are their 16 raw bytes and seq its eight
//! big-endian bytes. K is 32 bytes from the kernel's random source, written once into the
//! node ledger at provisioning with its check value. It lives only in the ledger and in
//! H's and L's memory, crosses only the private L-to-H channel, and is never logged,
//! printed or put into any wire reply: `TokenKey` has no `Serialize` and a redacted
//! `Debug`, and its only transfer form, [`KeyTransfer`], is private to the L protocol.
use crate::model::{Digest, Id128};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// The highest sequence a token may carry (RTC-1): 2^63 − 2.
pub const MAX_SEQ: u64 = (1 << 63) - 2;
/// The exclusive issue pointer's ceiling: at 2^63 − 1 Preflight refuses and never wraps.
pub const POINTER_CEILING: u64 = (1 << 63) - 1;

const TOKEN_LABEL: &[u8] = b"kilnd-fc-token-v1";
const CHECK_LABEL: &[u8] = b"kilnd-fc-key-check-v1";
const COMPACTED_LABEL: &[u8] = b"kilnd-fc-compacted-v1";
const BLOCK: usize = 64;

/// HMAC-SHA-256 (RFC 2104) over `sha2`, with the message given in parts.
fn hmac_sha256(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut padded = [0u8; BLOCK];
    padded[..32].copy_from_slice(key);
    let mut inner = Sha256::new();
    inner.update(padded.map(|b| b ^ 0x36));
    for part in parts {
        inner.update(part);
    }
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(padded.map(|b| b ^ 0x5c));
    outer.update(inner);
    outer.finalize().into()
}

/// Constant-time equality of two equal-length byte strings.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let difference = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(difference) == 0
}

/// The sequence a token names: its first eight bytes, big-endian.
pub fn seq_of(token: Id128) -> u64 {
    let bytes = token.as_bytes();
    u64::from_be_bytes(bytes[..8].try_into().expect("eight bytes"))
}

/// The tag-free shape check a daemon can make (section 9.1): seq in 1 ..= 2^63 − 2.
pub fn shape_ok(token: Id128) -> bool {
    (1..=MAX_SEQ).contains(&seq_of(token))
}

/// The node's token key. No `Serialize`, no `Clone` into anything public, and a
/// redacted `Debug`: K never reaches a log, error or reply.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenKey {
    node_id: Id128,
    key: [u8; 32],
}

impl std::fmt::Debug for TokenKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TokenKey(node {}, redacted)", self.node_id)
    }
}

impl TokenKey {
    /// A fresh key from the kernel's CSPRNG, for the provisioning transaction only.
    pub fn generate(node_id: Id128) -> std::io::Result<Self> {
        let mut key = [0u8; 32];
        // SAFETY: key is writable and within getentropy's 256-byte limit.
        if unsafe { libc::getentropy(key.as_mut_ptr().cast(), key.len()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { node_id, key })
    }

    /// A key read back from the ledger. Its check value is the caller's to verify.
    pub fn from_parts(node_id: Id128, key: [u8; 32]) -> Self {
        Self { node_id, key }
    }

    pub fn node_id(&self) -> Id128 {
        self.node_id
    }

    /// The raw bytes, for the ledger's one provisioning write and nothing else.
    pub(super) fn secret_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// The first 16 bytes of HMAC-SHA-256(K, "kilnd-fc-key-check-v1" ‖ node_id).
    pub fn check_value(&self) -> [u8; 16] {
        let mac = hmac_sha256(&self.key, &[CHECK_LABEL, self.node_id.as_bytes()]);
        mac[..16].try_into().expect("sixteen bytes")
    }

    /// Whether `check` is this key's check value, in constant time.
    pub fn check_matches(&self, check: &[u8]) -> bool {
        ct_eq(&self.check_value(), check)
    }

    fn tag(&self, instance: Id128, seq: u64) -> [u8; 8] {
        let mac = hmac_sha256(
            &self.key,
            &[
                TOKEN_LABEL,
                self.node_id.as_bytes(),
                instance.as_bytes(),
                &seq.to_be_bytes(),
            ],
        );
        mac[..8].try_into().expect("eight bytes")
    }

    /// The token for `seq` in `instance`. Only L calls this, after the issue pointer has
    /// durably passed `seq`.
    pub fn issue(&self, instance: Id128, seq: u64) -> Id128 {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&seq.to_be_bytes());
        bytes[8..].copy_from_slice(&self.tag(instance, seq));
        Id128::from_bytes(bytes)
    }

    /// RTC-3's whole H check: seq ≠ 0 and a tag that verifies in the caller's instance,
    /// compared in constant time. Returns the sequence, or `None` (Malformed).
    pub fn verify(&self, instance: Id128, token: Id128) -> Option<u64> {
        let seq = seq_of(token);
        let expected = self.tag(instance, seq);
        let tag_ok = ct_eq(&token.as_bytes()[8..], &expected);
        (seq != 0 && seq <= MAX_SEQ && tag_ok).then_some(seq)
    }
}

/// The synthesized receipt ID for a compacted token (RTC-8): the first 16 bytes of
/// SHA-256("kilnd-fc-compacted-v1" ‖ node ‖ instance ‖ allocation ‖ plan digest ‖ G_W),
/// with the IDs and digest as raw bytes and G_W as eight big-endian bytes.
pub fn compacted_receipt_id(
    node: Id128,
    instance: Id128,
    allocation: Id128,
    plan_digest: &Digest,
    watermark_generation: u64,
) -> Id128 {
    let mut hasher = Sha256::new();
    hasher.update(COMPACTED_LABEL);
    hasher.update(node.as_bytes());
    hasher.update(instance.as_bytes());
    hasher.update(allocation.as_bytes());
    hasher.update(plan_digest.as_bytes());
    hasher.update(watermark_generation.to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    Id128::from_bytes(digest[..16].try_into().expect("sixteen bytes"))
}

/// K's only transfer form: L's reply to H over their private socket, never a wire or
/// public reply. Its `Debug` is redacted like the key's.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyTransfer {
    node_id: Id128,
    key: String,
}

impl std::fmt::Debug for KeyTransfer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyTransfer(node {}, redacted)", self.node_id)
    }
}

impl KeyTransfer {
    pub(super) fn of(key: &TokenKey) -> Self {
        Self {
            node_id: key.node_id,
            key: key.key.iter().map(|b| format!("{b:02x}")).collect(),
        }
    }

    pub(super) fn into_key(self) -> Option<TokenKey> {
        let bytes = self.key.as_bytes();
        if bytes.len() != 64 {
            return None;
        }
        let mut key = [0u8; 32];
        for (index, pair) in bytes.chunks(2).enumerate() {
            let text = std::str::from_utf8(pair).ok()?;
            if text.bytes().any(|b| !matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                return None;
            }
            key[index] = u8::from_str_radix(text, 16).ok()?;
        }
        Some(TokenKey::from_parts(self.node_id, key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> TokenKey {
        TokenKey::from_parts(Id128::from_bytes([7; 16]), [9; 32])
    }

    #[test]
    fn rtc1_hmac_matches_the_rfc_4231_vector() {
        // RFC 4231 test case 2 uses a 4-byte key; pad it into our fixed 32-byte form.
        // HMAC zero-pads short keys, so the result is the same.
        let mut k = [0u8; 32];
        k[..4].copy_from_slice(b"Jefe");
        let mac = hmac_sha256(&k, &[b"what do ya want ", b"for nothing?"]);
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn rtc1_tokens_are_seq_then_tag_and_verify_only_in_their_instance() {
        let key = key();
        let (mine, other) = (Id128::from_bytes([1; 16]), Id128::from_bytes([2; 16]));
        let token = key.issue(mine, 42);
        assert_eq!(seq_of(token), 42);
        assert!(token.to_string().starts_with("000000000000002a"));
        assert_eq!(token.to_string().len(), 32);
        assert_eq!(key.verify(mine, token), Some(42));
        assert_eq!(key.verify(other, token), None, "another instance's token is Malformed");
        for bit in 64..128 {
            let mut bytes = *token.as_bytes();
            bytes[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(key.verify(mine, Id128::from_bytes(bytes)), None);
        }
        let mut zero = *key.issue(mine, 0).as_bytes();
        zero[..8].copy_from_slice(&0u64.to_be_bytes());
        assert_eq!(key.verify(mine, Id128::from_bytes(zero)), None, "seq 0");
        let random = Id128::from_bytes([0xab; 16]);
        assert_eq!(key.verify(mine, random), None, "an old random ID");
        let substituted = TokenKey::from_parts(key.node_id(), [10; 32]);
        assert_eq!(substituted.verify(mine, token), None);
        assert!(!substituted.check_matches(&key.check_value()));
        assert!(key.check_matches(&key.check_value()));
        assert!(shape_ok(token));
        assert!(!shape_ok(Id128::from_bytes([0; 16])));
        assert!(!shape_ok(Id128::from_bytes([0xff; 16])));
    }

    #[test]
    fn rtc1_key_is_never_printed_and_transfers_exactly() {
        let key = key();
        let printed = format!("{key:?} {:?}", KeyTransfer::of(&key));
        assert!(!printed.contains("0909"), "{printed}");
        let back = KeyTransfer::of(&key).into_key().unwrap();
        assert_eq!(back, key);
        let wire = serde_json::to_string(&KeyTransfer::of(&key)).unwrap();
        let mut tampered: KeyTransfer = serde_json::from_str(&wire).unwrap();
        tampered.key.truncate(10);
        assert!(tampered.into_key().is_none());
    }

    #[test]
    fn rtc8_compacted_receipt_ids_bind_every_input() {
        let (n, i, a) = (
            Id128::from_bytes([1; 16]),
            Id128::from_bytes([2; 16]),
            Id128::from_bytes([3; 16]),
        );
        let d = Digest::of(b"plan");
        let base = compacted_receipt_id(n, i, a, &d, 9);
        assert_eq!(base, compacted_receipt_id(n, i, a, &d, 9));
        assert_ne!(base, compacted_receipt_id(n, i, a, &d, 10));
        assert_ne!(base, compacted_receipt_id(n, i, a, &Digest::of(b"other"), 9));
        assert_ne!(base, compacted_receipt_id(i, n, a, &d, 9));
    }
}
