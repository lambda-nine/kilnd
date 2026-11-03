//! Bounded field types. Each one rejects, while deserializing, any value outside its
//! exact form, so a parsed message never holds an unbounded or ambiguous field.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::MAX_DIAGNOSTIC_BYTES;

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_lower_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// 128 bits: request IDs, execution tokens and kilnd's instance and allocation IDs.
/// Exactly 32 lowercase hex characters in JSON.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Id128(pub [u8; 16]);

/// 256 bits: challenges, nonces and SHA-256 digests. Exactly 64 lowercase hex
/// characters in JSON.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Hex32(pub [u8; 32]);

macro_rules! hex_type {
    ($name:ident, $n:literal, $what:literal) => {
        impl $name {
            pub fn parse(value: &str) -> Option<Self> {
                parse_lower_hex::<$n>(value).map(Self)
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&lower_hex(&self.0))
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), lower_hex(&self.0))
            }
        }
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&lower_hex(&self.0))
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let value = String::deserialize(d)?;
                Self::parse(&value).ok_or_else(|| serde::de::Error::custom($what))
            }
        }
    };
}

hex_type!(Id128, 16, "expected 32 lowercase hex characters");
hex_type!(Hex32, 32, "expected 64 lowercase hex characters");

impl Id128 {
    /// From the kernel's CSPRNG.
    pub fn random() -> std::io::Result<Self> {
        use std::io::Read;
        let mut bytes = [0u8; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        Ok(Self(bytes))
    }
}

impl Hex32 {
    pub fn random() -> std::io::Result<Self> {
        use std::io::Read;
        let mut bytes = [0u8; 32];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        Ok(Self(bytes))
    }

    pub fn sha256(bytes: &[u8]) -> Self {
        use sha2::Digest;
        Self(sha2::Sha256::digest(bytes).into())
    }
}

/// A string newtype whose deserializer accepts only values `$check` approves.
macro_rules! checked_string {
    ($(#[$doc:meta])* $name:ident, $check:expr, $what:literal) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, Hash, Debug)]
        pub struct $name(String);
        impl $name {
            pub fn new(value: impl Into<String>) -> Option<Self> {
                let value = value.into();
                let check: fn(&str) -> bool = $check;
                check(&value).then_some(Self(value))
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.0)
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                Self::new(String::deserialize(d)?)
                    .ok_or_else(|| serde::de::Error::custom($what))
            }
        }
    };
}

/// kilnd's `<kind>-<16 lowercase hex>` ID shape.
fn kilnd_id(kind: &str, value: &str) -> bool {
    value.len() == kind.len() + 17
        && value.starts_with(kind)
        && value.as_bytes()[kind.len()] == b'-'
        && value[kind.len() + 1..]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// A canonical lowercase UUID, `8-4-4-4-12`.
fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        })
}

checked_string!(
    /// kilnd's sandbox ID, `sb-` and 16 lowercase hex characters.
    SandboxId,
    |v| kilnd_id("sb", v),
    "expected a kilnd sandbox ID"
);
checked_string!(
    /// kilnd's public execution ID, `ex-` and 16 lowercase hex characters.
    ExecutionId,
    |v| kilnd_id("ex", v),
    "expected a kilnd execution ID"
);
checked_string!(
    /// The guest kernel's boot ID (`/proc/sys/kernel/random/boot_id`).
    BootId,
    uuid,
    "expected a canonical lowercase boot ID"
);
checked_string!(
    /// The work disk's XFS UUID: a canonical lowercase UUIDv4, as B1's launch
    /// derivation requires.
    WorkUuid,
    |v| uuid(v) && v.as_bytes()[14] == b'4' && b"89ab".contains(&v.as_bytes()[19]),
    "expected a canonical lowercase UUIDv4"
);
checked_string!(
    /// The persistent inner kiln sandbox ID, under kiln's own ID grammar.
    InnerId,
    kilnd_exec_core::runtime::kiln_direct::valid_kiln_id,
    "expected a kiln sandbox ID"
);
checked_string!(
    /// A diagnostic narrowed for the wire: at most 2048 UTF-8 bytes (design 5.2).
    WireText,
    |v| v.len() <= MAX_DIAGNOSTIC_BYTES,
    "diagnostic exceeds 2048 bytes"
);

impl WireText {
    /// Narrows any text to the wire bound on a character boundary. Returns the text
    /// and whether anything was cut.
    pub fn narrow(text: &str) -> (Self, bool) {
        if text.len() <= MAX_DIAGNOSTIC_BYTES {
            return (Self(text.to_string()), false);
        }
        let mut end = MAX_DIAGNOSTIC_BYTES;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        (Self(text[..end].to_string()), true)
    }
}
