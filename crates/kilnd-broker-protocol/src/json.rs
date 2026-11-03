//! Strict control-payload JSON (design 5.2): UTF-8, integers only, no duplicate keys at
//! any level, nesting of at most [`MAX_DEPTH`], and nothing after the value. A full
//! grammar check runs before serde sees a byte, so serde only maps an already strict
//! document onto a `deny_unknown_fields` type.

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{ProtocolError, Result};

/// Objects and arrays may nest this deep; the top-level object is depth 1.
pub const MAX_DEPTH: usize = 8;
/// A serde error message is echoed at most this long; it can quote a field name.
const MAX_SCHEMA_MESSAGE: usize = 256;

/// Checks `bytes` against the strict grammar.
pub fn check(bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes).map_err(|_| ProtocolError::Utf8)?;
    let mut scanner = Scanner {
        bytes: text.as_bytes(),
        at: 0,
    };
    scanner.whitespace();
    scanner.value(1)?;
    scanner.whitespace();
    if scanner.at != scanner.bytes.len() {
        return Err(ProtocolError::JsonSyntax(scanner.at));
    }
    Ok(())
}

/// Checks, then deserializes into a strict type.
pub fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    check(bytes)?;
    serde_json::from_slice(bytes).map_err(|error| {
        let mut message = error.to_string();
        if message.len() > MAX_SCHEMA_MESSAGE {
            let mut end = MAX_SCHEMA_MESSAGE;
            while !message.is_char_boundary(end) {
                end -= 1;
            }
            message.truncate(end);
        }
        ProtocolError::Schema(message)
    })
}

/// Compact JSON. Every protocol type serializes without floats or maps with
/// duplicate keys, so the result passes [`check`].
pub fn to_vec<T: Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).expect("protocol types always serialize")
}

struct Scanner<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Scanner<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn syntax<T>(&self) -> Result<T> {
        Err(ProtocolError::JsonSyntax(self.at))
    }

    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn literal(&mut self, word: &[u8]) -> Result<()> {
        if self.bytes[self.at..].starts_with(word) {
            self.at += word.len();
            Ok(())
        } else {
            self.syntax()
        }
    }

    fn value(&mut self, depth: usize) -> Result<()> {
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(drop),
            Some(b't') => self.literal(b"true"),
            Some(b'f') => self.literal(b"false"),
            Some(b'n') => self.literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => self.syntax(),
        }
    }

    fn object(&mut self, depth: usize) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(ProtocolError::JsonDepth);
        }
        self.at += 1;
        self.whitespace();
        // A set, so a wide object costs O(n log n), not quadratic comparisons.
        let mut keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(());
        }
        loop {
            if self.peek() != Some(b'"') {
                return self.syntax();
            }
            let key = self.string()?;
            // Compared decoded, so `"a"` and `"\u0061"` are the same key.
            if !keys.insert(key) {
                return Err(ProtocolError::JsonDuplicateKey);
            }
            self.whitespace();
            if self.peek() != Some(b':') {
                return self.syntax();
            }
            self.at += 1;
            self.whitespace();
            self.value(depth + 1)?;
            self.whitespace();
            match self.peek() {
                Some(b',') => {
                    self.at += 1;
                    self.whitespace();
                }
                Some(b'}') => {
                    self.at += 1;
                    return Ok(());
                }
                _ => return self.syntax(),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(ProtocolError::JsonDepth);
        }
        self.at += 1;
        self.whitespace();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(());
        }
        loop {
            self.value(depth + 1)?;
            self.whitespace();
            match self.peek() {
                Some(b',') => {
                    self.at += 1;
                    self.whitespace();
                }
                Some(b']') => {
                    self.at += 1;
                    return Ok(());
                }
                _ => return self.syntax(),
            }
        }
    }

    /// An integer: `-?(0|[1-9][0-9]*)`. A fraction or exponent is a float; `-0` is
    /// refused as well, so every number has one spelling.
    fn number(&mut self) -> Result<()> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.at += 1;
                if self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    return self.syntax();
                }
                if self.at - start == 2 {
                    return Err(ProtocolError::JsonFloat);
                }
            }
            Some(b'1'..=b'9') => {
                while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    self.at += 1;
                }
            }
            _ => return self.syntax(),
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(ProtocolError::JsonFloat);
        }
        Ok(())
    }

    fn hex4(&mut self) -> Result<u16> {
        let digits = self.bytes.get(self.at..self.at + 4);
        let value = digits
            .and_then(|d| std::str::from_utf8(d).ok())
            .filter(|d| d.bytes().all(|c| c.is_ascii_hexdigit()))
            .and_then(|d| u16::from_str_radix(d, 16).ok());
        match value {
            Some(value) => {
                self.at += 4;
                Ok(value)
            }
            None => self.syntax(),
        }
    }

    /// A string, decoded. Raw control characters and lone surrogates are refused.
    fn string(&mut self) -> Result<String> {
        self.at += 1;
        let mut out = String::new();
        loop {
            let start = self.at;
            while let Some(c) = self.peek() {
                if c == b'"' || c == b'\\' || c < 0x20 {
                    break;
                }
                self.at += 1;
            }
            // The input is valid UTF-8 and the stops are ASCII, so this is a boundary.
            out.push_str(std::str::from_utf8(&self.bytes[start..self.at]).expect("UTF-8"));
            match self.peek() {
                Some(b'"') => {
                    self.at += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.at += 1;
                    let escape = self.peek();
                    self.at += 1;
                    match escape {
                        Some(b'"') => out.push('"'),
                        Some(b'\\') => out.push('\\'),
                        Some(b'/') => out.push('/'),
                        Some(b'b') => out.push('\u{8}'),
                        Some(b'f') => out.push('\u{c}'),
                        Some(b'n') => out.push('\n'),
                        Some(b'r') => out.push('\r'),
                        Some(b't') => out.push('\t'),
                        Some(b'u') => {
                            let first = self.hex4()?;
                            let scalar = match first {
                                0xd800..=0xdbff => {
                                    if !self.bytes[self.at..].starts_with(b"\\u") {
                                        return self.syntax();
                                    }
                                    self.at += 2;
                                    let second = self.hex4()?;
                                    if !(0xdc00..=0xdfff).contains(&second) {
                                        return self.syntax();
                                    }
                                    0x10000
                                        + ((u32::from(first) - 0xd800) << 10)
                                        + (u32::from(second) - 0xdc00)
                                }
                                0xdc00..=0xdfff => return self.syntax(),
                                _ => u32::from(first),
                            };
                            out.push(char::from_u32(scalar).expect("valid scalar"));
                        }
                        _ => {
                            self.at -= 1;
                            return self.syntax();
                        }
                    }
                }
                _ => return self.syntax(),
            }
        }
    }
}
