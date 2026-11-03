//! Strict persistent-exec v1 codec. Phase 1b B5 moved it to the direct-kiln core crate
//! (`kilnd_exec_core::runtime::kiln_protocol`); this module re-exports it.

pub use kilnd_exec_core::runtime::kiln_protocol::*;

/// Golden frames the kiln adapter's tests use. A copy of the core crate's `cfg(test)`
/// vectors, which another crate's tests cannot reach.
#[cfg(test)]
pub(super) mod tests {
    pub fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    pub fn exit125() -> Vec<u8> {
        hex(
            "4b494c4e45584f00 0100 0100 18000000 01010200 7d000000 0000 0000 00000000 00000000 00000000",
        )
    }
}
