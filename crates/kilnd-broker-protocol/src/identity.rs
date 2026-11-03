//! The vdc identity block (B1 contract `identity`): `KID1`, a big-endian length of
//! 1..=4088, the canonical JSON record and zero padding to 4096 bytes. The guest reads
//! it from `/dev/vdc` (through `/init`'s bootstrap descriptor); the host writes it from
//! its plan. Both sides parse it here, strictly: the record must be the exact canonical
//! encoding of its eight fields, so no second spelling of the same identity exists.

use crate::error::{ProtocolError, Result};
use crate::json;
use crate::message::{GuestIdentity, canonical_string};

pub const IDENTITY_BYTES: usize = 4096;
pub const IDENTITY_MAGIC: [u8; 4] = *b"KID1";
/// `/init`'s hardening record after the identity block on the bootstrap descriptor.
pub const HARDENING_MAGIC: [u8; 4] = *b"KGH1";
pub const BOOTSTRAP_BYTES: usize = IDENTITY_BYTES + 8;

impl GuestIdentity {
    /// The canonical record: sorted keys, compact, every value an ASCII string.
    pub fn canonical_json(&self) -> Vec<u8> {
        let fields = [
            ("allocation_id", self.allocation_id.to_string()),
            ("boot_nonce", self.boot_nonce.to_string()),
            (
                "guest_exec_spec_sha256",
                self.guest_exec_spec_sha256.to_string(),
            ),
            ("instance_id", self.instance_id.to_string()),
            ("launch_sha256", self.launch_sha256.to_string()),
            ("manifest_sha256", self.manifest_sha256.to_string()),
            ("sandbox_id", self.sandbox_id.to_string()),
            ("work_uuid", self.work_uuid.to_string()),
        ];
        let mut out = String::from("{");
        for (i, (key, value)) in fields.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            canonical_string(&mut out, key);
            out.push(':');
            canonical_string(&mut out, value);
        }
        out.push('}');
        out.into_bytes()
    }

    /// The 4096-byte block.
    pub fn block(&self) -> Vec<u8> {
        let record = self.canonical_json();
        let mut block = Vec::with_capacity(IDENTITY_BYTES);
        block.extend_from_slice(&IDENTITY_MAGIC);
        block.extend_from_slice(&(record.len() as u32).to_be_bytes());
        block.extend_from_slice(&record);
        block.resize(IDENTITY_BYTES, 0);
        block
    }
}

/// Parses a whole identity block.
pub fn parse_block(block: &[u8]) -> Result<GuestIdentity> {
    if block.len() != IDENTITY_BYTES || block[..4] != IDENTITY_MAGIC {
        return Err(ProtocolError::InvalidField("identity block"));
    }
    let len = u32::from_be_bytes(block[4..8].try_into().expect("4 bytes")) as usize;
    if len == 0 || len > IDENTITY_BYTES - 8 {
        return Err(ProtocolError::InvalidField("identity length"));
    }
    if block[8 + len..].iter().any(|b| *b != 0) {
        return Err(ProtocolError::InvalidField("identity padding"));
    }
    let record = &block[8..8 + len];
    let identity: GuestIdentity = json::from_slice(record)?;
    if identity.canonical_json() != record {
        return Err(ProtocolError::InvalidField("identity is not canonical"));
    }
    Ok(identity)
}

/// The bootstrap record `/init` writes on descriptor 3: the identity block, then
/// `KGH1` and a big-endian bitmask of its seven hardening checks.
pub fn parse_bootstrap(bytes: &[u8]) -> Result<(GuestIdentity, u32)> {
    if bytes.len() != BOOTSTRAP_BYTES
        || bytes[IDENTITY_BYTES..IDENTITY_BYTES + 4] != HARDENING_MAGIC
    {
        return Err(ProtocolError::InvalidField("bootstrap record"));
    }
    let identity = parse_block(&bytes[..IDENTITY_BYTES])?;
    let mask = u32::from_be_bytes(bytes[IDENTITY_BYTES + 4..].try_into().expect("4 bytes"));
    if mask & !0x7f != 0 {
        return Err(ProtocolError::InvalidField("hardening mask"));
    }
    Ok((identity, mask))
}

/// The hardening record's bits, in `Hardening`'s field order.
pub fn hardening_from_mask(mask: u32) -> crate::message::Hardening {
    let bit = |n: u32| mask & (1 << n) != 0;
    crate::message::Hardening {
        cmdline: bit(0),
        kernel_log_bounded: bit(1),
        kaslr: bit(2),
        memory_initialization: bit(3),
        kstack_offset: bit(4),
        lockdown_confidentiality: bit(5),
        kexec_absent: bit(6),
    }
}
