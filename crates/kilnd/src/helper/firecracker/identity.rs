//! Allocation, UID, GID and CID identities. Each host identity has its own type, so
//! a VMM UID cannot stand in for a relay UID or a GID. Preflight only *selects*
//! currently unclaimed candidates; the ledger claims them, or refuses them, at C2.
use crate::model::{Digest, Id128};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io::Read;
use std::ops::RangeInclusive;

macro_rules! lease_type {
    ($name:ident, $kind:literal) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name(pub u32);

        impl $name {
            pub const KIND: &'static str = $kind;
            pub fn substitution(self) -> Value {
                json!({"kind": Self::KIND, "value": self.0})
            }
        }
    };
}

lease_type!(VmmUid, "VmmUid");
lease_type!(VmmGid, "VmmGid");
lease_type!(RelayUid, "RelayUid");
lease_type!(RelayGid, "RelayGid");

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestCid(pub u32);

/// The exact identities one plan names. They are claimed together or not at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityLeases {
    pub vmm_uid: VmmUid,
    pub vmm_gid: VmmGid,
    pub relay_uid: RelayUid,
    pub relay_gid: RelayGid,
    pub cid: GuestCid,
}

/// The lease types in collision order; `LeaseKind::as_str` names them in the ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseKind {
    VmmUid,
    RelayUid,
    VmmGid,
    RelayGid,
    Cid,
}

impl LeaseKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VmmUid => "vmm_uid",
            Self::RelayUid => "relay_uid",
            Self::VmmGid => "vmm_gid",
            Self::RelayGid => "relay_gid",
            Self::Cid => "cid",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "vmm_uid" => Self::VmmUid,
            "relay_uid" => Self::RelayUid,
            "vmm_gid" => Self::VmmGid,
            "relay_gid" => Self::RelayGid,
            "cid" => Self::Cid,
            _ => return None,
        })
    }

    /// UIDs, GIDs and CIDs are separate numeric spaces. An equal UID and GID is
    /// allowed; two allocations sharing either is not.
    pub fn namespace(self) -> &'static str {
        match self {
            Self::VmmUid | Self::RelayUid => "uid",
            Self::VmmGid | Self::RelayGid => "gid",
            Self::Cid => "cid",
        }
    }
}

impl IdentityLeases {
    pub fn rows(&self) -> [(LeaseKind, u32); 5] {
        [
            (LeaseKind::VmmUid, self.vmm_uid.0),
            (LeaseKind::RelayUid, self.relay_uid.0),
            (LeaseKind::VmmGid, self.vmm_gid.0),
            (LeaseKind::RelayGid, self.relay_gid.0),
            (LeaseKind::Cid, self.cid.0),
        ]
    }
}

/// The root-configured ranges. Installation checks them against NSS and subuid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityRanges {
    pub uid: RangeInclusive<u32>,
    pub gid: RangeInclusive<u32>,
    pub cid: RangeInclusive<u32>,
}

impl Default for IdentityRanges {
    fn default() -> Self {
        Self {
            uid: 300_000..=365_535,
            gid: 300_000..=365_535,
            cid: 3..=65_535,
        }
    }
}

impl IdentityRanges {
    /// Section 6.2's frozen limits, and never the service account itself.
    pub fn validate(&self, service_uid: u32) -> Result<(), String> {
        let frozen = Self::default();
        let inside = |range: &RangeInclusive<u32>, frozen: &RangeInclusive<u32>| {
            range.start() <= range.end()
                && frozen.contains(range.start())
                && frozen.contains(range.end())
        };
        if !inside(&self.uid, &frozen.uid)
            || !inside(&self.gid, &frozen.gid)
            || !inside(&self.cid, &frozen.cid)
        {
            return Err("identity ranges leave the frozen contract limits".into());
        }
        if self.uid.contains(&service_uid) {
            return Err("identity range contains the service UID".into());
        }
        Ok(())
    }

    /// A plan may name only identities its catalog could have selected.
    pub fn contains(&self, leases: &IdentityLeases) -> bool {
        self.uid.contains(&leases.vmm_uid.0)
            && self.uid.contains(&leases.relay_uid.0)
            && self.gid.contains(&leases.vmm_gid.0)
            && self.gid.contains(&leases.relay_gid.0)
            && self.cid.contains(&leases.cid.0)
    }
}

/// Every unreleased identity on the node, used only to pick candidates. Being absent
/// here reserves nothing: another plan can pick the same value before C2.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimedIdentities {
    pub uids: BTreeSet<u32>,
    pub gids: BTreeSet<u32>,
    pub cids: BTreeSet<u32>,
}

fn free_values(
    range: &RangeInclusive<u32>,
    claimed: &BTreeSet<u32>,
    count: usize,
    entropy: &mut impl FnMut() -> u32,
) -> Option<Vec<u32>> {
    let (start, end) = (*range.start(), *range.end());
    let span = u64::from(end - start) + 1;
    let first = u64::from(entropy()) % span;
    let mut picked = Vec::with_capacity(count);
    // A bounded probe from a random start spreads concurrent preflights apart.
    // `claimed` is bounded by the node's slot ceiling, so this ends quickly.
    for offset in 0..span.min(claimed.len() as u64 + count as u64) {
        let value = start + ((first + offset) % span) as u32;
        if !claimed.contains(&value) {
            picked.push(value);
            if picked.len() == count {
                return Some(picked);
            }
        }
    }
    None
}

/// Selects a free VMM and relay UID/GID pair and a CID without reserving any of them.
pub fn select_candidates(
    ranges: &IdentityRanges,
    claimed: &ClaimedIdentities,
    entropy: &mut impl FnMut() -> u32,
) -> Result<IdentityLeases, String> {
    let exhausted = |name: &str| format!("no free {name} identity in the configured range");
    let uids =
        free_values(&ranges.uid, &claimed.uids, 2, entropy).ok_or_else(|| exhausted("UID"))?;
    let gids =
        free_values(&ranges.gid, &claimed.gids, 2, entropy).ok_or_else(|| exhausted("GID"))?;
    let cids =
        free_values(&ranges.cid, &claimed.cids, 1, entropy).ok_or_else(|| exhausted("CID"))?;
    Ok(IdentityLeases {
        vmm_uid: VmmUid(uids[0]),
        relay_uid: RelayUid(uids[1]),
        vmm_gid: VmmGid(gids[0]),
        relay_gid: RelayGid(gids[1]),
        cid: GuestCid(cids[0]),
    })
}

fn urandom(bytes: &mut [u8]) -> std::io::Result<()> {
    std::fs::File::open("/dev/urandom")?.read_exact(bytes)
}

pub fn random_u32() -> std::io::Result<u32> {
    let mut bytes = [0u8; 4];
    urandom(&mut bytes)?;
    Ok(u32::from_ne_bytes(bytes))
}

/// A fresh 256-bit boot nonce in the plan's hexadecimal form.
pub fn new_boot_nonce() -> std::io::Result<String> {
    let mut bytes = [0u8; 32];
    urandom(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// A canonical UUIDv4, as the contract's `work_uuid` substitution requires.
pub fn new_work_uuid() -> std::io::Result<String> {
    let mut bytes = [0u8; 16];
    urandom(&mut bytes)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

/// The only backend ID an allocation can ever publish. It names the allocation inside its
/// own instance, as the allocation ID does: two instances may hold the same one.
pub fn backend_id(allocation: Id128) -> String {
    format!("fc-{allocation}")
}

/// One allocation's identity across the node. An allocation ID means nothing without the
/// authenticated instance it belongs to, and anything held per allocation is held by this.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllocationKey {
    pub instance: Id128,
    pub allocation: Id128,
}

/// What the launch contract's host names are derived from, in place of a bare allocation
/// ID: jailer IDs and jail roots are node-global, and a copied allocation ID must not reach
/// another instance's. The same 32 digits the contract's formula takes, so its paths still
/// fit sockaddr_un, and finding another pair with this value is a SHA-256 second preimage.
pub fn host_allocation(instance: Id128, allocation: Id128) -> String {
    let digest =
        Digest::of(format!("kilnd-firecracker-host-name-v1\0{instance}\0{allocation}").as_bytes());
    digest.to_string()[..32].to_string()
}

/// The node-unique name of this allocation's host resources.
pub fn host_name(instance: Id128, allocation: Id128) -> String {
    format!("fc-{}", host_allocation(instance, allocation))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_avoid_every_claim_and_distinct_kinds_stay_distinct() {
        let ranges = IdentityRanges {
            uid: 300_000..=300_003,
            gid: 300_000..=300_003,
            cid: 3..=5,
        };
        let claimed = ClaimedIdentities {
            uids: [300_001].into(),
            gids: [300_002].into(),
            cids: [3].into(),
        };
        for seed in 0..64u32 {
            let mut entropy = {
                let mut next = seed;
                move || {
                    next = next.wrapping_mul(31).wrapping_add(7);
                    next
                }
            };
            let leases = select_candidates(&ranges, &claimed, &mut entropy).unwrap();
            assert!(ranges.contains(&leases));
            assert_ne!(leases.vmm_uid.0, leases.relay_uid.0);
            assert_ne!(leases.vmm_gid.0, leases.relay_gid.0);
            assert!(!claimed.uids.contains(&leases.vmm_uid.0));
            assert!(!claimed.uids.contains(&leases.relay_uid.0));
            assert!(!claimed.gids.contains(&leases.vmm_gid.0));
            assert!(!claimed.gids.contains(&leases.relay_gid.0));
            assert!(!claimed.cids.contains(&leases.cid.0));
        }
    }

    #[test]
    fn exhausted_ranges_refuse_without_a_substitute_outside_the_range() {
        let ranges = IdentityRanges {
            uid: 300_000..=300_001,
            gid: 300_000..=300_001,
            cid: 3..=3,
        };
        let mut entropy = || 0;
        let mut claimed = ClaimedIdentities::default();
        assert!(select_candidates(&ranges, &claimed, &mut entropy).is_ok());
        claimed.uids.insert(300_000);
        assert!(
            select_candidates(&ranges, &claimed, &mut entropy)
                .unwrap_err()
                .contains("UID")
        );
        claimed.uids.clear();
        claimed.gids.insert(300_001);
        assert!(
            select_candidates(&ranges, &claimed, &mut entropy)
                .unwrap_err()
                .contains("GID")
        );
        claimed.gids.clear();
        claimed.cids.insert(3);
        assert!(
            select_candidates(&ranges, &claimed, &mut entropy)
                .unwrap_err()
                .contains("CID")
        );
    }

    #[test]
    fn ranges_stay_inside_the_contract_and_away_from_the_service_uid() {
        let contract = crate::firecracker::contract();
        let limits = &contract["leases"];
        let frozen = IdentityRanges::default();
        assert_eq!(
            [*frozen.uid.start() as u64, *frozen.uid.end() as u64],
            [
                limits["uid"][0].as_u64().unwrap(),
                limits["uid"][1].as_u64().unwrap()
            ]
        );
        assert_eq!(
            [*frozen.cid.start() as u64, *frozen.cid.end() as u64],
            [
                limits["cid"][0].as_u64().unwrap(),
                limits["cid"][1].as_u64().unwrap()
            ]
        );
        assert!(frozen.validate(999).is_ok());
        assert!(frozen.validate(300_500).is_err());
        let wide = IdentityRanges {
            cid: 1..=65_535,
            ..IdentityRanges::default()
        };
        assert!(wide.validate(999).is_err());
        let wide = IdentityRanges {
            gid: 299_999..=365_535,
            ..IdentityRanges::default()
        };
        assert!(wide.validate(999).is_err());
    }

    #[test]
    fn b3r_01_a_host_name_belongs_to_one_instance_and_one_allocation() {
        let (first, second) = (Id128::from_bytes([1; 16]), Id128::from_bytes([2; 16]));
        let shared = Id128::from_bytes([3; 16]);
        assert_ne!(host_name(first, shared), host_name(second, shared));
        assert_ne!(host_name(first, shared), host_name(shared, first));
        assert_ne!(host_name(first, shared), host_name(first, second));
        assert_eq!(host_name(first, shared), host_name(first, shared));
        // The contract's own shape, so every path it derives is the same length.
        let name = host_name(first, shared);
        assert_eq!(name.len(), backend_id(shared).len());
        assert!(name.strip_prefix("fc-").is_some_and(|hex| {
            hex.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }));
    }

    #[test]
    fn fresh_identity_material_has_its_exact_form() {
        assert_eq!(new_boot_nonce().unwrap().len(), 64);
        let uuid = new_work_uuid().unwrap();
        assert_eq!(uuid.len(), 36);
        assert_eq!(uuid.as_bytes()[14], b'4');
        assert!(b"89ab".contains(&uuid.as_bytes()[19]));
        assert_ne!(new_work_uuid().unwrap(), uuid);
    }
}
