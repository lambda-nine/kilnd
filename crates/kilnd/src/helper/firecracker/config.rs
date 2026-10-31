//! The root-owned node policy and the exact plan. A plan is canonical bytes built by
//! one function; `Create` recomputes that function from the plan's typed fields and
//! compares bytes, so nothing a client returns can differ from what was approved.
use super::executable::{ExecutableIdentity, Role};
use super::identity::{
    GuestCid, IdentityLeases, IdentityRanges, RelayGid, RelayUid, VmmGid, VmmUid,
};
use crate::firecracker::{SpecBinding, canonical, derive_launch, strict_json};
use crate::model::{Digest, Id128, ResourceReservation, SandboxSpec};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;

const MIB: u64 = 1024 * 1024;
pub const POLICY_SCHEMA: &str = "kilnd-firecracker-node-policy-v1";
pub const PLAN_SCHEMA: &str = "kilnd-firecracker-plan-v1";
pub const PLAN_VERSION: u32 = 1;
pub const DEFAULT_LEDGER_DIR: &str = "/var/lib/kilnd-helper/firecracker";
pub const DEFAULT_EXEC_STORE: &str = "/opt/kilnd/exec/sha256";
pub const MAX_PROFILES: usize = 8;

/// The root catalog's node ceilings. A daemon can narrow these, never expand them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeCeilings {
    pub slots: u64,
    pub memory_bytes: u64,
    pub disk_bytes: u64,
    pub host_cpu_millis: u64,
    pub virtual_cpu_slots: u64,
    pub pids: u64,
    pub host_pids: u64,
}

impl Default for NodeCeilings {
    fn default() -> Self {
        Self {
            slots: 3,
            memory_bytes: 3072 * MIB,
            disk_bytes: 16 * 1024 * MIB,
            host_cpu_millis: 3500,
            virtual_cpu_slots: 3,
            pids: 2048,
            host_pids: 128,
        }
    }
}

/// Infrastructure charged once per node, before any session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedReserve {
    pub memory_bytes: u64,
    pub host_cpu_millis: u64,
    pub pids: u64,
    pub host_pids: u64,
    pub disk_bytes: u64,
    pub store_bytes: u64,
    pub fence_allowance_bytes: u64,
}

impl Default for SharedReserve {
    fn default() -> Self {
        Self {
            memory_bytes: 128 * MIB,
            host_cpu_millis: 500,
            pids: 32,
            host_pids: 32,
            disk_bytes: 512 * MIB,
            store_bytes: 1024 * MIB,
            fence_allowance_bytes: 64 * MIB,
        }
    }
}

impl SharedReserve {
    /// Everything counted in the aggregate disk dimension.
    pub fn total_disk(&self) -> Option<u64> {
        self.disk_bytes.checked_add(self.store_bytes)
    }
}

/// One operator-approved profile. Its digest is configured here, independently of
/// the bundle; nothing a request says can name another bundle or path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileCatalog {
    pub profile: String,
    pub approved_manifest_sha256: Digest,
    pub bundle_directory: PathBuf,
    pub exec_store: PathBuf,
    pub catalog_generation: u64,
    /// Per-role node-local installation generations.
    pub installation_generations: BTreeMap<Role, u64>,
}

/// The parsed policy file. Its absence means the group stays disabled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodePolicy {
    pub node_id: Id128,
    pub ledger_dir: PathBuf,
    pub ceilings: NodeCeilings,
    pub identity_ranges: IdentityRanges,
    pub profiles: Vec<ProfileCatalog>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRange {
    first: u32,
    last: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePolicy {
    schema: String,
    node_id: Id128,
    ledger_dir: PathBuf,
    ceilings: NodeCeilings,
    uid_range: WireRange,
    gid_range: WireRange,
    cid_range: WireRange,
    profiles: Vec<ProfileCatalog>,
}

/// Valid profile names are `[a-z0-9-]`, 1 to 64 bytes.
pub fn valid_profile(profile: &str) -> bool {
    !profile.is_empty()
        && profile.len() <= 64
        && profile
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Parses the root-owned policy with strict JSON and exact fields. It does not read
/// the paths it names; those are verified by protected traversal in the workers.
pub fn parse_policy(raw: &[u8], service_uid: u32) -> Result<NodePolicy, String> {
    let wire: WirePolicy =
        serde_json::from_value(strict_json(raw)?).map_err(|e| format!("node policy: {e}"))?;
    if wire.schema != POLICY_SCHEMA {
        return Err("node policy has an unknown schema".into());
    }
    let ranges = IdentityRanges {
        uid: wire.uid_range.first..=wire.uid_range.last,
        gid: wire.gid_range.first..=wire.gid_range.last,
        cid: wire.cid_range.first..=wire.cid_range.last,
    };
    ranges.validate(service_uid)?;
    if wire.profiles.len() > MAX_PROFILES {
        return Err("too many approved profiles".into());
    }
    for catalog in &wire.profiles {
        if !valid_profile(&catalog.profile)
            || !catalog.bundle_directory.is_absolute()
            || !catalog.exec_store.is_absolute()
            || catalog.catalog_generation == 0
        {
            return Err("invalid profile catalog".into());
        }
    }
    if !wire.ledger_dir.is_absolute() {
        return Err("ledger directory must be absolute".into());
    }
    validate_ceilings(&wire.ceilings, &SharedReserve::default())?;
    Ok(NodePolicy {
        node_id: wire.node_id,
        ledger_dir: wire.ledger_dir,
        ceilings: wire.ceilings,
        identity_ranges: ranges,
        profiles: wire.profiles,
    })
}

/// The shared reserve always fits inside the ceilings, or no session could.
pub fn validate_ceilings(ceilings: &NodeCeilings, shared: &SharedReserve) -> Result<(), String> {
    let disk = shared.total_disk().ok_or("shared disk reserve overflows")?;
    if ceilings.slots == 0
        || ceilings.memory_bytes < shared.memory_bytes
        || ceilings.host_cpu_millis < shared.host_cpu_millis
        || ceilings.pids < shared.pids
        || ceilings.host_pids < shared.host_pids
        || ceilings.disk_bytes < disk
    {
        return Err("node ceilings do not cover the shared infrastructure reserve".into());
    }
    Ok(())
}

/// Everything that determines a plan. There is no field for a path, flag or command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanInputs {
    pub node_id: Id128,
    pub instance_id: Id128,
    pub allocation_id: Id128,
    pub sandbox_id: String,
    pub profile: String,
    pub manifest_sha256: Digest,
    pub catalog_generation: u64,
    pub spec: SandboxSpec,
    pub leases: IdentityLeases,
    pub boot_nonce: String,
    pub work_uuid: String,
    pub executables: Vec<ExecutableIdentity>,
    pub pins: Value,
}

/// Exact plan bytes and the facts derived from them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExactPlan {
    pub bytes: Vec<u8>,
    pub digest: Digest,
    pub reservation: ResourceReservation,
    pub host_spec_sha256: Digest,
    pub guest_exec_spec_sha256: Digest,
    pub inputs: PlanInputs,
}

fn parse_digest(value: &str) -> Result<Digest, String> {
    Digest::parse(value)
}

/// Builds the complete plan. The launch object is B1's production `derive_launch`,
/// whose config, argv, paths and limits are expanded from the frozen contract.
pub fn build_plan(inputs: PlanInputs) -> Result<ExactPlan, String> {
    let binding = SpecBinding::new(&inputs.spec)?;
    let reservation = crate::firecracker::offline_768_v1_reservation(&inputs.spec)?;
    let mut inner = serde_json::to_value(&inputs.spec).map_err(|e| e.to_string())?;
    inner
        .as_object_mut()
        .ok_or("spec is not an object")?
        .remove("labels");
    let mut vector = serde_json::Map::new();
    for identity in &inputs.executables {
        vector.insert(identity.role.as_str().into(), identity.substitution());
    }
    let substitutions = json!({
        "instance_id": inputs.instance_id.to_string(),
        "allocation_id": inputs.allocation_id.to_string(),
        "sandbox_id": inputs.sandbox_id,
        "boot_nonce": inputs.boot_nonce,
        "uid": inputs.leases.vmm_uid.substitution(),
        "gid": inputs.leases.vmm_gid.substitution(),
        "relay_uid": inputs.leases.relay_uid.substitution(),
        "relay_gid": inputs.leases.relay_gid.substitution(),
        "cid": inputs.leases.cid.0,
        "work_uuid": inputs.work_uuid,
        "inner_spec": inner,
        "executables": Value::Object(vector),
    });
    let launch = derive_launch(&substitutions, &inputs.pins)?;
    // Two independent derivations of the charge must agree before a plan exists.
    if launch["reservation"] != serde_json::to_value(reservation).map_err(|e| e.to_string())? {
        return Err("contract and reservation formula disagree".into());
    }
    let mut document = binding.journal_value();
    let object = document.as_object_mut().ok_or("binding is not an object")?;
    object.insert("schema".into(), json!(PLAN_SCHEMA));
    object.insert("plan_version".into(), json!(PLAN_VERSION));
    object.insert("profile".into(), json!(inputs.profile));
    object.insert("node_id".into(), json!(inputs.node_id.to_string()));
    object.insert(
        "manifest_sha256".into(),
        json!(inputs.manifest_sha256.to_string()),
    );
    object.insert(
        "catalog_generation".into(),
        json!(inputs.catalog_generation),
    );
    object.insert("substitutions".into(), substitutions);
    object.insert("launch".into(), launch);
    let bytes = canonical(&document)?;
    if bytes.len() > crate::runtime::MAX_BACKEND_PLAN_BYTES {
        return Err("plan exceeds its strict size bound".into());
    }
    Ok(ExactPlan {
        digest: Digest::of(&bytes),
        reservation,
        host_spec_sha256: parse_digest(binding.host_spec_sha256())?,
        guest_exec_spec_sha256: parse_digest(binding.guest_exec_spec_sha256())?,
        bytes,
        inputs,
    })
}

fn lease(value: &Value, kind: &str) -> Result<u32, String> {
    if value["kind"] != kind {
        return Err("UID/GID lease types are not interchangeable".into());
    }
    value["value"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| "lease value".to_string())
}

fn text<'a>(value: &'a Value, what: &str) -> Result<&'a str, String> {
    value.as_str().ok_or_else(|| format!("plan {what}"))
}

/// Recovers typed fields from untrusted plan bytes and rebuilds the plan from them
/// under the expected identity. Passing means these exact bytes are what this helper's
/// own recipe produces for that token: no alternate field or fixture schema survives.
pub fn verify_plan_bytes(
    raw: &[u8],
    expected_digest: &Digest,
    node_id: Id128,
    instance_id: Id128,
    allocation_id: Id128,
    sandbox_id: &str,
) -> Result<ExactPlan, String> {
    if raw.is_empty() || raw.len() > crate::runtime::MAX_BACKEND_PLAN_BYTES {
        return Err("plan size is outside its bound".into());
    }
    if &Digest::of(raw) != expected_digest {
        return Err("plan digest mismatch".into());
    }
    let document = strict_json(raw)?;
    if document["schema"] != PLAN_SCHEMA || document["plan_version"] != json!(PLAN_VERSION) {
        return Err("plan is outside the production schema".into());
    }
    let spec: SandboxSpec =
        serde_json::from_value(document["host_spec"].clone()).map_err(|e| e.to_string())?;
    let subs = &document["substitutions"];
    let mut executables = Vec::new();
    for role in Role::ALL {
        let record = &subs["executables"][role.as_str()];
        let field = |name: &str| {
            record[name]
                .as_u64()
                .ok_or_else(|| format!("plan executable {name}"))
        };
        executables.push(ExecutableIdentity {
            role,
            st_dev: field("st_dev")?,
            st_ino: field("st_ino")?,
            bytes: field("bytes")?,
            sha256: parse_digest(text(&record["sha256"], "executable digest")?)?,
            installation_generation: field("installation_generation")?,
        });
    }
    let mut pins = serde_json::Map::new();
    for identity in &executables {
        pins.insert(
            identity.role.as_str().into(),
            json!({"bytes": identity.bytes, "sha256": identity.sha256.to_string()}),
        );
    }
    let inputs = PlanInputs {
        node_id,
        instance_id,
        allocation_id,
        sandbox_id: sandbox_id.to_string(),
        profile: text(&document["profile"], "profile")?.to_string(),
        manifest_sha256: parse_digest(text(&document["manifest_sha256"], "manifest digest")?)?,
        catalog_generation: document["catalog_generation"]
            .as_u64()
            .ok_or("plan catalog generation")?,
        spec,
        leases: IdentityLeases {
            vmm_uid: VmmUid(lease(&subs["uid"], VmmUid::KIND)?),
            vmm_gid: VmmGid(lease(&subs["gid"], VmmGid::KIND)?),
            relay_uid: RelayUid(lease(&subs["relay_uid"], RelayUid::KIND)?),
            relay_gid: RelayGid(lease(&subs["relay_gid"], RelayGid::KIND)?),
            cid: GuestCid(
                subs["cid"]
                    .as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or("plan CID")?,
            ),
        },
        boot_nonce: text(&subs["boot_nonce"], "boot nonce")?.to_string(),
        work_uuid: text(&subs["work_uuid"], "work UUID")?.to_string(),
        executables,
        pins: Value::Object(pins),
    };
    let rebuilt = build_plan(inputs)?;
    if rebuilt.bytes != raw {
        return Err("plan differs from this helper's own recomputation".into());
    }
    Ok(rebuilt)
}

/// The identity vector, in role order, of a plan's executables.
pub fn executable(plan: &ExactPlan, role: Role) -> Option<ExecutableIdentity> {
    plan.inputs
        .executables
        .iter()
        .find(|identity| identity.role == role)
        .copied()
}

#[cfg(test)]
#[allow(clippy::type_complexity)]
pub(super) mod tests {
    use super::*;
    use crate::model::Network;

    pub fn sample_spec() -> SandboxSpec {
        SandboxSpec {
            image: "alpine".into(),
            memory_bytes: 512 * MIB,
            cpu_millis: 1000,
            pids: 128,
            disk_bytes: 1 << 30,
            network: Network::None,
            read_only_root: false,
            writable_paths: vec![],
            labels: [("tenant".to_string(), "alpha".to_string())].into(),
        }
    }

    pub fn sample_leases(offset: u32) -> IdentityLeases {
        IdentityLeases {
            vmm_uid: VmmUid(300_000 + offset * 2),
            relay_uid: RelayUid(300_001 + offset * 2),
            vmm_gid: VmmGid(300_000 + offset * 2),
            relay_gid: RelayGid(300_001 + offset * 2),
            cid: GuestCid(3 + offset),
        }
    }

    pub fn sample_vector() -> Vec<ExecutableIdentity> {
        Role::ALL
            .iter()
            .enumerate()
            .map(|(index, role)| ExecutableIdentity {
                role: *role,
                st_dev: 7,
                st_ino: 100 + index as u64,
                bytes: 4096 + index as u64,
                sha256: Digest::of(role.as_str().as_bytes()),
                installation_generation: 1,
            })
            .collect()
    }

    pub fn sample_inputs() -> PlanInputs {
        let executables = sample_vector();
        let mut pins = serde_json::Map::new();
        for identity in &executables {
            pins.insert(
                identity.role.as_str().into(),
                json!({"bytes": identity.bytes, "sha256": identity.sha256.to_string()}),
            );
        }
        PlanInputs {
            node_id: Id128::from_bytes([1; 16]),
            instance_id: Id128::from_bytes([2; 16]),
            allocation_id: Id128::from_bytes([3; 16]),
            sandbox_id: "sb-0123456789abcdef".into(),
            profile: "offline-768-v1".into(),
            manifest_sha256: Digest::of(b"manifest"),
            catalog_generation: 1,
            spec: sample_spec(),
            leases: sample_leases(0),
            boot_nonce: "4d".repeat(32),
            work_uuid: "12345678-1234-4234-8234-123456789abc".into(),
            executables,
            pins: Value::Object(pins),
        }
    }

    fn verify(plan: &ExactPlan, raw: &[u8]) -> Result<ExactPlan, String> {
        verify_plan_bytes(
            raw,
            &Digest::of(raw),
            plan.inputs.node_id,
            plan.inputs.instance_id,
            plan.inputs.allocation_id,
            &plan.inputs.sandbox_id,
        )
    }

    #[test]
    fn plan_round_trips_and_derives_the_contract_reservation() {
        let plan = build_plan(sample_inputs()).unwrap();
        assert!(plan.bytes.len() <= crate::runtime::MAX_BACKEND_PLAN_BYTES);
        assert_eq!(plan.digest, Digest::of(&plan.bytes));
        assert_eq!(plan.reservation.memory_bytes, 896 * MIB);
        assert_eq!(plan.reservation.disk_bytes, 1408 * MIB);
        let again = verify(&plan, &plan.bytes).unwrap();
        assert_eq!(again.bytes, plan.bytes);
        assert_eq!(again.inputs.leases, plan.inputs.leases);
        assert_eq!(again.inputs.executables, plan.inputs.executables);
    }

    #[test]
    fn a_label_change_moves_host_and_plan_digests_but_not_the_guest_digest() {
        let base = build_plan(sample_inputs()).unwrap();
        let mut inputs = sample_inputs();
        inputs.spec.labels.insert("tenant".into(), "beta".into());
        let relabeled = build_plan(inputs).unwrap();
        assert_ne!(base.digest, relabeled.digest);
        assert_ne!(base.host_spec_sha256, relabeled.host_spec_sha256);
        assert_eq!(
            base.guest_exec_spec_sha256,
            relabeled.guest_exec_spec_sha256
        );
    }

    #[test]
    fn every_plan_mutation_is_refused_even_with_a_matching_digest() {
        let plan = build_plan(sample_inputs()).unwrap();
        let document = strict_json(&plan.bytes).unwrap();
        let attacks: Vec<(&str, Box<dyn Fn(&mut Value)>)> = vec![
            (
                "fixture schema",
                Box::new(|d| d["schema"] = json!("kiln-test-plan-v1")),
            ),
            ("plan version", Box::new(|d| d["plan_version"] = json!(2))),
            ("extra field", Box::new(|d| d["debug"] = json!(true))),
            (
                "node id",
                Box::new(|d| d["node_id"] = json!("00".repeat(16))),
            ),
            (
                "instance substitution",
                Box::new(|d| {
                    d["substitutions"]["instance_id"] = json!("00".repeat(16));
                }),
            ),
            (
                "allocation substitution",
                Box::new(|d| {
                    d["substitutions"]["allocation_id"] = json!("00".repeat(16));
                }),
            ),
            (
                "sandbox substitution",
                Box::new(|d| {
                    d["substitutions"]["sandbox_id"] = json!("sb-ffffffffffffffff");
                }),
            ),
            (
                "uid kind",
                Box::new(|d| {
                    d["substitutions"]["uid"]["kind"] = json!("VmmGid");
                }),
            ),
            (
                "relay equals vmm",
                Box::new(|d| {
                    d["substitutions"]["relay_uid"]["value"] =
                        d["substitutions"]["uid"]["value"].clone();
                }),
            ),
            (
                "launch cid",
                Box::new(|d| {
                    d["launch"]["firecracker"]["vsock"]["guest_cid"] = json!(99);
                }),
            ),
            (
                "launch argv",
                Box::new(|d| {
                    d["launch"]["jailer_argv"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!("--debug"));
                }),
            ),
            (
                "spec digest",
                Box::new(|d| d["host_spec_sha256"] = json!("00".repeat(32))),
            ),
            (
                "guest digest",
                Box::new(|d| d["guest_exec_spec_sha256"] = json!("00".repeat(32))),
            ),
            (
                "network spec",
                Box::new(|d| d["host_spec"]["network"] = json!("full")),
            ),
            (
                "executable inode",
                Box::new(|d| {
                    d["launch"]["executable_paths"]["jailer"] = json!("/tmp/jailer");
                }),
            ),
        ];
        for (name, attack) in attacks {
            let mut mutated = document.clone();
            attack(&mut mutated);
            let raw = canonical(&mutated).unwrap();
            assert!(verify(&plan, &raw).is_err(), "{name} was accepted");
        }
    }

    #[test]
    fn wrong_token_identity_or_noncanonical_bytes_cannot_verify() {
        let plan = build_plan(sample_inputs()).unwrap();
        for (node, instance, allocation, sandbox) in [
            (
                Id128::from_bytes([9; 16]),
                plan.inputs.instance_id,
                plan.inputs.allocation_id,
                "sb-0123456789abcdef",
            ),
            (
                plan.inputs.node_id,
                Id128::from_bytes([9; 16]),
                plan.inputs.allocation_id,
                "sb-0123456789abcdef",
            ),
            (
                plan.inputs.node_id,
                plan.inputs.instance_id,
                Id128::from_bytes([9; 16]),
                "sb-0123456789abcdef",
            ),
            (
                plan.inputs.node_id,
                plan.inputs.instance_id,
                plan.inputs.allocation_id,
                "sb-ffffffffffffffff",
            ),
        ] {
            assert!(
                verify_plan_bytes(
                    &plan.bytes,
                    &plan.digest,
                    node,
                    instance,
                    allocation,
                    sandbox
                )
                .is_err()
            );
        }
        // A digest over the wrong bytes.
        assert!(
            verify_plan_bytes(
                &plan.bytes,
                &Digest::of(b"other"),
                plan.inputs.node_id,
                plan.inputs.instance_id,
                plan.inputs.allocation_id,
                &plan.inputs.sandbox_id
            )
            .unwrap_err()
            .contains("digest")
        );
        // Whitespace is equivalent JSON but not the exact bytes.
        let mut spaced = plan.bytes.clone();
        spaced.push(b' ');
        assert!(verify(&plan, &spaced).is_err());
        assert!(verify(&plan, &[]).is_err());
        let oversized = vec![b' '; crate::runtime::MAX_BACKEND_PLAN_BYTES + 1];
        assert!(verify(&plan, &oversized).is_err());
    }

    #[test]
    fn fixture_plan_bytes_never_verify_as_a_production_plan() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/firecracker/plan.json"
        );
        let raw = std::fs::read(path).unwrap();
        let plan = build_plan(sample_inputs()).unwrap();
        assert!(
            verify(&plan, &raw)
                .unwrap_err()
                .contains("outside the production schema")
        );
    }

    #[test]
    fn policy_is_strict_and_cannot_widen_the_contract() {
        let good = json!({
            "schema": POLICY_SCHEMA,
            "node_id": "11".repeat(16),
            "ledger_dir": DEFAULT_LEDGER_DIR,
            "ceilings": NodeCeilings::default(),
            "uid_range": {"first": 300000, "last": 365535},
            "gid_range": {"first": 300000, "last": 365535},
            "cid_range": {"first": 3, "last": 65535},
            "profiles": [],
        });
        let parse = |value: &Value| parse_policy(&canonical(value).unwrap(), 999);
        let policy = parse(&good).unwrap();
        assert!(policy.profiles.is_empty());
        for (name, attack) in [
            ("schema", json!({"schema": "fixture"})),
            ("field", json!({"fixture_mode": true})),
        ] {
            let mut mutated = good.clone();
            mutated
                .as_object_mut()
                .unwrap()
                .extend(attack.as_object().unwrap().clone());
            assert!(parse(&mutated).is_err(), "{name}");
        }
        let mut wide = good.clone();
        wide["cid_range"]["first"] = json!(1);
        assert!(parse(&wide).is_err());
        let mut relative = good.clone();
        relative["ledger_dir"] = json!("node");
        assert!(parse(&relative).is_err());
        let mut small = good.clone();
        small["ceilings"]["memory_bytes"] = json!(1);
        assert!(parse(&small).is_err());
        let duplicated =
            format!("{{\"schema\":\"{POLICY_SCHEMA}\",\"schema\":\"{POLICY_SCHEMA}\"}}");
        assert!(parse_policy(duplicated.as_bytes(), 999).is_err());
    }

    #[test]
    fn default_ceilings_and_reserve_match_the_frozen_contract() {
        let contract = crate::firecracker::contract();
        let shared = SharedReserve::default();
        assert_eq!(
            contract["shared"]["memory_bytes"].as_u64(),
            Some(shared.memory_bytes)
        );
        assert_eq!(
            contract["shared"]["cpu_millis"].as_u64(),
            Some(shared.host_cpu_millis)
        );
        assert_eq!(contract["shared"]["pids"].as_u64(), Some(shared.pids));
        assert_eq!(
            contract["shared"]["disk_bytes"].as_u64(),
            Some(shared.disk_bytes)
        );
        assert_eq!(
            contract["shared"]["store_bytes"].as_u64(),
            Some(shared.store_bytes)
        );
        assert_eq!(
            contract["shared"]["fence_allowance_bytes"].as_u64(),
            Some(shared.fence_allowance_bytes)
        );
        assert!(validate_ceilings(&NodeCeilings::default(), &shared).is_ok());
    }
}
