//! B1's strict byte and spec contract. This module allocates no host resources.
//! There is deliberately no PreparedCreate constructor or fixture mode here.
//!
//! Canonical JSON is ASCII: sorted Unicode-scalar keys, compact separators,
//! Python ensure_ascii string escapes (lowercase hex and UTF-16 surrogate pairs),
//! integers in i64::MIN..=u64::MAX, no negative zero/floats/duplicates/BOM.
//! Root depth is zero, keys and values add one; maximum depth 32, input 4 MiB.
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::{self, Write};

pub const MAX_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_DEPTH: usize = 32;
pub type Result<T> = std::result::Result<T, String>;

struct Strict(usize);
impl<'de> DeserializeSeed<'de> for Strict {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> std::result::Result<Value, D::Error> {
        if self.0 > MAX_DEPTH {
            return Err(de::Error::custom("JSON depth"));
        }
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Strict {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("strict integer-only JSON")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    // No visit_f64: serde also sends -0 and out-of-range integers there.
    fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(Strict(self.0 + 1))? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
        let mut items = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if self.0 + 1 > MAX_DEPTH {
                return Err(de::Error::custom("JSON key depth"));
            }
            if items.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON key"));
            }
            items.insert(key, map.next_value_seed(Strict(self.0 + 1))?);
        }
        Ok(Value::Object(items))
    }
}

pub fn strict_json(raw: &[u8]) -> Result<Value> {
    if raw.len() > MAX_BYTES {
        return Err("JSON exceeds 4 MiB".into());
    }
    let mut d = serde_json::Deserializer::from_slice(raw);
    let value = Strict(0).deserialize(&mut d).map_err(|e| e.to_string())?;
    d.end().map_err(|e| e.to_string())?;
    Ok(value)
}

fn string(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ' '..='~' => out.push(c),
            _ => {
                for u in c.encode_utf16(&mut [0; 2]) {
                    write!(out, "\\u{u:04x}").unwrap();
                }
            }
        }
    }
    out.push('"');
}
fn encode(value: &Value, depth: usize, out: &mut String) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err("JSON depth".into());
    }
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
        Value::Number(v) => {
            if !v.is_i64() && !v.is_u64() {
                return Err("floats forbidden".into());
            }
            write!(out, "{v}").unwrap();
        }
        Value::String(v) => string(out, v),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i != 0 {
                    out.push(',');
                }
                encode(item, depth + 1, out)?;
            }
            out.push(']');
        }
        Value::Object(items) => {
            out.push('{');
            // Explicit ordering even if serde_json's preserve_order feature is enabled later.
            let mut keys: Vec<_> = items.keys().collect();
            keys.sort();
            for (i, key) in keys.iter().enumerate() {
                if depth + 1 > MAX_DEPTH {
                    return Err("JSON key depth".into());
                }
                if i != 0 {
                    out.push(',');
                }
                string(out, key);
                out.push(':');
                encode(&items[*key], depth + 1, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}
pub fn canonical(value: &Value) -> Result<Vec<u8>> {
    let mut out = String::new();
    encode(value, 0, &mut out)?;
    Ok(out.into_bytes())
}
pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn json_digest(value: &Value) -> Result<String> {
    Ok(sha256(&canonical(value)?))
}

/// Exact structural comparison of an actual serialized document with an independently
/// derived expected recipe. Reapproval of mutated bytes cannot bypass this check.
pub fn verify_exact(raw: &[u8], expected: &Value) -> Result<Value> {
    let actual = strict_json(raw)?;
    if canonical(&actual)? != canonical(expected)? {
        return Err("contract deviation".into());
    }
    Ok(actual)
}
pub fn contract() -> Value {
    strict_json(include_bytes!("contract.json")).expect("checked-in contract")
}
pub fn validate_contract(raw: &[u8]) -> Result<Value> {
    verify_exact(raw, &contract())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GuestExecSpec {
    image: String,
    memory_bytes: u64,
    cpu_millis: u32,
    pids: u32,
    disk_bytes: u64,
    network: String,
    read_only_root: bool,
    writable_paths: Vec<String>,
}
pub fn validate_guest_exec_spec(value: &Value) -> Result<()> {
    let s: GuestExecSpec = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    if s.image != "alpine"
        || s.network != "none"
        || s.memory_bytes == 0
        || s.memory_bytes > 512 * 1024 * 1024
        || s.cpu_millis == 0
        || s.cpu_millis > 1000
        || s.pids == 0
        || s.disk_bytes == 0
        || s.writable_paths.len() > 16
        || (!s.writable_paths.is_empty() && !s.read_only_root)
    {
        return Err("invalid offline execution spec".into());
    }
    let mut seen = BTreeSet::new();
    for path in &s.writable_paths {
        crate::validation::validate_writable_path(path)?;
        if !seen.insert(path) {
            return Err("duplicate writable path".into());
        }
    }
    Ok(())
}

/// Both spec digests under the canonical byte contract, without the offline profile
/// checks `SpecBinding` adds. Legacy kiln rows use this; a Firecracker plan never does.
pub fn spec_digests(spec: &crate::model::SandboxSpec) -> Result<(String, String)> {
    let host = serde_json::to_value(spec).map_err(|e| e.to_string())?;
    let mut guest = host.clone();
    guest.as_object_mut().unwrap().remove("labels");
    Ok((json_digest(&host)?, json_digest(&guest)?))
}

const MIB: u64 = 1024 * 1024;

/// Section 7.2's versioned `offline-768-v1` reservation, in checked arithmetic. The
/// outer charge is configured RAM plus overhead, never RSS/PSS.
pub fn offline_768_v1_reservation(
    spec: &crate::model::SandboxSpec,
) -> Result<crate::model::ResourceReservation> {
    let overflow = || "reservation arithmetic overflow".to_string();
    let rounded = spec
        .disk_bytes
        .checked_add(256 * MIB)
        .and_then(|bytes| bytes.checked_next_multiple_of(64 * MIB))
        .ok_or_else(overflow)?;
    Ok(crate::model::ResourceReservation {
        memory_bytes: (768 + 128) * MIB,
        disk_bytes: rounded
            .max(512 * MIB)
            .checked_add(128 * MIB)
            .ok_or_else(overflow)?,
        pids: u64::from(spec.pids)
            .checked_add(32 + 32)
            .ok_or_else(overflow)?,
        host_cpu_millis: 1000,
        virtual_cpu_slots: 1,
        host_pids: 32,
    })
}

/// Immutable daemon plan/journal payload. The guest receives only the projection
/// and guest_exec_spec_sha256. Deserialize is intentionally unavailable: recovery
/// must recompute and compare via verify_spec_binding before accepting a journal.
#[derive(Clone, Debug, Serialize)]
pub struct SpecBinding {
    host_spec: crate::model::SandboxSpec,
    host_spec_sha256: String,
    guest_exec_spec_sha256: String,
}
impl SpecBinding {
    pub fn new(spec: &crate::model::SandboxSpec) -> Result<Self> {
        let mut guest = serde_json::to_value(spec).map_err(|e| e.to_string())?;
        guest.as_object_mut().unwrap().remove("labels");
        validate_guest_exec_spec(&guest)?;
        if spec.labels.len() > 32 {
            return Err("too many labels".into());
        }
        for (key, value) in &spec.labels {
            if key.is_empty()
                || key.len() > 63
                || !key
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_./".contains(&c))
                || value.len() > 256
                || value.chars().any(char::is_control)
            {
                return Err("invalid label".into());
            }
        }
        let (host_spec_sha256, guest_exec_spec_sha256) = spec_digests(spec)?;
        Ok(Self {
            host_spec: spec.clone(),
            host_spec_sha256,
            guest_exec_spec_sha256,
        })
    }
    pub fn host_spec_sha256(&self) -> &str {
        &self.host_spec_sha256
    }
    pub fn guest_exec_spec_sha256(&self) -> &str {
        &self.guest_exec_spec_sha256
    }
    pub fn journal_value(&self) -> Value {
        serde_json::to_value(self).expect("spec binding")
    }
}
pub fn bind_host_spec(value: &Value) -> Result<SpecBinding> {
    let spec: crate::model::SandboxSpec =
        serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    // Serde enums also accept {"none":null} for a unit variant. The wire contract
    // permits only "none"; never silently normalize an alternate input shape.
    let typed = serde_json::to_value(&spec).map_err(|e| e.to_string())?;
    if canonical(value)? != canonical(&typed)? {
        return Err("host spec is not the exact effective model shape".into());
    }
    SpecBinding::new(&spec)
}

pub fn verify_spec_binding(raw: &[u8]) -> Result<SpecBinding> {
    let value = strict_json(raw)?;
    let binding = bind_host_spec(&value["host_spec"])?;
    verify_exact(raw, &binding.journal_value())?;
    Ok(binding)
}

/// Production schemas never accept fixtures, even with independent approval.
/// B1 has no approved broker/jailer, so even schema 2 remains unavailable.
pub fn validate_manifest(raw: &[u8], approved_sha256: &str) -> Result<Value> {
    if sha256(raw) != approved_sha256 {
        return Err("independent manifest approval mismatch".into());
    }
    let m = strict_json(raw)?;
    if m["schema"] != json!(2) || m["fixture_only"] != json!(false) {
        return Err("fixture/legacy manifest refused".into());
    }
    Err("production disabled: broker/patched-jailer/bundle approval absent".into())
}

fn fields(value: &Value, names: &[&str]) -> Result<()> {
    let map = value.as_object().ok_or("object required")?;
    if map.len() != names.len() || names.iter().any(|key| !map.contains_key(*key)) {
        return Err("missing/unknown fields".into());
    }
    Ok(())
}
fn uint(value: &Value, low: u64, high: u64) -> Result<u64> {
    value
        .as_u64()
        .filter(|n| *n >= low && *n <= high)
        .ok_or("integer type/range".into())
}
fn hex(value: &Value, length: usize) -> Result<&str> {
    value
        .as_str()
        .filter(|s| {
            s.len() == length
                && s.bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        })
        .ok_or("invalid hex identity".into())
}
fn lease(value: &Value, kind: &str) -> Result<u64> {
    fields(value, &["kind", "value"])?;
    if value["kind"] != kind {
        return Err("UID/GID roles not interchangeable".into());
    }
    uint(&value["value"], 300000, 365535)
}
/// Pure recipe derivation. Executable pins must originate from an independently
/// validated catalog. Returning config/argv grants no launch or PreparedCreate.
pub fn derive_launch(subs: &Value, pins: &Value) -> Result<Value> {
    let policy = contract();
    let names: Vec<_> = policy["substitutions"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields(subs, &names)?;
    let instance = hex(&subs["instance_id"], 32)?;
    let allocation = hex(&subs["allocation_id"], 32)?;
    hex(&subs["boot_nonce"], 64)?;
    if !subs["sandbox_id"]
        .as_str()
        .is_some_and(|s| crate::model::valid_id("sb", s))
    {
        return Err("sandbox ID".into());
    }
    let uid = lease(&subs["uid"], "VmmUid")?;
    let gid = lease(&subs["gid"], "VmmGid")?;
    let relay_uid = lease(&subs["relay_uid"], "RelayUid")?;
    let relay_gid = lease(&subs["relay_gid"], "RelayGid")?;
    if uid == relay_uid || gid == relay_gid {
        return Err("relay lease overlaps VMM".into());
    }
    uint(&subs["cid"], 3, 65535)?;
    let uuid = subs["work_uuid"].as_str().ok_or("UUID")?;
    if uuid.len() != 36
        || uuid.bytes().enumerate().any(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c != b'-'
            } else {
                !c.is_ascii_digit() && !(b'a'..=b'f').contains(&c)
            }
        })
        || uuid.as_bytes()[14] != b'4'
        || !b"89ab".contains(&uuid.as_bytes()[19])
    {
        return Err("canonical UUIDv4 required".into());
    }
    validate_guest_exec_spec(&subs["inner_spec"])?;
    let roles = ["jailer", "firecracker", "mkfs.xfs", "kilnd-helper"];
    fields(&subs["executables"], &roles)?;
    fields(pins, &roles)?;
    let mut inodes = BTreeSet::new();
    let mut paths = Map::new();
    for role in roles {
        let v = &subs["executables"][role];
        let pin = &pins[role];
        fields(
            v,
            &[
                "role",
                "st_dev",
                "st_ino",
                "bytes",
                "sha256",
                "installation_generation",
            ],
        )?;
        if v["role"] != role || v["bytes"] != pin["bytes"] || v["sha256"] != pin["sha256"] {
            return Err("executable identity differs from pin".into());
        }
        uint(&v["bytes"], 1, 1024 * 1024 * 1024)?;
        let digest = hex(&v["sha256"], 64)?;
        let dev = uint(&v["st_dev"], 1, u64::MAX)?;
        let ino = uint(&v["st_ino"], 1, u64::MAX)?;
        uint(&v["installation_generation"], 1, u64::MAX)?;
        if !inodes.insert((dev, ino)) {
            return Err("executable roles alias inode".into());
        }
        paths.insert(
            role.into(),
            json!(format!("/opt/kilnd/exec/sha256/{digest}/{role}")),
        );
    }
    let spec = &subs["inner_spec"];
    let round = 64 * 1024 * 1024;
    let work = spec["disk_bytes"]
        .as_u64()
        .unwrap()
        .checked_add(256 * 1024 * 1024)
        .and_then(|v| v.checked_add(round - 1))
        .map(|v| (v / round) * round)
        .ok_or("reservation exceeds u64")?
        .max(512 * 1024 * 1024);
    let disk = work
        .checked_add(128 * 1024 * 1024)
        .ok_or("reservation exceeds u64")?;
    let backend = format!("fc-{allocation}");
    let cgroup = format!("kilnd-firecracker/{instance}/{backend}");
    let jail = format!("/var/lib/kilnd-helper/jails/firecracker/{backend}/root");
    let backing = format!("/var/lib/kilnd-helper/work/{instance}/{backend}/work.xfs");
    let vsock = format!("{jail}/run/vsock.sock");
    if vsock.len() >= 108 {
        return Err("vsock path exceeds sockaddr_un".into());
    }
    let mut typed = Value::Object(paths.clone());
    for (key, val) in [
        ("backend_id", json!(backend)),
        ("vmm_cgroup", json!(format!("{cgroup}/vm/vmm"))),
        ("cid", subs["cid"].clone()),
        ("uid", json!(uid)),
        ("gid", json!(gid)),
        ("relay_uid", json!(relay_uid)),
        ("relay_gid", json!(relay_gid)),
        ("work_uuid", json!(uuid)),
        ("work_backing_path", json!(backing)),
        ("work_bytes", json!(work)),
    ] {
        typed[key] = val;
    }
    let mut recipe = Map::new();
    for key in [
        "jail",
        "work",
        "cgroups",
        "workers",
        "shared",
        "vmm_credentials",
        "relay_credentials",
        "process",
        "identity",
        "handoff",
        "timing_exception",
    ] {
        recipe.insert(key.into(), expand(&policy[key], &typed)?);
    }
    let semantic: Vec<_> = policy["vmm_argv"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .filter(|(i, _)| ![3, 4, 5, 6, 7, 8].contains(i))
        .map(|(_, v)| v.clone())
        .collect();
    let jailer = expand(&policy["jailer_argv"], &typed)?
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            json!(
                v.as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| v.to_string())
            )
        })
        .collect::<Vec<_>>();
    Ok(
        json!({"firecracker":expand(&policy["firecracker"],&typed)?, "jailer_argv":jailer,
        "vmm_argv_semantic":expand(&json!(semantic),&typed)?, "formatter_argv":recipe["work"]["formatter_argv"],
        "executable_paths":paths, "jail_root":jail, "vsock_host_path":vsock, "cgroup":cgroup,
        "work_backing_path":backing, "work_bytes":work,
        "reservation":{"memory_bytes":896 * 1024 * 1024u64, "disk_bytes":disk,
            "pids":spec["pids"].as_u64().unwrap()+64, "host_pids":32, "host_cpu_millis":1000,"virtual_cpu_slots":1},
        "resource_recipe":recipe}),
    )
}
fn expand(value: &Value, values: &Value) -> Result<Value> {
    match value {
        Value::Array(a) => a
            .iter()
            .map(|v| expand(v, values))
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        Value::Object(o) => o
            .iter()
            .map(|(k, v)| Ok((k.clone(), expand(v, values)?)))
            .collect::<Result<Map<_, _>>>()
            .map(Value::Object),
        Value::String(s) => {
            let mut out = String::new();
            let mut rest = s.as_str();
            while let Some(i) = rest.find('$') {
                out.push_str(&rest[..i]);
                rest = &rest[i + 1..];
                let n = rest
                    .bytes()
                    .take_while(|c| c.is_ascii_lowercase() || b"_.".contains(c))
                    .count();
                if n == 0 {
                    out.push('$');
                    continue;
                }
                let slot = values.get(&rest[..n]).ok_or("unknown substitution")?;
                if out.is_empty() && n == rest.len() {
                    return Ok(slot.clone());
                }
                out.push_str(
                    &slot
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| slot.to_string()),
                );
                rest = &rest[n..];
            }
            out.push_str(rest);
            Ok(json!(out))
        }
        _ => Ok(value.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Network, SandboxSpec};

    const MIB: u64 = 1024 * 1024;

    fn spec(disk_bytes: u64, pids: u32) -> SandboxSpec {
        SandboxSpec {
            image: "alpine".into(),
            memory_bytes: 512 * MIB,
            cpu_millis: 1000,
            pids,
            disk_bytes,
            network: Network::None,
            read_only_root: false,
            writable_paths: vec![],
            labels: Default::default(),
        }
    }

    #[test]
    fn offline_768_reservation_arithmetic_is_checked() {
        let r = offline_768_v1_reservation(&spec(1 << 30, 128)).unwrap();
        // Section 7.1's worked example: W = 1280 MiB, host disk = 1408 MiB.
        assert_eq!(r.disk_bytes, 1408 * MIB);
        assert_eq!(r.memory_bytes, 896 * MIB);
        assert_eq!(r.pids, 192);
        assert_eq!(r.host_pids, 32);
        assert_eq!(r.host_cpu_millis, 1000);
        assert_eq!(r.virtual_cpu_slots, 1);

        // W = max(512 MiB, round_up(D + 256 MiB, 64 MiB)), reserved = W + 128 MiB.
        for (disk, expected_w) in [
            (1, 512),             // floor
            (256 * MIB, 512),     // exactly the floor
            (256 * MIB + 1, 576), // one byte rounds a whole quantum
            (320 * MIB, 576),     // exact multiple does not round further
            (320 * MIB + 1, 640),
            (1024 * MIB, 1280),
            (1024 * MIB + 1, 1344),
        ] {
            let reserved = offline_768_v1_reservation(&spec(disk, 1))
                .unwrap()
                .disk_bytes;
            assert_eq!(reserved, (expected_w + 128) * MIB, "disk {disk}");
            assert_eq!(reserved % (64 * MIB), 0, "disk {disk}");
        }

        // Overflow fails at every addition rather than wrapping to a small charge.
        for disk in [
            u64::MAX,
            u64::MAX - 256 * MIB + 1,
            // D + 256 MiB fits, its round-up does not.
            u64::MAX - 256 * MIB,
            // W fits, W + 128 MiB does not.
            (u64::MAX / (64 * MIB)) * (64 * MIB) - 256 * MIB,
        ] {
            assert!(
                offline_768_v1_reservation(&spec(disk, 1)).is_err(),
                "disk {disk}"
            );
        }
        // The largest PID count cannot overflow the aggregate.
        assert_eq!(
            offline_768_v1_reservation(&spec(1, u32::MAX)).unwrap().pids,
            u64::from(u32::MAX) + 64
        );
    }

    #[test]
    fn three_sessions_fit_and_a_fourth_does_not_in_the_3_gib_budget() {
        let session = offline_768_v1_reservation(&spec(1 << 30, 128))
            .unwrap()
            .memory_bytes;
        let (shared, budget) = (128 * MIB, 3072 * MIB);
        let total = |sessions: u64| {
            session
                .checked_mul(sessions)
                .and_then(|memory| memory.checked_add(shared))
                .unwrap()
        };
        assert_eq!(total(3), 2816 * MIB);
        assert!(total(3) <= budget, "3*896+128 fits");
        assert_eq!(total(4), 3712 * MIB);
        assert!(total(4) > budget, "4*896+128 does not");
    }

    #[test]
    fn spec_digests_match_spec_binding_without_its_offline_profile() {
        let offline = spec(1 << 30, 128);
        let binding = SpecBinding::new(&offline).unwrap();
        assert_eq!(
            spec_digests(&offline).unwrap(),
            (
                binding.host_spec_sha256().to_string(),
                binding.guest_exec_spec_sha256().to_string()
            )
        );
        let mut full = offline.clone();
        full.network = Network::Full;
        full.image = "ubuntu".into();
        assert!(SpecBinding::new(&full).is_err());
        assert!(spec_digests(&full).is_ok());
    }
}
