//! Section 3.2's strict manifest and artifact verification. The bytes are hashed and
//! compared with an independently configured approval before anything else trusts
//! them. Fixture schemas are refused unconditionally, and the production gate keeps
//! every manifest refused until the reviewed B4/B5/B7 artifacts exist.
use super::executable::{ExecutablePin, ProtectedDir, Role, hash_descriptor};
use crate::firecracker::{canonical, contract, strict_json};
use crate::model::Digest;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

pub const MANIFEST_NAME: &str = "manifest.json";
/// The approved root-owned schema number. `fixture_only` must also be false.
pub const MANIFEST_SCHEMA: u64 = 2;
const ARTIFACTS: [&str; 5] = [
    "Image",
    "kernel.config",
    "kiln",
    "kilnd-guest-broker",
    "rootfs.squashfs",
];
const FIELDS: [&str; 16] = [
    "architecture",
    "artifacts",
    "broker",
    "bundle_version",
    "executables",
    "firecracker_version",
    "fixture_only",
    "inner_images",
    "inputs",
    "kernel_policy",
    "kernel_version",
    "kiln_commit",
    "launch_contract",
    "schema",
    "source_date_epoch",
    "work_disk",
];

/// Whether an otherwise valid production manifest may be used at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestGate {
    /// `firecracker::validate_manifest`'s disabled gate. It stays until B7.
    ProductionDisabled,
    /// Internal test injection. No constructor exists outside `cfg(test)`, there is
    /// no CLI or policy spelling, and fixture schemas remain refused regardless.
    #[cfg(test)]
    TestApproved,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactPin {
    pub bytes: u64,
    pub sha256: Digest,
}

/// A manifest that passed every check, including its gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedManifest {
    pub sha256: Digest,
    pub artifacts: BTreeMap<String, ArtifactPin>,
    pub executables: BTreeMap<Role, (u64, Digest)>,
    /// `derive_launch`'s pin object: role to bytes and digest.
    pub pins: Value,
}

fn digest_field(value: &Value, what: &str) -> Result<Digest, String> {
    value
        .as_str()
        .ok_or_else(|| format!("{what} is not a digest"))
        .and_then(|text| Digest::parse(text).map_err(|e| format!("{what}: {e}")))
}

fn byte_count(value: &Value, what: &str) -> Result<u64, String> {
    value
        .as_u64()
        .filter(|n| (1..=1 << 30).contains(n))
        .ok_or_else(|| format!("{what} size is outside the catalog limit"))
}

fn exact_fields(value: &Value, names: &[&str], what: &str) -> Result<(), String> {
    let map = value
        .as_object()
        .ok_or_else(|| format!("{what} is not an object"))?;
    let actual: BTreeSet<_> = map.keys().map(String::as_str).collect();
    if actual != names.iter().copied().collect() {
        return Err(format!("{what} has missing or unknown fields"));
    }
    Ok(())
}

/// Complete schema and launch-contract verification of exact bytes.
pub fn verify_manifest(
    raw: &[u8],
    approved: &Digest,
    gate: ManifestGate,
) -> Result<VerifiedManifest, String> {
    if raw.len() > crate::firecracker::MAX_BYTES {
        return Err("manifest exceeds 4 MiB".into());
    }
    let sha256 = Digest::of(raw);
    if &sha256 != approved {
        return Err("independent manifest approval mismatch".into());
    }
    let manifest = strict_json(raw)?;
    // Fixture schemas stay outside production whatever the gate or the approval says.
    if manifest["schema"].as_u64() != Some(MANIFEST_SCHEMA)
        || manifest["fixture_only"] != Value::Bool(false)
    {
        return Err("fixture/legacy manifest refused".into());
    }
    exact_fields(&manifest, &FIELDS, "manifest")?;
    let frozen = contract();
    if canonical(&manifest["launch_contract"])? != canonical(&frozen)? {
        return Err("launch contract deviation".into());
    }
    if manifest["architecture"] != frozen["architecture"] {
        return Err("manifest architecture differs from the contract".into());
    }
    if manifest["firecracker_version"] != frozen["firecracker_lineage"] {
        return Err("manifest Firecracker lineage differs from the contract".into());
    }
    let broker = &manifest["broker"];
    if broker["enabled"] != Value::Bool(true)
        || broker["protocol"].as_u64() != Some(1)
        || broker["artifact"].as_str() != Some("kilnd-guest-broker")
    {
        return Err("broker is not the enabled protocol 1 artifact".into());
    }
    if manifest["inner_images"].get("alpine").is_none()
        || manifest["inner_images"]
            .as_object()
            .is_none_or(|images| images.len() != 1)
    {
        return Err("inner image catalog is not exactly the approved image".into());
    }
    if manifest["kernel_policy"]["config_artifact"].as_str() != Some("kernel.config") {
        return Err("kernel policy does not bind its config artifact".into());
    }
    let mut artifacts = BTreeMap::new();
    exact_fields(&manifest["artifacts"], &ARTIFACTS, "artifacts")?;
    for name in ARTIFACTS {
        let record = &manifest["artifacts"][name];
        exact_fields(record, &["bytes", "sha256"], name)?;
        artifacts.insert(
            name.to_string(),
            ArtifactPin {
                bytes: byte_count(&record["bytes"], name)?,
                sha256: digest_field(&record["sha256"], name)?,
            },
        );
    }
    let role_names: Vec<_> = Role::ALL.iter().map(|role| role.as_str()).collect();
    exact_fields(&manifest["executables"], &role_names, "executables")?;
    let mut executables = BTreeMap::new();
    let mut images = BTreeSet::new();
    let mut pins = serde_json::Map::new();
    for role in Role::ALL {
        let record = &manifest["executables"][role.as_str()];
        exact_fields(
            record,
            &["bytes", "dependencies", "format", "sha256"],
            role.as_str(),
        )?;
        // An unbound dynamic closure is refused: no loader or library approvals exist.
        if record["format"].as_str() != Some("static-elf")
            || record["dependencies"]
                .as_array()
                .is_none_or(|d| !d.is_empty())
        {
            return Err(format!("{}: dynamic closure unsupported", role.as_str()));
        }
        let bytes = byte_count(&record["bytes"], role.as_str())?;
        let digest = digest_field(&record["sha256"], role.as_str())?;
        if !images.insert(digest) {
            return Err("executable roles alias one image".into());
        }
        executables.insert(role, (bytes, digest));
        pins.insert(
            role.as_str().into(),
            serde_json::json!({"bytes": bytes, "sha256": digest.to_string()}),
        );
    }
    match gate {
        // The same function B1 and its conformance corpus exercise. It refuses every
        // manifest today; removing that is a B7 change, not a configuration.
        ManifestGate::ProductionDisabled => {
            crate::firecracker::validate_manifest(raw, &approved.to_string())?;
        }
        #[cfg(test)]
        ManifestGate::TestApproved => {}
    }
    Ok(VerifiedManifest {
        sha256,
        artifacts,
        executables,
        pins: Value::Object(pins),
    })
}

/// The catalog's executable pins, with its node-local installation generations.
pub fn executable_pins(
    manifest: &VerifiedManifest,
    generations: &BTreeMap<Role, u64>,
) -> Result<Vec<ExecutablePin>, String> {
    Role::ALL
        .iter()
        .map(|role| {
            let (bytes, sha256) = manifest.executables[role];
            let installation_generation = *generations
                .get(role)
                .filter(|generation| **generation >= 1)
                .ok_or_else(|| format!("no installation generation for {}", role.as_str()))?;
            Ok(ExecutablePin {
                role: *role,
                bytes,
                sha256,
                installation_generation,
            })
        })
        .collect()
}

/// Reads the manifest through a pinned directory, bounded before reading.
pub fn read_manifest(bundle: &ProtectedDir, owner_uid: u32) -> Result<Vec<u8>, String> {
    read_bounded(
        bundle,
        MANIFEST_NAME,
        owner_uid,
        crate::firecracker::MAX_BYTES as u64,
    )
}

/// Reads one protected regular file, bounded before anything is allocated.
pub fn read_bounded(
    directory: &ProtectedDir,
    name: &str,
    owner_uid: u32,
    max: u64,
) -> Result<Vec<u8>, String> {
    let (file, meta) = open_regular(directory, name, owner_uid)?;
    if meta.len() > max {
        return Err(format!("{name} exceeds its size bound"));
    }
    let mut raw = Vec::with_capacity(meta.len() as usize);
    std::io::Read::read_to_end(&mut std::io::Read::take(&file, max + 1), &mut raw)
        .map_err(|e| format!("read {name}: {e}"))?;
    if raw.len() as u64 != meta.len() {
        return Err(format!("{name} changed while reading"));
    }
    Ok(raw)
}

fn open_regular(
    bundle: &ProtectedDir,
    name: &str,
    owner_uid: u32,
) -> Result<(File, std::fs::Metadata), String> {
    let name_c = std::ffi::CString::new(name).map_err(|_| "artifact name contains NUL")?;
    // SAFETY: the pinned directory and name are live. O_NONBLOCK neuters a FIFO.
    let fd = unsafe {
        libc::openat(
            bundle.file().as_raw_fd(),
            name_c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!("{name}: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: openat returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = file.metadata().map_err(|e| format!("{name}: {e}"))?;
    if !meta.is_file() || meta.nlink() != 1 || meta.uid() != owner_uid {
        return Err(format!(
            "{name} is not a single-link root-owned regular file"
        ));
    }
    if meta.permissions().mode() & 0o022 != 0 {
        return Err(format!("{name} is writable by a non-owner"));
    }
    Ok((file, meta))
}

/// Every declared artifact matches through its own descriptor, and the directory
/// holds nothing undeclared. Authenticating only what a VM attaches is insufficient.
pub fn verify_artifacts(
    bundle: &ProtectedDir,
    owner_uid: u32,
    manifest: &VerifiedManifest,
) -> Result<(), String> {
    let mut expected: BTreeSet<&str> = manifest.artifacts.keys().map(String::as_str).collect();
    expected.insert(MANIFEST_NAME);
    for entry in list_directory(bundle)? {
        let name = entry.as_str();
        if !expected.remove(name) {
            return Err(format!("undeclared bundle entry {name}"));
        }
    }
    if let Some(missing) = expected.iter().next() {
        return Err(format!("missing bundle artifact {missing}"));
    }
    for (name, pin) in &manifest.artifacts {
        let (file, meta) = open_regular(bundle, name, owner_uid)?;
        if meta.len() != pin.bytes {
            return Err(format!("{name} size differs from the manifest"));
        }
        if hash_descriptor(&file, meta.len()).map_err(|e| e.to_string())? != pin.sha256 {
            return Err(format!("{name} digest differs from the manifest"));
        }
    }
    Ok(())
}

/// A bounded listing of the pinned directory itself, not a pathname lookup.
fn list_directory(bundle: &ProtectedDir) -> Result<Vec<String>, String> {
    // SAFETY: fdopendir takes ownership of a fresh duplicate; rewinddir resets the
    // shared offset so every listing begins at the start.
    let duplicate = unsafe { libc::fcntl(bundle.file().as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(format!("{}", std::io::Error::last_os_error()));
    }
    let directory = unsafe { libc::fdopendir(duplicate) };
    if directory.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(duplicate) };
        return Err(format!("{error}"));
    }
    unsafe { libc::rewinddir(directory) };
    let mut names = Vec::new();
    loop {
        // SAFETY: directory is live; the entry is copied before the next call.
        let entry = unsafe { libc::readdir(directory) };
        if entry.is_null() {
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        if names.len() >= 64 {
            unsafe { libc::closedir(directory) };
            return Err("bundle directory has too many entries".into());
        }
        names.push(
            std::ffi::OsStr::from_bytes(bytes)
                .to_string_lossy()
                .into_owned(),
        );
    }
    unsafe { libc::closedir(directory) };
    Ok(names)
}

#[cfg(test)]
#[allow(clippy::type_complexity)]
mod tests {
    use super::*;
    use serde_json::json;

    fn production_shaped() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/firecracker/bundle/manifest.json"
        );
        let mut manifest = strict_json(&std::fs::read(path).unwrap()).unwrap();
        manifest["schema"] = json!(2);
        manifest["fixture_only"] = json!(false);
        manifest
    }

    fn verified(value: &Value, gate: ManifestGate) -> Result<VerifiedManifest, String> {
        let raw = canonical(value).unwrap();
        verify_manifest(&raw, &Digest::of(&raw), gate)
    }

    #[test]
    fn production_gate_refuses_even_a_complete_approved_manifest() {
        let manifest = production_shaped();
        assert!(verified(&manifest, ManifestGate::TestApproved).is_ok());
        let error = verified(&manifest, ManifestGate::ProductionDisabled).unwrap_err();
        assert!(error.contains("production disabled"), "{error}");
    }

    #[test]
    fn fixture_schemas_are_refused_under_every_gate_and_approval() {
        let fixture = strict_json(
            &std::fs::read(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/firecracker/bundle/manifest.json"
            ))
            .unwrap(),
        )
        .unwrap();
        for gate in [ManifestGate::ProductionDisabled, ManifestGate::TestApproved] {
            for (schema, flag) in [
                (json!("kiln-test-manifest-v1"), json!(true)),
                (json!("kiln-test-manifest-v1"), json!(false)),
                (json!(2), json!(true)),
                (json!(1), json!(false)),
                (json!("2"), json!(false)),
            ] {
                let mut mutated = fixture.clone();
                mutated["schema"] = schema;
                mutated["fixture_only"] = flag;
                assert_eq!(
                    verified(&mutated, gate).unwrap_err(),
                    "fixture/legacy manifest refused"
                );
            }
        }
    }

    #[test]
    fn approval_compares_exact_bytes_not_a_canonical_form() {
        let manifest = production_shaped();
        let raw = canonical(&manifest).unwrap();
        let approved = Digest::of(&raw);
        assert!(verify_manifest(&raw, &approved, ManifestGate::TestApproved).is_ok());
        let mut spaced = raw.clone();
        spaced.push(b' ');
        assert!(
            verify_manifest(&spaced, &approved, ManifestGate::TestApproved)
                .unwrap_err()
                .contains("approval mismatch")
        );
    }

    #[test]
    fn every_security_field_mutation_is_refused_under_reapproval() {
        let base = production_shaped();
        let attacks: Vec<(&str, Box<dyn Fn(&mut Value)>)> = vec![
            ("unknown field", Box::new(|m| m["debug"] = json!(true))),
            (
                "dropped field",
                Box::new(|m| {
                    m.as_object_mut().unwrap().remove("kernel_policy");
                }),
            ),
            (
                "architecture",
                Box::new(|m| m["architecture"] = json!("x86_64")),
            ),
            (
                "lineage",
                Box::new(|m| m["firecracker_version"] = json!("1.18.0")),
            ),
            (
                "contract vcpu",
                Box::new(|m| {
                    m["launch_contract"]["firecracker"]["machine-config"]["vcpu_count"] = json!(2);
                }),
            ),
            (
                "contract network",
                Box::new(|m| {
                    m["launch_contract"]["firecracker"]["network-interfaces"] = json!([]);
                }),
            ),
            (
                "contract boot args",
                Box::new(|m| {
                    m["launch_contract"]["firecracker"]["boot-source"]["boot_args"] =
                        json!("nokaslr");
                }),
            ),
            (
                "broker disabled",
                Box::new(|m| m["broker"]["enabled"] = json!(false)),
            ),
            (
                "broker protocol",
                Box::new(|m| m["broker"]["protocol"] = json!(2)),
            ),
            (
                "extra artifact",
                Box::new(|m| {
                    m["artifacts"]["extra"] = m["artifacts"]["kiln"].clone();
                }),
            ),
            (
                "missing artifact",
                Box::new(|m| {
                    m["artifacts"].as_object_mut().unwrap().remove("kiln");
                }),
            ),
            (
                "artifact bytes",
                Box::new(|m| m["artifacts"]["kiln"]["bytes"] = json!(0)),
            ),
            (
                "artifact digest",
                Box::new(|m| m["artifacts"]["kiln"]["sha256"] = json!("ABC")),
            ),
            (
                "dynamic executable",
                Box::new(|m| {
                    m["executables"]["mkfs.xfs"]["format"] = json!("dynamic-elf");
                }),
            ),
            (
                "unbound dependency",
                Box::new(|m| {
                    m["executables"]["mkfs.xfs"]["dependencies"] = json!(["libc.so.6"]);
                }),
            ),
            (
                "worker role",
                Box::new(|m| {
                    m["executables"]["kilnd-vm-supervisor"] = m["executables"]["jailer"].clone();
                }),
            ),
            (
                "aliased images",
                Box::new(|m| {
                    m["executables"]["jailer"]["sha256"] =
                        m["executables"]["firecracker"]["sha256"].clone();
                }),
            ),
            (
                "inner image",
                Box::new(|m| m["inner_images"]["ubuntu"] = json!({})),
            ),
        ];
        for (name, attack) in attacks {
            let mut mutated = base.clone();
            attack(&mut mutated);
            assert!(
                verified(&mutated, ManifestGate::TestApproved).is_err(),
                "{name} was accepted"
            );
        }
    }

    #[test]
    fn duplicate_keys_and_oversize_are_refused_before_schema_checks() {
        let raw = br#"{"schema":2,"schema":2}"#;
        assert!(
            verify_manifest(raw, &Digest::of(raw), ManifestGate::TestApproved)
                .unwrap_err()
                .contains("duplicate")
        );
        let big = vec![b' '; crate::firecracker::MAX_BYTES + 1];
        assert!(
            verify_manifest(&big, &Digest::of(&big), ManifestGate::TestApproved)
                .unwrap_err()
                .contains("4 MiB")
        );
    }
}
