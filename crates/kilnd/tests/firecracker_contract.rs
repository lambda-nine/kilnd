//! Phase 1b B1: the frozen `offline-768-v1` contract, checked independently of
//! the kiln-guest Python that generated these fixtures. B3's helper implements
//! the real preflight; nothing here enables the Firecracker backend.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Bumped deliberately whenever kiln-guest's fixtures are copied here.
const DIGESTS_JSON_SHA256: &str =
    "cb246d1e2c5cd21555fd680b82f6f9e224828861598bbe6ff163bc8e3a7b26ce";
const MIB: u64 = 1024 * 1024;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/firecracker")
}

fn bytes(name: &str) -> Vec<u8> {
    fs::read(fixtures().join(name)).unwrap_or_else(|error| panic!("{name}: {error}"))
}

fn load(name: &str) -> Value {
    kilnd::firecracker::strict_json(&bytes(name)).unwrap_or_else(|error| panic!("{name}: {error}"))
}

fn canonical(value: &Value) -> Vec<u8> {
    kilnd::firecracker::canonical(value).unwrap()
}

fn text<'a>(value: &'a Value, pointer: &str) -> &'a str {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{pointer} is not a string"))
}

fn number(value: &Value, pointer: &str) -> u64 {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{pointer} is not an integer"))
}

/// A test-only FIPS 180-4 SHA-256: the workspace has no hash crate to borrow,
/// and an independent implementation also cross-checks the Python digests.
fn sha256(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for block in message.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (slot, word) in w.iter_mut().zip(block.as_chunks::<4>().0) {
            *slot = u32::from_be_bytes(*word);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(choose)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(majority);
            (h, g, f, e, d, c, b, a) = (g, f, e, d.wrapping_add(t1), c, b, a, t1.wrapping_add(t2));
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
    state.iter().map(|word| format!("{word:08x}")).collect()
}

fn fixture_files(directory: &Path, prefix: &str, files: &mut BTreeSet<String>) {
    for entry in fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let name = format!("{prefix}{}", entry.file_name().to_string_lossy());
        if entry.file_type().unwrap().is_dir() {
            fixture_files(&entry.path(), &format!("{name}/"), files);
        } else {
            files.insert(name);
        }
    }
}

#[test]
fn sha256_matches_known_vectors() {
    assert_eq!(
        sha256(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256(&[b'a'; 1_000_000]),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

#[test]
fn fixture_set_is_exact_and_pinned() {
    let digests = load("digests.json");
    assert_eq!(sha256(&bytes("digests.json")), DIGESTS_JSON_SHA256);
    let listed = digests["files"].as_object().unwrap();
    let mut present = BTreeSet::new();
    fixture_files(&fixtures(), "", &mut present);
    assert!(present.remove("digests.json"));
    assert_eq!(present, listed.keys().cloned().collect::<BTreeSet<_>>());
    for (name, expected) in listed {
        assert_eq!(sha256(&bytes(name)), expected.as_str().unwrap(), "{name}");
    }
}

#[test]
fn json_fixtures_are_strict_sorted_documents() {
    // A byte-exact pretty round trip also proves there are no duplicate keys,
    // floats or non-canonical key orders hiding in a golden file.
    for name in [
        "bootstrap.json",
        "bundle/manifest.json",
        "contract.json",
        "digests.json",
        "legacy-no-vsock-manifest.json",
        "negative-cases.json",
        "plan-equal-ids.json",
        "plan.json",
        "replacement-cases.json",
        "substitutions-equal-ids.json",
        "substitutions.json",
        "vmm-argv.json",
    ] {
        let reserialized = serde_json::to_string_pretty(&load(name)).unwrap() + "\n";
        assert_eq!(reserialized.as_bytes(), bytes(name), "{name}");
    }
}

#[test]
fn manifest_is_test_schema_bound_to_its_approval() {
    let raw = bytes("bundle/manifest.json");
    let manifest = load("bundle/manifest.json");
    assert_eq!(
        sha256(&raw),
        text(&load("digests.json"), "/approved_manifest_sha256")
    );
    assert!(raw.len() <= 4 * MIB as usize);
    let fields: BTreeSet<_> = manifest.as_object().unwrap().keys().cloned().collect();
    let expected: BTreeSet<_> = [
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
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(fields, expected);
    assert_eq!(manifest["schema"], json!("kiln-test-manifest-v1"));
    assert_eq!(manifest["fixture_only"], json!(true));
    assert_eq!(manifest["architecture"], json!("aarch64"));
    assert_eq!(manifest["firecracker_version"], json!("1.17.0"));
    assert_eq!(manifest["launch_contract"], load("contract.json"));
    assert_eq!(manifest["broker"]["protocol"], json!(1));
    assert_eq!(
        manifest["broker"]["lifecycle"],
        json!("init-supervised-no-restart")
    );
    let artifacts = manifest["artifacts"].as_object().unwrap();
    assert_eq!(artifacts.len(), 5);
    for (name, record) in artifacts {
        let data = bytes(&format!("bundle/{name}"));
        assert_eq!(number(record, "/bytes"), data.len() as u64, "{name}");
        assert_eq!(text(record, "/sha256"), sha256(&data), "{name}");
    }
    let executables = manifest["executables"].as_object().unwrap();
    assert_eq!(
        executables.keys().map(String::as_str).collect::<Vec<_>>(),
        ["firecracker", "jailer", "kilnd-helper", "mkfs.xfs"]
    );
    let mut images = BTreeSet::new();
    for (role, pin) in executables {
        let data = bytes(&format!("executables/{role}"));
        assert_eq!(number(pin, "/bytes"), data.len() as u64, "{role}");
        assert_eq!(text(pin, "/sha256"), sha256(&data), "{role}");
        assert_eq!(pin["format"], json!("static-elf"));
        assert_eq!(pin["dependencies"], json!([]));
        assert!(images.insert(text(pin, "/sha256").to_string()));
        assert_static_aarch64_elf(&data);
    }
}

/// Executable closure of one role: no loader, no libraries, no interpreter.
fn assert_static_aarch64_elf(data: &[u8]) {
    assert_eq!(&data[..7], b"\x7fELF\x02\x01\x01");
    assert_eq!(u16::from_le_bytes([data[18], data[19]]), 183, "EM_AARCH64");
    let offset = u64::from_le_bytes(data[32..40].try_into().unwrap()) as usize;
    let count = u16::from_le_bytes([data[56], data[57]]) as usize;
    for index in 0..count {
        let start = offset + index * 56;
        let kind = u32::from_le_bytes(data[start..start + 4].try_into().unwrap());
        assert!(
            kind != 3 && kind != 2,
            "PT_INTERP/PT_DYNAMIC in a static image"
        );
    }
}

#[test]
fn contract_freezes_the_designed_values() {
    let contract = load("contract.json");
    for (pointer, expected) in [
        ("/schema", json!(2)),
        ("/profile", json!("offline-768-v1")),
        ("/boot", json!("cold-only")),
        ("/sessions_per_vm", json!(1)),
        ("/persistent_inner_sandboxes", json!(1)),
        ("/warm_pool", json!(0)),
        ("/interruption", json!("terminate-vm-after-dispatch")),
        (
            "/firecracker/boot-source/boot_args",
            json!(
                "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rootfstype=squashfs ro init=/init loglevel=3 randomize_kstack_offset=on"
            ),
        ),
        (
            "/firecracker_cmdline_suffix",
            json!(" pci=off root=/dev/vda ro earlycon=uart,mmio,0x40002000"),
        ),
        (
            "/firecracker/machine-config",
            json!({"vcpu_count": 1, "mem_size_mib": 768, "smt": false,
                   "huge_pages": "Transparent", "track_dirty_pages": false}),
        ),
        ("/firecracker/vsock/uds_path", json!("/run/vsock.sock")),
        ("/broker/port", json!(5252)),
        ("/broker/peer_cid", json!(2)),
        ("/broker/restart", json!(false)),
        ("/leases/uid", json!([300000, 365535])),
        ("/leases/gid", json!([300000, 365535])),
        ("/leases/cid", json!([3, 65535])),
        ("/admission/guest_memory_bytes", json!(768 * MIB)),
        ("/admission/host_overhead_bytes", json!(128 * MIB)),
        ("/admission/inner_memory_max", json!(512 * MIB)),
        ("/admission/inner_cpu_millis_max", json!(1000)),
        ("/admission/inner_network", json!("none")),
        ("/vmm_credentials/groups", json!([])),
        ("/vmm_credentials/CapEff", json!(0)),
        ("/vmm_credentials/CapPrm", json!(0)),
        ("/vmm_credentials/CapInh", json!(0)),
        ("/vmm_credentials/CapBnd", json!(0)),
        ("/vmm_credentials/CapAmb", json!(0)),
        ("/vmm_credentials/NoNewPrivs", json!(1)),
        ("/vmm_credentials/seccomp", json!("default")),
        ("/jail/size_bytes", json!(16 * MIB)),
        ("/jail/nr_inodes", json!(1024)),
        (
            "/jail/mount_data",
            json!("size=16M,nr_inodes=1024,mode=0700"),
        ),
        ("/jail/mount_flags", json!(["MS_NOSUID"])),
        ("/jail/binds_read_only", json!(true)),
        ("/work/loop/offset", json!(0)),
        ("/work/loop/node_mode", json!("0600")),
        ("/work/loop/regular_file_fallback", json!(false)),
        ("/work/loop/loop_control_exposed", json!(false)),
        ("/work/loop/discard", json!(false)),
        ("/work/loop/intent_before_configure", json!(true)),
        ("/work/guest_headroom_bytes", json!(256 * MIB)),
        ("/work/host_allowance_bytes", json!(128 * MIB)),
        ("/work/minimum_bytes", json!(512 * MIB)),
        ("/work/round_bytes", json!(64 * MIB)),
        ("/cgroups/allocation/memory.max", json!(896 * MIB)),
        ("/cgroups/allocation/memory.swap.max", json!(0)),
        ("/cgroups/allocation/memory.oom.group", json!(1)),
        ("/cgroups/allocation/pids.max", json!(32)),
        ("/cgroups/allocation/cpu.max", json!("100000 100000")),
        ("/cgroups/allocation/direct_tasks", json!(false)),
        ("/cgroups/relay/memory.max", json!(16 * MIB)),
        ("/cgroups/relay/pids.max", json!(4)),
        ("/cgroups/relay/cpu.max", json!("5000 100000")),
        ("/cgroups/vm~1console/memory.max", json!(4 * MIB)),
        ("/cgroups/vm~1console/pids.max", json!(2)),
        ("/cgroups/vm~1console/cpu.max", json!("5000 100000")),
        ("/workers/L/node_limit", json!(1)),
        ("/workers/P/node_limit", json!(2)),
        ("/workers/P/per_allocation", json!(1)),
        ("/workers/S/per_allocation", json!(1)),
        ("/workers/R/per_allocation", json!(1)),
        ("/workers/D/per_allocation", json!(1)),
        ("/workers/M/node_limit", json!(1)),
        ("/workers/K/node_limit", json!(2)),
        ("/workers/K/reserved", json!(true)),
        ("/workers/separate_executables", json!([])),
        ("/timing_exception/source", json!("jailer-only")),
        ("/timing_exception/type", json!("u64-decimal-microseconds")),
        ("/executable/path_fallback", json!(false)),
        ("/executable/shell_or_shebang", json!(false)),
        ("/executable/environment", json!({})),
        ("/executable/exec", json!("execveat-AT_EMPTY_PATH")),
        ("/executable/ancestry/owner_uid", json!(0)),
        ("/executable/ancestry/group_world_write", json!(false)),
        ("/executable/ancestry/nonroot_acl_write", json!(false)),
        ("/executable/ancestry/default_acl_write", json!(false)),
        (
            "/executable/ancestry/parent_rename_authority",
            json!("root-only"),
        ),
        ("/executable/ancestry/symlinks", json!(false)),
        ("/executable/installation/hardlinks", json!(false)),
        ("/executable/installation/file_capabilities", json!(false)),
        ("/executable/installation/setid", json!(false)),
        ("/executable/installation/create_may_install", json!(false)),
        (
            "/executable/identity_fields",
            json!([
                "role",
                "st_dev",
                "st_ino",
                "bytes",
                "sha256",
                "installation_generation"
            ]),
        ),
        ("/handoff/version", json!(1)),
        ("/handoff/vmm_fd", json!(3)),
        ("/handoff/control_fd", json!(4)),
        ("/handoff/only_inherited_extra_fds", json!([3, 4])),
        ("/handoff/close_on_vmm_exec", json!([3, 4])),
        ("/handoff/jailer_exec_fd_min", json!(5)),
        ("/handoff/jailer_exec_fd_cloexec", json!(true)),
        ("/handoff/bootstrap_max_bytes", json!(4096)),
        ("/handoff/stock_jailer_compatible", json!(false)),
        ("/identity/bytes", json!(4096)),
        ("/identity/magic", json!("KID1")),
        ("/identity/device", json!("vdc")),
        ("/identity/read_only", json!(true)),
        ("/shared/memory_bytes", json!(128 * MIB)),
        ("/shared/cpu_millis", json!(500)),
        ("/shared/pids", json!(32)),
        ("/shared/once_per_node", json!(true)),
    ] {
        assert_eq!(contract.pointer(pointer), Some(&expected), "{pointer}");
    }
    let drives = contract["firecracker"]["drives"].as_array().unwrap();
    let layout: Vec<_> = drives
        .iter()
        .map(|drive| {
            (
                text(drive, "/drive_id"),
                text(drive, "/path_on_host"),
                drive["is_root_device"].as_bool().unwrap(),
                drive["is_read_only"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        layout,
        [
            ("rootfs", "/rootfs", true, true),
            ("work", "/work", false, false),
            ("identity", "/identity", false, true),
        ]
    );
    let top: BTreeSet<_> = contract["firecracker"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        top,
        ["boot-source", "drives", "machine-config", "vsock"]
            .map(String::from)
            .into_iter()
            .collect(),
        "no NIC, MMDS, CPU template or other device key"
    );
    assert_eq!(
        contract["substitutions"],
        json!({"allocation_id": "Id128", "boot_nonce": "Nonce256", "cid": "GuestCid",
               "executables": "VerifiedInstalledIdentityVector", "gid": "VmmGid",
               "inner_spec": "ValidatedOfflineSpec", "instance_id": "Id128",
               "relay_gid": "RelayGid", "relay_uid": "RelayUid",
               "sandbox_id": "SandboxId64", "uid": "VmmUid", "work_uuid": "Uuid"})
    );
}

/// Re-derive the launch from substitutions alone, as B3's `config` module must.
fn check_derived_plan(plan: &Value, subs: &Value, uid: u64, gid: u64) {
    let manifest = load("bundle/manifest.json");
    let allocation = text(subs, "/allocation_id");
    let instance = text(subs, "/instance_id");
    let backend = format!("fc-{allocation}");
    let store = |role: &str| {
        let digest = text(&manifest, &format!("/executables/{role}/sha256"));
        format!("/opt/kilnd/exec/sha256/{digest}/{role}")
    };
    let cgroup = format!("kilnd-firecracker/{instance}/{backend}");
    let launch = &plan["launch"];
    assert_eq!(
        plan["manifest_sha256"],
        load("digests.json")["approved_manifest_sha256"]
    );
    assert_eq!(&plan["substitutions"], subs);
    assert_eq!(
        launch["jailer_argv"],
        json!([
            store("jailer"),
            "--id",
            backend,
            "--exec-file",
            store("firecracker"),
            "--uid",
            uid.to_string(),
            "--gid",
            gid.to_string(),
            "--chroot-base-dir",
            "/var/lib/kilnd-helper/jails",
            "--cgroup-version",
            "2",
            "--parent-cgroup",
            format!("{cgroup}/vm/vmm"),
            "--new-pid-ns",
            "--resource-limit",
            "no-file=256",
            "--",
            "--no-api",
            "--config-file",
            "/config.json"
        ])
    );
    assert_eq!(
        launch["vmm_argv_semantic"],
        json!([
            "/firecracker",
            "--id",
            backend,
            "--no-api",
            "--config-file",
            "/config.json"
        ])
    );
    let backing = format!("/var/lib/kilnd-helper/work/{instance}/{backend}/work.xfs");
    assert_eq!(
        launch["formatter_argv"],
        json!([
            store("mkfs.xfs"),
            "-q",
            "-f",
            "-K",
            "-m",
            format!("uuid={}", text(subs, "/work_uuid")),
            backing
        ])
    );
    assert_eq!(launch["work_backing_path"], json!(backing));
    assert_eq!(launch["cgroup"], json!(cgroup));
    let jail = format!("/var/lib/kilnd-helper/jails/firecracker/{backend}/root");
    assert_eq!(launch["jail_root"], json!(jail));
    let vsock = format!("{jail}/run/vsock.sock");
    assert_eq!(launch["vsock_host_path"], json!(vsock));
    assert!(vsock.len() < 108, "sockaddr_un");
    let config = &launch["firecracker"];
    assert_eq!(config["vsock"]["guest_cid"], subs["cid"]);
    let mut expected_config = load("contract.json")["firecracker"].clone();
    expected_config["vsock"]["guest_cid"] = subs["cid"].clone();
    assert_eq!(config, &expected_config);

    let inner_disk = number(subs, "/inner_spec/disk_bytes");
    let round = 64 * MIB;
    let work = (512 * MIB).max((inner_disk + 256 * MIB).div_ceil(round) * round);
    assert_eq!(number(launch, "/work_bytes"), work);
    let pids = number(subs, "/inner_spec/pids");
    assert_eq!(
        launch["reservation"],
        json!({"memory_bytes": 896 * MIB, "disk_bytes": work + 128 * MIB, "pids": pids + 64,
               "host_pids": 32, "host_cpu_millis": 1000, "virtual_cpu_slots": 1})
    );
    let recipe = &launch["resource_recipe"];
    assert_eq!(recipe["vmm_credentials"]["uid"], json!(uid));
    assert_eq!(recipe["vmm_credentials"]["gid"], json!(gid));
    assert_eq!(
        recipe["relay_credentials"]["uid"],
        subs["relay_uid"]["value"]
    );
    assert_eq!(
        recipe["relay_credentials"]["gid"],
        subs["relay_gid"]["value"]
    );
    assert_eq!(recipe["work"]["loop"]["size_limit"], json!(work));
    assert_eq!(recipe["work"]["loop"]["owner"], json!([uid, gid]));
    assert_eq!(recipe["work"]["formatter_argv"], launch["formatter_argv"]);
    // The identity drive is in the launch digest; the block's content is not.
    assert_eq!(recipe["identity"]["path"], json!("/identity"));
}

#[test]
fn plans_rederive_with_typed_unequal_and_equal_ids() {
    let (plan, subs) = (load("plan.json"), load("substitutions.json"));
    assert_eq!(subs["uid"], json!({"kind": "VmmUid", "value": 300001}));
    assert_eq!(subs["gid"], json!({"kind": "VmmGid", "value": 300002}));
    assert_eq!(subs["relay_uid"]["kind"], json!("RelayUid"));
    assert_eq!(subs["relay_gid"]["kind"], json!("RelayGid"));
    check_derived_plan(&plan, &subs, 300001, 300002);
    let (plan, subs) = (
        load("plan-equal-ids.json"),
        load("substitutions-equal-ids.json"),
    );
    assert_eq!(subs["uid"], json!({"kind": "VmmUid", "value": 300005}));
    assert_eq!(subs["gid"], json!({"kind": "VmmGid", "value": 300005}));
    check_derived_plan(&plan, &subs, 300005, 300005);
}

#[test]
fn inner_spec_and_vector_match_kilnd_model_shape() {
    let subs = load("substitutions.json");
    assert_eq!(
        subs["inner_spec"],
        json!({"image": "alpine", "memory_bytes": 512 * MIB, "cpu_millis": 1000, "pids": 128,
               "disk_bytes": 1024 * MIB, "network": "none", "read_only_root": false,
               "writable_paths": []})
    );
    assert!(kilnd::model::valid_id("sb", text(&subs, "/sandbox_id")));
    assert_eq!(text(&subs, "/instance_id").len(), 32);
    assert_eq!(text(&subs, "/allocation_id").len(), 32);
    let mut inodes = BTreeSet::new();
    for (role, record) in subs["executables"].as_object().unwrap() {
        assert_eq!(text(record, "/role"), role);
        assert!(inodes.insert((number(record, "/st_dev"), number(record, "/st_ino"))));
        assert!(number(record, "/installation_generation") >= 1);
    }
}

#[test]
fn canonical_digests_agree_across_implementations() {
    let digests = load("digests.json");
    let plan = load("plan.json");
    assert_eq!(sha256(&canonical(&plan)), text(&digests, "/plan_sha256"));
    assert_eq!(
        sha256(&canonical(&plan["launch"])),
        text(&digests, "/launch_sha256")
    );
}

#[test]
fn identity_block_is_framed_canonical_and_bound() {
    let block = bytes("identity.bin");
    assert_eq!(block.len(), 4096);
    assert_eq!(&block[..4], b"KID1");
    let length = u32::from_be_bytes(block[4..8].try_into().unwrap()) as usize;
    assert!((1..=4088).contains(&length));
    assert!(block[8 + length..].iter().all(|byte| *byte == 0));
    let record: Value = serde_json::from_slice(&block[8..8 + length]).unwrap();
    assert_eq!(
        canonical(&record),
        &block[8..8 + length],
        "canonical record"
    );
    let subs = load("substitutions.json");
    let digests = load("digests.json");
    assert_eq!(
        record,
        json!({
            "instance_id": subs["instance_id"], "allocation_id": subs["allocation_id"],
            "sandbox_id": subs["sandbox_id"], "boot_nonce": subs["boot_nonce"],
            "work_uuid": subs["work_uuid"],
            "manifest_sha256": digests["approved_manifest_sha256"],
            "launch_sha256": digests["launch_sha256"],
            "guest_exec_spec_sha256": sha256(&canonical(&subs["inner_spec"])),
        })
    );
    assert_eq!(text(&subs, "/boot_nonce").len(), 64);
    let names: Vec<_> = record.as_object().unwrap().keys().cloned().collect();
    let frozen: BTreeSet<_> = load("contract.json")["identity"]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap().to_string())
        .collect();
    assert_eq!(names.into_iter().collect::<BTreeSet<_>>(), frozen);
}

fn apply_mutation(document: &mut Value, case: &Value) {
    let path = case["path"].as_array().unwrap();
    let mut target = document;
    for part in &path[..path.len() - 1] {
        target = match part {
            Value::String(key) => &mut target[key.as_str()],
            index => &mut target[index.as_u64().unwrap() as usize],
        };
    }
    let last = &path[path.len() - 1];
    let remove = case.get("remove").is_some();
    match (target, last) {
        (Value::Object(map), Value::String(key)) if remove => {
            map.remove(key).unwrap();
        }
        (Value::Object(map), Value::String(key)) => {
            map.insert(key.clone(), case["value"].clone());
        }
        (Value::Array(items), index) if remove => {
            items.remove(index.as_u64().unwrap() as usize);
        }
        (Value::Array(items), index) if index.as_u64().unwrap() as usize == items.len() => {
            items.push(case["value"].clone());
        }
        (Value::Array(items), index) => {
            items[index.as_u64().unwrap() as usize] = case["value"].clone();
        }
        (target, _) => panic!("cannot mutate {target}"),
    }
}

#[test]
fn every_named_attack_is_refused_even_when_reapproved() {
    let manifest = load("bundle/manifest.json");
    let approved = load("digests.json")["approved_manifest_sha256"].clone();
    let cases = load("negative-cases.json");
    let cases = cases.as_array().unwrap();
    assert!(cases.len() >= 40);
    let bases = load("conformance.json")["bases"].clone();
    let mut names = BTreeSet::new();
    for case in cases {
        let name = text(case, "/name");
        assert!(names.insert(name.to_string()), "duplicate case {name}");
        assert!(!text(case, "/why").is_empty());
        let mut mutated = manifest.clone();
        apply_mutation(&mut mutated, case);
        assert_ne!(mutated, manifest, "{name} changed nothing");
        let raw = serde_json::to_string_pretty(&mutated).unwrap() + "\n";
        assert_ne!(json!(sha256(raw.as_bytes())), approved, "{name}");
        assert!(
            corpus_validate("fixture_manifest", raw.as_bytes(), &bases).is_err(),
            "{name}"
        );
        assert!(
            kilnd::firecracker::validate_manifest(raw.as_bytes(), &sha256(raw.as_bytes())).is_err(),
            "{name}"
        );
    }
    for name in [
        "nokaslr",
        "init-zeroing-off",
        "writable-root",
        "vcpu",
        "ram",
        "thp",
        "nic",
        "no-vsock",
        "extra-drive",
        "custom-seccomp",
        "api-socket",
        "cold-only",
        "cap-bounding",
        "tmpfs-bytes",
        "path-fallback",
        "dynamic-formatter",
        "legacy-schema",
    ] {
        assert!(names.contains(name), "{name}");
    }
}

#[test]
fn legacy_no_vsock_manifest_cannot_satisfy_the_contract() {
    let legacy = load("legacy-no-vsock-manifest.json");
    assert_eq!(legacy["schema"], json!(1));
    assert_eq!(
        legacy["broker"],
        json!({"enabled": false, "protocol": null})
    );
    let production = &legacy["launch_contract"]["profiles"]["production"];
    assert!(production["firecracker"].get("vsock").is_none());
    assert_eq!(production["jailer"]["uid"], json!(10000));
    assert_eq!(production["jailer"]["new_pid_namespace"], json!(false));
    assert_eq!(
        production["firecracker"]["drives"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        text(&legacy, "/inputs/projected_from_manifest_sha256"),
        "e855fbee1914cc6ea5e57a1250610e128412c85a905c94a48fb54afdaa47f3d3"
    );
    assert_ne!(
        sha256(&bytes("legacy-no-vsock-manifest.json")),
        text(&load("digests.json"), "/approved_manifest_sha256")
    );
}

/// B3's comparison: the journal tuple against what /proc reports for the running process.
fn identity_matches(expected: &Value, observed: &Value) -> bool {
    observed.as_object().unwrap().len() == 5
        && ["role", "st_dev", "st_ino", "bytes", "sha256"]
            .iter()
            .all(|field| expected[field] == observed[field])
}

#[test]
fn replacement_verdicts_use_the_actual_executed_tuple() {
    let cases = load("replacement-cases.json");
    assert_eq!(cases["argv_and_prior_digest"], json!("insufficient"));
    assert_eq!(cases["post_C1"], json!("charged-until-AbsentFenced"));
    assert_eq!(cases["C0"], json!("zero-session-side-effects"));
    let vector = load("substitutions.json")["executables"].clone();
    let mut races = BTreeSet::new();
    for case in cases["cases"].as_array().unwrap() {
        let role = text(case, "/role");
        assert_eq!(case["expected"], vector[role]);
        assert_eq!(
            identity_matches(&case["expected"], &case["observed"]),
            case["accept"].as_bool().unwrap(),
            "{role} {}",
            text(case, "/race")
        );
        races.insert((role.to_string(), text(case, "/race").to_string()));
    }
    assert_eq!(races.len(), 4 * 5, "every role under every modeled race");
}

#[test]
fn vmm_argv_varies_only_in_jailer_timing() {
    let argv = load("vmm-argv.json");
    let argv: Vec<_> = argv
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let backend = format!("fc-{}", text(&load("substitutions.json"), "/allocation_id"));
    let template = load("contract.json")["vmm_argv"].clone();
    assert_eq!(template.as_array().unwrap().len(), argv.len());
    for (index, slot) in template.as_array().unwrap().iter().enumerate() {
        match slot.as_str().unwrap() {
            "$backend_id" => assert_eq!(argv[index], backend),
            name if name.starts_with('$') => {
                assert!(
                    [
                        "$start_time_us",
                        "$start_time_cpu_us",
                        "$parent_cpu_time_us"
                    ]
                    .contains(&name)
                );
                argv[index].parse::<u64>().unwrap();
                assert!(argv[index] == "0" || !argv[index].starts_with('0'));
            }
            literal => assert_eq!(argv[index], literal),
        }
    }
    let semantic: Vec<_> = argv
        .iter()
        .enumerate()
        .filter(|(index, _)| ![3, 4, 5, 6, 7, 8].contains(index))
        .map(|(_, item)| *item)
        .collect();
    assert_eq!(
        json!(semantic),
        load("plan.json")["launch"]["vmm_argv_semantic"]
    );
}

#[test]
fn status_fixture_has_separate_ids_empty_groups_and_zero_masks() {
    let status = String::from_utf8(bytes("vmm-status.txt")).unwrap();
    let field = |name: &str| -> Vec<String> {
        let prefix = format!("{name}:");
        let line = status
            .lines()
            .find(|line| line.starts_with(&prefix))
            .unwrap();
        line[prefix.len()..]
            .split_whitespace()
            .map(String::from)
            .collect()
    };
    assert_eq!(field("Uid"), ["300001"; 4]);
    assert_eq!(field("Gid"), ["300002"; 4]);
    assert!(field("Groups").is_empty());
    assert_eq!(field("NoNewPrivs"), ["1"]);
    assert_eq!(field("Seccomp"), ["2"]);
    for mask in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        assert_eq!(field(mask), ["0000000000000000"], "{mask}");
    }
}

#[test]
fn bootstrap_record_binds_the_retained_vmm_and_jail() {
    let golden = load("bootstrap.json");
    let record = &golden["record"];
    assert!(canonical(record).len() <= 4096);
    assert_eq!(record["version"], json!(1));
    assert_eq!(record["plan_generation"], golden["plan_generation"]);
    assert_eq!(record["jail_root_identity"], golden["jail_root_identity"]);
    let vmm = &load("substitutions.json")["executables"]["firecracker"];
    assert_eq!(
        record["vmm_identity"],
        json!({"st_dev": vmm["st_dev"], "st_ino": vmm["st_ino"],
               "bytes": vmm["bytes"], "sha256": vmm["sha256"]})
    );
    assert_eq!(
        record["exec_file_label"],
        load("plan.json")["launch"]["executable_paths"]["firecracker"]
    );
    let fields: BTreeSet<_> = record.as_object().unwrap().keys().cloned().collect();
    let frozen: BTreeSet<_> = load("contract.json")["handoff"]["bootstrap_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap().to_string())
        .collect();
    assert_eq!(fields, frozen);
}

fn assert_no_placeholder(name: &str, value: &Value) {
    match value {
        Value::String(item) => assert!(
            !item.contains('$')
                && !item.contains('{')
                && !item.to_lowercase().contains("placeholder"),
            "{name}: {item}"
        ),
        Value::Array(items) => items
            .iter()
            .for_each(|item| assert_no_placeholder(name, item)),
        Value::Object(map) => map
            .values()
            .for_each(|item| assert_no_placeholder(name, item)),
        _ => {}
    }
}

#[test]
fn resolved_fixtures_have_no_placeholder_security_fields() {
    for name in [
        "plan.json",
        "plan-equal-ids.json",
        "substitutions.json",
        "bootstrap.json",
    ] {
        assert_no_placeholder(name, &load(name));
    }
}

#[test]
fn production_stays_disabled_without_the_broker() {
    // Fixtures only: B7 alone may let the daemon select this backend in production.
    assert_eq!(load("bundle/manifest.json")["fixture_only"], json!(true));
    assert!(
        String::from_utf8(bytes("README.md"))
            .unwrap()
            .contains("they grant no deployment")
    );
    // B6: the default stays kiln, and Firecracker is constructed only after the isolated
    // test deployment was read and its paths and observed identity checked
    // (deploy/firecracker-test/), and only in a build with the non-default
    // `firecracker-test-deployment` feature (B6-BI-01).
    let main =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs")).unwrap();
    assert!(main.contains("default_value_t = Backend::Kiln"));
    assert_eq!(main.matches("FirecrackerRuntime::new(").count(), 1);
    let (_, run) = main
        .split_once("let deployment = selected_deployment(&args, gid)?;")
        .unwrap();
    let (arm, _) = run.split_once("FirecrackerRuntime::new(").unwrap();
    assert!(
        arm.contains(
            "#[cfg(feature = \"firecracker-test-deployment\")]\n        Some(deployment) =>"
        ),
        "{arm}"
    );
    let (_, selection) = main
        .split_once("#[cfg(feature = \"firecracker-test-deployment\")]\nfn selected_deployment(")
        .unwrap();
    let (read, checked) = selection.split_once("TestDeployment::read(").unwrap();
    assert!(read.contains("(Backend::Firecracker, Some(path)) =>"));
    let (checked, _) = checked.split_once("Ok(Some(deployment))").unwrap();
    assert!(checked.contains("check_daemon("));
    assert!(checked.contains("check_process(socket_gid)?"));
}

// This type exists only in this integration-test binary. It cannot construct a
// PreparedCreate; its JSON schema/profile are outside the production namespace.
struct FixturePlan(Value);
fn fixture_plan(bases: &Value) -> Result<FixturePlan, String> {
    use kilnd::firecracker as fc;
    let baseline = &bases["fixture_plan"];
    let subs = &baseline["substitutions"];
    let binding = fc::bind_host_spec(&baseline["host_spec"])?;
    let mut doc = binding.journal_value();
    doc["schema"] = json!("kiln-test-plan-v1");
    doc["profile"] = json!("test-only-b1");
    doc["substitutions"] = subs.clone();
    doc["manifest_sha256"] = baseline["manifest_sha256"].clone();
    doc["launch"] = fc::derive_launch(subs, &bases["fixture_manifest"]["executables"])?;
    Ok(FixturePlan(doc))
}
fn corpus_validate(kind: &str, raw: &[u8], bases: &Value) -> Result<Vec<u8>, String> {
    use kilnd::firecracker as fc;
    let v = fc::strict_json(raw)?;
    match kind {
        "json" => {}
        "contract" => {
            fc::validate_contract(raw)?;
        }
        "guest_exec_spec" => fc::validate_guest_exec_spec(&v)?,
        "substitutions" => {
            fc::derive_launch(&v, &bases["fixture_manifest"]["executables"])?;
        }
        "host_spec" => {
            fc::bind_host_spec(&v)?;
        }
        "binding" => {
            fc::verify_spec_binding(raw)?;
        }
        "fixture_manifest" => {
            // Fixed schema and provenance, independently checked recipe, and
            // actual artifact bytes. No approval-hash-only mutation test.
            fc::verify_exact(raw, &bases["fixture_manifest"])?;
            fc::validate_contract(&fc::canonical(&v["launch_contract"])?)?;
            for (group, prefix) in [("artifacts", "bundle"), ("executables", "executables")] {
                for (name, pin) in v[group].as_object().ok_or("fixture records")? {
                    let data = bytes(&format!("{prefix}/{name}"));
                    if pin["bytes"] != json!(data.len()) || pin["sha256"] != fc::sha256(&data) {
                        return Err("fixture byte mismatch".into());
                    }
                }
            }
        }
        "fixture_plan" => {
            fc::verify_exact(raw, &fixture_plan(bases)?.0)?;
        }
        "production_manifest" => {
            fc::validate_manifest(raw, &fc::sha256(raw))?;
        }
        _ => return Err(format!("unknown kind {kind}")),
    }
    fc::canonical(&v)
}
fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn shared_conformance_corpus() {
    use kilnd::firecracker as fc;
    let corpus = load("conformance.json");
    let bases = &corpus["bases"];
    let cases = corpus["cases"].as_array().unwrap();
    assert!(cases.len() > 2000);
    for case in cases {
        let raw = if let Some(repeat) = case["repeat_hex"].as_str() {
            let mut raw = unhex(repeat).repeat(case["repeat"].as_u64().unwrap() as usize);
            raw.extend(unhex(text(case, "/suffix_hex")));
            raw
        } else if let Some(raw) = case["raw_hex"].as_str() {
            unhex(raw)
        } else {
            let mut v = bases[case["base"].as_str().unwrap()].clone();
            apply_mutation(&mut v, case);
            fc::canonical(&v).unwrap()
        };
        let result = corpus_validate(text(case, "/kind"), &raw, bases);
        assert_eq!(
            result.is_ok(),
            case["accept"].as_bool().unwrap(),
            "{}: {result:?}",
            text(case, "/name")
        );
        if let Ok(actual) = result {
            assert_eq!(
                actual,
                text(case, "/canonical_ascii").as_bytes(),
                "{}",
                text(case, "/name")
            );
            assert_eq!(
                fc::sha256(&actual),
                text(case, "/sha256"),
                "{}",
                text(case, "/name")
            );
        }
    }
}
#[test]
fn unicode_and_duplicate_poc() {
    use kilnd::firecracker as fc;
    let value = fc::strict_json("{\"writable_paths\":[\"/雪\"]}".as_bytes()).unwrap();
    assert_eq!(
        fc::canonical(&value).unwrap(),
        br#"{"writable_paths":["/\u96ea"]}"#
    );
    assert!(fc::strict_json(br#"{"schema":1,"schema":2}"#).is_err());
    assert!(fc::canonical(&json!(1.0)).is_err());
}
#[test]
fn label_collision_and_journal_replay() {
    use kilnd::firecracker as fc;
    let mut host = load("plan.json")["host_spec"].clone();
    host["labels"] = json!({"tenant":"alpha"});
    let a = fc::bind_host_spec(&host).unwrap();
    host["labels"] = json!({"tenant":"beta"});
    let b = fc::bind_host_spec(&host).unwrap();
    assert_ne!(a.host_spec_sha256(), b.host_spec_sha256());
    assert_eq!(a.guest_exec_spec_sha256(), b.guest_exec_spec_sha256());
    fc::verify_spec_binding(&fc::canonical(&a.journal_value()).unwrap()).unwrap();
    let mut stale = a.journal_value();
    stale["host_spec"] = host;
    assert!(fc::verify_spec_binding(&fc::canonical(&stale).unwrap()).is_err());
}
#[test]
fn fixture_mode_poc_cannot_make_production_plan() {
    use kilnd::firecracker as fc;
    let fixture = load("bundle/manifest.json");
    assert_eq!(fixture["schema"], json!("kiln-test-manifest-v1"));
    assert_eq!(load("plan.json")["schema"], json!("kiln-test-plan-v1"));
    assert_eq!(load("plan.json")["profile"], json!("test-only-b1"));
    for schema in [json!("kiln-test-manifest-v1"), json!(2)] {
        for flag in [true, false] {
            let mut m = fixture.clone();
            m["schema"] = schema.clone();
            m["fixture_only"] = json!(flag);
            let raw = fc::canonical(&m).unwrap();
            assert!(fc::validate_manifest(&raw, &fc::sha256(&raw)).is_err());
        }
    }
}
