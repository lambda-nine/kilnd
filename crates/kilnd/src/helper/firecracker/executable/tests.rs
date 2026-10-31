//! Exit 5: the KR-05 matrix over real files and descriptors. Every case compares the
//! tuple a descriptor actually names with the plan's tuple, never argv or a past hash.
//! Linux root tests below run the real `execveat` chain and read `/proc/<pid>/exe`.
use super::*;
use crate::model::Digest;
use std::io::Read as _;
use std::os::fd::IntoRawFd;
use std::os::unix::fs::{OpenOptionsExt, symlink};

pub(in crate::helper::firecracker) fn fixture_bytes(role: Role) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/firecracker/executables/{}",
        env!("CARGO_MANIFEST_DIR"),
        role.as_str()
    ))
    .unwrap()
}

pub(in crate::helper::firecracker) fn pin_of(role: Role) -> ExecutablePin {
    let bytes = fixture_bytes(role);
    ExecutablePin {
        role,
        bytes: bytes.len() as u64,
        sha256: Digest::of(&bytes),
        installation_generation: 1,
    }
}

pub(in crate::helper::firecracker) fn all_pins() -> Vec<ExecutablePin> {
    Role::ALL.iter().map(|role| pin_of(*role)).collect()
}

struct Store {
    _temp: tempfile::TempDir,
    root: PathBuf,
    policy: WalkPolicy,
    store: PathBuf,
    source: PathBuf,
}

fn store() -> Store {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let policy = WalkPolicy::test_rooted(&root);
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let store = root.join("exec/sha256");
    let source = root.join("source");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::create_dir_all(&source).unwrap();
    for directory in [root.join("exec"), store.clone()] {
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    for role in Role::ALL {
        let path = source.join(role.as_str());
        std::fs::write(&path, fixture_bytes(role)).unwrap();
        let file = File::open(&path).unwrap();
        publish_object(&policy, &store, &file, &pin_of(role)).unwrap();
    }
    Store {
        _temp: temp,
        root,
        policy,
        store,
        source,
    }
}

impl Store {
    fn object(&self, role: Role) -> PathBuf {
        self.store
            .join(pin_of(role).sha256.to_string())
            .join(role.as_str())
    }

    fn table(&self) -> ExecutableTable {
        ExecutableTable::open(self.policy.clone(), &self.store, &all_pins()).unwrap()
    }
}

fn expected(table: &ExecutableTable, role: Role) -> ExecutableIdentity {
    table.identity(role).unwrap()
}

/// Installs a replacement object at the same name, as a non-atomic administrator or a
/// root fault would. `bytes` decides whether the digest would still match.
fn replace_installed(store: &Store, role: Role, bytes: &[u8]) -> PathBuf {
    let object = store.object(role);
    let parked = store.root.join(format!("parked-{}", role.as_str()));
    std::fs::rename(&object, &parked).unwrap();
    let mut options = std::fs::OpenOptions::new();
    let mut file = options
        .create_new(true)
        .write(true)
        .mode(0o555)
        .open(&object)
        .unwrap();
    std::io::Write::write_all(&mut file, bytes).unwrap();
    parked
}

fn restore_installed(store: &Store, role: Role, parked: &Path) {
    let object = store.object(role);
    std::fs::remove_file(&object).unwrap();
    std::fs::rename(parked, &object).unwrap();
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Boundary {
    C1Preflight,
    C2Revalidate,
    PreDispatch,
}

const BOUNDARIES: [Boundary; 3] = [
    Boundary::C1Preflight,
    Boundary::C2Revalidate,
    Boundary::PreDispatch,
];

/// A boundary that rechecks through the protected tree refuses a replacement. Dispatch
/// uses only the retained descriptor, so it runs the approved inode regardless. Either
/// way, a replacement inode can never be what executes.
fn assert_boundary_outcome(
    table: &ExecutableTable,
    role: Role,
    plan: &[ExecutableIdentity],
    boundary: Boundary,
    case: &str,
) {
    let approved = plan.iter().find(|identity| identity.role == role).unwrap();
    match boundary {
        Boundary::C1Preflight | Boundary::C2Revalidate => {
            let refused = table.revalidate(plan);
            assert!(
                refused.is_err(),
                "{role:?} {boundary:?} {case} was accepted"
            );
        }
        Boundary::PreDispatch => {
            let observed = table.model_execute(approved).unwrap();
            assert_eq!(observed.actual, *approved, "{role:?} {case}");
            assert_eq!(observed.expected, *approved, "{role:?} {case}");
        }
    }
}

#[test]
fn exit5_source_parent_swap_is_harmless_to_retained_descriptors_at_every_boundary() {
    for role in Role::ALL {
        for boundary in BOUNDARIES {
            let fixture = store();
            let table = fixture.table();
            let plan = table.vector();
            // The source is an installation input, never execution authority: rename
            // its whole parent and plant different bytes at the same name.
            let moved = fixture.root.join("source-moved");
            std::fs::rename(&fixture.source, &moved).unwrap();
            std::fs::create_dir(&fixture.source).unwrap();
            std::fs::write(fixture.source.join(role.as_str()), b"attacker").unwrap();
            match boundary {
                Boundary::C1Preflight | Boundary::C2Revalidate => {
                    table.revalidate(&plan).unwrap();
                }
                Boundary::PreDispatch => {
                    let observed = table.model_execute(&expected(&table, role)).unwrap();
                    assert_eq!(observed.actual, expected(&table, role));
                }
            }
        }
    }
}

#[test]
fn exit5_installed_name_swap_with_identical_or_other_bytes_cannot_authorize_a_new_inode() {
    for role in Role::ALL {
        for boundary in BOUNDARIES {
            for (case, bytes) in [
                ("identical bytes", fixture_bytes(role)),
                ("other bytes", b"\x7fELF replacement".to_vec()),
            ] {
                let fixture = store();
                let table = fixture.table();
                let plan = table.vector();
                let parked = replace_installed(&fixture, role, &bytes);
                assert_boundary_outcome(&table, role, &plan, boundary, case);
                // Restoring the same inode restores acceptance: no latch hides a real
                // refusal and no hash of a look-alike passes in its place.
                restore_installed(&fixture, role, &parked);
                table.revalidate(&plan).unwrap();
            }
        }
    }
}

#[test]
fn exit5_installed_parent_swap_cannot_redirect_or_pass_as_the_old_tree() {
    for role in Role::ALL {
        for boundary in BOUNDARIES {
            let fixture = store();
            let table = fixture.table();
            let plan = table.vector();
            // Swap the digest directory itself, then the store root above it.
            let digest = pin_of(role).sha256.to_string();
            let directory = fixture.store.join(&digest);
            let parked = fixture.root.join(format!("parked-{digest}"));
            std::fs::rename(&directory, &parked).unwrap();
            std::fs::create_dir(&directory).unwrap();
            std::fs::write(directory.join(role.as_str()), fixture_bytes(role)).unwrap();
            std::fs::set_permissions(
                directory.join(role.as_str()),
                std::fs::Permissions::from_mode(0o555),
            )
            .unwrap();
            assert_boundary_outcome(&table, role, &plan, boundary, "digest directory swap");
            std::fs::set_permissions(
                directory.join(role.as_str()),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            std::fs::remove_dir_all(&directory).unwrap();
            std::fs::rename(&parked, &directory).unwrap();
            table.revalidate(&plan).unwrap();

            let moved_store = fixture.root.join("store-moved");
            std::fs::rename(&fixture.store, &moved_store).unwrap();
            assert_boundary_outcome(&table, role, &plan, boundary, "store root swap");
            std::fs::rename(&moved_store, &fixture.store).unwrap();
            table.revalidate(&plan).unwrap();
        }
    }
}

/// Runs a closure in a forked child, reporting a panic or failure as an exit status.
/// Descriptors can be destroyed there without any effect on this test process.
fn in_child(body: impl FnOnce()) {
    // SAFETY: the child runs one closure and exits without returning here.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let code = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
        // SAFETY: never run the parent's destructors in the child.
        unsafe { libc::_exit(if code.is_ok() { 0 } else { 1 }) };
    }
    let mut status = 0;
    // SAFETY: status is writable and pid is this process's child.
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "child failed with status {status}"
    );
}

#[test]
fn exit5_descriptor_close_or_reuse_refuses_instead_of_falling_back_to_a_path() {
    for role in Role::ALL {
        let fixture = store();
        let table = fixture.table();
        let plan = table.vector();
        let approved = expected(&table, role);
        let fd = table.raw_fd(role).unwrap();
        let other = fixture.source.join(role.as_str());
        // A closed number, a number reused by another open file, and a number reused by
        // an identical copy at another inode. The object name stays intact and valid.
        in_child(|| {
            // SAFETY: closing this child's copy of a descriptor it owns.
            unsafe { libc::close(fd) };
            assert!(matches!(
                table.model_execute(&approved),
                Err(ExecutableError::Descriptor(_))
            ));
            assert!(table.revalidate(&plan).is_err());
        });
        in_child(|| {
            let file = File::open("/dev/null").unwrap();
            // SAFETY: replacing this child's copy of the descriptor number.
            unsafe { libc::dup2(file.as_raw_fd(), fd) };
            assert!(table.model_execute(&approved).is_err());
            assert!(table.revalidate(&plan).is_err());
        });
        in_child(|| {
            std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o555)).unwrap();
            let file = File::open(&other).unwrap();
            // SAFETY: replacing this child's copy of the descriptor number.
            unsafe { libc::dup2(file.as_raw_fd(), fd) };
            assert!(matches!(
                table.model_execute(&approved),
                Err(ExecutableError::Mismatch(_))
            ));
            assert!(table.revalidate(&plan).is_err());
        });
        // The parent's descriptors were untouched by any of that.
        table.model_execute(&approved).unwrap();
    }
}

#[test]
fn exit5_restart_reopens_only_the_exact_journal_tuple() {
    for role in Role::ALL {
        let fixture = store();
        let journal = fixture.table().vector();
        // An unchanged installation reopens.
        let reopened =
            ExecutableTable::reopen_exact(fixture.policy.clone(), &fixture.store, &journal)
                .unwrap();
        assert_eq!(reopened.vector(), journal);
        // Same bytes at a new inode cannot satisfy the old plan.
        let parked = replace_installed(&fixture, role, &fixture_bytes(role));
        let refused =
            ExecutableTable::reopen_exact(fixture.policy.clone(), &fixture.store, &journal)
                .unwrap_err();
        assert!(
            matches!(refused, ExecutableError::Mismatch(_)),
            "{refused:?}"
        );
        restore_installed(&fixture, role, &parked);
        // A stale generation in the journal is a different tuple too.
        let mut stale = journal.clone();
        stale
            .iter_mut()
            .find(|identity| identity.role == role)
            .unwrap()
            .installation_generation = 2;
        let table =
            ExecutableTable::reopen_exact(fixture.policy.clone(), &fixture.store, &stale).unwrap();
        assert!(table.revalidate(&journal).is_err());
        assert!(
            table
                .model_execute(
                    journal
                        .iter()
                        .find(|identity| identity.role == role)
                        .unwrap()
                )
                .is_err(),
            "a stale descriptor generation must not authorize dispatch"
        );
        // A vector field the journal changed never matches.
        let mut wrong = journal.clone();
        wrong
            .iter_mut()
            .find(|identity| identity.role == role)
            .unwrap()
            .st_ino += 1;
        assert!(
            ExecutableTable::reopen_exact(fixture.policy.clone(), &fixture.store, &wrong).is_err()
        );
    }
}

#[test]
fn exit5_every_fork_only_worker_records_the_inherited_helper_image() {
    let fixture = store();
    let table = fixture.table();
    let helper = expected(&table, Role::KilndHelper);
    // No separate worker image exists in the contract; each mode has this same tuple.
    let contract = crate::firecracker::contract();
    assert_eq!(
        contract["workers"]["separate_executables"],
        serde_json::json!([])
    );
    assert_eq!(
        contract["workers"]["fork_only"].as_array().unwrap().len(),
        WorkerMode::ALL.len()
    );
    for _mode in WorkerMode::ALL {
        assert_eq!(table.model_execute(&helper).unwrap().actual, helper);
    }
    let parked = replace_installed(
        &fixture,
        Role::KilndHelper,
        &fixture_bytes(Role::KilndHelper),
    );
    // A running worker keeps its image; a restart cannot adopt the replacement.
    assert_eq!(table.model_execute(&helper).unwrap().actual, helper);
    assert!(
        ExecutableTable::reopen_exact(fixture.policy.clone(), &fixture.store, &table.vector())
            .is_err()
    );
    restore_installed(&fixture, Role::KilndHelper, &parked);
}

#[test]
fn exit5_unsafe_ancestry_and_objects_are_refused_before_any_retained_table_exists() {
    let refuses = |fixture: &Store| {
        ExecutableTable::open(fixture.policy.clone(), &fixture.store, &all_pins()).is_err()
    };
    // Writable ancestors grant rename authority over everything below.
    for writable in [0o720, 0o702, 0o770, 0o777] {
        for depth in [0usize, 1, 2] {
            let fixture = store();
            let digest = pin_of(Role::Jailer).sha256.to_string();
            let target = match depth {
                0 => fixture.root.join("exec"),
                1 => fixture.store.clone(),
                _ => fixture.store.join(&digest),
            };
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(writable)).unwrap();
            assert!(refuses(&fixture), "{writable:o} at depth {depth}");
        }
    }
    // A symlink anywhere in the walk.
    let fixture = store();
    let digest = pin_of(Role::Jailer).sha256.to_string();
    let real = fixture.root.join("real-digest");
    std::fs::rename(fixture.store.join(&digest), &real).unwrap();
    symlink(&real, fixture.store.join(&digest)).unwrap();
    assert!(refuses(&fixture), "symlinked digest directory");
    let fixture = store();
    let object = fixture.object(Role::Jailer);
    let real = fixture.root.join("real-object");
    std::fs::rename(&object, &real).unwrap();
    symlink(&real, &object).unwrap();
    assert!(refuses(&fixture), "symlinked object");
    // A hardlink is a writable alias waiting to happen.
    let fixture = store();
    std::fs::hard_link(
        fixture.object(Role::Firecracker),
        fixture.root.join("alias"),
    )
    .unwrap();
    assert!(refuses(&fixture), "hardlinked object");
    // Wrong mode, including setuid and writable bits.
    for mode in [0o755, 0o575, 0o557, 0o4555, 0o2555, 0o500] {
        let fixture = store();
        std::fs::set_permissions(
            fixture.object(Role::MkfsXfs),
            std::fs::Permissions::from_mode(mode),
        )
        .unwrap();
        assert!(refuses(&fixture), "mode {mode:o}");
    }
    // Non-regular objects, with a FIFO that must not block the walk.
    let fixture = store();
    let object = fixture.object(Role::Jailer);
    std::fs::set_permissions(&object, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::remove_file(&object).unwrap();
    let name = CString::new(object.as_os_str().as_bytes()).unwrap();
    // SAFETY: name is NUL-terminated; this makes a test FIFO in a private directory.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o555) }, 0);
    assert!(refuses(&fixture), "FIFO object");
    let fixture = store();
    let object = fixture.object(Role::Jailer);
    std::fs::set_permissions(&object, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::remove_file(&object).unwrap();
    std::fs::create_dir(&object).unwrap();
    assert!(refuses(&fixture), "directory object");
    // A missing object is C0: Create cannot install or download it.
    let fixture = store();
    std::fs::remove_file(fixture.object(Role::Jailer)).unwrap();
    assert!(refuses(&fixture), "missing object");
    // Wrong size, wrong digest, and two roles aliased to one inode.
    let fixture = store();
    let mut wrong = all_pins();
    wrong[0].bytes += 1;
    assert!(ExecutableTable::open(fixture.policy.clone(), &fixture.store, &wrong).is_err());
    let mut wrong = all_pins();
    wrong[0].sha256 = Digest::of(b"other");
    assert!(ExecutableTable::open(fixture.policy.clone(), &fixture.store, &wrong).is_err());
    let duplicate = vec![all_pins()[0], all_pins()[0]];
    assert!(ExecutableTable::open(fixture.policy.clone(), &fixture.store, &duplicate).is_err());
    // Relative paths, escapes and paths outside the anchor never walk.
    let fixture = store();
    for path in ["relative/path", "/elsewhere"] {
        assert!(
            walk_directory(&fixture.policy, Path::new(path)).is_err(),
            "{path}"
        );
    }
    assert!(walk_directory(&fixture.policy, &fixture.store.join("..").join("exec")).is_err());
}

#[test]
fn exit5_production_policy_refuses_a_user_owned_tree_from_the_real_root() {
    // As a non-root user every Mac run hits this, and root still must not pass a tree
    // owned by another user. `/` itself is the first checked ancestor.
    let temp = tempfile::tempdir().unwrap();
    let inside = temp.path().canonicalize().unwrap();
    assert!(walk_directory(&WalkPolicy::production(), &inside).is_err());
}

fn elf_with_program_headers(entries: &[(u32, u64, u64)], payload: &[u8]) -> Vec<u8> {
    let mut image = vec![0u8; 64 + entries.len() * 56];
    image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    image[18..20].copy_from_slice(&183u16.to_le_bytes());
    image[32..40].copy_from_slice(&64u64.to_le_bytes());
    image[54..56].copy_from_slice(&56u16.to_le_bytes());
    image[56..58].copy_from_slice(&(entries.len() as u16).to_le_bytes());
    for (index, (kind, offset, size)) in entries.iter().enumerate() {
        let start = 64 + index * 56;
        image[start..start + 4].copy_from_slice(&kind.to_le_bytes());
        image[start + 8..start + 16].copy_from_slice(&offset.to_le_bytes());
        image[start + 32..start + 40].copy_from_slice(&size.to_le_bytes());
    }
    image.extend_from_slice(payload);
    image
}

#[test]
fn exit5_dynamic_closures_scripts_and_foreign_images_fail_closed() {
    let check = |bytes: &[u8]| {
        let mut file = tempfile::tempfile().unwrap();
        std::io::Write::write_all(&mut file, bytes).unwrap();
        check_static_elf(&file, bytes.len() as u64)
    };
    for role in Role::ALL {
        check(&fixture_bytes(role)).unwrap();
    }
    // PT_INTERP means an unbound loader; this revision approves no such closure.
    let interp = elf_with_program_headers(&[(3, 0, 0)], &[]);
    assert!(
        check(&interp)
            .unwrap_err()
            .to_string()
            .contains("PT_INTERP")
    );
    // Static-PIE is fine: PT_DYNAMIC with no DT_NEEDED.
    let dynamic_at = 64 + 56;
    let mut empty_dynamic = [0u8; 16];
    empty_dynamic[..8].copy_from_slice(&5u64.to_le_bytes());
    check(&elf_with_program_headers(
        &[(2, dynamic_at, 16)],
        &empty_dynamic,
    ))
    .unwrap();
    let mut needed = [0u8; 16];
    needed[..8].copy_from_slice(&1u64.to_le_bytes());
    let dynamic = elf_with_program_headers(&[(2, dynamic_at, 16)], &needed);
    assert!(
        check(&dynamic)
            .unwrap_err()
            .to_string()
            .contains("DT_NEEDED")
    );
    // Malformed headers refuse rather than being skipped.
    assert!(check(&elf_with_program_headers(&[(2, 1 << 40, 16)], &[])).is_err());
    assert!(check(&elf_with_program_headers(&[(2, dynamic_at, 15)], &[0; 15])).is_err());
    let mut outside = elf_with_program_headers(&[], &[]);
    outside[56..58].copy_from_slice(&1u16.to_le_bytes());
    outside[32..40].copy_from_slice(&(1u64 << 40).to_le_bytes());
    assert!(check(&outside).is_err());
    // Scripts, other architectures and truncations.
    assert!(check(b"#!/bin/sh\nexit 0\n").is_err());
    let mut x86 = elf_with_program_headers(&[], &[]);
    x86[18..20].copy_from_slice(&62u16.to_le_bytes());
    assert!(check(&x86).is_err());
    assert!(check(b"\x7fELF").is_err());
}

#[test]
fn exit5_publishing_never_replaces_and_a_lease_holder_keeps_its_exact_object() {
    let fixture = store();
    let pin = pin_of(Role::Jailer);
    let object = fixture.object(Role::Jailer);
    let before = std::fs::metadata(&object).unwrap().ino();
    // Republishing identical bytes verifies the existing object and leaves its inode.
    let source = File::open(fixture.source.join("jailer")).unwrap();
    publish_object(&fixture.policy, &fixture.store, &source, &pin).unwrap();
    assert_eq!(std::fs::metadata(&object).unwrap().ino(), before);
    // A mismatching source fails and changes nothing.
    let attacker = fixture.source.join("attacker");
    std::fs::write(&attacker, b"attacker").unwrap();
    let wrong = ExecutablePin {
        role: Role::Firecracker,
        bytes: 8,
        sha256: pin_of(Role::Firecracker).sha256,
        installation_generation: 1,
    };
    assert!(
        publish_object(
            &fixture.policy,
            &fixture.store,
            &File::open(&attacker).unwrap(),
            &wrong
        )
        .is_err()
    );
    let fresh = ExecutablePin {
        role: Role::Jailer,
        bytes: 8,
        sha256: Digest::of(b"different"),
        installation_generation: 2,
    };
    assert!(
        publish_object(
            &fixture.policy,
            &fixture.store,
            &File::open(&attacker).unwrap(),
            &fresh
        )
        .is_err()
    );
    assert!(
        !fixture
            .store
            .join(fresh.sha256.to_string())
            .join("jailer")
            .exists()
    );
    assert_eq!(std::fs::metadata(&object).unwrap().ino(), before);
    assert_eq!(std::fs::metadata(&object).unwrap().mode() & 0o7777, 0o555);
}

fn golden_record() -> serde_json::Value {
    let raw = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/firecracker/bootstrap.json"
    ))
    .unwrap();
    crate::firecracker::strict_json(&raw).unwrap()["record"].clone()
}

#[test]
fn exit5_bootstrap_record_is_the_frozen_bounded_canonical_message() {
    let golden = golden_record();
    let raw = crate::firecracker::canonical(&golden).unwrap();
    let record = BootstrapRecord::decode(&raw).unwrap();
    assert_eq!(record.encode().unwrap(), raw);
    assert_eq!(record.version, 1);
    // Construction from an identity gives the same exact-label record.
    let vmm = ExecutableIdentity {
        role: Role::Firecracker,
        st_dev: record.vmm_identity.st_dev,
        st_ino: record.vmm_identity.st_ino,
        bytes: record.vmm_identity.bytes,
        sha256: record.vmm_identity.sha256,
        installation_generation: 1,
    };
    assert_eq!(
        BootstrapRecord::for_vmm(record.plan_generation, &vmm, record.jail_root_identity),
        record
    );
    // Bound, version, extra fields and alternate encodings all refuse.
    assert!(BootstrapRecord::decode(&vec![b' '; MAX_BOOTSTRAP_BYTES + 1]).is_err());
    let mut wrong = golden.clone();
    wrong["version"] = serde_json::json!(2);
    assert!(BootstrapRecord::decode(&crate::firecracker::canonical(&wrong).unwrap()).is_err());
    let mut extra = golden.clone();
    extra["debug"] = serde_json::json!(true);
    assert!(BootstrapRecord::decode(&crate::firecracker::canonical(&extra).unwrap()).is_err());
    let mut spaced = raw.clone();
    spaced.push(b' ');
    assert!(BootstrapRecord::decode(&spaced).is_err());
}

fn descriptor_open(fd: RawFd) -> bool {
    // SAFETY: querying a descriptor number has no effect on it.
    unsafe { libc::fcntl(fd, libc::F_GETFD) >= 0 }
}

fn cloexec(fd: RawFd) -> bool {
    // SAFETY: querying a descriptor number has no effect on it.
    unsafe { libc::fcntl(fd, libc::F_GETFD) & libc::FD_CLOEXEC != 0 }
}

/// Runs `/bin/sh` from a forked child (a test-only path exec standing in for "J exec")
/// and reports which of FD 3 and 4 actually crossed that exec.
fn surviving_across_exec() -> (bool, bool) {
    let sh = c"/bin/sh";
    let script = c"(: <&3) 2>/dev/null && echo three; (: <&4) 2>/dev/null && echo four; true";
    let argv = [
        sh.as_ptr(),
        c"-c".as_ptr(),
        script.as_ptr(),
        std::ptr::null(),
    ];
    let env: [*const libc::c_char; 1] = [std::ptr::null()];
    let mut pipe_fds = [0; 2];
    // SAFETY: pipe_fds is writable.
    assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
    // SAFETY: the child only dup2s and execs.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        // SAFETY: async-signal-safe calls with live NUL-terminated argv/env arrays.
        unsafe {
            libc::dup2(pipe_fds[1], 1);
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
            libc::execve(sh.as_ptr(), argv.as_ptr(), env.as_ptr());
            libc::_exit(127);
        }
    }
    // SAFETY: closing this process's write end.
    unsafe { libc::close(pipe_fds[1]) };
    // SAFETY: the read end is owned from here on.
    let mut reader = unsafe { File::from_raw_fd(pipe_fds[0]) };
    let mut text = String::new();
    reader.read_to_string(&mut text).unwrap();
    let mut status = 0;
    // SAFETY: status is writable and pid is this process's child.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    (text.contains("three"), text.contains("four"))
}

#[test]
fn exit5_jailer_to_vmm_descriptor_boundary_is_exact_across_real_execs() {
    for role in [Role::Jailer] {
        let fixture = store();
        let table = fixture.table();
        let vmm = expected(&table, Role::Firecracker);
        let record = BootstrapRecord::for_vmm(
            7,
            &vmm,
            JailRootIdentity {
                mount_id: 1,
                st_dev: 2,
                st_ino: 3,
            },
        );
        let vmm_fd = table.raw_fd(Role::Firecracker).unwrap();
        let jailer_fd = table.raw_fd(role).unwrap();
        // Also the awkward arrangements: inputs already sitting on 3 and 4, crossed.
        for shuffle in [false, true] {
            let table = &table;
            let record = record.clone();
            in_child(move || {
                // Raw from here: the arrangement closes everything else out from under
                // any owner, and this child exits without running destructors.
                let (control, peer) = std::os::unix::net::UnixStream::pair().unwrap();
                let control = control.into_raw_fd();
                let _ = peer.into_raw_fd();
                let (mut vmm_in, mut control_in, mut jailer_in) = (vmm_fd, control, jailer_fd);
                if shuffle {
                    // SAFETY: placing this child's descriptors at the crossed numbers.
                    unsafe {
                        let high_vmm = libc::fcntl(vmm_fd, libc::F_DUPFD_CLOEXEC, 100);
                        let high_control = libc::fcntl(control, libc::F_DUPFD_CLOEXEC, 100);
                        let high_jailer = libc::fcntl(jailer_fd, libc::F_DUPFD_CLOEXEC, 100);
                        libc::dup2(high_control, 3);
                        libc::dup2(high_vmm, 4);
                        libc::dup2(high_jailer, 5);
                        (vmm_in, control_in, jailer_in) = (4, 3, 5);
                    }
                }
                let stray = File::open("/dev/null").unwrap().into_raw_fd();
                // Before J exec: exact numbers and flags, and nothing else stays open.
                let j = arrange_bootstrap_fds(jailer_in, vmm_in, control_in).unwrap();
                assert!(j >= JAILER_EXEC_FD_MIN);
                assert!(cloexec(j), "J exec descriptor must close on its own exec");
                assert!(!cloexec(VMM_FD) && !cloexec(CONTROL_FD));
                if stray != j && stray > CONTROL_FD {
                    assert!(!descriptor_open(stray), "unexpected descriptor crossed");
                }
                for fd in CONTROL_FD + 1..256 {
                    if fd != j {
                        assert!(!descriptor_open(fd), "unexpected descriptor {fd}");
                    }
                }
                // SAFETY: fstat writes into live storage.
                let mut stat: libc::stat = unsafe { std::mem::zeroed() };
                assert_eq!(unsafe { libc::fstat(VMM_FD, &mut stat) }, 0);
                assert_eq!(
                    stat.st_ino,
                    table.identity(Role::Firecracker).unwrap().st_ino
                );
                // A real exec keeps exactly FD 3 and 4.
                assert_eq!(surviving_across_exec(), (true, true));
                // J's entry validates them and arranges their closure at V's exec.
                jailer_entry(&record).unwrap();
                assert!(cloexec(VMM_FD) && cloexec(CONTROL_FD));
                assert_eq!(surviving_across_exec(), (false, false));
            });
        }
    }
}

#[test]
fn exit5_jailer_entry_refuses_a_wrong_or_missing_bootstrap_descriptor() {
    let fixture = store();
    let table = fixture.table();
    let vmm = expected(&table, Role::Firecracker);
    let jail = JailRootIdentity {
        mount_id: 1,
        st_dev: 2,
        st_ino: 3,
    };
    let good = BootstrapRecord::for_vmm(1, &vmm, jail);
    let vmm_fd = table.raw_fd(Role::Firecracker).unwrap();
    let jailer_fd = table.raw_fd(Role::Jailer).unwrap();
    let arrange = move || {
        let (control, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let _ = peer.into_raw_fd();
        arrange_bootstrap_fds(jailer_fd, vmm_fd, control.into_raw_fd()).unwrap();
    };
    in_child(|| {
        arrange();
        let mut wrong = good.clone();
        wrong.vmm_identity.st_ino += 1;
        assert!(matches!(
            jailer_entry(&wrong),
            Err(ExecutableError::Mismatch(_))
        ));
    });
    in_child(|| {
        arrange();
        let mut wrong = good.clone();
        wrong.vmm_identity.bytes += 1;
        assert!(matches!(
            jailer_entry(&wrong),
            Err(ExecutableError::Mismatch(_))
        ));
    });
    in_child(|| {
        arrange();
        let mut wrong = good.clone();
        wrong.vmm_identity.sha256 = Digest::of(b"other");
        assert!(matches!(
            jailer_entry(&wrong),
            Err(ExecutableError::Mismatch(_))
        ));
    });
    // FD 3 opened writable, or a non-socket at FD 4.
    in_child(|| {
        arrange();
        // SAFETY: closing this child's descriptor number.
        unsafe { libc::close(VMM_FD) };
        assert!(jailer_entry(&good).is_err());
    });
    in_child(|| {
        arrange();
        let file = File::open("/dev/null").unwrap().into_raw_fd();
        // SAFETY: replacing this child's descriptor number.
        unsafe { libc::dup2(file, CONTROL_FD) };
        assert!(jailer_entry(&good).is_err());
    });
    // Arranging itself refuses a writable V descriptor.
    in_child(|| {
        let path = fixture.source.join("writable");
        let writable = File::create(path).unwrap().into_raw_fd();
        let (control, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let _ = peer.into_raw_fd();
        assert!(arrange_bootstrap_fds(jailer_fd, writable, control.into_raw_fd()).is_err());
    });
}

// Privileged Linux evidence, run by hand in the VM: `sudo <test-binary> --ignored
// --exact <name>`. Real traversal from `/`, real ACLs and caps, real `execveat`, and
// `/proc/<pid>/exe` tuples compared with the expected journal tuple.
#[cfg(target_os = "linux")]
mod linux_root {
    use super::*;
    use std::os::unix::fs::chown;

    const PROBE_ENV: &str = "KILND_B3_PROBE";

    struct RootTree {
        root: PathBuf,
    }

    impl Drop for RootTree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn root_tree(name: &str) -> RootTree {
        assert_eq!(unsafe { libc::geteuid() }, 0, "run this test as root");
        let root = PathBuf::from(format!("/var/lib/kilnd-b3-{name}-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        RootTree { root }
    }

    fn install(root: &Path, digest: &str, name: &str, bytes: &[u8]) -> PathBuf {
        let directory = root.join("sha256").join(digest);
        std::fs::create_dir_all(&directory).unwrap();
        for path in [root.join("sha256"), directory.clone()] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = directory.join(name);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o555)).unwrap();
        path
    }

    #[test]
    #[ignore = "needs root on Linux: run in the VM"]
    fn exit5_linux_root_protected_traversal_from_slash_checks_owner_mode_acl_caps_links() {
        let tree = root_tree("walk");
        let policy = WalkPolicy::production();
        let bytes = fixture_bytes(Role::Jailer);
        let digest = Digest::of(&bytes).to_string();
        let object = install(&tree.root, &digest, "jailer", &bytes);
        let store = tree.root.join("sha256");
        let pin = pin_of(Role::Jailer);
        let open = || ExecutableTable::open(policy.clone(), &store, &[pin]);
        let table = open().expect("a root-owned tree passes the real walk");
        let identity = table.identity(Role::Jailer).unwrap();
        assert_eq!(identity.st_ino, std::fs::metadata(&object).unwrap().ino());
        // Non-root ownership anywhere fails.
        chown(&object, Some(65534), None).unwrap();
        assert!(open().is_err());
        chown(&object, Some(0), None).unwrap();
        chown(store.join(&digest), Some(65534), None).unwrap();
        assert!(open().is_err());
        chown(store.join(&digest), Some(0), None).unwrap();
        // A group-writable ancestor fails.
        std::fs::set_permissions(&tree.root, std::fs::Permissions::from_mode(0o720)).unwrap();
        assert!(open().is_err());
        std::fs::set_permissions(&tree.root, std::fs::Permissions::from_mode(0o700)).unwrap();
        // A file capability and an extended ACL xattr fail.
        let name = CString::new(object.as_os_str().as_bytes()).unwrap();
        let capability = [1u8, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        // SAFETY: path, name and value are live for the call.
        let set = unsafe {
            libc::setxattr(
                name.as_ptr(),
                c"security.capability".as_ptr(),
                capability.as_ptr().cast(),
                capability.len(),
                0,
            )
        };
        assert_eq!(set, 0, "capability fixture: {}", io::Error::last_os_error());
        assert!(open().is_err(), "a file capability must refuse");
        // SAFETY: path and name are live.
        assert_eq!(unsafe { libc::removexattr(name.as_ptr(), c"security.capability".as_ptr()) }, 0);
        open().expect("removing the capability restores the positive control");
        // user:nobody:rwx on the digest directory, in the kernel's xattr format.
        let directory = CString::new(store.join(&digest).as_os_str().as_bytes()).unwrap();
        let mut acl: Vec<u8> = 2u32.to_le_bytes().to_vec();
        for (tag, perm, id) in [
            (0x01u16, 7u16, u32::MAX),
            (0x02, 7, 65534),
            (0x04, 5, u32::MAX),
            (0x10, 7, u32::MAX),
            (0x20, 5, u32::MAX),
        ] {
            acl.extend_from_slice(&tag.to_le_bytes());
            acl.extend_from_slice(&perm.to_le_bytes());
            acl.extend_from_slice(&id.to_le_bytes());
        }
        // SAFETY: path, name and value are live for the call.
        let set = unsafe {
            libc::setxattr(
                directory.as_ptr(),
                c"system.posix_acl_access".as_ptr(),
                acl.as_ptr().cast(),
                acl.len(),
                0,
            )
        };
        assert_eq!(set, 0, "ACL fixture: {}", io::Error::last_os_error());
        assert!(open().is_err(), "an extended ACL must refuse");
        // SAFETY: path and name are live.
        assert_eq!(unsafe { libc::removexattr(directory.as_ptr(), c"system.posix_acl_access".as_ptr()) }, 0);
        // Linux projects the ACL mask into mode bits, and removing the xattr does
        // not restore those bits. Restore the mode before the next independent case.
        std::fs::set_permissions(store.join(&digest), std::fs::Permissions::from_mode(0o700)).unwrap();
        open().expect("removing the ACL and restoring mode restores the positive control");
        // A symlink ancestor fails.
        let moved = tree.root.join("moved");
        std::fs::rename(&store, &moved).unwrap();
        symlink(&moved, &store).unwrap();
        assert!(open().is_err());
        std::fs::remove_file(&store).unwrap();
        std::fs::rename(&moved, &store).unwrap();
        open().expect("restored tree");
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug)]
    struct Report {
        stage: String,
        exe: ExecutableIdentity,
        fd3_open_at_entry: bool,
        fd4_open_at_entry: bool,
    }

    /// The fixture image's two stages: re-exec'd from retained descriptors only. It is
    /// the test binary itself, so `kiln` and `kilnd` code is exercised from a real exec.
    #[test]
    #[ignore = "exec target of exit5_linux_root_execveat_chain_runs_only_the_retained_inodes"]
    fn linux_probe_child() {
        let Ok(stage) = std::env::var(PROBE_ENV) else {
            return;
        };
        // Read FD flags before anything in this process could open a descriptor.
        let (fd3_open, fd4_open) = (descriptor_open(VMM_FD), descriptor_open(CONTROL_FD));
        let report_dir = PathBuf::from(std::env::var("KILND_B3_REPORT").unwrap());
        let me = unsafe { libc::getpid() };
        let exe = observe_process_image(me, Role::Jailer, 1).unwrap();
        std::fs::write(
            report_dir.join(&stage),
            serde_json::to_vec(&Report {
                stage: stage.clone(),
                exe,
                fd3_open_at_entry: fd3_open,
                fd4_open_at_entry: fd4_open,
            })
            .unwrap(),
        )
        .unwrap();
        if stage == "jailer" {
            let record = std::fs::read(report_dir.join("record")).unwrap();
            let record = BootstrapRecord::decode(&record).unwrap();
            jailer_entry(&record).unwrap();
            let argv: Vec<CString> = [
                "/firecracker",
                "--exact",
                "helper::firecracker::executable::tests::linux_root::linux_probe_child",
                "--ignored",
                "--nocapture",
            ]
            .iter()
            .map(|arg| CString::new(*arg).unwrap())
            .collect();
            let env: Vec<CString> = [
                format!("{PROBE_ENV}=vmm"),
                format!("KILND_B3_REPORT={}", report_dir.display()),
            ]
            .iter()
            .map(|arg| CString::new(arg.as_str()).unwrap())
            .collect();
            let error = exec_retained(VMM_FD, &argv, &env);
            panic!("execveat of FD 3 failed: {error}");
        }
    }

    #[test]
    #[ignore = "needs root on Linux: run in the VM"]
    fn exit5_linux_root_execveat_chain_runs_only_the_retained_inodes() {
        let tree = root_tree("exec");
        let image = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let digest = Digest::of(&image).to_string();
        let jailer_path = install(&tree.root, &digest, "jailer", &image);
        let vmm_path = install(&tree.root, &digest, "firecracker", &image);
        let open = |path: &Path| {
            let name = CString::new(path.as_os_str().as_bytes()).unwrap();
            // SAFETY: name is NUL-terminated; the flags are the contract's.
            let fd = unsafe {
                libc::open(
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            assert!(fd >= 0);
            // SAFETY: open returned a new owned descriptor.
            unsafe { File::from_raw_fd(fd) }
        };
        let jailer = open(&jailer_path);
        let vmm = open(&vmm_path);
        let identity = |file: &File, role| {
            let meta = file.metadata().unwrap();
            ExecutableIdentity {
                role,
                st_dev: meta.dev(),
                st_ino: meta.ino(),
                bytes: meta.len(),
                sha256: hash_descriptor(file, meta.len()).unwrap(),
                installation_generation: 1,
            }
        };
        let expected_jailer = identity(&jailer, Role::Jailer);
        let expected_vmm = identity(&vmm, Role::Firecracker);
        let reports = tree.root.join("reports");
        std::fs::create_dir(&reports).unwrap();
        let record = BootstrapRecord::for_vmm(
            1,
            &expected_vmm,
            JailRootIdentity {
                mount_id: 1,
                st_dev: 2,
                st_ino: 3,
            },
        );
        std::fs::write(reports.join("record"), record.encode().unwrap()).unwrap();

        // The race: after hashing and before exec, both installed names and their whole
        // parent are replaced, with another image, by anyone able to rename them.
        let parked = tree.root.join("parked");
        std::fs::rename(tree.root.join("sha256"), &parked).unwrap();
        install(&tree.root, &digest, "jailer", b"#!/bin/sh\nexit 66\n");
        install(&tree.root, &digest, "firecracker", b"#!/bin/sh\nexit 66\n");

        let (control, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let (jailer_raw, vmm_raw, control_raw) =
            (jailer.as_raw_fd(), vmm.as_raw_fd(), control.as_raw_fd());
        let argv: Vec<CString> = [
            jailer_path.to_str().unwrap(),
            "--exact",
            "helper::firecracker::executable::tests::linux_root::linux_probe_child",
            "--ignored",
            "--nocapture",
        ]
        .iter()
        .map(|arg| CString::new(*arg).unwrap())
        .collect();
        let env: Vec<CString> = [
            format!("{PROBE_ENV}=jailer"),
            format!("KILND_B3_REPORT={}", reports.display()),
        ]
        .iter()
        .map(|arg| CString::new(arg.as_str()).unwrap())
        .collect();
        // SAFETY: the child only arranges descriptors and execs.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let j = arrange_bootstrap_fds(jailer_raw, vmm_raw, control_raw).unwrap();
            let _ = exec_retained(j, &argv, &env);
            // SAFETY: exec failed; leave without running the parent's destructors.
            unsafe { libc::_exit(66) };
        }
        let mut status = 0;
        // SAFETY: status is writable and pid is this process's child.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "{status}"
        );
        let read = |name: &str| -> Report {
            serde_json::from_slice(&std::fs::read(reports.join(name)).unwrap()).unwrap()
        };
        let jailer_report = read("jailer");
        let vmm_report = read("vmm");
        // The tuple that actually ran, device and inode and digest, equals the journal's.
        assert_eq!(jailer_report.exe.st_dev, expected_jailer.st_dev);
        assert_eq!(jailer_report.exe.st_ino, expected_jailer.st_ino);
        assert_eq!(jailer_report.exe.sha256, expected_jailer.sha256);
        assert_eq!(jailer_report.exe.bytes, expected_jailer.bytes);
        assert_eq!(vmm_report.exe.st_dev, expected_vmm.st_dev);
        assert_eq!(vmm_report.exe.st_ino, expected_vmm.st_ino);
        assert_eq!(vmm_report.exe.sha256, expected_vmm.sha256);
        // J got exactly the two bootstrap descriptors; V got neither.
        assert!(jailer_report.fd3_open_at_entry && jailer_report.fd4_open_at_entry);
        assert!(!vmm_report.fd3_open_at_entry, "FD 3 survived V's exec");
        assert!(!vmm_report.fd4_open_at_entry, "FD 4 survived V's exec");
        drop(parked);
    }

    #[test]
    #[ignore = "needs root on Linux: run in the VM"]
    fn exit5_linux_root_self_image_check_compares_the_running_tuple() {
        let tree = root_tree("self");
        let bytes = fixture_bytes(Role::KilndHelper);
        let digest = Digest::of(&bytes).to_string();
        install(&tree.root, &digest, "kilnd-helper", &bytes);
        let table = ExecutableTable::open(
            WalkPolicy::production(),
            &tree.root.join("sha256"),
            &[pin_of(Role::KilndHelper)],
        )
        .unwrap();
        // This process is not the installed helper, whatever its bytes or name.
        assert!(matches!(
            verify_self_image(&table),
            Err(ExecutableError::Mismatch(_))
        ));
    }
}
