//! Checkpoint milestone C6b: the hostile-content set and the two-uid hostile callers
//! (design 11.2 items 2–5), through kilnd's capture and fork on the installed kiln.
//! Root only, on the prepared VM; run by `scripts/checkpoint-crash-matrix.py --set
//! hostile`.
//!
//! Each case builds its tree in a fresh source sandbox: from inside, as the sandbox's
//! own user, or, for what an unprivileged sandbox user cannot make (sockets, device
//! nodes, ACLs, file capabilities, overlay and `security.*` xattrs, protected paths),
//! planted by root in the run's raw upper with the sandbox's own owner, standing in for
//! an escaped process or a hostile operator. Then it captures and asserts one of:
//!
//! - **refused**: a typed `checkpoint_*` refusal, the node's charge back where it was,
//!   no artifact or staging left, any row FAILED; or
//! - **round trip**: READY, and a fork whose tree (types, modes, owners, sizes, link
//!   counts, link targets, file digests and file mtimes) equals the source's, and whose
//!   real commands print the same.
//!
//! Around every case: a host sentinel's content, inode and mtime and another uid's
//! sandbox stay unchanged.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use super::harness::*;

fn run<F: std::future::Future<Output = ()>>(f: F) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f);
}

/// The second unprivileged caller, in the same socket group.
const STRANGER: u32 = 1001;

const SENTINEL: &str = "/var/tmp/kilnd-c6b-sentinel";

/// What a case may end as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    RoundTrip,
    Refused(&'static str),
    /// The format allows either; the case records which and checks its invariant.
    Either,
}

/// Root's plant in the raw upper, given its path and the sandbox's owner.
type Plant = Box<dyn FnOnce(&Path, (u32, u32))>;

fn no_plant() -> Plant {
    Box::new(|_, _| {})
}

/// The tree a comparison covers: `/root/w`, and for a read-only root `/workspace`.
const LISTING: &str = "for p in /root/w /workspace; do [ -e \"$p\" ] || [ -L \"$p\" ] || continue; \
    find \"$p\" -xdev | LC_ALL=C sort | while IFS= read -r f; do \
      t=$(stat -c '%F' \"$f\"); \
      if [ \"$t\" = directory ]; then stat -c '%n|%F|%a|%u|%g' \"$f\"; \
      else stat -c '%n|%F|%a|%u|%g|%s|%h|%y' \"$f\"; fi; \
      [ -L \"$f\" ] && printf 'link %s\\n' \"$(readlink \"$f\")\"; \
      [ -f \"$f\" ] && [ ! -L \"$f\" ] && sha256sum < \"$f\"; \
    done; done";

/// A command whose output the fork must reproduce.
const BEHAVIOR: &str = "cd /root/w 2>/dev/null && (ls -la; for f in *; do [ -f \"$f\" ] && head -c 64 \"$f\"; echo; done) 2>&1 | sed 's/ [A-Z][a-z][a-z] [ 0-9][0-9] [0-9:]* / /'";

/// Root's check of the fork's raw upper (what the sandbox's own tools cannot show).
type ForkCheck = Box<dyn FnOnce(&Path) -> Value>;

struct Case {
    name: &'static str,
    inside: String,
    plant: Plant,
    expect: Expect,
    disk_bytes: u64,
    listing: &'static str,
    fork_check: Option<ForkCheck>,
}

fn case(name: &'static str, inside: &str, expect: Expect) -> Case {
    Case {
        name,
        inside: inside.into(),
        plant: no_plant(),
        expect,
        disk_bytes: 0,
        listing: LISTING,
        fork_check: None,
    }
}

/// A cheap comparison for trees of many entries: the count and the sorted names.
const COUNT_LISTING: &str = "find /root/w -xdev | wc -l; find /root/w -xdev | LC_ALL=C sort | sha256sum";

fn many(mut c: Case) -> Case {
    c.listing = COUNT_LISTING;
    c
}

fn with_fork_check(mut c: Case, check: ForkCheck) -> Case {
    c.fork_check = Some(check);
    c
}

fn get_xattr(path: &Path, name: &str) -> Option<Vec<u8>> {
    let p = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let n = std::ffi::CString::new(name).unwrap();
    let mut buf = vec![0u8; 65536];
    // SAFETY: live C strings and buffer.
    let rc = unsafe { libc::lgetxattr(p.as_ptr(), n.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    (rc >= 0).then(|| {
        buf.truncate(rc as usize);
        buf
    })
}

fn planted(name: &'static str, inside: &str, plant: Plant, expect: Expect) -> Case {
    Case {
        plant,
        ..case(name, inside, expect)
    }
}

/// The run's raw upper directory, found by a marker file the sandbox wrote: the copy
/// on the runs filesystem itself, not the overlay view of it.
fn upper_of(backend_id: &str) -> PathBuf {
    let run = PathBuf::from(format!("{}/{backend_id}", super::RUNS));
    let runs_dev = std::fs::metadata(super::RUNS).unwrap().dev();
    let mut stack = vec![(run.clone(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.filter_map(Result::ok) {
            let path = e.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.dev() != runs_dev {
                continue;
            }
            if path.ends_with("root/c6b-marker") && meta.is_file() {
                return path.parent().unwrap().parent().unwrap().to_path_buf();
            }
            if meta.is_dir() && depth < 3 {
                stack.push((path, depth + 1));
            }
        }
    }
    panic!("no raw upper with the marker under {}", run.display());
}

fn set_xattr(path: &Path, name: &str, value: &[u8]) {
    let p = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let n = std::ffi::CString::new(name).unwrap();
    // SAFETY: live C strings and buffer.
    let rc = unsafe {
        libc::lsetxattr(
            p.as_ptr(),
            n.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    assert_eq!(rc, 0, "setxattr {name} on {}: {}", path.display(), std::io::Error::last_os_error());
}

fn chown(path: &Path, owner: (u32, u32)) {
    std::os::unix::fs::lchown(path, Some(owner.0), Some(owner.1)).unwrap();
}

/// A file capability: VFS_CAP_REVISION_2 with cap_net_raw permitted.
fn capability() -> Vec<u8> {
    let mut v = vec![0u8; 20];
    v[..4].copy_from_slice(&0x0200_0000u32.to_le_bytes());
    v[4..8].copy_from_slice(&(1u32 << 13).to_le_bytes());
    v
}

/// A POSIX access ACL granting uid 4242 read (`system.posix_acl_access`, version 2).
fn acl(owner_uid: u32) -> Vec<u8> {
    let mut v = 2u32.to_le_bytes().to_vec();
    for (tag, perm, id) in [
        (0x01u16, 6u16, u32::MAX),
        (0x02, 4, owner_uid + 4242),
        (0x04, 4, u32::MAX),
        (0x10, 4, u32::MAX),
        (0x20, 4, u32::MAX),
    ] {
        v.extend_from_slice(&tag.to_le_bytes());
        v.extend_from_slice(&perm.to_le_bytes());
        v.extend_from_slice(&id.to_le_bytes());
    }
    v
}

struct Bystanders {
    sentinel: (Vec<u8>, u64, i64, i64),
    stranger: String,
}

fn sentinel_state() -> (Vec<u8>, u64, i64, i64) {
    let m = std::fs::metadata(SENTINEL).unwrap();
    (std::fs::read(SENTINEL).unwrap(), m.ino(), m.mtime(), m.mtime_nsec())
}

async fn bystanders(w: &World) -> Bystanders {
    std::fs::write(SENTINEL, b"host sentinel\n").unwrap();
    let s = w
        .rpc(STRANGER, json!({ "op": "create" }))
        .await;
    let stranger = ok(&s)["id"].as_str().unwrap().to_string();
    let r = w
        .rpc(
            STRANGER,
            json!({ "op": "exec", "id": stranger, "script": "mkdir -p /root/w && printf mine > /root/w/a" }),
        )
        .await;
    assert_eq!(ok(&r)["exit_code"], 0, "{r}");
    Bystanders {
        sentinel: sentinel_state(),
        stranger,
    }
}

impl Bystanders {
    async fn unchanged(&self, w: &World, after: &str) {
        assert_eq!(sentinel_state(), self.sentinel, "the host sentinel changed after {after}");
        let r = w
            .rpc(STRANGER, json!({ "op": "exec", "id": self.stranger, "script": "cat /root/w/a" }))
            .await;
        assert_eq!(ok(&r)["stdout"], "mine", "the other uid's sandbox changed after {after}: {r}");
    }

    async fn finish(self, w: &World) {
        w.rpc(STRANGER, json!({ "op": "delete", "id": self.stranger })).await;
        let _ = std::fs::remove_file(SENTINEL);
    }
}

/// The raw upper and the sandbox's owner of a running sandbox, by a marker file it
/// writes and then removes from inside (root never edits a mounted upper's view).
async fn locate(w: &World, id: &str, backend_id: &str) -> (PathBuf, (u32, u32)) {
    w.sh(id, "mkdir -p /root/w && touch /root/c6b-marker").await;
    let upper = upper_of(backend_id);
    let m = std::fs::symlink_metadata(upper.join("root/c6b-marker")).unwrap();
    w.sh(id, "rm -f /root/c6b-marker").await;
    (upper, (m.uid(), m.gid()))
}

/// One case end to end; its matrix entry.
async fn check(w: &World, by: &Bystanders, c: Case) -> Value {
    let s = w.ok(json!({ "op": "create", "disk_bytes": c.disk_bytes })).await;
    let src = s["id"].as_str().unwrap().to_string();
    let (upper, owner) = locate(w, &src, s["backend_id"].as_str().unwrap()).await;
    if !c.inside.is_empty() {
        let r = w.ok(json!({ "op": "exec", "id": src, "script": c.inside, "timeout_ms": 600_000 })).await;
        assert_eq!(r["exit_code"], 0, "{}: setup failed: {r}", c.name);
    }
    (c.plant)(&upper, owner);
    let before = w.charge();
    let listing = w.sh(&src, c.listing).await["stdout"].clone();
    let behavior = w.ok(json!({ "op": "exec", "id": src, "script": BEHAVIOR })).await["stdout"].clone();
    let r = w
        .rpc(
            OWNER,
            json!({ "op": "capture", "id": src, "request_id": format!("h-{}", c.name), "lifetime_ms": 3_600_000 }),
        )
        .await;
    let outcome = if let Some(e) = r.get("error") {
        let reason = e["reason"].as_str().unwrap().to_string();
        assert!(reason.starts_with("checkpoint_"), "{}: untyped refusal {r}", c.name);
        w.until("the refusal settled", 120, |w| {
            w.rows().iter().all(|(_, s)| s != "capturing" && s != "deleting")
        })
        .await;
        assert_eq!(w.charge(), before, "{}: charge left by a refusal", c.name);
        assert!(
            !w.artifacts().iter().any(|n| n.starts_with("cp-") || n.starts_with(".staging")),
            "{}: artifact left: {:?}",
            c.name,
            w.artifacts()
        );
        json!({ "refused": reason, "row": w.rows().iter().any(|(id, _)| {
            w.cp_col(id, "request_id") == format!("h-{}", c.name)
        }) })
    } else {
        let cp = r["ok"]["id"].as_str().unwrap().to_string();
        assert_eq!(r["ok"]["state"], "CHECKPOINT_STATE_READY", "{}: {r}", c.name);
        let f = w
            .ok(json!({ "op": "create", "from_checkpoint": cp, "disk_bytes": c.disk_bytes }))
            .await;
        let fid = f["id"].as_str().unwrap().to_string();
        let fork_listing = w.sh(&fid, c.listing).await["stdout"].clone();
        let fork_behavior = w.ok(json!({ "op": "exec", "id": fid, "script": BEHAVIOR })).await["stdout"].clone();
        assert_eq!(fork_listing, listing, "{}: the fork's tree differs", c.name);
        assert_eq!(fork_behavior, behavior, "{}: the fork behaves differently", c.name);
        let checked = match c.fork_check {
            Some(check) => {
                let (fork_upper, _) = locate(w, &fid, f["backend_id"].as_str().unwrap()).await;
                check(&fork_upper)
            }
            None => Value::Null,
        };
        w.ok(json!({ "op": "delete", "id": fid })).await;
        let d = w.ok(json!({ "op": "delete_checkpoint", "id": cp })).await;
        assert_eq!(d["state"], "CHECKPOINT_STATE_DELETED", "{d}");
        json!({ "round_trip": true, "size_bytes": r["ok"]["size_bytes"],
                "entries": w.cp_col(&cp, "entry_count"), "fork_upper": checked })
    };
    match c.expect {
        Expect::RoundTrip => assert!(outcome.get("round_trip").is_some(), "{}: {outcome}", c.name),
        Expect::Refused(token) => assert_eq!(outcome["refused"], token, "{}: {outcome}", c.name),
        Expect::Either => {}
    }
    w.ok(json!({ "op": "delete", "id": src })).await;
    by.unchanged(w, c.name).await;
    eprintln!("C6B hostile {}: {outcome}", c.name);
    json!({ "case": c.name, "expect": format!("{:?}", c.expect), "outcome": outcome })
}

async fn run_cases(set: &str, cases: Vec<Case>) {
    let w = World::start(json!({})).await;
    let by = bystanders(&w).await;
    let mut results = Vec::new();
    for c in cases {
        results.push(check(&w, &by, c).await);
    }
    by.finish(&w).await;
    matrix(set, Value::Array(results));
    w.finish().await;
}

#[test]
#[ignore = "root on the prepared VM: C6b hostile content"]
fn c6b_hostile_links_and_roots_are_refused_or_round_trip() {
    use Expect::*;
    run(run_cases(
        "hostile links and roots",
        vec![
            case("symlink-parent", "mkdir -p /root/w/real && printf p > /root/w/real/f && ln -s real /root/w/link && cat /root/w/link/f", RoundTrip),
            case("absolute-targets", &format!("ln -s /etc/passwd /root/w/abs && ln -s {SENTINEL} /root/w/host && ln -s / /root/w/root"), RoundTrip),
            case("dot-dot-targets", "ln -s ../../../../../../../etc/shadow /root/w/up && ln -s .. /root/w/parent", RoundTrip),
            case("symlink-cycle", "ln -s b /root/w/a2 && ln -s a2 /root/w/b", RoundTrip),
            case("hardlink-chain", "printf h > /root/w/h1 && ln /root/w/h1 /root/w/h2 && ln /root/w/h2 /root/w/h3", RoundTrip),
            case("hardlink-to-image-file", "ln /etc/hostname /root/w/hn", Either),
            case("duplicate-looking-names", "printf 1 > '/root/w/a b' && printf 2 > '/root/w/a\tb' && printf 3 > /root/w/.a", RoundTrip),
            case("long-link-target", "ln -s $(head -c 1023 /dev/zero | tr '\\0' x) /root/w/l1023", RoundTrip),
            case("over-long-link-target", "ln -s $(head -c 1024 /dev/zero | tr '\\0' x) /root/w/l1024", Either),
            planted(
                "hardlinked-symlink",
                "ln -s target /root/w/sl",
                Box::new(|u: &Path, _| std::fs::hard_link(u.join("root/w/sl"), u.join("root/w/sl2")).unwrap()),
                Refused("checkpoint_metadata_unsupported"),
            ),
            case("scratch-root-replaced-by-a-symlink", "mv /root/w /tmp/w && cd / && rm -rf /root && ln -s /tmp /root && ls /root/w", Either),
            planted(
                "host-root-owned-file",
                "",
                Box::new(|u: &Path, _| std::fs::write(u.join("root/w/rootowned"), b"x").unwrap()),
                Refused("checkpoint_metadata_unsupported"),
            ),
        ],
    ));
}

#[test]
#[ignore = "root on the prepared VM: C6b hostile content"]
fn c6b_hostile_special_files_and_metadata_are_refused_before_allocation() {
    use Expect::*;
    let meta = Refused("checkpoint_metadata_unsupported");
    run(run_cases(
        "hostile special files and metadata",
        vec![
            case("fifo", "mkfifo /root/w/fifo", meta),
            planted("unix-socket", "", Box::new(|u: &Path, o| {
                let p = u.join("root/w/sock");
                drop(std::os::unix::net::UnixListener::bind(&p).unwrap());
                chown(&p, o);
            }), meta),
            planted("char-device", "", Box::new(|u: &Path, o| {
                let p = u.join("root/w/null");
                let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
                // SAFETY: a live path; makedev(1, 3) is /dev/null's number.
                assert_eq!(unsafe { libc::mknod(c.as_ptr(), libc::S_IFCHR | 0o600, libc::makedev(1, 3)) }, 0);
                chown(&p, o);
            }), meta),
            planted("block-device", "", Box::new(|u: &Path, o| {
                let p = u.join("root/w/blk");
                let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
                // SAFETY: a live path; makedev(7, 0) is loop0's number.
                assert_eq!(unsafe { libc::mknod(c.as_ptr(), libc::S_IFBLK | 0o600, libc::makedev(7, 0)) }, 0);
                chown(&p, o);
            }), meta),
            planted("posix-acl", "printf a > /root/w/f", Box::new(|u: &Path, o| {
                set_xattr(&u.join("root/w/f"), "system.posix_acl_access", &acl(o.0));
            }), meta),
            planted("file-capability", "printf a > /root/w/f", Box::new(|u: &Path, _| {
                set_xattr(&u.join("root/w/f"), "security.capability", &capability());
            }), meta),
            planted("security-xattr", "printf a > /root/w/f", Box::new(|u: &Path, _| {
                set_xattr(&u.join("root/w/f"), "security.c6b", b"x");
            }), meta),
            with_fork_check(planted("user-xattr", "printf a > /root/w/f", Box::new(|u: &Path, _| {
                set_xattr(&u.join("root/w/f"), "user.c6b", b"value\0with nul");
            }), RoundTrip), Box::new(|u: &Path| {
                let v = get_xattr(&u.join("root/w/f"), "user.c6b");
                assert_eq!(v.as_deref(), Some(&b"value\0with nul"[..]), "user xattr not restored");
                json!("user.c6b restored")
            })),
            with_fork_check(planted("user-xattr-32", "printf a > /root/w/f", Box::new(|u: &Path, _| {
                for i in 0..32 {
                    set_xattr(&u.join("root/w/f"), &format!("user.k{i}"), b"v");
                }
            }), RoundTrip), Box::new(|u: &Path| {
                let n = (0..32).filter(|i| get_xattr(&u.join("root/w/f"), &format!("user.k{i}")).is_some()).count();
                assert_eq!(n, 32, "user xattrs not restored");
                json!("32 user xattrs restored")
            })),
            planted("user-xattr-33", "printf a > /root/w/f", Box::new(|u: &Path, _| {
                for i in 0..33 {
                    set_xattr(&u.join("root/w/f"), &format!("user.k{i}"), b"v");
                }
            }), meta),
            planted("user-xattr-oversized", "printf a > /root/w/f", Box::new(|u: &Path, _| {
                set_xattr(&u.join("root/w/f"), "user.big", &vec![b'x'; 4096]);
            }), meta),
            planted("user-overlay-xattr", "printf a > /root/w/f", Box::new(|u: &Path, _| {
                set_xattr(&u.join("root/w/f"), "user.overlay.redirect", b"/x");
            }), meta),
            planted("overlay-redirect", "mkdir -p /root/w/d", Box::new(|u: &Path, _| {
                set_xattr(&u.join("root/w/d"), "trusted.overlay.redirect", b"/etc");
            }), meta),
            planted("overlay-metacopy", "printf a > /root/w/f", Box::new(|u: &Path, _| {
                set_xattr(&u.join("root/w/f"), "trusted.overlay.metacopy", b"");
            }), meta),
            planted("overlay-index-upper", "printf a > /root/w/f", Box::new(|u: &Path, _| {
                set_xattr(&u.join("root/w/f"), "trusted.overlay.upper", b"\x00\xfb\x1d\x00");
            }), meta),
            planted("overlay-nlink", "printf a > /root/w/f", Box::new(|u: &Path, _| {
                set_xattr(&u.join("root/w/f"), "trusted.overlay.nlink", b"U+1");
            }), meta),
            planted("overlay-escaped", "printf a > /root/w/f", Box::new(|u: &Path, _| {
                set_xattr(&u.join("root/w/f"), "trusted.overlay.overlay.origin", b"x");
            }), meta),
            case("setuid-and-sticky", "printf s > /root/w/su && chmod 4755 /root/w/su && mkdir /root/w/t && chmod 1777 /root/w/t", RoundTrip),
        ],
    ));
}

#[test]
#[ignore = "root on the prepared VM: C6b hostile content"]
fn c6b_hostile_names_depth_and_counts_hold_their_limits() {
    use Expect::*;
    // Depth: /root is 1, /root/w 2, and each `d` one more; the deepest entry is the
    // file in the last directory.
    let chain = |dirs: usize| {
        format!(
            "cd /root/w && p=. && for i in $(seq 1 {dirs}); do p=$p/d; done && mkdir -p $p && printf x > $p/f"
        )
    };
    let layout = Refused("checkpoint_layout_unsupported");
    run(run_cases(
        "hostile names, depth and counts",
        vec![
            case("non-utf8-names", "printf a > \"/root/w/$(printf 'n\\377\\376')\" && mkdir \"/root/w/$(printf 'd\\200')\"", RoundTrip),
            case("name-255", &format!("printf a > /root/w/{}", "n".repeat(255)), RoundTrip),
            case("depth-126", &chain(124), RoundTrip),
            case("depth-128", &chain(126), Either),
            case("depth-130", &chain(128), layout),
        ],
    ));
    run(entry_limit());
}

/// The 65,536-entry bound exactly: a capture of a known tree gives the entries a fresh
/// source contributes besides the files, so `65,536 - base` files fit and one more
/// does not.
async fn entry_limit() {
    let w = World::start(json!({})).await;
    let files = |n: usize| format!("mkdir -p /root/w/n && cd /root/w/n && seq 1 {n} | sed 's/^/f/' | xargs touch");
    let src = w.source(1 << 30, &files(1000)).await;
    let c = w.ok(json!({ "op": "capture", "id": src, "lifetime_ms": 3_600_000 })).await;
    let cp = c["id"].as_str().unwrap().to_string();
    let base = w.cp_col(&cp, "entry_count").parse::<usize>().unwrap() - 1000;
    w.ok(json!({ "op": "delete_checkpoint", "id": cp })).await;
    w.ok(json!({ "op": "delete", "id": src })).await;
    let mut seen = Vec::new();
    for (n, fits) in [(65_536 - base, true), (65_537 - base, false)] {
        let src = w.source(1 << 30, &files(n)).await;
        let r = w.rpc(OWNER, json!({ "op": "capture", "id": src, "lifetime_ms": 3_600_000 })).await;
        if fits {
            let cp = ok(&r)["id"].as_str().unwrap().to_string();
            assert_eq!(w.cp_col(&cp, "entry_count"), "65536");
            let f = w.ok(json!({ "op": "create", "from_checkpoint": cp, "disk_bytes": 1u64 << 30 })).await;
            let fid = f["id"].as_str().unwrap().to_string();
            assert_eq!(
                w.sh(&fid, COUNT_LISTING).await["stdout"],
                w.sh(&src, COUNT_LISTING).await["stdout"]
            );
            w.ok(json!({ "op": "delete", "id": fid })).await;
            w.ok(json!({ "op": "delete_checkpoint", "id": cp })).await;
            seen.push(json!({ "files": n, "entries": 65_536, "outcome": "round trip" }));
        } else {
            assert_eq!(refused(&r), "checkpoint_size_limit", "{r}");
            w.until("settled", 60, |w| w.charge() == (0, 0)).await;
            seen.push(json!({ "files": n, "entries": 65_537, "outcome": "checkpoint_size_limit" }));
        }
        w.ok(json!({ "op": "delete", "id": src })).await;
    }
    matrix("hostile entry limit", json!({ "base_entries": base, "cases": seen }));
    w.finish().await;
}

#[test]
#[ignore = "root on the prepared VM: C6b hostile content"]
fn c6b_hostile_sizes_sparse_and_inode_bombs_hold_their_limits() {
    use Expect::*;
    let big = |mut c: Case| {
        c.disk_bytes = 3 << 30;
        c
    };
    run(run_cases(
        "hostile sizes, sparse files and inode bombs",
        vec![
            big(case("sparse-2g-over-the-1g-cap", "truncate -s 2G /root/w/sparse", Refused("checkpoint_size_limit"))),
            big(case("sparse-512m", "truncate -s 512M /root/w/sparse && printf end >> /root/w/sparse", Either)),
            many(case("inode-bomb-to-the-quota", "mkdir -p /root/w/i && cd /root/w/i && (seq 1 100000 | sed 's/^/f/' | xargs touch 2>/dev/null || true)", Either)),
            case("zero-length-and-empty-dirs", "touch /root/w/z && mkdir -p /root/w/e1/e2", RoundTrip),
        ],
    ));
}

#[test]
#[ignore = "root on the prepared VM: C6b hostile content"]
fn c6b_hostile_protected_trees_and_sentinels_are_unchanged() {
    use Expect::*;
    let layout = Refused("checkpoint_layout_unsupported");
    run(run_cases(
        "hostile protected trees",
        vec![
            planted("file-beneath-dev", "", Box::new(|u: &Path, o| {
                std::fs::create_dir_all(u.join("dev")).unwrap();
                std::fs::write(u.join("dev/c6b"), b"x").unwrap();
                chown(&u.join("dev/c6b"), o);
            }), layout),
            planted("sys-replaced-by-a-symlink", "", Box::new(|u: &Path, o| {
                let _ = std::fs::remove_dir_all(u.join("sys"));
                std::os::unix::fs::symlink("/", u.join("sys")).unwrap();
                chown(&u.join("sys"), o);
            }), layout),
            planted("opaque-scaffold", "", Box::new(|u: &Path, _| {
                std::fs::create_dir_all(u.join("proc")).unwrap();
                set_xattr(&u.join("proc"), "trusted.overlay.opaque", b"y");
            }), layout),
            case("sentinel-links-are-not-followed", &format!("ln -s {SENTINEL} /root/w/s && printf changed > /root/w/s.copy"), RoundTrip),
        ],
    ));
}

/// The two-uid subset of the hostile callers, through the real socket: another uid's
/// checkpoint IDs are NOT_FOUND everywhere; a reused key with another request
/// conflicts; one uid at its worker limit does not stop the other's capture.
#[test]
#[ignore = "root on the prepared VM: C6b hostile callers"]
fn c6b_hostile_callers_two_uids_get_only_their_own() {
    run(async {
        let w = World::start(json!({})).await;
        let src = w.source(0, "mkdir -p /root/w && printf one > /root/w/a").await;
        let c = w
            .ok(json!({ "op": "capture", "id": src, "request_id": "mine", "lifetime_ms": 3_600_000 }))
            .await;
        let cp = c["id"].as_str().unwrap().to_string();
        let mut seen = serde_json::Map::new();
        // Foreign IDs: Get, Delete, List's sandbox filter and from_checkpoint.
        for (label, call) in [
            ("get", json!({ "op": "get_checkpoint", "id": cp })),
            ("delete", json!({ "op": "delete_checkpoint", "id": cp })),
            ("fork", json!({ "op": "create", "from_checkpoint": cp })),
            ("capture-foreign-sandbox", json!({ "op": "capture", "id": src, "lifetime_ms": 3_600_000 })),
        ] {
            let r = w.rpc(STRANGER, call).await;
            assert_eq!(r["error"]["code"], "NotFound", "{label}: {r}");
            seen.insert(label.into(), r["error"]["code"].clone());
        }
        let listed = w
            .rpc(STRANGER, json!({ "op": "list_checkpoints", "sandbox_id": src }))
            .await;
        let listed_ok = listed.get("ok").map(|l| l.as_array().unwrap().len());
        assert!(listed_ok.is_none_or(|n| n == 0), "{listed}");
        seen.insert("list-foreign-sandbox".into(), json!(listed.get("error").map(|e| e["code"].clone()).unwrap_or(json!(0))));
        // A key reused with another request.
        let conflict = w
            .rpc(OWNER, json!({ "op": "capture", "id": src, "request_id": "mine", "lifetime_ms": 7_200_000 }))
            .await;
        assert_eq!(refused(&conflict), "request_id_conflict", "{conflict}");
        // The same key under the other uid is that uid's own (not found: not its sandbox).
        let theirs = w.rpc(STRANGER, json!({ "op": "create" })).await;
        let tsrc = ok(&theirs)["id"].as_str().unwrap().to_string();
        w.rpc(STRANGER, json!({ "op": "exec", "id": tsrc, "script": "mkdir -p /root/w && printf two > /root/w/a" })).await;
        let tc = w
            .rpc(STRANGER, json!({ "op": "capture", "id": tsrc, "request_id": "mine", "lifetime_ms": 3_600_000 }))
            .await;
        let tcp = ok(&tc)["id"].as_str().unwrap().to_string();
        assert_ne!(tcp, cp);
        // One uid's long capture holds its worker slot; the other's capture still runs.
        let big = w.source(1 << 30, &format!("mkdir -p /root/w && {BIG}")).await;
        let long = {
            let api = w.api.clone();
            let call = json!({ "op": "capture", "id": big, "lifetime_ms": 3_600_000 });
            tokio::spawn(async move { rpc(&api, OWNER, call).await })
        };
        w.worker("capture", 60).await;
        let second = w
            .rpc(OWNER, json!({ "op": "capture", "id": src, "lifetime_ms": 3_600_000 }))
            .await;
        let owner_second = second.get("error").map(|e| e["reason"].clone());
        let other = w
            .rpc(STRANGER, json!({ "op": "capture", "id": tsrc, "lifetime_ms": 3_600_000 }))
            .await;
        assert!(other.get("ok").is_some(), "the other uid was blocked by this one's worker: {other}");
        let long = long.await.unwrap();
        assert!(long.get("ok").is_some(), "{long}");
        // Everything of the stranger's, deleted by the stranger.
        for (_, state) in w.rows() {
            assert_ne!(state, "capturing");
        }
        for id in [tcp, ok(&other)["id"].as_str().unwrap().to_string()] {
            w.rpc(STRANGER, json!({ "op": "delete_checkpoint", "id": id })).await;
        }
        w.rpc(STRANGER, json!({ "op": "delete", "id": tsrc })).await;
        matrix(
            "hostile callers, two uids",
            json!({ "foreign": seen, "conflict": "request_id_conflict",
                    "same_key_other_uid": "its own checkpoint",
                    "owner_second_capture_while_busy": owner_second,
                    "other_uid_captured_while_owner_busy": true }),
        );
        w.finish().await;
    });
}
