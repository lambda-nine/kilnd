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

/// The tree a comparison covers: `/root/w`, and for a read-only root `/workspace`
/// ([`listing_script`]: every name byte, directory mtimes included).
fn listing() -> String {
    listing_script(&["/root/w", "/workspace"])
}

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
    listing: String,
    fork_check: Option<ForkCheck>,
}

fn case(name: &'static str, inside: &str, expect: Expect) -> Case {
    Case {
        name,
        inside: inside.into(),
        plant: no_plant(),
        expect,
        disk_bytes: 0,
        listing: listing(),
        fork_check: None,
    }
}

/// A compact summary for the inode-bomb fixture, whose names are generated numbers.
const COUNT_LISTING: &str = r#"
    names=$(find /root/w -xdev) || exit 1
    count=$(printf '%s\n' "$names" | wc -l) || exit 1
    sorted=$(printf '%s\n' "$names" | LC_ALL=C sort) || exit 1
    digest=$(printf '%s\n' "$sorted" | sha256sum) || exit 1
    printf '%s|%s\000' "$count" "${digest%% *}"
"#;

fn many(mut c: Case) -> Case {
    c.listing = COUNT_LISTING.into();
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
    // The exact bytes of both (C6b review HIGH 3): two different invalid names must
    // never compare equal.
    let listing = w.sh(&src, &c.listing).await;
    let behavior = w.ok(json!({ "op": "exec", "id": src, "script": BEHAVIOR })).await;
    let r = w
        .rpc(
            OWNER,
            json!({ "op": "capture", "id": src, "request_id": format!("h-{}", c.name), "lifetime_ms": 3_600_000 }),
        )
        .await;
    // A keyed capture answers a refusal, or the row as it stands carrying its typed
    // failure while it settles (`token: detail`).
    let failed = r.get("error").map(|e| e["reason"].as_str().unwrap().to_string()).or_else(|| {
        (r["ok"]["state"] != "CHECKPOINT_STATE_READY").then(|| {
            let reason = r["ok"]["failure_reason"].as_str().unwrap_or("");
            reason.split(':').next().unwrap_or("").to_string()
        })
    });
    let outcome = if let Some(reason) = failed {
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
        let fork_listing = w.sh(&fid, &c.listing).await;
        let fork_behavior = w.ok(json!({ "op": "exec", "id": fid, "script": BEHAVIOR })).await;
        if let Err(e) = same_tree(&[listing.clone(), behavior.clone()], &[fork_listing, fork_behavior]) {
            panic!("{}: {e}", c.name);
        }
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
                "entries": w.cp_col(&cp, "entry_count"), "fork_upper": checked,
                "listing_bytes": output_bytes(&listing).len() })
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
    let results = case_results(cases).await;
    matrix(set, Value::Array(results));
}

async fn case_results(cases: Vec<Case>) -> Vec<Value> {
    let w = World::start(json!({})).await;
    let by = bystanders(&w).await;
    let mut results = Vec::new();
    for c in cases {
        results.push(check(&w, &by, c).await);
    }
    by.finish(&w).await;
    w.finish().await;
    results
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
    run(async {
        let cases = case_results(
        vec![
            case("non-utf8-names", "printf a > \"/root/w/$(printf 'n\\377\\376')\" && mkdir \"/root/w/$(printf 'd\\200')\"", RoundTrip),
            image_changes_and_id_extremes(),
            case("name-255", &format!("printf a > /root/w/{}", "n".repeat(255)), RoundTrip),
            case("depth-126", &chain(124), RoundTrip),
            case("depth-128", &chain(126), Either),
            case("depth-130", &chain(128), layout),
        ]).await;
        let limit = entry_limit().await;
        matrix("hostile names, depth and counts", json!({ "cases": cases, "entry_limit": limit }));
    });
}

/// Changes to the image's own files and owners at the ends of the sandbox's ID map
/// (C6b review HIGH 2: each is its own ledger row now): a lower file modified (copied
/// up), a lower file removed (a whiteout), a lower file renamed into the workspace, a lower file replaced by a
/// directory and a lower directory by a file, a lower directory removed and recreated
/// (opaque, its lower entries hidden), and files owned by ID 0 and by the highest
/// mapped uid and gid. The listing covers each changed path, so a lost whiteout or
/// opacity shows as an extra line in the fork.
fn image_changes_and_id_extremes() -> Case {
    let inside = "set -e; \
        for f in /etc/motd /etc/issue /etc/shells; do test -f $f; done; \
        test -d /etc/apk/keys; test -d /etc/profile.d; test -n \"$(ls /etc/profile.d)\"; \
        test -f /etc/profile; printf '\\n# c6b\\n' >> /etc/profile; \
        rm /etc/motd; \
        mv /etc/issue /root/w/issue-moved; \
        rm /etc/shells; mkdir /etc/shells; printf d > /etc/shells/inner; \
        rm -rf /etc/apk/keys; printf f > /etc/apk/keys; \
        rm -rf /etc/profile.d; mkdir /etc/profile.d; printf o > /etc/profile.d/only; \
        u=$(awk '{ print $1 + $3 - 1 }' /proc/self/uid_map | sort -n | tail -n 1); \
        g=$(awk '{ print $1 + $3 - 1 }' /proc/self/gid_map | sort -n | tail -n 1); \
        printf z > /root/w/id-low; chown 0:0 /root/w/id-low; \
        printf m > /root/w/id-high; chown $u:$g /root/w/id-high; \
        test \"$(stat -c %u:%g /root/w/id-high)\" = \"$u:$g\"; \
        test ! -e /etc/motd; test \"$(ls /etc/profile.d)\" = only";
    let mut c = case("image-changes-and-id-extremes", inside, Expect::RoundTrip);
    c.listing = listing_script(&[
        "/root/w",
        "/etc/profile",
        "/etc/motd",
        "/etc/issue",
        "/etc/shells",
        "/etc/apk",
        "/etc/profile.d",
    ]);
    c
}

/// The 65,536-entry bound exactly: a capture of a known tree gives the entries a fresh
/// source contributes besides the files, so `65,536 - base` files fit and one more
/// does not.
async fn entry_limit() -> Value {
    let w = World::start(json!({})).await;
    let files = |n: usize| format!("mkdir -p /root/w/n && cd /root/w/n && seq 1 {n} | sed 's/^/f/' | xargs touch");
    // 2 GiB disks: a 1 GiB disk's project quota allows only 65,536 inodes.
    let src = w.source(2 << 30, &files(1000)).await;
    let c = w.ok(json!({ "op": "capture", "id": src, "lifetime_ms": 3_600_000 })).await;
    let cp = c["id"].as_str().unwrap().to_string();
    let base = w.cp_col(&cp, "entry_count").parse::<usize>().unwrap() - 1000;
    w.ok(json!({ "op": "delete_checkpoint", "id": cp })).await;
    w.ok(json!({ "op": "delete", "id": src })).await;
    let mut seen = Vec::new();
    for (n, fits) in [(65_536 - base, true), (65_537 - base, false)] {
        let src = w.source(2 << 30, &files(n)).await;
        let r = w.rpc(OWNER, json!({ "op": "capture", "id": src, "lifetime_ms": 3_600_000 })).await;
        // At exactly 65,536 entries the 16 KiB-per-entry allowance alone reaches the 1 GiB
        // cap, so the size rule may answer first; record which bound refused.
        if fits && r.get("error").is_some() {
            let reason = refused(&r);
            assert_eq!(reason, "checkpoint_size_limit", "{r}");
            w.until("settled", 60, |w| w.charge() == (0, 0)).await;
            seen.push(json!({ "files": n, "entries": 65_536, "outcome": reason,
                              "message": r["error"]["message"] }));
        } else if fits {
            let cp = ok(&r)["id"].as_str().unwrap().to_string();
            assert_eq!(w.cp_col(&cp, "entry_count"), "65536");
            let f = w.ok(json!({ "op": "create", "from_checkpoint": cp, "disk_bytes": 2u64 << 30 })).await;
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
    w.finish().await;
    json!({ "base_entries": base, "cases": seen })
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
                chown(&u.join("dev"), o);
                std::fs::write(u.join("dev/c6b"), b"x").unwrap();
                chown(&u.join("dev/c6b"), o);
            }), layout),
            planted("sys-replaced-by-a-symlink", "", Box::new(|u: &Path, o| {
                let _ = std::fs::remove_dir_all(u.join("sys"));
                std::os::unix::fs::symlink("/", u.join("sys")).unwrap();
                chown(&u.join("sys"), o);
            }), layout),
            planted("opaque-scaffold", "", Box::new(|u: &Path, o| {
                std::fs::create_dir_all(u.join("proc")).unwrap();
                chown(&u.join("proc"), o);
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

/// `kiln ls`: (ID, status) of every run.
fn kiln_ids() -> Vec<(String, String)> {
    let out = std::process::Command::new(kiln_bin()).arg("ls").output().unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            Some((f.first()?.to_string(), f.get(1)?.to_string()))
        })
        .collect()
}

/// The backend IDs of the daemon's sandboxes that are not deleted, sorted.
fn live_backends(w: &World) -> Vec<String> {
    backends(w, "WHERE state != 'deleted' AND backend_id IS NOT NULL")
}

/// Every backend ID a sandbox row of the daemon names.
fn all_backends(w: &World) -> Vec<String> {
    backends(w, "WHERE backend_id IS NOT NULL")
}

fn backends(w: &World, filter: &str) -> Vec<String> {
    let db = w.db();
    let mut q = db
        .prepare(&format!("SELECT backend_id FROM sandboxes {filter} ORDER BY backend_id"))
        .unwrap();
    q.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect()
}

/// The deliberately stale runs of a failed create, exactly these: each is listed
/// stale by kiln (or already removed by it) within 60 s, then root's `kiln gc` of
/// exactly those IDs removes them. Their IDs, as collected.
async fn collect_expected_stale_runs(expected: &[String]) -> Vec<String> {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let stale = loop {
        let listed = kiln_ids();
        let present: Vec<&String> = expected.iter().filter(|r| run_dirs().contains(r)).collect();
        if present.iter().all(|r| listed.iter().any(|(id, st)| id == *r && st == "stale")) {
            break present.into_iter().cloned().collect::<Vec<_>>();
        }
        assert!(std::time::Instant::now() < end, "never stale: {present:?} in {listed:?}");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    };
    if !stale.is_empty() {
        let out = std::process::Command::new(kiln_bin())
            .arg("gc")
            .args(&stale)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
    }
    let left: Vec<String> = run_dirs().into_iter().filter(|r| expected.contains(r)).collect();
    assert!(left.is_empty(), "kiln gc left {left:?}");
    stale
}

/// The shim pid `kiln ls` reports for a backend.
fn shim_of(backend_id: &str) -> u32 {
    let out = std::process::Command::new(kiln_bin()).arg("ls").output().unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.first() == Some(&backend_id)).then(|| f.get(2)?.parse().ok()).flatten()
        })
        .unwrap_or_else(|| panic!("no shim for {backend_id}"))
}

/// Attacks on the artifact and the processes around a capture (design 11.2 items 3
/// and 4): a tampered manifest, a killed sandbox PID 1 mid-capture, a root `kiln exec`
/// straight into the source, and writable paths over reserved ones.
#[test]
#[ignore = "root on the prepared VM: C6b hostile content"]
fn c6b_hostile_artifact_and_process_attacks_are_refused_typed() {
    run(async {
        let w = World::start(json!({})).await;
        let mut seen = serde_json::Map::new();
        // 1. A manifest edited on disk: the fork refuses it corrupt and the checkpoint is
        // quarantined with its charge.
        let src = w.source(0, "mkdir -p /root/w && printf one > /root/w/a").await;
        let c = w.ok(json!({ "op": "capture", "id": src, "lifetime_ms": 3_600_000 })).await;
        let cp = c["id"].as_str().unwrap().to_string();
        let manifest = PathBuf::from(format!("{}/{}/{cp}/manifest.json", super::CPS, w.instance));
        let mut text = std::fs::read(&manifest).unwrap();
        let at = text.windows(4).position(|b| b == b"\"one").unwrap_or(text.len() / 2);
        text[at + 1] ^= 0x01;
        std::fs::write(&manifest, &text).unwrap();
        let charged = w.charge();
        let f = w.rpc(OWNER, json!({ "op": "create", "from_checkpoint": cp })).await;
        let tampered = refused(&f);
        assert_eq!(tampered, "checkpoint_corrupt", "{f}");
        w.until("QUARANTINED", 60, |w| w.cp_state(&cp) == "quarantined").await;
        assert_eq!(w.charge(), charged);
        w.ok(json!({ "op": "delete_checkpoint", "id": cp })).await;
        seen.insert("tampered_manifest".into(), json!({ "fork": tampered, "row": "quarantined" }));
        // 2. The source's PID 1 killed mid-capture: a typed failure, nothing left.
        let charge_before = w.charge();
        let big = w.source(1 << 30, &format!("mkdir -p /root/w && {BIG}")).await;
        let backend = w.ok(json!({ "op": "get", "id": big })).await["backend_id"]
            .as_str()
            .unwrap()
            .to_string();
        let pending = {
            let (api, id) = (w.api.clone(), big.clone());
            tokio::spawn(async move {
                rpc(&api, OWNER, json!({ "op": "capture", "id": id, "request_id": "pid1", "lifetime_ms": 3_600_000 })).await
            })
        };
        w.worker("capture", 60).await;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        kill_pid(shim_of(&backend));
        let r = pending.await.unwrap();
        let pid1 = match r.get("ok") {
            Some(row) => row["failure_reason"].as_str().unwrap().to_string(),
            None => refused(&r),
        };
        assert!(pid1.starts_with("checkpoint_"), "{r}");
        w.until("settled", 120, |w| {
            w.rows().iter().all(|(_, s)| s != "capturing" && s != "deleting")
        })
        .await;
        assert_eq!(w.charge(), (0, 0));
        seen.insert("pid1_killed_mid_capture".into(), json!(pid1));
        // The killed shim leaves the source's run stale. kilnd's strict removal cannot
        // prove that backend gone (its probe of the dead PID 1 fails), so Delete reads
        // kiln's listing: exactly this run, listed once and stale, is collected by ID and
        // then proved absent. One Delete answers DELETED and releases the reservation,
        // and the run is gone, with no root `kiln gc` anywhere in the scene.
        let row_of = |w: &World| {
            w.host_state().sandboxes.into_iter().find(|r| r.id == big).unwrap()
        };
        let end = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while !kiln_ids().iter().any(|(id, st)| *id == backend && st == "stale") {
            assert!(std::time::Instant::now() < end, "never stale: {:?}", kiln_ids());
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        // The row is still live and charged; kilnd never saw the shim die.
        let before = row_of(&w);
        assert!(
            before.state != "deleting" && before.state != "deleted" && !before.released,
            "the dead-shim source before its Delete: {before:?}"
        );
        let d = w.ok(json!({ "op": "delete", "id": big })).await;
        assert_eq!(d["state"], "SANDBOX_STATE_DELETED", "Delete of the dead-shim source: {d}");
        let gone = row_of(&w);
        assert!(gone.state == "deleted" && gone.released, "{gone:?}");
        assert_eq!(w.charge(), charge_before);
        assert!(
            !kiln_ids().iter().any(|(id, _)| *id == backend) && !run_dirs().contains(&backend),
            "kiln still lists or keeps the dead-shim run {backend}: {:?}",
            kiln_ids()
        );
        seen.insert(
            "dead_shim_delete".into(),
            json!({ "row_before": before.state, "listed": "stale",
                    "delete": "deleted, released", "root_gc": false, "run": "gone" }),
        );
        // 3. Root's own `kiln exec` into the source makes a capture busy (C6b review
        // HIGH 4: required, not recorded). The direct Exec reports it started, then waits
        // on its stdin, which is released only after Capture has answered, so it is
        // running at the admission instant; a READY capture fails the test. kilnd's gate
        // sees only its own executions, so it admits the capture (row, charge, dispatch)
        // and kiln's checkpoint lease refuses it (the design: "manager locking alone
        // cannot exclude a direct root CLI execution"). The row must fail as busy and
        // release its charge, with no artifact left.
        let backend = w.ok(json!({ "op": "get", "id": src })).await["backend_id"]
            .as_str()
            .unwrap()
            .to_string();
        let mut direct = tokio::process::Command::new(kiln_bin())
            .args(["exec", &backend, "sh", "-c", "echo started; read line; echo released"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = tokio::io::BufReader::new(direct.stdout.take().unwrap());
        let mut line = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            tokio::io::AsyncBufReadExt::read_line(&mut out, &mut line),
        )
        .await
        .expect("the direct exec never started")
        .unwrap();
        assert_eq!(line, "started\n");
        let (rows, charge, artifacts) = (w.rows(), w.charge(), w.artifacts());
        let mark = w.relay.mark();
        let busy = w.rpc(OWNER, json!({ "op": "capture", "id": src, "lifetime_ms": 3_600_000 })).await;
        assert!(direct.try_wait().unwrap().is_none(), "the direct exec ended before Capture answered");
        assert_eq!(busy["error"]["code"], "FailedPrecondition", "{busy}");
        assert_eq!(busy["error"]["reason"], "checkpoint_busy", "{busy}");
        let added: Vec<String> = w
            .rows()
            .into_iter()
            .map(|(id, _)| id)
            .filter(|id| !rows.iter().any(|(old, _)| old == id))
            .collect();
        assert_eq!(added.len(), 1, "the busy capture's rows: {added:?}");
        let refused_cp = added[0].clone();
        // Settled within 30 s: FAILED as busy, its charge released on ABSENT evidence
        // and no artifact entry left; otherwise fail with what the row holds.
        let settled = |w: &World| {
            w.cp_state(&refused_cp) == "failed"
                && w.charge() == charge
                && w.artifacts() == artifacts
        };
        let end = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !settled(&w) && std::time::Instant::now() < end {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            settled(&w),
            "the busy capture {refused_cp} did not settle in 30 s: state {} token {:?} charge {:?} (before {charge:?}) artifacts {:?} (before {artifacts:?})",
            w.cp_state(&refused_cp),
            w.cp_col(&refused_cp, "failure_token"),
            w.charge(),
            w.artifacts()
        );
        assert_eq!(w.cp_col(&refused_cp, "failure_token"), "checkpoint_busy");
        assert!(w.evidence(&refused_cp, "absent") >= 1, "the busy capture was released without ABSENT");
        assert!(!w.cp_col(&refused_cp, "release_evidence_id").is_empty(), "no release evidence on the row");
        assert_eq!(w.relay.requests_since(mark, "checkpoint.capture").len(), 1, "busy capture dispatches");
        assert_eq!(w.sandbox_state(&src), "ready", "the source after a busy capture");
        let mut stdin = direct.stdin.take().unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut stdin, b"go\n").await.unwrap();
        drop(stdin);
        let mut rest = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut out, &mut rest).await.unwrap();
        assert!(direct.wait().await.unwrap().success());
        assert_eq!(rest, "released\n");
        seen.insert(
            "direct_kiln_exec".into(),
            json!({ "code": busy["error"]["code"], "reason": busy["error"]["reason"],
                    "exec_running_at_admission": true, "row": "failed checkpoint_busy",
                    "charge_artifacts_unchanged": true }),
        );
        // 4. Writable paths at create (a source can't have them). One over a filesystem
        // kiln mounts itself is refused before anything is allocated: INVALID_ARGUMENT,
        // no row, no run.
        for path in ["/proc/x", "/sys/fs/cgroup/x"] {
            let runs_before = run_dirs();
            let rows_before = w.host_state().sandboxes.len();
            let r = w
                .rpc(OWNER, json!({ "op": "create", "read_only_root": true, "writable_paths": [path] }))
                .await;
            assert_eq!(r["error"]["code"], "InvalidArgument", "{path}: {r}");
            assert_eq!(w.host_state().sandboxes.len(), rows_before, "{path}: a refused create left a row");
            assert_eq!(run_dirs(), runs_before, "{path}: a refused create left a run");
            seen.insert(format!("writable {path}"), json!({ "create": r["error"] }));
        }
        // kiln may still refuse another path only after allocating, leaving a stale run
        // kilnd cannot name (a recorded LOW). Each create is checked alone: the run
        // directories that appeared while it ran are its own, each must turn stale and
        // be named by no sandbox, and root's `kiln gc` removes exactly those (C6b review
        // HIGH 6: nothing else is ever collected).
        for path in ["/dev/shm/x", "/etc/passwd/x"] {
            let runs_before = run_dirs();
            let live = live_backends(&w);
            assert!(
                runs_before.iter().all(|r| live.contains(r)),
                "{path}: a run no live sandbox names before the create: {runs_before:?}, {live:?}"
            );
            let rows_before: Vec<String> = w.host_state().sandboxes.into_iter().map(|r| r.id).collect();
            let r = w
                .rpc(OWNER, json!({ "op": "create", "read_only_root": true, "writable_paths": [path] }))
                .await;
            let new_runs: Vec<String> = run_dirs().into_iter().filter(|r| !runs_before.contains(r)).collect();
            let outcome = match r.get("ok") {
                Some(s) => {
                    let id = s["id"].as_str().unwrap().to_string();
                    assert_eq!(new_runs, vec![s["backend_id"].as_str().unwrap().to_string()], "{path}: {s}");
                    let c = w.rpc(OWNER, json!({ "op": "capture", "id": id, "lifetime_ms": 3_600_000 })).await;
                    let o = c.get("error").map(|e| e["reason"].clone()).unwrap_or(json!("captured"));
                    if let Some(cp) = c["ok"]["id"].as_str() {
                        w.ok(json!({ "op": "delete_checkpoint", "id": cp })).await;
                    }
                    let d = w.ok(json!({ "op": "delete", "id": id })).await;
                    assert_eq!(d["state"], "SANDBOX_STATE_DELETED", "{d}");
                    json!({ "create": "ok", "capture": o })
                }
                None => {
                    assert!(new_runs.len() <= 1, "{path}: one create made runs {new_runs:?}");
                    let named = all_backends(&w);
                    assert!(
                        new_runs.iter().all(|r| !named.contains(r)),
                        "{path}: a failed create's run is a sandbox's backend: {new_runs:?}"
                    );
                    let collected = collect_expected_stale_runs(&new_runs).await;
                    // kiln failed the create with no backend ID reported, so kilnd keeps
                    // the row FAILED with its reservation charged and refuses to delete
                    // it (an ambiguous reservation): exactly one new row, the one the
                    // error names, declared for `finish`.
                    let new_rows: Vec<SandboxRow> = w
                        .host_state()
                        .sandboxes
                        .into_iter()
                        .filter(|row| !rows_before.contains(&row.id))
                        .collect();
                    assert_eq!(new_rows.len(), 1, "{path}: the refused create's rows: {new_rows:?}");
                    let row = &new_rows[0];
                    assert!(
                        row.state == "failed" && !row.released && row.backend_id.is_none(),
                        "{path}: the refused create's row is not an ambiguous reservation: {row:?}"
                    );
                    let message = r["error"]["message"].as_str().unwrap_or_default();
                    assert!(
                        message.starts_with(&format!("create sandbox {}: ", row.id)),
                        "{path}: the refusal names another sandbox than {}: {r}",
                        row.id
                    );
                    w.expect_ambiguous(&row.id);
                    json!({ "create": r["error"], "stale_runs": collected, "ambiguous": row.id })
                }
            };
            assert_ne!(outcome["capture"], "captured", "{path}: {outcome}");
            assert_eq!(run_dirs(), runs_before, "{path}: runs left after the case");
            seen.insert(format!("writable {path}"), outcome);
        }
        matrix("hostile artifact and process attacks", Value::Object(seen));
        w.finish().await;
    });
}
