//! B6's isolated Firecracker test deployment (`deploy/firecracker-test/`). Until B7,
//! `kilnd --backend firecracker` exists only in a build with the non-default
//! `firecracker-test-deployment` feature, runs only with this file, only at the exact
//! non-production paths it names, and only as the account, socket group and systemd
//! unit it names, compared with what the kernel says this process is (B6-BI-01). It is
//! one half of the gate: the other is the helper's, whose production build serves no
//! Firecracker profile at all (the test approval exists only in test builds), so even a
//! daemon started this way against the installed helper gets a C0 refusal for every
//! Create.
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::ffi::CString;
use std::io::Read;
use std::path::{Path, PathBuf};

/// The only schema this build reads.
/// Version 2 (B7) adds `kilnd.cgroup`, the exact cgroup the daemon must run in.
pub const SCHEMA: &str = "kilnd-firecracker-test-deployment/2";
/// The only deployment kind B6 has.
pub const ISOLATED_TEST: &str = "isolated-test";
/// The checked-in deployment, which the privileged end-to-end test also reads.
pub const CHECKED_IN: &str = include_str!("../../../deploy/firecracker-test/deployment.json");
const MAX_BYTES: u64 = 64 * 1024;

/// Production's paths. The test deployment may name none of them.
const PRODUCTION_PATHS: [&str; 6] = [
    "/run/kilnd/kilnd.sock",
    "/var/lib/kilnd",
    "/run/kilnd-helper/helper.sock",
    "/run/kilnd-helper",
    "/var/lib/kilnd-helper",
    "/etc/kilnd",
];

/// The production daemon's account and group. The test deployment may be neither.
const PRODUCTION_ACCOUNT: &str = "kilnd";

/// The deployment's account and group as the account databases resolve them, beside
/// production's, which may not exist on a test host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resolved {
    pub account_uid: u32,
    pub group_gid: u32,
    pub production_uid: Option<u32>,
    pub production_gid: Option<u32>,
}

/// What this process is, as the kernel reports it, never as a file names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observed {
    pub real_uid: u32,
    pub effective_uid: u32,
    pub saved_uid: u32,
    /// The resolved CLI `--socket-group`; `None` when it is empty (root only).
    pub socket_gid: Option<u32>,
    /// This process's own `cgroup` file, read beneath `sys::procfs`.
    pub cgroup: String,
}

impl Observed {
    /// The real, effective and saved UIDs, and the cgroup from this process's own
    /// procfs entry: `<pid>/cgroup` beneath the private procfs instance, not a pathname
    /// another mount could shadow.
    #[cfg(target_os = "linux")]
    pub fn current(socket_gid: Option<u32>) -> Result<Self> {
        let (mut real_uid, mut effective_uid, mut saved_uid) = (0, 0, 0);
        // SAFETY: getresuid writes three live u32s.
        if unsafe { libc::getresuid(&mut real_uid, &mut effective_uid, &mut saved_uid) } != 0 {
            return Err(std::io::Error::last_os_error()).context("read this process's UIDs");
        }
        let cgroup = crate::sys::procfs::read_to_string(&crate::sys::procfs::own("cgroup"))
            .context("read this process's own cgroup")?;
        Ok(Self {
            real_uid,
            effective_uid,
            saved_uid,
            socket_gid,
            cgroup,
        })
    }

    /// Only Linux can say which account and unit a process runs as here.
    #[cfg(not(target_os = "linux"))]
    pub fn current(_socket_gid: Option<u32>) -> Result<Self> {
        bail!(
            "the isolated Firecracker test deployment runs only on Linux, where its identity is observed"
        )
    }
}

/// The single cgroup v2 path in a `cgroup` file (`0::/path`). Anything else, such as a
/// hybrid hierarchy's several lines, is refused rather than guessed at.
fn unified_cgroup(text: &str) -> Result<&str> {
    let mut lines = text.lines();
    match (lines.next(), lines.next()) {
        (Some(line), None) => match line.strip_prefix("0::") {
            Some(path) if path.starts_with('/') => Ok(path),
            _ => bail!("this process's cgroup {line:?} is not a cgroup v2 path"),
        },
        _ => bail!("this process is not in exactly one cgroup v2 hierarchy: {text:?}"),
    }
}

/// An account's UID through `getpwnam_r`, or `None` when it does not exist.
fn account_uid(name: &str) -> Result<Option<u32>> {
    let cname = CString::new(name).context("account name contains NUL")?;
    // SAFETY: passwd is plain data; zeroed is a valid empty value.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer refers to a live, correctly sized buffer.
    let rc = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut found,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::from_raw_os_error(rc))
            .with_context(|| format!("look up account {name:?}"));
    }
    Ok((!found.is_null()).then_some(pwd.pw_uid))
}

/// A group's GID through `getgrnam_r`, or `None` when it does not exist.
fn group_gid(name: &str) -> Result<Option<u32>> {
    let cname = CString::new(name).context("group name contains NUL")?;
    // SAFETY: group is plain data; zeroed is a valid empty value.
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut found: *mut libc::group = std::ptr::null_mut();
    // SAFETY: every pointer refers to a live, correctly sized buffer.
    let rc = unsafe {
        libc::getgrnam_r(
            cname.as_ptr(),
            &mut grp,
            buf.as_mut_ptr(),
            buf.len(),
            &mut found,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::from_raw_os_error(rc))
            .with_context(|| format!("look up group {name:?}"));
    }
    Ok((!found.is_null()).then_some(grp.gr_gid))
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Daemon {
    pub socket: PathBuf,
    pub socket_group: String,
    pub state_dir: PathBuf,
    pub account: String,
    pub unit: String,
    /// The unit's whole cgroup v2 path, `/<slice>/.../<unit>` (B7, B6-RC-02): the
    /// daemon must run in exactly this cgroup, the one the helper enrolls, not merely
    /// in some cgroup named after the unit.
    pub cgroup: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Helper {
    /// The test helper's private root: its ledger, faults and socket live here.
    pub root: PathBuf,
    pub socket: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestDeployment {
    pub schema: String,
    pub deployment: String,
    pub profile: String,
    pub kilnd: Daemon,
    pub helper: Helper,
}

fn under_production(path: &Path) -> bool {
    PRODUCTION_PATHS
        .iter()
        .any(|production| path.starts_with(production) || Path::new(production).starts_with(path))
}

impl TestDeployment {
    /// Strict JSON with exact fields, then every path checked.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let value = crate::firecracker::strict_json(raw)
            .map_err(anyhow::Error::msg)
            .context("test deployment is not strict JSON")?;
        let deployment: Self =
            serde_json::from_value(value).context("test deployment has the wrong fields")?;
        deployment.validate()?;
        Ok(deployment)
    }

    pub fn read(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)
            .with_context(|| format!("open test deployment {}", path.display()))?;
        if !file.metadata()?.is_file() {
            bail!("test deployment {} is not a regular file", path.display());
        }
        let mut raw = Vec::new();
        file.take(MAX_BYTES + 1).read_to_end(&mut raw)?;
        if raw.len() as u64 > MAX_BYTES {
            bail!("test deployment exceeds {MAX_BYTES} bytes");
        }
        Self::parse(&raw)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != SCHEMA {
            bail!("test deployment schema must be {SCHEMA:?}");
        }
        if self.deployment != ISOLATED_TEST {
            bail!("only the {ISOLATED_TEST:?} deployment exists before B7");
        }
        if !crate::helper::firecracker::config::valid_profile(&self.profile) {
            bail!("invalid profile name");
        }
        for path in [
            &self.kilnd.socket,
            &self.kilnd.state_dir,
            &self.helper.root,
            &self.helper.socket,
        ] {
            if !path.is_absolute()
                || path.components().any(|c| {
                    !matches!(
                        c,
                        std::path::Component::RootDir | std::path::Component::Normal(_)
                    )
                })
            {
                bail!("{} must be absolute and normal", path.display());
            }
            if under_production(path) {
                bail!(
                    "{} is a production path; the test deployment stays isolated",
                    path.display()
                );
            }
        }
        if self.helper.socket.parent() != Some(self.helper.root.as_path()) {
            bail!("the test helper's socket must be directly in its root");
        }
        for name in [&self.kilnd.account, &self.kilnd.socket_group] {
            if name.is_empty() || name == "kilnd" || name == "root" {
                bail!("the test daemon needs its own account and group, not {name:?}");
            }
        }
        if !self.kilnd.unit.ends_with(".service") || self.kilnd.unit.starts_with("kilnd.") {
            bail!("the test daemon runs in its own service unit");
        }
        let cgroup = Path::new(&self.kilnd.cgroup);
        if !self.kilnd.cgroup.starts_with('/')
            || self.kilnd.cgroup.ends_with('/')
            || self.kilnd.cgroup.contains("//")
            || cgroup.components().any(|c| {
                !matches!(
                    c,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
            || cgroup.file_name().and_then(|n| n.to_str()) != Some(self.kilnd.unit.as_str())
            || cgroup.components().count() < 3
        {
            bail!(
                "the test daemon's cgroup must be an absolute, normal path below a slice, ending in its unit {:?}",
                self.kilnd.unit
            );
        }
        Ok(())
    }

    /// The daemon's own flags must be exactly the deployment's, so the file is the one
    /// description of where this daemon lives.
    pub fn check_daemon(
        &self,
        socket: &Path,
        state_dir: &Path,
        helper_socket: &Path,
    ) -> Result<()> {
        for (what, given, expected) in [
            ("--socket", socket, self.kilnd.socket.as_path()),
            ("--state-dir", state_dir, self.kilnd.state_dir.as_path()),
            (
                "--helper-socket",
                helper_socket,
                self.helper.socket.as_path(),
            ),
        ] {
            if given != expected {
                bail!(
                    "{what} {} differs from the test deployment's {}",
                    given.display(),
                    expected.display()
                );
            }
        }
        Ok(())
    }

    /// B6-BI-01: the deployment's account, group and unit must be what this process
    /// observably is. Called before any state is opened or any runtime built; refuses
    /// on any mismatch, naming each one.
    pub fn check_process(&self, socket_gid: Option<u32>) -> Result<()> {
        let resolved = self.resolve()?;
        let observed = Observed::current(socket_gid)?;
        self.check_identity(&resolved, &observed)
    }

    /// The deployment's names through `getpwnam`/`getgrnam`. Each must exist.
    pub fn resolve(&self) -> Result<Resolved> {
        let account = &self.kilnd.account;
        let group = &self.kilnd.socket_group;
        Ok(Resolved {
            account_uid: account_uid(account)?.with_context(|| {
                format!("the test deployment's account {account:?} does not exist")
            })?,
            group_gid: group_gid(group)?.with_context(|| {
                format!("the test deployment's socket group {group:?} does not exist")
            })?,
            production_uid: account_uid(PRODUCTION_ACCOUNT)?,
            production_gid: group_gid(PRODUCTION_ACCOUNT)?,
        })
    }

    /// Compares the resolved deployment with the observed process. Every mismatch is
    /// collected, so the refusal names all of them.
    pub fn check_identity(&self, resolved: &Resolved, observed: &Observed) -> Result<()> {
        let mut wrong = Vec::new();
        let account = &self.kilnd.account;
        let group = &self.kilnd.socket_group;
        let unit = &self.kilnd.unit;

        // The account: real, effective and saved UIDs, never root, never production's.
        let uid = resolved.account_uid;
        if uid == 0 {
            wrong.push(format!("account {account:?} is UID 0"));
        }
        if resolved.production_uid == Some(uid) {
            wrong.push(format!(
                "account {account:?} has the production {PRODUCTION_ACCOUNT:?} account's UID {uid}"
            ));
        }
        let uids = [
            observed.real_uid,
            observed.effective_uid,
            observed.saved_uid,
        ];
        if uids.iter().any(|&observed| observed != uid) {
            wrong.push(format!(
                "this process runs as UIDs {}/{}/{} (real/effective/saved), not account {account:?} (UID {uid})",
                uids[0], uids[1], uids[2]
            ));
        }
        if uids.contains(&0) {
            wrong.push("this process has UID 0".into());
        }
        if let Some(production) = resolved.production_uid
            && uids.contains(&production)
        {
            wrong.push(format!(
                "this process runs as the production {PRODUCTION_ACCOUNT:?} account"
            ));
        }

        // The socket group: the CLI's resolved GID, never production's.
        let gid = resolved.group_gid;
        if resolved.production_gid == Some(gid) {
            wrong.push(format!(
                "socket group {group:?} has the production {PRODUCTION_ACCOUNT:?} group's GID {gid}"
            ));
        }
        match observed.socket_gid {
            Some(cli) if cli == gid => {}
            Some(cli) => wrong.push(format!(
                "--socket-group resolves to GID {cli}, not group {group:?} (GID {gid})"
            )),
            None => wrong.push(format!(
                "--socket-group is empty (root only), not group {group:?}"
            )),
        }
        if let Some(production) = resolved.production_gid
            && observed.socket_gid == Some(production)
        {
            wrong.push(format!(
                "--socket-group is the production {PRODUCTION_ACCOUNT:?} group"
            ));
        }

        // The unit: this process's own cgroup is exactly the deployment's whole cgroup
        // path, not merely one ending in the unit's name (B6-RC-02).
        let expected = &self.kilnd.cgroup;
        match unified_cgroup(&observed.cgroup) {
            Ok(path) if path == expected => {}
            Ok(path) => wrong.push(format!(
                "this process runs in cgroup {path}, not in unit {unit:?} at {expected}"
            )),
            Err(error) => wrong.push(format!("{error:#}; not in unit {unit:?} at {expected}")),
        }

        if wrong.is_empty() {
            Ok(())
        } else {
            bail!(
                "this process is not the isolated Firecracker test deployment's daemon: {}",
                wrong.join("; ")
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn checked_in() -> Value {
        serde_json::from_str(CHECKED_IN).unwrap()
    }

    fn parse(value: &Value) -> Result<TestDeployment> {
        TestDeployment::parse(&serde_json::to_vec(value).unwrap())
    }

    #[test]
    fn the_checked_in_deployment_is_isolated_and_valid() {
        let deployment = TestDeployment::parse(CHECKED_IN.as_bytes()).unwrap();
        assert_eq!(deployment.deployment, ISOLATED_TEST);
        assert_eq!(deployment.profile, "offline-768-v1");
        deployment
            .check_daemon(
                &deployment.kilnd.socket,
                &deployment.kilnd.state_dir,
                &deployment.helper.socket,
            )
            .unwrap();
    }

    #[test]
    fn production_paths_names_and_other_kinds_are_refused() {
        let mutations: Vec<(&str, Value)> = vec![
            ("/schema", json!("kilnd-firecracker-test-deployment/1")),
            ("/schema", json!("kilnd-firecracker-test-deployment/3")),
            ("/deployment", json!("production")),
            ("/profile", json!("Offline")),
            ("/kilnd/socket", json!("/run/kilnd/kilnd.sock")),
            ("/kilnd/state_dir", json!("/var/lib/kilnd")),
            ("/kilnd/state_dir", json!("/var/lib/kilnd/sub")),
            ("/kilnd/state_dir", json!("/var/lib")),
            ("/kilnd/state_dir", json!("relative")),
            ("/kilnd/state_dir", json!("/var/lib/x/../kilnd")),
            ("/helper/socket", json!("/run/kilnd-helper/helper.sock")),
            ("/helper/root", json!("/var/lib/kilnd-helper/test")),
            ("/helper/socket", json!("/run/elsewhere/helper.sock")),
            ("/kilnd/account", json!("kilnd")),
            ("/kilnd/socket_group", json!("root")),
            ("/kilnd/unit", json!("kilnd.service")),
            ("/kilnd/unit", json!("kilnd-fctest")),
            ("/kilnd/cgroup", json!("kilnd-fctest.service")),
            ("/kilnd/cgroup", json!("/kilnd-fctest.service")),
            ("/kilnd/cgroup", json!("/system.slice/kilnd.service")),
            (
                "/kilnd/cgroup",
                json!("/system.slice/kilnd-fctest.service/"),
            ),
            (
                "/kilnd/cgroup",
                json!("/system.slice/../kilnd-fctest.service"),
            ),
            (
                "/kilnd/cgroup",
                json!("/system.slice//kilnd-fctest.service"),
            ),
        ];
        for (pointer, value) in mutations {
            let mut mutated = checked_in();
            *mutated.pointer_mut(pointer).unwrap() = value.clone();
            assert!(parse(&mutated).is_err(), "{pointer} = {value} was accepted");
        }
        let mut extra = checked_in();
        extra["gate"] = json!("test_approved");
        assert!(parse(&extra).is_err(), "an unknown field was accepted");
        let duplicate = CHECKED_IN.replacen('{', r#"{"schema": "x","#, 1);
        assert!(TestDeployment::parse(duplicate.as_bytes()).is_err());
    }

    const UID: u32 = 990;
    const GID: u32 = 991;

    fn resolved() -> Resolved {
        Resolved {
            account_uid: UID,
            group_gid: GID,
            production_uid: Some(980),
            production_gid: Some(981),
        }
    }

    fn observed() -> Observed {
        Observed {
            real_uid: UID,
            effective_uid: UID,
            saved_uid: UID,
            socket_gid: Some(GID),
            cgroup: "0::/system.slice/kilnd-fctest.service\n".into(),
        }
    }

    fn identity_error(resolved: &Resolved, observed: &Observed) -> String {
        let deployment = TestDeployment::parse(CHECKED_IN.as_bytes()).unwrap();
        format!(
            "{:#}",
            deployment.check_identity(resolved, observed).unwrap_err()
        )
    }

    /// B6-BI-01: the account, socket group and unit are compared with what the process
    /// is, each refused on its own, and every mismatch is named.
    #[test]
    fn b6_bi_01_identity_is_observed_not_declared() {
        let deployment = TestDeployment::parse(CHECKED_IN.as_bytes()).unwrap();
        deployment.check_identity(&resolved(), &observed()).unwrap();

        let account = |set: fn(&mut Observed)| {
            let mut o = observed();
            set(&mut o);
            identity_error(&resolved(), &o)
        };
        for error in [
            account(|o| o.real_uid = 1000),
            account(|o| o.effective_uid = 1000),
            account(|o| o.saved_uid = 1000),
        ] {
            assert!(error.contains("not account \"kilnd-fctest\""), "{error}");
            assert!(
                !error.contains("socket-group") && !error.contains("unit"),
                "{error}"
            );
        }
        let error = account(|o| o.socket_gid = Some(50));
        assert!(
            error.contains("--socket-group resolves to GID 50"),
            "{error}"
        );
        assert!(
            !error.contains("UIDs") && !error.contains("unit"),
            "{error}"
        );
        let error = account(|o| o.socket_gid = None);
        assert!(error.contains("--socket-group is empty"), "{error}");
        for cgroup in [
            // B6-RC-02: the right unit name under another slice, or a user service's.
            "0::/b6.slice/b6-recheck.slice/kilnd-fctest.service\n",
            "0::/user.slice/user-990.slice/user@990.service/app.slice/kilnd-fctest.service\n",
            "0::/system.slice/kilnd.service\n",
            "0::/system.slice/kilnd-fctest.service/extra\n",
            "0::/system.slice/xkilnd-fctest.service\n",
            "0::/user.slice/user-1000.slice/session-3.scope\n",
            "0::/\n",
            "",
            "0::relative/kilnd-fctest.service\n",
            "1:name=systemd:/system.slice/kilnd-fctest.service\n0::/system.slice/kilnd-fctest.service\n",
        ] {
            let mut o = observed();
            o.cgroup = cgroup.into();
            let error = identity_error(&resolved(), &o);
            assert!(
                error.contains("not in unit \"kilnd-fctest.service\""),
                "{cgroup:?}: {error}"
            );
            assert!(
                !error.contains("UIDs") && !error.contains("socket-group"),
                "{error}"
            );
        }
    }

    /// B6-BI-01: root and production's account and group are refused even when the
    /// process matches them.
    #[test]
    fn b6_bi_01_root_and_production_identities_are_refused() {
        let mut root = resolved();
        root.account_uid = 0;
        let mut o = observed();
        (o.real_uid, o.effective_uid, o.saved_uid) = (0, 0, 0);
        let error = identity_error(&root, &o);
        assert!(
            error.contains("is UID 0") && error.contains("has UID 0"),
            "{error}"
        );

        let mut production = resolved();
        production.account_uid = 980;
        let mut o = observed();
        (o.real_uid, o.effective_uid, o.saved_uid) = (980, 980, 980);
        let error = identity_error(&production, &o);
        assert!(error.contains("production \"kilnd\" account"), "{error}");

        let mut production = resolved();
        production.group_gid = 981;
        let mut o = observed();
        o.socket_gid = Some(981);
        let error = identity_error(&production, &o);
        assert!(error.contains("production \"kilnd\" group"), "{error}");

        // Every mismatch at once is named at once (Daybreak's PoC).
        let mut o = observed();
        (o.real_uid, o.effective_uid, o.saved_uid) = (501, 501, 501);
        o.socket_gid = Some(20);
        o.cgroup = "0::/user.slice/user-501.slice/session-1.scope\n".into();
        let error = identity_error(&resolved(), &o);
        for needle in ["UIDs 501/501/501", "GID 20", "not in unit"] {
            assert!(error.contains(needle), "{needle}: {error}");
        }
    }

    /// A deployment whose account or group does not exist is refused before anything
    /// is compared.
    #[test]
    fn b6_bi_01_names_must_resolve() {
        let mut value = checked_in();
        value["kilnd"]["account"] = json!("kilnd-no-such-account-b6");
        value["kilnd"]["socket_group"] = json!("kilnd-no-such-group-b6");
        let deployment = parse(&value).unwrap();
        let error = format!("{:#}", deployment.resolve().unwrap_err());
        assert!(error.contains("does not exist"), "{error}");
        assert!(deployment.check_process(Some(0)).is_err());
    }

    #[test]
    fn the_daemon_must_run_at_the_deployments_paths() {
        let deployment = TestDeployment::parse(CHECKED_IN.as_bytes()).unwrap();
        let elsewhere = Path::new("/run/other/kilnd.sock");
        assert!(
            deployment
                .check_daemon(
                    elsewhere,
                    &deployment.kilnd.state_dir,
                    &deployment.helper.socket
                )
                .is_err()
        );
        assert!(
            deployment
                .check_daemon(
                    &deployment.kilnd.socket,
                    &deployment.kilnd.state_dir,
                    Path::new("/run/kilnd-helper/helper.sock")
                )
                .is_err()
        );
    }
}
