//! B6's isolated Firecracker test deployment (`deploy/firecracker-test/`). Until B7,
//! `kilnd --backend firecracker` runs only with this file, and only at the exact
//! non-production paths it names. It is one half of the gate: the other is the
//! helper's, whose production build serves no Firecracker profile at all (the test
//! approval exists only in test builds), so even a daemon started this way against the
//! installed helper gets a C0 refusal for every Create.
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::io::Read;
use std::path::{Path, PathBuf};

/// The only schema this build reads.
pub const SCHEMA: &str = "kilnd-firecracker-test-deployment/1";
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

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Daemon {
    pub socket: PathBuf,
    pub socket_group: String,
    pub state_dir: PathBuf,
    pub account: String,
    pub unit: String,
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
            ("/schema", json!("kilnd-firecracker-test-deployment/2")),
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
