//! B7's root offline commands (design 16.6 "Clearing a rollback fault", 16.7): the
//! mandatory node-wide offline inventory, the RTC-14 fault clear, and read-only ledger
//! statistics. Each runs over no socket, as root, with the helper stopped: it takes the
//! node lock exactly as `enroll` does, so no H or L can run beside it.
//!
//! The inventory walks everything owned on the host, node-wide (every jail directory,
//! jail mount, loop device, VMM and supervisor process, cgroup and work file; see
//! `inventory::OfflineObservation`), against the ledger's active allocations, and
//! reads each instance's daemon database read-only for its highest token whose tag
//! verifies. It destroys nothing: anything the ledger does not own is reported, root
//! settles it by hand, and the inventory runs again. Its verdict is `explained` only
//! when nothing is left unaccounted for. The clear accepts only a current, canonical,
//! root-owned, explained report.
use super::executable::{WalkPolicy, walk_directory};
use super::inventory::{ObservationBackend, OfflineObservation};
use super::journal::{self, ClearOutcome, Ledger, LedgerConfig};
use crate::firecracker::{canonical, strict_json};
use crate::model::{Digest, Id128};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CString, OsStr};
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};

pub const REPORT_SCHEMA: &str = "kilnd-fc-offline-inventory-v1";
const MAX_REPORT_BYTES: u64 = 1 << 20;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportFault {
    pub generation: u64,
    pub kind: String,
    pub instance_id: Id128,
    pub token: Id128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportInstance {
    pub instance_id: Id128,
    /// The highest token in the daemon database whose tag verifies for this instance.
    pub highest_token: Option<Id128>,
    pub daemon_database: PathBuf,
    /// Tokens in that database that do not verify (pre-B7 random IDs, corruption).
    pub unverified_tokens: u64,
    pub issue_next: u64,
    pub watermark: u64,
    pub active_allocations: u64,
}

/// The inventory report, canonical JSON. `report_sha256` covers the canonical bytes of
/// every other field; it detects corruption, and the file's protected, root-owned
/// placement is what the clear relies on, not the digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryReport {
    pub schema: String,
    pub node_id: Id128,
    pub ledger_generation: u64,
    pub faults: Vec<ReportFault>,
    pub failstop: bool,
    pub instances: Vec<ReportInstance>,
    pub unexplained: Vec<String>,
    pub verdict: String,
    pub report_sha256: Digest,
}

impl InventoryReport {
    fn body_digest(&self) -> Result<Digest, String> {
        let mut value = serde_json::to_value(self).map_err(|e| e.to_string())?;
        value
            .as_object_mut()
            .ok_or("report is not an object")?
            .remove("report_sha256");
        Ok(Digest::of(&canonical(&value).map_err(|e| e.to_string())?))
    }

    fn encode(&self) -> Result<Vec<u8>, String> {
        canonical(&serde_json::to_value(self).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())
    }

    /// Strict, canonical and self-consistent, or refused.
    pub fn decode(raw: &[u8]) -> Result<Self, String> {
        let value = strict_json(raw).map_err(|e| format!("report: {e}"))?;
        if canonical(&value).map_err(|e| e.to_string())? != raw {
            return Err("the report is not canonical JSON".into());
        }
        let report: Self =
            serde_json::from_value(value).map_err(|e| format!("report: {e}"))?;
        if report.schema != REPORT_SCHEMA {
            return Err("the report has an unknown schema".into());
        }
        if report.body_digest()? != report.report_sha256 {
            return Err("the report's digest does not match its contents".into());
        }
        let unique: BTreeSet<_> = report.instances.iter().map(|i| i.instance_id).collect();
        if unique.len() != report.instances.len() {
            return Err("the report names an instance twice".into());
        }
        Ok(report)
    }
}

/// Every allocation token a daemon database records for `instance`, read-only.
fn daemon_tokens(path: &Path, instance: Id128) -> Result<Vec<Id128>, String> {
    let conn = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|e| format!("{}: {e}", path.display()))?;
    let mut statement = conn
        .prepare(
            "SELECT allocation_id FROM sandboxes
              WHERE accounting_kind = 'fenced' AND instance_id = ?1 AND allocation_id IS NOT NULL
             UNION
             SELECT allocation_id FROM release_evidence WHERE instance_id = ?1",
        )
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let rows = statement
        .query_map([instance.to_string()], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?;
    let mut tokens = Vec::new();
    for row in rows {
        let text = row.map_err(|e| e.to_string())?;
        tokens.push(Id128::parse(&text)?);
    }
    Ok(tokens)
}

fn with_node_lock<T>(
    config: &LedgerConfig,
    command: impl FnOnce(&mut Ledger) -> Result<T, String>,
) -> Result<T, String> {
    let directory =
        walk_directory(&config.policy, &config.directory).map_err(|e| e.to_string())?;
    let _lock = crate::lock::ExclusiveFileLock::acquire_at(
        directory.file(),
        OsStr::new(journal::LEDGER_LOCK),
        &journal::ledger_lock_path(&config.directory),
        "Firecracker node ledger",
    )
    .map_err(|error| format!("stop kilnd-helper first: {error:#}"))?;
    let mut ledger = Ledger::open(config.clone()).map_err(|e| e.to_string())?;
    command(&mut ledger)
}

/// `kilnd-helper offline-inventory`: builds the report under the node lock and writes
/// it, new and mode 0600, to `report`. `daemon_databases` must name exactly the
/// enrolled instances.
pub fn offline_inventory(
    config: &LedgerConfig,
    observation: &ObservationBackend,
    daemon_databases: &BTreeMap<Id128, PathBuf>,
    report: &Path,
) -> Result<InventoryReport, String> {
    let built = with_node_lock(config, |ledger| {
        build_report(ledger, config, observation, daemon_databases)
    })?;
    write_report(&config.policy, report, &built.encode()?)?;
    Ok(built)
}

fn build_report(
    ledger: &mut Ledger,
    config: &LedgerConfig,
    observation: &ObservationBackend,
    daemon_databases: &BTreeMap<Id128, PathBuf>,
) -> Result<InventoryReport, String> {
    let instances = ledger.instance_ids().map_err(|e| e.to_string())?;
    let enrolled: BTreeSet<Id128> = instances.iter().copied().collect();
    let named: BTreeSet<Id128> = daemon_databases.keys().copied().collect();
    if enrolled != named {
        return Err(
            "--daemon-db must name every enrolled instance's database, and nothing else".into(),
        );
    }
    let mut unexplained = Vec::new();
    let mut known: BTreeMap<Id128, Vec<Id128>> = BTreeMap::new();
    for instance in &instances {
        let active = ledger.inventory(*instance).map_err(|e| e.to_string())?;
        if active.overflow {
            unexplained.push(format!("instance {instance}: more active allocations than one listing"));
        }
        known.insert(*instance, active.records.iter().map(|r| r.allocation_id).collect());
    }
    // One node-wide walk: anything owned on the host that no active allocation explains.
    match observation.observe_offline(&known) {
        OfflineObservation::Observed { orphans, .. } => {
            for orphan in orphans {
                unexplained.push(format!("{}: {}", orphan.family, orphan.detail));
            }
        }
        OfflineObservation::Unknown { reason } => {
            unexplained.push(format!("host observation incomplete: {reason}"));
        }
    }
    let mut rows = Vec::new();
    for instance in &instances {
        let pointers = ledger.pointers(*instance).map_err(|e| e.to_string())?;
        let active_allocations = known[instance].len() as u64;
        let path = &daemon_databases[instance];
        let tokens = daemon_tokens(path, *instance)?;
        let key = ledger.token_key();
        let mut highest: Option<(u64, Id128)> = None;
        let mut unverified = 0;
        for token in tokens {
            match key.verify(*instance, token) {
                Some(seq) if highest.is_none_or(|(best, _)| seq > best) => {
                    highest = Some((seq, token));
                }
                Some(_) => {}
                None => unverified += 1,
            }
        }
        rows.push(ReportInstance {
            instance_id: *instance,
            highest_token: highest.map(|(_, token)| token),
            daemon_database: path.clone(),
            unverified_tokens: unverified,
            issue_next: pointers.issue_next,
            watermark: pointers.watermark,
            active_allocations,
        });
    }
    let faults = ledger
        .faults()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|(generation, kind, instance_id, token)| ReportFault {
            generation,
            kind,
            instance_id,
            token,
        })
        .collect();
    let failstop = super::compaction::failstop_latched(config).map_err(|e| e.to_string())?;
    let mut report = InventoryReport {
        schema: REPORT_SCHEMA.into(),
        node_id: ledger.node_id(),
        ledger_generation: ledger.generation().map_err(|e| e.to_string())?,
        faults,
        failstop,
        instances: rows,
        verdict: if unexplained.is_empty() {
            "explained".into()
        } else {
            "unexplained".into()
        },
        unexplained,
        report_sha256: Digest::of(b""),
    };
    report.report_sha256 = report.body_digest()?;
    Ok(report)
}

fn write_report(policy: &WalkPolicy, path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("the report path has no directory")?;
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or("the report path has no file name")?;
    let directory = walk_directory(policy, parent).map_err(|e| e.to_string())?;
    let name = CString::new(name).map_err(|_| "report name contains NUL")?;
    // SAFETY: directory and name are live; O_EXCL refuses an existing entry and
    // O_NOFOLLOW a symlink.
    let fd = unsafe {
        libc::openat(
            directory.file().as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(format!("write the report: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: openat returned a new owned descriptor.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    use std::io::Write;
    (&file).write_all(bytes).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    directory.file().sync_all().map_err(|e| e.to_string())?;
    Ok(())
}

/// Reads a report through a protected walk: a single-link regular file owned by the
/// policy's owner (root) and writable by no one else, no symlink anywhere.
pub fn read_report(policy: &WalkPolicy, path: &Path) -> Result<InventoryReport, String> {
    let parent = path.parent().ok_or("the report path has no directory")?;
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or("the report path has no file name")?;
    let directory = walk_directory(policy, parent).map_err(|e| e.to_string())?;
    let raw = super::manifest::read_bounded(&directory, name, policy.owner_uid, MAX_REPORT_BYTES)?;
    InventoryReport::decode(&raw)
}

/// `kilnd-helper clear-node-faults`: the one path that deletes fault rows (RTC-14).
pub fn clear_node_faults(config: &LedgerConfig, report: &Path) -> Result<String, String> {
    let report = read_report(&config.policy, report)?;
    if report.verdict != "explained" || !report.unexplained.is_empty() {
        return Err("the inventory left resources unexplained; settle them and run it again".into());
    }
    if report.node_id != config.node_id {
        return Err("the report is for another node".into());
    }
    with_node_lock(config, |ledger| {
        let enrolled: BTreeSet<Id128> = ledger
            .instance_ids()
            .map_err(|e| e.to_string())?
            .into_iter()
            .collect();
        let named: BTreeSet<Id128> = report.instances.iter().map(|i| i.instance_id).collect();
        if enrolled != named {
            return Err("the report does not name exactly the enrolled instances".into());
        }
        let failstop = super::compaction::failstop_latched(config).map_err(|e| e.to_string())?;
        if failstop != report.failstop {
            return Err("the fail-stop marker changed since the inventory".into());
        }
        let generations: Vec<u64> = report.faults.iter().map(|f| f.generation).collect();
        let highest: Vec<(Id128, Option<Id128>)> = report
            .instances
            .iter()
            .map(|i| (i.instance_id, i.highest_token))
            .collect();
        let outcome = ledger
            .clear_node_faults(
                report.ledger_generation,
                &generations,
                &highest,
                report.report_sha256,
            )
            .map_err(|e| e.to_string())?;
        match outcome {
            ClearOutcome::Cleared {
                generation,
                cleared_through,
                raised,
            } => {
                if failstop {
                    super::compaction::write_failstop(config, false)
                        .map_err(|e| format!("the faults cleared, but the marker: {e}"))?;
                }
                Ok(serde_json::json!({
                    "cleared_generation": generation,
                    "cleared_through_generation": cleared_through,
                    "raised_pointers": serde_json::from_str::<Value>(&raw_or_empty(&raised))
                        .unwrap_or(Value::Null),
                    "failstop_reset": failstop,
                })
                .to_string())
            }
            ClearOutcome::Stale => Err(
                "the ledger changed since the inventory: run the inventory again".into(),
            ),
            ClearOutcome::Malformed { instance } => Err(format!(
                "instance {instance}'s reported token does not verify"
            )),
        }
    })
}

fn raw_or_empty(text: &str) -> String {
    if text.is_empty() { "[]".into() } else { text.into() }
}

/// `kilnd-helper ledger-stats`: per instance, the pointers, W, retained rows and the
/// last compaction (design 16.3 A, "operator repair and observability"). Read-only.
pub fn ledger_stats(config: &LedgerConfig) -> Result<String, String> {
    with_node_lock(config, |ledger| {
        let mut instances = Vec::new();
        for instance in ledger.instance_ids().map_err(|e| e.to_string())? {
            let snapshot = ledger
                .accounting(Some(instance))
                .map_err(|e| e.to_string())?;
            instances.push(serde_json::json!({
                "instance_id": instance.to_string(),
                "tokens": snapshot.tokens,
                "last_compaction": ledger.last_compaction(instance).map_err(|e| e.to_string())?,
            }));
        }
        let node = ledger.accounting(None).map_err(|e| e.to_string())?;
        Ok(serde_json::json!({
            "node_id": ledger.node_id().to_string(),
            "generation": node.generation,
            "retained_admitted_total": node.retained_admitted_total,
            "retained_never_admitted_total": node.retained_never_admitted_total,
            "admitted_entries": node.admitted_entries,
            "share": node.share,
            "share_shortfall": node.share_shortfall,
            "node_fault": node.node_fault,
            "instances": instances,
        })
        .to_string())
    })
}
