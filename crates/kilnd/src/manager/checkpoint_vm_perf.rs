//! Checkpoint milestone C6b: the performance harness (design 11.2, the C6 perf report),
//! against the installed kiln on the prepared VM. Root only; run by
//! `scripts/checkpoint-crash-matrix.py --set perf` with `KILND_C6B_PERF` naming the
//! phase (`warm`, `cold`, `extra`) and `KILND_C6B_PERF_OUT` a directory for the CSVs:
//!
//! - **warm**: capture (CheckpointSandbox round trip) and fork (Create
//!   `from_checkpoint` to READY) over 10/50/100 MiB × 100/10k/50k entries;
//! - **cold**: the same three diagonal cells with the page cache dropped before each;
//! - **extra**: a 960 MiB sparse file and 50,000 empty files with user xattrs; two
//!   simultaneous workers (two captures, capture + fork) against one idle; the helper's
//!   Capabilities round trip; Health with the feature on and off.
//!
//! Latencies are measured inside the rpc child around the one call, so process start is
//! not in them. Each capture row also has the helper's own CPU, the workers' (the
//! helper's reaped children's) user and system CPU, the largest worker RSS seen by a
//! 20 ms poll, R, S, the artifact's physical blocks and inodes, the fork's upper's
//! physical blocks, a `sha256sum` reference over the same bytes, and device flushes
//! (count and milliseconds, `/sys/block/*/stat` fields 16–17) on `loop0` and `vda`
//! across the call: these count every flush the guest issued in the interval.
//!
//! A phase stops a cell early, and records it, once `KILND_C6B_PERF_UNTIL` (Unix
//! seconds) is near, so a VM window's restore starts on time.

use std::io::Write as _;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::harness::*;

fn run<F: std::future::Future<Output = ()>>(f: F) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f);
}

const MIB: u64 = 1 << 20;
const STRANGER: u32 = 1001;

fn deadline() -> Option<u64> {
    std::env::var("KILND_C6B_PERF_UNTIL").ok()?.parse().ok()
}

fn out_dir() -> PathBuf {
    PathBuf::from(std::env::var("KILND_C6B_PERF_OUT").expect("KILND_C6B_PERF_OUT"))
}

/// Seconds left before the phase must stop.
fn left() -> i64 {
    match deadline() {
        Some(until) => until as i64 - crate::model::now_ms() / 1000,
        None => i64::MAX,
    }
}

/// `utime + stime` and `cutime`, `cstime` of a pid, in clock ticks.
fn cpu(pid: u32) -> (u64, u64, u64) {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    let f: Vec<u64> = stat
        .rsplit_once(')')
        .map(|(_, r)| r.split_whitespace().map(|x| x.parse().unwrap_or(0)).collect())
        .unwrap_or_default();
    let g = |i: usize| f.get(i).copied().unwrap_or(0);
    // After the ')': state is 0, utime 11, stime 12, cutime 13, cstime 14.
    (g(11) + g(12), g(13), g(14))
}

fn ticks_ms(t: u64) -> u64 {
    // SAFETY: no preconditions.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
    t * 1000 / hz
}

/// (flushes completed, milliseconds flushing) of a block device.
fn flushes(dev: &str) -> (u64, u64) {
    let s = std::fs::read_to_string(format!("/sys/block/{dev}/stat")).unwrap_or_default();
    let f: Vec<u64> = s.split_whitespace().map(|x| x.parse().unwrap_or(0)).collect();
    (f.get(15).copied().unwrap_or(0), f.get(16).copied().unwrap_or(0))
}

/// Physical bytes and inodes under a directory (no link followed).
fn physical(dir: &Path) -> (u64, u64) {
    let (mut bytes, mut inodes) = (0, 0);
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.filter_map(Result::ok) {
            let Ok(m) = std::fs::symlink_metadata(e.path()) else {
                continue;
            };
            bytes += m.blocks() * 512;
            inodes += 1;
            if m.is_dir() {
                stack.push(e.path());
            }
        }
    }
    (bytes, inodes)
}

/// The run's raw upper, by a marker written from inside (see the hostile set).
async fn upper(w: &World, id: &str, backend_id: &str) -> PathBuf {
    w.sh(id, "touch /root/c6b-perf-marker").await;
    let run = PathBuf::from(format!("{}/{backend_id}", super::RUNS));
    let runs_dev = std::fs::metadata(super::RUNS).unwrap().dev();
    let mut found = None;
    let mut stack = vec![(run, 0)];
    while let Some((dir, depth)) = stack.pop() {
        for e in std::fs::read_dir(&dir).into_iter().flatten().filter_map(Result::ok) {
            let p = e.path();
            let Ok(m) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if m.dev() != runs_dev {
                continue;
            }
            if p.ends_with("root/c6b-perf-marker") {
                found = Some(p.parent().unwrap().parent().unwrap().to_path_buf());
            } else if m.is_dir() && depth < 3 {
                stack.push((p, depth + 1));
            }
        }
    }
    w.sh(id, "rm -f /root/c6b-perf-marker").await;
    found.expect("the raw upper")
}

/// The source script for `bytes` spread over `entries` files under /root/p.
fn workspace(bytes: u64, entries: u64) -> String {
    format!(
        "mkdir -p /root/p && cd /root/p && head -c {bytes} /dev/urandom | split -b {} -a 5 - f && \
         m=$(({entries} - $(ls | wc -l))) && if [ $m -gt 0 ]; then seq 1 $m | sed 's/^/z/' | xargs touch; fi && \
         [ $(ls | wc -l) -eq {entries} ] && sync",
        bytes.div_ceil(entries)
    )
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let rank = (p * (sorted.len() - 1) as f64).round() as usize;
    sorted[rank.min(sorted.len() - 1)]
}

fn summary(values: &[f64]) -> Value {
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    json!({ "n": v.len(), "p50_ms": percentile(&v, 0.5), "p95_ms": percentile(&v, 0.95) })
}

struct Csv(std::fs::File);

impl Csv {
    fn new(name: &str, header: &str) -> Self {
        let mut f = std::fs::File::create(out_dir().join(name)).unwrap();
        writeln!(f, "{header}").unwrap();
        Self(f)
    }
    fn row(&mut self, fields: &[String]) {
        writeln!(self.0, "{}", fields.join(",")).unwrap();
    }
}

const CAPTURE_HEADER: &str = "phase,cell_mib,cell_entries,run,capture_ms,fork_ms,helper_cpu_ms,worker_user_ms,worker_sys_ms,worker_max_rss_kib,charged_r,sealed_s,logical,allocated,entries,artifact_physical,artifact_inodes,fork_upper_physical,sha256sum_ref_ms,loop0_flushes,loop0_flush_ms,vda_flushes,vda_flush_ms";

/// One capture and fork of a prepared source, with every measured column.
async fn measure(w: &World, src: &str, phase: &str, cell: (u64, u64), run: usize, cold: bool, reference: &Path) -> Vec<String> {
    if cold {
        let _ = std::process::Command::new("sync").status();
        std::fs::write("/proc/sys/vm/drop_caches", "3\n").unwrap();
    }
    let helper = w.helper.as_ref().unwrap().pid as u32;
    let (h0, cu0, cs0) = cpu(helper);
    let (l0, v0) = (flushes("loop0"), flushes("vda"));
    let pending = {
        let (api, id) = (w.api.clone(), src.to_string());
        tokio::spawn(async move {
            rpc(&api, OWNER, json!({ "op": "capture", "id": id, "lifetime_ms": 3_600_000 })).await
        })
    };
    let mut rss = 0u64;
    while !pending.is_finished() {
        for (pid, _) in w.workers() {
            if descends_from(pid, helper) {
                let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
                if let Some(kib) = status
                    .lines()
                    .find_map(|l| l.strip_prefix("VmHWM:"))
                    .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
                {
                    rss = rss.max(kib);
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let r = pending.await.unwrap();
    let (h1, cu1, cs1) = cpu(helper);
    let (l1, v1) = (flushes("loop0"), flushes("vda"));
    let c = ok(&r).clone();
    let cp = c["id"].as_str().unwrap().to_string();
    let capture_ms = r["elapsed_us"].as_f64().unwrap() / 1000.0;
    let artifact = physical(&PathBuf::from(format!("{}/{}", super::CPS, w.instance)));
    // The digest reference: sha256sum over the same file bytes, its CPU from rusage.
    let ref_ms = {
        // SAFETY: plain getrusage into a zeroed struct.
        let usage = || unsafe {
            let mut u: libc::rusage = std::mem::zeroed();
            libc::getrusage(libc::RUSAGE_CHILDREN, &mut u);
            u.ru_utime.tv_sec as f64 * 1000.0 + u.ru_utime.tv_usec as f64 / 1000.0
        };
        let before = usage();
        let ok = std::process::Command::new("sh")
            .arg("-c")
            .arg("find . -type f -exec cat {} + | sha256sum >/dev/null")
            .current_dir(reference)
            .status()
            .unwrap();
        assert!(ok.success());
        usage() - before
    };
    let f = w
        .rpc(OWNER, json!({ "op": "create", "from_checkpoint": cp, "disk_bytes": 1u64 << 30 }))
        .await;
    let fork_ms = f["elapsed_us"].as_f64().unwrap() / 1000.0;
    let fork = ok(&f).clone();
    let fid = fork["id"].as_str().unwrap().to_string();
    let fork_upper = physical(&upper(w, &fid, fork["backend_id"].as_str().unwrap()).await.join("root"));
    w.ok(json!({ "op": "delete", "id": fid })).await;
    w.ok(json!({ "op": "delete_checkpoint", "id": cp })).await;
    vec![
        phase.into(),
        cell.0.to_string(),
        cell.1.to_string(),
        run.to_string(),
        format!("{capture_ms:.1}"),
        format!("{fork_ms:.1}"),
        ticks_ms(h1 - h0).to_string(),
        ticks_ms(cu1 - cu0).to_string(),
        ticks_ms(cs1 - cs0).to_string(),
        rss.to_string(),
        c["max_size_bytes"].to_string(),
        c["size_bytes"].to_string(),
        c["logical_bytes"].to_string(),
        c["allocated_bytes"].to_string(),
        w.cp_col(&cp, "entry_count"),
        artifact.0.to_string(),
        artifact.1.to_string(),
        fork_upper.0.to_string(),
        format!("{ref_ms:.1}"),
        (l1.0 - l0.0).to_string(),
        (l1.1 - l0.1).to_string(),
        (v1.0 - v0.0).to_string(),
        (v1.1 - v0.1).to_string(),
    ]
}

/// One grid cell: a source, `runs` measured capture-and-fork pairs; their latencies.
async fn cell(w: &World, csv: &mut Csv, phase: &str, mib: u64, entries: u64, runs: usize, cold: bool) -> Value {
    let s = w
        .ok(json!({ "op": "create", "disk_bytes": 2u64 << 30 }))
        .await;
    let src = s["id"].as_str().unwrap().to_string();
    let r = w
        .ok(json!({ "op": "exec", "id": src, "script": workspace(mib * MIB, entries), "timeout_ms": 1_200_000 }))
        .await;
    assert_eq!(r["exit_code"], 0, "{r}");
    let reference = upper(w, &src, s["backend_id"].as_str().unwrap()).await.join("root/p");
    let (mut captures, mut forks) = (Vec::new(), Vec::new());
    let mut stopped = false;
    for run in 0..runs {
        if left() < 120 {
            stopped = true;
            break;
        }
        let row = measure(w, &src, phase, (mib, entries), run, cold, &reference).await;
        captures.push(row[4].parse::<f64>().unwrap());
        forks.push(row[5].parse::<f64>().unwrap());
        csv.row(&row);
    }
    w.ok(json!({ "op": "delete", "id": src })).await;
    json!({ "mib": mib, "entries": entries, "capture": summary(&captures), "fork": summary(&forks),
            "stopped_early": stopped })
}

async fn warm(w: &World) -> Value {
    let mut csv = Csv::new("perf-warm.csv", CAPTURE_HEADER);
    let mut cells = Vec::new();
    for mib in [10, 50, 100] {
        for entries in [100, 10_000, 50_000] {
            cells.push(cell(w, &mut csv, "warm", mib, entries, 20, false).await);
        }
    }
    Value::Array(cells)
}

async fn cold(w: &World) -> Value {
    let mut csv = Csv::new("perf-cold.csv", CAPTURE_HEADER);
    let mut cells = Vec::new();
    for (mib, entries) in [(10, 100), (50, 10_000), (100, 50_000)] {
        cells.push(cell(w, &mut csv, "cold", mib, entries, 10, true).await);
    }
    Value::Array(cells)
}

/// Two calls at once by two uids, `runs` times; each call's latency.
async fn pair(w: &World, a: Value, b: Value, runs: usize) -> (Vec<f64>, Vec<f64>) {
    let (mut xs, mut ys) = (Vec::new(), Vec::new());
    for _ in 0..runs {
        if left() < 120 {
            break;
        }
        let (api1, api2) = (w.api.clone(), w.api.clone());
        let (a1, b1) = (a.clone(), b.clone());
        let (x, y) = tokio::join!(rpc(&api1, OWNER, a1), rpc(&api2, STRANGER, b1));
        xs.push(x["elapsed_us"].as_f64().unwrap() / 1000.0);
        ys.push(y["elapsed_us"].as_f64().unwrap() / 1000.0);
        for (r, uid) in [(&x, OWNER), (&y, STRANGER)] {
            let v = ok(r);
            if v["id"].as_str().is_some_and(|i| i.starts_with("cp-")) {
                rpc(&w.api, uid, json!({ "op": "delete_checkpoint", "id": v["id"] })).await;
            } else if v["id"].as_str().is_some_and(|i| i.starts_with("sb-")) {
                rpc(&w.api, uid, json!({ "op": "delete", "id": v["id"] })).await;
            }
        }
    }
    (xs, ys)
}

async fn extra(w: &World) -> Value {
    let mut csv = Csv::new("perf-extra.csv", CAPTURE_HEADER);
    let mut out = serde_json::Map::new();
    // Sparse: the largest logical size under the 1 GiB cap with its per-entry allowance.
    let s = w.ok(json!({ "op": "create", "disk_bytes": 2u64 << 30 })).await;
    let src = s["id"].as_str().unwrap().to_string();
    w.sh(&src, "mkdir -p /root/p && truncate -s 960M /root/p/sparse && printf end >> /root/p/sparse").await;
    let reference = upper(w, &src, s["backend_id"].as_str().unwrap()).await.join("root/p");
    let mut times = Vec::new();
    for run in 0..10 {
        if left() < 120 {
            break;
        }
        let row = measure(w, &src, "sparse-960m", (960, 1), run, false, &reference).await;
        times.push(row[4].parse::<f64>().unwrap());
        csv.row(&row);
    }
    out.insert("sparse_960m_capture".into(), summary(&times));
    w.ok(json!({ "op": "delete", "id": src })).await;
    // Metadata-heavy: 50,000 empty files, each with one user xattr planted by root.
    let s = w.ok(json!({ "op": "create", "disk_bytes": 2u64 << 30 })).await;
    let src = s["id"].as_str().unwrap().to_string();
    w.sh(&src, "mkdir -p /root/p && cd /root/p && seq 1 50000 | sed 's/^/e/' | xargs touch").await;
    let reference = upper(w, &src, s["backend_id"].as_str().unwrap()).await.join("root/p");
    for e in std::fs::read_dir(&reference).unwrap().filter_map(Result::ok) {
        let p = std::ffi::CString::new(e.path().as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: live C strings and buffer.
        let rc = unsafe { libc::lsetxattr(p.as_ptr(), c"user.c6b".as_ptr(), b"v".as_ptr().cast(), 1, 0) };
        assert_eq!(rc, 0);
    }
    let mut times = Vec::new();
    for run in 0..10 {
        if left() < 120 {
            break;
        }
        let row = measure(w, &src, "xattr-50k", (0, 50_000), run, false, &reference).await;
        times.push(row[4].parse::<f64>().unwrap());
        csv.row(&row);
    }
    out.insert("xattr_50k_capture".into(), summary(&times));
    w.ok(json!({ "op": "delete", "id": src })).await;
    // Two workers: 50 MiB / 10k sources for each uid.
    let mine = w.source(2 << 30, &workspace(50 * MIB, 10_000)).await;
    let theirs = ok(&w.rpc(STRANGER, json!({ "op": "create", "disk_bytes": 2u64 << 30 })).await)["id"]
        .as_str()
        .unwrap()
        .to_string();
    let r = w
        .rpc(STRANGER, json!({ "op": "exec", "id": theirs, "script": workspace(50 * MIB, 10_000), "timeout_ms": 1_200_000 }))
        .await;
    assert_eq!(ok(&r)["exit_code"], 0);
    let cap = |id: &str| json!({ "op": "capture", "id": id, "lifetime_ms": 3_600_000 });
    let mut idle = Vec::new();
    for _ in 0..20 {
        if left() < 120 {
            break;
        }
        let r = w.rpc(OWNER, cap(&mine)).await;
        idle.push(r["elapsed_us"].as_f64().unwrap() / 1000.0);
        w.ok(json!({ "op": "delete_checkpoint", "id": ok(&r)["id"] })).await;
    }
    let (a, b) = pair(w, cap(&mine), cap(&theirs), 20).await;
    let seeded = ok(&w.rpc(STRANGER, cap(&theirs)).await)["id"].as_str().unwrap().to_string();
    let fork = json!({ "op": "create", "from_checkpoint": seeded, "disk_bytes": 1u64 << 30 });
    let (c, f) = pair(w, cap(&mine), fork, 20).await;
    w.rpc(STRANGER, json!({ "op": "delete_checkpoint", "id": seeded })).await;
    w.rpc(STRANGER, json!({ "op": "delete", "id": theirs })).await;
    w.ok(json!({ "op": "delete", "id": mine })).await;
    out.insert(
        "two_workers_50m_10k".into(),
        json!({ "idle_capture": summary(&idle), "two_captures_owner": summary(&a),
                "two_captures_other": summary(&b), "capture_with_fork_capture": summary(&c),
                "capture_with_fork_fork": summary(&f) }),
    );
    // The helper's Capabilities round trip, timed directly.
    let runtime = crate::runtime::kiln::KilnRuntime::with_helper_uid(w.helper_socket.clone(), 0);
    let mut caps = Vec::new();
    for _ in 0..200 {
        let t = Instant::now();
        crate::runtime::Runtime::checkpoint(
            &runtime,
            None,
            crate::checkpoint::wire::CheckpointOperation::Capabilities,
            tokio::time::Instant::now() + Duration::from_secs(5),
            &tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap();
        caps.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    out.insert("helper_capabilities".into(), summary(&caps));
    // Health with the feature on, and the helper calls each one caused.
    let mark = w.relay.mark();
    let mut on = Vec::new();
    for _ in 0..200 {
        on.push(w.rpc(OWNER, json!({ "op": "health" })).await["elapsed_us"].as_f64().unwrap() / 1000.0);
    }
    let calls = w.relay.seen()[mark..]
        .iter()
        .filter(|s| s.phase == Phase::Request)
        .count();
    out.insert("health_on".into(), json!({ "latency": summary(&on), "helper_requests_per_200": calls }));
    let mut csv = Csv::new("perf-latency.csv", "measure,run,ms");
    for (name, values) in [("helper_capabilities", &caps), ("health_on", &on), ("idle_capture", &idle),
                           ("two_captures_owner", &a), ("two_captures_other", &b),
                           ("capture_with_fork_capture", &c), ("capture_with_fork_fork", &f)] {
        for (i, v) in values.iter().enumerate() {
            csv.row(&[name.into(), i.to_string(), format!("{v:.2}")]);
        }
    }
    Value::Object(out)
}

/// Health with the feature off, on its own daemon (the comparison for `extra`).
async fn health_off(w: &mut World) -> Value {
    w.stop_daemon().await;
    w.daemon_args = json!({ "checkpoints_off": true });
    w.start_daemon().await;
    let mark = w.relay.mark();
    let mut off = Vec::new();
    for _ in 0..200 {
        off.push(w.rpc(OWNER, json!({ "op": "health" })).await["elapsed_us"].as_f64().unwrap() / 1000.0);
    }
    let calls = w.relay.seen()[mark..]
        .iter()
        .filter(|s| s.phase == Phase::Request)
        .count();
    let mut csv = Csv::new("perf-health-off.csv", "measure,run,ms");
    for (i, v) in off.iter().enumerate() {
        csv.row(&["health_off".into(), i.to_string(), format!("{v:.2}")]);
    }
    json!({ "latency": summary(&off), "helper_requests_per_200": calls })
}

#[test]
#[ignore = "root on the prepared VM: C6b perf"]
fn c6b_perf() {
    run(async {
        let phase = std::env::var("KILND_C6B_PERF").unwrap_or_else(|_| "warm".into());
        std::fs::create_dir_all(out_dir()).unwrap();
        let mut w = World::start(json!({})).await;
        let conditions = json!({
            "kernel": std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap().trim(),
            "cpus": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0),
            "meminfo": std::fs::read_to_string("/proc/meminfo").unwrap().lines().take(2).collect::<Vec<_>>(),
            "kiln": String::from_utf8_lossy(&std::process::Command::new(kiln_bin()).arg("--version").output().unwrap().stdout).trim(),
            "runs_mount": std::fs::read_to_string("/proc/self/mountinfo").unwrap().lines()
                .find(|l| l.contains(" /var/lib/kiln/runs ")).unwrap_or("").to_string(),
            "loadavg": std::fs::read_to_string("/proc/loadavg").unwrap().trim(),
        });
        let result = match phase.as_str() {
            "warm" => warm(&w).await,
            "cold" => cold(&w).await,
            "extra" => {
                let mut e = extra(&w).await;
                e["health_off"] = health_off(&mut w).await;
                e
            }
            other => panic!("unknown phase {other}"),
        };
        let out = json!({ "phase": phase, "conditions": conditions, "result": result });
        std::fs::write(out_dir().join(format!("perf-{phase}.json")), serde_json::to_string_pretty(&out).unwrap()).unwrap();
        matrix(&format!("perf {phase}"), out);
        w.finish().await;
    });
}
