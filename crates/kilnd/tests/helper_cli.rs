//! kilnd-helper's command line, as a process: every command, `create-timings` included,
//! is root's alone, and an unprivileged caller is refused before anything is read.
// Approved (design 7.1): test fixtures, an integration-test crate. It runs the built
// kilnd-helper binary as this unprivileged test's own subprocess.
#![allow(clippy::disallowed_methods)]

use std::io::Write;
use std::process::{Command, Output, Stdio};

const HELPER: &str = env!("CARGO_BIN_EXE_kilnd-helper");
const ID: &str = "0123456789abcdef0123456789abcdef";
const MISSING: &str = "/nonexistent/kilnd-helper-cli-test";

/// A timing line `create-timings` would report on, if it ever ran.
fn timing_line() -> String {
    format!(
        "kilnd-helper: create timing v1 {{\"allocation\":\"{ID}\",\"outcome\":\"ready\",\
         \"steps\":[{{\"n\":\"l.issue\",\"s\":0,\"e\":1000}}]}}\n"
    )
}

fn run(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(HELPER)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A refused command may exit before reading any of it.
    let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
    child.wait_with_output().unwrap()
}

/// The subcommands `--help` lists, which clap prints before any check of the caller.
fn listed_commands() -> Vec<String> {
    let help = run(&["--help"], "");
    assert!(help.status.success(), "{help:?}");
    let text = String::from_utf8(help.stdout).unwrap();
    text.lines()
        .skip_while(|line| !line.starts_with("Commands:"))
        .skip(1)
        .take_while(|line| line.starts_with("  "))
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| *name != "help")
        .map(str::to_string)
        .collect()
}

#[test]
fn every_root_command_refuses_an_unprivileged_caller() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: this test needs an unprivileged caller");
        return;
    }
    // (subcommand, its arguments). An empty name is serving, the default.
    let cases: &[(&str, &[&str])] = &[
        ("", &[]),
        (
            "",
            &["--firecracker-policy", MISSING, "--firecracker-init-ledger"],
        ),
        ("enroll", &["--instance", ID, "--unit", "kilnd.service"]),
        ("enrollments", &[]),
        ("refresh-enrollments", &["--check"]),
        (
            "offline-inventory",
            &["--daemon-db", "0123456789abcdef0123456789abcdef=/x", "--report", MISSING],
        ),
        ("clear-node-faults", &["--report", MISSING]),
        ("ledger-stats", &[]),
        ("create-timings", &[]),
        ("create-timings", &["--last", "5", "--summary"]),
        ("create-timings", &["--allocation", ID]),
        ("restore-enrollments", &["--snapshot", MISSING]),
    ];
    let mut covered: Vec<String> = cases
        .iter()
        .filter(|(name, _)| !name.is_empty())
        .map(|(name, _)| name.to_string())
        .collect();
    covered.dedup();
    let mut listed = listed_commands();
    listed.sort();
    covered.sort();
    assert_eq!(listed, covered, "every listed command has a case here");

    for (name, args) in cases {
        let mut argv: Vec<&str> = Vec::new();
        if !name.is_empty() {
            argv.push(name);
        }
        argv.extend_from_slice(args);
        // The log a report would read: refused, none of it reaches standard output.
        let out = run(&argv, &timing_line());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{argv:?} ran unprivileged: {out:?}");
        assert!(
            stderr.contains("kilnd-helper must run as root"),
            "{argv:?}: {stderr}"
        );
        assert!(out.stdout.is_empty(), "{argv:?} printed: {out:?}");
    }
}
