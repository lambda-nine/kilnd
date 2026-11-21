//! Schema 17's triggers against direct SQL: only the insert of a matching audit row
//! releases an ambiguous reservation, the audit is append-only, and every transition
//! schemas 8-16 forbid stays forbidden.

use std::collections::BTreeMap;

use super::*;
use crate::model::{Network, new_id};

fn sandbox() -> Sandbox {
    let spec = SandboxSpec {
        image: "alpine".into(),
        memory_bytes: 1 << 29,
        cpu_millis: 1000,
        pids: 128,
        disk_bytes: 1 << 30,
        network: Network::None,
        read_only_root: false,
        writable_paths: vec![],
        labels: BTreeMap::new(),
    };
    let now = now_ms();
    Sandbox {
        id: new_id("sb"),
        state: SandboxState::Creating,
        accounting: SandboxAccounting::legacy(&spec, ""),
        spec,
        backend: "fake".into(),
        backend_id: None,
        created_at_ms: now,
        updated_at_ms: now,
        deleted_at_ms: None,
        failure_reason: None,
        create_certainty: CreateCertainty::AllocationAmbiguous,
        owner_uid: 1000,
        lifecycle: Default::default(),
    }
}

/// A charged ambiguous FAILED legacy row with no backend ID.
fn ambiguous(store: &Store) -> Sandbox {
    let s = sandbox();
    store.insert_sandbox(&s).unwrap();
    store
        .set_sandbox_state(&s.id, SandboxState::Failed, None, Some("kiln exited 1"))
        .unwrap();
    let row = store.sandbox(&s.id).unwrap().unwrap();
    assert!(row.is_charged());
    row
}

const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// The audit insert for `row`, with `column = value` overriding one field.
fn audit_insert(
    conn: &Connection,
    row: &Sandbox,
    column: &str,
    value: &str,
) -> rusqlite::Result<usize> {
    let r = row.accounting.reservation;
    let mut fields: Vec<(&str, String)> = vec![
        ("sandbox_id", format!("'{}'", row.id)),
        ("owner_uid", row.owner_uid.to_string()),
        ("released_sandboxes", "1".into()),
        ("released_host_cpu_millis", r.host_cpu_millis.to_string()),
        ("released_memory_bytes", r.memory_bytes.to_string()),
        ("released_pids", r.pids.to_string()),
        ("released_disk_bytes", r.disk_bytes.to_string()),
        (
            "released_virtual_cpu_slots",
            r.virtual_cpu_slots.to_string(),
        ),
        ("released_host_pids", r.host_pids.to_string()),
        ("operator_uid", "0".into()),
        ("released_at_ms", now_ms().to_string()),
        ("reason", "'proved clean'".into()),
        ("inventory_sha256", format!("'{SHA}'")),
    ];
    if !column.is_empty() {
        fields.iter_mut().find(|(c, _)| *c == column).unwrap().1 = value.into();
    }
    let (columns, values): (Vec<&str>, Vec<String>) = fields.into_iter().unzip();
    conn.execute(
        &format!(
            "INSERT INTO operator_releases ({}) VALUES ({})",
            columns.join(", "),
            values.join(", ")
        ),
        [],
    )
}

fn tag(conn: &Connection, id: &str) -> Option<String> {
    conn.query_row(
        "SELECT legacy_release FROM sandboxes WHERE id = ?1",
        [id],
        |r| r.get(0),
    )
    .unwrap()
}

fn audited(conn: &Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM operator_releases", [], |r| r.get(0))
        .unwrap()
}

#[test]
fn nothing_but_a_matching_audit_row_writes_operator_attested() {
    let store = Store::open_in_memory().unwrap();
    let row = ambiguous(&store);
    let charged = store.sandbox_resources().unwrap();
    {
        let conn = store.conn();
        for direct in [
            "UPDATE sandboxes SET legacy_release = 'operator_attested' WHERE id = ?1",
            "UPDATE sandboxes SET legacy_release = 'operator_attested', updated_at_ms = updated_at_ms + 1 WHERE id = ?1",
            "UPDATE sandboxes SET state = 'deleted', legacy_release = 'operator_attested' WHERE id = ?1",
        ] {
            let e = conn.execute(direct, [&row.id]).unwrap_err().to_string();
            assert!(
                e.contains("operator release") || e.contains("CHECK"),
                "{direct}: {e}"
            );
        }
        // An insert can't carry the tag either.
        conn.execute_batch(&format!(
            "CREATE TEMP TABLE copy AS SELECT * FROM sandboxes WHERE id = '{}';
             UPDATE copy SET id = '{}', list_seq = list_seq + 1000, legacy_release = 'operator_attested';",
            row.id,
            new_id("sb")
        ))
        .unwrap();
        let e = conn
            .execute("INSERT INTO sandboxes SELECT * FROM copy", [])
            .unwrap_err()
            .to_string();
        assert!(e.contains("operator release"), "{e}");

        // The audit row must name the row's owner and every exact charge.
        for (column, value) in [
            ("owner_uid", "1001"),
            ("released_sandboxes", "2"),
            ("released_host_cpu_millis", "1"),
            ("released_memory_bytes", "1"),
            ("released_pids", "1"),
            ("released_disk_bytes", "1"),
            ("released_virtual_cpu_slots", "1"),
            ("released_host_pids", "1"),
            ("sandbox_id", "'sb-0000000000000000'"),
            // A bounded, control-free reason and a hex digest.
            ("reason", "''"),
            ("reason", "'   '"),
            ("reason", "'tab' || char(9) || 'here'"),
            ("reason", "'line' || char(10) || 'break'"),
            ("reason", "'caf' || char(233)"),
            ("reason", "printf('%.513c', 'x')"),
            ("reason", "x'61'"),
            ("inventory_sha256", "'0123'"),
            ("inventory_sha256", &format!("'{}'", SHA.to_uppercase())),
            ("operator_uid", "-1"),
            ("released_at_ms", "'now'"),
        ] {
            assert!(
                audit_insert(&conn, &row, column, value).is_err(),
                "{column} = {value}"
            );
        }
        assert_eq!(tag(&conn, &row.id), None);
        assert_eq!(audited(&conn), 0);
    }
    assert_eq!(store.sandbox_resources().unwrap(), charged);

    // The matching insert is the release, in its own statement.
    let reason_at_the_limit = format!("'{}'", "x".repeat(MAX_RELEASE_REASON_BYTES));
    audit_insert(&store.conn(), &row, "reason", &reason_at_the_limit).unwrap();
    {
        let conn = store.conn();
        assert_eq!(tag(&conn, &row.id).as_deref(), Some("operator_attested"));
        let noted: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM reservation_unsettled WHERE id = ?1",
                [&row.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            noted, 1,
            "the release is noted for settlement like any other"
        );
    }
    let released = store.sandbox(&row.id).unwrap().unwrap();
    assert_eq!(
        released.accounting.release,
        ReservationRelease::Legacy(LegacyRelease::OperatorAttested)
    );
    assert_eq!(
        store.sandbox_resources().unwrap().sandboxes,
        charged.sandboxes - 1
    );
}

#[test]
fn only_a_charged_ambiguous_failed_legacy_row_without_a_backend_can_be_audited() {
    let store = Store::open_in_memory().unwrap();
    let creating = sandbox();
    store.insert_sandbox(&creating).unwrap();
    let ready = sandbox();
    store.insert_sandbox(&ready).unwrap();
    store
        .set_sandbox_state(&ready.id, SandboxState::Ready, Some("f00d-ready"), None)
        .unwrap();
    let compensated = sandbox();
    store.insert_sandbox(&compensated).unwrap();
    store
        .set_sandbox_state(
            &compensated.id,
            SandboxState::Failed,
            Some("f00d-gone"),
            None,
        )
        .unwrap();
    let definite = sandbox();
    store.insert_sandbox(&definite).unwrap();
    store
        .fail_create_definitely(&definite.id, "image missing")
        .unwrap();
    let lost = sandbox();
    store.insert_sandbox(&lost).unwrap();
    store
        .set_sandbox_state(&lost.id, SandboxState::Lost, None, Some("lost"))
        .unwrap();
    let conn = store.conn();
    for (name, s) in [
        ("creating", &creating),
        ("ready", &ready),
        ("compensated", &compensated),
        ("definitely not created", &definite),
        ("lost without an ID", &lost),
    ] {
        let e = audit_insert(&conn, s, "", "").unwrap_err().to_string();
        assert!(
            e.contains("names a charged ambiguous FAILED"),
            "{name}: {e}"
        );
    }
    assert_eq!(audited(&conn), 0);
    // An absence-fenced row can't carry a legacy tag at all (schema 8's CHECK), and
    // no row changes regime.
    let e = conn
        .execute(
            "UPDATE sandboxes SET accounting_kind = 'fenced' WHERE id = ?1",
            [&creating.id],
        )
        .unwrap_err()
        .to_string();
    assert!(e.contains("immutable"), "{e}");
}

#[test]
fn the_audit_is_append_only_and_the_release_permanent() {
    let store = Store::open_in_memory().unwrap();
    let row = ambiguous(&store);
    audit_insert(&store.conn(), &row, "", "").unwrap();
    let conn = store.conn();
    for statement in [
        "UPDATE operator_releases SET reason = 'edited'",
        "UPDATE operator_releases SET released_memory_bytes = 0",
        "DELETE FROM operator_releases",
    ] {
        let e = conn.execute(statement, []).unwrap_err().to_string();
        assert!(e.contains("append-only"), "{statement}: {e}");
    }
    // Recorded once: a second insert, plain or OR REPLACE, aborts in a BEFORE trigger
    // before any conflict resolution could replace the first.
    for or in ["", "OR REPLACE "] {
        let e = conn
            .execute(
                &format!("INSERT {or}INTO operator_releases SELECT * FROM operator_releases"),
                [],
            )
            .unwrap_err()
            .to_string();
        // Either BEFORE trigger may fire first; both refuse.
        assert!(
            e.contains("recorded once") || e.contains("names a charged ambiguous"),
            "{or}: {e}"
        );
    }
    assert_eq!(audited(&conn), 1);
    // The released row is never charged again, and acquires no other provenance.
    for laundering in [
        "UPDATE sandboxes SET legacy_release = NULL WHERE id = ?1",
        "UPDATE sandboxes SET legacy_release = 'definitely_not_created' WHERE id = ?1",
        "UPDATE sandboxes SET create_certainty = 'definitely_not_created', legacy_release = 'definitely_not_created' WHERE id = ?1",
        "UPDATE sandboxes SET backend_id = 'f00d', legacy_release = 'compensated' WHERE id = ?1",
        "UPDATE sandboxes SET backend_id = 'f00d' WHERE id = ?1",
        "UPDATE sandboxes SET state = 'ready' WHERE id = ?1",
        "UPDATE sandboxes SET state = 'creating' WHERE id = ?1",
        "UPDATE sandboxes SET state = 'deleted' WHERE id = ?1",
        "UPDATE sandboxes SET owner_uid = 0 WHERE id = ?1",
        "UPDATE sandboxes SET reserved_memory_bytes = 0 WHERE id = ?1",
    ] {
        assert!(conn.execute(laundering, [&row.id]).is_err(), "{laundering}");
    }
    assert_eq!(tag(&conn, &row.id).as_deref(), Some("operator_attested"));
    // A schema 8 release of a still-charged row by tag alone stays forbidden too.
    drop(conn);
    let other = ambiguous(&store);
    let conn = store.conn();
    for laundering in [
        "UPDATE sandboxes SET legacy_release = 'definitely_not_created' WHERE id = ?1",
        "UPDATE sandboxes SET legacy_release = 'compensated' WHERE id = ?1",
        "UPDATE sandboxes SET state = 'deleted', legacy_release = 'deleted' WHERE id = ?1",
        "DELETE FROM sandboxes WHERE id = ?1",
    ] {
        assert!(
            conn.execute(laundering, [&other.id]).is_err(),
            "{laundering}"
        );
    }
}

#[test]
fn a_released_row_deletes_and_prunes_but_its_id_and_audit_stay() {
    let store = Store::open_in_memory().unwrap();
    let row = ambiguous(&store);
    store
        .release_ambiguous_by_operator(&OperatorRelease {
            sandbox_id: &row.id,
            operator_uid: 0,
            reason: "proved clean",
            inventory_sha256: SHA,
        })
        .unwrap();
    // The legacy transition keeps the tag through a FAILED rewrite and takes
    // `deleted` at DELETED, as for any released FAILED row.
    store
        .set_sandbox_state(&row.id, SandboxState::Failed, None, Some("again"))
        .unwrap();
    assert_eq!(
        tag(&store.conn(), &row.id).as_deref(),
        Some("operator_attested")
    );
    store
        .set_sandbox_state(&row.id, SandboxState::Deleted, None, None)
        .unwrap();
    assert_eq!(tag(&store.conn(), &row.id).as_deref(), Some("deleted"));
    let conn = store.conn();
    conn.execute_batch(&format!(
        "CREATE TEMP TABLE copy AS SELECT * FROM sandboxes WHERE id = '{}';",
        row.id
    ))
    .unwrap();
    conn.execute("DELETE FROM sandboxes WHERE id = ?1", [&row.id])
        .unwrap();
    assert_eq!(audited(&conn), 1, "the audit outlives the row's prune");
    // The audit row's ID can never name a second row.
    conn.execute_batch(
        "UPDATE copy SET state = 'failed', legacy_release = NULL, deleted_at_ms = NULL;",
    )
    .unwrap();
    let e = conn
        .execute("INSERT INTO sandboxes SELECT * FROM copy", [])
        .unwrap_err()
        .to_string();
    assert!(e.contains("one row that had its ID"), "{e}");
}

#[test]
fn the_typed_release_refuses_what_the_triggers_refuse_and_writes_nothing() {
    let store = Store::open_in_memory().unwrap();
    let release = |id: &str, reason: &str| {
        store.release_ambiguous_by_operator(&OperatorRelease {
            sandbox_id: id,
            operator_uid: 0,
            reason,
            inventory_sha256: SHA,
        })
    };
    assert!(matches!(
        release(&new_id("sb"), "why"),
        Err(OperatorReleaseError::NoSandbox)
    ));
    let row = ambiguous(&store);
    assert!(matches!(
        release(&row.id, "bad\u{7f}reason"),
        Err(OperatorReleaseError::Ineligible(_))
    ));
    assert_eq!(audited(&store.conn()), 0);
    let released = release(&row.id, "why").unwrap();
    assert_eq!(released.owner_uid, 1000);
    assert_eq!(released.reservation, row.accounting.reservation);
    assert!(matches!(
        release(&row.id, "why"),
        Err(OperatorReleaseError::Ineligible(why)) if why.contains("already released")
    ));
    let stored: (u32, i64, i64, String, String) = store
        .conn()
        .query_row(
            "SELECT owner_uid, released_sandboxes, released_memory_bytes, reason, inventory_sha256 FROM operator_releases",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap();
    assert_eq!(
        stored,
        (1000, 1, 1 << 29, "why".to_string(), SHA.to_string())
    );
    assert_eq!(store.operator_release_count().unwrap(), 1);
}
