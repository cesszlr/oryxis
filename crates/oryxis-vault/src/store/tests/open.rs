//! `VaultStore::open`: the error names the step it failed at (issue
//! #250 arrived as "Failed to open vault database" and nothing else).

use super::*;

#[test]
fn a_file_that_is_not_a_database_fails_at_the_first_read_and_says_so() {
    let tmp = NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), b"this is not an SQLite file, by a long way\n").unwrap();
    let Err(err) = VaultStore::open(tmp.path()) else {
        panic!("garbage must not open");
    };
    match &err {
        VaultError::Open { step, source } => {
            assert_eq!(*step, "pragmas");
            assert!(
                matches!(**source, VaultError::Database(_)),
                "the cause is the engine's, got {source:?}"
            );
        }
        other => panic!("expected VaultError::Open, got {other:?}"),
    }
    let text = err.to_string();
    assert!(text.contains("pragmas"), "{text}");
    assert!(text.contains("not a database"), "{text}");
}

#[test]
fn the_session_log_size_migration_refuses_a_caller_transaction() {
    let vault = temp_vault();
    vault.db.execute_batch("BEGIN").unwrap();
    let err = vault.ensure_session_log_bytes().expect_err("must refuse");
    assert!(err.to_string().contains("session log sizes"), "{err}");
    assert!(err.to_string().contains("already open"), "{err}");
    vault.db.execute_batch("ROLLBACK").unwrap();
    // Outside a transaction it is idempotent.
    vault.ensure_session_log_bytes().unwrap();
    vault.ensure_session_log_bytes().unwrap();
}

#[test]
fn open_error_display_carries_the_step_and_the_cause() {
    let err = VaultError::Open {
        step: "schema",
        source: Box::new(VaultError::Database("session log sizes, begin: database is locked".into())),
    };
    assert_eq!(
        err.to_string(),
        "Could not open the vault at step \"schema\": Database error: session log sizes, begin: database is locked"
    );
}
