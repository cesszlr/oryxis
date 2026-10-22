use super::*;
use crate::mcp_consent::{Decision, SudoRequest};
use uuid::Uuid;

fn request() -> SudoRequest {
    SudoRequest {
        id: SudoRequest::new_id().unwrap(),
        vault_id: Uuid::new_v4(),
        vault_label: "Personal".into(),
        host_id: Uuid::new_v4(),
        host_label: "web".into(),
        login: "deploy".into(),
        address: "10.0.0.5:22".into(),
        route: Vec::new(),
        client: None,
        command: "id".into(),
        created_unix: 0,
    }
}

#[test]
fn two_handles_on_one_file_agree_on_the_tag() {
    // The app and `oryxis-mcp` each open the vault file on their own:
    // the tag one makes is the tag the other checks.
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_path_buf();
    let mut app = VaultStore::open(&path).unwrap();
    app.set_master_password("testpass123").unwrap();
    let mut mcp = VaultStore::open(&path).unwrap();
    mcp.unlock("testpass123").unwrap();

    let r = request();
    let tag = app.mcp_consent_tag(&r, Decision::Session).unwrap();
    assert!(mcp.verify_mcp_consent_tag(&r, Decision::Session, &tag));
}

#[test]
fn a_tag_answers_one_decision_on_one_request() {
    let vault = unlocked_vault();
    let r = request();
    let tag = vault.mcp_consent_tag(&r, Decision::Once).unwrap();
    assert!(vault.verify_mcp_consent_tag(&r, Decision::Once, &tag));
    // "Once" does not stretch to the whole session.
    assert!(!vault.verify_mcp_consent_tag(&r, Decision::Session, &tag));
    // Nor to another request, another host or another vault.
    let mut other = r.clone();
    other.id = SudoRequest::new_id().unwrap();
    assert!(!vault.verify_mcp_consent_tag(&other, Decision::Once, &tag));
    let mut other = r.clone();
    other.host_id = Uuid::new_v4();
    assert!(!vault.verify_mcp_consent_tag(&other, Decision::Once, &tag));
    let mut other = r.clone();
    other.vault_id = Uuid::new_v4();
    assert!(!vault.verify_mcp_consent_tag(&other, Decision::Once, &tag));
}

#[test]
fn another_vaults_key_does_not_verify() {
    let a = unlocked_vault();
    let b = unlocked_vault();
    let r = request();
    let tag = a.mcp_consent_tag(&r, Decision::Once).unwrap();
    assert!(!b.verify_mcp_consent_tag(&r, Decision::Once, &tag));
}

#[test]
fn forged_or_malformed_tags_never_allow() {
    let vault = unlocked_vault();
    let r = request();
    for tag in ["", "00", "zz", &"0".repeat(64), "not hex at all"] {
        assert!(!vault.verify_mcp_consent_tag(&r, Decision::Once, tag), "{tag:?}");
    }
}

#[test]
fn a_locked_vault_neither_tags_nor_verifies() {
    let mut vault = unlocked_vault();
    let r = request();
    let tag = vault.mcp_consent_tag(&r, Decision::Once).unwrap();
    vault.lock();
    assert!(matches!(vault.mcp_consent_tag(&r, Decision::Once), Err(VaultError::Locked)));
    assert!(!vault.verify_mcp_consent_tag(&r, Decision::Once, &tag));
}
