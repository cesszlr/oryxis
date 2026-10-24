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

#[test]
fn the_tag_binds_every_field_the_person_reads() {
    // The app tags the request AS IT READ IT from the folder, the server
    // checks the tag against the request IT HOLDS. A process that can
    // write the folder (the agent's own shell) may rewrite the posted
    // file between the post and the claim; whatever it changes, the
    // dialog's approval must not carry over to the server's request.
    let vault = unlocked_vault();
    let r = request();
    let tag = vault.mcp_consent_tag(&r, Decision::Once).unwrap();
    assert!(vault.verify_mcp_consent_tag(&r, Decision::Once, &tag));

    let mut swapped_command = r.clone();
    swapped_command.command = "uptime".into();
    assert!(
        !vault.verify_mcp_consent_tag(&swapped_command, Decision::Once, &tag),
        "an approval of \"id\" must not run another command"
    );
    let mut swapped_login = r.clone();
    swapped_login.login = "root".into();
    assert!(!vault.verify_mcp_consent_tag(&swapped_login, Decision::Once, &tag));
    let mut swapped_address = r.clone();
    swapped_address.address = "10.0.0.6:22".into();
    assert!(!vault.verify_mcp_consent_tag(&swapped_address, Decision::Once, &tag));
    let mut swapped_route = r.clone();
    swapped_route.route = vec!["bastion (jump.example:22)".into()];
    assert!(!vault.verify_mcp_consent_tag(&swapped_route, Decision::Once, &tag));
    let mut swapped_client = r.clone();
    swapped_client.client = Some("some agent".into());
    assert!(!vault.verify_mcp_consent_tag(&swapped_client, Decision::Once, &tag));
    let mut swapped_labels = r.clone();
    swapped_labels.host_label = "db".into();
    assert!(!vault.verify_mcp_consent_tag(&swapped_labels, Decision::Once, &tag));
    let mut swapped_time = r.clone();
    swapped_time.created_unix = 1;
    assert!(!vault.verify_mcp_consent_tag(&swapped_time, Decision::Once, &tag));
}

#[test]
fn a_request_read_back_from_its_file_tags_like_the_original() {
    // The app never holds the server's struct, only what it deserialized
    // from the posted file: the two must agree byte for byte.
    let vault = unlocked_vault();
    let mut r = request();
    r.route = vec!["bastion (jump.example:22)".into()];
    r.client = Some("agent".into());
    r.command = "apt-get update && apt-get -y upgrade\n# second line\n".into();
    let read_back: SudoRequest = serde_json::from_slice(&serde_json::to_vec(&r).unwrap()).unwrap();
    let tag = vault.mcp_consent_tag(&read_back, Decision::Session).unwrap();
    assert!(vault.verify_mcp_consent_tag(&r, Decision::Session, &tag));
}
