use super::*;
use crate::mcp_consent::{claim, post, Decision, SudoRequest};
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

/// The bytes the server would post for `r`.
fn bytes(r: &SudoRequest) -> Vec<u8> {
    serde_json::to_vec(r).unwrap()
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

    let r = bytes(&request());
    let tag = app.mcp_consent_tag(&r, Decision::Session).unwrap();
    assert!(mcp.verify_mcp_consent_tag(&r, Decision::Session, &tag));
}

#[test]
fn a_tag_answers_one_decision_on_one_request() {
    let vault = unlocked_vault();
    let r = request();
    let tag = vault.mcp_consent_tag(&bytes(&r), Decision::Once).unwrap();
    assert!(vault.verify_mcp_consent_tag(&bytes(&r), Decision::Once, &tag));
    // "Once" does not stretch to the whole session.
    assert!(!vault.verify_mcp_consent_tag(&bytes(&r), Decision::Session, &tag));
    // Nor to another request, another host or another vault.
    let mut other = r.clone();
    other.id = SudoRequest::new_id().unwrap();
    assert!(!vault.verify_mcp_consent_tag(&bytes(&other), Decision::Once, &tag));
    let mut other = r.clone();
    other.host_id = Uuid::new_v4();
    assert!(!vault.verify_mcp_consent_tag(&bytes(&other), Decision::Once, &tag));
    let mut other = r.clone();
    other.vault_id = Uuid::new_v4();
    assert!(!vault.verify_mcp_consent_tag(&bytes(&other), Decision::Once, &tag));
}

#[test]
fn another_vaults_key_does_not_verify() {
    let a = unlocked_vault();
    let b = unlocked_vault();
    let r = bytes(&request());
    let tag = a.mcp_consent_tag(&r, Decision::Once).unwrap();
    assert!(!b.verify_mcp_consent_tag(&r, Decision::Once, &tag));
}

#[test]
fn forged_or_malformed_tags_never_allow() {
    let vault = unlocked_vault();
    let r = bytes(&request());
    for tag in ["", "00", "zz", &"0".repeat(64), "not hex at all"] {
        assert!(!vault.verify_mcp_consent_tag(&r, Decision::Once, tag), "{tag:?}");
    }
}

#[test]
fn a_locked_vault_neither_tags_nor_verifies() {
    let mut vault = unlocked_vault();
    let r = bytes(&request());
    let tag = vault.mcp_consent_tag(&r, Decision::Once).unwrap();
    vault.lock();
    assert!(matches!(vault.mcp_consent_tag(&r, Decision::Once), Err(VaultError::Locked)));
    assert!(!vault.verify_mcp_consent_tag(&r, Decision::Once, &tag));
}

#[test]
fn the_tag_binds_the_bytes_the_person_read() {
    // The app tags the request file AS IT READ IT at the claim, the
    // server checks the tag against the bytes IT POSTED. A process that
    // can write the folder (the agent's own shell) may rewrite the posted
    // file between the post and the claim; whatever it changes, the
    // dialog's approval must not carry over to the server's request.
    let vault = unlocked_vault();
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join(crate::mcp_consent::DIR_NAME);
    let r = request();
    let server = post(&dir, &r).unwrap();
    let file = dir.join(format!("{}.request", r.id));
    let rewrites: [(&str, &str, &str); 7] = [
        ("command", "\"command\":\"id\"", "\"command\":\"uptime\""),
        ("login", "\"login\":\"deploy\"", "\"login\":\"root\""),
        ("address", "\"address\":\"10.0.0.5:22\"", "\"address\":\"10.0.0.6:22\""),
        ("route", "\"route\":[]", "\"route\":[\"bastion (jump.example:22)\"]"),
        ("client", "\"client\":null", "\"client\":\"some agent\""),
        ("host label", "\"host_label\":\"web\"", "\"host_label\":\"db\""),
        ("whitespace alone", "\"command\":\"id\"", "\"command\": \"id\""),
    ];
    let original = String::from_utf8(server.clone()).unwrap();
    for (what, from, to) in rewrites {
        assert!(original.contains(from), "{what}: the fixture lost {from}");
        std::fs::write(&file, original.replace(from, to)).unwrap();
        let claimed = claim(&dir, &r.id).unwrap();
        let tag = vault.mcp_consent_tag(&claimed.bytes, Decision::Once).unwrap();
        assert!(
            !vault.verify_mcp_consent_tag(&server, Decision::Once, &tag),
            "{what}: an approval of the rewritten file must not verify against the posted one"
        );
        // Back to posted for the next rewrite.
        std::fs::remove_file(dir.join(format!("{}.claimed", r.id))).unwrap();
        std::fs::write(&file, &server).unwrap();
    }
    // Untouched, the claim's bytes are the server's and the tag verifies.
    let claimed = claim(&dir, &r.id).unwrap();
    let tag = vault.mcp_consent_tag(&claimed.bytes, Decision::Once).unwrap();
    assert!(vault.verify_mcp_consent_tag(&server, Decision::Once, &tag));
}

#[test]
fn a_field_this_build_does_not_know_is_covered_all_the_same() {
    // The app and the plugin are released on their own tags: a server
    // that posts a field this app has never heard of must still get an
    // allowance it can verify, and the tag must still bind that field.
    let vault = unlocked_vault();
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join(crate::mcp_consent::DIR_NAME);
    let r = request();
    let posted = String::from_utf8(post(&dir, &r).unwrap()).unwrap();
    let newer = posted.replacen('{', "{\"reason\":\"deploy step 3\",", 1);
    let file = dir.join(format!("{}.request", r.id));
    std::fs::write(&file, newer.as_bytes()).unwrap();
    let claimed = claim(&dir, &r.id).unwrap();
    assert_eq!(claimed.request, r, "the unknown field is dropped from the struct");
    let tag = vault.mcp_consent_tag(&claimed.bytes, Decision::Session).unwrap();
    assert!(vault.verify_mcp_consent_tag(newer.as_bytes(), Decision::Session, &tag));
    // Changing that field changes the tag, like any other.
    let changed = newer.replace("deploy step 3", "deploy step 4");
    assert!(!vault.verify_mcp_consent_tag(changed.as_bytes(), Decision::Session, &tag));
}
