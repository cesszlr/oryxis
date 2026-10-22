//! The question `oryxis-mcp` asks the app before it hands a host's stored
//! password to `sudo`, and the answer the app gives.
//!
//! `oryxis-mcp` runs as a child of an AI client and has no window; the
//! app does. So the request crosses on disk, in the runtime folder the
//! deep-link inbox and the vault-change marker already use:
//!
//! 1. the server POSTS `<id>.request` (temp + rename, owner-only);
//! 2. an app instance that has the request's vault open and unlocked
//!    CLAIMS it by renaming it to `<id>.claimed`: a rename has one
//!    winner, so two instances never ask the same question twice, and a
//!    request nobody claims within [`CLAIM_WINDOW`] tells the server that
//!    no app could ask (closed, or the vault locked);
//! 3. the app ANSWERS `<id>.answer` and drops its claim;
//! 4. the server reads the answer and removes every file of the request
//!    ([`withdraw`]), which is also how a cancelled call takes the
//!    question off the screen: the app sees its claim gone.
//!
//! An answer that allows carries a tag: HMAC-SHA256 under the vault's
//! master key over the request id (random, 128 bits, minted by the
//! server), the vault, the host and the decision
//! ([`crate::VaultStore::mcp_consent_tag`]). The server accepts an
//! allowance only with a tag it recomputes itself, so a process that can
//! write the runtime folder (the AI client's own shell tool runs as the
//! user) cannot approve by writing a file. What that stops is a forged
//! FILE, not a forger with the key: a vault without a master password
//! derives its key from the file alone, and a client config that embeds
//! the vault password hands it to whoever reads that config. A refusal
//! needs no tag: forging one only refuses.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Folder under the runtime folder.
pub const DIR_NAME: &str = "mcp-consent";

/// How long a posted request may wait for an app to claim it. The app
/// polls every 500 ms; the rest is room for an app busy drawing.
pub const CLAIM_WINDOW: Duration = Duration::from_secs(10);

/// How long a claimed request may wait for the person. The app's dialog
/// refuses by itself at this deadline, so it never outlives the call.
pub const DECISION_WINDOW: Duration = Duration::from_secs(60);

/// Past this age a file of a request is debris (a server that died
/// mid-question) and the app's scan removes it.
pub const STALE_AFTER: Duration = Duration::from_secs(5 * 60);

/// Where requests and answers live, `None` when the home directory is
/// unknown.
pub fn consent_dir() -> Option<PathBuf> {
    crate::change_notice::marker_path()
        .and_then(|p| p.parent().map(|d| d.join(DIR_NAME)))
}

/// What the server asks: everything the person needs to decide, and
/// nothing secret (the password stays in the server).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SudoRequest {
    /// 32 lowercase hex digits, random: the file name and the nonce the
    /// answer's tag binds.
    pub id: String,
    /// The registry id of the vault holding the host.
    pub vault_id: Uuid,
    pub vault_label: String,
    pub host_id: Uuid,
    pub host_label: String,
    /// The login the dial uses, whose password `sudo` would get.
    pub login: String,
    /// `host:port` of the target.
    pub address: String,
    /// The jump hosts the dial crosses, in order, each as `label (host:port)`.
    #[serde(default)]
    pub route: Vec<String>,
    /// The client's own name for itself (`clientInfo.name` of the MCP
    /// handshake): self-reported, shown as such.
    #[serde(default)]
    pub client: Option<String>,
    /// The command that asked, verbatim.
    pub command: String,
    /// Seconds since the epoch when it was posted.
    pub created_unix: u64,
}

impl SudoRequest {
    /// A fresh request id: 128 random bits, hex.
    pub fn new_id() -> std::io::Result<String> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(hex(&bytes))
    }
}

/// What the person chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Deny,
    /// This command only.
    Once,
    /// Every sudo call to this host until the server exits.
    Session,
}

impl Decision {
    pub fn allows(self) -> bool {
        !matches!(self, Decision::Deny)
    }

    fn wire(self) -> &'static str {
        match self {
            Decision::Deny => "deny",
            Decision::Once => "once",
            Decision::Session => "session",
        }
    }
}

/// Why the app refused without the person deciding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// The person pressed Deny (or Esc, or clicked outside).
    Person,
    /// Nobody answered within [`DECISION_WINDOW`].
    TimedOut,
    /// The vault was locked (or removed) while the question was up.
    Locked,
    /// The app quit, or hid its window to the tray, while the question
    /// was up.
    AppClosed,
}

/// The answer file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Answer {
    pub decision: Decision,
    #[serde(default)]
    pub reason: Option<DenyReason>,
    /// Hex HMAC for an allowance, empty for a refusal.
    #[serde(default)]
    pub tag: String,
}

/// Where a request stands, as the server sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// Posted, no app took it yet.
    Posted,
    /// An app is asking the person.
    Claimed,
    /// Answered (tag not checked yet).
    Answered(Answer),
    /// None of its files is there (removed under the server).
    Gone,
}

/// What the app's poll found.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Scan {
    /// Requests nobody claimed yet.
    pub posted: Vec<SudoRequest>,
    /// Ids with a live claim (asked in some app instance).
    pub claimed: Vec<String>,
}

/// Whether `id` has the shape [`SudoRequest::new_id`] makes. Every path
/// is built from an id, and a file name is not trusted to be one.
pub fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn path_of(dir: &Path, id: &str, ext: &str) -> PathBuf {
    dir.join(format!("{id}.{ext}"))
}

/// Post `request` (server side).
pub fn post(dir: &Path, request: &SudoRequest) -> std::io::Result<()> {
    if !valid_id(&request.id) {
        return Err(std::io::Error::other("malformed request id"));
    }
    create_private_dir(dir)?;
    let bytes = serde_json::to_vec(request).map_err(std::io::Error::other)?;
    write_atomic(&path_of(dir, &request.id, "request"), &bytes)
}

/// Where request `id` stands (server side). The answer is read first: an
/// app answers and only then drops its claim.
pub fn status(dir: &Path, id: &str) -> Status {
    if !valid_id(id) {
        return Status::Gone;
    }
    if let Ok(bytes) = std::fs::read(path_of(dir, id, "answer")) {
        return match serde_json::from_slice::<Answer>(&bytes) {
            Ok(answer) => Status::Answered(answer),
            // Unreadable = a refusal: never an allowance by accident.
            Err(_) => Status::Answered(Answer {
                decision: Decision::Deny,
                reason: None,
                tag: String::new(),
            }),
        };
    }
    if path_of(dir, id, "claimed").exists() {
        Status::Claimed
    } else if path_of(dir, id, "request").exists() {
        Status::Posted
    } else {
        Status::Gone
    }
}

/// Remove every file of request `id` (server side: answered, timed
/// out, or cancelled).
pub fn withdraw(dir: &Path, id: &str) {
    if !valid_id(id) {
        return;
    }
    for ext in ["request", "claimed", "answer"] {
        let _ = std::fs::remove_file(path_of(dir, id, ext));
    }
}

/// Take request `id` for this app instance (app side). `None` when
/// another instance took it first or the server withdrew it; else the
/// request as claimed.
pub fn claim(dir: &Path, id: &str) -> Option<SudoRequest> {
    if !valid_id(id) {
        return None;
    }
    let claimed = path_of(dir, id, "claimed");
    std::fs::rename(path_of(dir, id, "request"), &claimed).ok()?;
    std::fs::read(&claimed)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<SudoRequest>(&bytes).ok())
        .filter(|r| r.id == id)
}

/// Answer request `id` (app side) and drop the claim. A request whose
/// claim is gone was withdrawn by its server: nobody reads an answer to
/// it, so none is written (it would only wait for the debris sweep).
pub fn answer(dir: &Path, id: &str, answer: &Answer) -> std::io::Result<()> {
    if !valid_id(id) {
        return Err(std::io::Error::other("malformed request id"));
    }
    if !path_of(dir, id, "claimed").exists() {
        return Ok(());
    }
    let bytes = serde_json::to_vec(answer).map_err(std::io::Error::other)?;
    write_atomic(&path_of(dir, id, "answer"), &bytes)?;
    let _ = std::fs::remove_file(path_of(dir, id, "claimed"));
    Ok(())
}

/// Read the folder (app side): the requests waiting for a claim and the
/// live claims. Removes debris older than [`STALE_AFTER`], and a request
/// past its claim window (its server has stopped waiting for it).
pub fn scan(dir: &Path, now_unix: u64) -> Scan {
    let mut out = Scan::default();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let (Some(stem), Some(ext)) = (
            path.file_stem().and_then(|s| s.to_str()),
            path.extension().and_then(|s| s.to_str()),
        ) else {
            continue;
        };
        let age = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .unwrap_or_default();
        if !valid_id(stem) {
            // A temp file of a write that never renamed.
            if ext.starts_with("tmp-") && age > STALE_AFTER {
                let _ = std::fs::remove_file(&path);
            }
            continue;
        }
        if age > STALE_AFTER {
            let _ = std::fs::remove_file(&path);
            continue;
        }
        match ext {
            "request" => {
                let Some(request) = std::fs::read(&path)
                    .ok()
                    .and_then(|b| serde_json::from_slice::<SudoRequest>(&b).ok())
                    .filter(|r| r.id == stem)
                else {
                    continue;
                };
                if now_unix.saturating_sub(request.created_unix) > CLAIM_WINDOW.as_secs() {
                    let _ = std::fs::remove_file(&path);
                    continue;
                }
                out.posted.push(request);
            }
            "claimed" => out.claimed.push(stem.to_string()),
            _ => {}
        }
    }
    out.posted.sort_by(|a, b| a.created_unix.cmp(&b.created_unix).then(a.id.cmp(&b.id)));
    out.claimed.sort();
    out
}

/// The bytes the tag covers. Unit separators keep the fields apart.
pub(crate) fn tag_message(request: &SudoRequest, decision: Decision) -> Vec<u8> {
    let mut msg = Vec::with_capacity(128);
    for part in [
        request.id.as_str(),
        &request.vault_id.to_string(),
        &request.host_id.to_string(),
        decision.wire(),
    ] {
        msg.push(0x1f);
        msg.extend_from_slice(part.as_bytes());
    }
    msg
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap());
        out.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap());
    }
    out
}

pub(crate) fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// Owner-only on unix, temp + rename so a reader never sees half a file.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let written = options.open(&tmp).and_then(|mut f| {
        f.write_all(bytes)?;
        f.sync_all()
    });
    if let Err(e) = written.and_then(|()| std::fs::rename(&tmp, path)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(dir: &Path) -> SudoRequest {
        let r = SudoRequest {
            id: SudoRequest::new_id().unwrap(),
            vault_id: Uuid::new_v4(),
            vault_label: "Personal".into(),
            host_id: Uuid::new_v4(),
            host_label: "web".into(),
            login: "deploy".into(),
            address: "10.0.0.5:22".into(),
            route: vec!["bastion (1.2.3.4:22)".into()],
            client: Some("claude-code".into()),
            command: "systemctl restart nginx".into(),
            created_unix: now(),
        };
        post(dir, &r).unwrap();
        r
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn a_request_goes_posted_claimed_answered_and_away() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(DIR_NAME);
        let r = request(&dir);
        assert_eq!(status(&dir, &r.id), Status::Posted);
        let scanned = scan(&dir, now());
        assert_eq!(scanned.posted, vec![r.clone()]);
        assert!(scanned.claimed.is_empty());

        assert_eq!(claim(&dir, &r.id), Some(r.clone()));
        assert_eq!(status(&dir, &r.id), Status::Claimed);
        assert_eq!(claim(&dir, &r.id), None, "one claim wins");
        let scanned = scan(&dir, now());
        assert!(scanned.posted.is_empty());
        assert_eq!(scanned.claimed, vec![r.id.clone()]);

        let a = Answer { decision: Decision::Once, reason: None, tag: "ab".into() };
        answer(&dir, &r.id, &a).unwrap();
        assert_eq!(status(&dir, &r.id), Status::Answered(a));
        assert!(scan(&dir, now()).claimed.is_empty(), "the claim goes with the answer");

        withdraw(&dir, &r.id);
        assert_eq!(status(&dir, &r.id), Status::Gone);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    }

    #[test]
    fn a_withdrawn_request_gets_no_answer_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(DIR_NAME);
        let r = request(&dir);
        assert!(claim(&dir, &r.id).is_some());
        withdraw(&dir, &r.id);
        let a = Answer { decision: Decision::Deny, reason: None, tag: String::new() };
        answer(&dir, &r.id, &a).unwrap();
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    }

    #[test]
    fn a_withdrawn_request_cannot_be_claimed() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(DIR_NAME);
        let r = request(&dir);
        withdraw(&dir, &r.id);
        assert_eq!(claim(&dir, &r.id), None);
    }

    #[test]
    fn an_unreadable_answer_is_a_refusal() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(DIR_NAME);
        let r = request(&dir);
        std::fs::write(dir.join(format!("{}.answer", r.id)), b"{\"decision\":\"session\"").unwrap();
        match status(&dir, &r.id) {
            Status::Answered(a) => assert_eq!(a.decision, Decision::Deny),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_request_past_its_claim_window_is_dropped_by_the_scan() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(DIR_NAME);
        let r = request(&dir);
        let later = r.created_unix + CLAIM_WINDOW.as_secs() + 1;
        assert!(scan(&dir, later).posted.is_empty());
        assert_eq!(status(&dir, &r.id), Status::Gone);
    }

    #[test]
    fn names_that_are_not_ids_are_never_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(DIR_NAME);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("notanid.request"), b"{}").unwrap();
        assert!(scan(&dir, now()).posted.is_empty());
        assert_eq!(claim(&dir, "../x"), None);
        assert_eq!(status(&dir, "../../vault"), Status::Gone);
        assert!(!valid_id(&"A".repeat(32)));
        assert!(valid_id(&SudoRequest::new_id().unwrap()));
    }

    #[test]
    fn a_request_whose_body_names_another_id_is_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(DIR_NAME);
        let r = request(&dir);
        let other = SudoRequest::new_id().unwrap();
        std::fs::rename(
            dir.join(format!("{}.request", r.id)),
            dir.join(format!("{other}.request")),
        )
        .unwrap();
        assert!(scan(&dir, now()).posted.is_empty());
        assert_eq!(claim(&dir, &other), None);
    }

    #[cfg(unix)]
    #[test]
    fn the_folder_and_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(DIR_NAME);
        let r = request(&dir);
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join(format!("{}.request", r.id))), 0o600);
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0u8, 1, 0xab, 0xff];
        assert_eq!(unhex(&hex(&bytes)).unwrap(), bytes);
        assert_eq!(unhex("abc"), None);
        assert_eq!(unhex("zz"), None);
    }
}
