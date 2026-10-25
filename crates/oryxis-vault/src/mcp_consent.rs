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
//! master key over the BYTES of the request file as the app read them
//! at the claim ([`Claimed::bytes`]) and the decision
//! ([`crate::VaultStore::mcp_consent_tag`]). The server accepts an
//! allowance only with a tag it recomputes over the bytes it POSTED
//! ([`post`] returns them), so a process that can write the runtime
//! folder (the AI client's own shell tool runs as the user) cannot
//! approve by writing a file, and cannot rewrite the posted request
//! either: a command (or a host address) swapped in the file before the
//! app claimed it is what the person reads and tags, and those bytes are
//! not the server's. The bytes, not a re-serialization of the struct: the
//! app and the plugin are released on their own tags, and a field one
//! side knows and the other does not would otherwise turn every
//! allowance into a bad tag until both were on the same build; over the
//! bytes, a field this build has never heard of is covered all the same.
//! What that stops is a forged FILE, not a forger with the key: a vault
//! without a master password derives its key from the file alone, and a
//! client config that embeds the vault password hands it to whoever
//! reads that config. A refusal needs no tag: forging one only refuses.

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

/// The most a command may weigh to run under sudo, in bytes. The person
/// may have to READ it in the app's dialog before the password goes, and
/// the agent decides how long it is: past this, the dialog is a wall of
/// text nobody judges, and the window spends its frames shaping it. The
/// server refuses a longer command before anything is dialled.
pub const MAX_COMMAND_BYTES: usize = 32 * 1024;

/// The most a request FILE may weigh: the command at its cap plus room
/// for every other field (labels, a long jump route, the client's name).
/// A server never posts past it; a file over it was written by someone
/// else (the runtime folder's other writer runs as the user), and the
/// app neither reads nor lays it out: the scan removes it and a claim
/// refuses it, so a forged file of any size costs the app nothing.
pub const MAX_REQUEST_BYTES: u64 = (MAX_COMMAND_BYTES + 16 * 1024) as u64;

/// Where requests and answers live, `None` when the home directory is
/// unknown.
pub fn consent_dir() -> Option<PathBuf> {
    crate::change_notice::marker_path()
        .and_then(|p| p.parent().map(|d| d.join(DIR_NAME)))
}

/// What the server asks: everything the person needs to decide, and
/// nothing secret (the password stays in the server).
///
/// The app and the plugin are released on their own tags, so the two
/// sides of this file are often different builds. A field one side does
/// not know is dropped on read and covered by the tag all the same (the
/// tag is over the bytes), which settles a NEWER server. A newer APP
/// reads files the older server posts, so **every field added here
/// carries `#[serde(default)]`**: a required field would make `claim`
/// fail on every request of the installed plugin, and the agent would
/// read "not picked up" while the app sits there unlocked.
/// `a_file_of_the_first_shape_still_claims` pins the shape of the first
/// release.
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

/// A request as the app claimed it: what the dialog shows, and the bytes
/// it was read from, which the answer's tag covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claimed {
    pub request: SudoRequest,
    /// The request file, byte for byte.
    pub bytes: Vec<u8>,
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

/// Post `request` (server side). Returns the bytes written: the server
/// verifies the answer's tag over them.
pub fn post(dir: &Path, request: &SudoRequest) -> std::io::Result<Vec<u8>> {
    if !valid_id(&request.id) {
        return Err(std::io::Error::other("malformed request id"));
    }
    create_private_dir(dir)?;
    let bytes = serde_json::to_vec(request).map_err(std::io::Error::other)?;
    write_atomic(&path_of(dir, &request.id, "request"), &bytes)?;
    Ok(bytes)
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
/// another instance took it first, the server withdrew it, or the file
/// is not a request this build can ask (over [`MAX_REQUEST_BYTES`], or
/// unreadable: logged, since a plugin and an app of different builds
/// would otherwise read as "nobody picked it up"); else the request as
/// claimed, with the bytes it was read from.
pub fn claim(dir: &Path, id: &str) -> Option<Claimed> {
    if !valid_id(id) {
        return None;
    }
    let posted = path_of(dir, id, "request");
    if std::fs::metadata(&posted).ok()?.len() > MAX_REQUEST_BYTES {
        tracing::warn!(target = "oryxis::mcp", request = %id, "sudo request file over the size cap, removed unread");
        let _ = std::fs::remove_file(&posted);
        return None;
    }
    let claimed = path_of(dir, id, "claimed");
    std::fs::rename(&posted, &claimed).ok()?;
    let bytes = std::fs::read(&claimed).ok()?;
    let request = match serde_json::from_slice::<SudoRequest>(&bytes) {
        Ok(request) if request.id == id => request,
        Ok(_) => return None,
        Err(e) => {
            tracing::warn!(target = "oryxis::mcp", request = %id, "sudo request does not parse (plugin and app of different builds?): {e}");
            return None;
        }
    };
    Some(Claimed { request, bytes })
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
/// live claims. Removes debris older than [`STALE_AFTER`], a request
/// past its claim window (its server has stopped waiting for it), and a
/// request file over [`MAX_REQUEST_BYTES`], unread.
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
        let metadata = entry.metadata().ok();
        let age = metadata
            .as_ref()
            .and_then(|m| m.modified().ok())
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
                if metadata.as_ref().is_some_and(|m| m.len() > MAX_REQUEST_BYTES) {
                    tracing::warn!(target = "oryxis::mcp", request = %stem, "sudo request file over the size cap, removed unread");
                    let _ = std::fs::remove_file(&path);
                    continue;
                }
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

/// The bytes the tag covers: the request file as read (the server's
/// bytes when nobody touched it, every field the person reads included,
/// known to this build or not) and the decision, a unit separator before
/// each.
pub(crate) fn tag_message(request: &[u8], decision: Decision) -> Vec<u8> {
    let mut msg = Vec::with_capacity(request.len() + 16);
    msg.push(0x1f);
    msg.extend_from_slice(request);
    msg.push(0x1f);
    msg.extend_from_slice(decision.wire().as_bytes());
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
        let (r, _) = posted(dir);
        r
    }

    fn posted(dir: &Path) -> (SudoRequest, Vec<u8>) {
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
        let bytes = post(dir, &r).unwrap();
        (r, bytes)
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

        assert_eq!(claim(&dir, &r.id).map(|c| c.request), Some(r.clone()));
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
    fn the_claim_reads_the_bytes_the_server_posted() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(DIR_NAME);
        let (r, bytes) = posted(&dir);
        let claimed = claim(&dir, &r.id).unwrap();
        assert_eq!(claimed.request, r);
        assert_eq!(claimed.bytes, bytes, "the tag is over these: they must be the server's");
    }

    #[test]
    fn a_request_rewritten_in_the_folder_is_claimed_as_rewritten() {
        // The agent's shell may rewrite the posted file before the app
        // claims it. The app shows and tags what it read: not the server's
        // bytes, so the server's check fails (`tag_message` differs).
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(DIR_NAME);
        let (r, bytes) = posted(&dir);
        let swapped = String::from_utf8(bytes.clone())
            .unwrap()
            .replace("systemctl restart nginx", "uptime");
        std::fs::write(dir.join(format!("{}.request", r.id)), swapped.as_bytes()).unwrap();
        let claimed = claim(&dir, &r.id).unwrap();
        assert_eq!(claimed.request.command, "uptime", "the person reads the swapped command");
        assert_ne!(claimed.bytes, bytes);
        assert_ne!(tag_message(&claimed.bytes, Decision::Once), tag_message(&bytes, Decision::Once));
    }

    #[test]
    fn an_oversized_request_is_removed_unread_by_scan_and_claim() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(DIR_NAME);
        let r = request(&dir);
        let big = SudoRequest { command: "x".repeat(MAX_REQUEST_BYTES as usize), ..r.clone() };
        let file = dir.join(format!("{}.request", r.id));
        std::fs::write(&file, serde_json::to_vec(&big).unwrap()).unwrap();
        assert!(scan(&dir, now()).posted.is_empty(), "never offered");
        assert!(!file.exists(), "removed by the scan");
        std::fs::write(&file, serde_json::to_vec(&big).unwrap()).unwrap();
        assert_eq!(claim(&dir, &r.id), None, "never claimed");
        assert!(!file.exists() && !dir.join(format!("{}.claimed", r.id)).exists());
        // At the server's own cap the request goes through.
        let capped = SudoRequest { command: "x".repeat(MAX_COMMAND_BYTES), ..r.clone() };
        std::fs::write(&file, serde_json::to_vec(&capped).unwrap()).unwrap();
        assert_eq!(scan(&dir, now()).posted.len(), 1);
        assert!(claim(&dir, &r.id).is_some());
    }

    #[test]
    fn a_file_of_the_first_shape_still_claims() {
        // The request file as the first plugin release (mcp 0.1.14)
        // posts it, with the two optional fields of that shape left out.
        // A newer app adds fields with `#[serde(default)]` only, so this
        // file claims on every later build; a required field would turn
        // every request of an installed plugin into "not picked up".
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(DIR_NAME);
        std::fs::create_dir_all(&dir).unwrap();
        let id = "0123456789abcdef0123456789abcdef";
        let first_shape = format!(
            "{{\"id\":\"{id}\",\"vault_id\":\"11111111-2222-4333-8444-555555555555\",\"vault_label\":\"Personal\",\
             \"host_id\":\"66666666-7777-4888-8999-000000000000\",\"host_label\":\"web\",\"login\":\"deploy\",\
             \"address\":\"10.0.0.5:22\",\"command\":\"id\",\"created_unix\":0}}"
        );
        std::fs::write(dir.join(format!("{id}.request")), first_shape.as_bytes()).unwrap();
        let claimed = claim(&dir, id).expect("the first release's file claims on this build");
        assert_eq!(claimed.request.command, "id");
        assert!(claimed.request.route.is_empty() && claimed.request.client.is_none());
        assert_eq!(claimed.bytes, first_shape.as_bytes());
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
