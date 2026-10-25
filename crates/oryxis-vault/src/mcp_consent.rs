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
//!    no app could ask (closed, or the vault locked). A request file any
//!    instance's scan cannot read (it does not parse, or names another
//!    id) is claimed and refused at once as [`DenyReason::Unreadable`],
//!    whatever the vault's state; an entry that is not a plain file
//!    within [`MAX_REQUEST_BYTES`] is removed unread;
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
/// Counted over the file's bytes, which are JSON: a line break, a quote,
/// a backslash or a control byte in the command is written as its escape
/// (two to six bytes), so a command under [`MAX_COMMAND_BYTES`] can make
/// a file over this cap. [`encode`] measures the file as [`post`] writes
/// it, the server runs it before posting and `post` refuses past it, so
/// no server writes a file the app removes unread; a file over the cap
/// was written by someone else (the runtime folder's other writer runs
/// as the user), and the app neither reads nor lays it out: the scan
/// and a claim remove it unread, so a forged file of any size costs the
/// app nothing.
pub const MAX_REQUEST_BYTES: u64 = (MAX_COMMAND_BYTES + 16 * 1024) as u64;

/// Why a request cannot become a file.
#[derive(Debug)]
pub enum EncodeError {
    /// The file would weigh `bytes`, over [`MAX_REQUEST_BYTES`].
    TooLarge { bytes: usize },
    /// The request does not serialize (nothing in [`SudoRequest`] can
    /// make this happen; kept for the type's sake, never swallowed).
    Json(serde_json::Error),
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodeError::TooLarge { bytes } => {
                write!(f, "request file of {bytes} bytes over the {MAX_REQUEST_BYTES} byte cap")
            }
            EncodeError::Json(e) => write!(f, "request does not serialize: {e}"),
        }
    }
}

impl std::error::Error for EncodeError {}

/// The request as its file carries it, the bytes the answer's tag covers.
/// Refused past [`MAX_REQUEST_BYTES`]: the one measure of the file, taken
/// by the server before anything is posted and by [`post`] itself.
pub fn encode(request: &SudoRequest) -> Result<Vec<u8>, EncodeError> {
    let bytes = serde_json::to_vec(request).map_err(EncodeError::Json)?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err(EncodeError::TooLarge { bytes: bytes.len() });
    }
    Ok(bytes)
}

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
/// fail on every request of the installed plugin, and every one would be
/// refused as [`DenyReason::Unreadable`] while the app sits there
/// unlocked.
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
///
/// The app and the plugin ship on their own tags, so a plugin may read a
/// reason a newer app added. Every reason this build does not know reads
/// as [`DenyReason::Unknown`], and so does an answer file that does not
/// parse at all ([`status`]): never as the person's refusal, which tells
/// the agent not to retry.
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
    /// The app could not read the request file (a plugin and an app of
    /// different builds, or a file nobody posted).
    Unreadable,
    /// A reason this build does not know (a newer app), or an answer that
    /// does not parse. Read only: no build writes it.
    #[serde(other)]
    Unknown,
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
/// verifies the answer's tag over them. A request whose file would be
/// over [`MAX_REQUEST_BYTES`] is refused ([`encode`]) and nothing is
/// written: the app would remove such a file unread, and the server
/// would read that as the request vanishing.
pub fn post(dir: &Path, request: &SudoRequest) -> std::io::Result<Vec<u8>> {
    if !valid_id(&request.id) {
        return Err(std::io::Error::other("malformed request id"));
    }
    let bytes = encode(request).map_err(std::io::Error::other)?;
    create_private_dir(dir)?;
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
            // Unreadable = a refusal: never an allowance by accident, and
            // never the person's (a decision a newer app added lands here).
            Err(_) => Status::Answered(Answer {
                decision: Decision::Deny,
                reason: Some(DenyReason::Unknown),
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
/// another instance took it first or the server withdrew it (silently);
/// when the entry is not a plain file within [`MAX_REQUEST_BYTES`]
/// (removed unread, logged); when the read failed for a reason of its
/// own (the claim is put back, so the next poll tries again); or when
/// the body does not parse or names another id (refused at once as
/// [`DenyReason::Unreadable`], so the server tells its agent now). Else
/// the request as claimed, with the bytes it was read from.
pub fn claim(dir: &Path, id: &str) -> Option<Claimed> {
    if !valid_id(id) {
        return None;
    }
    let posted = path_of(dir, id, "request");
    match std::fs::symlink_metadata(&posted) {
        Ok(m) if m.is_file() => {}
        // Withdrawn by its server, or claimed by another instance.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Ok(_) => {
            tracing::warn!(target = "oryxis::mcp", request = %id, "sudo request is not a plain file, removed unread");
            let _ = std::fs::remove_file(&posted);
            return None;
        }
        Err(e) => {
            tracing::debug!(target = "oryxis::mcp", request = %id, "sudo request not readable yet, next poll: {e}");
            return None;
        }
    }
    let claimed = path_of(dir, id, "claimed");
    std::fs::rename(&posted, &claimed).ok()?;
    let bytes = match read_request_file(&claimed) {
        RequestRead::Bytes(bytes) => bytes,
        RequestRead::Refused(why) => {
            tracing::warn!(target = "oryxis::mcp", request = %id, "sudo request {why}, removed unread");
            let _ = std::fs::remove_file(&claimed);
            return None;
        }
        RequestRead::Failed(e) => {
            // Nothing wrong with the request: give it back to the folder.
            tracing::debug!(target = "oryxis::mcp", request = %id, "sudo request read failed, put back for the next poll: {e}");
            let _ = std::fs::rename(&claimed, &posted);
            return None;
        }
    };
    let request = match serde_json::from_slice::<SudoRequest>(&bytes) {
        Ok(request) if request.id == id => request,
        Ok(_) => {
            tracing::warn!(target = "oryxis::mcp", request = %id, "sudo request names another id, refused");
            refuse_unreadable(dir, id);
            return None;
        }
        Err(e) => {
            tracing::warn!(target = "oryxis::mcp", request = %id, "sudo request does not parse (plugin and app of different builds?), refused: {e}");
            refuse_unreadable(dir, id);
            return None;
        }
    };
    Some(Claimed { request, bytes })
}

/// What reading a request file came to.
#[derive(Debug)]
enum RequestRead {
    Bytes(Vec<u8>),
    /// Not something a server posted: not a plain file (the runtime
    /// folder's other writer runs as the user and may plant a symlink to
    /// something huge, a FIFO, whose open blocks until a writer shows up,
    /// or a device), or past [`MAX_REQUEST_BYTES`]. Removed unread.
    Refused(&'static str),
    /// The read itself failed (a descriptor limit, a scanner holding the
    /// file on Windows): nothing says the request is bad, so it stays for
    /// the next poll instead of reaching its server as withdrawn.
    Failed(std::io::Error),
}

/// Read a request file through ONE handle, bounded by
/// [`MAX_REQUEST_BYTES`]: a plain file by `lstat` first, the size taken
/// on the opened handle (not on a path a writer could swap under us),
/// the read stopped at the cap whatever the file grew to meanwhile.
fn read_request_file(path: &Path) -> RequestRead {
    use std::io::Read as _;
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_file() => {}
        Ok(_) => return RequestRead::Refused("is not a plain file"),
        Err(e) => return RequestRead::Failed(e),
    }
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) => return RequestRead::Failed(e),
    };
    let meta = match file.metadata() {
        Ok(meta) => meta,
        Err(e) => return RequestRead::Failed(e),
    };
    if !meta.is_file() {
        return RequestRead::Refused("is not a plain file");
    }
    if meta.len() > MAX_REQUEST_BYTES {
        return RequestRead::Refused("is over the size cap");
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    if let Err(e) = file.take(MAX_REQUEST_BYTES + 1).read_to_end(&mut bytes) {
        return RequestRead::Failed(e);
    }
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return RequestRead::Refused("is over the size cap");
    }
    RequestRead::Bytes(bytes)
}

/// A claimed request this app cannot read is answered at once with
/// [`DenyReason::Unreadable`], so the server tells its agent now (a
/// plugin and an app of different builds, most likely) instead of
/// reading a live claim until the decision window runs out.
fn refuse_unreadable(dir: &Path, id: &str) {
    let refusal = Answer { decision: Decision::Deny, reason: Some(DenyReason::Unreadable), tag: String::new() };
    if let Err(e) = answer(dir, id, &refusal) {
        tracing::warn!(target = "oryxis::mcp", request = %id, "sudo refusal not written: {e}");
        let _ = std::fs::remove_file(path_of(dir, id, "claimed"));
    }
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
/// request that is not a plain file within [`MAX_REQUEST_BYTES`],
/// unread. A request file this build cannot read is claimed and refused
/// as [`DenyReason::Unreadable`] here, so it is read once, not on every
/// poll, and its server learns now.
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
        // `DirEntry::metadata` is an `lstat`: a link's own age, never
        // its target's.
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
                let bytes = match read_request_file(&path) {
                    RequestRead::Bytes(bytes) => bytes,
                    RequestRead::Refused(why) => {
                        tracing::warn!(target = "oryxis::mcp", request = %stem, "sudo request {why}, removed unread");
                        let _ = std::fs::remove_file(&path);
                        continue;
                    }
                    // The next poll tries again (gone meanwhile = withdrawn
                    // or claimed elsewhere: nothing to do either way).
                    RequestRead::Failed(_) => continue,
                };
                let Some(request) = serde_json::from_slice::<SudoRequest>(&bytes).ok().filter(|r| r.id == stem) else {
                    tracing::warn!(target = "oryxis::mcp", request = %stem, "sudo request does not parse (plugin and app of different builds?), refused");
                    if std::fs::rename(&path, path_of(dir, stem, "claimed")).is_ok() {
                        refuse_unreadable(dir, stem);
                    }
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
    fn post_refuses_a_request_whose_file_outgrows_the_cap() {
        // The command cap counts raw bytes, the file cap the JSON the
        // app reads: a line break is two bytes there, so a command AT
        // the command cap made of line breaks makes a file over the file
        // cap, which the app removes unread. The server never writes it.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(DIR_NAME);
        let r = request(&dir);
        withdraw(&dir, &r.id);
        let file = dir.join(format!("{}.request", r.id));
        let escaped = SudoRequest { command: "\n".repeat(MAX_COMMAND_BYTES), ..r.clone() };
        let bytes = serde_json::to_vec(&escaped).unwrap().len();
        assert!(bytes as u64 > MAX_REQUEST_BYTES, "{bytes}");
        match encode(&escaped) {
            Err(EncodeError::TooLarge { bytes: measured }) => assert_eq!(measured, bytes),
            other => panic!("{other:?}"),
        }
        let err = post(&dir, &escaped).unwrap_err();
        assert!(err.to_string().contains(&format!("{bytes} bytes")), "{err}");
        assert!(!file.exists(), "nothing written");
        // The same command of plain bytes is within both caps.
        let plain = SudoRequest { command: "x".repeat(MAX_COMMAND_BYTES), ..r.clone() };
        let written = post(&dir, &plain).unwrap();
        assert_eq!(written, encode(&plain).unwrap());
        assert_eq!(std::fs::read(&file).unwrap(), written);
        assert!(claim(&dir, &r.id).is_some());
    }

    #[test]
    fn a_file_of_the_first_shape_still_claims() {
        // The request file byte for byte as the first plugin release
        // (mcp 0.1.14) posts it (`post` writes every field, `route` and
        // `client` included), and the same with the two defaulted fields
        // left out. A newer app adds fields with `#[serde(default)]`
        // only, so both claim on every later build; a required field
        // would turn every request of an installed plugin into a refusal.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(DIR_NAME);
        std::fs::create_dir_all(&dir).unwrap();
        let id = "0123456789abcdef0123456789abcdef";
        let as_posted = format!(
            "{{\"id\":\"{id}\",\"vault_id\":\"11111111-2222-4333-8444-555555555555\",\"vault_label\":\"Personal\",\
             \"host_id\":\"66666666-7777-4888-8999-000000000000\",\"host_label\":\"web\",\"login\":\"deploy\",\
             \"address\":\"10.0.0.5:22\",\"route\":[],\"client\":null,\"command\":\"id\",\"created_unix\":0}}"
        );
        let fields_left_out = as_posted.replace("\"route\":[],\"client\":null,", "");
        assert_ne!(as_posted, fields_left_out);
        // The literal above IS what this build's `post` writes.
        let built: SudoRequest = serde_json::from_str(&as_posted).unwrap();
        assert_eq!(serde_json::to_string(&built).unwrap(), as_posted, "post writes exactly this shape");
        for shape in [as_posted, fields_left_out] {
            std::fs::write(dir.join(format!("{id}.request")), shape.as_bytes()).unwrap();
            let claimed = claim(&dir, id).expect("the first release's file claims on this build");
            assert_eq!(claimed.request.command, "id");
            assert!(claimed.request.route.is_empty() && claimed.request.client.is_none());
            assert_eq!(claimed.bytes, shape.as_bytes());
            std::fs::remove_file(dir.join(format!("{id}.claimed"))).unwrap();
        }
    }

    #[test]
    fn a_reason_or_a_decision_this_build_does_not_know_is_never_the_persons() {
        // A newer app's reason reaches this plugin as Unknown, not as the
        // person's refusal (whose text tells the agent not to retry).
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(DIR_NAME);
        let r = request(&dir);
        assert!(claim(&dir, &r.id).is_some());
        let file = dir.join(format!("{}.answer", r.id));
        std::fs::write(&file, br#"{"decision":"deny","reason":"busy_elsewhere","tag":""}"#).unwrap();
        assert_eq!(
            status(&dir, &r.id),
            Status::Answered(Answer { decision: Decision::Deny, reason: Some(DenyReason::Unknown), tag: String::new() })
        );
        // A decision it does not know refuses, for an unknown reason too.
        std::fs::write(&file, br#"{"decision":"twice","tag":"ab"}"#).unwrap();
        assert_eq!(
            status(&dir, &r.id),
            Status::Answered(Answer { decision: Decision::Deny, reason: Some(DenyReason::Unknown), tag: String::new() })
        );
        // The reasons this build writes still read as themselves.
        for reason in [DenyReason::Person, DenyReason::TimedOut, DenyReason::Locked, DenyReason::AppClosed, DenyReason::Unreadable] {
            let a = Answer { decision: Decision::Deny, reason: Some(reason), tag: String::new() };
            std::fs::write(&file, serde_json::to_vec(&a).unwrap()).unwrap();
            assert_eq!(status(&dir, &r.id), Status::Answered(a));
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_request_the_app_fails_to_read_stays_for_the_next_poll() {
        // A read that fails for a reason of its own (here: no permission,
        // as a descriptor limit or a scanner holding the file would) is
        // not a bad request: the scan leaves it, the claim puts it back,
        // and once it reads it is offered and claimed as usual.
        use std::os::unix::fs::PermissionsExt as _;
        if running_as_root() {
            return; // root reads a 0000 file: nothing to fail.
        }
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(DIR_NAME);
        let (r, bytes) = posted(&dir);
        let file = dir.join(format!("{}.request", r.id));
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert!(scan(&dir, now()).posted.is_empty());
        assert!(file.exists(), "the scan kept it");
        assert_eq!(claim(&dir, &r.id), None);
        assert!(file.exists(), "the claim put it back");
        assert!(!dir.join(format!("{}.claimed", r.id)).exists());
        assert_eq!(status(&dir, &r.id), Status::Posted, "its server still waits for an answer");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(scan(&dir, now()).posted, vec![r.clone()]);
        assert_eq!(claim(&dir, &r.id).map(|c| c.bytes), Some(bytes));
    }

    #[cfg(unix)]
    fn running_as_root() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| s.lines().find(|l| l.starts_with("Uid:")).map(|l| l.split_whitespace().nth(1) == Some("0")))
            .unwrap_or(false)
    }

    #[test]
    fn a_request_gone_before_the_claim_is_no_alarm() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(DIR_NAME);
        let r = request(&dir);
        withdraw(&dir, &r.id);
        assert_eq!(claim(&dir, &r.id), None);
        assert_eq!(status(&dir, &r.id), Status::Gone, "nothing written for a withdrawn request");
    }

    #[test]
    fn a_request_this_build_cannot_read_is_refused_at_once() {
        // Not left as a live claim the server would wait a minute on.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(DIR_NAME);
        std::fs::create_dir_all(&dir).unwrap();
        let unreadable = Answer { decision: Decision::Deny, reason: Some(DenyReason::Unreadable), tag: String::new() };
        // Found by the scan: refused there, read once.
        let a = SudoRequest::new_id().unwrap();
        std::fs::write(dir.join(format!("{a}.request")), b"{\"id\":").unwrap();
        assert!(scan(&dir, now()).posted.is_empty());
        assert_eq!(status(&dir, &a), Status::Answered(unreadable.clone()));
        assert!(!dir.join(format!("{a}.claimed")).exists());
        // Rewritten between the scan and the claim: refused by the claim.
        let (r, _) = posted(&dir);
        std::fs::write(dir.join(format!("{}.request", r.id)), b"not json").unwrap();
        assert_eq!(claim(&dir, &r.id), None);
        assert_eq!(status(&dir, &r.id), Status::Answered(unreadable.clone()));
        // A body naming another id is refused the same way.
        let (r, bytes) = posted(&dir);
        let other = SudoRequest::new_id().unwrap();
        std::fs::write(dir.join(format!("{other}.request")), &bytes).unwrap();
        assert_eq!(claim(&dir, &other), None);
        assert_eq!(status(&dir, &other), Status::Answered(unreadable));
        assert_eq!(status(&dir, &r.id), Status::Posted, "the honest one is untouched");
    }

    #[cfg(unix)]
    #[test]
    fn a_request_that_is_not_a_plain_file_is_removed_unread() {
        // The folder's other writer (the agent's shell, as the user) may
        // plant a symlink to something huge, or a socket: neither is
        // opened, let alone read, on either path.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(DIR_NAME);
        std::fs::create_dir_all(&dir).unwrap();
        let big = tmp.path().join("big");
        std::fs::write(&big, vec![b'x'; (MAX_REQUEST_BYTES as usize) * 4]).unwrap();
        let (r, _) = posted(&dir);
        let request = dir.join(format!("{}.request", r.id));
        std::fs::remove_file(&request).unwrap();
        std::os::unix::fs::symlink(&big, &request).unwrap();
        assert!(scan(&dir, now()).posted.is_empty(), "a link is never offered");
        assert!(std::fs::symlink_metadata(&request).is_err(), "removed by the scan");
        std::os::unix::fs::symlink(&big, &request).unwrap();
        assert_eq!(claim(&dir, &r.id), None, "a link is never claimed");
        assert!(std::fs::symlink_metadata(&request).is_err());
        assert!(!dir.join(format!("{}.claimed", r.id)).exists());
        assert_eq!(std::fs::read(&big).unwrap().len(), (MAX_REQUEST_BYTES as usize) * 4, "the target is untouched");

        let socket = dir.join(format!("{}.request", SudoRequest::new_id().unwrap()));
        let _held = std::os::unix::net::UnixDatagram::bind(&socket).unwrap();
        assert!(scan(&dir, now()).posted.is_empty());
        assert!(std::fs::symlink_metadata(&socket).is_err(), "a socket is removed unread");
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
