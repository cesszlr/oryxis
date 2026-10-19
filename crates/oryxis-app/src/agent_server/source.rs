//! The key source an agent connection signs against.
//!
//! The protocol layer ([`super::protocol`]) is generic over this trait
//! so it can be exercised with a [`MockKeySource`] in tests and backed
//! by the vault in production (`VaultKeySource`, Phase 2). Vault keys
//! are strictly read-only over the wire; when the user opts in
//! (Phase 4), external clients such as KeePassXC may ADD keys, which
//! live in an in-memory [`EphemeralStore`] beside the vault roster and
//! are never persisted.
//!
//! Security contract for the vault-backed impl: [`sign`](AgentKeySource::sign)
//! decrypts exactly one private key, uses it, and drops it; nothing is
//! cached across calls. A locked vault makes [`list`](AgentKeySource::list)
//! return empty and [`sign`](AgentKeySource::sign) fail, so an external
//! `git` sees "agent has no identities" instead of a hang. Ephemeral
//! keys are swept on lock: a locked Oryxis serves nothing at all.

use ssh_key::HashAlg;

/// One public key the agent advertises: its SSH wire blob (the bytes an
/// `IDENTITIES_ANSWER` carries) and a human comment (the vault label).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AgentPublicKey {
    /// The public key encoded as an SSH wire blob (`KeyData` encoding).
    pub blob: Vec<u8>,
    /// Comment shown by `ssh-add -l` etc.; the vault key's label.
    pub comment: String,
    /// The client asked for a per-signature confirm when it added this
    /// key (`SSH_AGENT_CONSTRAIN_CONFIRM`); prompts even when the
    /// global confirm setting is off. Always `false` for vault keys
    /// (their prompting is the global setting's call).
    pub requires_confirm: bool,
}

/// Why a sign request could not be answered. The protocol layer maps
/// every variant to a single `FAILURE` on the wire (the ssh-agent
/// protocol has no error detail), but the distinction drives logging.
#[derive(Debug)]
pub(crate) enum AgentSignError {
    /// No exposed key matches the requested blob.
    UnknownKey,
    /// The vault is locked (or the key is gone); nothing to sign with.
    Unavailable,
    /// The key material could not be parsed or the signature failed.
    SignFailed(String),
}

/// The RSA hash the client asked for, decoded from the `SIGN_REQUEST`
/// flag bits. Ed25519 / ECDSA ignore it (their hash is fixed by the
/// algorithm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SignHash {
    /// No RSA flag set: default to SHA-256. Legacy ssh-rsa (SHA-1) is
    /// deprecated and rejected by modern servers, so we never emit it;
    /// a client that sets no flag is rare and SHA-256 is universally
    /// accepted.
    Default,
    Sha256,
    Sha512,
}

impl SignHash {
    /// The `ssh-key` hash for RSA signing (`None` for non-RSA keys,
    /// which the caller passes through unchanged).
    pub(crate) fn rsa_hash(self) -> Option<HashAlg> {
        match self {
            Self::Sha512 => Some(HashAlg::Sha512),
            // Default and explicit 256 both sign with SHA-256.
            Self::Default | Self::Sha256 => Some(HashAlg::Sha256),
        }
    }
}

/// A source of SSH keys for the agent to serve. `Send + Sync` so one
/// instance is shared across per-connection tasks. The write ops
/// default to refusing (a read-only signing oracle); sources that
/// accept external keys override them with an [`EphemeralStore`].
pub(crate) trait AgentKeySource: Send + Sync {
    /// The keys to advertise right now. Empty while the vault is locked
    /// or when the user has exposed none.
    fn list(&self) -> Vec<AgentPublicKey>;

    /// Sign `data` with the key whose wire blob is `key_blob`, honoring
    /// the requested RSA hash. Returns the SSH signature wire blob (the
    /// `string signature` a `SIGN_RESPONSE` carries).
    fn sign(
        &self,
        key_blob: &[u8],
        data: &[u8],
        hash: SignHash,
    ) -> Result<Vec<u8>, AgentSignError>;

    /// Accept a client-added key (`ADD_IDENTITY`). `false` = refused
    /// (the wire answer is FAILURE). Read-only by default.
    fn add(
        &self,
        _private: ssh_key::PrivateKey,
        _comment: String,
        _requires_confirm: bool,
        _expires_at: Option<std::time::Instant>,
    ) -> bool {
        false
    }

    /// Remove a client-added key by its public blob. Vault keys are
    /// never removable over the wire. Read-only by default.
    fn remove(&self, _key_blob: &[u8]) -> bool {
        false
    }

    /// Remove every client-added key (`REMOVE_ALL_IDENTITIES`); the
    /// vault roster is untouched. Read-only by default.
    fn remove_all(&self) -> bool {
        false
    }
}

/// Sign `data` with an in-memory private key, honoring the requested
/// RSA hash, and encode the signature as its SSH wire blob. Shared by
/// the vault decrypt-at-sign path and the ephemeral store.
pub(crate) fn sign_blob(
    private: &ssh_key::PrivateKey,
    data: &[u8],
    hash: SignHash,
) -> Result<Vec<u8>, AgentSignError> {
    use ssh_encoding::Encode;
    use ssh_key::private::KeypairData;

    let sig: ssh_key::Signature = match private.key_data() {
        KeypairData::Rsa(pair) => signature::Signer::try_sign(&(pair, hash.rsa_hash()), data)
            .map_err(|e| AgentSignError::SignFailed(e.to_string()))?,
        _ => signature::Signer::try_sign(private, data)
            .map_err(|e| AgentSignError::SignFailed(e.to_string()))?,
    };
    let mut out = Vec::new();
    sig.encode(&mut out)
        .map_err(|e| AgentSignError::SignFailed(e.to_string()))?;
    Ok(out)
}

/// A key pushed in by an external client (KeePassXC et al). Lives in
/// memory only; the vault never sees it.
struct EphemeralKey {
    blob: Vec<u8>,
    private: ssh_key::PrivateKey,
    comment: String,
    requires_confirm: bool,
    /// Lifetime constraint deadline; `None` = until removed / swept.
    expires_at: Option<std::time::Instant>,
}

/// The in-memory roster of client-added keys. Expired entries are
/// pruned lazily on every access (no timer to leak); [`clear`] is the
/// sweep hook for vault lock / toggle-off.
///
/// [`clear`]: EphemeralStore::clear
#[derive(Default)]
pub(crate) struct EphemeralStore {
    keys: std::sync::Mutex<Vec<EphemeralKey>>,
    /// Bumped on every accepted ADD, never decremented. Lets the app
    /// notice "a key just landed" by comparing two readings, without
    /// walking the roster (which holds private material) and without a
    /// push channel into the update loop. A re-add of the same blob
    /// counts: KeePassXC re-pushes on every database unlock, and that
    /// unlock IS the event a waiting connection cares about.
    adds: std::sync::atomic::AtomicU64,
}

impl EphemeralStore {
    fn prune(keys: &mut Vec<EphemeralKey>) {
        let now = std::time::Instant::now();
        keys.retain(|k| k.expires_at.is_none_or(|t| t > now));
    }

    pub(crate) fn list(&self) -> Vec<AgentPublicKey> {
        let Ok(mut keys) = self.keys.lock() else {
            return Vec::new();
        };
        Self::prune(&mut keys);
        keys.iter()
            .map(|k| AgentPublicKey {
                blob: k.blob.clone(),
                comment: k.comment.clone(),
                requires_confirm: k.requires_confirm,
            })
            .collect()
    }

    /// Store a key, replacing any existing entry for the same public
    /// blob (a re-add refreshes comment and constraints, matching
    /// OpenSSH). `false` only when the public blob cannot be encoded.
    pub(crate) fn add(
        &self,
        private: ssh_key::PrivateKey,
        comment: String,
        requires_confirm: bool,
        expires_at: Option<std::time::Instant>,
    ) -> bool {
        use ssh_encoding::Encode;
        let mut blob = Vec::new();
        if private.public_key().key_data().encode(&mut blob).is_err() {
            return false;
        }
        let Ok(mut keys) = self.keys.lock() else {
            return false;
        };
        Self::prune(&mut keys);
        keys.retain(|k| k.blob != blob);
        keys.push(EphemeralKey {
            blob,
            private,
            comment,
            requires_confirm,
            expires_at,
        });
        self.adds
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        true
    }

    /// Monotonic count of accepted ADDs (see [`EphemeralStore::adds`]).
    pub(crate) fn add_generation(&self) -> u64 {
        self.adds.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Drop the entry for `blob`; `false` when no added key matches
    /// (vault keys deliberately land here).
    pub(crate) fn remove(&self, blob: &[u8]) -> bool {
        let Ok(mut keys) = self.keys.lock() else {
            return false;
        };
        Self::prune(&mut keys);
        let before = keys.len();
        keys.retain(|k| k.blob != blob);
        keys.len() < before
    }

    /// Sweep every added key (vault lock, toggle-off, REMOVE_ALL).
    pub(crate) fn clear(&self) {
        if let Ok(mut keys) = self.keys.lock() {
            keys.clear();
        }
    }

    /// Number of live (non-expired) client-added keys. Feeds the
    /// settings status line so "the agent is up but currently holds
    /// zero external keys" is visible instead of a silent auth
    /// failure (issue #98).
    pub(crate) fn live_count(&self) -> usize {
        let Ok(mut keys) = self.keys.lock() else {
            return 0;
        };
        Self::prune(&mut keys);
        keys.len()
    }

    /// Sign with an added key if `blob` is ours; `None` hands the
    /// lookup back to the caller (a vault key or unknown).
    pub(crate) fn sign(
        &self,
        blob: &[u8],
        data: &[u8],
        hash: SignHash,
    ) -> Option<Result<Vec<u8>, AgentSignError>> {
        let Ok(mut keys) = self.keys.lock() else {
            return None;
        };
        Self::prune(&mut keys);
        let key = keys.iter().find(|k| k.blob == blob)?;
        Some(sign_blob(&key.private, data, hash))
    }
}

/// One unlocked vault the agent serves from: its own dedicated
/// `VaultStore` handle (a second SQLite handle on the same file, like
/// `sync_runtime`; WAL keeps concurrent handles safe).
struct AttachedVault {
    id: uuid::Uuid,
    /// The vault's name, for the key comment when several are attached
    /// (`ssh-add -l`, the confirm prompt).
    label: String,
    store: oryxis_vault::VaultStore,
}

/// The production [`AgentKeySource`]: every UNLOCKED vault's exposed
/// keys, merged (`MULTI_VAULT_SPEC.md` § 11), plus the client-added
/// ones. A vault is attached on its unlock and detached on its lock, so
/// its keys leave the roster at once (the next `REQUEST_IDENTITIES`
/// does not list them, a sign request for one fails). Keys are
/// advertised by their public blob; a private key is decrypted only
/// inside [`sign`] and dropped immediately. The same public key in two
/// vaults is listed once and signed by the first vault holding it.
/// With no vault attached the agent is dark: it lists nothing, signs
/// nothing and takes no adds.
pub(crate) struct VaultKeySource {
    vaults: std::sync::Mutex<Vec<AttachedVault>>,
    /// The runtime is gone (`AgentRuntime` dropped): per-connection
    /// tasks that outlive it must go dark for good, whatever attaches.
    closed: std::sync::atomic::AtomicBool,
    /// The `agent_server_allow_add` setting, baked at spawn (the
    /// runtime restarts on toggle). Off = pure read-only oracle.
    allow_add: bool,
    /// Client-added keys (Phase 4). Belong to no vault; only ever
    /// populated when `allow_add` is on; swept when the last vault
    /// detaches.
    ephemeral: EphemeralStore,
}

impl VaultKeySource {
    /// A source serving nothing yet: vaults come with [`Self::attach`].
    pub(crate) fn new(allow_add: bool) -> Self {
        Self {
            vaults: std::sync::Mutex::new(Vec::new()),
            closed: std::sync::atomic::AtomicBool::new(false),
            allow_add,
            ephemeral: EphemeralStore::default(),
        }
    }

    /// Live count of client-added keys (settings status line).
    pub(crate) fn external_key_count(&self) -> usize {
        self.ephemeral.live_count()
    }

    /// Monotonic ADD counter, compared reading-to-reading by the
    /// port-forward healer to spot "an external tool just pushed a key".
    pub(crate) fn external_add_generation(&self) -> u64 {
        self.ephemeral.add_generation()
    }

    /// Serve vault `id` from `store`, an unlocked handle of its own
    /// (replacing one already attached for it).
    pub(crate) fn attach(&self, id: uuid::Uuid, label: String, store: oryxis_vault::VaultStore) {
        let Ok(mut vaults) = self.vaults.lock() else {
            return;
        };
        if vaults.is_empty() {
            // An `add` that read "something attached" just before the
            // last detach swept the roster could have inserted its key
            // AFTER that sweep (the check is outside the ephemeral
            // mutex). Invisible while dark, it would resurface now;
            // clear it so "swept when the agent goes dark" holds across
            // the race.
            self.ephemeral.clear();
        }
        if let Some(mut old) = vaults.iter().position(|v| v.id == id).map(|i| vaults.remove(i)) {
            old.store.lock();
        }
        vaults.push(AttachedVault { id, label, store });
    }

    /// Stop serving vault `id` (its lock, its removal): its handle is
    /// locked (the key zeroized) and dropped. The last vault leaving
    /// sweeps the client-added keys: a locked Oryxis serves nothing
    /// (clients like KeePassXC re-add after the next unlock).
    pub(crate) fn detach(&self, id: uuid::Uuid) {
        let Ok(mut vaults) = self.vaults.lock() else {
            return;
        };
        if let Some(mut gone) = vaults.iter().position(|v| v.id == id).map(|i| vaults.remove(i)) {
            gone.store.lock();
        }
        if vaults.is_empty() {
            self.ephemeral.clear();
        }
    }

    /// The vault's new name, for its keys' comments.
    pub(crate) fn relabel(&self, id: uuid::Uuid, label: String) {
        if let Ok(mut vaults) = self.vaults.lock()
            && let Some(v) = vaults.iter_mut().find(|v| v.id == id)
        {
            v.label = label;
        }
    }

    /// Go dark for good (the runtime is dropped): every handle locked
    /// and dropped, the added keys swept, nothing attaches again.
    pub(crate) fn close(&self) {
        self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Ok(mut vaults) = self.vaults.lock() {
            for mut v in vaults.drain(..) {
                v.store.lock();
            }
        }
        self.ephemeral.clear();
    }

    /// Nothing to serve: closed, or no vault attached.
    fn dark(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::SeqCst)
            || self.vaults.lock().map_or(true, |v| v.is_empty())
    }

    /// The public blob (KeyData wire encoding) of a stored key's
    /// OpenSSH public line, or `None` when it does not parse.
    fn blob_of(public_line: &str) -> Option<Vec<u8>> {
        use ssh_encoding::Encode;
        let pk = ssh_key::PublicKey::from_openssh(public_line).ok()?;
        let mut blob = Vec::new();
        pk.key_data().encode(&mut blob).ok()?;
        Some(blob)
    }

    /// The keys a vault serves: exposed, holding private material, and
    /// never a security-key row, whether or not it holds material. The
    /// app signs with a token natively (the stored blob is a FIDO2
    /// credential handle, not a scalar), so a `has_private` row can
    /// still be one this agent must not advertise: `sign` would hand
    /// the handle to a software signer. The algorithm check is what
    /// keeps `list()` symmetric with `sign()`; `has_private`
    /// additionally covers a plain public-only import.
    fn served(key: &oryxis_core::models::SshKey) -> bool {
        key.expose_via_agent && key.has_private && !key.algorithm.is_security_key()
    }
}

impl AgentKeySource for VaultKeySource {
    fn list(&self) -> Vec<AgentPublicKey> {
        if self.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return Vec::new();
        }
        let Ok(vaults) = self.vaults.lock() else {
            return Vec::new();
        };
        if vaults.is_empty() {
            return Vec::new();
        }
        // With several vaults a key's comment names its vault, which is
        // also how the confirm prompt says where the key came from.
        let several = vaults.len() > 1;
        let mut out: Vec<AgentPublicKey> = Vec::new();
        for vault in vaults.iter() {
            for key in vault.store.list_keys().unwrap_or_default().into_iter().filter(Self::served) {
                let Some(blob) = Self::blob_of(&key.public_key) else {
                    continue;
                };
                if out.iter().any(|k| k.blob == blob) {
                    continue;
                }
                let comment = if several { format!("{} \u{b7} {}", key.label, vault.label) } else { key.label };
                out.push(AgentPublicKey { blob, comment, requires_confirm: false });
            }
        }
        out.extend(self.ephemeral.list());
        out
    }

    fn sign(
        &self,
        key_blob: &[u8],
        data: &[u8],
        hash: SignHash,
    ) -> Result<Vec<u8>, AgentSignError> {
        use ssh_key::PrivateKey;

        if self.dark() {
            return Err(AgentSignError::Unavailable);
        }
        // Client-added keys sign from memory; the vault path below only
        // ever sees vault keys.
        if let Some(result) = self.ephemeral.sign(key_blob, data, hash) {
            return result;
        }
        let vaults = self.vaults.lock().map_err(|_| AgentSignError::Unavailable)?;

        // The first attached vault whose exposed key matches the blob,
        // then decrypt exactly that one private key.
        let (vault, key) = vaults
            .iter()
            .find_map(|v| {
                v.store
                    .list_keys()
                    .ok()?
                    .into_iter()
                    .find(|k| Self::served(k) && Self::blob_of(&k.public_key).as_deref() == Some(key_blob))
                    .map(|k| (v, k))
            })
            .ok_or(AgentSignError::UnknownKey)?;

        // The vault getter hands back a plain `String`; wrap it so the
        // decrypted PEM (the same key material as the parsed key) is
        // wiped when it drops, not left in freed heap. Honours the
        // module's decrypt-per-signature / nothing-cached contract.
        let pem = zeroize::Zeroizing::new(
            vault
                .store
                .get_key_private(&key.id)
                .map_err(|e| AgentSignError::SignFailed(e.to_string()))?
                .ok_or(AgentSignError::Unavailable)?,
        );
        // The parsed key is zeroized on drop by ssh_key; the PEM above
        // by the Zeroizing wrapper.
        let private = PrivateKey::from_openssh(&*pem)
            .map_err(|e| AgentSignError::SignFailed(e.to_string()))?;

        sign_blob(&private, data, hash)
    }

    fn add(
        &self,
        private: ssh_key::PrivateKey,
        comment: String,
        requires_confirm: bool,
        expires_at: Option<std::time::Instant>,
    ) -> bool {
        // Adds are refused while dark (no vault unlocked) and when the
        // user has not opted in.
        if !self.allow_add || self.dark() {
            return false;
        }
        self.ephemeral.add(private, comment, requires_confirm, expires_at)
    }

    fn remove(&self, key_blob: &[u8]) -> bool {
        if !self.allow_add || self.dark() {
            return false;
        }
        self.ephemeral.remove(key_blob)
    }

    fn remove_all(&self) -> bool {
        if !self.allow_add || self.dark() {
            return false;
        }
        // Clearing an already-empty roster is still a success.
        self.ephemeral.clear();
        true
    }
}

#[cfg(test)]
pub(crate) mod mock {
    use super::*;
    use ssh_encoding::Encode;
    use ssh_key::PrivateKey;

    /// In-memory key source for protocol tests: holds decrypted keys
    /// directly (a test convenience the vault-backed impl never does).
    /// `new` mirrors the read-only default; [`writable`] mirrors the
    /// opt-in `allow_add` mode.
    ///
    /// [`writable`]: MockKeySource::writable
    pub(crate) struct MockKeySource {
        keys: Vec<(Vec<u8>, PrivateKey, String)>,
        pub locked: std::sync::atomic::AtomicBool,
        allow_add: bool,
        ephemeral: EphemeralStore,
    }

    impl MockKeySource {
        pub(crate) fn new(keys: Vec<(PrivateKey, String)>) -> Self {
            Self::build(keys, false)
        }

        /// A source that accepts ADD/REMOVE, like a production source
        /// with `agent_server_allow_add` on.
        pub(crate) fn writable(keys: Vec<(PrivateKey, String)>) -> Self {
            Self::build(keys, true)
        }

        fn build(keys: Vec<(PrivateKey, String)>, allow_add: bool) -> Self {
            let keys = keys
                .into_iter()
                .map(|(k, label)| {
                    let mut blob = Vec::new();
                    k.public_key().key_data().encode(&mut blob).unwrap();
                    (blob, k, label)
                })
                .collect();
            Self {
                keys,
                locked: std::sync::atomic::AtomicBool::new(false),
                allow_add,
                ephemeral: EphemeralStore::default(),
            }
        }
    }

    impl AgentKeySource for MockKeySource {
        fn list(&self) -> Vec<AgentPublicKey> {
            if self.locked.load(std::sync::atomic::Ordering::Relaxed) {
                return Vec::new();
            }
            self.keys
                .iter()
                .map(|(blob, _, comment)| AgentPublicKey {
                    blob: blob.clone(),
                    comment: comment.clone(),
                    requires_confirm: false,
                })
                .chain(self.ephemeral.list())
                .collect()
        }

        fn sign(
            &self,
            key_blob: &[u8],
            data: &[u8],
            hash: SignHash,
        ) -> Result<Vec<u8>, AgentSignError> {
            if self.locked.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(AgentSignError::Unavailable);
            }
            if let Some(result) = self.ephemeral.sign(key_blob, data, hash) {
                return result;
            }
            let (_, key, _) = self
                .keys
                .iter()
                .find(|(blob, _, _)| blob == key_blob)
                .ok_or(AgentSignError::UnknownKey)?;
            sign_blob(key, data, hash)
        }

        fn add(
            &self,
            private: PrivateKey,
            comment: String,
            requires_confirm: bool,
            expires_at: Option<std::time::Instant>,
        ) -> bool {
            if !self.allow_add || self.locked.load(std::sync::atomic::Ordering::Relaxed) {
                return false;
            }
            self.ephemeral.add(private, comment, requires_confirm, expires_at)
        }

        fn remove(&self, key_blob: &[u8]) -> bool {
            if !self.allow_add || self.locked.load(std::sync::atomic::Ordering::Relaxed) {
                return false;
            }
            self.ephemeral.remove(key_blob)
        }

        fn remove_all(&self) -> bool {
            if !self.allow_add || self.locked.load(std::sync::atomic::Ordering::Relaxed) {
                return false;
            }
            self.ephemeral.clear();
            true
        }
    }
}

/// Unit tests for the ephemeral store's own mechanics (expiry pruning,
/// same-blob replacement); the wire-level behavior is covered by the
/// protocol tests.
#[cfg(test)]
mod ephemeral_tests {
    use super::*;

    fn key(label: &str) -> ssh_key::PrivateKey {
        let g = oryxis_vault::generate_key(label, "", oryxis_vault::GenerateSpec::Ed25519)
            .unwrap();
        ssh_key::PrivateKey::from_openssh(&g.private_pem).unwrap()
    }

    #[test]
    fn expired_key_is_pruned_on_access() {
        let store = EphemeralStore::default();
        assert!(store.add(key("a"), "a".into(), false, Some(std::time::Instant::now())));
        // The deadline has passed by the next access (retain keeps only
        // strictly-future deadlines).
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(store.list().is_empty(), "expired key no longer advertised");
        let blob = {
            use ssh_encoding::Encode;
            let k = key("b");
            let mut blob = Vec::new();
            k.public_key().key_data().encode(&mut blob).unwrap();
            blob
        };
        assert!(store.sign(&blob, b"x", SignHash::Default).is_none());
    }

    #[test]
    fn re_add_replaces_same_key() {
        let store = EphemeralStore::default();
        let k = key("a");
        assert!(store.add(k.clone(), "first".into(), false, None));
        assert!(store.add(k, "second".into(), true, None));
        let listed = store.list();
        assert_eq!(listed.len(), 1, "same blob is replaced, not duplicated");
        assert_eq!(listed[0].comment, "second");
        assert!(listed[0].requires_confirm, "constraints refreshed on re-add");
    }
}

/// Integration tests for the production [`VaultKeySource`] against a
/// real on-disk vault, exercising the two-handle model the runtime
/// uses (the app writes through one `VaultStore`, the agent reads
/// through its own). These cover the runtime guarantees the protocol
/// tests only prove on the mock: a live `expose_via_agent` toggle
/// crossing handles, and the lock gate.
#[cfg(test)]
mod vault_source_tests {
    use super::*;
    use oryxis_vault::{generate_key, GenerateSpec, VaultStore};

    /// Open a fresh password-protected vault, save one exposed key
    /// through the "app" handle, and return the temp dir (kept alive),
    /// the db path, and the key id.
    fn seed_vault() -> (tempfile::TempDir, std::path::PathBuf, uuid::Uuid) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let mut app = VaultStore::open(&path).unwrap();
        app.set_master_password("master").unwrap();
        let generated = generate_key("agent-key", "", GenerateSpec::Ed25519).unwrap();
        let id = generated.key.id;
        app.save_key(&generated.key, Some(&generated.private_pem)).unwrap();
        (dir, path, id)
    }

    /// A second handle on the same file, unlocked, wrapped as the
    /// production source, mirroring `AgentRuntime::spawn`.
    fn agent_source(path: &std::path::Path) -> VaultKeySource {
        agent_source_with(path, false)
    }

    fn agent_source_with(path: &std::path::Path, allow_add: bool) -> VaultKeySource {
        let source = VaultKeySource::new(allow_add);
        source.attach(VAULT, "Personal".into(), agent_handle(path));
        source
    }

    /// The vault id the single-vault tests attach under.
    const VAULT: uuid::Uuid = uuid::Uuid::from_u128(1);

    /// The agent's own unlocked handle on the file.
    fn agent_handle(path: &std::path::Path) -> VaultStore {
        let mut agent = VaultStore::open(path).unwrap();
        agent.unlock("master").unwrap();
        agent
    }

    /// A decrypted in-memory key, as an external ADD would deliver it.
    fn external_key(label: &str) -> ssh_key::PrivateKey {
        let g = generate_key(label, "", GenerateSpec::Ed25519).unwrap();
        ssh_key::PrivateKey::from_openssh(&g.private_pem).unwrap()
    }

    #[test]
    fn exposed_key_lists_and_signs() {
        use signature::Verifier;
        use ssh_encoding::Decode;

        let (_dir, path, _id) = seed_vault();
        let source = agent_source(&path);

        let listed = source.list();
        assert_eq!(listed.len(), 1, "the exposed key is advertised");

        // The advertised blob signs, and the signature verifies against
        // the same public key: the decrypt-at-sign path is real crypto.
        let blob = listed[0].blob.clone();
        let data = b"cross-handle sign";
        let sig_blob = source.sign(&blob, data, SignHash::Default).unwrap();
        let sig = ssh_key::Signature::decode(&mut sig_blob.as_slice()).unwrap();
        let key_data = ssh_key::public::KeyData::decode(&mut blob.as_slice()).unwrap();
        key_data.verify(data, &sig).expect("signature verifies");
    }

    #[test]
    fn expose_toggle_crosses_handles_live() {
        let (_dir, path, id) = seed_vault();
        let source = agent_source(&path);
        assert_eq!(source.list().len(), 1);
        let blob = source.list()[0].blob.clone();

        // Flip the flag through a SEPARATE app handle (the write path
        // the UI uses), then confirm the already-running agent source
        // drops the key on its very next read. This is the guarantee
        // the "Hidden from agent" menu item makes.
        let app = {
            let mut v = VaultStore::open(&path).unwrap();
            v.unlock("master").unwrap();
            v
        };
        let mut key = app.list_keys().unwrap().into_iter().find(|k| k.id == id).unwrap();
        key.expose_via_agent = false;
        app.save_key(&key, None).unwrap();

        assert!(source.list().is_empty(), "hidden key is no longer advertised");
        // The sign path re-checks the flag independently: even a stale
        // blob from a client that listed earlier cannot sign now.
        assert!(
            matches!(source.sign(&blob, b"x", SignHash::Default), Err(AgentSignError::UnknownKey)),
            "a hidden key refuses to sign",
        );

        // Re-expose: the key comes back on the next read, no restart.
        key.expose_via_agent = true;
        app.save_key(&key, None).unwrap();
        assert_eq!(source.list().len(), 1, "re-exposed key is advertised again");
    }

    #[test]
    fn lock_gate_hides_and_restores_roster() {
        let (_dir, path, _id) = seed_vault();
        let source = agent_source(&path);
        assert_eq!(source.list().len(), 1);
        let blob = source.list()[0].blob.clone();

        source.detach(VAULT);
        assert!(source.list().is_empty(), "a locked vault serves no identities");
        assert!(
            matches!(source.sign(&blob, b"x", SignHash::Default), Err(AgentSignError::Unavailable)),
            "a locked vault cannot sign",
        );

        source.attach(VAULT, "Personal".into(), agent_handle(&path));
        assert_eq!(source.list().len(), 1, "unlock restores the roster");
        assert!(source.sign(&blob, b"x", SignHash::Default).is_ok(), "unlock restores signing");
    }

    #[test]
    fn add_refused_unless_opted_in() {
        let (_dir, path, _id) = seed_vault();

        // Default (allow_add off): the read-only oracle refuses every
        // write op even though the vault is unlocked.
        let source = agent_source(&path);
        assert!(!source.add(external_key("ext"), "ext".into(), false, None));
        assert!(!source.remove_all());

        // Opted in: the add lands beside the vault key.
        let source = agent_source_with(&path, true);
        assert!(source.add(external_key("ext"), "ext".into(), false, None));
        assert_eq!(source.list().len(), 2, "vault key + added key");
    }

    #[test]
    fn lock_sweeps_added_keys() {
        let (_dir, path, _id) = seed_vault();
        let source = agent_source_with(&path, true);
        assert!(source.add(external_key("ext"), "ext".into(), false, None));
        assert_eq!(source.list().len(), 2);

        // Lock: everything goes dark, INCLUDING the added key, and it
        // stays gone after unlock (the client re-adds when it wants to).
        source.detach(VAULT);
        assert!(source.list().is_empty());
        assert!(!source.add(external_key("ext2"), "ext2".into(), false, None), "locked refuses adds");
        source.attach(VAULT, "Personal".into(), agent_handle(&path));
        assert_eq!(source.list().len(), 1, "only the vault key survives the lock");

        // REMOVE_ALL sweeps added keys but never the vault roster.
        assert!(source.add(external_key("ext"), "ext".into(), false, None));
        assert_eq!(source.list().len(), 2);
        assert!(source.remove_all());
        assert_eq!(source.list().len(), 1, "vault key untouched by REMOVE_ALL");
    }

    #[test]
    fn every_unlocked_vault_serves_and_a_lock_takes_only_its_own() {
        use oryxis_vault::{generate_key, GenerateSpec};

        let (_a_dir, a_path, _) = seed_vault();
        let (_b_dir, b_path, _) = seed_vault();
        // A key both vaults hold (an import keeps the key): listed once.
        let shared = generate_key("shared", "", GenerateSpec::Ed25519).unwrap();
        for path in [&a_path, &b_path] {
            let mut v = VaultStore::open(path).unwrap();
            v.unlock("master").unwrap();
            v.save_key(&shared.key, Some(&shared.private_pem)).unwrap();
        }
        let (work, home) = (uuid::Uuid::from_u128(2), uuid::Uuid::from_u128(3));
        let source = VaultKeySource::new(true);
        source.attach(work, "Work".into(), agent_handle(&a_path));
        source.attach(home, "Home".into(), agent_handle(&b_path));
        let listed = source.list();
        assert_eq!(listed.len(), 3, "each vault's own key, the shared one once");
        assert!(listed.iter().all(|k| k.comment.ends_with(" \u{b7} Work") || k.comment.ends_with(" \u{b7} Home")),
            "with several vaults a key names its vault: {listed:?}");
        let shared_blob = listed.iter().find(|k| k.comment.starts_with("shared")).unwrap().blob.clone();
        assert!(source.add(external_key("ext"), "ext".into(), false, None));

        // Work locks: its own key leaves, Home's stay, the shared key
        // signs from Home, the added key stays while a vault serves.
        source.detach(work);
        let left = source.list();
        assert_eq!(left.len(), 3, "Home's key, the shared key, the added key: {left:?}");
        assert!(left.iter().all(|k| !k.comment.ends_with("Work")));
        assert_eq!(left.iter().filter(|k| k.comment.contains("Home")).count(), 0, "one vault left: plain comments");
        assert!(source.sign(&shared_blob, b"x", SignHash::Default).is_ok(), "the other vault signs it");

        // The last one locks: dark, the added key swept.
        source.detach(home);
        assert!(source.list().is_empty());
        assert!(!source.add(external_key("ext2"), "ext2".into(), false, None));
        source.attach(home, "Home".into(), agent_handle(&b_path));
        assert_eq!(source.list().len(), 2, "the added key did not survive the dark");
    }

    #[test]
    fn a_closed_source_never_serves_again() {
        let (_dir, path, _id) = seed_vault();
        let source = agent_source(&path);
        source.close();
        source.attach(VAULT, "Personal".into(), agent_handle(&path));
        assert!(source.list().is_empty(), "a dropped runtime's survivors stay dark");
    }
}
