//! The device store: `~/.oryxis/device.json`, what belongs to this
//! MACHINE rather than to any vault.
//!
//! Two things live here, both readable with every vault locked:
//!
//! - the vault REGISTRY (which vault files this device knows, the one
//!   the app opens first). Today it holds the one vault every install
//!   has, `vault.db`; multi-vault adds rows.
//! - the DEVICE SETTINGS: the few settings a process or a machine can
//!   only have one of (the UI language, the window geometry, the
//!   renderer, the folders and programs on this disk, the agent socket,
//!   the shortcut table). [`DEVICE_KEYS`] and [`DEVICE_PREFIXES`] are the
//!   one authority on which keys those are; every other setting belongs
//!   to a vault.
//!
//! **The routing is inside `VaultStore`.** `get_setting`, `set_setting`,
//! `list_settings` and `delete_settings_with_prefix` send a device key
//! here when the store has a device store attached, so the hundreds of
//! call sites that read and write settings by key keep doing so and
//! cannot pick the wrong side. `VaultStore::open` attaches the store
//! INSTALLED for the process ([`install`], called once by the app at
//! startup, before the first open); a process that installs none (the
//! MCP server, every test binary) keeps reading the vault's own rows.
//! Tests attach explicitly (`VaultStore::attach_device`) and NEVER
//! install: a test binary runs its tests in one process, and an
//! installed store would route every other test's settings into one
//! shared file.
//!
//! **Read-through.** Every read stats the file and re-reads it when it
//! changed (another process wrote it) or vanished (the harness wipes the
//! sandbox between tests while the process lives on); a missing file
//! reads as a fresh device, so nothing a previous run cached survives a
//! wipe. Writes are read-modify-write under an OS lock on
//! `device.json.lock`, temp + rename, so two processes (a second launch
//! on Linux / macOS) never lose each other's keys.
//!
//! **Migration.** The device keys used to be rows in the vault's own
//! `settings` table. [`DeviceStore::seed_from_first_vault`] copies them
//! ONCE, read-only, from the first vault, filling only keys the device
//! store does not hold yet, and marks the store seeded only after a read
//! that succeeded (a vault that does not open today, the rebuild's
//! patient, is read on the next start). The rows stay in the vault: a
//! downgraded build still finds them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// File name under the `.oryxis` folder.
pub const FILE_NAME: &str = "device.json";

/// The file name every install's first vault has, relative to the
/// `.oryxis` folder.
pub const FIRST_VAULT_FILE: &str = "vault.db";

/// The id of the vault that existed before the registry did (the
/// install's `vault.db`). Fixed, so a device store that has not been
/// written yet (first run, a wiped harness sandbox) names that vault
/// with the same id on every read.
pub const FIRST_VAULT_ID: Uuid = Uuid::from_u128(0x6f72_7978_6973_4000_8000_0000_0000_0001);

/// Format version written into the file. Unknown fields a newer build
/// adds are carried through untouched (`extra`), so an older build that
/// rewrites the file does not strip them.
const FORMAT_VERSION: u32 = 1;

/// Settings that belong to the device, by exact key. Kept beside
/// [`DEVICE_PREFIXES`]; `is_device_key` reads both.
pub const DEVICE_KEYS: &[&str] = &[
    // `i18n::t` and the RTL switch are process-wide: two windows cannot
    // speak two languages.
    "language",
    "layout_direction",
    // One remembered geometry, one tray.
    "window_width",
    "window_height",
    "window_pos_x",
    "window_pos_y",
    "window_maximized",
    "window_fullscreen",
    "window_fullscreen_immersive",
    "close_to_tray",
    "minimize_to_tray",
    // One renderer, one log per process.
    "renderer_backend",
    "perf_overlay",
    "debug_logging",
    // One binary, one plugin cache, one network posture.
    "offline_mode",
    "download_mirror",
    "auto_check_updates",
    "update_channel",
    "skipped_update_version",
    // Programs and folders on THIS disk.
    "local_terminals",
    "local_terminal_default",
    "sftp_default_editor",
    "zmodem_download_dir",
    "session_log_file_dir",
    "command_history_file_dir",
    "snippet_output_dir",
    // One agent socket / pipe.
    "agent_server_enabled",
    "agent_server_confirm",
    "agent_server_allow_add",
    "agent_server_openssh_pipe",
    // One sync listener; the machine's name.
    "sync_listen_port",
    "sync_listen_port_auto",
    "sync_device_name",
    // Binding state of the shortcut table (the table itself is the
    // `hotkey_` prefix).
    "middle_click_paste",
    "middle_click_paste_migrated",
    "wheel_zoom_migrated",
];

/// Settings that belong to the device, by key prefix: the shortcut
/// table (`hotkey_<action>`) and the plugin cache's per-plugin state
/// (`plugins_<id>_pinned_version`, `plugins_<id>_auto_update`,
/// `plugins_auto_update_global`).
pub const DEVICE_PREFIXES: &[&str] = &["hotkey_", "plugins_"];

/// Whether `key` is a device setting (lives in `device.json`) rather
/// than a vault setting.
pub fn is_device_key(key: &str) -> bool {
    DEVICE_KEYS.contains(&key) || DEVICE_PREFIXES.iter().any(|p| key.starts_with(p))
}

/// One vault this device knows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id: Uuid,
    /// Unique, ASCII: what `--vault` and the per-vault MCP variables
    /// name.
    pub slug: String,
    /// What the user called it. `None` = the app's translated default
    /// name (the first vault of every install has none).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The file. Relative = inside the `.oryxis` folder (so a moved
    /// `ORYXIS_HOME` takes its vaults along); absolute = where the user
    /// put it.
    pub path: PathBuf,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl VaultEntry {
    /// The entry for the install's `vault.db`.
    pub fn first() -> Self {
        Self {
            id: FIRST_VAULT_ID,
            slug: "personal".to_owned(),
            label: None,
            path: PathBuf::from(FIRST_VAULT_FILE),
            extra: serde_json::Map::new(),
        }
    }
}

/// The file's content.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct DeviceFile {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    vaults: Vec<VaultEntry>,
    /// The vault the app opened last; the one a start opens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_vault: Option<Uuid>,
    #[serde(default)]
    settings: BTreeMap<String, String>,
    /// The device keys were copied from the first vault (or there was
    /// nothing to copy). See [`DeviceStore::seed_from_first_vault`].
    #[serde(default)]
    seeded: bool,
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

impl DeviceFile {
    /// A device that has never written its file: the first vault and
    /// nothing else.
    fn fresh() -> Self {
        Self {
            version: FORMAT_VERSION,
            vaults: vec![VaultEntry::first()],
            last_vault: None,
            settings: BTreeMap::new(),
            seeded: false,
            extra: serde_json::Map::new(),
        }
    }

    /// Repairs what a hand edit can break: a registry with no vault at
    /// all gets the first one back (the app always has a vault to open).
    fn normalized(mut self) -> Self {
        if self.vaults.is_empty() {
            self.vaults.push(VaultEntry::first());
        }
        self
    }
}

/// What was on disk when the cache was filled: a changed stamp means
/// another process (or a wipe) changed the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stamp {
    Missing,
    Present { modified: Option<std::time::SystemTime>, len: u64 },
}

fn stamp_of(path: &Path) -> Stamp {
    match std::fs::metadata(path) {
        Ok(meta) => Stamp::Present { modified: meta.modified().ok(), len: meta.len() },
        Err(_) => Stamp::Missing,
    }
}

struct Cached {
    stamp: Option<Stamp>,
    file: DeviceFile,
}

/// Errors of the device store. Reads never fail (an unreadable file is
/// reported once and read as fresh); writes do.
#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    #[error("device store I/O at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("device store encode: {0}")]
    Encode(#[from] serde_json::Error),
}

/// `~/.oryxis/device.json`, read through, written under a lock.
pub struct DeviceStore {
    dir: PathBuf,
    cache: Mutex<Cached>,
}

impl std::fmt::Debug for DeviceStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceStore").field("dir", &self.dir).finish_non_exhaustive()
    }
}

impl DeviceStore {
    /// The store whose file is `<dir>/device.json`, `dir` being the
    /// `.oryxis` folder. Nothing is read or created yet.
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            cache: Mutex::new(Cached { stamp: None, file: DeviceFile::fresh() }),
        }
    }

    /// The `.oryxis` folder this store lives in (relative vault paths
    /// resolve against it).
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The file itself.
    pub fn path(&self) -> PathBuf {
        self.dir.join(FILE_NAME)
    }

    fn lock_path(&self) -> PathBuf {
        self.dir.join(format!("{FILE_NAME}.lock"))
    }

    /// The cache, refreshed from disk when the file changed or vanished.
    /// A poisoned mutex (a panic while it was held: the panic hook writes
    /// the renderer fallback through here) is taken over, not
    /// propagated: the content is a plain map, never half-written in
    /// memory.
    fn with_current<R>(&self, f: impl FnOnce(&DeviceFile) -> R) -> R {
        let path = self.path();
        let mut cached = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        let now = stamp_of(&path);
        if cached.stamp != Some(now) {
            cached.file = read_file(&path);
            cached.stamp = Some(now);
        }
        f(&cached.file)
    }

    /// Read-modify-write: the file is re-read under the OS lock (another
    /// process may have written since the cache was filled), `change`
    /// applied, the result written temp + rename and kept as the cache.
    fn update(&self, change: impl FnOnce(&mut DeviceFile)) -> Result<(), DeviceError> {
        let io = |path: &Path| {
            let path = path.to_path_buf();
            move |source| DeviceError::Io { path, source }
        };
        std::fs::create_dir_all(&self.dir).map_err(io(&self.dir))?;
        let lock_path = self.lock_path();
        let mut lock_options = std::fs::OpenOptions::new();
        lock_options.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            lock_options.mode(0o600);
        }
        let lock = lock_options.open(&lock_path).map_err(io(&lock_path))?;
        // A file system with no locks (some network mounts): the
        // in-process mutex below still serializes this process.
        if let Err(e) = lock.lock() {
            tracing::warn!(error = %e, "no file lock for the device store; writing without one");
        }
        let path = self.path();
        let mut cached = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        let mut file = read_file(&path);
        change(&mut file);
        file.version = file.version.max(FORMAT_VERSION);
        write_file(&path, &file)?;
        cached.stamp = Some(stamp_of(&path));
        cached.file = file;
        drop(cached);
        drop(lock);
        Ok(())
    }

    // -- settings ---------------------------------------------------------

    /// A device setting, `None` when never set.
    pub fn get(&self, key: &str) -> Option<String> {
        self.with_current(|f| f.settings.get(key).cloned())
    }

    /// Store a device setting.
    pub fn set(&self, key: &str, value: &str) -> Result<(), DeviceError> {
        self.update(|f| {
            f.settings.insert(key.to_owned(), value.to_owned());
        })
    }

    /// Every device setting, sorted by key.
    pub fn settings(&self) -> Vec<(String, String)> {
        self.with_current(|f| f.settings.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
    }

    /// Remove every device setting whose key starts with `prefix`.
    pub fn delete_with_prefix(&self, prefix: &str) -> Result<(), DeviceError> {
        if !self.with_current(|f| f.settings.keys().any(|k| k.starts_with(prefix))) {
            return Ok(());
        }
        self.update(|f| f.settings.retain(|k, _| !k.starts_with(prefix)))
    }

    // -- registry ---------------------------------------------------------

    /// Every vault this device knows, in registry order. Never empty.
    pub fn vaults(&self) -> Vec<VaultEntry> {
        self.with_current(|f| f.vaults.clone())
    }

    /// The vault a start opens: the last one opened while it is still
    /// registered, else the first.
    pub fn boot_vault(&self) -> VaultEntry {
        self.with_current(|f| {
            f.last_vault
                .and_then(|id| f.vaults.iter().find(|v| v.id == id))
                .or_else(|| f.vaults.first())
                .cloned()
                .unwrap_or_else(VaultEntry::first)
        })
    }

    /// Where `entry`'s file is: a relative path inside this store's
    /// folder, an absolute one as written.
    pub fn resolve(&self, entry: &VaultEntry) -> PathBuf {
        if entry.path.is_absolute() { entry.path.clone() } else { self.dir.join(&entry.path) }
    }

    // -- migration --------------------------------------------------------

    /// Whether the device keys were already copied out of the first
    /// vault.
    pub fn is_seeded(&self) -> bool {
        self.with_current(|f| f.seeded)
    }

    /// Copy the device keys out of the first vault's `settings` table,
    /// once. Read-only (no schema step, no write lock: the vault may be
    /// damaged or held by another process), only keys the store does not
    /// hold yet (one set meanwhile, on a start where the vault did not
    /// open, wins). Marks the store seeded when the read succeeded or
    /// there was no vault to read (a fresh install); a read that FAILED
    /// leaves it unseeded, so the next start tries again.
    ///
    /// Returns how many keys were copied.
    pub fn seed_from_first_vault(&self) -> Result<usize, DeviceError> {
        if self.is_seeded() {
            return Ok(0);
        }
        let first = self.with_current(|f| {
            f.vaults.iter().find(|v| v.id == FIRST_VAULT_ID).cloned()
        });
        let rows = match first.map(|e| self.resolve(&e)) {
            Some(path) if path.exists() => match read_device_rows(&path) {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::warn!(error = %e, path = %path.display(), "device settings not copied from the vault yet");
                    return Ok(0);
                }
            },
            // No first vault on disk (fresh install, or registered away):
            // nothing to copy, ever.
            _ => Vec::new(),
        };
        let mut copied = 0;
        self.update(|f| {
            for (key, value) in rows {
                if let std::collections::btree_map::Entry::Vacant(slot) = f.settings.entry(key) {
                    slot.insert(value);
                    copied += 1;
                }
            }
            f.seeded = true;
        })?;
        Ok(copied)
    }
}

/// The file's content, a fresh device when absent. A file that does not
/// parse is reported and read as fresh; the next write replaces it (the
/// broken copy is kept beside it first, see [`write_file`]).
fn read_file(path: &Path) -> DeviceFile {
    match std::fs::read(path) {
        Ok(bytes) => match serde_json::from_slice::<DeviceFile>(&bytes) {
            Ok(file) => file.normalized(),
            Err(e) => {
                tracing::warn!(error = %e, path = %path.display(), "device store does not parse; reading it as fresh");
                keep_broken_copy(path);
                DeviceFile::fresh()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => DeviceFile::fresh(),
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "device store unreadable; reading it as fresh");
            DeviceFile::fresh()
        }
    }
}

/// A file that did not parse is copied to `device.json.broken` once, so
/// the next write (which replaces it) does not destroy what a hand edit
/// left there.
fn keep_broken_copy(path: &Path) {
    let broken = path.with_extension("json.broken");
    if !broken.exists() {
        let _ = std::fs::copy(path, &broken);
    }
}

fn write_file(path: &Path, file: &DeviceFile) -> Result<(), DeviceError> {
    let mut bytes = serde_json::to_vec_pretty(file)?;
    bytes.push(b'\n');
    let tmp = path.with_extension(format!("json.tmp-{}", std::process::id()));
    let io = |p: &Path| {
        let path = p.to_path_buf();
        move |source| DeviceError::Io { path, source }
    };
    write_private(&tmp, &bytes).map_err(io(&tmp))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        DeviceError::Io { path: path.to_path_buf(), source: e }
    })
}

/// Owner-only on unix, like the vault: the file names where every vault
/// lives.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut out = options.open(path)?;
    out.write_all(bytes)?;
    out.sync_all()
}

/// The device keys of a vault file's `settings` table, read-only.
fn read_device_rows(path: &Path) -> rusqlite::Result<Vec<(String, String)>> {
    let db = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    db.busy_timeout(std::time::Duration::from_secs(5))?;
    let mut stmt = db.prepare("SELECT key, value FROM settings")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let mut out = Vec::new();
    for row in rows {
        let (key, value) = row?;
        if is_device_key(&key) {
            out.push((key, value));
        }
    }
    Ok(out)
}

// -- the process's store ----------------------------------------------------

static INSTALLED: OnceLock<Arc<DeviceStore>> = OnceLock::new();

/// Install the device store for this process: every `VaultStore` opened
/// from now on routes device keys to it. Once per process (the app's
/// `main`, before the first vault open); a second call is ignored and
/// answers `false`. Tests never call it (module docs).
pub fn install(store: Arc<DeviceStore>) -> bool {
    INSTALLED.set(store).is_ok()
}

/// The store installed for this process, if any.
pub fn installed() -> Option<Arc<DeviceStore>> {
    INSTALLED.get().cloned()
}

/// The store for the app's own `.oryxis` folder (`ORYXIS_HOME`
/// included), `None` when the home directory is unknown.
pub fn for_app_dir() -> Option<DeviceStore> {
    oryxis_core::paths::oryxis_dir().map(DeviceStore::at)
}

/// The file the app opens at start: the installed store's boot vault,
/// else (no store installed: the MCP server) the install's `vault.db`.
pub fn boot_vault_path() -> Option<PathBuf> {
    match installed() {
        Some(store) => Some(store.resolve(&store.boot_vault())),
        None => crate::VaultStore::default_path(),
    }
}

#[cfg(test)]
mod tests;
