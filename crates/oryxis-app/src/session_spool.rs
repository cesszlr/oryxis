//! Where a recording goes while the vault is soft-locked.
//!
//! The soft lock zeroizes the master key and keeps the live sessions
//! (`SoftLockVault`), so their output keeps arriving with nowhere to be
//! stored: the vault refuses an append, and the flush tick is unmounted
//! for that reason. The buffers used to sit on the panes until unlock,
//! without bound, so a chatty session left running overnight under the
//! idle lock grew the process by everything it printed.
//!
//! This is the bound. Under lock, the flush spools the rows it would
//! have written to the vault into
//! `~/.oryxis/runtime/spool/<pid>/<vault>/<log>.spool`, one folder and one
//! key per open vault of this process (a soft lock is a vault's own, and
//! the drain after its unlock must replay that vault's recordings and
//! nothing else; a second Oryxis process has folders of its own),
//! each row sealed under an [`oryxis_vault::EphemeralKey`] that lives in
//! this process alone: the file is as readable at rest as the process's
//! memory was, which is the posture the lock already accepts, and it is
//! unreadable to the next launch, which sweeps the folder. The drain
//! runs on the first flush after unlock and replays every file into the
//! vault ahead of whatever the panes hold then, `End` rows included, so
//! a recording that ended under lock is stamped ended too.
//!
//! A session closed under the lock is fine: its spool has no pane any
//! more and is drained all the same. What is lost is a spool whose
//! PROCESS exits before the unlock (the window closed under the lock):
//! only that process could read it. Unlocking first keeps it, which is
//! what the lock screen is for.

use std::io::{Read, Write};
use std::path::PathBuf;

use uuid::Uuid;

use crate::dispatch_terminal::PendingSessionRow;

const KIND_CHUNK: u8 = 0;
const KIND_RESIZE: u8 = 1;
const KIND_END: u8 = 2;

/// The spool folder plus the key its files are sealed under.
pub(crate) struct SessionSpool {
    key: oryxis_vault::EphemeralKey,
    dir: PathBuf,
}

/// A vault's spool and what its flushes learned about it, kept on the
/// vault (`OpenVault::spool`): the drain after its unlock reads this
/// vault's spool alone.
#[derive(Default)]
pub(crate) struct VaultSpool {
    /// Opened by the first flush under this vault's lock.
    pub(crate) spool: Option<SessionSpool>,
    /// The spool could not be opened, or could not take a batch; the
    /// flush then keeps the rows on the panes as it always did, and does
    /// not retry a folder it cannot write on every batch. What was
    /// spooled before still drains.
    pub(crate) unavailable: bool,
    /// Recordings that lost a batch to a spool that could not write,
    /// marked truncated at the drain so the vault row says so.
    pub(crate) lost: Vec<Uuid>,
    /// Recordings that ended under the lock with no spool to carry the
    /// stamp; ended at the drain.
    pub(crate) end_pending: Vec<Uuid>,
}

impl VaultSpool {
    /// The spool, opened on first use for vault `vault`. `None` when it
    /// could not be opened, in which case the rows stay on their panes.
    pub(crate) fn get(&mut self, vault: Uuid) -> Option<&SessionSpool> {
        if self.unavailable {
            return None;
        }
        if self.spool.is_none() {
            self.spool = SessionSpool::open(vault);
            self.unavailable = self.spool.is_none();
        }
        self.spool.as_ref()
    }
}

impl SessionSpool {
    /// The folder every spool lives in, `None` with no home to put it in.
    fn root() -> Option<PathBuf> {
        Some(oryxis_core::paths::oryxis_dir()?.join("runtime").join("spool"))
    }

    /// This process's folder under the spool root.
    fn own_dir() -> Option<PathBuf> {
        Some(Self::root()?.join(std::process::id().to_string()))
    }

    /// Open vault `vault`'s spool for this process: its folder
    /// (owner-only on unix) and a fresh key. `None` when either cannot
    /// be had, which the caller reads as "keep the rows in memory", the
    /// old behaviour.
    pub(crate) fn open(vault: Uuid) -> Option<Self> {
        Self::open_in(Self::own_dir()?.join(vault.simple().to_string()))
    }

    /// Delete vault `vault`'s spool folder in this process (the vault is
    /// being removed; its key goes with it).
    pub(crate) fn remove_for(vault: Uuid) {
        let Some(own) = Self::own_dir() else {
            return;
        };
        let dir = own.join(vault.simple().to_string());
        if dir.exists()
            && let Err(e) = std::fs::remove_dir_all(&dir)
        {
            tracing::warn!("session spool {} not removed: {e}", dir.display());
        }
    }

    fn open_in(dir: PathBuf) -> Option<Self> {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        if let Err(e) = builder.create(&dir) {
            tracing::warn!("session spool folder {}: {e}", dir.display());
            return None;
        }
        let key = match oryxis_vault::EphemeralKey::generate() {
            Ok(key) => key,
            Err(e) => {
                tracing::warn!("session spool key: {e}");
                return None;
            }
        };
        Some(Self { key, dir })
    }

    fn path_for(&self, log_id: Uuid) -> PathBuf {
        self.dir.join(format!("{}.spool", log_id.simple()))
    }

    /// Append `rows` to the recording's spool, in order. One write for
    /// the batch, so a crash mid-batch leaves at most a torn tail, which
    /// the reader stops at.
    pub(crate) fn append(&self, log_id: Uuid, rows: &[PendingSessionRow]) -> std::io::Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut out: Vec<u8> = Vec::new();
        for row in rows {
            let blob = self
                .key
                .seal(&encode_row(row))
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            out.extend_from_slice(&(blob.len() as u32).to_be_bytes());
            out.extend_from_slice(&blob);
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(self.path_for(log_id))?;
        file.write_all(&out)?;
        file.flush()
    }

    /// Take every spooled recording: its rows in the order they were
    /// spooled, and the file gone. A file that stops decoding (a torn
    /// tail, a blob from another key) yields what it had up to there;
    /// the file is removed either way, since nothing later could read
    /// it.
    pub(crate) fn drain_all(&self) -> Vec<(Uuid, Vec<PendingSessionRow>)> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut drained = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(log_id) = path
                .extension()
                .filter(|ext| *ext == "spool")
                .and_then(|_| path.file_stem())
                .and_then(|stem| stem.to_str())
                .and_then(|stem| Uuid::parse_str(stem).ok())
            else {
                continue;
            };
            let rows = match std::fs::File::open(&path) {
                Ok(mut file) => {
                    let mut data = Vec::new();
                    match file.read_to_end(&mut data) {
                        Ok(_) => self.decode_all(&data, &path),
                        Err(e) => {
                            tracing::warn!("session spool {}: {e}", path.display());
                            Vec::new()
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("session spool {}: {e}", path.display());
                    Vec::new()
                }
            };
            if let Err(e) = std::fs::remove_file(&path) {
                tracing::warn!("session spool {} not removed: {e}", path.display());
            }
            if !rows.is_empty() {
                drained.push((log_id, rows));
            }
        }
        drained
    }

    fn decode_all(&self, data: &[u8], path: &std::path::Path) -> Vec<PendingSessionRow> {
        let mut rows = Vec::new();
        let mut rest = data;
        while let Some((len, after)) = rest.split_first_chunk::<4>() {
            let len = u32::from_be_bytes(*len) as usize;
            let Some((blob, after)) = after.split_at_checked(len) else {
                tracing::debug!("session spool {}: torn tail dropped", path.display());
                break;
            };
            let row = self.key.open(blob).ok().and_then(|frame| decode_row(&frame));
            let Some(row) = row else {
                tracing::warn!("session spool {}: a row did not decode; stopping there", path.display());
                break;
            };
            rows.push(row);
            rest = after;
        }
        rows
    }

    /// Delete every spool a process that is gone left: sealed under a key
    /// that died with it, they can only be removed. A folder of a live
    /// Oryxis process (a second window process on Linux / macOS, a
    /// JumpList launch) is its spool in use and stays. Runs at boot.
    pub(crate) fn sweep_stale() {
        let Some(root) = Self::root() else {
            return;
        };
        let swept = Self::sweep_dead(&root, std::process::id(), crate::tray_ipc::is_live_oryxis);
        if swept > 0 {
            tracing::info!("swept {swept} session spool file(s) from a previous run");
        }
    }

    /// Sweep the spool root: a process folder (named by its PID) goes
    /// unless `live` says that process is an Oryxis still running (this
    /// one's own folder is stale at its boot: the PID was reused); files
    /// and folders of the layouts before the per-process one go too.
    /// Answers how many spool files went.
    fn sweep_dead(root: &std::path::Path, own: u32, live: impl Fn(u32) -> bool) -> usize {
        let Ok(entries) = std::fs::read_dir(root) else {
            return 0;
        };
        let mut swept = 0usize;
        for entry in entries.flatten() {
            let path = entry.path();
            let pid = path
                .is_dir()
                .then(|| path.file_name().and_then(|n| n.to_str()).and_then(|n| n.parse::<u32>().ok()))
                .flatten();
            if pid.is_some_and(|pid| pid != own && live(pid)) {
                continue;
            }
            if path.is_dir() {
                swept += Self::sweep_dir(&path);
                let _ = std::fs::remove_dir(&path);
            } else if path.extension().is_some_and(|ext| ext == "spool") && std::fs::remove_file(&path).is_ok() {
                swept += 1;
            }
        }
        swept
    }

    /// Remove the spool files under `dir` and its folders, each folder
    /// going too once empty. Answers how many files went.
    fn sweep_dir(dir: &std::path::Path) -> usize {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return 0;
        };
        let mut swept = 0usize;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                swept += Self::sweep_dir(&path);
                // Only removes an empty folder.
                let _ = std::fs::remove_dir(&path);
            } else if path.extension().is_some_and(|ext| ext == "spool")
                && std::fs::remove_file(&path).is_ok()
            {
                swept += 1;
            }
        }
        swept
    }
}

fn encode_row(row: &PendingSessionRow) -> Vec<u8> {
    let mut out = Vec::new();
    match row {
        PendingSessionRow::Chunk(offset_ms, bytes) => {
            out.push(KIND_CHUNK);
            match offset_ms {
                Some(ms) => {
                    out.push(1);
                    out.extend_from_slice(&ms.to_be_bytes());
                }
                None => {
                    out.push(0);
                    out.extend_from_slice(&0i64.to_be_bytes());
                }
            }
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        PendingSessionRow::Resize(ms, cols, rows) => {
            out.push(KIND_RESIZE);
            out.extend_from_slice(&ms.to_be_bytes());
            out.extend_from_slice(&cols.to_be_bytes());
            out.extend_from_slice(&rows.to_be_bytes());
        }
        PendingSessionRow::End => out.push(KIND_END),
    }
    out
}

fn decode_row(frame: &[u8]) -> Option<PendingSessionRow> {
    let (kind, rest) = frame.split_first()?;
    match *kind {
        KIND_CHUNK => {
            let (has_offset, rest) = rest.split_first()?;
            let (ms, rest) = rest.split_first_chunk::<8>()?;
            let (len, rest) = rest.split_first_chunk::<4>()?;
            let len = u32::from_be_bytes(*len) as usize;
            let bytes = rest.get(..len)?;
            let offset = (*has_offset == 1).then(|| i64::from_be_bytes(*ms));
            Some(PendingSessionRow::Chunk(offset, bytes.to_vec()))
        }
        KIND_RESIZE => {
            let (ms, rest) = rest.split_first_chunk::<8>()?;
            let (cols, rest) = rest.split_first_chunk::<2>()?;
            let (rows, _) = rest.split_first_chunk::<2>()?;
            Some(PendingSessionRow::Resize(
                i64::from_be_bytes(*ms),
                u16::from_be_bytes(*cols),
                u16::from_be_bytes(*rows),
            ))
        }
        KIND_END => Some(PendingSessionRow::End),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spool() -> (tempfile::TempDir, SessionSpool) {
        let dir = tempfile::tempdir().expect("tempdir");
        let spool = SessionSpool::open_in(dir.path().join("spool")).expect("spool");
        (dir, spool)
    }

    fn same(a: &PendingSessionRow, b: &PendingSessionRow) -> bool {
        match (a, b) {
            (PendingSessionRow::Chunk(x, xb), PendingSessionRow::Chunk(y, yb)) => x == y && xb == yb,
            (PendingSessionRow::Resize(a1, a2, a3), PendingSessionRow::Resize(b1, b2, b3)) => {
                a1 == b1 && a2 == b2 && a3 == b3
            }
            (PendingSessionRow::End, PendingSessionRow::End) => true,
            _ => false,
        }
    }

    /// Every row kind comes back as it went, in order, and the drain
    /// leaves nothing behind for a second drain to find.
    #[test]
    fn rows_round_trip_in_order_and_the_file_goes() {
        let (_dir, spool) = spool();
        let id = Uuid::new_v4();
        let rows = vec![
            PendingSessionRow::Resize(0, 120, 40),
            PendingSessionRow::Chunk(Some(12), b"hello\r\n".to_vec()),
            PendingSessionRow::Chunk(None, b"plain".to_vec()),
            PendingSessionRow::End,
        ];
        spool.append(id, &rows[..2]).expect("append");
        spool.append(id, &rows[2..]).expect("append");
        let drained = spool.drain_all();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].0, id);
        assert_eq!(drained[0].1.len(), rows.len());
        for (got, want) in drained[0].1.iter().zip(&rows) {
            assert!(same(got, want), "a row changed on the way");
        }
        assert!(spool.drain_all().is_empty(), "the file survived its drain");
    }

    /// Bytes on disk are sealed: the payload is not there to read.
    #[test]
    fn the_file_holds_no_plaintext() {
        let (_dir, spool) = spool();
        let id = Uuid::new_v4();
        spool
            .append(id, &[PendingSessionRow::Chunk(Some(1), b"secret output".to_vec())])
            .expect("append");
        let raw = std::fs::read(spool.path_for(id)).expect("read");
        assert!(!raw.windows(13).any(|w| w == b"secret output"));
    }

    /// A torn tail (a crash mid-write) costs the torn row only.
    #[test]
    fn a_torn_tail_keeps_the_rows_before_it() {
        let (_dir, spool) = spool();
        let id = Uuid::new_v4();
        spool
            .append(id, &[PendingSessionRow::Chunk(Some(1), b"first".to_vec())])
            .expect("append");
        spool
            .append(id, &[PendingSessionRow::Chunk(Some(2), b"second".to_vec())])
            .expect("append");
        let path = spool.path_for(id);
        let mut raw = std::fs::read(&path).expect("read");
        raw.truncate(raw.len() - 5);
        std::fs::write(&path, raw).expect("write");
        let drained = spool.drain_all();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].1.len(), 1);
        assert!(same(&drained[0].1[0], &PendingSessionRow::Chunk(Some(1), b"first".to_vec())));
    }

    /// Another process's spool (another key) yields nothing and is
    /// removed, which is what the boot sweep does without a key at all.
    #[test]
    fn a_foreign_file_is_dropped_not_decoded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = SessionSpool::open_in(dir.path().join("spool")).expect("spool");
        let b = SessionSpool::open_in(dir.path().join("spool")).expect("spool");
        let id = Uuid::new_v4();
        a.append(id, &[PendingSessionRow::End]).expect("append");
        assert!(b.drain_all().is_empty());
        assert!(!a.path_for(id).exists(), "the foreign file was kept");
    }

    #[test]
    fn each_vault_drains_its_own_folder() {
        let dir = tempfile::tempdir().expect("tempdir");
        let work = SessionSpool::open_in(dir.path().join("work")).expect("spool");
        let personal = SessionSpool::open_in(dir.path().join("personal")).expect("spool");
        let (w, p) = (Uuid::new_v4(), Uuid::new_v4());
        work.append(w, &[PendingSessionRow::End]).expect("append");
        personal.append(p, &[PendingSessionRow::End]).expect("append");
        let drained = work.drain_all();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].0, w, "a vault drained another vault's recording");
        // The other vault's file is where it was.
        assert_eq!(personal.drain_all().len(), 1);
    }

    #[test]
    fn the_boot_sweep_reaches_every_vault_folder() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("spool");
        // One file from a build before the per-vault folders, one per vault.
        let old = SessionSpool::open_in(root.clone()).expect("spool");
        let work = SessionSpool::open_in(root.join("work")).expect("spool");
        old.append(Uuid::new_v4(), &[PendingSessionRow::End]).expect("append");
        work.append(Uuid::new_v4(), &[PendingSessionRow::End]).expect("append");
        assert_eq!(SessionSpool::sweep_dead(&root, 1, |_| false), 2);
        assert!(!root.join("work").exists(), "an emptied vault folder stayed");
        assert!(root.exists(), "the sweep removed the spool root itself");
    }

    #[test]
    fn the_boot_sweep_spares_a_live_process_spool() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("spool");
        let live = SessionSpool::open_in(root.join("4242").join("work")).expect("spool");
        let dead = SessionSpool::open_in(root.join("4343").join("work")).expect("spool");
        let reused = SessionSpool::open_in(root.join("7").join("work")).expect("spool");
        for spool in [&live, &dead, &reused] {
            spool.append(Uuid::new_v4(), &[PendingSessionRow::End]).expect("append");
        }
        // 4242 is an Oryxis still running; 7 is this process's own PID,
        // whose folder at boot was left by an earlier process.
        let swept = SessionSpool::sweep_dead(&root, 7, |pid| pid == 4242 || pid == 7);
        assert_eq!(swept, 2);
        assert_eq!(live.drain_all().len(), 1, "a running process keeps its spool");
        assert!(!root.join("4343").exists() && !root.join("7").exists());
    }

}
