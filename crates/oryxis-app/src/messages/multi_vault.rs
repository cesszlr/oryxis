//! The vault doors: the switcher, a new vault, moving a window between
//! vaults, locking them all. Wrapped by
//! [`crate::messages::Message::MultiVault`], handled by
//! `Oryxis::handle_multi_vault`.

use uuid::Uuid;

#[derive(Debug, Clone)]
pub enum MultiVaultMessage {
    /// The vault chip was pressed: its menu opens under it.
    ShowVaultSwitcher(crate::dispatch_multi_vault::VaultChipPlace),
    /// This window works on vault `id` from now on (opened first when it
    /// is not open in this process).
    SwitchToVault(Uuid),
    /// A new window working on vault `id`.
    OpenVaultInNewWindow(Uuid),
    /// "New vault…": the dialog opens in its create mode.
    ShowNewVault,
    /// "Manage vaults…": Settings opens on its Vaults section.
    ShowVaultSettings,
    /// Settings > Vaults: rename vault `id`.
    ShowRenameVault(Uuid),
    /// Settings > Vaults: delete vault `id` (its name typed back; the
    /// vault open and unlocked).
    ShowDeleteVault(Uuid),
    VaultDialogNameChanged(String),
    NewVaultCopyFromChanged(Option<Uuid>),
    /// Do what the dialog's mode says: create (and switch this window to
    /// the new vault), rename, or delete.
    VaultDialogSubmit,
    CancelVaultDialog,
    /// Settings > Vaults: take vault `id` off this device's list (asks
    /// first); its file is left where it is.
    RemoveVaultFromList(Uuid),
    RemoveVaultFromListConfirmed(Uuid),
    /// Settings > Vaults "Open existing vault…": pick a vault file kept
    /// elsewhere (a USB key, a synced folder) and register it.
    OpenExistingVault,
    ExistingVaultPicked(Option<std::path::PathBuf>),
    /// Settings > Vaults: lock vault `id`, whichever vault this window is on.
    LockVaultById(Uuid),
    /// Settings > Vaults: hide the switcher while this device has a
    /// single vault.
    VaultSwitcherHideSingleToggled(bool),
    /// Settings > Vaults: record the chord of vault `id` (the next
    /// keypress).
    VaultHotkeyCaptureStart(Uuid),
    /// Settings > Vaults: vault `id` has no chord any more.
    VaultHotkeyClear(Uuid),
    /// Settings > Vaults: ask which vault to open at a start.
    VaultStartPickerToggled(bool),
    /// The start picker: open this vault in the window.
    PickStartVault(Uuid),
    /// Settings > Vaults: where the switcher lives.
    VaultSwitcherPlaceChanged(crate::state::VaultSwitcherPlace),
    /// The setup step of a vault just made was abandoned: back to the
    /// vault it was made from, and the empty new one goes away.
    CancelVaultSetup,
    /// "Lock all vaults": asks first (it ends their sessions).
    LockAllVaults,
    /// The confirm's answer: lock every open vault that has a master
    /// password.
    LockAllVaultsConfirmed,
}
