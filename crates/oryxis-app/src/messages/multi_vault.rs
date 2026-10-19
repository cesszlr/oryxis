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
    /// "New vault…": the dialog opens.
    ShowNewVault,
    NewVaultNameChanged(String),
    NewVaultCopyFromChanged(Option<Uuid>),
    /// Create the vault the dialog describes, and switch this window to
    /// it (its setup screen asks for the master password).
    CreateVault,
    CancelNewVault,
    /// The setup step of a vault just made was abandoned: back to the
    /// vault it was made from, and the empty new one goes away.
    CancelVaultSetup,
    /// "Lock all vaults": asks first (it ends their sessions).
    LockAllVaults,
    /// The confirm's answer: lock every open vault that has a master
    /// password.
    LockAllVaultsConfirmed,
}
