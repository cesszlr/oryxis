//! State of the vault doors: the vault dialog (create, rename, delete)
//! and its picks.

use uuid::Uuid;

/// What the vault dialog does on submit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum VaultDialogMode {
    /// "New vault…": a name and the vault whose settings it starts with.
    #[default]
    Create,
    /// Settings > Vaults "Rename": the name only.
    Rename(Uuid),
    /// Settings > Vaults "Delete…": the vault's name typed back. Offered
    /// only for a vault open and unlocked (or without a master password):
    /// the unlock already proved it is the user's.
    Delete(Uuid),
}

/// The vault dialog (`Oryxis::vault_dialog`, `Modal::VaultDialog`).
#[derive(Debug, Clone, Default)]
pub(crate) struct VaultDialog {
    pub(crate) mode: VaultDialogMode,
    /// The name: what the new vault is called, the new name, or the name
    /// typed back to confirm a delete.
    pub(crate) name: String,
    /// Create: the vault whose settings the new one starts with, copied
    /// once (never a live link); `None` = the factory settings.
    pub(crate) copy_from: Option<Uuid>,
    /// Why the last submit did not go through.
    pub(crate) error: Option<String>,
}

impl VaultDialog {
    pub(crate) fn create() -> Self {
        Self::default()
    }

    pub(crate) fn rename(id: Uuid, current: String) -> Self {
        Self { mode: VaultDialogMode::Rename(id), name: current, ..Self::default() }
    }

    pub(crate) fn delete(id: Uuid) -> Self {
        Self { mode: VaultDialogMode::Delete(id), ..Self::default() }
    }
}

/// One choice of the dialog's "Start with settings from" picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CopySettingsChoice {
    pub(crate) vault: Option<Uuid>,
    pub(crate) label: String,
}

impl std::fmt::Display for CopySettingsChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.label)
    }
}
