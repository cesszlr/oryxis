//! State of the vault doors: the "New vault" dialog and its picks.

use uuid::Uuid;

/// The "New vault" dialog (`Oryxis::new_vault`, `Modal::NewVault`).
#[derive(Debug, Clone, Default)]
pub(crate) struct NewVaultForm {
    /// What the user calls it.
    pub(crate) name: String,
    /// The vault whose settings the new one starts with, copied once at
    /// creation (never a live link); `None` = the factory settings.
    pub(crate) copy_from: Option<Uuid>,
    /// Why the last Create did not go through.
    pub(crate) error: Option<String>,
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
