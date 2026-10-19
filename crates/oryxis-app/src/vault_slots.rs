//! The vaults this process has open, and which one a piece of code is
//! working on.
//!
//! Several vaults may be open at once, and every window works on one of
//! them (`MULTI_VAULT_SPEC.md`): the window carries the vault's id
//! (`ExtraWindow::vault`, and for the window whose values are in the
//! fields, [`VaultSlots::current_id`]), and reads and writes that vault
//! here. Vault data never moves: a view is built with `&self`, so it
//! could not be swapped into the fields for the window being drawn the
//! way `enter_window` swaps a window's own values in `update`.
//!
//! [`VaultSlots::cur`] is the one way to read a vault and resolves "the
//! vault of the window acting now": during a view pass, the window being
//! drawn (`window_ctx::viewed_vault`); otherwise the window whose values
//! are in the fields (the resident one, or the window `update_in_window`
//! entered). [`VaultSlots::cur_mut`] is the `update`-only way to change
//! it. The fields are private, so no code can reach a vault around the
//! resolution and read another window's.

use std::collections::HashMap;

use uuid::Uuid;

use oryxis_vault::VaultStore;

/// One open vault: its store and what the app loaded from it.
pub(crate) struct OpenVault {
    /// The registry id (`oryxis_vault::device::VaultEntry::id`).
    pub(crate) id: Uuid,
    /// `None` when the file did not open (the open-failed screen).
    pub(crate) store: Option<VaultStore>,
}

/// Every open vault, and the one the window acting now works on.
pub(crate) struct VaultSlots {
    open: HashMap<Uuid, OpenVault>,
    /// The vault of the window whose values are in the fields.
    current: Uuid,
}

impl VaultSlots {
    /// A process with one vault open (or the one it failed to open).
    pub(crate) fn single(vault: OpenVault) -> Self {
        let current = vault.id;
        Self { open: HashMap::from([(current, vault)]), current }
    }

    /// The id of the vault the window in the fields works on: what a
    /// new window opened from it starts on.
    pub(crate) fn current_id(&self) -> Uuid {
        self.current
    }

    /// Make `id` the vault of the window in the fields (the window swap
    /// of `enter_window` / `exit_window`), handing back the one it
    /// replaces.
    pub(crate) fn set_current(&mut self, id: Uuid) -> Uuid {
        std::mem::replace(&mut self.current, id)
    }

    /// The vault the acting window works on.
    pub(crate) fn cur(&self) -> &OpenVault {
        let id = crate::window_ctx::viewed_vault().unwrap_or(self.current);
        self.open
            .get(&id)
            .or_else(|| self.open.get(&self.current))
            .expect("the current vault is always open")
    }

    /// The vault the running `update` works on, to change it. Never
    /// called while a view is built (views get `&self`).
    pub(crate) fn cur_mut(&mut self) -> &mut OpenVault {
        self.open.get_mut(&self.current).expect("the current vault is always open")
    }
}

#[cfg(test)]
impl VaultSlots {
    /// Open a second vault beside the first (the multi-vault doors that
    /// open one in the app arrive with the switcher).
    pub(crate) fn insert_for_test(&mut self, vault: OpenVault) {
        self.open.insert(vault.id, vault);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bare(id: Uuid) -> OpenVault {
        OpenVault { id, store: None }
    }

    #[test]
    fn the_window_in_the_fields_decides_the_vault() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut slots = VaultSlots::single(bare(a));
        slots.insert_for_test(bare(b));
        assert_eq!(slots.cur().id, a);
        // `enter_window` of a window on vault `b`.
        let resident = slots.set_current(b);
        assert_eq!(resident, a);
        assert_eq!(slots.cur().id, b);
        assert_eq!(slots.cur_mut().id, b);
        // `exit_window`.
        slots.set_current(resident);
        assert_eq!(slots.cur().id, a);
    }

    #[test]
    fn a_view_pass_reads_the_vault_of_the_window_it_draws() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut slots = VaultSlots::single(bare(a));
        slots.insert_for_test(bare(b));
        crate::window_ctx::with_viewed_vault_for_test(Some(b), || {
            assert_eq!(slots.cur().id, b, "an extra window on vault b draws vault b");
        });
        assert_eq!(slots.cur().id, a, "the pass ends, the fields' vault again");
    }

    #[test]
    fn a_window_naming_a_vault_that_is_not_open_falls_back_to_the_current() {
        let a = Uuid::new_v4();
        let slots = VaultSlots::single(bare(a));
        crate::window_ctx::with_viewed_vault_for_test(Some(Uuid::new_v4()), || {
            assert_eq!(slots.cur().id, a);
        });
    }
}
