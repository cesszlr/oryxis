//! Host-icon picker save / reset handlers split out of
//! `dispatch_tabs`. Called from `handle_tabs`.

#![allow(clippy::result_large_err)]

use iced::Task;

use crate::app::{Message, Oryxis};

impl Oryxis {
    pub(super) fn handle_icon_picker_save(&mut self) -> Task<Message> {
        if self.vaults.cur().icon_picker.for_local_terminal {
            // Deferred save: flow the choice into the local-terminal
            // add / edit form; the modal's own Add / Save persists it.
            self.local_terminal_form.icon = self.vaults.cur().icon_picker.icon.clone();
            self.local_terminal_form.color = self.vaults.cur().icon_picker.color.clone();
        } else if self.vaults.cur().icon_picker.for_session_group {
            // Deferred save: flow the choice into the session-group
            // editor form; the form's own Save persists it.
            self.vaults.cur_mut().editor_session_group.icon_style = self.vaults.cur_mut().icon_picker.icon.clone();
            self.vaults.cur_mut().editor_session_group.color = self.vaults.cur_mut().icon_picker.color.clone();
        } else if self.vaults.cur().icon_picker.for_group_form {
            // Form-target: flow the choice back to the dynamic
            // group editor fields. The form's own Save button
            // persists to the vault, so the icon picker stays
            // an in-memory editor here.
            self.vaults.cur_mut().cloud_dynamic_form.icon =
                self.vaults.cur().icon_picker.icon.clone().unwrap_or_default();
            self.vaults.cur_mut().cloud_dynamic_form.color =
                self.vaults.cur().icon_picker.color.clone().unwrap_or_default();
        } else if self.vaults.cur().icon_picker.for_group_edit {
            // Deferred save: flow into the manual group editor; the
            // panel's own Save persists to the vault.
            self.vaults.cur_mut().group_edit.icon = self.vaults.cur_mut().icon_picker.icon.clone().unwrap_or_default();
            self.vaults.cur_mut().group_edit.color = self.vaults.cur_mut().icon_picker.color.clone().unwrap_or_default();
        } else if let Some(conn_id) = self.vaults.cur().icon_picker.for_id {
            let icon = self.vaults.cur().icon_picker.icon.clone();
            let color = self.vaults.cur().icon_picker.color.clone();
            let ov = self.vaults.cur_mut();
            if let Some(conn) = ov.connections.iter_mut().find(|c| c.id == conn_id) {
                conn.custom_icon = icon.clone();
                conn.custom_color = color.clone();
                // Full save so the row persists (and other fields
                // aren't accidentally overwritten).
                if let Some(vault) = &ov.store {
                    let _ = vault.save_connection(conn, None);
                }
            }
        }
        self.vaults.cur_mut().panels.icon_picker = false;
        self.vaults.cur_mut().icon_picker.for_id = None;
        self.vaults.cur_mut().icon_picker.for_group_form = false;
        self.vaults.cur_mut().icon_picker.for_session_group = false;
        self.vaults.cur_mut().icon_picker.for_group_edit = false;
        self.vaults.cur_mut().icon_picker.for_local_terminal = false;
        self.vaults.cur_mut().icon_picker.icon_search.clear();
        self.icon_color_popover = None;
        Task::none()
    }

    pub(super) fn handle_icon_picker_reset_auto(&mut self) -> Task<Message> {
        // Clears the icon/color override, letting OS detection
        // drive the icon again on the next successful connect.
        // (Terminal-theme override is edited separately in the
        // host editor and is not touched here.)
        if self.vaults.cur().icon_picker.for_local_terminal {
            self.local_terminal_form.icon = None;
            self.local_terminal_form.color = None;
        } else if self.vaults.cur().icon_picker.for_session_group {
            self.vaults.cur_mut().editor_session_group.icon_style = None;
            self.vaults.cur_mut().editor_session_group.color = None;
        } else if self.vaults.cur().icon_picker.for_group_form {
            self.vaults.cur_mut().cloud_dynamic_form.icon = String::new();
            self.vaults.cur_mut().cloud_dynamic_form.color = String::new();
        } else if self.vaults.cur().icon_picker.for_group_edit {
            self.vaults.cur_mut().group_edit.icon = String::new();
            self.vaults.cur_mut().group_edit.color = String::new();
        } else if let Some(conn_id) = self.vaults.cur().icon_picker.for_id
            && let ov = self.vaults.cur_mut()
            && let Some(conn) = ov.connections.iter_mut().find(|c| c.id == conn_id) {
            conn.custom_icon = None;
            conn.custom_color = None;
            if let Some(vault) = &ov.store {
                let _ = vault.save_connection(conn, None);
            }
        }
        self.vaults.cur_mut().panels.icon_picker = false;
        self.vaults.cur_mut().icon_picker.for_id = None;
        self.vaults.cur_mut().icon_picker.for_group_form = false;
        self.vaults.cur_mut().icon_picker.for_session_group = false;
        self.vaults.cur_mut().icon_picker.for_group_edit = false;
        self.vaults.cur_mut().icon_picker.for_local_terminal = false;
        self.icon_color_popover = None;
        Task::none()
    }

}
