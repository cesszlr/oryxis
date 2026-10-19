//! Settings -> Vaults section view: every vault this device knows (its
//! state, its file, what can be done with it), the doors to make or open
//! one, and the switcher's visibility. All of it is the DEVICE's (the
//! registry lives in `device.json`), which the section says once.

use super::*;
use iced::widget::column;

use crate::app::MultiVaultMessage;
use crate::state::VaultState;

impl Oryxis {
    pub(crate) fn view_settings_vaults(&self) -> Element<'_, Message> {
        // Keyboard rows are recorded in visual order.
        self.keynav_settings_reset();
        let c = OryxisColors::t();

        let mut list = iced::widget::Column::<Element<'_, Message>>::new().spacing(8);
        for entry in self.registered_vaults() {
            list = list.push(self.vault_settings_card(&entry));
        }

        let new_vault = Message::MultiVault(MultiVaultMessage::ShowNewVault);
        let open_existing = Message::MultiVault(MultiVaultMessage::OpenExistingVault);
        let doors = dir_row(vec![
            self.settings_nav_slot_labeled(
                t("vault_new"),
                crate::keynav::RowAction::activate(new_vault.clone()),
                6.0,
                styled_button(t("vault_new"), new_vault, c.accent),
            ),
            Space::new().width(8).boxed(),
            self.settings_nav_slot_labeled(
                t("vault_open_existing"),
                crate::keynav::RowAction::activate(open_existing.clone()),
                6.0,
                styled_button(t("vault_open_existing"), open_existing, c.bg_selected),
            ),
        ]);

        use crate::state::VaultSwitcherPlace;
        let place_row = self.nav_pick_row(
            t("vault_switcher_place"),
            VaultSwitcherPlace::ALL.iter().map(|p| p.code().to_string()).collect(),
            self.device_prefs.vault_switcher_place.code().to_string(),
            |code: &String| {
                VaultSwitcherPlace::from_code(code).map(|p| t(p.label_key())).unwrap_or_default().to_string()
            },
            220.0,
            |code| {
                Message::MultiVault(MultiVaultMessage::VaultSwitcherPlaceChanged(
                    VaultSwitcherPlace::from_code(&code).unwrap_or_default(),
                ))
            },
        );

        let ask = self.device_prefs.vault_start_picker;
        let ask_msg = Message::MultiVault(MultiVaultMessage::VaultStartPickerToggled(!ask));
        let picker_row = self.settings_nav_slot_labeled(
            t("vault_start_picker"),
            crate::keynav::RowAction::activate(ask_msg.clone()),
            8.0,
            crate::widgets::toggle_row_desc(t("vault_start_picker"), t("vault_start_picker_desc"), ask, ask_msg),
        );

        let hide = self.device_prefs.vault_switcher_hide_single;
        let hide_msg = Message::MultiVault(MultiVaultMessage::VaultSwitcherHideSingleToggled(!hide));
        let hide_row = self.settings_nav_slot_labeled(
            t("vault_switcher_hide_single"),
            crate::keynav::RowAction::activate(hide_msg.clone()),
            8.0,
            crate::widgets::toggle_row_desc(
                t("vault_switcher_hide_single"),
                t("vault_switcher_hide_single_desc"),
                hide,
                hide_msg,
            ),
        );

        let content = column![
            text(t("vaults_section_desc"))
                .size(12)
                .color(c.text_secondary)
                .width(Length::Fill)
                .align_x(dir_align_x()),
            Space::new().height(4),
            text(t("vaults_section_device_note"))
                .size(11)
                .color(c.text_muted)
                .width(Length::Fill)
                .align_x(dir_align_x()),
            Space::new().height(14),
            panel_section(column![list, Space::new().height(14), doors]),
            Space::new().height(12),
            panel_section(column![place_row, Space::new().height(12), hide_row, Space::new().height(12), picker_row]),
            Space::new().height(24),
        ]
        .width(Length::Fill)
        .align_x(dir_align_x());

        scrollable(container(content).padding(Padding { top: 24.0, right: 24.0, bottom: 24.0, left: 24.0 }))
            .id(iced::widget::Id::new(SettingsSection::Vaults.scroll_id()))
            .on_scroll(|s| Message::Settings(SettingsMessage::SectionScrolled(s.viewport.relative_offset().y)))
            .height(Length::Fill)
            .boxed()
    }

    /// One vault of the list: its name (and whether this window is on
    /// it), its state, its file, and the actions that apply to it.
    fn vault_settings_card(&self, entry: &oryxis_vault::device::VaultEntry) -> Element<'_, Message> {
        let c = OryxisColors::t();
        let id = entry.id;
        let open = self.vaults.all().find(|v| v.id == id);
        let available = self.vault_available(id);
        let several = self.vault_count() > 1;
        let here = self.vaults.cur().id == id;
        let path = oryxis_vault::device::installed()
            .map(|d| d.resolve(entry).display().to_string())
            .unwrap_or_default();

        let (status_key, status_color) = match open.map(|v| v.vault_ui.state) {
            _ if !available => ("vault_status_missing", c.error),
            Some(VaultState::Unlocked) => ("vault_status_unlocked", c.success),
            Some(VaultState::Locked) => ("vault_status_locked", c.text_secondary),
            Some(VaultState::NeedSetup) => ("vault_status_not_set_up", c.text_secondary),
            // Any other state is the open vault's own transient screen.
            Some(_) => ("vault_status_locked", c.text_secondary),
            None => ("vault_status_closed", c.text_muted),
        };

        let mut title: Vec<Element<'_, Message>> = vec![
            text(self.vault_name(id)).size(13).color(c.text_primary).boxed(),
        ];
        if here {
            title.push(Space::new().width(8).boxed());
            title.push(
                container(text(t("vault_this_window")).size(10).color(c.text_secondary))
                    .padding(Padding { top: 1.0, right: 6.0, bottom: 1.0, left: 6.0 })
                    .style(|_| container::Style {
                        background: Some(Background::Color(OryxisColors::t().bg_selected)),
                        border: Border { radius: Radius::from(4.0), ..Default::default() },
                        ..Default::default()
                    })
                    .boxed(),
            );
        }

        // The actions that apply, each a keyboard row.
        let mut actions: Vec<Element<'_, Message>> = Vec::new();
        let push = |actions: &mut Vec<Element<'_, Message>>, label: &'static str, msg: Option<Message>, color: Color| {
            if !actions.is_empty() {
                actions.push(Space::new().width(6).boxed());
            }
            let button = styled_button_opt(label, msg.clone(), color);
            actions.push(match msg {
                Some(msg) => self.settings_nav_slot(crate::keynav::RowAction::activate(msg), 6.0, button),
                None => button,
            });
        };
        if available && !here {
            push(&mut actions, t("vault_switch_here"), Some(Message::MultiVault(MultiVaultMessage::SwitchToVault(id))), c.bg_selected);
        }
        if available {
            push(&mut actions, t("vault_open_new_window"), Some(Message::MultiVault(MultiVaultMessage::OpenVaultInNewWindow(id))), c.bg_selected);
        }
        push(&mut actions, t("vault_rename"), Some(Message::MultiVault(MultiVaultMessage::ShowRenameVault(id))), c.bg_selected);
        if open.is_some_and(|v| v.vault_ui.has_user_password && v.vault_ui.state == VaultState::Unlocked) {
            push(&mut actions, t("vault_lock"), Some(Message::MultiVault(MultiVaultMessage::LockVaultById(id))), c.bg_selected);
        }
        if several && (entry.is_outside() || !available) {
            push(&mut actions, t("vault_remove_from_list"), Some(Message::MultiVault(MultiVaultMessage::RemoveVaultFromList(id))), c.bg_selected);
        }
        let deletable = self.vault_deletable(id);
        if several && available {
            push(
                &mut actions,
                t("vault_delete"),
                deletable.then(|| Message::MultiVault(MultiVaultMessage::ShowDeleteVault(id))),
                c.error,
            );
        }

        let mut info = column![
            dir_row(title).align_y(iced::Alignment::Center),
            Space::new().height(3),
            text(t(status_key)).size(11).color(status_color),
            Space::new().height(2),
            text(path).size(11).font(iced::Font::MONOSPACE).color(c.text_muted).selectable(true),
            Space::new().height(8),
            self.vault_hotkey_row(id),
            Space::new().height(10),
            dir_row(actions).align_y(iced::Alignment::Center),
        ]
        .width(Length::Fill)
        .align_x(dir_align_x());
        if several && available && !deletable {
            info = info.push(Space::new().height(6).boxed()).push(
                text(t("vault_delete_unlock_hint")).size(11).color(c.text_muted).boxed(),
            );
        }

        container(info)
            .width(Length::Fill)
            .padding(12)
            .style(|_: &iced::Theme| container::Style {
                background: Some(Background::Color(OryxisColors::t().bg_surface)),
                border: Border { radius: Radius::from(8.0), color: OryxisColors::t().border, width: 1.0 },
                ..Default::default()
            })
            .boxed()
    }

    /// A vault's chord: what it is (or a dash), Record (the next keypress
    /// becomes it; "Press a key…" while armed) and a clear button once
    /// there is one. Fires from any window and any vault, a lock screen
    /// included.
    fn vault_hotkey_row(&self, id: uuid::Uuid) -> Element<'_, Message> {
        let c = OryxisColors::t();
        let chord = self.vault_chords.iter().find(|(v, _)| *v == id).map(|(_, chord)| *chord);
        let armed = self.editing_vault_hotkey == Some(id);
        let shown = chord.map(|ch| ch.badges().join(" + ")).unwrap_or_else(|| "-".to_string());
        let record = Message::MultiVault(MultiVaultMessage::VaultHotkeyCaptureStart(id));
        let (record_label, record_color) = if armed {
            (t("hotkey_press_a_key"), c.accent)
        } else {
            (t("snippet_hotkey_record"), c.bg_selected)
        };
        let mut row: Vec<Element<'_, Message>> = vec![
            text(t("vault_hotkey")).size(12).color(c.text_secondary).boxed(),
            Space::new().width(10).boxed(),
            text(shown).size(12).font(iced::Font::MONOSPACE).color(c.text_primary).boxed(),
            Space::new().width(12).boxed(),
            self.settings_nav_slot(
                crate::keynav::RowAction::activate(record.clone()),
                6.0,
                styled_button(record_label, record, record_color),
            ),
        ];
        if chord.is_some() {
            let clear = Message::MultiVault(MultiVaultMessage::VaultHotkeyClear(id));
            row.push(Space::new().width(6).boxed());
            row.push(self.settings_nav_slot(
                crate::keynav::RowAction::activate(clear.clone()),
                6.0,
                styled_button(t("vault_hotkey_clear"), clear, c.bg_selected),
            ));
        }
        dir_row(row).align_y(iced::Alignment::Center).boxed()
    }
}
