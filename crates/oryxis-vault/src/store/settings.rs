use super::*;

impl VaultStore {
    // -----------------------------------------------------------------------
    // Settings (key/value in settings table)
    // -----------------------------------------------------------------------

    /// The device store a key goes to: `Some` when `key` is a device
    /// setting (`crate::device::is_device_key`) and this store has one
    /// attached.
    fn device_for(&self, key: &str) -> Option<&crate::device::DeviceStore> {
        self.device.as_deref().filter(|_| crate::device::is_device_key(key))
    }

    /// Get a plain-text setting: a device key from the device store
    /// (`crate::device`), any other from the vault's settings table.
    pub fn get_setting(&self, key: &str) -> Result<Option<String>, VaultError> {
        if let Some(device) = self.device_for(key) {
            return Ok(device.get(key));
        }
        let val: Option<String> = self
            .db
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .ok();
        Ok(val)
    }

    /// Set a plain-text setting: a device key in the device store, any
    /// other in the vault's settings table.
    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), VaultError> {
        if let Some(device) = self.device_for(key) {
            return device.set(key, value).map_err(|e| VaultError::Io(std::io::Error::other(e)));
        }
        self.db.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    /// Return every `(key, value)` pair in the settings table, sorted by
    /// key for a stable export order. Values are returned verbatim, so
    /// encrypted settings (`ai_api_key`, `sync_device_identity`) come
    /// back as their base64-encoded ciphertext, the caller is
    /// responsible for substituting decrypted material when needed.
    ///
    /// With a device store attached, the device keys come from it and the
    /// vault's own rows for those keys (left behind by the migration,
    /// `crate::device`) are not listed: an export carries what the app
    /// actually uses.
    pub fn list_settings(&self) -> Result<Vec<(String, String)>, VaultError> {
        let mut stmt = self
            .db
            .prepare("SELECT key, value FROM settings ORDER BY key")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let mut out: Vec<(String, String)> = Vec::new();
        for r in rows {
            out.push(r?);
        }
        if let Some(device) = &self.device {
            out.retain(|(key, _)| !crate::device::is_device_key(key));
            out.extend(device.settings());
            out.sort_by(|a, b| a.0.cmp(&b.0));
        }
        Ok(out)
    }

    /// Delete every setting whose key starts with `prefix`. Backs the
    /// "Reset hints" action, which clears all `hint_*` one-time flags
    /// in one sweep so future hints don't each need their own reset.
    /// Device keys under the prefix go from the device store too.
    pub fn delete_settings_with_prefix(&self, prefix: &str) -> Result<(), VaultError> {
        if let Some(device) = &self.device {
            device
                .delete_with_prefix(prefix)
                .map_err(|e| VaultError::Io(std::io::Error::other(e)))?;
        }
        // ESCAPE so a literal `_`/`%` in the prefix can't wildcard-match.
        let pattern = format!(
            "{}%",
            prefix.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
        );
        self.db.execute(
            "DELETE FROM settings WHERE key LIKE ?1 ESCAPE '\\'",
            params![pattern],
        )?;
        Ok(())
    }

    /// Store an AI API key encrypted in the settings table (base64-encoded).
    pub fn set_ai_api_key(&self, api_key: &str) -> Result<(), VaultError> {
        let encrypted = self.encrypt_field(api_key)?;
        let encoded = BASE64.encode(&encrypted);
        self.set_setting("ai_api_key", &encoded)
    }

    /// Retrieve and decrypt the AI API key from the settings table.
    pub fn get_ai_api_key(&self) -> Result<Option<String>, VaultError> {
        match self.get_setting("ai_api_key")? {
            Some(encoded) => {
                let encrypted = BASE64.decode(encoded.as_bytes())
                    .map_err(|e| VaultError::Crypto(format!("Base64 decode: {}", e)))?;
                Ok(Some(self.decrypt_field(&encrypted)?))
            }
            None => Ok(None),
        }
    }

    /// Store the Files-sidebar folder history encrypted in the settings
    /// table (base64-encoded JSON). Same field-encryption path as the AI
    /// API key, so it rides key rotation via `convert_settings_b64`.
    ///
    /// Not a credential, but not plaintext material either: the settings
    /// table is read WITHOUT unlocking (that is what hydrates theme and
    /// language on the lock screen), so a plain row would hand the
    /// directory layout of every host to anyone holding the file. The
    /// rest of the user's browsing trail (command history, session logs,
    /// chat) is encrypted, and this belongs with it.
    pub fn set_files_recent_folders(&self, json: &str) -> Result<(), VaultError> {
        let encrypted = self.encrypt_field(json)?;
        let encoded = BASE64.encode(&encrypted);
        self.set_setting("files_recent_folders", &encoded)
    }

    /// Retrieve and decrypt the Files-sidebar folder history.
    ///
    /// Anything that fails to decode is DELETED and reported as absent:
    /// the only way to get a non-ciphertext row here is a pre-encryption
    /// build (the plain JSON this replaces), and leaving that row in
    /// place would keep the very plaintext this method exists to remove.
    /// The list is a convenience, so dropping it costs nothing.
    pub fn get_files_recent_folders(&self) -> Result<Option<String>, VaultError> {
        let Some(encoded) = self.get_setting("files_recent_folders")? else {
            return Ok(None);
        };
        let decoded = BASE64
            .decode(encoded.as_bytes())
            .ok()
            .and_then(|bytes| self.decrypt_field(&bytes).ok());
        match decoded {
            Some(json) => Ok(Some(json)),
            None => {
                self.db.execute(
                    "DELETE FROM settings WHERE key = ?1",
                    params!["files_recent_folders"],
                )?;
                Ok(None)
            }
        }
    }

    /// Store the SFTP-sync group passphrase encrypted in the settings
    /// table (base64-encoded). Same field-encryption path as the AI API
    /// key, so it rides key rotation via `convert_settings_b64`. An empty
    /// string clears it.
    pub fn set_sync_sftp_passphrase(&self, passphrase: &str) -> Result<(), VaultError> {
        if passphrase.is_empty() {
            // Delete rather than store an empty value: a "" row would feed
            // an empty ciphertext to the key-rotation re-encrypt pass and
            // fail to decrypt. Absence is the cleared state.
            self.db.execute(
                "DELETE FROM settings WHERE key = ?1",
                params!["sync_sftp_passphrase"],
            )?;
            return Ok(());
        }
        let encrypted = self.encrypt_field(passphrase)?;
        let encoded = BASE64.encode(&encrypted);
        self.set_setting("sync_sftp_passphrase", &encoded)
    }

    /// Retrieve and decrypt the SFTP-sync passphrase, or `None` when it
    /// was never set (or explicitly cleared).
    pub fn get_sync_sftp_passphrase(&self) -> Result<Option<String>, VaultError> {
        match self.get_setting("sync_sftp_passphrase")? {
            Some(encoded) if !encoded.is_empty() => {
                let encrypted = BASE64.decode(encoded.as_bytes())
                    .map_err(|e| VaultError::Crypto(format!("Base64 decode: {}", e)))?;
                Ok(Some(self.decrypt_field(&encrypted)?))
            }
            _ => Ok(None),
        }
    }

    /// Persist the WebDAV account password encrypted at rest.
    ///
    /// A DIFFERENT secret from the sync passphrase, deliberately: the
    /// passphrase derives the snapshot key and every device in a group
    /// shares it, while this is one account's credential on one server.
    /// Collapsing them would put the server password in the hands of
    /// everyone in the sync group.
    pub fn set_sync_webdav_password(&self, password: &str) -> Result<(), VaultError> {
        if password.is_empty() {
            // Absence is the cleared state; see `set_sync_sftp_passphrase`.
            self.db.execute(
                "DELETE FROM settings WHERE key = ?1",
                params!["sync_webdav_password"],
            )?;
            return Ok(());
        }
        let encrypted = self.encrypt_field(password)?;
        let encoded = BASE64.encode(&encrypted);
        self.set_setting("sync_webdav_password", &encoded)
    }

    /// Retrieve and decrypt the WebDAV account password.
    pub fn get_sync_webdav_password(&self) -> Result<Option<String>, VaultError> {
        match self.get_setting("sync_webdav_password")? {
            Some(encoded) if !encoded.is_empty() => {
                let encrypted = BASE64
                    .decode(encoded.as_bytes())
                    .map_err(|e| VaultError::Crypto(format!("Base64 decode: {}", e)))?;
                Ok(Some(self.decrypt_field(&encrypted)?))
            }
            _ => Ok(None),
        }
    }

    /// Persist the sync `DeviceIdentity` blob encrypted at rest. The
    /// caller (oryxis-sync) is responsible for the byte layout (see
    /// `crypto::DeviceIdentity::to_bytes`). We treat the bytes as
    /// opaque secret material and encrypt with the master key, then
    /// base64-encode for storage in the `settings` text column.
    pub fn set_sync_device_identity(&self, bytes: &[u8]) -> Result<(), VaultError> {
        let key = self.require_unlocked()?;
        let encrypted = encrypt_with_key(bytes, key)?;
        let encoded = BASE64.encode(&encrypted);
        self.set_setting("sync_device_identity", &encoded)
    }

    /// Retrieve and decrypt the sync `DeviceIdentity` blob, or `None`
    /// if no identity has been persisted yet. Returns an error if the
    /// stored value is corrupt or the master key has rotated without
    /// re-encryption (see `convert_all_fields`).
    pub fn get_sync_device_identity(&self) -> Result<Option<Vec<u8>>, VaultError> {
        let key = self.require_unlocked()?;
        match self.get_setting("sync_device_identity")? {
            Some(encoded) => {
                let encrypted = BASE64
                    .decode(encoded.as_bytes())
                    .map_err(|e| VaultError::Crypto(format!("Base64 decode: {}", e)))?;
                Ok(Some(decrypt_with_key(&encrypted, key)?))
            }
            None => Ok(None),
        }
    }

}
