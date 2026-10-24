use super::*;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::mcp_consent::{tag_message, Decision, SudoRequest};

/// Domain-separation context, so the master key's use as an HMAC key
/// here can never collide with another derivation.
const CONSENT_CONTEXT: &[u8] = b"oryxis.mcp.sudo_consent.v1";

fn consent_mac(key: &[u8]) -> Hmac<Sha256> {
    // HMAC accepts any key length, so new_from_slice can't fail. The
    // fully-qualified call disambiguates from the `chacha20poly1305`
    // KeyInit blanket impl that `use super::*` drags into scope.
    let mut mac =
        <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(CONSENT_CONTEXT);
    mac
}

impl VaultStore {
    /// The tag an app puts on its answer to `request` (see
    /// [`crate::mcp_consent`]): HMAC-SHA256 under this vault's master
    /// key, hex. Needs the vault unlocked.
    pub fn mcp_consent_tag(
        &self,
        request: &SudoRequest,
        decision: Decision,
    ) -> Result<String, VaultError> {
        let key = self.require_unlocked()?;
        let message = tag_message(request, decision)
            .map_err(|e| VaultError::Crypto(format!("sudo consent request does not serialize: {e}")))?;
        let mut mac = consent_mac(key);
        mac.update(&message);
        Ok(crate::mcp_consent::hex(&mac.finalize().into_bytes()))
    }

    /// Whether `tag` is this vault's tag for `decision` on `request`,
    /// compared in constant time. A locked vault, a malformed tag or a
    /// request that does not serialize is `false`: never an allowance by
    /// default.
    pub fn verify_mcp_consent_tag(
        &self,
        request: &SudoRequest,
        decision: Decision,
        tag: &str,
    ) -> bool {
        let (Ok(key), Some(tag), Ok(message)) = (
            self.require_unlocked(),
            crate::mcp_consent::unhex(tag),
            tag_message(request, decision),
        ) else {
            return false;
        };
        let mut mac = consent_mac(key);
        mac.update(&message);
        mac.verify_slice(&tag).is_ok()
    }
}
