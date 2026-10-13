//! The one Windows leaf of the remote-desktop launcher: protecting a
//! password for `password 51:b:` with DPAPI, the way mstsc does.
//!
//! VERIFIED 2026-10-13: a blob from this call (over the UTF-16LE text,
//! no trailing NUL, no entropy, `CRYPTPROTECT_UI_FORBIDDEN`) decrypts
//! with `ProtectedData.Unprotect(.., CurrentUser)` to the same bytes and
//! has the length and header of `ProtectedData.Protect`, the reference
//! every working `.rdp` generator uses. User scope: the blob survives a
//! reboot and is readable by this Windows user only, which is the
//! protection mstsc's own saved files carry.

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
};
use windows::core::PCWSTR;

/// The DPAPI blob of `password`'s UTF-16LE encoding, uppercase hex.
pub(super) fn protect_utf16(password: &str) -> Result<String, String> {
    let mut wide: Vec<u16> = password.encode_utf16().collect();
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(wide.len() * 2).map_err(|_| "password too long".to_string())?,
        pbData: wide.as_mut_ptr().cast::<u8>(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: `input` points into `wide`, which outlives the call;
    // `output` is filled by the OS with a LocalAlloc buffer we copy out
    // of and release below, so no pointer escapes this function.
    let result = unsafe {
        CryptProtectData(
            &input,
            PCWSTR::null(),
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    result.map_err(|e| format!("CryptProtectData: {e}"))?;
    // SAFETY: on success the OS set `pbData` / `cbData` to a buffer it
    // owns until `LocalFree`.
    let bytes = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    // SAFETY: `pbData` came from the call above and is freed once.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(output.pbData.cast())));
    }
    Ok(bytes.iter().map(|b| format!("{b:02X}")).collect())
}
