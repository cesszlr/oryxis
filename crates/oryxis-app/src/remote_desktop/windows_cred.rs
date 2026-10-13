//! The one Windows leaf of the remote-desktop launcher: the Credential
//! Manager entry mstsc reads its saved login from (issue #251).
//!
//! `mstsc /v:host` looks up a credential whose target is `TERMSRV/<host>`
//! (the host without the port) and connects with it instead of asking.
//! The launch writes that entry (a GENERIC credential, what `cmdkey
//! /generic:` creates and every working script relies on, the password
//! as its UTF-16LE blob), spawns mstsc, and removes the entry when the
//! client exits. The password never touches a command line.
//!
//! VERIFIED 2026-10-13 with a probe cross-compiled for
//! `x86_64-pc-windows-gnu` and run through WSL interop: `CredWriteW`
//! lands as "Generic / Local machine persistence" in `cmdkey /list`,
//! `CredReadW` returns the exact UTF-16LE blob (CJK and accented text
//! included), `CredEnumerateW` lists ours beside the user's own mstsc
//! entries under `TERMSRV/*` and finds it again under the exact target,
//! `CredDeleteW` removes ours and a second delete answers
//! `ERROR_NOT_FOUND`.
//!
//! A credential this user saved themselves (through mstsc's "remember
//! me", or `cmdkey`) is never overwritten: its blob cannot be read back
//! for the DOMAIN_PASSWORD type mstsc writes, so an overwrite would be
//! a loss with no restore. Ours carry a marker in `Comment`; the boot
//! sweep removes exactly those.

use windows::Win32::Security::Credentials::{
    CRED_ENUMERATE_FLAGS, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW,
    CredEnumerateW, CredFree, CredWriteW,
};
use windows::core::{PCWSTR, PWSTR};

/// What marks a credential as one of ours (the `Comment` field, which
/// nothing else writes on a `TERMSRV/` entry).
const MARKER: &str = "Oryxis remote desktop launch";

/// `ERROR_NOT_FOUND` as an HRESULT: no credential for that target.
const NOT_FOUND: i32 = 0x8007_0490_u32 as i32;

/// The credential target mstsc reads for a `/v:<host>[:port]` dial.
pub(super) fn target_for(host: &str) -> String {
    format!("TERMSRV/{}", host.trim_start_matches('[').trim_end_matches(']'))
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn pwstr_to_string(p: PWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: a non-null PWSTR from the credential store is NUL-terminated.
    unsafe { p.to_string() }.unwrap_or_default()
}

/// Every credential stored under `filter` (`CredEnumerateW` wildcard
/// syntax), as `(target, comment)`.
fn enumerate(filter: &str) -> Result<Vec<(String, String)>, String> {
    let filter_w = wide(filter);
    let mut count = 0u32;
    let mut creds: *mut *mut CREDENTIALW = std::ptr::null_mut();
    // SAFETY: `filter_w` is NUL-terminated and outlives the call; on
    // success `creds` points at `count` entries the OS owns until
    // `CredFree`.
    let res = unsafe {
        CredEnumerateW(
            PCWSTR(filter_w.as_ptr()),
            Some(CRED_ENUMERATE_FLAGS(0)),
            &mut count,
            &mut creds,
        )
    };
    if let Err(e) = res {
        if e.code().0 == NOT_FOUND {
            return Ok(Vec::new());
        }
        return Err(format!("CredEnumerate: {e}"));
    }
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        // SAFETY: `i < count`, each entry is a valid CREDENTIALW.
        let c = unsafe { &**creds.add(i) };
        out.push((pwstr_to_string(c.TargetName), pwstr_to_string(c.Comment)));
    }
    // SAFETY: freed once, the buffer `CredEnumerateW` allocated.
    unsafe { CredFree(creds.cast()) };
    Ok(out)
}

/// Whether a credential NOT written by us exists for `target`, of any
/// type (mstsc's own are DOMAIN_PASSWORD, `cmdkey /generic:` ones
/// GENERIC; the type is part of the key, so a second entry of another
/// type would sit beside the user's and leave mstsc to pick).
fn user_owns(target: &str) -> Result<bool, String> {
    Ok(enumerate(target)?
        .iter()
        .any(|(t, comment)| t.eq_ignore_ascii_case(target) && comment != MARKER))
}

/// What `stage` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Staged {
    /// Our entry is in place; `remove` it when the client exits.
    Written,
    /// The user has a credential of their own for this target; it was
    /// left alone and mstsc will use it.
    KeptExisting,
}

/// Put the login where mstsc reads it. Overwrites an entry of OURS
/// (a previous launch to the same host whose client is still up: the
/// newer password wins, its reaper removes the entry first), never the
/// user's.
pub(super) fn stage(target: &str, username: &str, password: &str) -> Result<Staged, String> {
    if user_owns(target)? {
        return Ok(Staged::KeptExisting);
    }
    let mut target_w = wide(target);
    let mut user_w = wide(username);
    let mut comment_w = wide(MARKER);
    // mstsc / cmdkey store the password as its UTF-16LE text, no NUL.
    let mut blob: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let cred = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: PWSTR(target_w.as_mut_ptr()),
        Comment: PWSTR(comment_w.as_mut_ptr()),
        CredentialBlobSize: u32::try_from(blob.len()).map_err(|_| "password too long".to_string())?,
        CredentialBlob: blob.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        UserName: PWSTR(user_w.as_mut_ptr()),
        ..Default::default()
    };
    // SAFETY: every pointer in `cred` is into a local buffer that
    // outlives the call; the OS copies what it keeps.
    unsafe { CredWriteW(&cred, 0) }.map_err(|e| format!("CredWrite: {e}"))?;
    Ok(Staged::Written)
}

/// Remove our entry for `target`; an entry already gone is not an error.
pub(super) fn remove(target: &str) -> Result<(), String> {
    let target_w = wide(target);
    // SAFETY: `target_w` is NUL-terminated and outlives the call.
    match unsafe { CredDeleteW(PCWSTR(target_w.as_ptr()), CRED_TYPE_GENERIC, None) } {
        Ok(()) => Ok(()),
        Err(e) if e.code().0 == NOT_FOUND => Ok(()),
        Err(e) => Err(format!("CredDelete: {e}")),
    }
}

/// Remove every entry we wrote: ours are the `TERMSRV/*` entries
/// carrying the marker, nothing else is touched. Boot, manual lock and
/// exit all call it.
pub(super) fn sweep_stale() {
    let entries = match enumerate("TERMSRV/*") {
        Ok(entries) => entries,
        Err(e) => {
            tracing::warn!("remote-desktop credential sweep: {e}");
            return;
        }
    };
    for (target, comment) in entries {
        if comment == MARKER
            && let Err(e) = remove(&target)
        {
            tracing::warn!("stale remote-desktop credential {target}: {e}");
        }
    }
}
