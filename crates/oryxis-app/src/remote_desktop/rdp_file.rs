//! The `.rdp` connection file handed to `mstsc` (issue #251).
//!
//! `mstsc /v:host` reads the login from nowhere: the address is the only
//! thing the switch carries, so a stored password never reached the
//! client and it asked again. A connection file carries everything the
//! client's own dialog can save: `full address:s:`, `username:s:` and
//! `password 51:b:`, the latter a DPAPI blob (current user, no entropy,
//! over the UTF-16LE password) in uppercase hex, exactly what mstsc
//! writes when "Allow me to save credentials" is ticked (VERIFIED
//! 2026-10-13 against `ProtectedData.Protect`, byte for byte).
//!
//! The base is the user's own `Default.rdp` (Documents), the file
//! `mstsc /v:` would have read, so display, multimon and redirection
//! preferences carry over; only the keys this launch owns are replaced.
//! mstsc writes that file as UTF-16LE with a BOM and CRLF (MEASURED on
//! a Windows 11 profile), and reads a BOM-less file in the ANSI code
//! page, where a CJK username would not survive: the launch file is
//! written the same way mstsc writes its own.
//!
//! Pure: the DPAPI call and the file I/O live in the parent module; this
//! one renders and codes text, and is tested on every platform.

use std::fmt;

/// What the connection file says about one launch.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RdpFile {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl fmt::Debug for RdpFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RdpFile")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Keys the launch owns: a base line carrying one is dropped, whatever
/// its value. `domain` goes too, so the username decides (`DOMAIN\user`
/// or `user@domain` as typed) rather than pairing with a domain the
/// last mstsc session left in `Default.rdp`.
const OWNED_KEYS: [&str; 5] = [
    "full address",
    "username",
    "password 51",
    "prompt for credentials",
    "domain",
];

/// The key of an `.rdp` line (`key:type:value`), or `None` for a line
/// with no `:`.
fn key_of(line: &str) -> Option<&str> {
    line.split_once(':').map(|(k, _)| k.trim())
}

/// Render the file text (LF-joined; `encode` turns it into mstsc's
/// bytes). `base` is the user's `Default.rdp` text, possibly empty;
/// `password_hex` the protected password, `None` when there is none to
/// hand over.
pub(crate) fn render(base: &str, file: &RdpFile, password_hex: Option<&str>) -> String {
    let mut lines: Vec<String> = base
        .lines()
        .map(|l| l.trim_end_matches('\r'))
        .filter(|l| !l.trim().is_empty())
        .filter(|l| {
            !key_of(l).is_some_and(|k| OWNED_KEYS.iter().any(|o| k.eq_ignore_ascii_case(o)))
        })
        .map(str::to_string)
        .collect();
    lines.push(format!("full address:s:{}", super::endpoint(&file.host, file.port)));
    if let Some(u) = file.username.as_deref().filter(|u| !u.is_empty()) {
        lines.push(format!("username:s:{u}"));
    }
    if let Some(hex) = password_hex {
        lines.push(format!("password 51:b:{hex}"));
        // "Always ask for credentials" in the user's own Default.rdp
        // would discard the password we just wrote.
        lines.push("prompt for credentials:i:0".to_string());
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// mstsc's own bytes: UTF-16LE with a BOM, CRLF line ends.
pub(crate) fn encode(text: &str) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFE];
    for line in text.split_inclusive('\n') {
        let (body, nl) = match line.strip_suffix('\n') {
            Some(body) => (body, true),
            None => (line, false),
        };
        for unit in body.encode_utf16() {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        if nl {
            out.extend_from_slice(&[b'\r', 0, b'\n', 0]);
        }
    }
    out
}

/// Read an `.rdp` file's text: UTF-16LE behind a BOM (mstsc's own
/// files), UTF-8 behind its BOM or bare (a hand-written one). Lossy on
/// purpose: a mangled line is a setting mstsc ignores, never a reason
/// to drop the user's whole base.
pub(crate) fn decode(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        // A trailing odd byte is not a code unit; it is dropped.
        let units: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    let rest = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    String::from_utf8_lossy(rest).into_owned()
}

/// The user's `Default.rdp` text, empty when there is none (or it
/// cannot be read: a base is a courtesy, never a requirement).
/// `dirs::document_dir()` is `FOLDERID_Documents` on Windows, the folder
/// mstsc keeps the file in, redirected or not.
pub(crate) fn default_rdp_base() -> String {
    dirs::document_dir()
        .map(|d| d.join("Default.rdp"))
        .and_then(|p| std::fs::read(p).ok())
        .map(|bytes| decode(&bytes))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(username: Option<&str>, password: Option<&str>) -> RdpFile {
        RdpFile {
            host: "127.0.0.1".into(),
            port: 55001,
            username: username.map(str::to_string),
            password: password.map(str::to_string),
        }
    }

    #[test]
    fn renders_address_login_and_protected_password() {
        let text = render("", &file(Some("admin"), Some("pw")), Some("01000000D08C"));
        assert_eq!(
            text,
            "full address:s:127.0.0.1:55001\nusername:s:admin\npassword 51:b:01000000D08C\nprompt for credentials:i:0\n"
        );
    }

    #[test]
    fn no_password_means_no_password_line_and_no_prompt_override() {
        let text = render("", &file(Some("admin"), None), None);
        assert_eq!(text, "full address:s:127.0.0.1:55001\nusername:s:admin\n");
        // A password that could not be protected is the same file: the
        // client asks, with the username filled in.
        assert_eq!(render("", &file(Some("admin"), Some("pw")), None), text);
    }

    #[test]
    fn base_preferences_carry_over_and_owned_keys_are_replaced() {
        let base = "screen mode id:i:2\r\nuse multimon:i:1\r\nfull address:s:old.example\r\nUsername:s:old\r\nDomain:s:OLD\r\nprompt for credentials:i:1\r\npassword 51:b:DEADBEEF\r\n\r\naudiomode:i:0\r\n";
        let text = render(base, &file(Some("jane"), Some("pw")), Some("CAFE"));
        assert_eq!(
            text,
            "screen mode id:i:2\nuse multimon:i:1\naudiomode:i:0\nfull address:s:127.0.0.1:55001\nusername:s:jane\npassword 51:b:CAFE\nprompt for credentials:i:0\n"
        );
        assert!(!text.contains("old"));
        assert!(!text.contains("DEADBEEF"));
    }

    #[test]
    fn ipv6_desktop_is_bracketed_in_full_address() {
        let f = RdpFile {
            host: "fd00::10".into(),
            port: 3389,
            username: None,
            password: None,
        };
        assert_eq!(render("", &f, None), "full address:s:[fd00::10]:3389\n");
    }

    #[test]
    fn encode_is_utf16le_bom_crlf_like_mstsc() {
        let bytes = encode("a:s:密\nb:i:1\n");
        let mut expected = vec![0xFF, 0xFE];
        for unit in "a:s:密\r\nb:i:1\r\n".encode_utf16() {
            expected.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(bytes, expected);
        assert_eq!(decode(&bytes), "a:s:密\r\nb:i:1\r\n");
    }

    #[test]
    fn decode_reads_utf8_with_and_without_bom() {
        assert_eq!(decode("x:s:y\r\n".as_bytes()), "x:s:y\r\n");
        assert_eq!(decode(b"\xEF\xBB\xBFx:s:y\n"), "x:s:y\n");
    }

    #[test]
    fn cjk_username_round_trips_through_the_file_bytes() {
        let text = render("", &file(Some("管理员"), None), None);
        let bytes = encode(&text);
        assert_eq!(decode(&bytes), "full address:s:127.0.0.1:55001\r\nusername:s:管理员\r\n");
    }

    #[test]
    fn debug_output_never_shows_the_password() {
        let f = file(Some("u"), Some("hunter2"));
        let s = format!("{f:?}");
        assert!(s.contains("\"u\""));
        assert!(!s.contains("hunter2"));
    }
}
