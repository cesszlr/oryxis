//! Resolving which OS-native client to spawn for an RDP/VNC launch, and
//! doing the spawn.
//!
//! The RESOLUTION (which program + args for this OS / kind, given what's
//! installed) is a pure function so it can be unit-tested per platform
//! without the clients present. The SPAWN is a thin leaf: the launched
//! client is detached (many clients, `open rdp://`, single-instance
//! Remmina, return immediately), so the SSH `-L` tunnel is NOT tied to
//! the client's process lifetime, it lives as a managed forward until
//! the user stops it. The spawn path has no automated coverage (no
//! headless RDP client exists); it needs manual QA.
//!
//! The desktop login travels the way each client can take it WITHOUT
//! putting the password on a command line (visible to every process on
//! the machine for as long as the client runs):
//!
//! - Windows `mstsc /v:host:port` reads its saved login from the
//!   Credential Manager entry `TERMSRV/<host>` (`windows_cred`): the
//!   launch writes it, the reaper removes it when the client exits
//!   (issue #251: the stored password never reached the client, which
//!   asked again). NOT a `.rdp` file: an unsigned connection file makes
//!   mstsc raise "The publisher of this remote connection can't be
//!   identified" before connecting (SEEN 2026-10-13 on Windows 11 when
//!   a generated file was opened), which trades one prompt for another.
//! - Linux `xfreerdp` takes `/from-stdin:force` and reads the password
//!   from its stdin, one line, before dialling.
//! - macOS `open rdp://` has `username=s:` in its URI scheme and no
//!   password attribute: the client asks for it.
//! - VNC viewers take no credential from us: each has its own password
//!   file format, left for a later change.

use std::fmt;
use std::io::Write as _;
use std::process::{Command, Stdio};

use oryxis_core::models::remote_desktop::RemoteDesktopKind;

#[cfg(windows)]
mod windows_cred;

/// The login staged in the OS credential store for the client to read
/// (`mstsc`): written right before the spawn, removed when the client
/// exits. Both fields present, or nothing is staged: a credential is a
/// pair.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct StagedCredential {
    pub host: String,
    pub username: String,
    pub password: String,
}

impl fmt::Debug for StagedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StagedCredential")
            .field("host", &self.host)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// A resolved client invocation.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LaunchCommand {
    pub program: String,
    pub args: Vec<String>,
    /// A line the client reads from its stdin, then the pipe closes:
    /// the password for `xfreerdp /from-stdin:force`. Never an argument.
    pub stdin_line: Option<String>,
    /// A login staged in the OS credential store before the spawn
    /// (`mstsc` reads `TERMSRV/<host>`), removed after the client exits.
    pub credential: Option<StagedCredential>,
}

impl fmt::Debug for LaunchCommand {
    /// `stdin_line` is the password: the derive would print it into
    /// any log that formats a command.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LaunchCommand")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("stdin_line", &self.stdin_line.as_ref().map(|_| "<redacted>"))
            .field("credential", &self.credential)
            .finish()
    }
}

/// No suitable client was found; carries the binaries we looked for so
/// the UI can tell the user what to install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NoClient {
    pub looked_for: Vec<String>,
}

/// What a spawn reports back. The client is running; `password_handoff_error`
/// is set when it could NOT be given the stored password (the
/// credential store refused) and will ask for it instead;
/// `credential_kept_for` names the host when the OS already held a
/// credential of the user's own for it, which the client used instead
/// of the stored password. Text only, never the secret: this rides a
/// `Message`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Launched {
    pub password_handoff_error: Option<String>,
    pub credential_kept_for: Option<String>,
}

/// `host:port`, with an IPv6 literal bracketed the way every client
/// (and `full address:s:`) expects it.
fn endpoint(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Percent-encode a URI query value: everything but RFC 3986's
/// unreserved set. The Microsoft scheme writes `full address=s:x`, and
/// the current Windows App for macOS refuses a bare colon after the
/// `=`, so the whole value is encoded (a decoder reads both the same).
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Ordered client candidates for (`os`, `kind`), most-preferred first.
/// `os` is `std::env::consts::OS`; injected so the table is testable on
/// any host. URL-scheme launchers (`open`, `mstsc`) are effectively
/// always present, so they're a single candidate; Linux lists several
/// real viewers and the first installed one wins.
fn candidates(
    kind: RemoteDesktopKind,
    os: &str,
    host: &str,
    port: u16,
    username: Option<&str>,
    password: Option<&str>,
) -> Vec<LaunchCommand> {
    let endpoint = endpoint(host, port);
    let username = username.map(str::trim).filter(|u| !u.is_empty());
    let password = password.filter(|p| !p.is_empty());
    let cmd = |program: &str, args: Vec<String>| LaunchCommand {
        program: program.to_string(),
        args,
        stdin_line: None,
        credential: None,
    };
    match (os, kind) {
        // Windows: built-in mstsc for RDP, the login staged where it
        // reads saved credentials (`/v:` carries only the address); no
        // built-in VNC, try common third-party viewers.
        ("windows", RemoteDesktopKind::Rdp) => vec![LaunchCommand {
            credential: username.zip(password).map(|(u, p)| StagedCredential {
                host: host.to_string(),
                username: u.to_string(),
                password: p.to_string(),
            }),
            ..cmd("mstsc", vec![format!("/v:{endpoint}")])
        }],
        ("windows", RemoteDesktopKind::Vnc) => vec![
            cmd("vncviewer", vec![endpoint.clone()]),
            cmd("tvnviewer", vec![endpoint.clone()]),
        ],
        // macOS: the URL schemes are handled by Windows App (rdp://, the
        // documented `attribute=s:value` query form, username included,
        // no password attribute) and built-in Screen Sharing (vnc://)
        // via `open`.
        ("macos", RemoteDesktopKind::Rdp) => {
            let mut uri = format!("rdp://full%20address=s%3A{}", percent_encode(&endpoint));
            if let Some(u) = username {
                uri.push_str("&username=s%3A");
                uri.push_str(&percent_encode(u));
            }
            vec![cmd("open", vec![uri])]
        }
        ("macos", RemoteDesktopKind::Vnc) => {
            vec![cmd("open", vec![format!("vnc://{endpoint}")])]
        }
        // Linux / other unix: real viewers, first installed wins.
        (_, RemoteDesktopKind::Rdp) => {
            let mut freerdp = vec![format!("/v:{endpoint}")];
            let mut stdin_line = None;
            if let Some(u) = username {
                freerdp.push(format!("/u:{u}"));
                // The password goes down stdin, never in argv. Only with
                // a username: `/from-stdin` makes xfreerdp read every
                // MISSING credential from stdin in turn (username,
                // domain, password), and our one line would be taken as
                // the username.
                if let Some(p) = password {
                    freerdp.push("/from-stdin:force".to_string());
                    stdin_line = Some(p.to_string());
                }
            }
            let remmina_target = match username {
                Some(u) => format!("rdp://{u}@{endpoint}"),
                None => format!("rdp://{endpoint}"),
            };
            vec![
                LaunchCommand {
                    stdin_line,
                    ..cmd("xfreerdp", freerdp)
                },
                cmd("remmina", vec!["-c".into(), remmina_target]),
            ]
        }
        (_, RemoteDesktopKind::Vnc) => vec![
            cmd("vncviewer", vec![endpoint.clone()]),
            cmd("remmina", vec!["-c".into(), format!("vnc://{endpoint}")]),
            cmd("vinagre", vec![endpoint.clone()]),
            cmd("xtightvncviewer", vec![endpoint.clone()]),
        ],
    }
}

/// Pick the first candidate whose program `is_available`. Returns the
/// full looked-for list on failure so the UI can name what to install.
pub(crate) fn resolve_command(
    kind: RemoteDesktopKind,
    os: &str,
    host: &str,
    port: u16,
    username: Option<&str>,
    password: Option<&str>,
    is_available: &dyn Fn(&str) -> bool,
) -> Result<LaunchCommand, NoClient> {
    let cands = candidates(kind, os, host, port, username, password);
    for c in &cands {
        if is_available(&c.program) {
            return Ok(c.clone());
        }
    }
    Err(NoClient {
        looked_for: cands.into_iter().map(|c| c.program).collect(),
    })
}

/// Whether `program` can be executed (found on PATH). Cheap: a
/// `Command::new(program)` spawn probe would run it; instead we scan
/// PATH entries, which is what a shell does and never executes anything.
pub(crate) fn program_on_path(program: &str) -> bool {
    // Windows binaries usually carry an extension; try the common ones.
    #[cfg(windows)]
    let names: Vec<String> = vec![
        program.to_string(),
        format!("{program}.exe"),
        format!("{program}.com"),
    ];
    #[cfg(not(windows))]
    let names: Vec<String> = vec![program.to_string()];

    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        names.iter().any(|n| {
            let candidate = dir.join(n);
            candidate.is_file()
        })
    })
}

/// What staging a credential did. Only the Windows arm builds a value;
/// the other targets keep the match in `spawn_client` honest.
#[cfg_attr(not(windows), allow(dead_code))]
enum StageOutcome {
    /// Our entry is in the store under this target; remove it when the
    /// client exits.
    Written(String),
    /// The user has a credential of their own for the host; it was left
    /// alone and the client uses it.
    KeptExisting,
}

/// Put the login where the client reads it. Windows only: `mstsc` is
/// the one client that takes a saved credential from the OS store.
#[cfg(windows)]
fn stage_credential(cred: &StagedCredential) -> Result<StageOutcome, String> {
    let target = windows_cred::target_for(&cred.host);
    Ok(match windows_cred::stage(&target, &cred.username, &cred.password)? {
        windows_cred::Staged::Written => StageOutcome::Written(target),
        windows_cred::Staged::KeptExisting => StageOutcome::KeptExisting,
    })
}

/// `resolve_command` only stages a credential for `os == "windows"`,
/// so this arm never runs; it exists so the spawn leaf compiles the
/// same on every target.
#[cfg(not(windows))]
fn stage_credential(_cred: &StagedCredential) -> Result<StageOutcome, String> {
    Err("the OS credential store is only used on Windows".to_string())
}

#[cfg(windows)]
fn remove_staged_credential(target: &str) {
    if let Err(e) = windows_cred::remove(target) {
        tracing::warn!("remote-desktop credential {target}: {e}");
    }
}

#[cfg(not(windows))]
fn remove_staged_credential(_target: &str) {}

/// Remove every credential this app staged for mstsc: at boot (a
/// process killed with a desktop open never ran its reaper), on the
/// manual lock and on exit (the reaper dies with the process, and the
/// next launch may be days away). A client already connected keeps the
/// login in memory. No-op off Windows.
pub(crate) fn sweep_stale_credentials() {
    #[cfg(windows)]
    windows_cred::sweep_stale();
}

/// Spawn the resolved client. Stages the credential first when the
/// command carries one (a refusal still launches, and is reported),
/// feeds the stdin line, and reaps the child on a thread of its own so
/// the staged credential is removed when the client exits. Blocking
/// (the credential store, the spawn): call it off the UI thread.
pub(crate) fn spawn_client(cmd: LaunchCommand) -> Result<Launched, String> {
    let LaunchCommand {
        program,
        args,
        stdin_line,
        credential,
    } = cmd;
    let mut launched = Launched {
        password_handoff_error: None,
        credential_kept_for: None,
    };
    // The store entry to remove once the client exits: only one WE wrote.
    let mut staged_target: Option<String> = None;
    if let Some(cred) = credential.as_ref() {
        match stage_credential(cred) {
            Ok(StageOutcome::Written(target)) => staged_target = Some(target),
            Ok(StageOutcome::KeptExisting) => launched.credential_kept_for = Some(cred.host.clone()),
            Err(e) => launched.password_handoff_error = Some(e),
        }
    }

    let mut command = Command::new(&program);
    command.args(&args);
    if stdin_line.is_some() {
        command.stdin(Stdio::piped());
        // An askpass helper would be consulted BEFORE stdin and win
        // over the stored password.
        command.env_remove("FREERDP_ASKPASS");
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            if let Some(target) = staged_target {
                remove_staged_credential(&target);
            }
            return Err(format!("{program}: {e}"));
        }
    };
    if let Some(line) = stdin_line
        && let Some(mut stdin) = child.stdin.take()
    {
        // A refused write (the client exited before reading) is the
        // client's own failure to report; the line ends the pipe.
        let _ = stdin.write_all(line.as_bytes()).and_then(|()| stdin.write_all(b"\n"));
    }
    // The reaper: waits out the client (a desktop session can last
    // hours, the thread sleeps in `wait`) and only then removes the
    // staged credential. Reaps the zombie on unix as well.
    std::thread::Builder::new()
        .name("remote-desktop-reaper".into())
        .spawn(move || {
            let _ = child.wait();
            if let Some(target) = staged_target {
                remove_staged_credential(&target);
            }
        })
        .map_err(|e| format!("reaper thread: {e}"))?;
    Ok(launched)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Everything installed.
    fn all(_: &str) -> bool {
        true
    }

    #[test]
    fn windows_rdp_stages_the_login_beside_a_plain_v_switch() {
        let c = resolve_command(
            RemoteDesktopKind::Rdp,
            "windows",
            "127.0.0.1",
            55001,
            Some("admin"),
            Some("s3cret"),
            &all,
        )
        .unwrap();
        assert_eq!(c.program, "mstsc");
        // The address on the switch, as before; the login in the store.
        assert_eq!(c.args, vec!["/v:127.0.0.1:55001"]);
        assert!(c.stdin_line.is_none());
        let cred = c.credential.unwrap();
        assert_eq!(cred.host, "127.0.0.1");
        assert_eq!(cred.username, "admin");
        assert_eq!(cred.password, "s3cret");
    }

    #[test]
    fn windows_rdp_stages_nothing_without_both_halves() {
        // A credential is a pair: a username alone or a password alone
        // has nothing to put in the store, and the client asks.
        for (u, p) in [(None, None), (Some("admin"), None), (None, Some("pw"))] {
            let c = resolve_command(RemoteDesktopKind::Rdp, "windows", "desk.example", 3389, u, p, &all).unwrap();
            assert_eq!(c.args, vec!["/v:desk.example:3389"]);
            assert!(c.credential.is_none());
        }
    }

    #[test]
    fn macos_uses_url_schemes() {
        let rdp = resolve_command(RemoteDesktopKind::Rdp, "macos", "127.0.0.1", 5001, None, None, &all).unwrap();
        assert_eq!(rdp.program, "open");
        assert_eq!(rdp.args, vec!["rdp://full%20address=s%3A127.0.0.1%3A5001"]);
        let vnc = resolve_command(RemoteDesktopKind::Vnc, "macos", "127.0.0.1", 5002, None, None, &all).unwrap();
        assert_eq!(vnc.args, vec!["vnc://127.0.0.1:5002"]);
    }

    #[test]
    fn macos_rdp_carries_the_username_and_never_the_password() {
        let rdp = resolve_command(
            RemoteDesktopKind::Rdp,
            "macos",
            "desk.example",
            3389,
            Some("CORP\\jane doe"),
            Some("s3cret"),
            &all,
        )
        .unwrap();
        assert_eq!(
            rdp.args,
            vec!["rdp://full%20address=s%3Adesk.example%3A3389&username=s%3ACORP%5Cjane%20doe"]
        );
        assert!(rdp.stdin_line.is_none());
        assert!(rdp.credential.is_none());
    }

    #[test]
    fn linux_rdp_prefers_freerdp_and_passes_user() {
        let c = resolve_command(
            RemoteDesktopKind::Rdp,
            "linux",
            "127.0.0.1",
            3390,
            Some("admin"),
            None,
            &all,
        )
        .unwrap();
        assert_eq!(c.program, "xfreerdp");
        assert_eq!(c.args, vec!["/v:127.0.0.1:3390", "/u:admin"]);
        assert!(c.stdin_line.is_none());
    }

    #[test]
    fn linux_freerdp_takes_the_password_on_stdin() {
        let c = resolve_command(
            RemoteDesktopKind::Rdp,
            "linux",
            "127.0.0.1",
            3390,
            Some("admin"),
            Some("s3cret"),
            &all,
        )
        .unwrap();
        assert_eq!(c.args, vec!["/v:127.0.0.1:3390", "/u:admin", "/from-stdin:force"]);
        assert_eq!(c.stdin_line.as_deref(), Some("s3cret"));
        // Never in argv, under any spelling.
        assert!(c.args.iter().all(|a| !a.contains("s3cret")));
    }

    #[test]
    fn linux_password_without_username_is_not_fed() {
        // `/from-stdin` would read the line as the USERNAME.
        let c = resolve_command(RemoteDesktopKind::Rdp, "linux", "127.0.0.1", 3390, None, Some("s3cret"), &all).unwrap();
        assert_eq!(c.args, vec!["/v:127.0.0.1:3390"]);
        assert!(c.stdin_line.is_none());
    }

    #[test]
    fn linux_falls_back_to_remmina_when_freerdp_missing() {
        let only_remmina = |p: &str| p == "remmina";
        let c = resolve_command(
            RemoteDesktopKind::Rdp,
            "linux",
            "127.0.0.1",
            3390,
            None,
            None,
            &only_remmina,
        )
        .unwrap();
        assert_eq!(c.program, "remmina");
        assert_eq!(c.args, vec!["-c", "rdp://127.0.0.1:3390"]);
        let c = resolve_command(RemoteDesktopKind::Rdp, "linux", "127.0.0.1", 3390, Some("admin"), Some("pw"), &only_remmina).unwrap();
        assert_eq!(c.args, vec!["-c", "rdp://admin@127.0.0.1:3390"]);
        assert!(c.stdin_line.is_none());
    }

    #[test]
    fn linux_vnc_walks_the_viewer_list() {
        let only_vinagre = |p: &str| p == "vinagre";
        let c = resolve_command(RemoteDesktopKind::Vnc, "linux", "127.0.0.1", 5901, None, None, &only_vinagre).unwrap();
        assert_eq!(c.program, "vinagre");
    }

    #[test]
    fn nothing_installed_reports_what_to_get() {
        let none = |_: &str| false;
        let err = resolve_command(RemoteDesktopKind::Rdp, "linux", "127.0.0.1", 3389, None, None, &none).unwrap_err();
        assert!(err.looked_for.contains(&"xfreerdp".to_string()));
        assert!(err.looked_for.contains(&"remmina".to_string()));
    }

    #[test]
    fn empty_username_is_omitted() {
        let c = resolve_command(RemoteDesktopKind::Rdp, "linux", "127.0.0.1", 3389, Some("  "), Some("pw"), &all).unwrap();
        assert_eq!(c.args, vec!["/v:127.0.0.1:3389"]);
        assert!(c.stdin_line.is_none());
        let w = resolve_command(RemoteDesktopKind::Rdp, "windows", "127.0.0.1", 3389, Some("  "), Some(""), &all).unwrap();
        assert!(w.credential.is_none());
    }

    #[test]
    fn ipv6_literals_are_bracketed() {
        assert_eq!(endpoint("::1", 3389), "[::1]:3389");
        assert_eq!(endpoint("[::1]", 3389), "[::1]:3389");
        assert_eq!(endpoint("10.0.0.1", 3389), "10.0.0.1:3389");
    }

    #[test]
    fn debug_output_never_shows_the_password() {
        let c = resolve_command(RemoteDesktopKind::Rdp, "linux", "h", 1, Some("u"), Some("hunter2"), &all).unwrap();
        assert!(!format!("{c:?}").contains("hunter2"));
        let w = resolve_command(RemoteDesktopKind::Rdp, "windows", "h", 1, Some("u"), Some("hunter2"), &all).unwrap();
        assert!(!format!("{w:?}").contains("hunter2"));
    }
}
