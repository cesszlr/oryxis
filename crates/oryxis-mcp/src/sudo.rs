//! `ssh_execute` with `sudo: true`: the command runs as root, and when
//! `sudo` wants the login's password, the one stored for the host is
//! handed to it only after the person approves in the Oryxis app.
//!
//! The approval guards the PASSWORD, not root: a login with
//! passwordless sudo could always run `sudo -n` in a plain command, so
//! that path asks nobody. The order, per call:
//!
//! 1. a root login runs the command as it is;
//! 2. `sudo -n true` probes ([`PROBE`]): passwordless runs under
//!    `sudo -n` with no secret anywhere;
//! 3. otherwise the host must store a password, and this server must
//!    hold a grant for (host, route) or get one from the app
//!    ([`oryxis_vault::mcp_consent`]); then the command runs under
//!    `sudo -S -k`, the password on stdin.
//!
//! What reaches the remote side, and why each piece is there:
//!
//! - The exec line is a FIXED script ([`password_line`],
//!   [`passwordless_line`]): the agent's command never enters it, so the
//!   login shell (sh, csh, fish) never parses agent text. The command
//!   rides stdin, after the password line, and reaches root's `sh` as an
//!   argument (`eval "$1"`).
//! - The password never enters a command line (`ps` shows those to every
//!   user): the outer shell `read`s it off stdin and `printf` (a builtin)
//!   pipes it to `sudo -S`.
//! - `-k` makes sudo ask even with a cached ticket, so it always reads
//!   the line, and the pipe it holds is empty while root's command runs.
//!   Root's `sh` also closes its stdin before the command
//!   (`exec </dev/null`): the command can never read a password line.
//! - A marker (random per call) printed by root's `sh` before the
//!   command says the command RAN: without it, the failure is sudo's
//!   (wrong password, not a sudoer, `requiretty`), and the answer says so
//!   instead of passing sudo's refusal off as the command's.

use std::time::Duration;

use tokio::time::Instant;

use oryxis_ssh::ExecResult;
use oryxis_vault::mcp_consent::{self, Decision, DenyReason, Status, SudoRequest};
use zeroize::Zeroizing;

/// The probe: exits 0 only when sudo needs no password (NOPASSWD, or a
/// rule that does not authenticate). `-n` never prompts.
pub const PROBE: &str = "sudo -n true";

/// Budget of the probe, on a connection that is already up.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// How often the server looks for the app's answer.
const POLL: Duration = Duration::from_millis(250);

/// Past the app's own deadline, so the dialog's timeout refusal (a file)
/// arrives before this side gives up.
const DECISION_GRACE: Duration = Duration::from_secs(5);

/// The most a command may weigh to run under sudo, in bytes. The person
/// may have to READ it in the app's dialog before the password goes, and
/// the agent decides how long it is: past this, the dialog is a wall of
/// text nobody judges, and the window spends its frames shaping it. A
/// longer job belongs in a script on the host. Checked before anything
/// is dialled, whatever path the probe would take.
pub const MAX_COMMAND_BYTES: usize = 32 * 1024;

/// Why `command` cannot run under sudo at all, before the dial: `None`
/// when its size is fine.
pub fn command_too_long(command: &str) -> Option<String> {
    (command.len() > MAX_COMMAND_BYTES).then(|| {
        format!(
            "The command is {} bytes; a command for sudo may be at most {} bytes, since the user may have to read it in Oryxis before approving. \
             Put the work in a script on the host and run that instead. Nothing ran.",
            command.len(),
            MAX_COMMAND_BYTES
        )
    })
}

/// What the probe found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    Passwordless,
    NeedsPassword,
    /// No `sudo` on the host (or none on the login's PATH).
    Missing,
}

pub fn classify_probe(result: &ExecResult) -> Probe {
    if result.exit_code == 0 {
        return Probe::Passwordless;
    }
    // 127 from a POSIX shell; csh says "sudo: Command not found." and
    // exits 1, fish exits 127 too. A Windows host's cmd.exe ("'sudo' is
    // not recognized as an internal or external command") and
    // PowerShell ("... is not recognized as the name of a cmdlet") exit
    // 1: read as "needs a password", they would raise a dialog asking
    // for root on a host that has no sudo to give it.
    let stderr = result.stderr.to_ascii_lowercase();
    if result.exit_code == 127 || stderr.contains("command not found") || stderr.contains("is not recognized") {
        return Probe::Missing;
    }
    Probe::NeedsPassword
}

/// A fresh marker: 128 random bits, hex. Hex keeps it inert inside the
/// fixed script (no quote, no `$`, no space).
pub fn new_marker() -> std::io::Result<String> {
    SudoRequest::new_id().map(|id| format!("oryxis-sudo-{id}"))
}

/// What root's `sh` runs, `MARK` replaced by the marker. Inside the outer
/// script it sits in double quotes, hence the escaped `"` and `$`.
const ROOT_SH: &str = r#""echo MARK >&2; exec </dev/null; eval \"\$1\"""#;

/// The exec line when sudo wants the password. stdin = the password,
/// a newline, then the command ([`password_stdin`]).
pub fn password_line(marker: &str) -> String {
    debug_assert!(marker.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    format!(
        "sh -c 'IFS= read -r p || exit 1; c=$(cat); printf \"%s\\n\" \"$p\" | sudo -S -k -p \"\" -- sh -c {} sh \"$c\"'",
        ROOT_SH.replace("MARK", marker)
    )
}

/// The exec line when sudo needs no password. stdin = the command.
pub fn passwordless_line(marker: &str) -> String {
    debug_assert!(marker.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    format!(
        "sh -c 'c=$(cat); sudo -n -- sh -c {} sh \"$c\"'",
        ROOT_SH.replace("MARK", marker)
    )
}

/// Why a password cannot go through `sudo -S`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StdinError {
    /// `sudo -S` reads one line: a line break would cut the password.
    PasswordLineBreak,
    /// A shell argument cannot carry a NUL byte.
    CommandNul,
}

/// The stdin of [`password_line`], wiped on drop.
pub fn password_stdin(password: &str, command: &str) -> Result<Zeroizing<Vec<u8>>, StdinError> {
    if password.contains(['\n', '\r']) {
        return Err(StdinError::PasswordLineBreak);
    }
    if command.contains('\0') {
        return Err(StdinError::CommandNul);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(password.len() + command.len() + 1));
    out.extend_from_slice(password.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(command.as_bytes());
    Ok(out)
}

/// The stdin of [`passwordless_line`].
pub fn passwordless_stdin(command: &str) -> Result<Vec<u8>, StdinError> {
    if command.contains('\0') {
        return Err(StdinError::CommandNul);
    }
    Ok(command.as_bytes().to_vec())
}

/// The command's stderr with the marker line taken out, or `None` when
/// the marker is not there (the command never ran). Whatever sudo said
/// before it (the first-use lecture) stays, in order.
pub fn ran_as_root(stderr: &str, marker: &str) -> Option<String> {
    let mut lines = stderr.split_inclusive('\n');
    let mut kept = String::with_capacity(stderr.len());
    for line in lines.by_ref() {
        if line.trim_end_matches(['\n', '\r']) == marker {
            kept.extend(lines);
            return Some(kept);
        }
        kept.push_str(line);
    }
    None
}

/// Why the app's approval did not come.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentError {
    /// No app instance took the request within the claim window.
    NotPickedUp,
    /// The person (or the dialog's own deadline, or a lock) refused.
    Refused(Option<DenyReason>),
    /// Claimed, then nothing within the decision window.
    TimedOut,
    /// An allowance whose tag this vault does not recognise.
    BadTag,
    /// The request's files vanished under the server.
    Vanished,
    /// The client cancelled the call.
    Cancelled,
    /// The runtime folder could not be written.
    Io(String),
}

/// Post `request`, wait for the answer, and check its tag with
/// `verify`, handed the bytes the request was posted as (the tag covers
/// them, see [`mcp_consent`]). Every file of the request is removed on
/// the way out, whatever the outcome.
pub async fn ask(
    dir: &std::path::Path,
    request: &SudoRequest,
    verify: impl Fn(&[u8], Decision, &str) -> bool,
    mut cancel: tokio::sync::watch::Receiver<bool>,
) -> Result<Decision, ConsentError> {
    let posted_bytes = mcp_consent::post(dir, request).map_err(|e| ConsentError::Io(e.to_string()))?;
    let id = request.id.as_str();
    let posted = Instant::now();
    let mut claimed_at: Option<Instant> = None;
    let outcome = loop {
        match mcp_consent::status(dir, id) {
            Status::Answered(answer) => {
                break if !answer.decision.allows() {
                    Err(ConsentError::Refused(answer.reason))
                } else if verify(&posted_bytes, answer.decision, &answer.tag) {
                    Ok(answer.decision)
                } else {
                    Err(ConsentError::BadTag)
                };
            }
            Status::Posted if posted.elapsed() >= mcp_consent::CLAIM_WINDOW => {
                break Err(ConsentError::NotPickedUp);
            }
            Status::Posted => {}
            Status::Claimed => {
                let since = *claimed_at.get_or_insert_with(Instant::now);
                if since.elapsed() >= mcp_consent::DECISION_WINDOW + DECISION_GRACE {
                    break Err(ConsentError::TimedOut);
                }
            }
            Status::Gone => break Err(ConsentError::Vanished),
        }
        tokio::select! {
            () = tokio::time::sleep(POLL) => {}
            () = cancelled(&mut cancel) => break Err(ConsentError::Cancelled),
        }
    };
    mcp_consent::withdraw(dir, id);
    outcome
}

async fn cancelled(rx: &mut tokio::sync::watch::Receiver<bool>) {
    loop {
        if *rx.borrow() {
            return;
        }
        if rx.changed().await.is_err() {
            // The sender is gone: nobody can cancel any more.
            std::future::pending::<()>().await;
        }
    }
}

/// Why a sudo call did not run, beyond a pool failure.
pub enum SudoFailure {
    /// Dial, auth or exec failed: answered like any `ssh_execute`.
    Pool(Box<crate::pool::PoolFailure>),
    /// Nothing ran, and this says why.
    NotRun(String),
}

impl From<Box<crate::pool::PoolFailure>> for SudoFailure {
    fn from(f: Box<crate::pool::PoolFailure>) -> Self {
        SudoFailure::Pool(f)
    }
}

/// A command that ran as root.
pub struct RootRun {
    pub run: crate::pool::PoolRun,
    /// How it got there, for the answer: `root_login`, `passwordless`
    /// or `stored_password`.
    pub mode: &'static str,
}

/// Run `command` as root on the host `plan` dials (see the module doc
/// for the order of the steps).
pub async fn execute(
    server: &crate::server::Server,
    served: &crate::server::Served,
    plan: &crate::handlers::DialPlan,
    command: &str,
    timeout: Duration,
    cancel: tokio::sync::watch::Receiver<bool>,
) -> Result<RootRun, SudoFailure> {
    let label = plan.label.as_str();
    if let Some(too_long) = command_too_long(command) {
        return Err(SudoFailure::NotRun(too_long));
    }
    if plan.auth_conn.username.as_deref() == Some("root") {
        let run = served.pool.exec(plan, command, None, timeout, cancel).await?;
        return Ok(RootRun { run, mode: "root_login" });
    }
    let probe = served
        .pool
        .exec(plan, PROBE, None, PROBE_TIMEOUT, cancel.clone())
        .await?;
    let marker = new_marker().map_err(|e| SudoFailure::NotRun(format!("No randomness for the sudo marker: {e}")))?;
    let not_run = |e: StdinError| {
        SudoFailure::NotRun(match e {
            StdinError::PasswordLineBreak => format!(
                "The password stored for {label} contains a line break, which sudo -S cannot read. Nothing ran."
            ),
            StdinError::CommandNul => "The command contains a NUL byte. Nothing ran.".to_string(),
        })
    };
    let (line, stdin, mode): (String, Zeroizing<Vec<u8>>, &'static str) =
        match classify_probe(&probe.result) {
            Probe::Missing => {
                return Err(SudoFailure::NotRun(format!(
                    "sudo is not available on {label} (exit {}): {}",
                    probe.result.exit_code,
                    probe.result.stderr.trim()
                )));
            }
            Probe::Passwordless => (
                passwordless_line(&marker),
                Zeroizing::new(passwordless_stdin(command).map_err(not_run)?),
                "passwordless",
            ),
            Probe::NeedsPassword => {
                let Some(password) = plan.password.as_deref() else {
                    return Err(SudoFailure::NotRun(format!(
                        "sudo on {label} needs the login's password, and this host stores none in Oryxis. \
                         Store the password on the host in Oryxis, or give this login passwordless sudo. \
                         Nothing ran. sudo said: {}",
                        probe.result.stderr.trim()
                    )));
                };
                let stdin = password_stdin(password, command).map_err(not_run)?;
                approve(server, served, plan, command, cancel.clone()).await?;
                (password_line(&marker), stdin, "stored_password")
            }
        };
    let mut run = served
        .pool
        .exec(plan, &line, Some(&stdin[..]), timeout, cancel)
        .await?;
    drop(stdin);
    match ran_as_root(&run.result.stderr, &marker) {
        Some(stderr) => {
            run.result.stderr = stderr;
            Ok(RootRun { run, mode })
        }
        None => Err(SudoFailure::NotRun(format!(
            "sudo on {label} refused (exit {}); the command did not run. sudo said: {}",
            run.result.exit_code,
            run.result.stderr.trim()
        ))),
    }
}

/// Make sure the app allowed the stored password for this host and
/// route: a grant from earlier in this process, or the person's answer
/// now.
async fn approve(
    server: &crate::server::Server,
    served: &crate::server::Served,
    plan: &crate::handlers::DialPlan,
    command: &str,
    mut cancel: tokio::sync::watch::Receiver<bool>,
) -> Result<(), SudoFailure> {
    let (host, signature) = (plan.conn_id, plan.signature);
    if served.sudo_granted(host, signature) {
        return Ok(());
    }
    let _turn = tokio::select! {
        turn = served.sudo_gate.lock() => turn,
        () = cancelled(&mut cancel) => return Err(SudoFailure::NotRun("Cancelled.".into())),
    };
    // The call ahead may have been granted for the session meanwhile.
    if served.sudo_granted(host, signature) {
        return Ok(());
    }
    let dir = mcp_consent::consent_dir()
        .ok_or_else(|| SudoFailure::NotRun("No home directory to reach Oryxis through.".into()))?;
    let route = plan
        .resolver
        .as_ref()
        .map(|r| {
            r.connections
                .iter()
                .map(|hop| format!("{} ({})", hop.label, oryxis_core::net::host_port(&hop.hostname, hop.port)))
                .collect()
        })
        .unwrap_or_default();
    let request = SudoRequest {
        id: SudoRequest::new_id().map_err(|e| SudoFailure::NotRun(format!("No randomness for the request: {e}")))?,
        vault_id: served.id,
        vault_label: served.label.clone(),
        host_id: host,
        host_label: plan.label.clone(),
        login: plan.auth_conn.username.clone().unwrap_or_default(),
        address: plan.endpoint.clone(),
        route,
        client: server.client_name(),
        command: command.to_string(),
        created_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };
    tracing::info!(host = %plan.label, vault = %served.slug, request = %request.id, "sudo: asking the app");
    let verify =
        |posted: &[u8], decision: Decision, tag: &str| served.vault().verify_mcp_consent_tag(posted, decision, tag);
    let outcome = ask(&dir, &request, verify, cancel).await;
    tracing::info!(host = %plan.label, request = %request.id, outcome = ?outcome, "sudo: the app answered");
    match outcome {
        Ok(Decision::Session) => {
            served.grant_sudo(host, signature);
            Ok(())
        }
        Ok(_) => Ok(()),
        Err(e) => Err(SudoFailure::NotRun(consent_text(&e, &plan.label, &served.label))),
    }
}

/// The answer to the agent when the approval did not come. Nothing ran
/// in any of these.
fn consent_text(e: &ConsentError, host: &str, vault: &str) -> String {
    match e {
        ConsentError::NotPickedUp => format!(
            "sudo on {host} needs the user's approval in Oryxis, and no Oryxis window that could ask picked up the request within {} s: \
             Oryxis is not running, its window is hidden to the tray, or the vault \"{vault}\" is locked there. \
             Ask the user to bring up the Oryxis window with that vault unlocked, then call again. Nothing ran.",
            mcp_consent::CLAIM_WINDOW.as_secs()
        ),
        ConsentError::Refused(Some(DenyReason::TimedOut)) | ConsentError::TimedOut => format!(
            "Nobody answered the sudo approval for {host} in Oryxis within {} s. Nothing ran.",
            mcp_consent::DECISION_WINDOW.as_secs()
        ),
        ConsentError::Refused(Some(DenyReason::Locked)) => format!(
            "The vault \"{vault}\" was locked in Oryxis while the sudo approval for {host} was up. Nothing ran."
        ),
        ConsentError::Refused(Some(DenyReason::AppClosed)) => format!(
            "Oryxis was closed (or hidden to the tray) while the sudo approval for {host} was up. Nothing ran."
        ),
        ConsentError::Refused(_) => format!(
            "The user refused to let sudo use the password stored for {host}. Nothing ran; do not retry unless the user asks."
        ),
        ConsentError::BadTag => format!(
            "The sudo approval for {host} did not carry a valid signature from Oryxis, so it was not honoured. Nothing ran."
        ),
        ConsentError::Vanished => format!(
            "The sudo approval request for {host} was removed before Oryxis answered. Nothing ran."
        ),
        ConsentError::Cancelled => "Cancelled.".to_string(),
        ConsentError::Io(why) => format!("Could not ask Oryxis for the sudo approval: {why}. Nothing ran."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "s3cret pass\\with$odd'chars";

    fn exec(code: u32, stderr: &str) -> ExecResult {
        ExecResult { exit_code: code, stdout: String::new(), stderr: stderr.into() }
    }

    #[test]
    fn the_probe_tells_the_three_cases_apart() {
        assert_eq!(classify_probe(&exec(0, "")), Probe::Passwordless);
        assert_eq!(classify_probe(&exec(1, "sudo: a password is required\n")), Probe::NeedsPassword);
        assert_eq!(classify_probe(&exec(127, "sh: 1: sudo: not found\n")), Probe::Missing);
        assert_eq!(classify_probe(&exec(1, "sudo: Command not found.\n")), Probe::Missing);
        assert_eq!(
            classify_probe(&exec(
                1,
                "'sudo' is not recognized as an internal or external command,\r\noperable program or batch file.\r\n"
            )),
            Probe::Missing
        );
        assert_eq!(
            classify_probe(&exec(
                1,
                "sudo : The term 'sudo' is not recognized as the name of a cmdlet, function, script file, or operable program.\r\n"
            )),
            Probe::Missing
        );
    }

    #[test]
    fn neither_the_password_nor_the_command_is_on_the_exec_line() {
        let marker = new_marker().unwrap();
        for line in [password_line(&marker), passwordless_line(&marker)] {
            assert!(!line.contains("s3cret"));
            // The fixed script holds exactly one single-quoted string,
            // so no login shell sees anything but `sh -c '<script>'`.
            assert_eq!(line.matches('\'').count(), 2, "{line}");
            assert!(line.starts_with("sh -c '") && line.ends_with('\''));
            assert!(!line.contains('!'), "csh history expansion");
        }
    }

    #[test]
    fn the_password_goes_first_on_its_own_line() {
        let stdin = password_stdin(PASSWORD, "id\nwhoami").unwrap();
        assert_eq!(&stdin[..], format!("{PASSWORD}\nid\nwhoami").as_bytes());
        assert_eq!(password_stdin("a\nb", "id").unwrap_err(), StdinError::PasswordLineBreak);
        assert_eq!(password_stdin("a\rb", "id").unwrap_err(), StdinError::PasswordLineBreak);
        assert_eq!(password_stdin("a", "i\0d").unwrap_err(), StdinError::CommandNul);
    }

    #[test]
    fn a_command_past_the_cap_does_not_run() {
        assert_eq!(command_too_long("id"), None);
        assert_eq!(command_too_long(&"x".repeat(MAX_COMMAND_BYTES)), None, "the cap is inclusive");
        let text = command_too_long(&"x".repeat(MAX_COMMAND_BYTES + 1)).unwrap();
        assert!(text.contains("32769 bytes") && text.contains("at most 32768 bytes"), "{text}");
        assert!(text.ends_with("Nothing ran."));
    }

    #[test]
    fn the_marker_says_whether_the_command_ran() {
        let m = "oryxis-sudo-abc";
        assert_eq!(ran_as_root(&format!("{m}\nwarn\n"), m).as_deref(), Some("warn\n"));
        assert_eq!(
            ran_as_root(&format!("lecture\n{m}\nwarn"), m).as_deref(),
            Some("lecture\nwarn")
        );
        assert_eq!(ran_as_root("Sorry, try again.\nsudo: 1 incorrect password attempt\n", m), None);
        // A line that merely CONTAINS the marker is not it.
        assert_eq!(ran_as_root(&format!("x{m}\n"), m), None);
    }

    /// The exec lines, run through a real `sh` (as the login shell would)
    /// against a stand-in `sudo` on PATH: what reaches root's command,
    /// and what never does.
    #[cfg(unix)]
    mod shell {
        use super::*;
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;

        /// A `sudo` that wants `PASSWORD` on stdin under `-S` (unless
        /// `READS=0`, the NOPASSWD shape that never reads it) and then
        /// runs what follows `--`.
        const FAKE_SUDO: &str = r#"#!/bin/sh
want=""
while [ "$1" != "--" ]; do
  case "$1" in -S) want=yes ;; esac
  shift
done
shift
if [ -n "$want" ] && [ "${READS:-1}" = 1 ]; then
  IFS= read -r got || got=""
  if [ "$got" != "$EXPECTED" ]; then
    echo "Sorry, try again." >&2
    echo "sudo: 1 incorrect password attempt" >&2
    exit 1
  fi
fi
exec "$@"
"#;

        struct Run {
            code: i32,
            stdout: String,
            stderr: String,
        }

        fn run(line: &str, stdin: &[u8], reads: bool) -> Run {
            let dir = tempfile::tempdir().unwrap();
            let sudo = dir.path().join("sudo");
            std::fs::write(&sudo, FAKE_SUDO).unwrap();
            std::fs::set_permissions(&sudo, std::fs::Permissions::from_mode(0o755)).unwrap();
            let path = format!("{}:{}", dir.path().display(), std::env::var("PATH").unwrap());
            let mut child = std::process::Command::new("sh")
                .arg("-c")
                .arg(line)
                .env("PATH", path)
                .env("EXPECTED", PASSWORD)
                .env("READS", if reads { "1" } else { "0" })
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(stdin).unwrap();
            let out = child.wait_with_output().unwrap();
            Run {
                code: out.status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            }
        }

        /// Quotes, `$`, a backslash, a line break and a stdin reader:
        /// the command arrives verbatim and reads nothing.
        const COMMAND: &str = "printf '%s\\n' \"it's \\$HOME\"\necho to-stderr >&2\ncat\nexit 3";

        #[test]
        fn the_password_path_runs_the_command_verbatim_with_stdin_closed() {
            let m = new_marker().unwrap();
            let stdin = password_stdin(PASSWORD, COMMAND).unwrap();
            let r = run(&password_line(&m), &stdin, true);
            assert_eq!(r.code, 3);
            assert_eq!(r.stdout, "it's $HOME\n");
            assert_eq!(ran_as_root(&r.stderr, &m).as_deref(), Some("to-stderr\n"));
            assert!(!r.stdout.contains("s3cret") && !r.stderr.contains("s3cret"));
        }

        #[test]
        fn a_wrong_password_never_runs_the_command() {
            let m = new_marker().unwrap();
            let stdin = password_stdin("wrong", "echo ran").unwrap();
            let r = run(&password_line(&m), &stdin, true);
            assert_eq!(r.code, 1);
            assert!(r.stdout.is_empty());
            assert_eq!(ran_as_root(&r.stderr, &m), None);
            assert!(r.stderr.contains("incorrect password"));
        }

        #[test]
        fn a_sudo_that_never_reads_the_password_leaves_it_out_of_reach() {
            // The race the probe cannot close: sudo turned passwordless
            // between the probe and the run. The line stays in the pipe;
            // the command, reading stdin, must not see it.
            let m = new_marker().unwrap();
            let stdin = password_stdin(PASSWORD, "cat; echo done").unwrap();
            let r = run(&password_line(&m), &stdin, false);
            assert_eq!(r.stdout, "done\n");
            assert!(!r.stdout.contains("s3cret") && !r.stderr.contains("s3cret"));
        }

        #[test]
        fn the_passwordless_path_runs_the_command_verbatim() {
            let m = new_marker().unwrap();
            let r = run(&passwordless_line(&m), &passwordless_stdin(COMMAND).unwrap(), false);
            assert_eq!(r.code, 3);
            assert_eq!(r.stdout, "it's $HOME\n");
            assert_eq!(ran_as_root(&r.stderr, &m).as_deref(), Some("to-stderr\n"));
        }
    }

    mod consent {
        use super::*;
        use oryxis_vault::mcp_consent::Answer;

        fn request() -> SudoRequest {
            SudoRequest {
                id: SudoRequest::new_id().unwrap(),
                vault_id: uuid::Uuid::new_v4(),
                vault_label: "Personal".into(),
                host_id: uuid::Uuid::new_v4(),
                host_label: "web".into(),
                login: "deploy".into(),
                address: "10.0.0.5:22".into(),
                route: Vec::new(),
                client: None,
                command: "id".into(),
                created_unix: 0,
            }
        }

        /// An app stand-in: claims the request once it shows up and
        /// answers with `answer`.
        fn app(dir: std::path::PathBuf, id: String, answer: Answer) {
            std::thread::spawn(move || {
                for _ in 0..200 {
                    if mcp_consent::claim(&dir, &id).is_some() {
                        mcp_consent::answer(&dir, &id, &answer).unwrap();
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            });
        }

        fn no_cancel() -> tokio::sync::watch::Receiver<bool> {
            let (tx, rx) = tokio::sync::watch::channel(false);
            std::mem::forget(tx);
            rx
        }

        #[tokio::test]
        async fn an_allowance_with_a_good_tag_comes_back_and_the_files_go() {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("c");
            let r = request();
            app(dir.clone(), r.id.clone(), Answer {
                decision: Decision::Session,
                reason: None,
                tag: "good".into(),
            });
            let got = ask(&dir, &r, |_, d, tag| d == Decision::Session && tag == "good", no_cancel()).await;
            assert_eq!(got, Ok(Decision::Session));
            assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        }

        #[tokio::test]
        async fn the_tag_is_checked_over_the_bytes_the_server_posted() {
            // The app tags the file as IT read it; this side checks over
            // what IT wrote. A file rewritten in between (the agent's
            // shell swapping the command) is a tag over other bytes.
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("c");
            let r = request();
            let expected = serde_json::to_vec(&r).unwrap();
            let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            app(dir.clone(), r.id.clone(), Answer {
                decision: Decision::Once,
                reason: None,
                tag: "good".into(),
            });
            let got = ask(
                &dir,
                &r,
                |posted, _, tag| {
                    seen.lock().unwrap().extend_from_slice(posted);
                    tag == "good"
                },
                no_cancel(),
            )
            .await;
            assert_eq!(got, Ok(Decision::Once));
            assert_eq!(*seen.lock().unwrap(), expected);
        }

        #[tokio::test]
        async fn an_allowance_with_a_bad_tag_is_refused() {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("c");
            let r = request();
            app(dir.clone(), r.id.clone(), Answer {
                decision: Decision::Once,
                reason: None,
                tag: "forged".into(),
            });
            let got = ask(&dir, &r, |_, _, tag| tag == "good", no_cancel()).await;
            assert_eq!(got, Err(ConsentError::BadTag));
        }

        #[tokio::test]
        async fn a_refusal_carries_its_reason() {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("c");
            let r = request();
            app(dir.clone(), r.id.clone(), Answer {
                decision: Decision::Deny,
                reason: Some(DenyReason::Locked),
                tag: String::new(),
            });
            let got = ask(&dir, &r, |_, _, _| true, no_cancel()).await;
            assert_eq!(got, Err(ConsentError::Refused(Some(DenyReason::Locked))));
        }

        #[tokio::test]
        async fn a_cancel_takes_the_question_away() {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("c");
            let r = request();
            let (tx, rx) = tokio::sync::watch::channel(false);
            let asking = tokio::spawn({
                let dir = dir.clone();
                let r = r.clone();
                async move { ask(&dir, &r, |_, _, _| true, rx).await }
            });
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(mcp_consent::status(&dir, &r.id), Status::Posted);
            tx.send(true).unwrap();
            assert_eq!(asking.await.unwrap(), Err(ConsentError::Cancelled));
            assert_eq!(mcp_consent::status(&dir, &r.id), Status::Gone);
        }

        #[tokio::test(start_paused = true)]
        async fn nobody_claiming_is_reported_after_the_claim_window() {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("c");
            let r = request();
            let got = ask(&dir, &r, |_, _, _| true, no_cancel()).await;
            assert_eq!(got, Err(ConsentError::NotPickedUp));
            assert_eq!(mcp_consent::status(&dir, &r.id), Status::Gone);
        }
    }
}
