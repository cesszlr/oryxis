mod handlers;
mod hostkey;
mod pool;
mod protocol;
mod server;
mod stdio;
mod sudo;
#[cfg(test)]
mod tests;
mod tools;
mod writes;

use std::io;
use std::sync::Arc;

use oryxis_vault::VaultStore;

use server::Served;

#[tokio::main]
async fn main() {
    // Logging to stderr (so it doesn't corrupt JSON-RPC on stdout). The
    // client that spawned us keeps stderr in its own log, so this is
    // the record a report comes with: every request and its outcome
    // here, every dial and auth step from the engine. `RUST_LOG`
    // widens it (`russh=debug` for the wire).
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("oryxis_mcp=info".parse().unwrap())
                .add_directive("oryxis_ssh=info".parse().unwrap()),
        )
        .init();

    let Some(device) = oryxis_vault::device::for_app_dir() else {
        eprintln!("No home directory to find the vaults in.");
        std::process::exit(1);
    };
    let served = match open_vaults(&device, std::env::args().skip(1).collect(), |name| std::env::var(name).ok()) {
        Ok(served) => served,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        vaults = %served.iter().map(|v| v.slug.as_str()).collect::<Vec<_>>().join(", "),
        "Oryxis MCP server started"
    );

    let server = server::Server::with_vaults(served);

    // Idle pooled connections are closed on a timer, so a host does not
    // keep a login from a conversation that went quiet.
    let sweeper = {
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(pool::SWEEP_INTERVAL).await;
                server.sweep_idle();
            }
        })
    };

    stdio::serve(Arc::clone(&server), tokio::io::stdin(), tokio::io::stdout()).await;

    sweeper.abort();
    tracing::info!("Oryxis MCP server stopped");
}

/// The vaults to serve (`MULTI_VAULT_SPEC.md` § 9), from the device's
/// registry (read, never installed: every setting the server reads is
/// the vault's own), in registry order:
///
/// - `--vault <slug>` (or `ORYXIS_MCP_VAULT`) serves that one vault, and
///   failing to open it is the error.
/// - Otherwise every registered vault whose file is there and that
///   opens: no master password, or its password in
///   `ORYXIS_VAULT_PASSWORD_<SLUG>` (`oryxis_vault::device::mcp_env_names`;
///   the first vault's is the plain `ORYXIS_VAULT_PASSWORD`, which old
///   client configs carry). One that does not open is skipped and said
///   on stderr; none at all is the error.
///
/// A vault storing an `mcp_server_token` is served only when the
/// caller presents it (`ORYXIS_MCP_TOKEN_<SLUG>`, plain for the first).
/// Whether MCP is ON is read per call (`Served::enabled`), so a vault
/// switched on later is served without restarting the client.
pub(crate) fn open_vaults(
    device: &oryxis_vault::device::DeviceStore,
    args: Vec<String>,
    env: impl Fn(&str) -> Option<String>,
) -> Result<Vec<Served>, String> {
    let named = args
        .iter()
        .position(|a| a == "--vault")
        .and_then(|i| args.get(i + 1).cloned())
        .or_else(|| env("ORYXIS_MCP_VAULT"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let entries = device.vaults();
    if let Some(slug) = &named {
        if !entries.iter().any(|e| &e.slug == slug) {
            let known: Vec<&str> = entries.iter().map(|e| e.slug.as_str()).collect();
            return Err(format!("No vault \"{slug}\" is registered; known: {}.", known.join(", ")));
        }
    }
    // A config written for several vaults names at least one by its
    // slug; a legacy one (the first vault only, from before there were
    // several) names none. Only the latter may reach the first vault
    // without a token: otherwise a config installed for vault B alone
    // would also be handed a tokenless first vault.
    let legacy_config = !entries
        .iter()
        .filter(|e| e.id != oryxis_vault::device::FIRST_VAULT_ID)
        .map(oryxis_vault::device::mcp_env_names)
        .any(|names| env(&names.token).is_some() || env(&names.password).is_some());
    let mut served = Vec::new();
    let mut skipped = Vec::new();
    for entry in entries.iter().filter(|e| named.as_ref().is_none_or(|n| &e.slug == n)) {
        match open_one(device, entry, &env, legacy_config || named.is_some()) {
            Ok(store) => served.push(Served::new(
                entry.id,
                entry.slug.clone(),
                entry.label.clone().unwrap_or_else(|| entry.slug.clone()),
                store,
            )),
            Err(e) => {
                tracing::warn!(vault = %entry.slug, "not served: {e}");
                skipped.push(format!("{}: {e}", entry.slug));
            }
        }
    }
    if served.is_empty() {
        return Err(format!("No vault could be served. {}", skipped.join(" ")));
    }
    Ok(served)
}

/// Open, unlock and authenticate one registered vault for serving.
fn open_one(
    device: &oryxis_vault::device::DeviceStore,
    entry: &oryxis_vault::device::VaultEntry,
    env: &impl Fn(&str) -> Option<String>,
    tokenless_first: bool,
) -> Result<VaultStore, String> {
    let path = device.resolve(entry);
    if !path.is_file() {
        return Err(format!("its file {} is not there.", path.display()));
    }
    let names = oryxis_vault::device::mcp_env_names(entry);
    let mut vault = VaultStore::open(&path).map_err(|e| format!("Failed to open vault: {e}"))?;
    let password = env(&names.password).unwrap_or_default();
    if password.is_empty() {
        vault
            .open_without_password()
            .map_err(|_| format!("Vault is password-protected. Set {}.", names.password))?;
    } else {
        vault.unlock(&password).map_err(|e| format!("Failed to unlock vault: {e}"))?;
    }
    // Token gate: a vault storing a non-empty `mcp_server_token` needs
    // the caller to present it. An empty stored token keeps the legacy
    // unauthenticated path, for the FIRST vault only (existing setups
    // don't break on upgrade): any other vault without a token would be
    // open to a client configured for the first one, so it is not served
    // (the app gives it a token when its MCP is turned on).
    let stored = vault.get_setting("mcp_server_token").ok().flatten().unwrap_or_default();
    if stored.is_empty() && (entry.id != oryxis_vault::device::FIRST_VAULT_ID || !tokenless_first) {
        return Err("it has no MCP token; set one in Oryxis Settings > MCP Server (Regenerate) and install \
                    the config again."
            .to_string());
    }
    if !stored.is_empty() && env(&names.token).unwrap_or_default() != stored {
        return Err(format!(
            "MCP token mismatch. Set {} to the value shown in Oryxis Settings > Security > MCP. \
             Regenerate the token there if you've lost it.",
            names.token
        ));
    }
    Ok(vault)
}
