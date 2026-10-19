//! `create_host` / `update_host`: the MCP's two writes to the host
//! table, behind a switch the user turns on in Settings > MCP Server
//! (`mcp_server_allow_writes`, off by default, read per call like the
//! server switch itself).
//!
//! The rules are the editor's, applied by a caller that is not a
//! person:
//!
//! - A folder is RESOLVED (path or label), never created: a typo must
//!   not mint a folder that then rides sync. The error lists the folders
//!   that exist (`list_groups` lists them anyway); an ambiguous label is
//!   refused with the paths it could mean.
//! - A key, an identity and a jump hop are named by id or by label; an
//!   ambiguous label is refused with a request for the id, never guessed,
//!   and a name that matches nothing is just "not found": no error lists
//!   identities or hosts, which no read tool exposes (hosts kept out of
//!   MCP among them). Hops resolve among ALL hosts (a bastion is a route,
//!   not a tool target), and a host is never its own hop.
//! - The hostname is a host: `user@host`, `host:port` or anything the
//!   host grammar rejects is refused with where the part belongs (an
//!   `ssh://` prefix alone is dropped, as the editor does), and so is a
//!   name starting with `-` (it would reach a command proxy's `%h` as an
//!   option).
//! - The password is the one secret accepted, tri-state like the vault's
//!   API: absent keeps what is stored, `null` clears it, a string stores
//!   it encrypted, verbatim (never trimmed). Nothing a write returns ever
//!   carries it.
//! - **A stored secret never goes to an address the user did not give
//!   it to** (`credential_guard`). The agent picks the address, and with
//!   `accept_host_key` it can make any server it runs trusted, so a write
//!   that pointed a stored credential at a new address would hand it to
//!   whoever answers. Refused: moving (hostname or port) a host that
//!   stores its own password or TOTP secret, unless the call replaces or
//!   clears the password and the host has no TOTP secret (a new jump
//!   chain or a folder whose proxy differs is a move too: the same
//!   private address through another route is another server); and attaching,
//!   directly or through a folder's default, an identity that stores a
//!   password, unless an MCP host at that same address, by the same
//!   route, already uses it.
//!   Keys stay attachable: a public-key signature is bound to its session
//!   and gives the server nothing to reuse. An address the user keeps out
//!   of MCP (a host there with MCP off) is refused outright: a copy of it
//!   would reach it anyway. A host that is a hop of a host storing a
//!   secret does not move either: moving it moves them.
//! - No proxy fields: `ProxyType::Command` becomes a LOCAL process, and
//!   only what the user TYPED is ever pre-approved; an AI-supplied proxy
//!   is not typed. A host that needs one is edited in the app.
//! - `updated_at` is stamped here: `save_connection` writes it as given,
//!   and an unstamped edit loses under sync's last-writer-wins.
//! - Every write announces itself (`oryxis_vault::change_notice`) so a
//!   running app re-reads its lists.

use std::collections::HashSet;

use serde_json::{json, Value};
use uuid::Uuid;

use oryxis_core::models::connection::{AuthMethod, Connection, ConnectionProtocol};
use oryxis_core::models::group::Group;
use oryxis_vault::VaultStore;

use crate::handlers::handle_get_host;
use crate::server::Server;

/// The setting that unlocks both tools.
pub const ALLOW_WRITES_SETTING: &str = "mcp_server_allow_writes";

/// Refuse unless the user switched writes on. Read per call so the
/// toggle takes effect on the next request without a restart.
fn gate(vault: &VaultStore) -> Result<(), String> {
    let on = vault
        .get_setting(ALLOW_WRITES_SETTING)
        .ok()
        .flatten()
        .is_some_and(|v| v == "true");
    if on {
        Ok(())
    } else {
        Err("Host writes over MCP are off. Turn on \"Allow the MCP server to add and edit hosts\" \
             in Oryxis Settings > MCP Server."
            .to_string())
    }
}

/// A field the call may carry: absent (keep), `null` (clear) or a value.
enum Field<T> {
    Absent,
    Clear,
    Set(T),
}

fn str_field(params: Option<&Value>, name: &str) -> Result<Field<String>, String> {
    Ok(match raw_str_field(params, name)? {
        Field::Set(s) => Field::Set(s.trim().to_string()),
        other => other,
    })
}

/// `str_field` without the trim: a password is stored as given, its
/// spaces included, and only `null` clears it.
fn raw_str_field(params: Option<&Value>, name: &str) -> Result<Field<String>, String> {
    match params.and_then(|p| p.get(name)) {
        None => Ok(Field::Absent),
        Some(Value::Null) => Ok(Field::Clear),
        Some(Value::String(s)) => Ok(Field::Set(s.clone())),
        Some(_) => Err(format!("Parameter {name} must be a string")),
    }
}

fn list_field(params: Option<&Value>, name: &str) -> Result<Field<Vec<String>>, String> {
    match params.and_then(|p| p.get(name)) {
        None => Ok(Field::Absent),
        Some(Value::Null) => Ok(Field::Clear),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(|s| s.trim().to_string())
                    .ok_or_else(|| format!("Parameter {name} must be an array of strings"))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Field::Set),
        Some(_) => Err(format!("Parameter {name} must be an array of strings")),
    }
}

fn bool_field(params: Option<&Value>, name: &str) -> Result<Option<bool>, String> {
    match params.and_then(|p| p.get(name)) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(format!("Parameter {name} must be a boolean")),
    }
}

fn port_field(params: Option<&Value>) -> Result<Option<u16>, String> {
    match params.and_then(|p| p.get("port")) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .filter(|p| (1..=65535).contains(p))
            .map(|p| Some(p as u16))
            .ok_or_else(|| "Parameter port must be an integer from 1 to 65535".to_string()),
    }
}

fn parse_auth_method(s: &str) -> Result<AuthMethod, String> {
    Ok(match s.trim().to_ascii_lowercase().as_str() {
        "auto" => AuthMethod::Auto,
        "password" => AuthMethod::Password,
        "key" => AuthMethod::Key,
        "agent" => AuthMethod::Agent,
        "interactive" => AuthMethod::Interactive,
        "password_prompt" => AuthMethod::PasswordPrompt,
        other => {
            return Err(format!(
                "Unknown auth_method \"{other}\"; one of auto, password, key, agent, interactive, \
                 password_prompt (certificate and security-key hosts are set up in the app)"
            ))
        }
    })
}

/// Resolve `input` to one entry of `items` by id or by exact label. An
/// ambiguous label is refused: the caller must say which one by id. A
/// miss names nothing: the list would expose labels no read tool shows.
fn resolve_named<T>(
    what: &str,
    input: &str,
    items: &[T],
    id_of: impl Fn(&T) -> Uuid,
    label_of: impl Fn(&T) -> &str,
) -> Result<Uuid, String> {
    if let Ok(id) = Uuid::parse_str(input) {
        return items
            .iter()
            .map(&id_of)
            .find(|i| *i == id)
            .ok_or_else(|| format!("No {what} with id {id}"));
    }
    let matches: Vec<&T> = items.iter().filter(|i| label_of(i) == input).collect();
    match matches.len() {
        1 => Ok(id_of(matches[0])),
        0 => Err(format!("No {what} named \"{input}\"")),
        n => Err(format!(
            "{n} {what}s are named \"{input}\"; pass the id instead ({})",
            matches
                .iter()
                .map(|m| id_of(m).to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// Resolve a folder by breadcrumb path or label among the MANUAL
/// folders. Never creates one.
fn resolve_group(vault: &VaultStore, input: &str) -> Result<Uuid, String> {
    let groups = vault.list_groups().map_err(|e| e.to_string())?;
    // A path is exact; a bare label can name several folders, and the
    // first one found would put the host (and what it inherits) in the
    // wrong one.
    let manual = || groups.iter().filter(|g| g.cloud_query.is_none());
    if !manual().any(|g| Group::path_of(&groups, g.id) == input.trim()) {
        let same_label: Vec<String> = manual()
            .filter(|g| g.label == input.trim())
            .map(|g| Group::path_of(&groups, g.id))
            .collect();
        if same_label.len() > 1 {
            return Err(format!(
                "{} folders are named \"{}\"; pass the path instead ({})",
                same_label.len(),
                input.trim(),
                same_label.join(", ")
            ));
        }
    }
    Group::resolve_path_or_label(&groups, input, &HashSet::new()).ok_or_else(|| {
        let mut paths: Vec<String> = groups
            .iter()
            .filter(|g| g.cloud_query.is_none())
            .map(|g| Group::path_of(&groups, g.id))
            .collect();
        paths.sort_unstable();
        paths.dedup();
        format!(
            "No folder \"{input}\". Folders are never created over MCP; existing: {}",
            if paths.is_empty() { "(none)".to_string() } else { paths.join(", ") }
        )
    })
}

/// Apply the call's fields to `conn`. Returns the password tri-state
/// for `save_connection` (`None` keep, `Some("")` clear, `Some(pw)`).
fn apply_fields(
    vault: &VaultStore,
    conn: &mut Connection,
    params: Option<&Value>,
) -> Result<Option<String>, String> {
    if let Field::Set(label) = str_field(params, "label")? {
        if label.is_empty() {
            return Err("Parameter label must not be empty".to_string());
        }
        conn.label = label;
    }
    if let Field::Set(hostname) = str_field(params, "hostname")? {
        conn.hostname = host_only(&hostname)?;
    }
    if let Some(port) = port_field(params)? {
        conn.port = port;
    }
    match str_field(params, "username")? {
        Field::Absent => {}
        Field::Clear => conn.username = None,
        Field::Set(u) => conn.username = (!u.is_empty()).then_some(u),
    }
    if let Field::Set(m) = str_field(params, "auth_method")? {
        conn.auth_method = parse_auth_method(&m)?;
    }
    match str_field(params, "notes")? {
        Field::Absent => {}
        Field::Clear => conn.notes = None,
        Field::Set(n) => conn.notes = (!n.is_empty()).then_some(n),
    }
    match list_field(params, "tags")? {
        Field::Absent => {}
        Field::Clear => conn.tags.clear(),
        Field::Set(tags) => {
            conn.tags = tags.into_iter().filter(|t| !t.is_empty()).collect();
        }
    }
    if let Some(on) = bool_field(params, "mcp_enabled")? {
        conn.mcp_enabled = on;
    }
    match str_field(params, "group")? {
        Field::Absent => {}
        Field::Clear => conn.group_id = None,
        Field::Set(g) if g.is_empty() => conn.group_id = None,
        Field::Set(g) => conn.group_id = Some(resolve_group(vault, &g)?),
    }
    match str_field(params, "key")? {
        Field::Absent => {}
        Field::Clear => conn.key_id = None,
        Field::Set(k) if k.is_empty() => conn.key_id = None,
        Field::Set(k) => {
            let keys = vault.list_keys().map_err(|e| e.to_string())?;
            conn.key_id = Some(resolve_named("key", &k, &keys, |x| x.id, |x| x.label.as_str())?);
        }
    }
    match str_field(params, "identity")? {
        Field::Absent => {}
        Field::Clear => conn.identity_id = None,
        Field::Set(i) if i.is_empty() => conn.identity_id = None,
        Field::Set(i) => {
            let identities = vault.list_identities().map_err(|e| e.to_string())?;
            conn.identity_id = Some(resolve_named(
                "identity",
                &i,
                &identities,
                |x| x.id,
                |x| x.label.as_str(),
            )?);
        }
    }
    match list_field(params, "jump_chain")? {
        Field::Absent => {}
        Field::Clear => conn.jump_chain.clear(),
        Field::Set(hops) => {
            let all = vault.list_connections().map_err(|e| e.to_string())?;
            let mut chain = Vec::with_capacity(hops.len());
            for hop in hops.iter().filter(|h| !h.is_empty()) {
                let id = resolve_named("host", hop, &all, |x| x.id, |x| x.label.as_str())?;
                if id == conn.id {
                    return Err("A host cannot be its own jump hop".to_string());
                }
                if !chain.contains(&id) {
                    chain.push(id);
                }
            }
            conn.jump_chain = chain;
        }
    }
    for refused in ["proxy", "proxy_identity", "proxy_identity_id", "proxy_command"] {
        if params.and_then(|p| p.get(refused)).is_some() {
            return Err(
                "Proxies are not set over MCP (a command proxy is a local process only the user \
                 may approve); edit the host in the app."
                    .to_string(),
            );
        }
    }
    Ok(match raw_str_field(params, "password")? {
        Field::Absent => None,
        Field::Clear => Some(String::new()),
        Field::Set(pw) => Some(pw),
    })
}

/// The hostname the call gave, as the host it must be: the editor's host
/// grammar (`SshTarget::from_host_field`), with nothing beside the host.
/// Where the editor splits `user@host:port` for a person, a caller that
/// is not one is told where each part goes.
fn host_only(input: &str) -> Result<String, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("Parameter hostname must not be empty".to_string());
    }
    let Some(target) = oryxis_core::ssh_target::SshTarget::from_host_field(input) else {
        return Err(format!("\"{input}\" is not a host name or address"));
    };
    if target.username.is_some() || target.password.is_some() || target.port.is_some() {
        return Err(format!(
            "\"{input}\" is more than a host: pass the user in username and the port in port"
        ));
    }
    if target.host.starts_with('-') {
        return Err(format!("\"{input}\" is not a host name or address"));
    }
    Ok(target.host)
}

/// The address a host dials, as compared by the guard: DNS names are
/// case-insensitive.
fn endpoint(conn: &Connection) -> (String, u16) {
    (conn.hostname.to_ascii_lowercase(), conn.port)
}

/// Where a dial of `conn` lands: its address, its jump chain and the
/// proxy it ends up with once its folders are applied (compared by its
/// serialized form; `ProxyConfig` keeps its secret out of it).
fn route(
    vault: &VaultStore,
    conn: &Connection,
    groups: &[Group],
    identities: &[oryxis_core::models::Identity],
) -> ((String, u16), Vec<Uuid>, Option<String>) {
    let mut c = conn.clone();
    vault.apply_effective(&mut c, groups, identities);
    let proxy = c.proxy.as_ref().and_then(|p| serde_json::to_string(p).ok());
    (endpoint(conn), conn.jump_chain.clone(), proxy)
}

/// The identity a host authenticates with once its folders are applied:
/// its own, else the nearest folder default (the dial's own resolution,
/// `VaultStore::apply_effective`).
fn effective_identity(
    vault: &VaultStore,
    conn: &Connection,
    groups: &[Group],
    identities: &[oryxis_core::models::Identity],
) -> Option<Uuid> {
    let mut c = conn.clone();
    vault.apply_effective(&mut c, groups, identities);
    c.identity_id
}

/// The rule in the module doc: a stored secret never goes to an address
/// the user did not give it to. `original` is the row before an
/// `update_host` (`None` for `create_host`); `password` is what the call
/// does to the host's own password (`None` = keeps the stored one).
fn credential_guard(
    vault: &VaultStore,
    original: Option<&Connection>,
    conn: &Connection,
    password: Option<&str>,
) -> Result<(), String> {
    let all = vault.list_connections().map_err(|e| e.to_string())?;
    let groups = vault.list_groups().map_err(|e| e.to_string())?;
    let identities = vault.list_identities().map_err(|e| e.to_string())?;
    let here = endpoint(conn);
    let addr = oryxis_core::net::host_port(&conn.hostname, conn.port);
    // The address is only half of where a dial lands: the same private
    // address through another bastion (or another folder's proxy) is
    // another server.
    let way = route(vault, conn, &groups, &identities);
    let moved = original.is_none_or(|o| route(vault, o, &groups, &identities) != way);
    // A host that already dials this address keeps doing so; a NEW way
    // there (a create, a move) must not reach what the user excluded.
    if moved
        && all
            .iter()
            .any(|h| h.id != conn.id && !h.mcp_enabled && endpoint(h) == here)
    {
        return Err(format!(
            "{addr} belongs to a host kept out of MCP; it is not reachable over MCP under \
             another entry either."
        ));
    }
    let stored_password = match original {
        Some(o) => vault.connection_has_password(&o.id).map_err(|e| e.to_string())?,
        None => false,
    };
    if let Some(o) = original.filter(|_| moved) {
        if password.is_none() && stored_password {
            return Err(format!(
                "\"{}\" stores a password, which never follows a host to a new address or route \
                 over MCP. Pass the password for {addr} in this call (or null to clear it), or \
                 move the host in the app.",
                o.label
            ));
        }
        if vault
            .get_connection_totp_secret(&o.id)
            .map_err(|e| e.to_string())?
            .is_some()
        {
            return Err(format!(
                "\"{}\" stores a TOTP secret, which never follows a host to a new address or \
                 route over MCP. Move the host in the app.",
                o.label
            ));
        }
        // A host that is a hop moves every host behind it (a hop's own
        // chain is expanded too, so behind it reaches through hops of
        // hops): one of them storing a secret is that secret moving.
        let identity_passwords = vault.list_identity_ids_with_password().map_err(|e| e.to_string())?;
        let mut behind: Vec<Uuid> = Vec::new();
        let mut frontier = vec![o.id];
        while let Some(hop) = frontier.pop() {
            for h in all.iter().filter(|h| h.jump_chain.contains(&hop) && h.id != o.id) {
                if !behind.contains(&h.id) {
                    behind.push(h.id);
                    frontier.push(h.id);
                }
            }
        }
        let mut carrying: Vec<&str> = Vec::new();
        for h in all.iter().filter(|h| behind.contains(&h.id)) {
            let secret = vault.connection_has_password(&h.id).map_err(|e| e.to_string())?
                || vault.get_connection_totp_secret(&h.id).map_err(|e| e.to_string())?.is_some()
                || effective_identity(vault, h, &groups, &identities)
                    .is_some_and(|i| identity_passwords.contains(&i));
            if secret {
                carrying.push(h.label.as_str());
            }
        }
        if !carrying.is_empty() {
            return Err(format!(
                "{} host(s) route through \"{}\" and store a password or a TOTP secret; moving \
                 it moves them, which never happens over MCP. Edit the bastion in the app.",
                carrying.len(),
                o.label
            ));
        }
    }
    // A host with its own password never sends its identity's: the own
    // one wins the dial (`resolve_credentials`).
    let own_password = match password {
        Some(p) => !p.is_empty(),
        None => stored_password,
    };
    if own_password {
        return Ok(());
    }
    let with_password = vault.list_identity_ids_with_password().map_err(|e| e.to_string())?;
    let Some(identity) = effective_identity(vault, conn, &groups, &identities) else {
        return Ok(());
    };
    if !with_password.contains(&identity) {
        return Ok(());
    }
    // Whoever already dials this address with this identity vouches for
    // it: the row as it was (the user set it up), or another MCP host.
    let vouched = original
        .filter(|o| !moved && effective_identity(vault, o, &groups, &identities) == Some(identity))
        .is_some()
        || all.iter().any(|h| {
            h.id != conn.id
                && h.mcp_enabled
                && h.protocol == ConnectionProtocol::Ssh
                && endpoint(h) == here
                && route(vault, h, &groups, &identities) == way
                && effective_identity(vault, h, &groups, &identities) == Some(identity)
        });
    if vouched {
        return Ok(());
    }
    let label = identities
        .iter()
        .find(|i| i.id == identity)
        .map(|i| i.label.as_str())
        .unwrap_or("?");
    Err(format!(
        "The identity \"{label}\" stores a password and no MCP host at {addr} uses it, so it is \
         not attached to {addr} over MCP (directly or through the folder's default): a stored \
         password only goes to an address the user gave it to. Attach it in the app, or give \
         this host its own password."
    ))
}

fn finish(vault: &VaultStore, conn: &Connection, password: Option<&str>) -> Result<Value, String> {
    vault
        .save_connection(conn, password)
        .map_err(|e| e.to_string())?;
    if let Err(e) = oryxis_vault::change_notice::announce("oryxis-mcp") {
        tracing::warn!(error = %e, "could not announce the vault change");
    }
    // A host written with MCP off is saved, and `get_host` (which sees
    // MCP hosts only) would answer "not found" for it: a client reading
    // that as a failure would write it again.
    if !conn.mcp_enabled {
        return Ok(json!({
            "id": conn.id.to_string(),
            "label": conn.label,
            "mcp_enabled": false,
            "saved": true,
            "note": "Saved with MCP off: the host is no longer visible to MCP tools.",
        }));
    }
    handle_get_host(vault, Some(&json!({ "id": conn.id.to_string() })))
}

/// `create_host`: a new SSH host from `label` + `hostname` and whatever
/// else the call carries.
pub fn handle_create_host(server: &Server, params: Option<&Value>) -> Result<Value, String> {
    // Into the one vault in scope; with several, the call's `vault`.
    let served = server.one_in_scope(params)?;
    let vault = served.vault();
    gate(&vault)?;
    let Field::Set(label) = str_field(params, "label")? else {
        return Err("Missing required parameter: label".to_string());
    };
    let Field::Set(hostname) = str_field(params, "hostname")? else {
        return Err("Missing required parameter: hostname".to_string());
    };
    if label.is_empty() {
        return Err("label and hostname must not be empty".to_string());
    }
    let mut conn = Connection::new(label, host_only(&hostname)?);
    let password = apply_fields(&vault, &mut conn, params)?;
    credential_guard(&vault, None, &conn, password.as_deref())?;
    conn.updated_at = chrono::Utc::now();
    tracing::info!(host = %conn.label, id = %conn.id, vault = %served.slug, "create_host");
    finish(&vault, &conn, password.as_deref()).map(|r| crate::server::tagged(r, &served.slug))
}

/// `update_host`: change the given fields of an MCP-visible SSH host;
/// every field not named keeps its value.
pub fn handle_update_host(server: &Server, params: Option<&Value>) -> Result<Value, String> {
    let id_str = params
        .and_then(|p| p.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter: id".to_string())?;
    let id = Uuid::parse_str(id_str).map_err(|_| "Invalid UUID".to_string())?;
    // The vault holding the host is the one written.
    let served = server.holding_host(params, id)?;
    let vault = served.vault();
    gate(&vault)?;
    let conns = vault.list_mcp_connections().map_err(|e| e.to_string())?;
    let mut conn = conns
        .into_iter()
        .find(|c| c.id == id)
        .ok_or_else(|| "Host not found or not MCP-enabled".to_string())?;
    if conn.protocol != ConnectionProtocol::Ssh {
        return Err("Only SSH hosts are edited over MCP".to_string());
    }
    let original = conn.clone();
    let password = apply_fields(&vault, &mut conn, params)?;
    credential_guard(&vault, Some(&original), &conn, password.as_deref())?;
    conn.updated_at = chrono::Utc::now();
    tracing::info!(host = %conn.label, id = %conn.id, vault = %served.slug, "update_host");
    finish(&vault, &conn, password.as_deref()).map(|r| crate::server::tagged(r, &served.slug))
}
