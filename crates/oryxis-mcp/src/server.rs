use std::sync::{Arc, Mutex, MutexGuard};

use serde_json::{json, Value};
use tokio::sync::watch;

use oryxis_vault::VaultStore;

use crate::handlers;
use crate::pool::Pool;
use crate::protocol::JsonRpcResponse;
use crate::tools;

/// Protocol revisions this server implements. Tools-only over stdio is
/// wire-identical across all three; listing them lets version
/// negotiation echo whatever the client asked for instead of forcing a
/// downgrade to the oldest revision.
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2024-11-05", "2025-03-26", "2025-06-18"];

/// Version negotiation per the MCP spec: echo the client's requested
/// version when we support it, otherwise answer with the latest one we
/// do (the client then decides whether to proceed or disconnect).
fn negotiate_protocol_version(params: Option<&Value>) -> &'static str {
    let requested = params
        .and_then(|p| p.get("protocolVersion"))
        .and_then(|v| v.as_str());
    SUPPORTED_PROTOCOL_VERSIONS
        .iter()
        .find(|v| Some(**v) == requested)
        .copied()
        .unwrap_or(SUPPORTED_PROTOCOL_VERSIONS[SUPPORTED_PROTOCOL_VERSIONS.len() - 1])
}

/// One vault this server serves: its unlocked store, its connection
/// pool and the host keys its dials refused. Every vault keeps its own:
/// a host id may exist in two vaults (an import keeps ids), and a key is
/// pinned into the vault whose dial refused it.
pub struct Served {
    /// The registry id (`oryxis_vault::device::VaultEntry::id`).
    pub id: uuid::Uuid,
    /// What the `vault` field of every answer and the `vault` parameter
    /// name it by.
    pub slug: String,
    /// Its name, for `list_vaults`.
    pub label: String,
    vault: Mutex<VaultStore>,
    pub pool: Pool,
    /// Host keys this vault's strict dials refused, for `accept_host_key`.
    pub refusals: Arc<crate::hostkey::RefusalLog>,
}

impl Served {
    pub fn new(id: uuid::Uuid, slug: String, label: String, vault: VaultStore) -> Self {
        Self {
            id,
            slug,
            label,
            vault: Mutex::new(vault),
            pool: Pool::new(),
            refusals: Arc::new(crate::hostkey::RefusalLog::default()),
        }
    }

    /// The vault, for one synchronous read. A poisoned lock is
    /// recovered rather than propagated: a panic in one request must
    /// not turn every later one into an error.
    pub fn vault(&self) -> MutexGuard<'_, VaultStore> {
        match self.vault.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        }
    }

    /// Its own `mcp_server_enabled`, read per call so the toggle in
    /// Settings takes effect on the next request without a restart.
    pub fn enabled(&self) -> bool {
        self.vault()
            .get_setting("mcp_server_enabled")
            .ok()
            .flatten()
            .is_some_and(|v| v == "true")
    }
}

/// `value` marked with the vault it came from: an object gains `vault`,
/// an array has each of its objects marked.
pub fn tagged(value: Value, slug: &str) -> Value {
    match value {
        Value::Object(mut map) => {
            map.insert("vault".into(), json!(slug));
            Value::Object(map)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(|v| tagged(v, slug)).collect()),
        other => other,
    }
}

/// What every request shares: the vaults served. Requests run
/// concurrently (one task each, see `stdio`), so each vault sits behind
/// a mutex; its reads are short and synchronous and no handler holds
/// the guard across an await, which is what keeps a slow dial from
/// blocking a `ping`.
pub struct Server {
    vaults: Vec<Served>,
}

impl Server {
    /// A server for one vault (the first: what a single-vault install
    /// has always been).
    #[cfg(test)]
    pub fn new(vault: VaultStore) -> Arc<Self> {
        Self::with_vaults(vec![Served::new(
            oryxis_vault::device::FIRST_VAULT_ID,
            "personal".into(),
            "Personal".into(),
            vault,
        )])
    }

    /// A server for `vaults`, in registry order.
    pub fn with_vaults(vaults: Vec<Served>) -> Arc<Self> {
        Arc::new(Self { vaults })
    }

    /// The first vault's store (tests of the single-vault shape).
    #[cfg(test)]
    pub fn vault(&self) -> MutexGuard<'_, VaultStore> {
        self.vaults[0].vault()
    }

    /// The first vault's refusals (tests of the single-vault shape).
    #[cfg(test)]
    pub fn refusals(&self) -> Arc<crate::hostkey::RefusalLog> {
        Arc::clone(&self.vaults[0].refusals)
    }

    /// Every vault served.
    pub fn served(&self) -> &[Served] {
        &self.vaults
    }

    /// The vaults a call may reach: those with MCP on, narrowed to the
    /// one its `vault` parameter names.
    pub fn in_scope(&self, params: Option<&Value>) -> Result<Vec<&Served>, String> {
        let named = params.and_then(|p| p.get("vault")).and_then(|v| v.as_str()).map(str::trim);
        let enabled: Vec<&Served> = self.vaults.iter().filter(|v| v.enabled()).collect();
        match named.filter(|n| !n.is_empty()) {
            None => Ok(enabled),
            Some(slug) => match enabled.into_iter().find(|v| v.slug == slug) {
                Some(v) => Ok(vec![v]),
                None => Err(format!(
                    "No vault \"{slug}\" is served with MCP on; served: {}.",
                    self.slugs_with_mcp_on()
                )),
            },
        }
    }

    /// The slugs of the vaults with MCP on, for error texts.
    fn slugs_with_mcp_on(&self) -> String {
        let slugs: Vec<&str> = self.vaults.iter().filter(|v| v.enabled()).map(|v| v.slug.as_str()).collect();
        if slugs.is_empty() { "none".into() } else { slugs.join(", ") }
    }

    /// The vault holding MCP host `id`, among those in scope. A host
    /// two vaults hold needs the call's `vault`.
    pub fn holding_host(&self, params: Option<&Value>, id: uuid::Uuid) -> Result<&Served, String> {
        let holding: Vec<&Served> = self
            .in_scope(params)?
            .into_iter()
            .filter(|v| v.vault().list_mcp_connections().is_ok_and(|c| c.iter().any(|c| c.id == id)))
            .collect();
        match holding.as_slice() {
            [one] => Ok(one),
            [] => Err("Host not found or not MCP-enabled".to_string()),
            several => Err(format!(
                "Host {id} is in more than one vault ({}); pass `vault`.",
                several.iter().map(|v| v.slug.as_str()).collect::<Vec<_>>().join(", ")
            )),
        }
    }

    /// The one vault a call that names no host writes into: the only
    /// one in scope, else the one its `vault` names.
    pub fn one_in_scope(&self, params: Option<&Value>) -> Result<&Served, String> {
        let scope = self.in_scope(params)?;
        match scope.as_slice() {
            [one] => Ok(one),
            [] => Err("No vault is served with MCP on.".to_string()),
            several => Err(format!(
                "Several vaults are served ({}); pass `vault` to say which one.",
                several.iter().map(|v| v.slug.as_str()).collect::<Vec<_>>().join(", ")
            )),
        }
    }

    /// Close idle pooled connections in every vault.
    pub fn sweep_idle(&self) {
        for v in &self.vaults {
            v.pool.sweep_idle();
        }
    }

    /// Close pooled connections before the process ends.
    pub async fn shutdown(&self) {
        for v in &self.vaults {
            v.pool.shutdown().await;
        }
    }

    /// A list tool over every vault in scope, each item marked.
    fn listed(
        &self,
        params: Option<&Value>,
        list: impl Fn(&VaultStore) -> Result<Value, String>,
    ) -> Result<Value, String> {
        let mut out: Vec<Value> = Vec::new();
        for v in self.in_scope(params)? {
            if let Value::Array(items) = tagged(list(&v.vault())?, &v.slug) {
                out.extend(items);
            }
        }
        Ok(Value::Array(out))
    }

    /// `list_vaults`: the served vaults with MCP on (one switched off is
    /// not exposed, its name included), and whether host writes are on.
    fn list_vaults(&self) -> Value {
        Value::Array(
            self.vaults
                .iter()
                .filter(|v| v.enabled())
                .map(|v| {
                    let writes = v
                        .vault()
                        .get_setting(crate::writes::ALLOW_WRITES_SETTING)
                        .ok()
                        .flatten()
                        .is_some_and(|w| w == "true");
                    json!({
                        "vault": v.slug,
                        "id": v.id.to_string(),
                        "label": v.label,
                        "writes_enabled": writes,
                    })
                })
                .collect(),
        )
    }

    pub async fn handle_request(
        &self,
        method: &str,
        id: Value,
        params: Option<&Value>,
        cancel: watch::Receiver<bool>,
    ) -> JsonRpcResponse {
        match method {
            "initialize" => JsonRpcResponse::success(
                id,
                json!({
                    "protocolVersion": negotiate_protocol_version(params),
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "oryxis-mcp",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                }),
            ),

            // Mandatory in every MCP revision: reply with an empty result so
            // health checks don't read a -32601 as a dead server.
            "ping" => JsonRpcResponse::success(id, json!({})),

            "tools/list" => {
                let tools = tools::tool_definitions();
                JsonRpcResponse::success(id, json!({ "tools": tools }))
            }

            "tools/call" => {
                let tool_name = params
                    .and_then(|p| p.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let arguments = params.and_then(|p| p.get("arguments"));

                // Check if MCP is enabled, per vault, read per call so the
                // toggle in Settings takes effect on the next request
                // without a restart of the client. Every vault off is the
                // whole server off.
                if !self.vaults.iter().any(Served::enabled) {
                    return JsonRpcResponse::success(
                        id,
                        json!({
                            "content": [{
                                "type": "text",
                                "text": "MCP server is disabled. Enable it in Oryxis Settings > Security."
                            }],
                            "isError": true
                        }),
                    );
                }

                let host_id = || -> Result<uuid::Uuid, String> {
                    let id_str = arguments
                        .and_then(|p| p.get("id"))
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "Missing required parameter: id".to_string())?;
                    uuid::Uuid::parse_str(id_str).map_err(|_| "Invalid UUID".to_string())
                };
                let result = match tool_name {
                    "list_vaults" => Ok(self.list_vaults()),
                    "list_hosts" => self.listed(arguments, |v| handlers::handle_list_hosts(v, arguments)),
                    "get_host" => host_id().and_then(|id| {
                        let v = self.holding_host(arguments, id)?;
                        handlers::handle_get_host(&v.vault(), arguments).map(|r| tagged(r, &v.slug))
                    }),
                    "list_groups" => self.listed(arguments, |v| Ok(handlers::handle_list_groups(v).unwrap_or(json!([])))),
                    "list_keys" => self.listed(arguments, |v| Ok(handlers::handle_list_keys(v).unwrap_or(json!([])))),
                    "ssh_execute" => handlers::handle_ssh_execute(self, arguments, cancel).await,
                    "accept_host_key" => crate::hostkey::handle_accept_host_key(self, arguments),
                    "create_host" => crate::writes::handle_create_host(self, arguments),
                    "update_host" => crate::writes::handle_update_host(self, arguments),
                    _ => Err(format!("Unknown tool: {}", tool_name)),
                };

                match result {
                    Ok(data) => {
                        let text = serde_json::to_string_pretty(&data).unwrap_or_default();
                        JsonRpcResponse::success(
                            id,
                            json!({
                                "content": [{
                                    "type": "text",
                                    "text": text
                                }]
                            }),
                        )
                    }
                    Err(e) => JsonRpcResponse::success(
                        id,
                        json!({
                            "content": [{
                                "type": "text",
                                "text": e
                            }],
                            "isError": true
                        }),
                    ),
                }
            }

            _ => JsonRpcResponse::error(id, -32601, format!("Method not found: {}", method)),
        }
    }
}
