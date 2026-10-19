//! One QUIC listener for every vault's engine on this device.
//!
//! Every vault has its own device identity (`DeviceIdentity`, stored in
//! that vault), so with several vaults open there are several engines.
//! They share ONE listening port and its accept loop: a peer records one
//! address for this machine, a configured port is bound once, and the
//! firewall sees one listener. An incoming connection is served by the
//! engine (the [`Route`]) its first message names:
//!
//! - a `Hello` carries the SENDER's identity, which exactly one local
//!   vault has paired (a remote identity pairs with one vault per device,
//!   `PeerGuard`): that vault serves it. No protocol change: the sender
//!   needs to know nothing about this machine's vaults, so an older peer
//!   reaches every vault it paired.
//! - a `PairingRequest` goes to the vault hosting that code.
//!
//! Nothing matching goes to the first route, which answers as a lone
//! engine always did (an unknown peer gets `Bye`, a wrong code is
//! counted and refused). A route that sends the wrong vault's answer
//! cannot do harm either: the dialer checks that the `HelloAck` comes
//! from the identity it dialled, and refuses otherwise.

use std::sync::{Arc, Mutex};

use uuid::Uuid;

use crate::error::SyncError;
use crate::protocol::{SyncMessage, PROTOCOL_VERSION};
use crate::transport;

use super::manifest::active_peer_pubkey;
use super::session::{accept_first, serve_accepted, Route};
use super::SyncEvent;

/// The device's sync listener; engines attach to it (`SyncEngine::with_listener`).
/// Dropping the last handle closes the port.
pub struct SyncListener {
    endpoint: quinn::Endpoint,
    port: u16,
    routes: Arc<Mutex<Vec<Route>>>,
    shutdown: tokio::sync::broadcast::Sender<()>,
}

impl SyncListener {
    /// Bind the device's listener on `port`, or, with `port` 0, on
    /// `remembered` when it is free (a peer dials the address it
    /// recorded, #219) and else on any free port. A configured port that
    /// cannot be bound is an error. Must run inside a Tokio runtime.
    pub fn bind(port: u16, remembered: Option<u16>) -> Result<Arc<Self>, SyncError> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        // The certificate is a throwaway: clients do not verify it, the
        // session is authenticated by each side signing the TLS exporter
        // with its vault's identity (`Hello` / `HelloAck`).
        let cert_id = Uuid::new_v4();
        let endpoint = if port != 0 {
            transport::create_server_endpoint(&cert_id, port)?
        } else {
            match remembered.filter(|p| *p != 0) {
                Some(p) => match transport::create_server_endpoint(&cert_id, p) {
                    Ok(endpoint) => endpoint,
                    Err(e) => {
                        tracing::warn!(
                            "sync: the remembered listen port {p} is unavailable ({e}); taking a new one"
                        );
                        transport::create_server_endpoint(&cert_id, 0)?
                    }
                },
                None => transport::create_server_endpoint(&cert_id, 0)?,
            }
        };
        let port = endpoint.local_addr().map(|a| a.port()).unwrap_or(0);
        let routes: Arc<Mutex<Vec<Route>>> = Arc::new(Mutex::new(Vec::new()));
        let (shutdown, mut shutdown_rx) = tokio::sync::broadcast::channel(1);
        let accept_endpoint = endpoint.clone();
        let accept_routes = routes.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    incoming = accept_endpoint.accept() => {
                        let Some(incoming) = incoming else { break };
                        let routes = accept_routes.clone();
                        tokio::spawn(async move {
                            if let Err(e) = serve_shared(incoming, routes).await {
                                tracing::warn!("Incoming connection failed: {}", e);
                            }
                        });
                    }
                    _ = shutdown_rx.recv() => break,
                }
            }
        });
        tracing::info!("sync listener for every vault on port {port}");
        Ok(Arc::new(Self { endpoint, port, routes, shutdown }))
    }

    /// The bound port, the one every attached vault advertises.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Serve `route`'s vault (replacing an earlier route of the same
    /// identity).
    pub(super) fn attach(&self, route: Route) {
        if let Ok(mut routes) = self.routes.lock() {
            routes.retain(|r| r.identity.device_id != route.identity.device_id);
            routes.push(route);
        }
    }

    /// Stop serving the vault with identity `device_id`.
    pub(super) fn detach(&self, device_id: &Uuid) {
        if let Ok(mut routes) = self.routes.lock() {
            routes.retain(|r| r.identity.device_id != *device_id);
        }
    }
}

impl Drop for SyncListener {
    fn drop(&mut self) {
        let _ = self.shutdown.send(());
        self.endpoint.close(0u32.into(), b"sync listener closed");
    }
}

/// Serve one incoming connection on the shared listener: read its first
/// message, pick the route it names, hand it over.
async fn serve_shared(incoming: quinn::Incoming, routes: Arc<Mutex<Vec<Route>>>) -> Result<(), SyncError> {
    let accepted = accept_first(incoming).await?;
    let snapshot: Vec<Route> = routes.lock().map(|r| r.clone()).unwrap_or_default();
    if snapshot.is_empty() {
        return Err(SyncError::Protocol("No vault is syncing on this device".into()));
    }
    let route = pick_route(&snapshot, &accepted.first);
    // A peer on another protocol version is refused by the route it
    // reached, which reports it; every other vault hears about it too,
    // since an old peer cannot be told apart by vault before it upgrades.
    if let SyncMessage::Hello { device_id, protocol_version, .. } = &accepted.first {
        if *protocol_version != PROTOCOL_VERSION {
            for other in snapshot.iter().filter(|r| r.identity.device_id != route.identity.device_id) {
                let _ = other.event_tx.send(SyncEvent::VersionMismatch {
                    peer_id: *device_id,
                    peer_version: *protocol_version,
                    local_version: PROTOCOL_VERSION,
                });
            }
        }
    }
    serve_accepted(accepted, route).await
}

/// The route a first message names (see the module docs).
fn pick_route<'a>(routes: &'a [Route], first: &SyncMessage) -> &'a Route {
    match first {
        SyncMessage::Hello { device_id, .. } => {
            let mut matches = routes
                .iter()
                .filter(|r| active_peer_pubkey(&r.vault, device_id).ok().flatten().is_some());
            let chosen = matches.next();
            if chosen.is_some() && matches.next().is_some() {
                tracing::warn!(
                    peer = %device_id,
                    "sync: a peer is paired with more than one vault here; the first attached serves it"
                );
            }
            chosen.unwrap_or(&routes[0])
        }
        SyncMessage::PairingRequest { pairing_code, .. } => {
            let hosting = |r: &&Route| {
                r.hosting_pairing
                    .lock()
                    .ok()
                    .and_then(|s| s.as_ref().filter(|p| p.expires_at > std::time::Instant::now()).map(|p| p.code.clone()))
            };
            routes
                .iter()
                .find(|r| {
                    hosting(r).is_some_and(|code| {
                        crate::crypto::constant_time_eq(code.as_bytes(), pairing_code.as_bytes())
                    })
                })
                // A wrong code is counted where a code is hosted.
                .or_else(|| routes.iter().find(|r| hosting(r).is_some()))
                .unwrap_or(&routes[0])
        }
        _ => &routes[0],
    }
}
