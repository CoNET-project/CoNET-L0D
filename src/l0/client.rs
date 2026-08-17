//! Overlay L0 client. Default is the MVP stub.
//!
//! When `[l0].enabled = true` and a peer has **user + route** public key files,
//! the daemon encrypts `conet_l0d_overlay_v1` to the peer user PGP, wraps
//! mailbox work `{ data, NoPush: true }` to B route PGP, then POSTs `{ "data" }`.
//! Do not POST plaintext JSON. Do not claim a live SI `p2p_stream_*` command.

use crate::config::ValidatedConfig;
use crate::error::L0dError;
use crate::l0::{envelope, frame, listen, pgp, post};
use crate::locator::{Locator, LocatorHost};
use sequoia_openpgp::Cert;
use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

const POST_QUEUE: usize = 32;
const LISTEN_QUEUE: usize = 32;
const LISTEN_RECONNECT_SECS: u64 = 3;

struct ArmoredCert(String);

impl fmt::Debug for ArmoredCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ArmoredCert(redacted)")
    }
}

struct SecretCert(Cert);

impl fmt::Debug for SecretCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretCert(redacted)")
    }
}

#[derive(Debug)]
struct PeerPgp {
    user: ArmoredCert,
    route: ArmoredCert,
}

struct PostJob {
    url: String,
    armor: String,
}

impl fmt::Debug for PostJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostJob")
            .field("url", &self.url)
            .field("armor_bytes", &self.armor.len())
            .finish()
    }
}

#[derive(Debug)]
pub struct PreparedPost {
    pub url: String,
    armor: String,
}

impl PreparedPost {
    pub fn armor_len(&self) -> usize {
        self.armor.len()
    }
}

pub struct L0Client {
    enabled: bool,
    seq: u64,
    pub noted_packets: u64,
    pub frames_ready: u64,
    pub posts_prepared: u64,
    pub posts_queued: u64,
    pub posts_dropped: u64,
    pub posts_refused: u64,
    pub inbound_ready: u64,
    pub tun_writes: u64,
    pub inbound_refused: u64,
    pub inbound_dropped: u64,
    routing_eoa: String,
    entries: Vec<String>,
    peers: HashMap<Ipv4Addr, PeerPgp>,
    post_tx: Option<mpsc::Sender<PostJob>>,
    user_secret: Option<SecretCert>,
    tun_tx: Option<mpsc::Sender<Vec<u8>>>,
    inbound_rx: Option<mpsc::Receiver<String>>,
}

impl fmt::Debug for L0Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("L0Client")
            .field("enabled", &self.enabled)
            .field("noted_packets", &self.noted_packets)
            .field("frames_ready", &self.frames_ready)
            .field("posts_prepared", &self.posts_prepared)
            .field("posts_queued", &self.posts_queued)
            .field("posts_dropped", &self.posts_dropped)
            .field("posts_refused", &self.posts_refused)
            .field("inbound_ready", &self.inbound_ready)
            .field("tun_writes", &self.tun_writes)
            .field("inbound_refused", &self.inbound_refused)
            .field("inbound_dropped", &self.inbound_dropped)
            .field("entries", &self.entries.len())
            .field("peers_with_pgp", &self.peers.len())
            .field("post_worker", &self.post_tx.is_some())
            .field("inbound_secret", &self.user_secret.is_some())
            .field("tun_writer", &self.tun_tx.is_some())
            .field("listen_worker", &self.inbound_rx.is_some())
            .finish()
    }
}

impl Default for L0Client {
    fn default() -> Self {
        Self::disabled()
    }
}

impl L0Client {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            seq: 0,
            noted_packets: 0,
            frames_ready: 0,
            posts_prepared: 0,
            posts_queued: 0,
            posts_dropped: 0,
            posts_refused: 0,
            inbound_ready: 0,
            tun_writes: 0,
            inbound_refused: 0,
            inbound_dropped: 0,
            routing_eoa: String::new(),
            entries: Vec::new(),
            peers: HashMap::new(),
            post_tx: None,
            user_secret: None,
            tun_tx: None,
            inbound_rx: None,
        }
    }

    pub fn from_config(cfg: &ValidatedConfig) -> Self {
        let routing_eoa = cfg
            .l0
            .routing_eoa
            .clone()
            .or_else(|| match &cfg.identity.host {
                LocatorHost::Eoa(eoa) => Some(eoa.clone()),
                LocatorHost::Tag(_) => None,
            })
            .unwrap_or_default();

        let mut peers = HashMap::new();
        for peer in &cfg.peers {
            if peers.contains_key(&peer.vip) {
                continue;
            }
            let (Some(user_path), Some(route_path)) =
                (peer.user_pgp_file.as_ref(), peer.route_pgp_file.as_ref())
            else {
                continue;
            };
            match load_peer_pgp(user_path, route_path) {
                Ok(keys) => {
                    peers.insert(peer.vip, keys);
                }
                Err(err) => tracing::warn!(
                    dest = %peer.vip,
                    error = %err,
                    "P1: peer OpenPGP public files were not loaded; POST stays refused for this vIP"
                ),
            }
        }

        let post_tx = if cfg.l0.enabled && !cfg.l0.entries.is_empty() {
            spawn_post_worker()
        } else {
            None
        };

        let user_secret = if cfg.l0.enabled {
            match cfg.l0.routing_key_file.as_ref() {
                Some(path) => match pgp::load_secret_cert(path) {
                    Ok(cert) => Some(SecretCert(cert)),
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            "P1: routing_key_file was not loaded; inbound write-back stays refused"
                        );
                        None
                    }
                },
                None => None,
            }
        } else {
            None
        };

        let inbound_rx = if cfg.l0.enabled
            && user_secret.is_some()
            && !cfg.l0.listen_entries.is_empty()
            && !routing_eoa.is_empty()
        {
            match cfg.l0.mailbox_route_pgp_file.as_ref() {
                Some(path) => match pgp::load_public_cert_armored(path) {
                    Ok(route) => spawn_listen_worker(
                        cfg.l0.listen_entries.clone(),
                        route,
                        routing_eoa.clone(),
                    ),
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            "P1: mailbox_route_pgp_file was not loaded; listen worker stays off"
                        );
                        None
                    }
                },
                None => None,
            }
        } else {
            None
        };

        Self {
            enabled: cfg.l0.enabled,
            seq: 0,
            noted_packets: 0,
            frames_ready: 0,
            posts_prepared: 0,
            posts_queued: 0,
            posts_dropped: 0,
            posts_refused: 0,
            inbound_ready: 0,
            tun_writes: 0,
            inbound_refused: 0,
            inbound_dropped: 0,
            routing_eoa,
            entries: cfg.l0.entries.clone(),
            peers,
            post_tx,
            user_secret,
            tun_tx: None,
            inbound_rx,
        }
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn attach_tun_writer(&mut self, tx: mpsc::Sender<Vec<u8>>) {
        self.tun_tx = Some(tx);
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn take_inbound_rx(&mut self) -> Option<mpsc::Receiver<String>> {
        self.inbound_rx.take()
    }

    /// Decrypt inbound user-PGP armor and queue raw IPv4 for TUN write-back.
    /// May be fed by the in-crate listen worker. Tests do not POST production SI.
    #[allow(dead_code)]
    pub fn apply_inbound_armor(&mut self, armor: &str) -> Result<usize, L0dError> {
        if !self.enabled {
            self.inbound_refused = self.inbound_refused.saturating_add(1);
            return Err(L0dError::L0(
                "[l0].enabled is false; inbound write-back refused".into(),
            ));
        }
        let Some(secret) = self.user_secret.as_ref() else {
            self.inbound_refused = self.inbound_refused.saturating_add(1);
            return Err(L0dError::L0(
                "routing_key_file OpenPGP secret is required for inbound write-back".into(),
            ));
        };
        match listen::inbound_ipv4_from_user_armor(armor, &secret.0) {
            Ok(ipv4) => {
                let n = ipv4.len();
                self.inbound_ready = self.inbound_ready.saturating_add(1);
                match &self.tun_tx {
                    Some(tx) => match tx.try_send(ipv4) {
                        Ok(()) => {
                            self.tun_writes = self.tun_writes.saturating_add(1);
                            tracing::info!(bytes = n, "P1 inbound IPv4 queued for TUN write-back");
                        }
                        Err(_) => {
                            self.inbound_dropped = self.inbound_dropped.saturating_add(1);
                            tracing::warn!(
                                dropped = self.inbound_dropped,
                                "P1 inbound TUN queue full; frame dropped"
                            );
                        }
                    },
                    None => tracing::info!(
                        bytes = n,
                        "P1 inbound IPv4 ready; TUN writer not attached"
                    ),
                }
                Ok(n)
            }
            Err(err) => {
                self.inbound_refused = self.inbound_refused.saturating_add(1);
                Err(err)
            }
        }
    }

    pub fn note_overlay_packet(
        &mut self,
        dest: Ipv4Addr,
        locator: Option<&Locator>,
        packet: &[u8],
    ) {
        self.noted_packets += 1;
        if !self.enabled {
            match locator {
                Some(loc) => tracing::debug!(
                    dest = %dest,
                    locator = %loc.display(),
                    "L0 stub: would encrypt overlay TCP to peer user PGP; [l0].enabled is false"
                ),
                None => tracing::debug!(
                    dest = %dest,
                    "L0 stub: dest vIP is not in the static peer table"
                ),
            }
            return;
        }

        let Some(loc) = locator else {
            tracing::debug!(
                dest = %dest,
                "P1: dest vIP is not in the static peer table"
            );
            return;
        };

        self.seq = self.seq.saturating_add(1);
        let framed = frame::encode(self.seq, packet);
        match self.prepare_overlay_post(dest, packet, self.seq) {
            Ok(prepared) => {
                self.frames_ready = self.frames_ready.saturating_add(1);
                self.posts_prepared = self.posts_prepared.saturating_add(1);
                self.enqueue_post(prepared, dest, loc, framed.len());
            }
            Err(err) => {
                self.posts_refused = self.posts_refused.saturating_add(1);
                tracing::warn!(
                    dest = %dest,
                    locator = %loc.display(),
                    seq = self.seq,
                    frame_bytes = framed.len(),
                    error = %err,
                    "P1 overlay POST refused; plaintext was not sent"
                );
            }
        }
    }

    fn prepare_overlay_post(
        &self,
        dest: Ipv4Addr,
        packet: &[u8],
        seq: u64,
    ) -> Result<PreparedPost, L0dError> {
        let keys = self.peers.get(&dest).ok_or_else(|| {
            L0dError::L0(
                "peer user+route PGP public files are required; refusing POST".into(),
            )
        })?;
        let entry = self.entries.first().ok_or_else(|| {
            L0dError::L0("l0.entries is empty; refusing POST".into())
        })?;
        let url = post::post_url(entry)?;
        let json = envelope::encode(&self.routing_eoa, seq, packet)?;
        let armor = pgp::wrap_overlay_for_post(&json, &keys.user.0, &keys.route.0)?;
        Ok(PreparedPost { url, armor })
    }

    fn enqueue_post(&mut self, prepared: PreparedPost, dest: Ipv4Addr, loc: &Locator, frame_bytes: usize) {
        let armor_bytes = prepared.armor_len();
        let Some(tx) = &self.post_tx else {
            tracing::info!(
                dest = %dest,
                locator = %loc.display(),
                seq = self.seq,
                armor_bytes,
                frame_bytes,
                "P1 overlay armor ready; POST worker not started (no tokio runtime)"
            );
            return;
        };
        match tx.try_send(PostJob {
            url: prepared.url,
            armor: prepared.armor,
        }) {
            Ok(()) => {
                self.posts_queued = self.posts_queued.saturating_add(1);
                tracing::info!(
                    dest = %dest,
                    locator = %loc.display(),
                    seq = self.seq,
                    armor_bytes,
                    frame_bytes,
                    queued = self.posts_queued,
                    "P1 overlay queued for POST /post"
                );
            }
            Err(_) => {
                self.posts_dropped = self.posts_dropped.saturating_add(1);
                tracing::warn!(
                    dest = %dest,
                    seq = self.seq,
                    dropped = self.posts_dropped,
                    "P1 overlay POST queue full; frame dropped (TUN not blocked)"
                );
            }
        }
    }
}

fn load_peer_pgp(
    user_path: &std::path::Path,
    route_path: &std::path::Path,
) -> Result<PeerPgp, L0dError> {
    let user = std::fs::read_to_string(user_path)?;
    let route = std::fs::read_to_string(route_path)?;
    if user.trim().is_empty() || route.trim().is_empty() {
        return Err(L0dError::L0("peer OpenPGP public file is empty".into()));
    }
    Ok(PeerPgp {
        user: ArmoredCert(user),
        route: ArmoredCert(route),
    })
}

fn spawn_listen_worker(
    entries: Vec<String>,
    mailbox_route: String,
    routing_eoa: String,
) -> Option<mpsc::Receiver<String>> {
    let handle = tokio::runtime::Handle::try_current().ok()?;
    let client = listen::listen_http_client().ok()?;
    let (tx, rx) = mpsc::channel::<String>(LISTEN_QUEUE);
    handle.spawn(async move {
        let mut last_failed: Option<String> = None;
        loop {
            let Some(entry) = listen::pick_listen_entry(&entries, last_failed.as_deref()) else {
                tracing::warn!("P1 listen: listen_entries empty; worker idle");
                tokio::time::sleep(Duration::from_secs(LISTEN_RECONNECT_SECS)).await;
                continue;
            };
            let ts = chrono::Utc::now().timestamp().max(0) as u64;
            match listen::prepare_listen_post(&routing_eoa, ts, &mailbox_route, entry) {
                Ok((url, armor)) => match listen::run_listen_once(&client, &url, &armor, &tx).await
                {
                    Ok(_) => {
                        last_failed = None;
                        tracing::info!("P1 listen SSE ended; reconnecting after idle");
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "P1 listen SSE failed");
                        last_failed = Some(entry.to_string());
                    }
                },
                Err(err) => {
                    tracing::warn!(error = %err, "P1 listen wrap refused");
                    last_failed = Some(entry.to_string());
                }
            }
            tokio::time::sleep(Duration::from_secs(LISTEN_RECONNECT_SECS)).await;
        }
    });
    Some(rx)
}

fn spawn_post_worker() -> Option<mpsc::Sender<PostJob>> {
    let handle = tokio::runtime::Handle::try_current().ok()?;
    let client = post::http_client().ok()?;
    let (tx, mut rx) = mpsc::channel::<PostJob>(POST_QUEUE);
    handle.spawn(async move {
        let client = Arc::new(client);
        while let Some(job) = rx.recv().await {
            match post::send(&client, &job.url, &job.armor).await {
                Ok(status) => tracing::info!(
                    status,
                    armor_bytes = job.armor.len(),
                    "P1 POST /post accepted"
                ),
                Err(err) => tracing::warn!(
                    error = %err,
                    armor_bytes = job.armor.len(),
                    "P1 POST /post failed"
                ),
            }
        }
    });
    Some(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l0::pgp::{decrypt_utf8, generate_test_cert, public_cert_armored};

    fn client_with_keys(user: &str, route: &str) -> L0Client {
        let mut peers = HashMap::new();
        peers.insert(
            Ipv4Addr::new(100, 64, 0, 6),
            PeerPgp {
                user: ArmoredCert(user.to_string()),
                route: ArmoredCert(route.to_string()),
            },
        );
        L0Client {
            enabled: true,
            seq: 0,
            noted_packets: 0,
            frames_ready: 0,
            posts_prepared: 0,
            posts_queued: 0,
            posts_dropped: 0,
            posts_refused: 0,
            inbound_ready: 0,
            tun_writes: 0,
            inbound_refused: 0,
            inbound_dropped: 0,
            routing_eoa: "0x1111111111111111111111111111111111111111".into(),
            entries: vec!["https://example.conet.network".into()],
            peers,
            post_tx: None,
            user_secret: None,
            tun_tx: None,
            inbound_rx: None,
        }
    }

    #[test]
    fn prepare_wraps_then_refuses_plaintext() {
        let user = generate_test_cert();
        let route = generate_test_cert();
        let user_pub = public_cert_armored(&user).unwrap();
        let route_pub = public_cert_armored(&route).unwrap();
        let client = client_with_keys(&user_pub, &route_pub);
        let prepared = client
            .prepare_overlay_post(Ipv4Addr::new(100, 64, 0, 6), b"\x45\x00pkt", 9)
            .unwrap();
        assert!(prepared.url.ends_with("/post"));
        assert!(pgp::is_pgp_message_armor(&prepared.armor));
        let work: serde_json::Value =
            serde_json::from_str(&decrypt_utf8(&prepared.armor, &route).unwrap()).unwrap();
        assert_eq!(work["NoPush"], true);
        let inner = work["data"].as_str().unwrap();
        let env_json = decrypt_utf8(inner, &user).unwrap();
        let (env, pkt) = envelope::decode(&env_json).unwrap();
        assert_eq!(env.seq, 9);
        assert_eq!(pkt, b"\x45\x00pkt");
        assert!(!env_json.contains("signMessage"));
    }

    #[test]
    fn refuse_without_peer_keys() {
        let client = L0Client {
            enabled: true,
            entries: vec!["https://example.conet.network".into()],
            routing_eoa: "0x1111111111111111111111111111111111111111".into(),
            ..L0Client::disabled()
        };
        let err = client
            .prepare_overlay_post(Ipv4Addr::new(100, 64, 0, 6), b"x", 1)
            .unwrap_err();
        assert!(err.to_string().contains("user+route"));
    }

    #[test]
    fn inbound_write_back_queues_ipv4() {
        let user = generate_test_cert();
        let user_pub = public_cert_armored(&user).unwrap();
        let pkt = b"\x45\x00inbound-ipv4-ok!!!";
        let json = envelope::encode("0x1111111111111111111111111111111111111111", 2, pkt).unwrap();
        let armor = pgp::encrypt_utf8(&json, &user_pub).unwrap();
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(4);
        let mut client = L0Client {
            enabled: true,
            user_secret: Some(SecretCert(user)),
            tun_tx: Some(tx),
            routing_eoa: "0x1111111111111111111111111111111111111111".into(),
            ..L0Client::disabled()
        };
        assert_eq!(client.apply_inbound_armor(&armor).unwrap(), pkt.len());
        assert_eq!(client.inbound_ready, 1);
        assert_eq!(client.tun_writes, 1);
        assert_eq!(rx.try_recv().unwrap(), pkt);
    }

    #[test]
    fn inbound_refused_when_disabled() {
        let mut client = L0Client::disabled();
        let err = client
            .apply_inbound_armor("-----BEGIN PGP MESSAGE-----\n\nxxxx\n-----END PGP MESSAGE-----\n")
            .unwrap_err();
        assert!(err.to_string().contains("enabled is false"));
        assert_eq!(client.inbound_refused, 1);
    }
}
