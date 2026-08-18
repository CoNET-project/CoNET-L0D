//! Overlay L0 client. Default is the MVP stub.
//!
//! Data plane prefers **application duplex** (AES-256-GCM on two owned Chat
//! SSEs). Offer rides the long-lived channel SSE; accept / reject / frames
//! ride the session listen SSE. Until `duplex_accept`, fallback is
//! `conet_l0d_overlay_v1` user-PGP gossip. HTTP `/post` is still `{ "data" }`
//! only. SI does not implement `duplex_*`. Do not claim live `p2p_stream_*`.

use crate::config::ValidatedConfig;
use crate::error::L0dError;
use crate::l0::aes;
use crate::l0::eip191::EthSecret;
use crate::l0::{duplex, eip191, envelope, frame, listen, pgp, post};
use crate::locator::{Locator, LocatorHost};
use crate::packet::overlay_channel_port;
use sequoia_openpgp::Cert;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, Semaphore};

const POST_QUEUE: usize = 2048;
// 32 in-flight POSTs each walking 3 entries × 12s starves SI /post (listen headers never arrive).
const POST_CONCURRENCY: usize = 4;
const LISTEN_QUEUE: usize = 512;
const LISTEN_RECONNECT_SECS: u64 = 3;
const BATCH_MAX_PACKETS: usize = 16;
const BATCH_MAX_BYTES: usize = 12 * 1024;

#[derive(Clone)]
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

#[derive(Debug, Clone)]
struct PeerPgp {
    user: ArmoredCert,
    route: ArmoredCert,
}

struct PendingOverlay {
    dest: Ipv4Addr,
    port: u16,
    loc: Locator,
    packets: Vec<Vec<u8>>,
    bytes: usize,
}

struct PostJob {
    armor: String,
}

#[derive(Clone)]
struct ChannelWire {
    eoa: String,
    #[allow(dead_code)]
    route_pgp: String,
    eth: EthSecret,
    #[allow(dead_code)]
    listen_entries: Vec<String>,
    /// Own session-listen user PGP (channel EOA in crate MVP).
    user_pub: String,
}

#[derive(Clone)]
struct DuplexSession {
    session_id: String,
    key: Option<[u8; aes::KEY_LEN]>,
    dest: Ipv4Addr,
    port: u16,
    /// Own channel Chat listen is the session listen SSE (crate MVP).
    #[allow(dead_code)]
    guest_up: bool,
    /// Peer app sent `duplex_accept` with matching key.
    peer_attached: bool,
    rejected: bool,
    #[allow(dead_code)]
    host_eoa: String,
    /// Peer's session-listen user PGP (from accept, or offer for the initiator).
    peer_listen_user_pgp: Option<String>,
}

impl fmt::Debug for PostJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostJob")
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
    pub     inbound_dropped: u64,
    routing_eoa: String,
    entries: Vec<String>,
    peers: HashMap<(Ipv4Addr, u16), PeerPgp>,
    channel_eoa: HashMap<u16, String>,
    known_ports: HashSet<u16>,
    post_tx: Option<mpsc::Sender<PostJob>>,
    user_secrets: Vec<SecretCert>,
    tun_tx: Option<mpsc::Sender<Vec<u8>>>,
    inbound_rx: Option<mpsc::Receiver<String>>,
    pending: Option<PendingOverlay>,
    channel_wire: HashMap<u16, ChannelWire>,
    duplex: Arc<Mutex<HashMap<(Ipv4Addr, u16), DuplexSession>>>,
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
            .field("inbound_secret", &self.user_secrets.len())
            .field("tun_writer", &self.tun_tx.is_some())
            .field("listen_worker", &self.inbound_rx.is_some())
            .field("listen_channels", &self.channel_eoa.len())
            .field(
                "pending_packets",
                &self.pending.as_ref().map(|p| p.packets.len()),
            )
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
            channel_eoa: HashMap::new(),
            known_ports: HashSet::new(),
            post_tx: None,
            user_secrets: Vec::new(),
            tun_tx: None,
            inbound_rx: None,
            pending: None,
            channel_wire: HashMap::new(),
            duplex: Arc::new(Mutex::new(HashMap::new())),
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

        let known_ports = cfg.overlay_ports();
        let mut channel_eoa = HashMap::new();
        if cfg.l0.channels.is_empty() {
            for port in &known_ports {
                if !routing_eoa.is_empty() {
                    channel_eoa.insert(*port, routing_eoa.clone());
                }
            }
        } else {
            for ch in &cfg.l0.channels {
                for port in &ch.ports {
                    channel_eoa.insert(*port, ch.routing_eoa.clone());
                }
            }
        }

        let mut peers = HashMap::new();
        for peer in &cfg.peers {
            let (Some(user_path), Some(route_path)) =
                (peer.user_pgp_file.as_ref(), peer.route_pgp_file.as_ref())
            else {
                continue;
            };
            match load_peer_pgp(user_path, route_path) {
                Ok(keys) => {
                    for port in peer.tcp_ports.iter().chain(peer.udp_ports.iter()) {
                        peers.insert((peer.vip, *port), keys.clone());
                    }
                }
                Err(err) => tracing::warn!(
                    dest = %peer.vip,
                    error = %err,
                    "P1: peer OpenPGP public files were not loaded; POST stays refused for this vIP"
                ),
            }
        }

        let post_tx = if cfg.l0.enabled && !cfg.l0.entries.is_empty() {
            spawn_post_worker(cfg.l0.entries.clone())
        } else {
            None
        };

        let (inbound_tx, inbound_rx_ch) = mpsc::channel::<String>(LISTEN_QUEUE);
        let mut user_secrets = Vec::new();
        let mut listen_spawned = false;
        if cfg.l0.enabled {
            listen_spawned = if cfg.l0.channels.is_empty() {
                if let Some(path) = cfg.l0.routing_key_file.as_ref() {
                    match pgp::load_secret_cert(path) {
                        Ok(cert) => user_secrets.push(SecretCert(cert)),
                        Err(err) => tracing::warn!(
                            error = %err,
                            "P1: routing_key_file was not loaded; inbound decrypt for that wallet stays off"
                        ),
                    }
                }
                spawn_legacy_listen_into(cfg, &routing_eoa, !user_secrets.is_empty(), inbound_tx.clone())
            } else {
                spawn_channel_listens_into(cfg, &mut user_secrets, inbound_tx.clone())
            };
        }

        let channel_wire = load_channel_wires(cfg);
        let duplex = Arc::new(Mutex::new(HashMap::new()));
        if cfg.l0.enabled {
            spawn_duplex_runtime(
                cfg,
                &channel_wire,
                &peers,
                duplex.clone(),
                post_tx.clone(),
            );
        }
        let inbound_rx = if listen_spawned {
            Some(inbound_rx_ch)
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
            channel_eoa,
            known_ports,
            post_tx,
            user_secrets,
            tun_tx: None,
            inbound_rx,
            pending: None,
            channel_wire,
            duplex,
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

    /// Decrypt inbound user-PGP armor, ingest a duplex frame, or queue raw IPv4.
    /// May be fed by the in-crate listen worker. Tests do not POST production SI.
    #[allow(dead_code)]
    pub fn apply_inbound_armor(&mut self, chunk: &str) -> Result<usize, L0dError> {
        if !self.enabled {
            self.inbound_refused = self.inbound_refused.saturating_add(1);
            return Err(L0dError::L0(
                "[l0].enabled is false; inbound write-back refused".into(),
            ));
        }
        let trimmed = chunk.trim();
        if let Some((session_id, payload)) = duplex::parse_duplex_frame_json(trimmed) {
            return self.apply_duplex_frame(&session_id, &payload);
        }
        if let Some(accept) = duplex::parse_accept(trimmed) {
            self.apply_duplex_accept(accept);
            return Ok(0);
        }
        if let Some(session_id) = duplex::parse_reject(trimmed) {
            self.mark_duplex_rejected(&session_id);
            return Ok(0);
        }
        if self.user_secrets.is_empty() {
            self.inbound_refused = self.inbound_refused.saturating_add(1);
            return Err(L0dError::L0(
                "routing_key_file OpenPGP secret is required for inbound write-back".into(),
            ));
        }
        let mut last_err = L0dError::L0("inbound decrypt failed for every listen wallet".into());
        for secret in &self.user_secrets {
            match listen::inbound_plain_from_user_armor(chunk, &secret.0) {
                Ok(plain) => {
                    if let Ok(offer) = duplex::parse_offer_from_inbound_plain(&plain) {
                        self.apply_duplex_offer(offer);
                        return Ok(0);
                    }
                    if let Some(accept) = duplex::parse_accept(&plain) {
                        self.apply_duplex_accept(accept);
                        return Ok(0);
                    }
                    if let Some(session_id) = duplex::parse_reject(&plain) {
                        self.mark_duplex_rejected(&session_id);
                        return Ok(0);
                    }
                    if let Some((session_id, payload)) = duplex::parse_duplex_frame_json(&plain) {
                        return self.apply_duplex_frame(&session_id, &payload);
                    }
                    match envelope::decode(&plain) {
                        Ok((_env, ipv4)) if listen::looks_like_ipv4(&ipv4) => {
                            return self.queue_inbound_ipv4(ipv4);
                        }
                        Ok(_) => {
                            last_err = L0dError::L0("inbound payload is not IPv4".into());
                        }
                        Err(err) => last_err = err,
                    }
                }
                Err(err) => last_err = err,
            }
        }
        self.inbound_refused = self.inbound_refused.saturating_add(1);
        Err(last_err)
    }

    fn apply_duplex_frame(&mut self, session_id: &str, payload_b64: &str) -> Result<usize, L0dError> {
        let key = {
            let guard = self.duplex.lock().unwrap_or_else(|p| p.into_inner());
            guard
                .values()
                .find(|s| s.session_id == session_id)
                .and_then(|s| s.key)
        };
        let Some(key) = key else {
            self.inbound_refused = self.inbound_refused.saturating_add(1);
            return Err(L0dError::L0(
                "duplex_frame has no overlay key yet; waiting for duplex_offer".into(),
            ));
        };
        let opened = aes::open(&key, payload_b64)?;
        let (_seq, ipv4) = frame::decode(&opened)?;
        if !listen::looks_like_ipv4(ipv4) {
            self.inbound_refused = self.inbound_refused.saturating_add(1);
            return Err(L0dError::L0("duplex plaintext is not IPv4".into()));
        }
        self.queue_inbound_ipv4(ipv4.to_vec())
    }

    fn apply_duplex_offer(&mut self, offer: duplex::DuplexOffer) {
        let mut send_accept: Option<(ChannelWire, String, DuplexSession)> = None;
        let mut send_reject: Option<(ChannelWire, String)> = None;
        {
            let mut guard = self.duplex.lock().unwrap_or_else(|p| p.into_inner());
            for sess in guard.values_mut() {
                if sess.session_id != offer.session_id {
                    continue;
                }
                let waiting = sess.key.is_none();
                sess.key = Some(offer.key);
                if !offer.listen_user_pgp.trim().is_empty() {
                    sess.peer_listen_user_pgp = Some(offer.listen_user_pgp.clone());
                }
                tracing::info!(
                    session = %offer.session_id,
                    from = %offer.from,
                    listen = %offer.listen_wallet,
                    "duplex_offer accepted; overlay AES key stored in memory only"
                );
                if waiting {
                    sess.peer_attached = true;
                    sess.rejected = false;
                    if let Some(wire) = self.channel_wire.get(&sess.port) {
                        let target = if offer.listen_user_pgp.trim().is_empty() {
                            self.peers
                                .get(&(sess.dest, sess.port))
                                .map(|k| k.user.0.clone())
                        } else {
                            Some(offer.listen_user_pgp.clone())
                        };
                        if let Some(user_pgp) = target {
                            send_accept = Some((wire.clone(), user_pgp, sess.clone()));
                        }
                    }
                }
                break;
            }
        }
        if let Some((wire, user_pgp, sess)) = send_accept {
            if let Some(tx) = &self.post_tx {
                spawn_duplex_accept(wire, user_pgp, sess, tx.clone());
            }
            return;
        }
        tracing::warn!(
            session = %offer.session_id,
            "duplex_offer did not match a local session; sending duplex_reject"
        );
        if let Some(wire) = self.channel_wire.values().next() {
            let target = if offer.listen_user_pgp.trim().is_empty() {
                None
            } else {
                Some(offer.listen_user_pgp.clone())
            };
            if let Some(user_pgp) = target {
                send_reject = Some((wire.clone(), user_pgp));
            }
        }
        if let Some((wire, user_pgp)) = send_reject {
            if let Some(tx) = &self.post_tx {
                spawn_duplex_reject(wire, user_pgp, offer.session_id, tx.clone());
            }
        }
    }

    fn apply_duplex_accept(&mut self, accept: duplex::DuplexAccept) {
        let mut guard = self.duplex.lock().unwrap_or_else(|p| p.into_inner());
        for sess in guard.values_mut() {
            if sess.session_id != accept.session_id {
                continue;
            }
            if let Some(own) = sess.key {
                if own != accept.key {
                    tracing::warn!(
                        session = %accept.session_id,
                        "duplex_accept Securitykey mismatch; keeping P1 gossip"
                    );
                    sess.rejected = true;
                    sess.peer_attached = false;
                    return;
                }
            } else {
                sess.key = Some(accept.key);
            }
            if !accept.listen_user_pgp.trim().is_empty() {
                sess.peer_listen_user_pgp = Some(accept.listen_user_pgp);
            }
            sess.peer_attached = true;
            sess.rejected = false;
            tracing::info!(
                session = %accept.session_id,
                peer_listen = %accept.listen_wallet,
                "duplex_accept on session listen SSE"
            );
            return;
        }
    }

    fn mark_duplex_rejected(&mut self, session_id: &str) {
        let mut guard = self.duplex.lock().unwrap_or_else(|p| p.into_inner());
        for sess in guard.values_mut() {
            if sess.session_id == session_id {
                sess.rejected = true;
                sess.peer_attached = false;
                tracing::info!(session = %session_id, "duplex_reject on session listen SSE; P1 gossip");
                return;
            }
        }
    }

    fn duplex_ready(&self, dest: Ipv4Addr, port: u16) -> Option<DuplexSession> {
        let guard = self.duplex.lock().unwrap_or_else(|p| p.into_inner());
        let sess = guard.get(&(dest, port))?;
        if sess.key.is_some() && sess.peer_attached && !sess.rejected {
            Some(sess.clone())
        } else {
            None
        }
    }

    fn queue_inbound_ipv4(&mut self, blob: Vec<u8>) -> Result<usize, L0dError> {
        let packets = envelope::split_ipv4_datagrams(&blob)?;
        let n = blob.len();
        let packet_count = packets.len();
        for ipv4 in packets {
            self.inbound_ready = self.inbound_ready.saturating_add(1);
            match &self.tun_tx {
                Some(tx) => match tx.try_send(ipv4) {
                    Ok(()) => {
                        self.tun_writes = self.tun_writes.saturating_add(1);
                    }
                    Err(_) => {
                        self.inbound_dropped = self.inbound_dropped.saturating_add(1);
                        tracing::warn!(
                            dropped = self.inbound_dropped,
                            "P1 inbound TUN queue full; frame dropped"
                        );
                    }
                },
                None => tracing::debug!(
                    bytes = n,
                    packets = packet_count,
                    "P1 inbound IPv4 ready; TUN writer not attached"
                ),
            }
        }
        tracing::debug!(
            bytes = n,
            packets = packet_count,
            "P1 inbound IPv4 queued for TUN write-back"
        );
        Ok(n)
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
        let Some(port) = overlay_channel_port(packet, &self.known_ports) else {
            self.posts_refused = self.posts_refused.saturating_add(1);
            tracing::debug!(
                dest = %dest,
                locator = %loc.display(),
                "P1: overlay packet has no well-known port; POST refused"
            );
            return;
        };

        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.dest != dest || p.port != port)
        {
            self.flush_pending_overlay();
        }
        if self.pending.is_none() {
            self.pending = Some(PendingOverlay {
                dest,
                port,
                loc: loc.clone(),
                packets: Vec::new(),
                bytes: 0,
            });
        }
        let should_flush = if let Some(pending) = self.pending.as_mut() {
            pending.packets.push(packet.to_vec());
            pending.bytes = pending.bytes.saturating_add(packet.len());
            pending.packets.len() >= BATCH_MAX_PACKETS || pending.bytes >= BATCH_MAX_BYTES
        } else {
            false
        };
        if should_flush {
            self.flush_pending_overlay();
        }
    }

    /// Flush a dest-aggregated IPv4 batch as one `conet_l0d_overlay_v1` POST.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn flush_pending_overlay(&mut self) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        if pending.packets.is_empty() {
            return;
        }
        let packet_count = pending.packets.len();
        let mut raw = Vec::with_capacity(pending.bytes);
        for pkt in &pending.packets {
            raw.extend_from_slice(pkt);
        }
        self.seq = self.seq.saturating_add(1);
        let framed = frame::encode(self.seq, &raw);
        match self.prepare_overlay_post(pending.dest, pending.port, &raw, self.seq) {
            Ok(prepared) => {
                self.frames_ready = self.frames_ready.saturating_add(packet_count as u64);
                self.posts_prepared = self.posts_prepared.saturating_add(1);
                tracing::info!(
                    dest = %pending.dest,
                    port = pending.port,
                    locator = %pending.loc.display(),
                    seq = self.seq,
                    packets = packet_count,
                    frame_bytes = framed.len(),
                    "P1 overlay batch flushed for POST"
                );
                self.enqueue_post(prepared, pending.dest, &pending.loc, raw.len(), packet_count);
            }
            Err(err) => {
                self.posts_refused = self.posts_refused.saturating_add(1);
                tracing::warn!(
                    dest = %pending.dest,
                    port = pending.port,
                    locator = %pending.loc.display(),
                    seq = self.seq,
                    packets = packet_count,
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
        port: u16,
        packet: &[u8],
        seq: u64,
    ) -> Result<PreparedPost, L0dError> {
        let keys = self.peers.get(&(dest, port)).ok_or_else(|| {
            L0dError::L0(
                "peer user+route PGP public files are required; refusing POST".into(),
            )
        })?;
        let entry = self.entries.first().ok_or_else(|| {
            L0dError::L0("l0.entries is empty; refusing POST".into())
        })?;
        let url = post::post_url(entry)?;
        if let Some(sess) = self.duplex_ready(dest, port) {
            if let Some(key) = sess.key {
                let framed = frame::encode(seq, packet);
                let payload = aes::seal(&key, &framed)?;
                let json = duplex::encode_frame_json(&sess.session_id, &payload)?;
                let user_pgp = sess
                    .peer_listen_user_pgp
                    .as_deref()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or(keys.user.0.as_str());
                let armor = pgp::wrap_overlay_for_post(&json, user_pgp, &keys.route.0)?;
                return Ok(PreparedPost { url, armor });
            }
        }
        let from = self
            .channel_eoa
            .get(&port)
            .cloned()
            .filter(|eoa| !eoa.is_empty())
            .unwrap_or_else(|| self.routing_eoa.clone());
        let json = envelope::encode(&from, seq, packet)?;
        let armor = pgp::wrap_overlay_for_post(&json, &keys.user.0, &keys.route.0)?;
        Ok(PreparedPost { url, armor })
    }

    fn enqueue_post(
        &mut self,
        prepared: PreparedPost,
        dest: Ipv4Addr,
        loc: &Locator,
        frame_bytes: usize,
        packet_count: usize,
    ) {
        let armor_bytes = prepared.armor_len();
        let Some(tx) = &self.post_tx else {
            tracing::debug!(
                dest = %dest,
                locator = %loc.display(),
                seq = self.seq,
                packets = packet_count,
                armor_bytes,
                frame_bytes,
                "P1 overlay armor ready; POST worker not started (no tokio runtime)"
            );
            return;
        };
        match tx.try_send(PostJob {
            armor: prepared.armor,
        }) {
            Ok(()) => {
                self.posts_queued = self.posts_queued.saturating_add(1);
                tracing::debug!(
                    dest = %dest,
                    locator = %loc.display(),
                    seq = self.seq,
                    first_entry = %prepared.url,
                    packets = packet_count,
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
                    packets = packet_count,
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

fn spawn_legacy_listen_into(
    cfg: &ValidatedConfig,
    routing_eoa: &str,
    has_secret: bool,
    tx: mpsc::Sender<String>,
) -> bool {
    if !has_secret || routing_eoa.is_empty() || cfg.l0.listen_entries.is_empty() {
        return false;
    }
    let Some(path) = cfg.l0.mailbox_route_pgp_file.as_ref() else {
        return false;
    };
    let eth = match cfg.l0.routing_eth_key_file.as_ref() {
        Some(eth_path) => match eip191::load_eth_secret(eth_path) {
            Ok(secret) => {
                if !eip191::eoa_eq(secret.address(), routing_eoa) {
                    tracing::warn!(
                        "P1: routing_eth_key_file does not match routing_eoa; listen worker stays off"
                    );
                    return false;
                }
                secret
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "P1: routing_eth_key_file was not loaded; listen worker stays off"
                );
                return false;
            }
        },
        None => return false,
    };
    let route = match pgp::load_public_cert_armored(path) {
        Ok(route) => route,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "P1: mailbox_route_pgp_file was not loaded; listen worker stays off"
            );
            return false;
        }
    };
    spawn_listen_worker(
        cfg.l0.listen_entries.clone(),
        route,
        routing_eoa.to_string(),
        eth,
        tx,
    )
}

fn spawn_channel_listens_into(
    cfg: &ValidatedConfig,
    user_secrets: &mut Vec<SecretCert>,
    tx: mpsc::Sender<String>,
) -> bool {
    let mut spawned = 0u32;
    for ch in &cfg.l0.channels {
        match pgp::load_secret_cert(&ch.routing_key_file) {
            Ok(cert) => user_secrets.push(SecretCert(cert)),
            Err(err) => tracing::warn!(
                eoa = %ch.routing_eoa,
                error = %err,
                "P1: channel routing_key_file was not loaded; inbound decrypt for that wallet stays off"
            ),
        }
        if ch.listen_entries.is_empty() {
            tracing::warn!(
                eoa = %ch.routing_eoa,
                "P1: channel listen_entries empty; that SSE stays off"
            );
            continue;
        }
        let eth = match eip191::load_eth_secret(&ch.routing_eth_key_file) {
            Ok(secret) => {
                if !eip191::eoa_eq(secret.address(), &ch.routing_eoa) {
                    tracing::warn!(
                        eoa = %ch.routing_eoa,
                        "P1: channel routing_eth_key_file does not match routing_eoa; SSE stays off"
                    );
                    continue;
                }
                secret
            }
            Err(err) => {
                tracing::warn!(
                    eoa = %ch.routing_eoa,
                    error = %err,
                    "P1: channel routing_eth_key_file was not loaded; SSE stays off"
                );
                continue;
            }
        };
        let route = match pgp::load_public_cert_armored(&ch.mailbox_route_pgp_file) {
            Ok(route) => route,
            Err(err) => {
                tracing::warn!(
                    eoa = %ch.routing_eoa,
                    error = %err,
                    "P1: channel mailbox_route_pgp_file was not loaded; SSE stays off"
                );
                continue;
            }
        };
        if spawn_listen_worker(
            ch.listen_entries.clone(),
            route,
            ch.routing_eoa.clone(),
            eth,
            tx.clone(),
        ) {
            spawned += 1;
        }
    }
    spawned > 0
}

fn spawn_listen_worker(
    entries: Vec<String>,
    mailbox_route: String,
    routing_eoa: String,
    eth: EthSecret,
    tx: mpsc::Sender<String>,
) -> bool {
    let Some(handle) = tokio::runtime::Handle::try_current().ok() else {
        return false;
    };
    let Ok(client) = listen::listen_http_client() else {
        return false;
    };
    handle.spawn(async move {
        let mut last_failed: Option<String> = None;
        loop {
            let Some(entry) = listen::pick_listen_entry(&entries, last_failed.as_deref()) else {
                tracing::warn!(
                    eoa = %routing_eoa,
                    "P1 listen: listen_entries empty; worker idle"
                );
                tokio::time::sleep(Duration::from_secs(LISTEN_RECONNECT_SECS)).await;
                continue;
            };
            let ts = chrono::Utc::now().timestamp().max(0) as u64;
            match listen::prepare_listen_post(&routing_eoa, ts, &mailbox_route, entry, &eth) {
                Ok((url, armor)) => match listen::run_listen_once(&client, &url, &armor, &tx).await
                {
                    Ok(_) => {
                        last_failed = None;
                        tracing::info!(
                            eoa = %routing_eoa,
                            "P1 listen SSE ended; reconnecting after idle"
                        );
                    }
                    Err(err) => {
                        tracing::warn!(eoa = %routing_eoa, error = %err, "P1 listen SSE failed");
                        last_failed = Some(entry.to_string());
                    }
                },
                Err(err) => {
                    tracing::warn!(eoa = %routing_eoa, error = %err, "P1 listen wrap refused");
                    last_failed = Some(entry.to_string());
                }
            }
            tokio::time::sleep(Duration::from_secs(LISTEN_RECONNECT_SECS)).await;
        }
    });
    true
}

fn load_channel_wires(cfg: &ValidatedConfig) -> HashMap<u16, ChannelWire> {
    let mut out = HashMap::new();
    if !cfg.l0.channels.is_empty() {
        for ch in &cfg.l0.channels {
            let eth = match eip191::load_eth_secret(&ch.routing_eth_key_file) {
                Ok(secret) if eip191::eoa_eq(secret.address(), &ch.routing_eoa) => secret,
                _ => continue,
            };
            let route = match pgp::load_public_cert_armored(&ch.mailbox_route_pgp_file) {
                Ok(route) => route,
                Err(_) => continue,
            };
            let listen_entries = if ch.listen_entries.is_empty() {
                cfg.l0.listen_entries.clone()
            } else {
                ch.listen_entries.clone()
            };
            let user_pub = match pgp::load_secret_cert(&ch.routing_key_file)
                .and_then(|cert| pgp::public_cert_armored(&cert))
            {
                Ok(armor) => armor,
                Err(_) => continue,
            };
            for port in &ch.ports {
                out.insert(
                    *port,
                    ChannelWire {
                        eoa: ch.routing_eoa.clone(),
                        route_pgp: route.clone(),
                        eth: eth.clone(),
                        listen_entries: listen_entries.clone(),
                        user_pub: user_pub.clone(),
                    },
                );
            }
        }
        return out;
    }
    let Some(eoa) = cfg.l0.routing_eoa.as_ref() else {
        return out;
    };
    let Some(eth_path) = cfg.l0.routing_eth_key_file.as_ref() else {
        return out;
    };
    let Some(route_path) = cfg.l0.mailbox_route_pgp_file.as_ref() else {
        return out;
    };
    let Ok(eth) = eip191::load_eth_secret(eth_path) else {
        return out;
    };
    if !eip191::eoa_eq(eth.address(), eoa) {
        return out;
    }
    let Ok(route) = pgp::load_public_cert_armored(route_path) else {
        return out;
    };
    let user_pub = match cfg
        .l0
        .routing_key_file
        .as_ref()
        .and_then(|path| pgp::load_secret_cert(path).ok())
        .and_then(|cert| pgp::public_cert_armored(&cert).ok())
    {
        Some(armor) => armor,
        None => return out,
    };
    for port in cfg.overlay_ports() {
        out.insert(
            port,
            ChannelWire {
                eoa: eoa.clone(),
                route_pgp: route.clone(),
                eth: eth.clone(),
                listen_entries: cfg.l0.listen_entries.clone(),
                user_pub: user_pub.clone(),
            },
        );
    }
    out
}

fn spawn_duplex_runtime(
    cfg: &ValidatedConfig,
    wires: &HashMap<u16, ChannelWire>,
    peers: &HashMap<(Ipv4Addr, u16), PeerPgp>,
    duplex: Arc<Mutex<HashMap<(Ipv4Addr, u16), DuplexSession>>>,
    post_tx: Option<mpsc::Sender<PostJob>>,
) {
    if wires.is_empty() {
        return;
    }
    {
        let mut map = duplex.lock().unwrap_or_else(|p| p.into_inner());
        for peer in &cfg.peers {
            let LocatorHost::Eoa(peer_eoa) = &peer.locator.host else {
                continue;
            };
            for port in peer.tcp_ports.iter().chain(peer.udp_ports.iter()) {
                let Some(wire) = wires.get(port) else {
                    continue;
                };
                if !peers.contains_key(&(peer.vip, *port)) {
                    continue;
                }
                let Ok(session_id) = duplex::session_id(&wire.eoa, peer_eoa, *port) else {
                    continue;
                };
                let initiator = duplex::we_are_initiator(&wire.eoa, peer_eoa).unwrap_or(false);
                let key = if initiator {
                    Some(aes::generate_key())
                } else {
                    None
                };
                map.insert(
                    (peer.vip, *port),
                    DuplexSession {
                        session_id,
                        key,
                        dest: peer.vip,
                        port: *port,
                        guest_up: true,
                        peer_attached: false,
                        rejected: false,
                        host_eoa: wire.eoa.clone(),
                        peer_listen_user_pgp: None,
                    },
                );
            }
        }
    }

    let snapshot: Vec<DuplexSession> = {
        let guard = duplex.lock().unwrap_or_else(|p| p.into_inner());
        guard.values().cloned().collect()
    };
    for sess in snapshot {
        let Some(wire) = wires.get(&sess.port) else {
            continue;
        };
        let Some(keys) = peers.get(&(sess.dest, sess.port)) else {
            continue;
        };
        let Some(peer) = cfg.peers.iter().find(|p| p.vip == sess.dest) else {
            continue;
        };
        let LocatorHost::Eoa(peer_eoa) = &peer.locator.host else {
            continue;
        };
        if sess.key.is_some() {
            if let Some(tx) = &post_tx {
                spawn_duplex_offer(
                    wire.clone(),
                    keys.user.0.clone(),
                    peer_eoa.clone(),
                    sess,
                    tx.clone(),
                );
            }
        }
    }
}

fn spawn_duplex_offer(
    wire: ChannelWire,
    peer_user_pgp: String,
    peer_eoa: String,
    sess: DuplexSession,
    post_tx: mpsc::Sender<PostJob>,
) {
    let Some(handle) = tokio::runtime::Handle::try_current().ok() else {
        return;
    };
    let Some(key) = sess.key else {
        return;
    };
    handle.spawn(async move {
        loop {
            let ts = chrono::Utc::now().timestamp().max(0) as u64;
            match duplex::encode_offer_command(
                &wire.eoa,
                &peer_eoa,
                &wire.eoa,
                &wire.user_pub,
                &sess.session_id,
                &key,
                ts,
            )
            .and_then(|cmd| duplex::wrap_offer_for_user_pgp(&cmd, &peer_user_pgp, &wire.eth))
            {
                Ok(armor) => {
                    if post_tx.send(PostJob { armor }).await.is_ok() {
                        tracing::info!(session = %sess.session_id, "duplex_offer queued for POST");
                        return;
                    }
                }
                Err(err) => tracing::warn!(error = %err, "duplex_offer wrap refused"),
            }
            tokio::time::sleep(Duration::from_secs(LISTEN_RECONNECT_SECS)).await;
        }
    });
}

fn spawn_duplex_accept(
    wire: ChannelWire,
    peer_user_pgp: String,
    sess: DuplexSession,
    post_tx: mpsc::Sender<PostJob>,
) {
    let Some(handle) = tokio::runtime::Handle::try_current().ok() else {
        return;
    };
    let Some(key) = sess.key else {
        return;
    };
    handle.spawn(async move {
        loop {
            let ts = chrono::Utc::now().timestamp().max(0) as u64;
            match duplex::encode_accept_command(
                &wire.eoa,
                &wire.eoa,
                &wire.user_pub,
                &sess.session_id,
                &key,
                ts,
            )
            .and_then(|cmd| duplex::wrap_app_for_user_pgp(&cmd, &peer_user_pgp, &wire.eth))
            {
                Ok(armor) => {
                    if post_tx.send(PostJob { armor }).await.is_ok() {
                        tracing::info!(session = %sess.session_id, "duplex_accept queued for POST");
                        return;
                    }
                }
                Err(err) => tracing::warn!(error = %err, "duplex_accept wrap refused"),
            }
            tokio::time::sleep(Duration::from_secs(LISTEN_RECONNECT_SECS)).await;
        }
    });
}

fn spawn_duplex_reject(
    wire: ChannelWire,
    initiator_listen_user_pgp: String,
    session_id: String,
    post_tx: mpsc::Sender<PostJob>,
) {
    let Some(handle) = tokio::runtime::Handle::try_current().ok() else {
        return;
    };
    handle.spawn(async move {
        loop {
            let ts = chrono::Utc::now().timestamp().max(0) as u64;
            match duplex::encode_reject_command(&wire.eoa, &session_id, ts)
                .and_then(|cmd| duplex::wrap_app_for_user_pgp(&cmd, &initiator_listen_user_pgp, &wire.eth))
            {
                Ok(armor) => {
                    if post_tx.send(PostJob { armor }).await.is_ok() {
                        tracing::info!(session = %session_id, "duplex_reject queued for POST");
                        return;
                    }
                }
                Err(err) => tracing::warn!(error = %err, "duplex_reject wrap refused"),
            }
            tokio::time::sleep(Duration::from_secs(LISTEN_RECONNECT_SECS)).await;
        }
    });
}

fn spawn_post_worker(entries: Vec<String>) -> Option<mpsc::Sender<PostJob>> {
    let handle = tokio::runtime::Handle::try_current().ok()?;
    let client = post::http_client().ok()?;
    let (tx, mut rx) = mpsc::channel::<PostJob>(POST_QUEUE);
    handle.spawn(async move {
        let client = Arc::new(client);
        let entries = Arc::new(entries);
        let sem = Arc::new(Semaphore::new(POST_CONCURRENCY));
        while let Some(job) = rx.recv().await {
            let Ok(permit) = sem.clone().acquire_owned().await else {
                tracing::warn!(
                    armor_bytes = job.armor.len(),
                    "P1 POST worker semaphore closed"
                );
                break;
            };
            let client = client.clone();
            let entries = entries.clone();
            tokio::spawn(async move {
                let _permit = permit;
                match post::send_via_entries(&client, &entries, &job.armor).await {
                    Ok((status, entry)) => tracing::debug!(
                        status,
                        entry,
                        armor_bytes = job.armor.len(),
                        "P1 POST /post accepted"
                    ),
                    Err(err) => tracing::warn!(
                        error = %err,
                        armor_bytes = job.armor.len(),
                        "P1 POST /post failed after trying configured entries"
                    ),
                }
            });
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
        let keys = PeerPgp {
            user: ArmoredCert(user.to_string()),
            route: ArmoredCert(route.to_string()),
        };
        let dest = Ipv4Addr::new(100, 64, 0, 6);
        for port in [8400_u16, 4200, 4300] {
            peers.insert((dest, port), keys.clone());
        }
        let mut channel_eoa = HashMap::new();
        channel_eoa.insert(
            8400,
            "0x1111111111111111111111111111111111111111".into(),
        );
        channel_eoa.insert(
            4200,
            "0x1111111111111111111111111111111111111111".into(),
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
            channel_eoa,
            known_ports: crate::packet::default_overlay_port_set(),
            post_tx: None,
            user_secrets: Vec::new(),
            tun_tx: None,
            inbound_rx: None,
            pending: None,
            channel_wire: HashMap::new(),
            duplex: Arc::new(Mutex::new(HashMap::new())),
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
            .prepare_overlay_post(Ipv4Addr::new(100, 64, 0, 6), 8400, b"\x45\x00pkt", 9)
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
    fn duplex_ready_posts_frame_mailbox_work_not_p1_envelope() {
        let user = generate_test_cert();
        let route = generate_test_cert();
        let user_pub = public_cert_armored(&user).unwrap();
        let route_pub = public_cert_armored(&route).unwrap();
        let client = client_with_keys(&user_pub, &route_pub);
        let dest = Ipv4Addr::new(100, 64, 0, 6);
        let key = aes::generate_key();
        let sid = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string();
        client.duplex.lock().unwrap().insert(
            (dest, 8400),
            DuplexSession {
                session_id: sid.clone(),
                key: Some(key),
                dest,
                port: 8400,
                guest_up: true,
                peer_attached: true,
                rejected: false,
                host_eoa: "0x1111111111111111111111111111111111111111".into(),
                peer_listen_user_pgp: None,
            },
        );
        let prepared = client
            .prepare_overlay_post(dest, 8400, b"\x45\x00pkt", 3)
            .unwrap();
        let work: serde_json::Value =
            serde_json::from_str(&decrypt_utf8(&prepared.armor, &route).unwrap()).unwrap();
        assert_eq!(work["NoPush"], true);
        let inner = work["data"].as_str().unwrap();
        let frame_json = decrypt_utf8(inner, &user).unwrap();
        assert!(frame_json.contains("duplex_frame"));
        assert!(!frame_json.contains("duplex_relay"));
        assert!(!frame_json.contains("Securitykey"));
        assert!(!frame_json.contains("conet_l0d_overlay_v1"));
    }

    #[test]
    fn inbound_duplex_frame_writes_ipv4() {
        let dest = Ipv4Addr::new(100, 64, 0, 6);
        let key = aes::generate_key();
        let pkt = b"\x45\x00fake-ipv4-header!!";
        let framed = frame::encode(1, pkt);
        let payload = aes::seal(&key, &framed).unwrap();
        let sid = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let mut client = L0Client {
            enabled: true,
            ..L0Client::disabled()
        };
        client.duplex.lock().unwrap().insert(
            (dest, 8400),
            DuplexSession {
                session_id: sid.to_string(),
                key: Some(key),
                dest,
                port: 8400,
                guest_up: true,
                peer_attached: true,
                rejected: false,
                host_eoa: "0x1111111111111111111111111111111111111111".into(),
                peer_listen_user_pgp: None,
            },
        );
        let json = serde_json::json!({
            "type": "duplex_frame",
            "sessionId": sid,
            "payload": payload,
        })
        .to_string();
        assert_eq!(client.apply_inbound_armor(&json).unwrap(), pkt.len());
        assert_eq!(client.inbound_ready, 1);
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
            .prepare_overlay_post(Ipv4Addr::new(100, 64, 0, 6), 8400, b"x", 1)
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
            user_secrets: vec![SecretCert(user)],
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

    #[test]
    fn post_worker_keeps_bounded_concurrency() {
        assert!(POST_CONCURRENCY >= 2);
        assert!(POST_CONCURRENCY <= 8);
        assert!(POST_CONCURRENCY <= POST_QUEUE);
        assert!(POST_QUEUE >= 512);
    }

    fn mini_ipv4(id: u8) -> Vec<u8> {
        mini_tcp(57594, 8400, id)
    }

    fn mini_tcp(sport: u16, dport: u16, id: u8) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[2] = 0;
        p[3] = 40;
        p[9] = 6;
        p[16] = 100;
        p[17] = 64;
        p[18] = 0;
        p[19] = id;
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p
    }

    #[test]
    fn inbound_splits_concatenated_ipv4() {
        let user = generate_test_cert();
        let user_pub = public_cert_armored(&user).unwrap();
        let a = mini_ipv4(1);
        let b = mini_ipv4(2);
        let mut raw = a.clone();
        raw.extend_from_slice(&b);
        let json = envelope::encode("0x1111111111111111111111111111111111111111", 2, &raw).unwrap();
        let armor = pgp::encrypt_utf8(&json, &user_pub).unwrap();
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(4);
        let mut client = L0Client {
            enabled: true,
            user_secrets: vec![SecretCert(user)],
            tun_tx: Some(tx),
            routing_eoa: "0x1111111111111111111111111111111111111111".into(),
            ..L0Client::disabled()
        };
        assert_eq!(client.apply_inbound_armor(&armor).unwrap(), raw.len());
        assert_eq!(client.inbound_ready, 2);
        assert_eq!(client.tun_writes, 2);
        assert_eq!(rx.try_recv().unwrap(), a);
        assert_eq!(rx.try_recv().unwrap(), b);
    }

    #[test]
    fn flush_batches_two_packets_as_one_post() {
        let user = generate_test_cert();
        let route = generate_test_cert();
        let user_pub = public_cert_armored(&user).unwrap();
        let route_pub = public_cert_armored(&route).unwrap();
        let mut client = client_with_keys(&user_pub, &route_pub);
        let loc = Locator {
            host: LocatorHost::Eoa("0x2222222222222222222222222222222222222222".into()),
            service: crate::locator::OverlayService::Geth,
        };
        let dest = Ipv4Addr::new(100, 64, 0, 6);
        client.note_overlay_packet(dest, Some(&loc), &mini_ipv4(1));
        client.note_overlay_packet(dest, Some(&loc), &mini_ipv4(2));
        assert_eq!(client.posts_prepared, 0);
        client.flush_pending_overlay();
        assert_eq!(client.posts_prepared, 1);
        assert_eq!(client.frames_ready, 2);
        assert_eq!(client.seq, 1);
    }

    #[test]
    fn flush_does_not_batch_across_ports() {
        let user = generate_test_cert();
        let route = generate_test_cert();
        let user_pub = public_cert_armored(&user).unwrap();
        let route_pub = public_cert_armored(&route).unwrap();
        let mut client = client_with_keys(&user_pub, &route_pub);
        let loc = Locator {
            host: LocatorHost::Eoa("0x2222222222222222222222222222222222222222".into()),
            service: crate::locator::OverlayService::Geth,
        };
        let dest = Ipv4Addr::new(100, 64, 0, 6);
        client.note_overlay_packet(dest, Some(&loc), &mini_tcp(57594, 8400, 6));
        client.note_overlay_packet(dest, Some(&loc), &mini_tcp(51152, 4200, 6));
        assert_eq!(client.posts_prepared, 1);
        client.flush_pending_overlay();
        assert_eq!(client.posts_prepared, 2);
    }

    #[test]
    fn return_path_uses_source_port() {
        let user = generate_test_cert();
        let route = generate_test_cert();
        let user_pub = public_cert_armored(&user).unwrap();
        let route_pub = public_cert_armored(&route).unwrap();
        let mut client = client_with_keys(&user_pub, &route_pub);
        let loc = Locator {
            host: LocatorHost::Eoa("0x2222222222222222222222222222222222222222".into()),
            service: crate::locator::OverlayService::Geth,
        };
        let dest = Ipv4Addr::new(100, 64, 0, 6);
        client.note_overlay_packet(dest, Some(&loc), &mini_tcp(8400, 57594, 6));
        client.flush_pending_overlay();
        assert_eq!(client.posts_prepared, 1);
        assert_eq!(client.posts_refused, 0);
    }

    #[test]
    fn inbound_tries_second_listen_wallet() {
        let first = generate_test_cert();
        let second = generate_test_cert();
        let second_pub = public_cert_armored(&second).unwrap();
        let pkt = b"\x45\x00inbound-ipv4-ok!!!";
        let json = envelope::encode("0x1111111111111111111111111111111111111111", 2, pkt).unwrap();
        let armor = pgp::encrypt_utf8(&json, &second_pub).unwrap();
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(4);
        let mut client = L0Client {
            enabled: true,
            user_secrets: vec![SecretCert(first), SecretCert(second)],
            tun_tx: Some(tx),
            routing_eoa: "0x1111111111111111111111111111111111111111".into(),
            ..L0Client::disabled()
        };
        assert_eq!(client.apply_inbound_armor(&armor).unwrap(), pkt.len());
        assert_eq!(rx.try_recv().unwrap(), pkt);
    }

    #[tokio::test]
    async fn post_worker_sends_jobs_concurrently() {
        use std::time::Instant;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/post"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(200))
                    .set_body_string("ok"),
            )
            .expect(4)
            .mount(&server)
            .await;

        let tx = spawn_post_worker(vec![server.uri()]).expect("worker");
        let armor = "-----BEGIN PGP MESSAGE-----\n\nxxxx\n-----END PGP MESSAGE-----\n";
        let started = Instant::now();
        for _ in 0..4 {
            tx.send(PostJob {
                armor: armor.to_string(),
            })
            .await
            .expect("queue");
        }
        loop {
            let n = server.received_requests().await.unwrap().len();
            if n >= 4 {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "worker did not deliver 4 POSTs; last_seen={n}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let first_wave = started.elapsed();
        assert!(
            first_wave < Duration::from_millis(400),
            "expected concurrent first wave, got {first_wave:?}"
        );
        drop(tx);
    }
}
