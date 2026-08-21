//! Overlay L0 client. Default is the MVP stub.
//!
//! Protocol: exclusive SI `l0_listen` / `l0_connect` occupancy pipe, then
//! application duplex (`duplex_offer` on Chat gossip; accept / reject / frames
//! as AES blobs on the occupied pipe). While a configured duplex session is
//! negotiating or recovering, overlay packets are suppressed rather than sent
//! through `conet_l0d_overlay_v1` transport frames. HTTP first body is still `{ "data" }`
//! only. Do not claim SI `duplex_*` or live `p2p_stream_*`.

use crate::config::ValidatedConfig;
use crate::error::L0dError;
use crate::l0::aes;
use crate::l0::eip191::EthSecret;
use crate::l0::{duplex, eip191, envelope, frame, listen, pgp, pipe, post, proxy};
use crate::locator::{Locator, LocatorHost};
use crate::packet::overlay_channel_port;
use base64::Engine;
use sequoia_openpgp::Cert;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, Semaphore};

const POST_QUEUE: usize = 2048;
// 32 in-flight POSTs each walking 3 entries × 12s starves SI /post (listen headers never arrive).
const POST_CONCURRENCY: usize = 4;
const LISTEN_QUEUE: usize = 512;
const LISTEN_RECONNECT_SECS: u64 = 3;
/// After `l0_connect` fails (e.g. peer L0 listen not idle yet), retry instead of
/// permanently clearing `pipe_tx` and falling back to P1.
const L0_PIPE_RETRY_SECS: u64 = 3;
/// SI signaled explicit teardown on the occupied inbound TCP; retry quickly.
const L0_PIPE_END_RETRY_SECS: u64 = 1;
/// Peer L0 listen still occupied (HTTP 409); back off to avoid occupy storms.
const L0_PIPE_OCCUPIED_RETRY_SECS: u64 = 5;
/// Duplex offer/accept must reach a healthy entry; a failed line is closed and
/// its bytes are discarded rather than falling back to P1 gossip.
const DUPLEX_CONTROL_POST_RETRY_SECS: u64 = 5;
/// Initiator re-posts `duplex_offer` until acceptor answers (spoke may start after hub).
const DUPLEX_OFFER_RESEND_SECS: u64 = 30;
/// Acceptor re-posts `duplex_accept` on Chat until the return `l0_connect` pipe is up.
const DUPLEX_ACCEPT_RESEND_SECS: u64 = 30;
/// Offers created before this local daemon incarnation belong to an older
/// mailbox delivery and must not claim a fresh pending session.
const DUPLEX_OFFER_CLOCK_SKEW_SECS: u64 = 10;
/// Absolute wall-clock max age for inbound `duplex_offer`. Mailbox offline flush
/// after a bounce can replay armors from a previous process *before* any live
/// peer:port pipe exists; reject those regardless of local duplex state.
const DUPLEX_OFFER_MAX_AGE_SECS: u64 = 90;
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
    /// Peer locator EOA when known (multiline dest resolution).
    peer_eoa: String,
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
    /// Per-port channel / listen EOA (exclusive SI `l0_listen` subject).
    eoa: String,
    /// Paid mainWallet used to match inbound `duplex_offer.mainWallet:port`.
    /// Distinct from `eoa` when a proxy hosts many ports under one billing
    /// identity while each port keeps its own exclusive occupy listen.
    main_wallet: String,
    #[allow(dead_code)]
    route_pgp: String,
    /// Billing key for duplex_offer / duplex_accept (peer verifies `billingWallet`).
    eth: EthSecret,
    /// Channel key for SI `l0_listen` / `l0_connect`. Committed SI fleets
    /// require EIP-191 recover == `walletAddress` (no `billingWallet` yet).
    si_eth: EthSecret,
    #[allow(dead_code)]
    listen_entries: Vec<String>,
    /// Outbound entries A ≠ B for `l0_connect` occupancy pipes.
    entries: Vec<String>,
    /// Own session-listen user PGP (channel EOA in crate MVP).
    user_pub: String,
}

/// Shared by exclusive `l0_listen` workers so a successful SSE reconnect can
/// rebuild outbound `l0_connect` pipes instead of leaving `pipe_tx = None` (P1).
type DuplexKey = (Ipv4Addr, u16, String);

#[derive(Clone)]
struct L0PipeRebuild {
    duplex: Arc<Mutex<HashMap<DuplexKey, DuplexSession>>>,
    wires: Arc<HashMap<u16, ChannelWire>>,
    peers: Arc<HashMap<(Ipv4Addr, u16), PeerPgp>>,
    extras: PipeExtras,
}

/// Shared by occupy tasks: listen inbound feed + optional proxy drain.
#[derive(Clone)]
struct PipeExtras {
    inbound_tx: Option<mpsc::Sender<String>>,
    proxy_registry: proxy::ProxyRegistry,
    proxy_receivers: Arc<Mutex<HashMap<String, mpsc::Sender<Vec<u8>>>>>,
    proxy_seq: Arc<AtomicU64>,
}

impl PipeExtras {
    fn empty() -> Self {
        Self {
            inbound_tx: None,
            proxy_registry: proxy::ProxyRegistry::new(Vec::new()),
            proxy_receivers: Arc::new(Mutex::new(HashMap::new())),
            proxy_seq: Arc::new(AtomicU64::new(1)),
        }
    }
}

#[derive(Clone)]
struct DuplexSession {
    session_id: String,
    created_at: u64,
    key: Option<[u8; aes::KEY_LEN]>,
    dest: Ipv4Addr,
    port: u16,
    /// Configured peer EOA. The responder uses this to adopt the initiator's
    /// session id when both sides created their local pending session
    /// independently.
    peer_eoa: String,
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
    peer_listen_wallet: Option<String>,
    /// Acceptor-side temporary identity, allocated after mainWallet:port
    /// matching. It is never reused by another line.
    accept_identity: Option<crate::l0::identity::TemporaryIdentity>,
    /// Acceptor: initiator sent at least one `duplex_frame` (return path is live).
    peer_return_attached: bool,
    /// Occupied `l0_connect` writer. AES blobs only; never overlay key on this channel.
    pipe_tx: Option<mpsc::Sender<String>>,
    /// Bumps on every `spawn_l0_pipe` so a dying task does not clear a newer pipe.
    pipe_gen: u64,
    /// True while an async `spawn_l0_pipe` task owns occupy/retry (prevents duplicate spawns).
    pipe_connect_inflight: bool,
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

#[derive(Debug)]
enum OverlayPostPlan {
    Occupied,
    P1(PreparedPost),
    Suppressed,
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
    peers: HashMap<(Ipv4Addr, u16), PeerPgp>,
    channel_eoa: HashMap<u16, String>,
    known_ports: HashSet<u16>,
    post_tx: Option<mpsc::Sender<PostJob>>,
    user_secrets: Vec<SecretCert>,
    tun_tx: Option<mpsc::Sender<Vec<u8>>>,
    inbound_rx: Option<mpsc::Receiver<String>>,
    pending: Option<PendingOverlay>,
    channel_wire: HashMap<u16, ChannelWire>,
    duplex: Arc<Mutex<HashMap<DuplexKey, DuplexSession>>>,
    /// Clone of the listen inbound sender so occupy TCP AES can share the queue.
    inbound_feed: Option<mpsc::Sender<String>>,
    proxy_registry: proxy::ProxyRegistry,
    proxy_receivers: Arc<Mutex<HashMap<String, mpsc::Sender<Vec<u8>>>>>,
    proxy_seq: Arc<AtomicU64>,
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
            inbound_feed: None,
            proxy_registry: proxy::ProxyRegistry::new(Vec::new()),
            proxy_receivers: Arc::new(Mutex::new(HashMap::new())),
            proxy_seq: Arc::new(AtomicU64::new(1)),
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
                channel_eoa.insert(ch.port, ch.routing_eoa.clone());
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
                Ok(mut keys) => {
                    if let LocatorHost::Eoa(peer_eoa) = &peer.locator.host {
                        keys.peer_eoa = peer_eoa.clone();
                    }
                    for port in peer.tcp_ports.iter().chain(peer.udp_ports.iter()) {
                        peers.insert((peer.vip, *port), keys.clone());
                    }
                    // Client targets may use ports absent from peers.*.ports.
                    for client in &cfg.clients {
                        let LocatorHost::Eoa(client_eoa) = &client.host else {
                            continue;
                        };
                        let LocatorHost::Eoa(peer_eoa) = &peer.locator.host else {
                            continue;
                        };
                        if eip191::eoa_eq(client_eoa, peer_eoa) {
                            peers.insert((peer.vip, client.port), keys.clone());
                        }
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
        let channel_wire = load_channel_wires(cfg);
        let duplex = Arc::new(Mutex::new(HashMap::new()));
        let proxy_receivers = Arc::new(Mutex::new(HashMap::new()));
        let proxy_seq = Arc::new(AtomicU64::new(1));
        let proxy_registry = proxy::ProxyRegistry::new(cfg.l0.proxies.clone());
        let pipe_extras = PipeExtras {
            inbound_tx: Some(inbound_tx.clone()),
            proxy_registry: proxy_registry.clone(),
            proxy_receivers: proxy_receivers.clone(),
            proxy_seq: proxy_seq.clone(),
        };
        let pipe_rebuild = L0PipeRebuild {
            duplex: duplex.clone(),
            wires: Arc::new(channel_wire.clone()),
            peers: Arc::new(peers.clone()),
            extras: pipe_extras.clone(),
        };
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
                spawn_legacy_listen_into(
                    cfg,
                    &routing_eoa,
                    !user_secrets.is_empty(),
                    inbound_tx.clone(),
                    Some(pipe_rebuild.clone()),
                )
            } else {
                spawn_channel_listens_into(
                    cfg,
                    &mut user_secrets,
                    inbound_tx.clone(),
                    Some(pipe_rebuild.clone()),
                )
            };
            spawn_duplex_runtime(cfg, &channel_wire, &peers, duplex.clone(), post_tx.clone());
        }
        let inbound_rx = if listen_spawned {
            Some(inbound_rx_ch)
        } else {
            None
        };
        let inbound_feed = if listen_spawned {
            Some(inbound_tx)
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
            inbound_feed,
            proxy_registry,
            proxy_receivers,
            proxy_seq,
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

    /// Resolve a configured proxy for one logical port. The returned line is
    /// newly allocated for the caller's session and never shares a socket or
    /// identity with another line.
    pub fn proxy_line(
        &self,
        session_id: &str,
        port: u16,
    ) -> Result<Option<proxy::ProxyLine>, L0dError> {
        self.proxy_registry.line(session_id, port)
    }

    /// Attach the byte stream of a dynamic proxy line to a duplex session.
    /// The receiver is owned by exactly one proxy task.
    pub fn open_proxy_session(
        &mut self,
        session_id: &str,
        port: u16,
    ) -> Result<Option<(proxy::ProxyLine, mpsc::Receiver<Vec<u8>>)>, L0dError> {
        let Some(line) = self.proxy_line(session_id, port)? else {
            return Ok(None);
        };
        let (tx, rx) = mpsc::channel(64);
        let mut receivers = self
            .proxy_receivers
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if receivers.insert(session_id.to_string(), tx).is_some() {
            return Ok(None);
        }
        Ok(Some((line, rx)))
    }

    /// Start the per-line upstream task. The returned receiver is the only
    /// path by which upstream bytes can return to this session's occupied
    /// pipe; callers must drain it and call `send_proxy_bytes` for that same
    /// `session_id`.
    pub fn start_proxy_session(
        &mut self,
        session_id: &str,
        port: u16,
    ) -> Result<Option<mpsc::Receiver<Vec<u8>>>, L0dError> {
        let Some((line, incoming)) = self.open_proxy_session(session_id, port)? else {
            return Ok(None);
        };
        let (outgoing, outgoing_rx) = mpsc::channel(64);
        let session = session_id.to_owned();
        tokio::spawn(async move {
            if let Err(err) = proxy::run_proxy_line(line, incoming, outgoing).await {
                tracing::debug!(session = %session, error = %err, "proxy line closed");
            }
        });
        Ok(Some(outgoing_rx))
    }

    pub fn close_proxy_session(&mut self, session_id: &str) {
        self.proxy_receivers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(session_id);
    }

    /// Encode bytes from the local upstream socket onto one occupied pipe.
    pub fn send_proxy_bytes(&mut self, session_id: &str, payload: &[u8]) -> Result<(), L0dError> {
        let seq = self.proxy_seq.fetch_add(1, Ordering::Relaxed);
        try_send_proxy_frame(&self.duplex, session_id, seq, payload)
    }

    fn pipe_extras(&self) -> PipeExtras {
        PipeExtras {
            inbound_tx: self.inbound_feed.clone(),
            proxy_registry: self.proxy_registry.clone(),
            proxy_receivers: self.proxy_receivers.clone(),
            proxy_seq: self.proxy_seq.clone(),
        }
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
        if duplex::parse_l0_occupied(trimmed) {
            tracing::info!("l0_occupied on exclusive listen SSE");
            return Ok(0);
        }
        if duplex::looks_like_aes_blob(trimmed) {
            return self.apply_duplex_aes_blob(trimmed);
        }
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

    fn apply_duplex_aes_blob(&mut self, blob: &str) -> Result<usize, L0dError> {
        let keys: Vec<[u8; aes::KEY_LEN]> = {
            let guard = self.duplex.lock().unwrap_or_else(|p| p.into_inner());
            guard.values().filter_map(|s| s.key).collect()
        };
        let mut last = L0dError::L0("AES blob did not open with any duplex key".into());
        for key in keys {
            match aes::open(&key, blob) {
                Ok(plain) => match String::from_utf8(plain) {
                    Ok(json) => {
                        if let Some(session_id) = duplex::parse_duplex_ping_json(&json) {
                            let mut guard = self.duplex.lock().unwrap_or_else(|p| p.into_inner());
                            if let Some(sess) =
                                guard.values_mut().find(|s| s.session_id == session_id)
                            {
                                sess.peer_return_attached = true;
                                return Ok(0);
                            }
                            return Err(L0dError::L0(
                                "duplex_ping has no matching pipe handle".into(),
                            ));
                        }
                        return self.apply_inbound_armor(&json);
                    }
                    Err(err) => last = L0dError::L0(format!("duplex AES plaintext utf8: {err}")),
                },
                Err(err) => last = err,
            }
        }
        self.inbound_refused = self.inbound_refused.saturating_add(1);
        tracing::warn!(
            error = %last,
            blob_chars = blob.len(),
            "duplex AES blob did not open"
        );
        Err(last)
    }

    fn apply_duplex_frame(
        &mut self,
        session_id: &str,
        payload_b64: &str,
    ) -> Result<usize, L0dError> {
        let has_session = {
            let guard = self.duplex.lock().unwrap_or_else(|p| p.into_inner());
            guard
                .values()
                .any(|s| s.session_id == session_id && s.key.is_some())
        };
        if !has_session {
            self.inbound_refused = self.inbound_refused.saturating_add(1);
            return Err(L0dError::L0(
                "duplex_frame has no overlay key yet; waiting for duplex_offer".into(),
            ));
        };
        let framed = Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            payload_b64.trim(),
        )
        .map_err(|e| L0dError::L0(format!("duplex_frame payload base64: {e}")))?;
        let (_seq, payload) = frame::decode(&framed)?;
        let inbound = payload.to_vec();
        // TUN clients seal full IPv4 datagrams. Proxy drain expects raw TCP
        // stream bytes only. Prefer TUN whenever the frame is IPv4 so hub
        // geth/beacon can complete TCP over the overlay VIP (+ listen-DNAT).
        let n = if listen::looks_like_ipv4(&inbound) {
            self.queue_inbound_ipv4(inbound)?
        } else {
            let receivers = self
                .proxy_receivers
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if let Some(tx) = receivers.get(session_id) {
                tx.try_send(inbound.clone())
                    .map_err(|_| L0dError::L0("proxy session inbound queue is full".into()))?;
                inbound.len()
            } else {
                drop(receivers);
                self.inbound_refused = self.inbound_refused.saturating_add(1);
                return Err(L0dError::L0(
                    "duplex plaintext is not IPv4 and no proxy drain is attached".into(),
                ));
            }
        };
        {
            let mut guard = self.duplex.lock().unwrap_or_else(|p| p.into_inner());
            for sess in guard.values_mut() {
                if sess.session_id == session_id {
                    sess.peer_return_attached = true;
                    break;
                }
            }
        }
        Ok(n)
    }

    fn apply_duplex_offer(&mut self, offer: duplex::DuplexOffer) {
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        if duplex_offer_is_expired(offer.timestamp, now) {
            tracing::info!(
                session = %offer.session_id,
                from = %offer.from,
                port = offer.port,
                offer_ts = offer.timestamp,
                now,
                max_age_secs = DUPLEX_OFFER_MAX_AGE_SECS,
                "duplex_offer expired by absolute age; ignored"
            );
            return;
        }
        // (wire, initiator_listen, mailbox_route, sess, initiator_pipe_pgp)
        let mut send_accept: Option<(ChannelWire, String, String, DuplexSession, String)> = None;
        let mut send_reject: Option<(ChannelWire, String, String, [u8; aes::KEY_LEN], String)> =
            None;
        let mut offer_matched = false;
        let mut offer_duplicate_ignored = false;
        {
            let mut guard = self.duplex.lock().unwrap_or_else(|p| p.into_inner());
            let mut rekey_from: Option<DuplexKey> = None;
            for (map_key, sess) in guard.iter_mut() {
                let session_id_matches = sess.session_id == offer.session_id;
                // `host_eoa` is this daemon's channel wallet, while
                // `listen_wallet` belongs to the remote daemon. They must
                // not be compared when matching a pending session. The
                // configured peer EOA already identifies the port.
                let offer_is_current = offer.timestamp.saturating_add(DUPLEX_OFFER_CLOCK_SKEW_SECS)
                    >= sess.created_at
                    && offer.timestamp <= now.saturating_add(DUPLEX_OFFER_CLOCK_SKEW_SECS);
                let pending_peer_matches = sess.key.is_none()
                    && offer_is_current
                    && sess.peer_eoa.eq_ignore_ascii_case(&offer.from)
                    && sess.host_eoa.eq_ignore_ascii_case(&offer.main_wallet)
                    && sess.port == offer.port;
                if !session_id_matches && !pending_peer_matches {
                    continue;
                }
                offer_matched = true;
                if pending_peer_matches && sess.session_id != offer.session_id {
                    // Local pending handle adopts the initiator session id; map key must follow.
                    rekey_from = Some(map_key.clone());
                    sess.session_id = offer.session_id.clone();
                }
                let had_key = sess.key.is_some();
                sess.key = Some(offer.key);
                sess.peer_listen_wallet = Some(offer.listen_wallet.clone());
                if !offer.listen_user_pgp.trim().is_empty() {
                    sess.peer_listen_user_pgp = Some(offer.listen_user_pgp.clone());
                }
                if !had_key {
                    match crate::l0::identity::TemporaryIdentity::generate() {
                        Ok(identity) => {
                            tracing::info!(
                                session = %offer.session_id,
                                main_wallet = %offer.main_wallet,
                                port = offer.port,
                                temporary_wallet = %identity.wallet_address(),
                                "allocated temporary duplex identity for accepted line"
                            );
                            sess.accept_identity = Some(identity);
                        }
                        Err(err) => {
                            tracing::warn!(
                                session = %offer.session_id,
                                error = %err,
                                "failed to allocate temporary duplex identity"
                            );
                            sess.rejected = true;
                            return;
                        }
                    }
                    sess.peer_attached = true;
                    sess.rejected = false;
                    tracing::info!(
                        session = %offer.session_id,
                        from = %offer.from,
                        listen = %offer.listen_wallet,
                        "duplex_offer accepted; overlay AES key stored in memory only"
                    );
                    if let Some(wire) = self.channel_wire.get(&sess.port) {
                        if let Some(keys) = self.peers.get(&(sess.dest, sess.port)) {
                            send_accept = Some((
                                wire.clone(),
                                offer.listen_wallet.clone(),
                                keys.route.0.clone(),
                                sess.clone(),
                                offer.listen_user_pgp.clone(),
                            ));
                        }
                    }
                } else if sess.pipe_tx.is_none() && !sess.rejected && !sess.pipe_connect_inflight {
                    tracing::info!(
                        session = %offer.session_id,
                        port = sess.port,
                        "duplex_offer observed by initiator; keeping single l0_connect owner"
                    );
                } else if duplex_duplicate_offer_should_ignore(sess, true) {
                    offer_duplicate_ignored = true;
                    tracing::debug!(
                        session = %offer.session_id,
                        port = sess.port,
                        pipe_up = sess.pipe_tx.is_some(),
                        pipe_inflight = sess.pipe_connect_inflight,
                        rejected = sess.rejected,
                        "duplex_offer duplicate ignored"
                    );
                }
                break;
            }
            if let Some(old_key) = rekey_from {
                if let Some(sess) = guard.remove(&old_key) {
                    guard.insert(duplex_key_of(&sess), sess);
                }
            }
            // Same mainWallet:port may host many independent lines. If this offer
            // did not hit a pending/local handle, open a fresh session instead of
            // rejecting (multiline proxy / additional overlay clients).
            if !offer_matched {
                let host_ok = self
                    .channel_wire
                    .get(&offer.port)
                    .map(|w| w.main_wallet.eq_ignore_ascii_case(&offer.main_wallet))
                    .unwrap_or(false);
                if host_ok {
                    // Mailbox offline flush can replay an older process's
                    // duplex_offer after a live line is already up. Prefer the
                    // live peer:port session over a stale armored offer.
                    if duplex_stale_offer_should_skip_additional(
                        &guard,
                        &offer.from,
                        offer.port,
                        offer.timestamp,
                    ) {
                        tracing::info!(
                            session = %offer.session_id,
                            from = %offer.from,
                            port = offer.port,
                            offer_ts = offer.timestamp,
                            "duplex_offer stale vs live peer:port; ignored"
                        );
                    } else {
                        let dest = guard
                            .values()
                            .find(|s| {
                                s.port == offer.port && s.peer_eoa.eq_ignore_ascii_case(&offer.from)
                            })
                            .map(|s| s.dest)
                            .or_else(|| {
                                self.peers
                                    .iter()
                                    .find(|((_, p), keys)| {
                                        *p == offer.port
                                            && !keys.peer_eoa.is_empty()
                                            && keys.peer_eoa.eq_ignore_ascii_case(&offer.from)
                                    })
                                    .map(|((vip, _), _)| *vip)
                            })
                            .or_else(|| {
                                self.peers
                                    .keys()
                                    .find(|(_, p)| *p == offer.port)
                                    .map(|(vip, _)| *vip)
                            });
                        if let Some(dest) = dest {
                            let Some(wire) = self.channel_wire.get(&offer.port).cloned() else {
                                // unreachable: host_ok already checked
                                return;
                            };
                            let Some(keys) = self.peers.get(&(dest, offer.port)).cloned() else {
                                tracing::warn!(
                                    session = %offer.session_id,
                                    port = offer.port,
                                    "multiline duplex_offer missing peer PGP; rejecting"
                                );
                                return;
                            };
                            // One occupy pipe per peer listen wallet. Drop conflicting
                            // ghost sessions so their TCP EOF frees SI exclusive occupy
                            // before this line's l0_connect (avoids sustained 409).
                            let retired = retire_conflicting_duplex_sessions(
                                &mut guard,
                                &self.proxy_receivers,
                                &offer.from,
                                offer.port,
                                &offer.session_id,
                            );
                            if retired > 0 {
                                tracing::info!(
                                    session = %offer.session_id,
                                    from = %offer.from,
                                    port = offer.port,
                                    retired,
                                    "retired conflicting duplex sessions for peer:port"
                                );
                            }
                            let identity = match crate::l0::identity::TemporaryIdentity::generate()
                            {
                                Ok(identity) => identity,
                                Err(err) => {
                                    tracing::warn!(
                                        session = %offer.session_id,
                                        error = %err,
                                        "failed to allocate temporary duplex identity"
                                    );
                                    return;
                                }
                            };
                            let sess = DuplexSession {
                                session_id: offer.session_id.clone(),
                                created_at: chrono::Utc::now().timestamp().max(0) as u64,
                                key: Some(offer.key),
                                dest,
                                port: offer.port,
                                peer_eoa: offer.from.clone(),
                                guest_up: true,
                                peer_attached: true,
                                rejected: false,
                                // Match key is mainWallet:port; channel EOA is listen only.
                                host_eoa: wire.main_wallet.clone(),
                                peer_listen_user_pgp: if offer.listen_user_pgp.trim().is_empty() {
                                    None
                                } else {
                                    Some(offer.listen_user_pgp.clone())
                                },
                                peer_listen_wallet: Some(offer.listen_wallet.clone()),
                                accept_identity: Some(identity),
                                peer_return_attached: false,
                                pipe_tx: None,
                                pipe_gen: 0,
                                pipe_connect_inflight: false,
                            };
                            tracing::info!(
                                session = %offer.session_id,
                                main_wallet = %offer.main_wallet,
                                port = offer.port,
                                dest = %dest,
                                temporary_wallet = %sess
                                    .accept_identity
                                    .as_ref()
                                    .map(|i| i.wallet_address().to_owned())
                                    .unwrap_or_default(),
                                "duplex_offer opened additional line on mainWallet:port"
                            );
                            guard.insert(duplex_key_of(&sess), sess.clone());
                            offer_matched = true;
                            send_accept = Some((
                                wire,
                                offer.listen_wallet.clone(),
                                keys.route.0.clone(),
                                sess,
                                offer.listen_user_pgp.clone(),
                            ));
                        }
                    }
                }
            }
        }
        if offer_matched && offer_duplicate_ignored {
            return;
        }
        if let Some((wire, target, route, sess, initiator_pipe_pgp)) = send_accept {
            // A proxy accept owns a fresh SI listen identity.  Start that
            // listen before sending the accept so the initiator's subsequent
            // l0_connect is addressed to a real per-line mailbox, rather than
            // the channel EOA shared by every client on this logical port.
            self.spawn_dynamic_accept_listen(&wire, &sess);
            // Chat gossip duplex_accept (control plane), then reverse occupy the
            // initiator's listenWallet so each endpoint owns a separate occupied
            // pipe bound by the same pipe_handle (RULES dedicated-pipe section).
            spawn_duplex_accept_chat(
                wire.clone(),
                initiator_pipe_pgp,
                sess.clone(),
                self.duplex.clone(),
            );
            spawn_l0_pipe(
                wire,
                route,
                target,
                None,
                sess,
                self.duplex.clone(),
                self.pipe_extras(),
            );
            return;
        }
        tracing::warn!(
            session = %offer.session_id,
            "duplex_offer did not match a local session; sending duplex_reject"
        );
        if let Some(wire) = self.channel_wire.values().next() {
            if let Some(keys) = self.peers.values().next() {
                send_reject = Some((
                    wire.clone(),
                    offer.listen_wallet.clone(),
                    keys.route.0.clone(),
                    offer.key,
                    offer.session_id.clone(),
                ));
            }
        }
        if let Some((wire, target, route, key, session_id)) = send_reject {
            let ts = chrono::Utc::now().timestamp().max(0) as u64;
            let first = duplex::encode_reject_command(&wire.eoa, &session_id, ts)
                .ok()
                .and_then(|json| aes::seal(&key, json.as_bytes()).ok());
            let dummy = DuplexSession {
                session_id,
                created_at: 0,
                key: Some(key),
                dest: Ipv4Addr::UNSPECIFIED,
                port: 0,
                peer_eoa: String::new(),
                guest_up: false,
                peer_attached: false,
                rejected: true,
                host_eoa: wire.eoa.clone(),
                peer_listen_user_pgp: None,
                peer_listen_wallet: Some(target.clone()),
                accept_identity: None,
                peer_return_attached: false,
                pipe_tx: None,
                pipe_gen: 0,
                pipe_connect_inflight: false,
            };
            spawn_l0_pipe(
                wire,
                route,
                target,
                first,
                dummy,
                self.duplex.clone(),
                PipeExtras::empty(),
            );
        }
    }

    fn spawn_dynamic_accept_listen(&self, wire: &ChannelWire, sess: &DuplexSession) {
        let Some(identity) = sess.accept_identity.as_ref() else {
            return;
        };
        let Some(tx) = self.inbound_feed.clone() else {
            tracing::warn!(
                session = %sess.session_id,
                "cannot start temporary duplex listen: inbound feed is unavailable"
            );
            return;
        };
        let rebuild = L0PipeRebuild {
            duplex: self.duplex.clone(),
            wires: Arc::new(self.channel_wire.clone()),
            peers: Arc::new(self.peers.clone()),
            extras: self.pipe_extras(),
        };
        let started = spawn_listen_worker(
            wire.listen_entries.clone(),
            wire.route_pgp.clone(),
            identity.wallet_address().to_owned(),
            wire.eth.clone(),
            tx,
            true,
            Some(rebuild),
            Some(wire.main_wallet.clone()),
            Some(wire.eth.clone()),
            Some(identity.clone()),
        );
        if started {
            tracing::info!(
                session = %sess.session_id,
                port = sess.port,
                temporary_wallet = %identity.wallet_address(),
                "started per-line temporary l0_listen"
            );
        }
    }

    fn apply_duplex_accept(&mut self, accept: duplex::DuplexAccept) {
        let mut launch: Option<(ChannelWire, String, String, DuplexSession)> = None;
        {
            let mut guard = self.duplex.lock().unwrap_or_else(|p| p.into_inner());
            for sess in guard.values_mut() {
                if sess.session_id != accept.session_id {
                    continue;
                }
                if let Some(own) = sess.key {
                    if own != accept.key {
                        tracing::warn!(
                            session = %accept.session_id,
                            "duplex_accept Securitykey mismatch; closing duplex line and discarding traffic"
                        );
                        sess.rejected = true;
                        sess.peer_attached = false;
                        return;
                    }
                } else {
                    sess.key = Some(accept.key);
                }
                if !accept.listen_user_pgp.trim().is_empty() {
                    sess.peer_listen_user_pgp = Some(accept.listen_user_pgp.clone());
                }
                sess.peer_listen_wallet = Some(accept.listen_wallet.clone());
                sess.peer_attached = true;
                sess.rejected = false;
                tracing::info!(
                    session = %accept.session_id,
                    peer_listen = %accept.listen_wallet,
                    "duplex_accept on occupied L0 SSE"
                );
                // Chat may deliver accept before/after the L0 first-blob path;
                // only open one return pipe.
                if sess.pipe_tx.is_some() {
                    break;
                }
                if let Some(wire) = self.channel_wire.get(&sess.port) {
                    if let Some(keys) = self.peers.get(&(sess.dest, sess.port)) {
                        launch = Some((
                            wire.clone(),
                            accept.listen_wallet.clone(),
                            keys.route.0.clone(),
                            sess.clone(),
                        ));
                    }
                }
                break;
            }
        }
        if let Some((wire, target, route, sess)) = launch {
            spawn_l0_pipe(
                wire,
                route,
                target,
                None,
                sess,
                self.duplex.clone(),
                self.pipe_extras(),
            );
        }
    }

    fn mark_duplex_rejected(&mut self, session_id: &str) {
        let mut guard = self.duplex.lock().unwrap_or_else(|p| p.into_inner());
        for sess in guard.values_mut() {
            if sess.session_id == session_id {
                sess.rejected = true;
                sess.peer_attached = false;
                tracing::info!(
                    session = %session_id,
                    "duplex_reject on session listen SSE; duplex line closed and traffic discarded"
                );
                return;
            }
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
            Ok(OverlayPostPlan::Occupied) => {
                self.frames_ready = self.frames_ready.saturating_add(packet_count as u64);
                tracing::info!(
                    dest = %pending.dest,
                    port = pending.port,
                    locator = %pending.loc.display(),
                    seq = self.seq,
                    packets = packet_count,
                    frame_bytes = framed.len(),
                    "duplex AES frame written on occupied l0_connect pipe"
                );
            }
            Ok(OverlayPostPlan::P1(prepared)) => {
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
                self.enqueue_post(
                    prepared,
                    pending.dest,
                    &pending.loc,
                    raw.len(),
                    packet_count,
                );
            }
            Ok(OverlayPostPlan::Suppressed) => {
                self.posts_dropped = self.posts_dropped.saturating_add(1);
                tracing::warn!(
                    dest = %pending.dest,
                    port = pending.port,
                    packets = packet_count,
                    dropped = self.posts_dropped,
                    "duplex handshake pending; P1 fallback disabled, overlay batch dropped"
                );
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
    ) -> Result<OverlayPostPlan, L0dError> {
        let keys = self.peers.get(&(dest, port)).ok_or_else(|| {
            L0dError::L0("peer user+route PGP public files are required; refusing POST".into())
        })?;
        let entry = self
            .entries
            .first()
            .ok_or_else(|| L0dError::L0("l0.entries is empty; refusing POST".into()))?;
        let url = post::post_url(entry)?;
        if let Some(sess) = duplex_live_session(&self.duplex, dest, port) {
            if !sess.rejected {
                if let (Some(key), Some(tx)) = (sess.key, sess.pipe_tx.as_ref()) {
                    let framed = frame::encode(seq, packet);
                    let blob = duplex::seal_frame(&key, &sess.session_id, &framed)?;
                    match tx.try_send(blob) {
                        Ok(()) => return Ok(OverlayPostPlan::Occupied),
                        Err(_) => {
                            tracing::warn!(
                                dest = %dest,
                                port,
                                "occupied l0 pipe queue full; P1 fallback disabled"
                            );
                            return Ok(OverlayPostPlan::Suppressed);
                        }
                    }
                }

                // A configured duplex session owns this traffic while it is
                // negotiating or recovering. Do not race l0_connect retries
                // with P1 packets, which can leave the peer with stale traffic.
                return Ok(OverlayPostPlan::Suppressed);
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
        Ok(OverlayPostPlan::P1(PreparedPost { url, armor }))
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
        peer_eoa: String::new(),
    })
}

fn spawn_legacy_listen_into(
    cfg: &ValidatedConfig,
    routing_eoa: &str,
    has_secret: bool,
    tx: mpsc::Sender<String>,
    pipe_rebuild: Option<L0PipeRebuild>,
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
    let chat = spawn_listen_worker(
        cfg.l0.listen_entries.clone(),
        route.clone(),
        routing_eoa.to_string(),
        eth.clone(),
        tx.clone(),
        false,
        None,
        None,
        None,
        None,
    );
    let l0 = spawn_listen_worker(
        cfg.l0.listen_entries.clone(),
        route,
        routing_eoa.to_string(),
        eth,
        tx,
        true,
        pipe_rebuild,
        None,
        None,
        None,
    );
    chat || l0
}

fn spawn_channel_listens_into(
    cfg: &ValidatedConfig,
    user_secrets: &mut Vec<SecretCert>,
    tx: mpsc::Sender<String>,
    pipe_rebuild: Option<L0PipeRebuild>,
) -> bool {
    // Billing key is for duplex control only. Mailbox listen/connect must be
    // signed by the channel wallet until SI fleets ship `billingWallet`.
    if let (Some(billing_eoa), Some(path)) = (
        cfg.l0.billing_eoa.as_ref(),
        cfg.l0.billing_eth_key_file.as_ref(),
    ) {
        match eip191::load_eth_secret(path) {
            Ok(secret) if eip191::eoa_eq(secret.address(), billing_eoa) => {}
            Ok(_) => tracing::warn!(
                "l0 billing_eth_key_file does not match billing_eoa; duplex control may fail"
            ),
            Err(err) => tracing::warn!(
                error = %err,
                "l0.billing_eth_key_file was not loaded; duplex control may fail"
            ),
        }
    }
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
            route.clone(),
            ch.routing_eoa.clone(),
            eth.clone(),
            tx.clone(),
            false,
            None,
            None,
            None,
            None,
        ) {
            spawned += 1;
        }
        if spawn_listen_worker(
            ch.listen_entries.clone(),
            route,
            ch.routing_eoa.clone(),
            eth,
            tx.clone(),
            true,
            pipe_rebuild.clone(),
            cfg.l0.billing_eoa.clone(),
            cfg.l0
                .billing_eth_key_file
                .as_ref()
                .and_then(|path| eip191::load_eth_secret(path).ok()),
            None,
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
    signer_eth: EthSecret,
    tx: mpsc::Sender<String>,
    l0_exclusive: bool,
    pipe_rebuild: Option<L0PipeRebuild>,
    billing_wallet: Option<String>,
    billing_eth: Option<EthSecret>,
    temporary_identity: Option<crate::l0::identity::TemporaryIdentity>,
) -> bool {
    let Some(handle) = tokio::runtime::Handle::try_current().ok() else {
        return false;
    };
    let Ok(client) = listen::listen_http_client() else {
        return false;
    };
    handle.spawn(async move {
        if let Some(identity) = temporary_identity.as_ref() {
            let route_key_id = match pgp::transport_key_id_armored(&mailbox_route) {
                Ok(key_id) => key_id,
                Err(err) => {
                    tracing::warn!(
                        eoa = %routing_eoa,
                        error = %err,
                        "cannot derive mailbox route key id; refusing unregistered SSE"
                    );
                    return;
                }
            };
            let mut registered = false;
            for attempt in 1..=5 {
                match identity
                    .register_route("https://beamio.app/api/regiestChatRoute", &route_key_id)
                    .await
                {
                    Ok(()) => {
                        registered = true;
                        tracing::info!(
                            eoa = %identity.wallet_address(),
                            route_key_id = %route_key_id,
                            "temporary route registered"
                        );
                        break;
                    }
                    Err(err) => {
                        tracing::warn!(
                            eoa = %identity.wallet_address(),
                            attempt,
                            error = %err,
                            "temporary route registration failed"
                        );
                        tokio::time::sleep(Duration::from_secs(
                            LISTEN_RECONNECT_SECS.saturating_mul(attempt as u64),
                        ))
                        .await;
                    }
                }
            }
            if !registered {
                tracing::warn!(
                    eoa = %identity.wallet_address(),
                    "temporary route registration exhausted; refusing SSE"
                );
                return;
            }
        }
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
            let prepared = if l0_exclusive {
                match (billing_wallet.as_deref(), billing_eth.as_ref()) {
                    (Some(wallet), Some(eth)) => listen::prepare_l0_listen_post_with_billing(
                        &routing_eoa,
                        wallet,
                        ts,
                        &mailbox_route,
                        entry,
                        eth,
                    ),
                    _ => listen::prepare_l0_listen_post(
                        &routing_eoa,
                        ts,
                        &mailbox_route,
                        entry,
                        &signer_eth,
                    ),
                }
            } else {
                listen::prepare_listen_post(&routing_eoa, ts, &mailbox_route, entry, &signer_eth)
            };
            match prepared {
                Ok((url, armor)) => match listen::open_listen_sse(&client, &url, &armor).await {
                    Ok(response) => {
                        last_failed = None;
                        if l0_exclusive {
                            if let Some(ctx) = pipe_rebuild.as_ref() {
                                rebuild_l0_pipes_after_listen_up(&routing_eoa, ctx);
                            }
                        }
                        match listen::pump_sse_armors_with_idle_timeout(
                            response,
                            &tx,
                            l0_exclusive.then_some(pipe::PIPE_DATA_TIMEOUT),
                        )
                        .await
                        {
                            Ok(()) => {
                                tracing::info!(
                                    eoa = %routing_eoa,
                                    l0 = l0_exclusive,
                                    "listen SSE ended; reconnecting after idle"
                                );
                            }
                            Err(err) => {
                                if l0_exclusive
                                    && err.to_string().contains("no inbound data for 120s")
                                {
                                    clear_l0_pipe_after_listen_timeout(
                                        &routing_eoa,
                                        pipe_rebuild.as_ref(),
                                    );
                                }
                                tracing::warn!(
                                    eoa = %routing_eoa,
                                    l0 = l0_exclusive,
                                    error = %err,
                                    "listen SSE failed"
                                );
                                last_failed = Some(entry.to_string());
                            }
                        }
                    }
                    Err(err) => {
                        tracing::warn!(
                            eoa = %routing_eoa,
                            l0 = l0_exclusive,
                            error = %err,
                            "listen SSE failed"
                        );
                        last_failed = Some(entry.to_string());
                    }
                },
                Err(err) => {
                    tracing::warn!(eoa = %routing_eoa, error = %err, "listen wrap refused");
                    last_failed = Some(entry.to_string());
                }
            }
            tokio::time::sleep(Duration::from_secs(LISTEN_RECONNECT_SECS)).await;
        }
    });
    true
}

/// Whether a listen SSE reconnect should spawn a fresh outbound `l0_connect`.
fn should_rebuild_l0_pipe_after_listen_up(sess: &DuplexSession, routing_eoa: &str) -> bool {
    sess.accept_identity
        .as_ref()
        .map(|identity| eip191::eoa_eq(identity.wallet_address(), routing_eoa))
        .unwrap_or_else(|| eip191::eoa_eq(&sess.host_eoa, routing_eoa))
        && sess.peer_attached
        && !sess.rejected
        && sess.key.is_some()
        && sess.pipe_tx.is_none()
        && !sess.pipe_connect_inflight
        && sess
            .peer_listen_wallet
            .as_ref()
            .map(|w| !w.trim().is_empty())
            .unwrap_or(false)
}

fn duplex_key(dest: Ipv4Addr, port: u16, session_id: &str) -> DuplexKey {
    (dest, port, session_id.to_owned())
}

fn duplex_key_of(sess: &DuplexSession) -> DuplexKey {
    duplex_key(sess.dest, sess.port, &sess.session_id)
}

fn duplex_session_by_id(
    duplex: &Arc<Mutex<HashMap<DuplexKey, DuplexSession>>>,
    dest: Ipv4Addr,
    port: u16,
    session_id: &str,
) -> Option<DuplexSession> {
    duplex
        .lock()
        .ok()
        .and_then(|g| g.get(&duplex_key(dest, port, session_id)).cloned())
}

/// TUN / overlay path helper: prefer a ready occupied pipe on this dest:port.
/// Multiple independent lines may share the same logical port.
fn duplex_live_session(
    duplex: &Arc<Mutex<HashMap<DuplexKey, DuplexSession>>>,
    dest: Ipv4Addr,
    port: u16,
) -> Option<DuplexSession> {
    let Ok(guard) = duplex.lock() else {
        return None;
    };
    let mut best: Option<DuplexSession> = None;
    for sess in guard.values().filter(|s| s.dest == dest && s.port == port) {
        let better = match &best {
            None => true,
            Some(cur) => {
                let cur_ready = cur.pipe_tx.is_some() && cur.key.is_some() && !cur.rejected;
                let next_ready = sess.pipe_tx.is_some() && sess.key.is_some() && !sess.rejected;
                (next_ready && !cur_ready)
                    || (!cur.rejected
                        && sess.rejected == false
                        && cur.key.is_none()
                        && sess.key.is_some())
            }
        };
        if better {
            best = Some(sess.clone());
        }
    }
    best
}

/// Initiator stops re-posting `duplex_offer` once accept is observed.
fn duplex_initiator_should_stop_offer(sess: &DuplexSession) -> bool {
    sess.rejected || sess.peer_attached
}

/// Acceptor stops re-posting `duplex_accept` once the reverse occupy pipe is up
/// or the initiator has confirmed the return path with traffic.
fn duplex_acceptor_should_stop_accept(sess: &DuplexSession) -> bool {
    sess.rejected || sess.peer_return_attached || sess.pipe_tx.is_some()
}

/// Seal raw bytes onto an occupied duplex pipe (proxy upstream → peer).
fn try_send_proxy_frame(
    duplex: &Arc<Mutex<HashMap<DuplexKey, DuplexSession>>>,
    session_id: &str,
    seq: u64,
    payload: &[u8],
) -> Result<(), L0dError> {
    let framed = frame::encode(seq, payload);
    let mut guard = duplex.lock().unwrap_or_else(|p| p.into_inner());
    let Some(sess) = guard.values_mut().find(|s| s.session_id == session_id) else {
        return Err(L0dError::L0(format!(
            "proxy frame: unknown session {session_id}"
        )));
    };
    let (Some(key), Some(tx)) = (sess.key, sess.pipe_tx.as_ref()) else {
        return Err(L0dError::L0("proxy frame: occupied pipe not ready".into()));
    };
    let blob = duplex::seal_frame(&key, session_id, &framed)?;
    tx.try_send(blob)
        .map_err(|_| L0dError::L0("occupied l0 pipe queue is full".into()))?;
    Ok(())
}

/// When this endpoint is a proxy server for `port`, attach one upstream line to
/// the newly installed occupy pipe and drain upstream → AES frames.
fn maybe_start_proxy_drain(
    extras: &PipeExtras,
    duplex: Arc<Mutex<HashMap<DuplexKey, DuplexSession>>>,
    session_id: String,
    port: u16,
) {
    {
        let receivers = extras
            .proxy_receivers
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if receivers.contains_key(&session_id) {
            return;
        }
    }
    let line = match extras.proxy_registry.line(&session_id, port) {
        Ok(Some(line)) => line,
        Ok(None) => return,
        Err(err) => {
            tracing::warn!(
                session = %session_id,
                port,
                error = %err,
                "proxy line allocate refused"
            );
            return;
        }
    };
    let (to_upstream, from_peer) = mpsc::channel::<Vec<u8>>(64);
    {
        let mut receivers = extras
            .proxy_receivers
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if receivers.insert(session_id.clone(), to_upstream).is_some() {
            return;
        }
    }
    let (from_upstream, mut to_pipe) = mpsc::channel::<Vec<u8>>(64);
    let sid = session_id.clone();
    tokio::spawn(async move {
        if let Err(err) = proxy::run_proxy_line(line, from_peer, from_upstream).await {
            tracing::debug!(session = %sid, error = %err, "proxy line closed");
        }
    });
    let seq = extras.proxy_seq.clone();
    let duplex_tx = duplex;
    let session_drain = session_id.clone();
    tokio::spawn(async move {
        while let Some(bytes) = to_pipe.recv().await {
            let n = seq.fetch_add(1, Ordering::Relaxed);
            if let Err(err) = try_send_proxy_frame(&duplex_tx, &session_drain, n, &bytes) {
                tracing::debug!(
                    session = %session_drain,
                    error = %err,
                    "proxy upstream → occupied pipe failed"
                );
                break;
            }
        }
    });
    tracing::info!(session = %session_id, port, "proxy drain attached to occupied pipe");
}

/// True when `offer_timestamp` is too old (or impossibly far in the future)
/// relative to `now`. Used before any local duplex matching so mailbox replay
/// cannot open ghost additional-line sessions on a fresh daemon.
fn duplex_offer_is_expired(offer_timestamp: u64, now: u64) -> bool {
    if offer_timestamp > now.saturating_add(DUPLEX_OFFER_CLOCK_SKEW_SECS) {
        return true;
    }
    now.saturating_sub(offer_timestamp)
        > DUPLEX_OFFER_MAX_AGE_SECS.saturating_add(DUPLEX_OFFER_CLOCK_SKEW_SECS)
}

/// Mailbox may flush an older process's `duplex_offer` after a live peer:port
/// line is already occupying. Skip opening another additional line when the
/// offer timestamp is clearly older than the live session.
fn duplex_stale_offer_should_skip_additional(
    guard: &HashMap<DuplexKey, DuplexSession>,
    peer_eoa: &str,
    port: u16,
    offer_timestamp: u64,
) -> bool {
    guard.values().any(|s| {
        s.port == port
            && s.peer_eoa.eq_ignore_ascii_case(peer_eoa)
            && s.peer_attached
            && !s.rejected
            && (s.pipe_tx.is_some() || s.pipe_connect_inflight)
            && offer_timestamp.saturating_add(DUPLEX_OFFER_CLOCK_SKEW_SECS) < s.created_at
    })
}

/// Tear down other duplex sessions for the same peer EOA + port so their
/// occupy TCP observes EOF and SI exclusive listen can accept the new line.
fn retire_conflicting_duplex_sessions(
    guard: &mut HashMap<DuplexKey, DuplexSession>,
    proxy_receivers: &Arc<Mutex<HashMap<String, mpsc::Sender<Vec<u8>>>>>,
    peer_eoa: &str,
    port: u16,
    keep_session_id: &str,
) -> usize {
    let stale_keys: Vec<DuplexKey> = guard
        .iter()
        .filter(|(_, s)| {
            s.port == port
                && s.peer_eoa.eq_ignore_ascii_case(peer_eoa)
                && s.session_id != keep_session_id
        })
        .map(|(k, _)| k.clone())
        .collect();
    let mut retired = 0usize;
    for key in stale_keys {
        if let Some(mut sess) = guard.remove(&key) {
            sess.rejected = true;
            sess.peer_attached = false;
            let sid = sess.session_id.clone();
            // Dropping the last pipe_tx Sender closes the occupy task Receiver
            // → TCP EOF → mailbox B releases exclusive listen for this peer.
            drop(sess.pipe_tx.take());
            proxy_receivers
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&sid);
            tracing::info!(
                session = %sid,
                peer = %peer_eoa,
                port,
                keep = %keep_session_id,
                "retired conflicting duplex session"
            );
            retired += 1;
        }
    }
    retired
}

fn duplex_duplicate_offer_should_ignore(sess: &DuplexSession, had_key: bool) -> bool {
    had_key && (sess.pipe_tx.is_some() || sess.rejected || sess.pipe_connect_inflight)
}

fn l0_pipe_retry_secs(err: &L0dError) -> u64 {
    match err {
        L0dError::L0PipeEnd { .. } => L0_PIPE_END_RETRY_SECS,
        L0dError::L0(msg) if msg.contains("peer disconnected") => L0_PIPE_END_RETRY_SECS,
        L0dError::L0(msg) if msg.contains("409") => L0_PIPE_OCCUPIED_RETRY_SECS,
        _ => L0_PIPE_RETRY_SECS,
    }
}

/// Occupy TCP ended (`Ok` EOF or `Err`). Drop a stale `pipe_tx` so TUN does
/// not keep sending into a dead channel (P1 / SYN-SENT). Retry while attached.
fn l0_pipe_closed_should_retry(
    duplex: &Arc<Mutex<HashMap<DuplexKey, DuplexSession>>>,
    dest: Ipv4Addr,
    port: u16,
    session_id: &str,
    gen: u64,
) -> bool {
    let mut guard = duplex.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(live) = guard.get_mut(&duplex_key(dest, port, session_id)) {
        if live.pipe_gen == gen {
            live.pipe_tx = None;
            return live.peer_attached && !live.rejected;
        }
    }
    false
}

/// After exclusive `l0_listen` HTTP 200 (SSE still live on mailbox B), rebuild
/// outbound occupy pipes for duplex sessions that already have `peer_attached`.
/// Do not call this after `pump_sse_armors` returns — B no longer has this listen.
fn rebuild_l0_pipes_after_listen_up(routing_eoa: &str, ctx: &L0PipeRebuild) {
    let to_launch: Vec<DuplexSession> = {
        let guard = ctx.duplex.lock().unwrap_or_else(|p| p.into_inner());
        guard
            .values()
            .filter(|s| should_rebuild_l0_pipe_after_listen_up(s, routing_eoa))
            .cloned()
            .collect()
    };
    for sess in to_launch {
        let Some(wire) = ctx.wires.get(&sess.port).cloned() else {
            continue;
        };
        let Some(keys) = ctx.peers.get(&(sess.dest, sess.port)) else {
            continue;
        };
        let Some(target) = sess.peer_listen_wallet.clone() else {
            continue;
        };
        tracing::info!(
            session = %sess.session_id,
            eoa = %routing_eoa,
            target = %target,
            "L0 listen up — rebuilding l0_connect"
        );
        spawn_l0_pipe(
            wire,
            keys.route.0.clone(),
            target,
            None,
            sess,
            ctx.duplex.clone(),
            ctx.extras.clone(),
        );
    }
}

/// The listen SSE is the peer's return path. If its inbound-data deadline
/// expires, discard the local writer so the next successful listen POST can
/// issue a fresh `l0_connect` request instead of queueing TUN traffic into a
/// stale channel. The occupied TCP peer will observe EOF and run its own
/// retry path.
fn clear_l0_pipe_after_listen_timeout(routing_eoa: &str, ctx: Option<&L0PipeRebuild>) {
    let Some(ctx) = ctx else {
        return;
    };
    let mut guard = ctx.duplex.lock().unwrap_or_else(|p| p.into_inner());
    for live in guard.values_mut() {
        let owns_listen = live
            .accept_identity
            .as_ref()
            .map(|identity| eip191::eoa_eq(identity.wallet_address(), routing_eoa))
            .unwrap_or_else(|| eip191::eoa_eq(&live.host_eoa, routing_eoa));
        if owns_listen {
            live.pipe_tx = None;
            live.peer_return_attached = false;
            tracing::warn!(
                session = %live.session_id,
                port = live.port,
                "listen SSE idle timeout cleared local occupied pipe"
            );
        }
    }
}

fn load_channel_wires(cfg: &ValidatedConfig) -> HashMap<u16, ChannelWire> {
    let mut out = HashMap::new();
    if !cfg.l0.channels.is_empty() {
        for ch in &cfg.l0.channels {
            let channel_eth = match eip191::load_eth_secret(&ch.routing_eth_key_file) {
                Ok(secret) if eip191::eoa_eq(secret.address(), &ch.routing_eoa) => secret,
                _ => continue,
            };
            let eth = match cfg.l0.billing_eth_key_file.as_ref() {
                Some(path) => match eip191::load_eth_secret(path) {
                    Ok(secret) => {
                        if let Some(eoa) = cfg.l0.billing_eoa.as_ref() {
                            if !eip191::eoa_eq(secret.address(), eoa) {
                                continue;
                            }
                        }
                        secret
                    }
                    _ => continue,
                },
                None => channel_eth.clone(),
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
            let main_wallet = cfg
                .l0
                .billing_eoa
                .clone()
                .unwrap_or_else(|| ch.routing_eoa.clone());
            out.insert(
                ch.port,
                ChannelWire {
                    eoa: ch.routing_eoa.clone(),
                    main_wallet,
                    route_pgp: route.clone(),
                    eth: eth.clone(),
                    si_eth: channel_eth,
                    listen_entries: listen_entries.clone(),
                    entries: cfg.l0.entries.clone(),
                    user_pub: user_pub.clone(),
                },
            );
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
                main_wallet: eoa.clone(),
                route_pgp: route.clone(),
                eth: eth.clone(),
                si_eth: eth.clone(),
                listen_entries: cfg.l0.listen_entries.clone(),
                entries: cfg.l0.entries.clone(),
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
    duplex: Arc<Mutex<HashMap<DuplexKey, DuplexSession>>>,
    _post_tx: Option<mpsc::Sender<PostJob>>,
) {
    if wires.is_empty() {
        return;
    }
    {
        let mut map = duplex.lock().unwrap_or_else(|p| p.into_inner());
        // Proxy-only servers only accept inbound `duplex_offer` (multiline). Do not
        // seed peer-port initiator races toward clients.
        if !cfg.proxy_server_only() {
            for peer in &cfg.peers {
                let LocatorHost::Eoa(peer_eoa) = &peer.locator.host else {
                    continue;
                };
                for port in peer.tcp_ports.iter().chain(peer.udp_ports.iter()) {
                    // Ports owned by `--client` are seeded below as always-initiator.
                    if cfg.clients.iter().any(|c| {
                        c.port == *port
                            && matches!(&c.host, LocatorHost::Eoa(e) if eip191::eoa_eq(e, peer_eoa))
                    }) {
                        continue;
                    }
                    let Some(wire) = wires.get(port) else {
                        continue;
                    };
                    if !peers.contains_key(&(peer.vip, *port)) {
                        continue;
                    }
                    let session_id = duplex::new_pipe_handle();
                    let initiator = duplex::we_are_initiator(&wire.eoa, peer_eoa).unwrap_or(false);
                    let key = if initiator {
                        Some(aes::generate_key())
                    } else {
                        None
                    };
                    map.insert(
                        duplex_key(peer.vip, *port, &session_id),
                        DuplexSession {
                            session_id,
                            created_at: chrono::Utc::now().timestamp().max(0) as u64,
                            key,
                            dest: peer.vip,
                            port: *port,
                            peer_eoa: peer_eoa.clone(),
                            guest_up: true,
                            peer_attached: false,
                            rejected: false,
                            // Pending match compares host_eoa to offer.main_wallet.
                            host_eoa: wire.main_wallet.clone(),
                            peer_listen_user_pgp: None,
                            peer_listen_wallet: None,
                            accept_identity: None,
                            peer_return_attached: false,
                            pipe_tx: None,
                            pipe_gen: 0,
                            pipe_connect_inflight: false,
                        },
                    );
                }
            }
        }
        // `--client web3://<mainWallet>:port` always initiates toward that
        // mainWallet:port (independent of EOA lexicographic order).
        for client in &cfg.clients {
            let LocatorHost::Eoa(peer_eoa) = &client.host else {
                tracing::warn!(
                    target = %client.display(),
                    "client target tag hosts are not seeded yet; use an EOA"
                );
                continue;
            };
            let Some(peer) = cfg.peers.iter().find(|p| match &p.locator.host {
                LocatorHost::Eoa(e) => eip191::eoa_eq(e, peer_eoa),
                LocatorHost::Tag(_) => false,
            }) else {
                tracing::warn!(
                    target = %client.display(),
                    "client target has no matching peer VIP; duplex not seeded"
                );
                continue;
            };
            let Some(wire) = wires.get(&client.port) else {
                continue;
            };
            if !peers.contains_key(&(peer.vip, client.port)) {
                tracing::warn!(
                    target = %client.display(),
                    vip = %peer.vip,
                    "client target missing peer PGP for port; duplex not seeded"
                );
                continue;
            }
            let already = map.values().any(|s| {
                s.dest == peer.vip && s.port == client.port && eip191::eoa_eq(&s.peer_eoa, peer_eoa)
            });
            if already {
                continue;
            }
            let session_id = duplex::new_pipe_handle();
            let key = Some(aes::generate_key());
            tracing::info!(
                target = %client.display(),
                vip = %peer.vip,
                "seeded duplex initiator from --client"
            );
            map.insert(
                duplex_key(peer.vip, client.port, &session_id),
                DuplexSession {
                    session_id,
                    created_at: chrono::Utc::now().timestamp().max(0) as u64,
                    key,
                    dest: peer.vip,
                    port: client.port,
                    peer_eoa: peer_eoa.clone(),
                    guest_up: true,
                    peer_attached: false,
                    rejected: false,
                    host_eoa: wire.main_wallet.clone(),
                    peer_listen_user_pgp: None,
                    peer_listen_wallet: None,
                    accept_identity: None,
                    peer_return_attached: false,
                    pipe_tx: None,
                    pipe_gen: 0,
                    pipe_connect_inflight: false,
                },
            );
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
            spawn_duplex_offer(
                wire.clone(),
                keys.user.0.clone(),
                peer_eoa.clone(),
                sess,
                duplex.clone(),
            );
        }
    }
}

fn wire_post_entries(wire: &ChannelWire) -> Vec<String> {
    if wire.entries.is_empty() {
        wire.listen_entries.clone()
    } else {
        wire.entries.clone()
    }
}

async fn post_control_armor_with_retry(entries: &[String], armor: &str, label: &'static str) {
    let Ok(client) = post::http_client() else {
        tracing::warn!(label, "duplex control POST: no HTTP client");
        return;
    };
    loop {
        match post::send_via_entries(&client, entries, armor).await {
            Ok((status, entry)) if (200..300).contains(&status) => {
                tracing::info!(status, entry, label, "duplex control POST accepted");
                return;
            }
            Ok((status, entry)) => {
                tracing::warn!(
                    status,
                    entry,
                    label,
                    "duplex control POST not 2xx; retrying"
                );
            }
            Err(err) => {
                tracing::warn!(error = %err, label, "duplex control POST failed; retrying");
            }
        }
        tokio::time::sleep(Duration::from_secs(DUPLEX_CONTROL_POST_RETRY_SECS)).await;
    }
}

fn spawn_duplex_offer(
    wire: ChannelWire,
    peer_user_pgp: String,
    peer_eoa: String,
    sess: DuplexSession,
    duplex: Arc<Mutex<HashMap<DuplexKey, DuplexSession>>>,
) {
    let Some(handle) = tokio::runtime::Handle::try_current().ok() else {
        return;
    };
    let Some(key) = sess.key else {
        return;
    };
    let entries = wire_post_entries(&wire);
    let dest = sess.dest;
    let port = sess.port;
    let session_id = sess.session_id.clone();
    handle.spawn(async move {
        loop {
            match duplex_session_by_id(&duplex, dest, port, &session_id) {
                Some(live) if duplex_initiator_should_stop_offer(&live) => {
                    tracing::info!(
                        session = %session_id,
                        peer_attached = live.peer_attached,
                        rejected = live.rejected,
                        "duplex_offer complete; stop resend"
                    );
                    return;
                }
                None => {
                    tracing::debug!(session = %session_id, "duplex_offer session gone; stop resend");
                    return;
                }
                _ => {}
            }
            let ts = chrono::Utc::now().timestamp().max(0) as u64;
            match duplex::encode_offer_command_for_port(
                &wire.eoa,
                &peer_eoa,
                &peer_eoa,
                &wire.eoa,
                &wire.user_pub,
                sess.port,
                &session_id,
                &key,
                ts,
            )
            .and_then(|cmd| duplex::wrap_offer_for_user_pgp(&cmd, &peer_user_pgp, &wire.eth))
            {
                Ok(armor) => {
                    tracing::info!(session = %session_id, "duplex_offer POST (periodic until accept)");
                    post_control_armor_with_retry(&entries, &armor, "duplex_offer").await;
                }
                Err(err) => tracing::warn!(error = %err, session = %session_id, "duplex_offer wrap refused"),
            }
            tokio::time::sleep(Duration::from_secs(DUPLEX_OFFER_RESEND_SECS)).await;
        }
    });
}

fn spawn_duplex_accept_chat(
    wire: ChannelWire,
    initiator_pipe_pgp: String,
    sess: DuplexSession,
    duplex: Arc<Mutex<HashMap<DuplexKey, DuplexSession>>>,
) {
    let Some(handle) = tokio::runtime::Handle::try_current().ok() else {
        return;
    };
    let Some(key) = sess.key else {
        return;
    };
    let entries = wire_post_entries(&wire);
    let dest = sess.dest;
    let port = sess.port;
    let session_id = sess.session_id.clone();
    // The billing wallet signs the application accept, but the listen wallet
    // is unique to this accepted proxy line.  Reusing wire.eoa here makes all
    // clients for mainWallet:port contend for one SI-exclusive occupation.
    let (accept_wallet, accept_user_pgp) = sess
        .accept_identity
        .as_ref()
        .map(|identity| {
            (
                identity.wallet_address().to_owned(),
                identity.user_public_armor.clone(),
            )
        })
        .unwrap_or_else(|| (wire.eoa.clone(), wire.user_pub.clone()));
    handle.spawn(async move {
        loop {
            match duplex_session_by_id(&duplex, dest, port, &session_id) {
                Some(live) if duplex_acceptor_should_stop_accept(&live) => {
                    tracing::info!(
                        session = %session_id,
                        pipe_up = live.pipe_tx.is_some(),
                        rejected = live.rejected,
                        "duplex_accept complete; stop resend"
                    );
                    return;
                }
                None => {
                    tracing::debug!(session = %session_id, "duplex_accept session gone; stop resend");
                    return;
                }
                _ => {}
            }
            let ts = chrono::Utc::now().timestamp().max(0) as u64;
            match duplex::encode_accept_command(
                &accept_wallet,
                &accept_wallet,
                &accept_user_pgp,
                &session_id,
                &key,
                ts,
            )
            .and_then(|cmd| duplex::wrap_accept_for_user_pgp(&cmd, &initiator_pipe_pgp, &wire.eth))
            {
                Ok(armor) => {
                    tracing::info!(
                        session = %session_id,
                        "duplex_accept POST (periodic until l0_connect pipe up)"
                    );
                    post_control_armor_with_retry(&entries, &armor, "duplex_accept").await;
                }
                Err(err) => tracing::warn!(error = %err, session = %session_id, "duplex_accept Chat wrap refused"),
            }
            tokio::time::sleep(Duration::from_secs(DUPLEX_ACCEPT_RESEND_SECS)).await;
        }
    });
}

fn spawn_l0_pipe(
    wire: ChannelWire,
    peer_route_pgp: String,
    target_wallet: String,
    first: Option<String>,
    sess: DuplexSession,
    duplex: Arc<Mutex<HashMap<DuplexKey, DuplexSession>>>,
    extras: PipeExtras,
) {
    let Some(handle) = tokio::runtime::Handle::try_current().ok() else {
        return;
    };
    let dest = sess.dest;
    let port = sess.port;
    let session_id = sess.session_id.clone();
    // An accepted proxy line must sign its SI mailbox command with its own
    // temporary wallet.  The configured channel key remains the compatibility
    // fallback for non-proxy/static sessions and reject paths.
    let (listen_wallet, listen_signer) = sess
        .accept_identity
        .as_ref()
        .map(|identity| {
            (
                identity.wallet_address().to_owned(),
                identity.wallet.clone(),
            )
        })
        .unwrap_or_else(|| (wire.eoa.clone(), wire.si_eth.clone()));
    let oneshot_reject = sess.rejected;
    let track_inflight = if oneshot_reject {
        false
    } else {
        let mut guard = duplex.lock().unwrap_or_else(|p| p.into_inner());
        let Some(live) = guard.get_mut(&duplex_key(dest, port, &session_id)) else {
            return;
        };
        if live.pipe_tx.is_some() && live.peer_attached && !live.rejected {
            tracing::debug!(
                session = %session_id,
                port,
                "l0_connect pipe already active; skip duplicate spawn"
            );
            return;
        }
        if live.pipe_connect_inflight {
            tracing::debug!(
                session = %session_id,
                port,
                "l0_connect occupy retry in flight; skip duplicate spawn"
            );
            return;
        }
        live.pipe_connect_inflight = true;
        true
    };
    let entries = if wire.entries.is_empty() {
        wire.listen_entries.clone()
    } else {
        wire.entries.clone()
    };
    let duplex_for_guard = duplex.clone();
    handle.spawn(async move {
        struct PipeConnectInflightGuard {
            duplex: Arc<Mutex<HashMap<DuplexKey, DuplexSession>>>,
            dest: Ipv4Addr,
            port: u16,
            session_id: String,
            active: bool,
        }
        impl Drop for PipeConnectInflightGuard {
            fn drop(&mut self) {
                if !self.active {
                    return;
                }
                let mut guard = self.duplex.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(live) =
                    guard.get_mut(&duplex_key(self.dest, self.port, &self.session_id))
                {
                    live.pipe_connect_inflight = false;
                }
            }
        }
        let _inflight_guard = PipeConnectInflightGuard {
            duplex: duplex_for_guard,
            dest,
            port,
            session_id: session_id.clone(),
            active: track_inflight,
        };
        let mut first_blob = first;
        loop {
            let ts = chrono::Utc::now().timestamp().max(0) as u64;
            let Ok(connect_armor) = listen::wrap_l0_connect_for_post(
                &listen_wallet,
                &target_wallet,
                ts,
                &peer_route_pgp,
                &listen_signer,
            ) else {
                tracing::warn!(session = %session_id, "l0_connect wrap refused");
                return;
            };
            let (tx, rx) = mpsc::channel::<String>(512);
            let tx_after_http = if oneshot_reject {
                drop(tx);
                None
            } else {
                let cloned = tx.clone();
                drop(tx);
                Some(cloned)
            };
            let gen = if oneshot_reject {
                None
            } else {
                let mut guard = duplex.lock().unwrap_or_else(|p| p.into_inner());
                let Some(live) = guard.get_mut(&duplex_key(dest, port, &session_id)) else {
                    return;
                };
                if live.rejected || !live.peer_attached {
                    return;
                }
                live.pipe_gen = live.pipe_gen.wrapping_add(1);
                Some(live.pipe_gen)
            };
            let duplex_up = duplex.clone();
            let session_up = session_id.clone();
            let extras_up = extras.clone();
            match pipe::run_occupied_pipe(
                &entries,
                &connect_armor,
                &session_id,
                sess.key,
                first_blob.take(),
                rx,
                extras.inbound_tx.clone(),
                || {
                    let (Some(gen), Some(tx_install)) = (gen, tx_after_http.as_ref()) else {
                        return;
                    };
                    let mut guard = duplex_up.lock().unwrap_or_else(|p| p.into_inner());
                    if let Some(live) = guard.get_mut(&duplex_key(dest, port, &session_up)) {
                        if live.pipe_gen == gen && live.peer_attached && !live.rejected {
                            live.pipe_tx = Some(tx_install.clone());
                            tracing::info!(
                                session = %session_up,
                                port,
                                "l0_connect HTTP 200; pipe_tx installed"
                            );
                            drop(guard);
                            maybe_start_proxy_drain(
                                &extras_up,
                                duplex_up.clone(),
                                session_up.clone(),
                                port,
                            );
                        }
                    }
                },
            )
            .await
            {
                Ok(()) => {
                    if oneshot_reject || gen.is_none() {
                        tracing::info!(session = %session_id, "l0_connect pipe closed");
                        return;
                    }
                    let gen = gen.expect("tracked pipe");
                    if l0_pipe_closed_should_retry(&duplex, dest, port, &session_id, gen) {
                        tracing::info!(
                            session = %session_id,
                            "l0_connect pipe closed; retrying occupy"
                        );
                        tokio::time::sleep(Duration::from_secs(L0_PIPE_RETRY_SECS)).await;
                        continue;
                    }
                    tracing::info!(session = %session_id, "l0_connect pipe closed");
                    return;
                }
                Err(err) => {
                    let retry_secs = l0_pipe_retry_secs(&err);
                    tracing::warn!(session = %session_id, error = %err, "l0_connect pipe failed");
                    if oneshot_reject || gen.is_none() {
                        return;
                    }
                    let gen = gen.expect("tracked pipe");
                    if !l0_pipe_closed_should_retry(&duplex, dest, port, &session_id, gen) {
                        return;
                    }
                    tracing::info!(
                        session = %session_id,
                        retry_secs,
                        "l0_connect failed; retrying occupy pipe"
                    );
                    tokio::time::sleep(Duration::from_secs(retry_secs)).await;
                }
            }
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
            peer_eoa: String::new(),
        };
        let dest = Ipv4Addr::new(100, 64, 0, 6);
        for port in [8400_u16, 4200, 4300] {
            peers.insert((dest, port), keys.clone());
        }
        let mut channel_eoa = HashMap::new();
        channel_eoa.insert(8400, "0x1111111111111111111111111111111111111111".into());
        channel_eoa.insert(4200, "0x1111111111111111111111111111111111111111".into());
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
            inbound_feed: None,
            proxy_registry: proxy::ProxyRegistry::new(Vec::new()),
            proxy_receivers: Arc::new(Mutex::new(HashMap::new())),
            proxy_seq: Arc::new(AtomicU64::new(1)),
        }
    }

    #[test]
    fn prepare_wraps_then_refuses_plaintext() {
        let user = generate_test_cert();
        let route = generate_test_cert();
        let user_pub = public_cert_armored(&user).unwrap();
        let route_pub = public_cert_armored(&route).unwrap();
        let client = client_with_keys(&user_pub, &route_pub);
        let prepared = match client
            .prepare_overlay_post(Ipv4Addr::new(100, 64, 0, 6), 8400, b"\x45\x00pkt", 9)
            .unwrap()
        {
            OverlayPostPlan::P1(prepared) => prepared,
            _ => panic!("expected P1 gossip POST"),
        };
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
    fn duplex_handshake_without_pipe_suppresses_p1() {
        let user = generate_test_cert();
        let route = generate_test_cert();
        let user_pub = public_cert_armored(&user).unwrap();
        let route_pub = public_cert_armored(&route).unwrap();
        let client = client_with_keys(&user_pub, &route_pub);
        let dest = Ipv4Addr::new(100, 64, 0, 6);
        let key = aes::generate_key();
        let sid = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string();
        client.duplex.lock().unwrap().insert(
            duplex_key(dest, 8400, &sid),
            DuplexSession {
                session_id: sid.clone(),
                created_at: 0,
                key: Some(key),
                dest,
                port: 8400,
                peer_eoa: "0x2222222222222222222222222222222222222222".into(),
                guest_up: true,
                peer_attached: true,
                rejected: false,
                host_eoa: "0x1111111111111111111111111111111111111111".into(),
                peer_listen_user_pgp: None,
                peer_listen_wallet: None,
                accept_identity: None,
                peer_return_attached: false,
                pipe_tx: None,
                pipe_gen: 0,
                pipe_connect_inflight: false,
            },
        );
        let prepared = client
            .prepare_overlay_post(dest, 8400, b"\x45\x00pkt", 3)
            .unwrap();
        assert!(matches!(prepared, OverlayPostPlan::Suppressed));
    }

    #[test]
    fn duplex_ready_with_pipe_does_not_pgp_post() {
        let user = generate_test_cert();
        let route = generate_test_cert();
        let user_pub = public_cert_armored(&user).unwrap();
        let route_pub = public_cert_armored(&route).unwrap();
        let client = client_with_keys(&user_pub, &route_pub);
        let dest = Ipv4Addr::new(100, 64, 0, 6);
        let key = aes::generate_key();
        let sid = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string();
        let (tx, mut rx) = mpsc::channel(4);
        client.duplex.lock().unwrap().insert(
            duplex_key(dest, 8400, &sid),
            DuplexSession {
                session_id: sid.clone(),
                created_at: 0,
                key: Some(key),
                dest,
                port: 8400,
                peer_eoa: "0x2222222222222222222222222222222222222222".into(),
                guest_up: true,
                peer_attached: true,
                rejected: false,
                host_eoa: "0x1111111111111111111111111111111111111111".into(),
                peer_listen_user_pgp: None,
                peer_listen_wallet: Some("0x2222222222222222222222222222222222222222".into()),
                accept_identity: None,
                peer_return_attached: false,
                pipe_tx: Some(tx),
                pipe_gen: 1,
                pipe_connect_inflight: false,
            },
        );
        let prepared = client
            .prepare_overlay_post(dest, 8400, b"\x45\x00pkt", 3)
            .unwrap();
        assert!(matches!(prepared, OverlayPostPlan::Occupied));
        let blob = rx.try_recv().expect("AES blob on pipe");
        assert!(duplex::looks_like_aes_blob(&blob));
        let json = String::from_utf8(aes::open(&key, &blob).unwrap()).unwrap();
        assert!(json.contains("duplex_frame"));
        assert!(!json.contains("Securitykey"));
    }

    #[test]
    fn inbound_duplex_frame_writes_ipv4() {
        let dest = Ipv4Addr::new(100, 64, 0, 6);
        let key = aes::generate_key();
        let pkt = b"\x45\x00fake-ipv4-header!!";
        let framed = frame::encode(1, pkt);
        let payload = Engine::encode(&base64::engine::general_purpose::STANDARD, &framed);
        let sid = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let mut client = L0Client {
            enabled: true,
            ..L0Client::disabled()
        };
        client.duplex.lock().unwrap().insert(
            duplex_key(dest, 8400, sid),
            DuplexSession {
                session_id: sid.to_string(),
                created_at: 0,
                key: Some(key),
                dest,
                port: 8400,
                peer_eoa: "0x2222222222222222222222222222222222222222".into(),
                guest_up: true,
                peer_attached: true,
                rejected: false,
                host_eoa: "0x1111111111111111111111111111111111111111".into(),
                peer_listen_user_pgp: None,
                peer_listen_wallet: None,
                accept_identity: None,
                peer_return_attached: false,
                pipe_tx: None,
                pipe_gen: 0,
                pipe_connect_inflight: false,
            },
        );
        let json = serde_json::json!({
            "type": "duplex_frame",
            "pipe_handle": sid,
            "payload": payload,
        })
        .to_string();
        assert_eq!(client.apply_inbound_armor(&json).unwrap(), pkt.len());
        let blob = duplex::seal_frame(&key, sid, &frame::encode(1, pkt)).unwrap();
        assert_eq!(client.apply_inbound_armor(&blob).unwrap(), pkt.len());
        assert_eq!(client.inbound_ready, 2);
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

    fn sample_duplex_session(pipe_active: bool) -> DuplexSession {
        DuplexSession {
            session_id: "sess".into(),
            created_at: 0,
            key: Some([7u8; aes::KEY_LEN]),
            dest: Ipv4Addr::new(100, 64, 0, 6),
            port: 8400,
            peer_eoa: "0x2222222222222222222222222222222222222222".into(),
            guest_up: true,
            peer_attached: true,
            rejected: false,
            host_eoa: "0x1111111111111111111111111111111111111111".into(),
            peer_listen_user_pgp: None,
            peer_listen_wallet: Some("0x2222222222222222222222222222222222222222".into()),
            accept_identity: None,
            peer_return_attached: false,
            pipe_tx: if pipe_active {
                let (tx, _rx) = mpsc::channel(1);
                Some(tx)
            } else {
                None
            },
            pipe_gen: 0,
            pipe_connect_inflight: false,
        }
    }

    #[test]
    fn duplex_initiator_stops_offer_after_peer_attached() {
        let mut sess = sample_duplex_session(false);
        sess.peer_attached = false;
        assert!(!duplex_initiator_should_stop_offer(&sess));
        sess.peer_attached = true;
        assert!(duplex_initiator_should_stop_offer(&sess));
        sess.peer_attached = false;
        sess.rejected = true;
        assert!(duplex_initiator_should_stop_offer(&sess));
    }

    #[test]
    fn duplex_acceptor_stops_accept_when_peer_return_attached() {
        let mut sess = sample_duplex_session(false);
        assert!(!duplex_acceptor_should_stop_accept(&sess));
        sess.peer_return_attached = true;
        assert!(duplex_acceptor_should_stop_accept(&sess));
        sess.peer_return_attached = false;
        sess.rejected = true;
        assert!(duplex_acceptor_should_stop_accept(&sess));
        sess.rejected = false;
        let with_pipe = sample_duplex_session(true);
        assert!(duplex_acceptor_should_stop_accept(&with_pipe));
    }

    #[test]
    fn duplicate_duplex_offer_ignored_when_pipe_up() {
        let mut sess = sample_duplex_session(true);
        assert!(duplex_duplicate_offer_should_ignore(&sess, true));
        sess.pipe_tx = None;
        sess.pipe_connect_inflight = true;
        assert!(duplex_duplicate_offer_should_ignore(&sess, true));
        sess.pipe_connect_inflight = false;
        assert!(!duplex_duplicate_offer_should_ignore(&sess, true));
    }

    #[test]
    fn duplex_offer_expired_by_absolute_age() {
        let now = 1_700_000_200;
        assert!(duplex_offer_is_expired(
            now - DUPLEX_OFFER_MAX_AGE_SECS - DUPLEX_OFFER_CLOCK_SKEW_SECS - 1,
            now
        ));
        assert!(!duplex_offer_is_expired(now - 30, now));
        assert!(!duplex_offer_is_expired(now, now));
        assert!(duplex_offer_is_expired(
            now + DUPLEX_OFFER_CLOCK_SKEW_SECS + 1,
            now
        ));
    }

    #[test]
    fn stale_offer_skipped_when_live_peer_port_newer() {
        let dest = Ipv4Addr::new(100, 64, 0, 6);
        let mut live = sample_duplex_session(true);
        live.created_at = 1_700_000_100;
        live.peer_eoa = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
        live.port = 4200;
        let map = HashMap::from([(duplex_key(dest, 4200, &live.session_id), live)]);
        assert!(duplex_stale_offer_should_skip_additional(
            &map,
            "0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa",
            4200,
            1_700_000_000, // older than live.created_at - skew
        ));
        assert!(!duplex_stale_offer_should_skip_additional(
            &map,
            "0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa",
            4200,
            1_700_000_100, // same era as live
        ));
        assert!(!duplex_stale_offer_should_skip_additional(
            &map,
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            4200,
            1_700_000_000,
        ));
    }

    #[test]
    fn retire_conflicting_sessions_drops_pipe_tx_for_same_peer_port() {
        let dest = Ipv4Addr::new(100, 64, 0, 6);
        let peer = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut ghost = sample_duplex_session(true);
        ghost.session_id = "ghost".into();
        ghost.peer_eoa = peer.into();
        ghost.port = 4200;
        ghost.dest = dest;
        let mut keep = sample_duplex_session(false);
        keep.session_id = "keep".into();
        keep.peer_eoa = peer.into();
        keep.port = 4200;
        keep.dest = dest;
        let mut map = HashMap::from([
            (duplex_key(dest, 4200, "ghost"), ghost),
            (duplex_key(dest, 4200, "keep"), keep),
        ]);
        let proxy = Arc::new(Mutex::new(HashMap::new()));
        let n = retire_conflicting_duplex_sessions(&mut map, &proxy, peer, 4200, "keep");
        assert_eq!(n, 1);
        assert!(map.contains_key(&duplex_key(dest, 4200, "keep")));
        assert!(!map.contains_key(&duplex_key(dest, 4200, "ghost")));
    }

    #[test]
    fn occupy_tcp_eof_clears_pipe_tx_and_retries_while_attached() {
        let dest = Ipv4Addr::new(100, 64, 0, 6);
        let sess = sample_duplex_session(true);
        let sid = sess.session_id.clone();
        let duplex = Arc::new(Mutex::new(HashMap::from([(
            duplex_key(dest, 8400, &sid),
            sess,
        )])));
        {
            let mut guard = duplex.lock().unwrap();
            guard
                .get_mut(&duplex_key(dest, 8400, &sid))
                .unwrap()
                .pipe_gen = 3;
        }
        assert!(l0_pipe_closed_should_retry(&duplex, dest, 8400, &sid, 3));
        let guard = duplex.lock().unwrap();
        let live = guard.get(&duplex_key(dest, 8400, &sid)).unwrap();
        assert!(live.pipe_tx.is_none());
        assert!(live.peer_attached);
    }

    #[test]
    fn occupy_tcp_eof_does_not_retry_stale_pipe_gen() {
        let dest = Ipv4Addr::new(100, 64, 0, 6);
        let sess = sample_duplex_session(true);
        let sid = sess.session_id.clone();
        let duplex = Arc::new(Mutex::new(HashMap::from([(
            duplex_key(dest, 8400, &sid),
            sess,
        )])));
        {
            let mut guard = duplex.lock().unwrap();
            guard
                .get_mut(&duplex_key(dest, 8400, &sid))
                .unwrap()
                .pipe_gen = 4;
        }
        assert!(!l0_pipe_closed_should_retry(&duplex, dest, 8400, &sid, 3));
        let guard = duplex.lock().unwrap();
        assert!(guard
            .get(&duplex_key(dest, 8400, &sid))
            .unwrap()
            .pipe_tx
            .is_some());
    }

    #[test]
    fn rebuild_skips_when_pipe_connect_inflight() {
        let routing = "0x1111111111111111111111111111111111111111";
        let mut sess = sample_duplex_session(false);
        sess.pipe_connect_inflight = true;
        assert!(!should_rebuild_l0_pipe_after_listen_up(&sess, routing));
    }

    #[test]
    fn rebuild_skips_when_l0_pipe_already_active() {
        let routing = "0x1111111111111111111111111111111111111111";
        assert!(!should_rebuild_l0_pipe_after_listen_up(
            &sample_duplex_session(true),
            routing
        ));
        assert!(should_rebuild_l0_pipe_after_listen_up(
            &sample_duplex_session(false),
            routing
        ));
    }

    #[test]
    fn l0_pipe_retry_secs_treats_409_as_occupied() {
        assert_eq!(
            l0_pipe_retry_secs(&L0dError::L0(
                "l0 pipe HTTP not 2xx: HTTP/1.1 409 Conflict".into()
            )),
            L0_PIPE_OCCUPIED_RETRY_SECS
        );
        assert_eq!(
            l0_pipe_retry_secs(&L0dError::L0(
                "l0 pipe peer disconnected: HTTP/1.1 410 Gone".into()
            )),
            L0_PIPE_END_RETRY_SECS
        );
        assert_eq!(
            l0_pipe_retry_secs(&L0dError::L0PipeEnd {
                reason: "test".into(),
                session_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .into(),
            }),
            L0_PIPE_END_RETRY_SECS
        );
    }

    #[test]
    fn same_dest_port_keeps_independent_duplex_lines() {
        let dest = Ipv4Addr::new(100, 64, 0, 6);
        let port = 8400u16;
        let mut a = sample_duplex_session(false);
        a.session_id = "line-a".into();
        a.dest = dest;
        a.port = port;
        let mut b = sample_duplex_session(true);
        b.session_id = "line-b".into();
        b.dest = dest;
        b.port = port;
        let duplex = Arc::new(Mutex::new(HashMap::from([
            (duplex_key(dest, port, "line-a"), a),
            (duplex_key(dest, port, "line-b"), b),
        ])));
        assert_eq!(duplex.lock().unwrap().len(), 2);
        assert!(duplex_session_by_id(&duplex, dest, port, "line-a").is_some());
        assert!(duplex_session_by_id(&duplex, dest, port, "line-b").is_some());
        let live = duplex_live_session(&duplex, dest, port).expect("prefer pipe-up line");
        assert_eq!(live.session_id, "line-b");
        assert!(live.pipe_tx.is_some());
    }
}
