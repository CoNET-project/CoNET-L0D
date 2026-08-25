//! Overlay L0 client. Default is the MVP stub.
//!
//! Protocol: exclusive SI `l0_listen` / `l0_connect` occupancy pipe, then
//! application duplex (`duplex_offer` on Chat gossip; accept / reject / frames
//! as AES blobs on the occupied pipe). While a configured duplex session is
//! negotiating or recovering, overlay packets are suppressed rather than sent
//! through `conet_l0d_overlay_v1` transport frames. HTTP first body is still `{ "data" }`
//! only. Do not claim SI `duplex_*` or live `p2p_stream_*`.

use crate::config::{ProxyMode, ValidatedConfig};
use crate::error::L0dError;
use crate::l0::aes;
use crate::l0::eip191::EthSecret;
use crate::l0::si_pool::SiPool;
use crate::l0::{duplex, eip191, envelope, frame, listen, pgp, pipe, post, proxy};
use crate::locator::{client_bind_candidates, Locator, LocatorHost};
use crate::packet::overlay_channel_port;
use base64::Engine;
use sequoia_openpgp::Cert;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Semaphore};

const POST_QUEUE: usize = 2048;
// 32 in-flight POSTs each walking 3 entries × 12s starves SI /post (listen headers never arrive).
const POST_CONCURRENCY: usize = 4;
const LISTEN_QUEUE: usize = 512;
const LISTEN_RECONNECT_SECS: u64 = 3;
/// Only a clean, already-established pipe may be rebuilt after its peer ends.
/// Occupation failures never use this delay; they terminate the duplex.
const L0_PIPE_RETRY_SECS: u64 = 3;
/// Temporary lines no longer wait on AddressPGP. Keep the local socket paused
/// until mailbox SI returns a real `text/event-stream` L0 listen handshake.
const DYNAMIC_LISTEN_READY_TIMEOUT_SECS: u64 = 120;
/// After `responseChunk`, keep the proxy upstream read side paused only until
/// the initiator occupy attaches. Geth / beacon often send no extra bytes
/// after Hello until the return pipe is live, so an empty first blob is OK.
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
/// Keep this many listen-ready temporary identities per duplex port so
/// `duplex_offer` / `duplex_accept` can fire before RLPx / libp2p RST the
/// local TCP (mailbox SSE handshake is typically well under a second).
const READY_IDENTITY_POOL_TARGET: usize = 2;

/// Pre-registered, listen-ready ephemeral identities for one logical port.
struct ReadyIdentityPool {
    ready: Mutex<VecDeque<crate::l0::identity::TemporaryIdentity>>,
    warming: AtomicU64,
}

impl ReadyIdentityPool {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            ready: Mutex::new(VecDeque::new()),
            warming: AtomicU64::new(0),
        })
    }

    fn take(&self) -> Option<crate::l0::identity::TemporaryIdentity> {
        self.ready
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pop_front()
    }

    fn push(&self, identity: crate::l0::identity::TemporaryIdentity) {
        self.ready
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push_back(identity);
    }

    fn ready_len(&self) -> usize {
        self.ready.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

#[derive(Clone)]
struct ArmoredCert(String);

impl fmt::Debug for ArmoredCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ArmoredCert(redacted)")
    }
}

struct SecretCert {
    cert: Cert,
    /// Wallet whose user-PGP key decrypted this armor. This is required to
    /// prove that a new offer actually arrived on the configured mainWallet,
    /// instead of trusting a mainWallet string carried inside the offer.
    wallet: Option<String>,
}

impl SecretCert {
    #[cfg(test)]
    fn unscoped(cert: Cert) -> Self {
        Self { cert, wallet: None }
    }
}

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
    /// GuardianNodesInfoV6 qualified SI pool, preferred over static entries.
    si_pool: Option<Arc<SiPool>>,
    /// Own session-listen user PGP (channel EOA in crate MVP).
    user_pub: String,
    /// CoNET L1 RPC (AddressPGP / destination lookup for configured peers).
    rpc: String,
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
    inbound_tx: Option<mpsc::Sender<listen::InboundChunk>>,
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

/// Per-line role. Proxy upstream drain is attached only for `Proxy` lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DuplexLineRole {
    /// Overlay peer / `--clientDuplex` initiator or acceptor. Never dials local
    /// `proxy_duplex` upstream merely because `session.port` matches a proxy port.
    Peer,
    /// Created by inbound proxy `mainWallet:port` + firstChunk handshake.
    Proxy,
}

#[derive(Clone)]
struct DuplexSession {
    session_id: String,
    /// Set at construction; `Proxy` only for proxy-handshake allocations.
    role: DuplexLineRole,
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
    /// Mailbox SI route PGP holding the peer's temporary listen SSE.
    peer_listen_route_pgp: Option<String>,
    peer_listen_wallet: Option<String>,
    /// Mailbox SI node wallet that accepted the peer's temporary listen.
    peer_listen_mailbox_wallet: Option<String>,
    /// Acceptor-side temporary identity, allocated after mainWallet:port
    /// matching. It is never reused by another line.
    accept_identity: Option<crate::l0::identity::TemporaryIdentity>,
    /// Acceptor: initiator sent at least one `duplex_frame` (return path is live).
    peer_return_attached: bool,
    /// The control-plane responseChunk is replayed until the reverse occupied
    /// pipe is established, but it must be written to the local socket once.
    response_chunk_delivered: bool,
    /// Occupied `l0_connect` writer. AES blobs only; never overlay key on this channel.
    pipe_tx: Option<mpsc::Sender<String>>,
    /// Bumps on every `spawn_l0_pipe` so a dying task does not clear a newer pipe.
    pipe_gen: u64,
    /// True while an async `spawn_l0_pipe` task owns occupy/retry (prevents duplicate spawns).
    pipe_connect_inflight: bool,
    /// Shared with the occupy task. Retain / remove must set this so the pipe
    /// stops instead of sending heartbeats with a stale spawn-time key.
    pipe_cancel: Option<Arc<AtomicBool>>,
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
    inbound_rx: Option<mpsc::Receiver<listen::InboundChunk>>,
    pending: Option<PendingOverlay>,
    channel_wire: HashMap<u16, ChannelWire>,
    duplex: Arc<Mutex<HashMap<DuplexKey, DuplexSession>>>,
    /// Clone of the listen inbound sender so occupy TCP AES can share the queue.
    inbound_feed: Option<mpsc::Sender<listen::InboundChunk>>,
    proxy_registry: proxy::ProxyRegistry,
    proxy_receivers: Arc<Mutex<HashMap<String, mpsc::Sender<Vec<u8>>>>>,
    proxy_seq: Arc<AtomicU64>,
    /// Raw TCP streams accepted on the automatically assigned local client
    /// endpoint. Duplex frames for these sessions bypass TUN packet handling.
    local_streams: Arc<Mutex<HashMap<String, mpsc::Sender<Vec<u8>>>>>,
    /// Per-port listen-ready temporary identities (spoke client + proxy hub).
    ready_identities: HashMap<u16, Arc<ReadyIdentityPool>>,
    /// Every inbound SSE has an owner object retained for its full lifetime.
    listen_owners: listen::ListenOwnerRegistry,
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
            listen_owners: listen::ListenOwnerRegistry::default(),
            proxy_registry: proxy::ProxyRegistry::new(Vec::new()),
            proxy_receivers: Arc::new(Mutex::new(HashMap::new())),
            proxy_seq: Arc::new(AtomicU64::new(1)),
            local_streams: Arc::new(Mutex::new(HashMap::new())),
            ready_identities: HashMap::new(),
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
                    // A single mainWallet can have distinct user-PGP keys per
                    // port. Only this row's explicit ports receive its key.
                    // Filling client_duplex ports from another row (or_insert)
                    // encrypted :8400 offers to the beacon PGP when the geth
                    // peer file failed to load.
                    insert_peer_pgp_ports(
                        &mut peers,
                        peer.vip,
                        peer.tcp_ports.iter().chain(peer.udp_ports.iter()).copied(),
                        &keys,
                    );
                }
                Err(err) => tracing::warn!(
                    dest = %peer.vip,
                    error = %err,
                    "P1: peer OpenPGP public files were not loaded; POST stays refused for this vIP"
                ),
            }
        }

        let si_pool = if cfg.l0.enabled && cfg.l0.si_pool_from_contract {
            match SiPool::new(&cfg.l0.rpc) {
                Ok(pool) => {
                    let warm = Arc::clone(&pool);
                    tokio::spawn(async move {
                        match warm.refresh().await {
                            Ok(nodes) => tracing::info!(
                                nodes,
                                "SI pool initial refresh from GuardianNodesInfoV6"
                            ),
                            Err(error) => tracing::warn!(%error, "SI pool initial refresh failed"),
                        }
                    });
                    pool.spawn_refresh_loop();
                    Some(pool)
                }
                Err(error) => {
                    tracing::warn!(%error, "SI pool disabled: failed to create");
                    None
                }
            }
        } else {
            None
        };
        let post_tx = if cfg.l0.enabled && (si_pool.is_some() || !cfg.l0.entries.is_empty()) {
            spawn_post_worker(si_pool.clone(), cfg.l0.entries.clone())
        } else {
            None
        };

        let (inbound_tx, inbound_rx_ch) = mpsc::channel::<listen::InboundChunk>(LISTEN_QUEUE);
        let mut user_secrets = Vec::new();
        let channel_wire = load_channel_wires(cfg, si_pool.clone());
        let duplex = Arc::new(Mutex::new(HashMap::new()));
        let proxy_receivers = Arc::new(Mutex::new(HashMap::new()));
        let proxy_seq = Arc::new(AtomicU64::new(1));
        let local_streams = Arc::new(Mutex::new(HashMap::new()));
        let proxy_registry = proxy::ProxyRegistry::new(
            cfg.l0
                .proxies
                .iter()
                .chain(cfg.l0.proxy_duplex.iter())
                .cloned()
                .collect(),
        );
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
        let listen_owners = listen::ListenOwnerRegistry::default();
        if cfg.l0.enabled {
            listen_spawned = if cfg.l0.channels.is_empty() {
                if let Some(path) = cfg.l0.routing_key_file.as_ref() {
                    match pgp::load_secret_cert(path) {
                        Ok(cert) => user_secrets.push(SecretCert {
                            cert,
                            wallet: Some(routing_eoa.clone()),
                        }),
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
                    listen_owners.clone(),
                    si_pool.clone(),
                )
            } else {
                spawn_channel_listens_into(
                    cfg,
                    &mut user_secrets,
                    inbound_tx.clone(),
                    Some(pipe_rebuild.clone()),
                    listen_owners.clone(),
                    si_pool.clone(),
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
        let mut ready_identities = HashMap::new();
        for port in cfg
            .client_duplex
            .iter()
            .map(|target| target.port)
            .chain(cfg.l0.proxy_duplex.iter().map(|proxy| proxy.port))
        {
            ready_identities
                .entry(port)
                .or_insert_with(ReadyIdentityPool::new);
        }
        spawn_ready_identity_warmers(
            &ready_identities,
            &channel_wire,
            inbound_feed.clone(),
            listen_owners.clone(),
        );

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
            local_streams,
            ready_identities,
            listen_owners,
        }
    }

    /// Start raw TCP listeners for configured duplex client targets.
    ///
    /// Every `accept()` event is a new local connection handle.  It must get
    /// its own temporary identity and occupied pipe; selecting a session by
    /// logical port would incorrectly merge concurrent Geth/Prysm sockets.
    pub fn spawn_local_tcp_listeners(&self, cfg: &ValidatedConfig) {
        struct DuplexListenPlan {
            dest: Ipv4Addr,
            port: u16,
            preferred_bind: u16,
            explicit_local: bool,
            wire: ChannelWire,
            peer_keys: PeerPgp,
            ready_pool: Option<Arc<ReadyIdentityPool>>,
        }

        let mut plans = Vec::new();
        for target in &cfg.client_duplex {
            let Some(peer) = cfg.peers.iter().find(|peer| {
                peer.tcp_ports.contains(&target.port)
                    && match (&target.host, &peer.locator.host) {
                        (LocatorHost::Eoa(target_eoa), LocatorHost::Eoa(peer_eoa)) => {
                            eip191::eoa_eq(target_eoa, peer_eoa)
                        }
                        _ => false,
                    }
            }) else {
                tracing::warn!(
                    target = %target.display(),
                    "duplex client target has no peer entry for its port"
                );
                continue;
            };
            let dest = peer.vip;
            let port = target.port;
            let Some(wire) = self.channel_wire.get(&port).cloned() else {
                tracing::warn!(port, "duplex client has no channel wire");
                continue;
            };
            let Some(peer_keys) = self.peers.get(&(dest, port)).cloned() else {
                tracing::warn!(port, "duplex client has no peer PGP keys");
                continue;
            };
            match pgp::transport_key_id_armored(&peer_keys.user.0) {
                Ok(kid) => tracing::info!(
                    port,
                    dest = %dest,
                    peer_user_key_id = %kid,
                    "duplex client listener bound to peer user PGP"
                ),
                Err(err) => tracing::warn!(
                    port,
                    dest = %dest,
                    error = %err,
                    "duplex client peer user PGP has no transport key"
                ),
            }
            plans.push(DuplexListenPlan {
                dest,
                port,
                preferred_bind: target.bind_port,
                explicit_local: target.local_port.is_some(),
                wire,
                peer_keys,
                ready_pool: self.ready_identities.get(&port).cloned(),
            });
        }
        if plans.is_empty() {
            return;
        }

        let bind = Ipv4Addr::LOCALHOST;
        let duplex = self.duplex.clone();
        let local_streams = self.local_streams.clone();
        let inbound_feed = self.inbound_feed.clone();
        let wires = Arc::new(self.channel_wire.clone());
        let peers = Arc::new(self.peers.clone());
        let proxy_registry = self.proxy_registry.clone();
        let proxy_receivers = self.proxy_receivers.clone();
        let proxy_seq = self.proxy_seq.clone();
        let listen_owners = self.listen_owners.clone();
        tokio::spawn(async move {
            // Bind serially so two remotes on the same logical PORT do not
            // race for `PORT` and steal each other's stride (`PORT+10000`).
            // Skip later targets' preferred binds plus already claimed ports.
            let mut reserved: HashSet<u16> = plans.iter().map(|plan| plan.preferred_bind).collect();
            let mut claimed = HashSet::new();
            for plan in plans {
                reserved.remove(&plan.preferred_bind);
                let skip: HashSet<u16> = reserved.union(&claimed).copied().collect();
                let mut listener = None;
                let mut local_port = plan.preferred_bind;
                let mut last_err = None;
                for candidate in client_bind_candidates(plan.preferred_bind, plan.explicit_local) {
                    if skip.contains(&candidate) {
                        continue;
                    }
                    match TcpListener::bind((bind, candidate)).await {
                        Ok(bound) => {
                            listener = Some(bound);
                            local_port = candidate;
                            last_err = None;
                            break;
                        }
                        Err(err) => {
                            last_err = Some((candidate, err));
                        }
                    }
                }
                let Some(listener) = listener else {
                    if let Some((failed_port, error)) = last_err {
                        tracing::warn!(
                            bind = %bind,
                            port = failed_port,
                            target_port = plan.port,
                            dest = %plan.dest,
                            explicit_local = plan.explicit_local,
                            error = %error,
                            "local client TCP listener failed"
                        );
                    }
                    continue;
                };
                claimed.insert(local_port);
                tracing::info!(
                    bind = %bind,
                    port = local_port,
                    target_port = plan.port,
                    dest = %plan.dest,
                    "local client TCP listener active"
                );
                let duplex = duplex.clone();
                let local_streams = local_streams.clone();
                let inbound_feed = inbound_feed.clone();
                let wires = wires.clone();
                let peers = peers.clone();
                let proxy_registry = proxy_registry.clone();
                let proxy_receivers = proxy_receivers.clone();
                let proxy_seq = proxy_seq.clone();
                let listen_owners = listen_owners.clone();
                tokio::spawn(async move {
                    loop {
                        let (stream, peer) = match listener.accept().await {
                            Ok(value) => value,
                            Err(err) => {
                                tracing::warn!(
                                    bind = %bind,
                                    port = plan.port,
                                    dest = %plan.dest,
                                    error = %err,
                                    "local client TCP accept failed"
                                );
                                continue;
                            }
                        };
                        tracing::info!(
                            %peer,
                            bind = %bind,
                            local_port,
                            target_port = plan.port,
                            dest = %plan.dest,
                            "local client TCP connection accepted"
                        );
                        let duplex = duplex.clone();
                        let local_streams = local_streams.clone();
                        let wire = plan.wire.clone();
                        let peer_keys = plan.peer_keys.clone();
                        let inbound_feed = inbound_feed.clone();
                        let wires = wires.clone();
                        let peers = peers.clone();
                        let proxy_registry = proxy_registry.clone();
                        let proxy_receivers = proxy_receivers.clone();
                        let proxy_seq = proxy_seq.clone();
                        let ready_pool = plan.ready_pool.clone();
                        let connection_listen_owners = listen_owners.clone();
                        let dest = plan.dest;
                        let port = plan.port;
                        tokio::spawn(async move {
                            if let Err(err) = run_dynamic_local_tcp_stream(
                                stream,
                                duplex,
                                local_streams,
                                dest,
                                port,
                                wire,
                                peer_keys,
                                inbound_feed,
                                wires,
                                peers,
                                proxy_registry,
                                proxy_receivers,
                                proxy_seq,
                                ready_pool,
                                connection_listen_owners,
                            )
                            .await
                            {
                                tracing::debug!(
                                    %peer,
                                    port,
                                    dest = %dest,
                                    error = %err,
                                    "local client TCP stream closed"
                                );
                            }
                        });
                    }
                });
            }
        });
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn attach_tun_writer(&mut self, tx: mpsc::Sender<Vec<u8>>) {
        self.tun_tx = Some(tx);
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn take_inbound_rx(&mut self) -> Option<mpsc::Receiver<listen::InboundChunk>> {
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
        self.apply_inbound_chunk(listen::InboundChunk::new(
            self.routing_eoa.clone(),
            None,
            chunk.to_owned(),
        ))
    }

    /// Apply a chunk from an owned listen stream.  Temporary duplex streams
    /// must use their bound session key; trying every key in the process would
    /// allow an old stream to be interpreted as a different session.
    pub fn apply_inbound_chunk(&mut self, chunk: listen::InboundChunk) -> Result<usize, L0dError> {
        if !self.enabled {
            self.inbound_refused = self.inbound_refused.saturating_add(1);
            return Err(L0dError::L0(
                "[l0].enabled is false; inbound write-back refused".into(),
            ));
        }
        let trimmed = chunk.payload.trim();
        if duplex::parse_l0_occupied(trimmed) {
            tracing::info!("l0_occupied on exclusive listen SSE");
            return Ok(0);
        }
        if duplex::looks_like_aes_blob(trimmed) {
            let Some(session_id) = chunk.session_id.as_deref() else {
                self.inbound_refused = self.inbound_refused.saturating_add(1);
                return Err(L0dError::L0(
                    "anonymous duplex AES blob rejected; listen owner is missing".into(),
                ));
            };
            let Some(owner) = self.listen_owners.get(&chunk.owner) else {
                self.inbound_refused = self.inbound_refused.saturating_add(1);
                return Err(L0dError::L0(
                    "duplex AES blob rejected; listen owner is missing".into(),
                ));
            };
            if owner.current_session_id().as_deref() != Some(session_id) {
                owner.cancel();
                self.inbound_refused = self.inbound_refused.saturating_add(1);
                return Err(L0dError::L0(
                    "duplex AES blob rejected; listen owner session mismatch".into(),
                ));
            }
            return self.apply_duplex_aes_blob_for_session(session_id, trimmed);
        }
        if let Some((session_id, payload)) = duplex::parse_duplex_frame_json(trimmed) {
            return self.apply_duplex_frame(&session_id, &payload);
        }
        if let Ok(accept) = duplex::parse_accept_from_inbound_plain(trimmed) {
            self.apply_duplex_accept(accept);
            return Ok(0);
        }
        if let Some(reject) = duplex::parse_reject_details(trimmed) {
            tracing::warn!(
                session = %reject.session_id,
                reason = %reject.reason,
                retryable = reject.retryable,
                "received duplex_reject; terminating duplex so the application can reconnect"
            );
            self.mark_duplex_rejected(&reject.session_id);
            return Ok(0);
        }
        let mut last_err = L0dError::L0("inbound decrypt failed for every listen wallet".into());
        let recipients = pgp::pkesk_recipient_key_ids(&chunk.payload).unwrap_or_default();
        if !recipients.is_empty() {
            tracing::debug!(
                recipients = ?recipients,
                "inbound user-PGP PKESK recipients"
            );
        }
        let static_secrets: Vec<(Cert, Option<String>)> = self
            .user_secrets
            .iter()
            .map(|secret| (secret.cert.clone(), secret.wallet.clone()))
            .collect();
        for (secret, ingress_wallet) in static_secrets {
            if !inbound_secret_matches_recipients(&secret, &recipients) {
                continue;
            }
            match listen::inbound_plain_from_user_armor(&chunk.payload, &secret) {
                Ok(plain) => {
                    return self.apply_decrypted_inbound_plain(&plain, ingress_wallet.as_deref())
                }
                Err(err) => last_err = err,
            }
        }
        // Per-socket temporary identities are process-memory-only and are not
        // part of the static channel secret list.  Their listen SSE carries
        // the peer's duplex_accept/reject encrypted to this temporary PGP key.
        let temporary_secrets: Vec<(Cert, String)> = {
            let guard = self.duplex.lock().unwrap_or_else(|p| p.into_inner());
            guard
                .values()
                .filter_map(|session| {
                    session.accept_identity.as_ref().map(|identity| {
                        (
                            identity.user_cert.clone(),
                            identity.wallet_address().to_owned(),
                        )
                    })
                })
                .collect()
        };
        for (secret, ingress_wallet) in temporary_secrets {
            if !inbound_secret_matches_recipients(&secret, &recipients) {
                continue;
            }
            match listen::inbound_plain_from_user_armor(&chunk.payload, &secret) {
                Ok(plain) => {
                    return self.apply_decrypted_inbound_plain(&plain, Some(&ingress_wallet))
                }
                Err(err) => last_err = err,
            }
        }
        self.inbound_refused = self.inbound_refused.saturating_add(1);
        Err(last_err)
    }

    fn apply_decrypted_inbound_plain(
        &mut self,
        plain: &str,
        ingress_wallet: Option<&str>,
    ) -> Result<usize, L0dError> {
        if let Ok(offer) = duplex::parse_offer_from_inbound_plain(plain) {
            self.apply_duplex_offer(offer, ingress_wallet);
            return Ok(0);
        }
        if let Ok(accept) = duplex::parse_accept_from_inbound_plain(plain) {
            self.apply_duplex_accept(accept);
            return Ok(0);
        }
        if let Some(reject) = duplex::parse_reject_details(plain) {
            tracing::warn!(
                session = %reject.session_id,
                reason = %reject.reason,
                retryable = reject.retryable,
                "received duplex_reject; terminating duplex so the application can reconnect"
            );
            self.mark_duplex_rejected(&reject.session_id);
            return Ok(0);
        }
        if let Some((session_id, payload)) = duplex::parse_duplex_frame_json(plain) {
            return self.apply_duplex_frame(&session_id, &payload);
        }
        match envelope::decode(plain) {
            Ok((_env, ipv4)) if listen::looks_like_ipv4(&ipv4) => self.queue_inbound_ipv4(ipv4),
            Ok(_) => Err(L0dError::L0("inbound payload is not IPv4".into())),
            Err(err) => Err(err),
        }
    }

    fn apply_duplex_aes_blob_for_session(
        &mut self,
        session_id: &str,
        blob: &str,
    ) -> Result<usize, L0dError> {
        let key = {
            let guard = self.duplex.lock().unwrap_or_else(|p| p.into_inner());
            let Some(session) = guard.values().find(|s| s.session_id == session_id) else {
                self.inbound_refused = self.inbound_refused.saturating_add(1);
                return Err(L0dError::L0(format!(
                    "duplex AES blob belongs to unknown session {session_id}"
                )));
            };
            let Some(key) = session.key else {
                return Err(L0dError::L0(format!(
                    "duplex AES blob session {session_id} has no key"
                )));
            };
            key
        };
        let plain = match aes::open(&key, blob) {
            Ok(plain) => plain,
            Err(err) => {
                self.mark_duplex_rejected(session_id);
                return Err(L0dError::L0(format!(
                    "duplex AES session {session_id}: {err}"
                )));
            }
        };
        let json = match String::from_utf8(plain) {
            Ok(json) => json,
            Err(err) => {
                self.mark_duplex_rejected(session_id);
                return Err(L0dError::L0(format!("duplex AES plaintext utf8: {err}")));
            }
        };
        if let Some(ping_session_id) = duplex::parse_duplex_ping_json(&json) {
            if ping_session_id != session_id {
                self.mark_duplex_rejected(session_id);
                return Err(L0dError::L0(format!(
                    "duplex ping session mismatch: owner={session_id}, payload={ping_session_id}"
                )));
            }
            let mut guard = self.duplex.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(sess) = guard.values_mut().find(|s| s.session_id == session_id) {
                sess.peer_return_attached = true;
            }
            return Ok(0);
        }
        if let Some((payload_session_id, payload)) = duplex::parse_duplex_frame_json(&json) {
            if payload_session_id != session_id {
                self.mark_duplex_rejected(session_id);
                return Err(L0dError::L0(format!(
                    "duplex frame session mismatch: owner={session_id}, payload={payload_session_id}"
                )));
            }
            return self.apply_duplex_frame(&payload_session_id, &payload);
        }
        self.apply_inbound_armor(&json)
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
        // Stream clients register a local TCP return channel before sending
        // bytes. Check it first: a raw TCP payload can begin with a byte that
        // looks like an IPv4 header, and proxy-only peers intentionally have
        // no TUN writer. Only legacy packet-mode sessions use the TUN path.
        // A stream payload must be routed by session first.  TCP data is
        // arbitrary bytes, so inspecting the first byte for an IPv4 header
        // before consulting the stream maps can misclassify a payload that
        // happens to start with 0x45 (or another IPv4-looking byte).  It also
        // made the proxy-only endpoint try to write stream data to a
        // nonexistent TUN device.
        let local_stream = {
            let receivers = self.local_streams.lock().unwrap_or_else(|p| p.into_inner());
            receivers.get(session_id).cloned()
        };
        let proxy_stream = if local_stream.is_none() {
            let receivers = self
                .proxy_receivers
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            receivers.get(session_id).cloned()
        } else {
            None
        };
        let n = if let Some(tx) = local_stream.or(proxy_stream) {
            tx.try_send(inbound.clone())
                .map_err(|_| L0dError::L0("duplex stream queue is full".into()))?;
            inbound.len()
        } else if listen::looks_like_ipv4(&inbound) {
            self.queue_inbound_ipv4(inbound)?
        } else {
            self.inbound_refused = self.inbound_refused.saturating_add(1);
            return Err(L0dError::L0(
                "duplex plaintext is not IPv4 and no stream receiver is attached".into(),
            ));
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

    fn apply_duplex_offer(&mut self, offer: duplex::DuplexOffer, ingress_wallet: Option<&str>) {
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
        let mut proxy_handshake: Option<(
            ChannelWire,
            String,
            String,
            DuplexSession,
            String,
            Vec<u8>,
            bool,
        )> = None;
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
                if duplex_duplicate_offer_should_ignore(sess, had_key, offer.key) {
                    offer_duplicate_ignored = true;
                    tracing::debug!(
                        session = %offer.session_id,
                        port = sess.port,
                        pipe_up = sess.pipe_tx.is_some(),
                        pipe_inflight = sess.pipe_connect_inflight,
                        rejected = sess.rejected,
                        "duplex_offer duplicate ignored before mutating session ownership"
                    );
                    break;
                }
                if had_key && sess.key != Some(offer.key) {
                    if let Some(cancel) = sess.pipe_cancel.take() {
                        cancel.store(true, Ordering::Release);
                    }
                    sess.pipe_tx = None;
                    sess.pipe_connect_inflight = false;
                    tracing::info!(
                        session = %offer.session_id,
                        "duplex_offer rekeyed; old occupied pipe cancelled"
                    );
                }
                sess.key = Some(offer.key);
                sess.peer_listen_wallet = Some(offer.listen_wallet.clone());
                if !offer.listen_user_pgp.trim().is_empty() {
                    sess.peer_listen_user_pgp = Some(offer.listen_user_pgp.clone());
                }
                if !offer.listen_route_pgp.trim().is_empty() {
                    sess.peer_listen_route_pgp = Some(offer.listen_route_pgp.clone());
                }
                if !offer.listen_mailbox_wallet.trim().is_empty() {
                    sess.peer_listen_mailbox_wallet = Some(offer.listen_mailbox_wallet.clone());
                }
                if !had_key {
                    sess.peer_attached = true;
                    sess.rejected = false;
                    tracing::info!(
                        session = %offer.session_id,
                        from = %offer.from,
                        listen = %offer.listen_wallet,
                        "duplex_offer accepted; overlay AES key stored in memory only"
                    );
                    if let Some(wire) = self.channel_wire.get(&sess.port) {
                        if !offer.listen_route_pgp.trim().is_empty() {
                            send_accept = Some((
                                wire.clone(),
                                offer.listen_wallet.clone(),
                                offer.listen_route_pgp.clone(),
                                sess.clone(),
                                offer.listen_user_pgp.clone(),
                            ));
                        }
                    }
                }
                break;
            }
            if let Some(old_key) = rekey_from {
                if let Some(sess) = guard.remove(&old_key) {
                    guard.insert(duplex_key_of(&sess), sess);
                }
            }
            // In proxy-only mode a signed mainWallet:port offer carrying a
            // firstChunk is the one explicit remote socket event. The signer
            // was already recovered as billingWallet by the parser; it does
            // not need to be pre-listed as a static overlay peer.
            if !offer_matched {
                let matching_wire = self.channel_wire.get(&offer.port);
                let host_ok = matching_wire
                    .map(|w| w.main_wallet.eq_ignore_ascii_case(&offer.main_wallet))
                    .unwrap_or(false);
                // A shared mainWallet may expose each port through a distinct
                // channel user-PGP wallet. New allocation is authorized only
                // when this armor was actually decrypted by that configured
                // port wallet. Merely carrying mainWallet + port in JSON is
                // insufficient and temporary listeners can never allocate.
                let arrived_on_main_wallet_port = matching_wire
                    .zip(ingress_wallet)
                    .map(|(wire, wallet)| eip191::eoa_eq(wallet, &wire.eoa))
                    .unwrap_or(false);
                let expected_port_wallet = matching_wire.map(|wire| wire.eoa.as_str());
                let socket_identity_ok = eip191::eoa_eq(&offer.from, &offer.listen_wallet);
                let target_ok = eip191::eoa_eq(&offer.peer_wallet, &offer.main_wallet);
                let peer_route_ready = !offer.listen_user_pgp.trim().is_empty()
                    && !offer.listen_route_pgp.trim().is_empty();
                if host_ok
                    && arrived_on_main_wallet_port
                    && socket_identity_ok
                    && target_ok
                    && peer_route_ready
                    && !offer.first_chunk.is_empty()
                    && self.proxy_registry.mode(offer.port) == Some(ProxyMode::Duplex)
                {
                    // A proxy has no local application socket from which to
                    // pre-register this line.  The initiator's socket event
                    // is therefore represented by the authenticated
                    // firstChunk in this offer.  Allocate exactly one
                    // per-offer line here; subsequent offers/frames must
                    // match this pipe_handle.
                    if let Some(wire) = self.channel_wire.get(&offer.port).cloned() {
                        let (identity, listen_ready) = match self
                            .ready_identities
                            .get(&offer.port)
                            .and_then(|pool| pool.take())
                        {
                            Some(identity) => (Some(identity), true),
                            None => match crate::l0::identity::TemporaryIdentity::generate() {
                                Ok(identity) => (Some(identity), false),
                                Err(err) => {
                                    tracing::warn!(
                                        port = offer.port,
                                        error = %err,
                                        "temporary proxy identity generation failed"
                                    );
                                    (None, false)
                                }
                            },
                        };
                        if let Some(identity) = identity {
                            let session = DuplexSession {
                                session_id: offer.session_id.clone(),
                                role: DuplexLineRole::Proxy,
                                created_at: now,
                                key: Some(offer.key),
                                dest: Ipv4Addr::UNSPECIFIED,
                                port: offer.port,
                                peer_eoa: offer.billing_wallet.clone(),
                                guest_up: false,
                                peer_attached: true,
                                rejected: false,
                                host_eoa: offer.main_wallet.clone(),
                                peer_listen_user_pgp: Some(offer.listen_user_pgp.clone()),
                                peer_listen_route_pgp: Some(offer.listen_route_pgp.clone()),
                                peer_listen_wallet: Some(offer.listen_wallet.clone()),
                                peer_listen_mailbox_wallet: (!offer.listen_mailbox_wallet
                                    .trim()
                                    .is_empty())
                                .then(|| offer.listen_mailbox_wallet.clone()),
                                accept_identity: Some(identity),
                                peer_return_attached: false,
                                response_chunk_delivered: false,
                                pipe_tx: None,
                                pipe_gen: 0,
                                pipe_connect_inflight: false,
                                pipe_cancel: None,
                            };
                            let session_id = session.session_id.clone();
                            guard.insert(duplex_key_of(&session), session.clone());
                            offer_matched = true;
                            proxy_handshake = Some((
                                wire.clone(),
                                offer.listen_wallet.clone(),
                                offer.listen_route_pgp.clone(),
                                session.clone(),
                                offer.listen_user_pgp.clone(),
                                offer.first_chunk.clone(),
                                listen_ready,
                            ));
                            tracing::info!(
                                session = %session_id,
                                port = offer.port,
                                socket_wallet = %offer.from,
                                billing_wallet = %offer.billing_wallet,
                                listen_ready,
                                "signed mainWallet:port firstChunk allocated one proxy duplex line"
                            );
                        }
                    }
                } else if host_ok {
                    tracing::warn!(
                        session = %offer.session_id,
                        main_wallet = %offer.main_wallet,
                        port = offer.port,
                        listen_wallet = %offer.listen_wallet,
                        ingress_wallet = ingress_wallet.unwrap_or("<unknown>"),
                        expected_port_wallet = expected_port_wallet.unwrap_or("<none>"),
                        arrived_on_main_wallet_port,
                        socket_identity_ok,
                        target_ok,
                        peer_route_ready,
                        "duplex_offer matched mainWallet:port but failed explicit new-socket checks; rejecting without allocation"
                    );
                }
            }
        }
        if offer_matched && offer_duplicate_ignored {
            return;
        }
        if let Some((wire, target, route, sess, initiator_pipe_pgp, initial, listen_ready)) =
            proxy_handshake
        {
            let session_id = sess.session_id.clone();
            let ready = self.spawn_dynamic_accept_listen(&wire, &sess, listen_ready);
            let Some(ready) = ready else {
                tracing::warn!(
                    session = %session_id,
                    "proxy duplex handshake could not start temporary listen"
                );
                return;
            };
            self.spawn_proxy_handshake(
                ready,
                wire,
                target,
                route,
                sess,
                initiator_pipe_pgp,
                initial,
            );
            return;
        }
        if let Some((wire, target, route, sess, initiator_pipe_pgp)) = send_accept {
            // A proxy accept owns a fresh SI listen identity.  Start that
            // listen before sending the accept so the initiator's subsequent
            // l0_connect is addressed to a real per-line mailbox, rather than
            // the channel EOA shared by every client on this logical port.
            self.spawn_dynamic_accept_listen(&wire, &sess, false);
            // Chat gossip duplex_accept (control plane), then reverse occupy the
            // initiator's listenWallet so each endpoint owns a separate occupied
            // pipe bound by the same pipe_handle (RULES dedicated-pipe section).
            spawn_duplex_accept_chat(
                wire.clone(),
                initiator_pipe_pgp,
                sess.clone(),
                self.duplex.clone(),
                None,
                self.listen_owners.clone(),
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
        if let Some(wire) = self.channel_wire.get(&offer.port) {
            if eip191::eoa_eq(&wire.main_wallet, &offer.main_wallet)
                && !offer.listen_route_pgp.trim().is_empty()
            {
                send_reject = Some((
                    wire.clone(),
                    offer.listen_wallet.clone(),
                    offer.listen_route_pgp.clone(),
                    offer.key,
                    offer.session_id.clone(),
                ));
            }
        }
        if let Some((wire, target, route, key, session_id)) = send_reject {
            let ts = chrono::Utc::now().timestamp().max(0) as u64;
            let first = duplex::encode_reject_command(
                &wire.eoa,
                &session_id,
                ts,
                "unsupported",
                false,
            )
                .ok()
                .and_then(|json| aes::seal(&key, json.as_bytes()).ok());
            let dummy = DuplexSession {
                session_id,
                role: DuplexLineRole::Peer,
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
                peer_listen_route_pgp: Some(route.clone()),
                peer_listen_wallet: Some(target.clone()),
                peer_listen_mailbox_wallet: None,
                accept_identity: None,
                peer_return_attached: false,
                response_chunk_delivered: false,
                pipe_tx: None,
                pipe_gen: 0,
                pipe_connect_inflight: false,
                pipe_cancel: None,
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

    fn spawn_dynamic_accept_listen(
        &self,
        wire: &ChannelWire,
        sess: &DuplexSession,
        listen_ready: bool,
    ) -> Option<oneshot::Receiver<()>> {
        let Some(identity) = sess.accept_identity.as_ref() else {
            return None;
        };
        if listen_ready {
            // Pre-warm minted TemporaryIdentity.session_id at pool fill time.
            // Duplex AES is sealed with offer.session_id (client pipe handle).
            // Rebind the live SSE owner so ingress looks up the duplex map.
            if let Some(owner) = self.listen_owners.find_by_wallet(identity.wallet_address()) {
                let previous = owner.current_session_id();
                owner.bind_session_id(sess.session_id.clone());
                tracing::info!(
                    session = %sess.session_id,
                    port = sess.port,
                    temporary_wallet = %identity.wallet_address(),
                    previous_session = ?previous,
                    "proxy handshake rebound pre-warmed listen to duplex session"
                );
            } else {
                tracing::warn!(
                    session = %sess.session_id,
                    port = sess.port,
                    temporary_wallet = %identity.wallet_address(),
                    "proxy handshake pre-warmed listen owner missing; AES may unknown-session"
                );
            }
            let (ready_tx, ready_rx) = oneshot::channel();
            let _ = ready_tx.send(());
            tracing::info!(
                session = %sess.session_id,
                port = sess.port,
                temporary_wallet = %identity.wallet_address(),
                "proxy handshake using pre-warmed temporary listen"
            );
            return Some(ready_rx);
        }
        let Some(tx) = self.inbound_feed.clone() else {
            tracing::warn!(
                session = %sess.session_id,
                "cannot start temporary duplex listen: inbound feed is unavailable"
            );
            return None;
        };
        if let Err(err) = pgp::transport_key_id_armored(&wire.route_pgp) {
            tracing::warn!(
                session = %sess.session_id,
                error = %err,
                "cannot start temporary duplex listen: mailbox route key is invalid"
            );
            return None;
        }
        let (ready_tx, ready_rx) = oneshot::channel();
        let identity = identity.clone();
        let entries = wire.listen_entries.clone();
        let si_pool = wire.si_pool.clone();
        let route_pgp = wire.route_pgp.clone();
        let signer = wire.eth.clone();
        let billing_wallet = wire.main_wallet.clone();
        let session_id = sess.session_id.clone();
        let port = sess.port;
        let listen_owners = self.listen_owners.clone();
        tokio::spawn(async move {
            // Handshake owns reverse occupy after duplex_accept. Passing a
            // rebuild here raced spawn_proxy_handshake and 409'd the
            // initiator mailbox as soon as this temporary SSE came up.
            if spawn_listen_worker_with_ready(
                entries,
                si_pool,
                route_pgp,
                identity.wallet_address().to_owned(),
                signer.clone(),
                tx,
                true,
                None,
                Some(billing_wallet),
                Some(signer),
                Some(identity.clone()),
                // Cold proxy listen must own the duplex pipe handle, not the
                // random TemporaryIdentity.session_id, or AES ingress misses.
                Some(session_id.clone()),
                Some(ready_tx),
                listen_owners,
            ) {
                tracing::info!(
                    session = %session_id,
                    port,
                    temporary_wallet = %identity.wallet_address(),
                    "started per-line temporary l0_listen"
                );
            } else {
                tracing::warn!(
                    session = %session_id,
                    port,
                    "temporary proxy l0_listen worker failed to start"
                );
            }
        });
        Some(ready_rx)
    }

    fn spawn_proxy_handshake(
        &self,
        ready: oneshot::Receiver<()>,
        wire: ChannelWire,
        target: String,
        route: String,
        sess: DuplexSession,
        initiator_pipe_pgp: String,
        initial: Vec<u8>,
    ) {
        let session_id = sess.session_id.clone();
        let port = sess.port;
        let Some(line) = self.proxy_registry.line(&session_id, port).ok().flatten() else {
            tracing::warn!(
                session = %session_id,
                port,
                "proxy duplex handshake has no configured upstream"
            );
            return;
        };
        let (to_upstream, mut from_peer) = mpsc::channel::<Vec<u8>>(64);
        {
            let mut receivers = self
                .proxy_receivers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if receivers.insert(session_id.clone(), to_upstream).is_some() {
                tracing::debug!(
                    session = %session_id,
                    "proxy duplex handshake receiver already exists"
                );
                return;
            }
        }
        let (from_upstream, mut to_pipe) = mpsc::channel::<Vec<u8>>(64);
        let receiver_registry = self.proxy_receivers.clone();
        let session_registry = self.duplex.clone();
        let duplex = self.duplex.clone();
        let extras = self.pipe_extras();
        let seq = self.proxy_seq.clone();
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_for_cleanup = cancel.clone();
        let listen_owners = self.listen_owners.clone();
        let listen_wallet = sess
            .accept_identity
            .as_ref()
            .map(|identity| identity.wallet_address().to_owned());
        tokio::spawn(async move {
            if !matches!(
                tokio::time::timeout(
                    Duration::from_secs(DYNAMIC_LISTEN_READY_TIMEOUT_SECS),
                    ready,
                )
                .await,
                Ok(Ok(()))
            ) {
                tracing::warn!(
                    session = %session_id,
                    "temporary proxy route/listen did not become ready"
                );
                // The initiator already has a live l0_listen and is waiting
                // for this side's accept.  Report the local SSE capacity
                // failure over one final occupied control pipe instead of
                // leaving the initiator waiting until its generic timeout.
                if let Some(key) = sess.key {
                    let responder = sess
                        .accept_identity
                        .as_ref()
                        .map(|identity| identity.wallet_address().to_owned())
                        .unwrap_or_else(|| wire.eoa.clone());
                    if let Ok(json) = duplex::encode_reject_command(
                        &responder,
                        &session_id,
                        chrono::Utc::now().timestamp().max(0) as u64,
                        "pool_full",
                        true,
                    ) {
                        if let Ok(first) = aes::seal(&key, json.as_bytes()) {
                            let mut reject_sess = sess.clone();
                            reject_sess.rejected = true;
                            reject_sess.pipe_tx = None;
                            reject_sess.pipe_cancel = None;
                            spawn_l0_pipe(
                                wire.clone(),
                                route.clone(),
                                target.clone(),
                                Some(first),
                                reject_sess,
                                duplex.clone(),
                                PipeExtras::empty(),
                            );
                        }
                    }
                }
                if let Some(wallet) = listen_wallet.as_deref() {
                    let _ = listen_owners.release_by_wallet(wallet);
                }
                receiver_registry
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .remove(&session_id);
                retain_duplex_except_session_id(
                    &mut session_registry
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()),
                    &session_id,
                );
                return;
            }

            let (mut upstream, response) =
                match proxy::connect_upstream_with_initial(&line, &initial).await {
                    Ok(value) => value,
                    Err(err) => {
                        tracing::warn!(
                            session = %session_id,
                            error = %err,
                            "proxy duplex upstream handshake failed"
                        );
                        receiver_registry
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .remove(&session_id);
                        retain_duplex_except_session_id(
                            &mut session_registry
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner()),
                            &session_id,
                        );
                        return;
                    }
                };

            // Accept first. Reverse-occupy only if the return pipe is still
            // empty — listen-up rebuild is skipped for this temp listen, so
            // an immediate reverse occupy no longer 409s the initiator.
            // Do not wait for a resume blob: geth/beacon stay paused until
            // both pipes are up. Later initiator frames still reach
            // `from_peer` and `run_proxy_stream` writes them upstream.
            spawn_duplex_accept_chat(
                wire.clone(),
                initiator_pipe_pgp,
                sess.clone(),
                duplex.clone(),
                Some(response),
                listen_owners.clone(),
            );

            let needs_reverse = {
                let guard = duplex.lock().unwrap_or_else(|p| p.into_inner());
                guard
                    .values()
                    .find(|session| session.session_id == session_id)
                    .map(|session| {
                        session.pipe_tx.is_none()
                            && !session.pipe_connect_inflight
                            && !session.rejected
                    })
                    .unwrap_or(false)
            };
            if needs_reverse {
                tracing::info!(
                    session = %session_id,
                    "proxy reverse occupy after accept"
                );
                spawn_l0_pipe(
                    wire,
                    route,
                    target,
                    None,
                    sess,
                    duplex.clone(),
                    extras.clone(),
                );
            } else {
                tracing::info!(
                    session = %session_id,
                    "proxy skip reverse occupy; pipe already attached"
                );
                let _ = (wire, route, target, sess, extras);
            }

            let pipe_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            loop {
                let pipe_ready = {
                    let guard = duplex.lock().unwrap_or_else(|p| p.into_inner());
                    guard
                        .values()
                        .find(|session| session.session_id == session_id)
                        .map(|session| session.pipe_tx.is_some() && !session.rejected)
                        .unwrap_or(false)
                };
                if pipe_ready {
                    break;
                }
                if tokio::time::Instant::now() >= pipe_deadline {
                    tracing::warn!(
                        session = %session_id,
                        "proxy reverse occupied pipe did not become ready"
                    );
                    receiver_registry
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .remove(&session_id);
                    retain_duplex_except_session_id(
                        &mut session_registry
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner()),
                        &session_id,
                    );
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }

            let forward_session = session_id.clone();
            let forward_duplex = duplex.clone();
            let forward_seq = seq.clone();
            tokio::spawn(async move {
                while let Some(bytes) = to_pipe.recv().await {
                    let n = forward_seq.fetch_add(1, Ordering::Relaxed);
                    if let Err(err) =
                        try_send_proxy_frame(&forward_duplex, &forward_session, n, &bytes)
                    {
                        tracing::debug!(
                            session = %forward_session,
                            error = %err,
                            "proxy upstream → occupied pipe failed"
                        );
                        break;
                    }
                }
            });

            if let Err(err) =
                proxy::run_proxy_stream(&session_id, &mut upstream, &mut from_peer, &from_upstream)
                    .await
            {
                tracing::warn!(
                    session = %session_id,
                    error = %err,
                    "proxy duplex stream closed"
                );
            }
            cancel_for_cleanup.store(true, Ordering::Release);
            if let Some(wallet) = listen_wallet.as_deref() {
                let _ = listen_owners.release_by_wallet(wallet);
            }
            receiver_registry
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&session_id);
            retain_duplex_except_session_id(
                &mut session_registry
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()),
                &session_id,
            );
        });
    }

    fn apply_duplex_accept(&mut self, accept: duplex::DuplexAccept) {
        {
            let mut guard = self.duplex.lock().unwrap_or_else(|p| p.into_inner());
            for sess in guard.values_mut() {
                if sess.session_id != accept.session_id {
                    continue;
                }
                if !eip191::eoa_eq(&accept.billing_wallet, &sess.peer_eoa) {
                    tracing::warn!(
                        session = %accept.session_id,
                        signer = %accept.billing_wallet,
                        expected = %sess.peer_eoa,
                        "duplex_accept signer is not this session's proxy main wallet"
                    );
                    return;
                }
                let now = chrono::Utc::now().timestamp().max(0) as u64;
                if duplex_offer_is_expired(accept.timestamp, now) {
                    tracing::warn!(
                        session = %accept.session_id,
                        timestamp = accept.timestamp,
                        now,
                        "duplex_accept expired; keeping local socket paused"
                    );
                    return;
                }
                if accept.listen_user_pgp.trim().is_empty()
                    || accept.listen_route_pgp.trim().is_empty()
                    || eip191::eoa_eq(&accept.listen_wallet, &accept.billing_wallet)
                {
                    tracing::warn!(
                        session = %accept.session_id,
                        listen_wallet = %accept.listen_wallet,
                        "duplex_accept lacks a distinct temporary listen mailbox"
                    );
                    return;
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
                sess.peer_listen_route_pgp = Some(accept.listen_route_pgp.clone());
                sess.peer_listen_wallet = Some(accept.listen_wallet.clone());
                if !accept.listen_mailbox_wallet.trim().is_empty() {
                    sess.peer_listen_mailbox_wallet = Some(accept.listen_mailbox_wallet.clone());
                }
                sess.peer_attached = true;
                sess.rejected = false;
                if !accept.response_chunk.is_empty() && !sess.response_chunk_delivered {
                    if let Some(tx) = self
                        .local_streams
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .get(&accept.session_id)
                        .cloned()
                    {
                        match tx.try_send(accept.response_chunk.clone()) {
                            Ok(()) => {
                                sess.response_chunk_delivered = true;
                            }
                            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                tracing::warn!(
                                    session = %accept.session_id,
                                    "duplex_accept responseChunk queue is full"
                                );
                            }
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                tracing::warn!(
                                    session = %accept.session_id,
                                    "duplex_accept responseChunk local socket closed"
                                );
                            }
                        }
                    } else {
                        tracing::warn!(
                            session = %accept.session_id,
                            "duplex_accept responseChunk has no local socket"
                        );
                    }
                }
                tracing::info!(
                    session = %accept.session_id,
                    peer_listen = %accept.listen_wallet,
                    "duplex_accept queued responseChunk; occupy after local write"
                );
                // Occupy is owned by the local TCP task after it writes
                // responseChunk. Do not spawn here: that raced the write and
                // left geth/beacon paused. The TCP task occupies even when
                // the local peer has no extra resume bytes yet.
                break;
            }
        }
    }

    fn mark_duplex_rejected(&mut self, session_id: &str) {
        let mut guard = self.duplex.lock().unwrap_or_else(|p| p.into_inner());
        for sess in guard.values_mut() {
            if sess.session_id == session_id {
                sess.rejected = true;
                sess.peer_attached = false;
                if let Some(cancel) = sess.pipe_cancel.take() {
                    cancel.store(true, Ordering::Release);
                }
                sess.pipe_tx = None;
                sess.pipe_connect_inflight = false;
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

fn inbound_secret_matches_recipients(cert: &Cert, recipients: &[String]) -> bool {
    if recipients.is_empty() {
        return true;
    }
    match pgp::transport_key_id(cert) {
        Ok(id) => recipients.iter().any(|r| r.eq_ignore_ascii_case(&id)),
        Err(_) => false,
    }
}

fn insert_peer_pgp_ports(
    peers: &mut HashMap<(Ipv4Addr, u16), PeerPgp>,
    dest: Ipv4Addr,
    explicit_ports: impl IntoIterator<Item = u16>,
    keys: &PeerPgp,
) {
    for port in explicit_ports {
        peers.insert((dest, port), keys.clone());
    }
}

fn spawn_legacy_listen_into(
    cfg: &ValidatedConfig,
    routing_eoa: &str,
    has_secret: bool,
    tx: mpsc::Sender<listen::InboundChunk>,
    pipe_rebuild: Option<L0PipeRebuild>,
    owners: listen::ListenOwnerRegistry,
    si_pool: Option<Arc<SiPool>>,
) -> bool {
    let has_si = si_pool.is_some() || !cfg.l0.listen_entries.is_empty();
    if !has_secret || routing_eoa.is_empty() || !has_si {
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
    let skip_chat = cfg.l0.proxies.is_empty()
        && cfg.l0.proxy_duplex.is_empty()
        && !cfg.client_duplex.is_empty();
    let chat = !skip_chat
        && spawn_listen_worker(
            cfg.l0.listen_entries.clone(),
            si_pool.clone(),
            route.clone(),
            routing_eoa.to_string(),
            eth.clone(),
            tx.clone(),
            false,
            None,
            None,
            None,
            None,
            owners.clone(),
        );
    let l0 = spawn_listen_worker(
        cfg.l0.listen_entries.clone(),
        si_pool,
        route,
        routing_eoa.to_string(),
        eth,
        tx,
        true,
        pipe_rebuild,
        None,
        None,
        None,
        owners,
    );
    chat || l0
}

fn spawn_channel_listens_into(
    cfg: &ValidatedConfig,
    user_secrets: &mut Vec<SecretCert>,
    tx: mpsc::Sender<listen::InboundChunk>,
    pipe_rebuild: Option<L0PipeRebuild>,
    owners: listen::ListenOwnerRegistry,
    si_pool: Option<Arc<SiPool>>,
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
            Ok(cert) => user_secrets.push(SecretCert {
                cert,
                wallet: Some(ch.routing_eoa.clone()),
            }),
            Err(err) => tracing::warn!(
                eoa = %ch.routing_eoa,
                error = %err,
                "P1: channel routing_key_file was not loaded; inbound decrypt for that wallet stays off"
            ),
        }
        if si_pool.is_none() && ch.listen_entries.is_empty() {
            tracing::warn!(eoa = %ch.routing_eoa, "P1: channel listen_entries empty and SI pool disabled; that SSE stays off");
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
        let skip_chat = cfg.l0.proxies.is_empty()
            && cfg.l0.proxy_duplex.is_empty()
            && !cfg.client_duplex.is_empty();
        if !skip_chat
            && spawn_listen_worker(
                ch.listen_entries.clone(),
                si_pool.clone(),
                route.clone(),
                ch.routing_eoa.clone(),
                eth.clone(),
                tx.clone(),
                false,
                None,
                None,
                None,
                None,
                owners.clone(),
            )
        {
            spawned += 1;
        }
        if spawn_listen_worker(
            ch.listen_entries.clone(),
            si_pool.clone(),
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
            owners.clone(),
        ) {
            spawned += 1;
        }
    }
    spawned > 0
}

fn spawn_listen_worker(
    entries: Vec<String>,
    si_pool: Option<Arc<SiPool>>,
    mailbox_route: String,
    routing_eoa: String,
    signer_eth: EthSecret,
    tx: mpsc::Sender<listen::InboundChunk>,
    l0_exclusive: bool,
    pipe_rebuild: Option<L0PipeRebuild>,
    billing_wallet: Option<String>,
    billing_eth: Option<EthSecret>,
    temporary_identity: Option<crate::l0::identity::TemporaryIdentity>,
    owners: listen::ListenOwnerRegistry,
) -> bool {
    spawn_listen_worker_with_ready(
        entries,
        si_pool,
        mailbox_route,
        routing_eoa,
        signer_eth,
        tx,
        l0_exclusive,
        pipe_rebuild,
        billing_wallet,
        billing_eth,
        temporary_identity,
        None,
        None,
        owners,
    )
}

fn spawn_listen_worker_with_ready(
    entries: Vec<String>,
    si_pool: Option<Arc<SiPool>>,
    mailbox_route: String,
    routing_eoa: String,
    signer_eth: EthSecret,
    tx: mpsc::Sender<listen::InboundChunk>,
    l0_exclusive: bool,
    pipe_rebuild: Option<L0PipeRebuild>,
    billing_wallet: Option<String>,
    billing_eth: Option<EthSecret>,
    temporary_identity: Option<crate::l0::identity::TemporaryIdentity>,
    // When set (proxy duplex), listen SSE AES is keyed by this pipe handle
    // instead of TemporaryIdentity.session_id.
    bind_session_id: Option<String>,
    mut ready: Option<oneshot::Sender<()>>,
    owners: listen::ListenOwnerRegistry,
) -> bool {
    let Some(handle) = tokio::runtime::Handle::try_current().ok() else {
        return false;
    };
    let Ok(client) = listen::listen_http_client() else {
        return false;
    };
    let owner_id = temporary_identity
        .as_ref()
        .map(|identity| identity.wallet_address().to_owned())
        .unwrap_or_else(|| routing_eoa.clone());
    let owned_session_id = bind_session_id.or_else(|| {
        temporary_identity
            .as_ref()
            .map(|identity| identity.session_id.clone())
    });
    let owner = listen::OwnedListenSession::new(
        owner_id,
        owned_session_id,
        if l0_exclusive { "l0" } else { "chat" },
    );
    if !owners.register(owner.clone()) {
        tracing::warn!(eoa = %routing_eoa, l0 = l0_exclusive, "listen owner already registered");
        return false;
    }
    let owner_registry = owners.clone();
    let registered_owner_id = owner.id.clone();
    let task_owner = owner.clone();
    let task = handle.spawn(async move {
        let user_pgp_key_id = temporary_identity
            .as_ref()
            .map(|identity| identity.user_key_id.clone());
        let mut last_failed: Option<String> = None;
        loop {
            if task_owner.is_cancelled() {
                break;
            }
            let entry = if let Some(pool) = si_pool.as_ref() { match pool.acquire(last_failed.as_deref()).await {
                Ok(entry) => entry,
                Err(error) => { tracing::warn!(eoa = %routing_eoa, %error, "P1 listen: SI pool acquire failed; worker idle"); tokio::time::sleep(Duration::from_secs(LISTEN_RECONNECT_SECS)).await; continue; }
            }} else { let Some(entry) = listen::pick_listen_entry(&entries, last_failed.as_deref()) else {
                tracing::warn!(eoa = %routing_eoa, "P1 listen: listen_entries empty; worker idle"); tokio::time::sleep(Duration::from_secs(LISTEN_RECONNECT_SECS)).await; continue;
            }; entry.to_string() };
            let ts = chrono::Utc::now().timestamp().max(0) as u64;
            let prepared = if l0_exclusive {
                match (billing_wallet.as_deref(), billing_eth.as_ref()) {
                    (Some(wallet), Some(eth)) => listen::prepare_l0_listen_post_with_billing(
                        &routing_eoa,
                        wallet,
                        ts,
                        &mailbox_route,
                        &entry,
                        eth,
                        user_pgp_key_id.as_deref(),
                    ),
                    _ => listen::prepare_l0_listen_post(
                        &routing_eoa,
                        ts,
                        &mailbox_route,
                        &entry,
                        &signer_eth,
                        user_pgp_key_id.as_deref(),
                    ),
                }
            } else {
                listen::prepare_listen_post(&routing_eoa, ts, &mailbox_route, &entry, &signer_eth)
            };
            match prepared {
                Ok((url, armor)) => match listen::open_listen_sse(&client, &url, &armor).await {
                    Ok(response) => {
                        task_owner.set_entry(&entry);
                        last_failed = None;
                        if l0_exclusive {
                            if let Some(ctx) = pipe_rebuild.as_ref() {
                                rebuild_l0_pipes_after_listen_up(&routing_eoa, ctx);
                            }
                        }
                        match listen::pump_sse_armors_owned_session(
                            response,
                            &tx,
                            task_owner.clone(),
                            l0_exclusive.then_some(pipe::PIPE_DATA_TIMEOUT),
                            ready.take(),
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
                                    && err.to_string().contains(&format!(
                                        "no inbound data for {}s",
                                        pipe::PIPE_DATA_TIMEOUT.as_secs()
                                    ))
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
                                last_failed = Some(entry.clone());
                                if let Some(pool) = si_pool.as_ref() { pool.mark_failed(&entry).await; }
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
                        if l0_exclusive && err.to_string().contains("pool_full") {
                            // `pool_full` is a terminal failure for this
                            // duplex incarnation.  Retrying the same
                            // l0_listen every three seconds only creates
                            // another abandoned SSE and amplifies the
                            // saturation.  Dropping `ready` wakes the
                            // caller immediately; the APP owns reconnect.
                            task_owner.cancel();
                            owner_registry.remove(&registered_owner_id);
                            tracing::warn!(
                                eoa = %routing_eoa,
                                "l0_listen pool_full; closing duplex incarnation without retry"
                            );
                            return;
                        }
                        last_failed = Some(entry.clone());
                                if let Some(pool) = si_pool.as_ref() { pool.mark_failed(&entry).await; }
                    }
                },
                Err(err) => {
                    tracing::warn!(eoa = %routing_eoa, error = %err, "listen wrap refused");
                    if l0_exclusive && err.to_string().contains("pool_full") {
                        task_owner.cancel();
                        owner_registry.remove(&registered_owner_id);
                        tracing::warn!(
                            eoa = %routing_eoa,
                            "l0_listen pool_full while preparing request; closing duplex incarnation"
                        );
                        return;
                    }
                    last_failed = Some(entry.clone());
                                if let Some(pool) = si_pool.as_ref() { pool.mark_failed(&entry).await; }
                }
            }
            tokio::time::sleep(Duration::from_secs(LISTEN_RECONNECT_SECS)).await;
        }
    });
    owner.attach_task(task);
    true
}

/// Whether a listen SSE reconnect should spawn a fresh outbound `l0_connect`.
fn should_rebuild_l0_pipe_after_listen_up(sess: &DuplexSession, routing_eoa: &str) -> bool {
    if sess.dest.is_unspecified() && sess.accept_identity.is_some() {
        return false;
    }
    // Spoke client first occupy is owned by `run_dynamic_local_tcp_stream`
    // after it writes `responseChunk`. Listen-up must not race that.
    if sess.accept_identity.is_some() && !sess.dest.is_unspecified() && sess.pipe_gen == 0 {
        return false;
    }
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

fn cancel_duplex_pipe(session: &DuplexSession) {
    if let Some(cancel) = session.pipe_cancel.as_ref() {
        cancel.store(true, Ordering::Release);
    }
}

/// Drop every session whose `session_id` matches and stop its occupy task.
fn retain_duplex_except_session_id(map: &mut HashMap<DuplexKey, DuplexSession>, session_id: &str) {
    map.retain(|_, session| {
        if session.session_id == session_id {
            cancel_duplex_pipe(session);
            false
        } else {
            true
        }
    });
}

/// Current AES key for occupy heartbeats. `Stop` when the session was
/// retained or rejected so the pipe does not keep sending a spawn-time key.
fn duplex_pipe_heartbeat(
    duplex: &Arc<Mutex<HashMap<DuplexKey, DuplexSession>>>,
    dest: Ipv4Addr,
    port: u16,
    session_id: &str,
) -> pipe::PipeHeartbeat {
    let guard = duplex.lock().unwrap_or_else(|p| p.into_inner());
    match guard.get(&duplex_key(dest, port, session_id)) {
        None => pipe::PipeHeartbeat::Stop,
        Some(session) if session.rejected => pipe::PipeHeartbeat::Stop,
        Some(session) => match session.key {
            Some(key) => pipe::PipeHeartbeat::Key(key),
            None => pipe::PipeHeartbeat::Skip,
        },
    }
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

/// Dropping a local TCP task must abort its exclusive `l0_listen` so Entry C
/// sees FIN/RST and mailbox B releases the slot. Beacon kill only closes this
/// socket; without this guard the listen worker keeps POSTing SI.
struct ReleaseListenOnDrop {
    owners: listen::ListenOwnerRegistry,
    wallet: String,
}

impl Drop for ReleaseListenOnDrop {
    fn drop(&mut self) {
        if self.owners.release_by_wallet(&self.wallet) {
            tracing::info!(
                eoa = %self.wallet,
                "released l0_listen after local TCP or handshake ended"
            );
        }
    }
}

async fn run_dynamic_local_tcp_stream(
    stream: TcpStream,
    duplex: Arc<Mutex<HashMap<DuplexKey, DuplexSession>>>,
    local_streams: Arc<Mutex<HashMap<String, mpsc::Sender<Vec<u8>>>>>,
    dest: Ipv4Addr,
    port: u16,
    wire: ChannelWire,
    peer_keys: PeerPgp,
    inbound_feed: Option<mpsc::Sender<listen::InboundChunk>>,
    wires: Arc<HashMap<u16, ChannelWire>>,
    peers: Arc<HashMap<(Ipv4Addr, u16), PeerPgp>>,
    proxy_registry: proxy::ProxyRegistry,
    proxy_receivers: Arc<Mutex<HashMap<String, mpsc::Sender<Vec<u8>>>>>,
    proxy_seq: Arc<AtomicU64>,
    ready_pool: Option<Arc<ReadyIdentityPool>>,
    listen_owners: listen::ListenOwnerRegistry,
) -> Result<(), L0dError> {
    // The accepted socket event is the local connection handle.  Allocate
    // before reading application bytes so concurrent sockets can never share
    // a port-selected session.
    let (mut reader, mut writer) = stream.into_split();
    let mut first_chunk = vec![0u8; 16 * 1024];
    let first_len = tokio::time::timeout(Duration::from_secs(15), reader.read(&mut first_chunk))
        .await
        .map_err(|_| L0dError::Net("local TCP first handshake read timeout".into()))??;
    if first_len == 0 {
        return Ok(());
    }
    first_chunk.truncate(first_len);
    // Temporary wallets stay local. Mailbox SI is announced in duplex_offer
    // after this host's l0_listen handshake; do not register AddressPGP.
    let (identity, listen_already_up) = match ready_pool.as_ref().and_then(|pool| pool.take()) {
        Some(identity) => {
            tracing::info!(
                eoa = %identity.wallet_address(),
                session = %identity.session_id,
                port,
                "bound local TCP to a pre-warmed temporary identity"
            );
            (identity, true)
        }
        None => {
            let identity = crate::l0::identity::TemporaryIdentity::generate()?;
            tracing::info!(
                eoa = %identity.wallet_address(),
                "temporary identity minted before duplex offer (no AddressPGP registration)"
            );
            (identity, false)
        }
    };
    let _listen_guard = ReleaseListenOnDrop {
        owners: listen_owners.clone(),
        wallet: identity.wallet_address().to_owned(),
    };
    let session_id = identity.session_id.clone();
    let (return_tx, return_rx) = mpsc::channel::<Vec<u8>>(64);
    {
        let mut receivers = local_streams.lock().unwrap_or_else(|p| p.into_inner());
        receivers.insert(session_id.clone(), return_tx);
    }
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    let session = DuplexSession {
        session_id: session_id.clone(),
        role: DuplexLineRole::Peer,
        created_at: now,
        key: Some(identity.aes_key),
        dest,
        port,
        peer_eoa: peer_keys.peer_eoa.clone(),
        guest_up: true,
        peer_attached: false,
        rejected: false,
        host_eoa: wire.main_wallet.clone(),
        peer_listen_user_pgp: None,
        peer_listen_route_pgp: None,
        peer_listen_wallet: None,
        peer_listen_mailbox_wallet: None,
        accept_identity: Some(identity.clone()),
        peer_return_attached: false,
        response_chunk_delivered: false,
        pipe_tx: None,
        pipe_gen: 0,
        pipe_connect_inflight: false,
        pipe_cancel: None,
    };
    duplex
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(duplex_key(dest, port, &session_id), session.clone());
    let Some(tx) = inbound_feed.clone() else {
        return Err(L0dError::L0(
            "dynamic client l0_listen requires an inbound feed".into(),
        ));
    };
    let extras = PipeExtras {
        inbound_tx: Some(tx.clone()),
        proxy_registry,
        proxy_receivers,
        proxy_seq,
    };
    if !listen_already_up {
        let rebuild = L0PipeRebuild {
            duplex: duplex.clone(),
            wires,
            peers,
            extras: extras.clone(),
        };
        let (ready_tx, ready_rx) = oneshot::channel();
        if !spawn_listen_worker_with_ready(
            wire.listen_entries.clone(),
            wire.si_pool.clone(),
            wire.route_pgp.clone(),
            identity.wallet_address().to_owned(),
            wire.si_eth.clone(),
            tx,
            true,
            Some(rebuild),
            Some(wire.main_wallet.clone()),
            Some(wire.eth.clone()),
            Some(identity.clone()),
            Some(identity.session_id.clone()),
            Some(ready_tx),
            listen_owners.clone(),
        ) {
            return Err(L0dError::L0(
                "dynamic client l0_listen failed to start".into(),
            ));
        }
        if !matches!(
            tokio::time::timeout(
                Duration::from_secs(DYNAMIC_LISTEN_READY_TIMEOUT_SECS),
                ready_rx,
            )
            .await,
            Ok(Ok(()))
        ) {
            local_streams
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&session_id);
            retain_duplex_except_session_id(
                &mut duplex.lock().unwrap_or_else(|p| p.into_inner()),
                &session_id,
            );
            return Err(L0dError::L0(
                "dynamic client route/listen did not become ready".into(),
            ));
        }
    }
    spawn_duplex_offer(
        wire.clone(),
        peer_keys.user.0,
        peer_keys.route.0.clone(),
        peer_keys.peer_eoa.clone(),
        session,
        duplex.clone(),
        Some(first_chunk),
        listen_owners
            .find_by_wallet(identity.wallet_address())
            .and_then(|owner| owner.mailbox_si_wallet())
            .unwrap_or_default(),
        listen_owners.clone(),
    );
    tracing::info!(
        session = %session_id,
        port,
        temporary_wallet = %identity.wallet_address(),
        "new local TCP connection allocated a duplex line"
    );
    let mut return_rx = return_rx;
    let mut pending_resume: Vec<Vec<u8>> = Vec::new();
    let mut read_buf = vec![0u8; 16 * 1024];
    let mut occupy_spawned = false;
    let mut local_eof = false;
    let mut next_seq = 1u64;
    let mut response_written_at: Option<tokio::time::Instant> = None;
    let wait_deadline =
        tokio::time::Instant::now() + Duration::from_secs(DYNAMIC_LISTEN_READY_TIMEOUT_SECS);
    let (key, pipe_tx) = loop {
        if tokio::time::Instant::now() >= wait_deadline {
            local_streams
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&session_id);
            retain_duplex_except_session_id(
                &mut duplex.lock().unwrap_or_else(|p| p.into_inner()),
                &session_id,
            );
            return Err(L0dError::L0(
                "dynamic duplex did not install occupy pipe before timeout".into(),
            ));
        }
        let snapshot = {
            let guard = duplex.lock().unwrap_or_else(|p| p.into_inner());
            guard.get(&duplex_key(dest, port, &session_id)).cloned()
        };
        let Some(sess) = snapshot else {
            local_streams
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&session_id);
            return Err(L0dError::L0("dynamic duplex session rejected".into()));
        };
        if sess.rejected {
            local_streams
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&session_id);
            return Err(L0dError::L0("dynamic duplex session rejected".into()));
        }
        if let (Some(key), Some(pipe)) = (sess.key, sess.pipe_tx.clone()) {
            break (key, pipe);
        }
        if !occupy_spawned && sess.peer_attached {
            if let (Some(key), Some(target), Some(route)) = (
                sess.key,
                sess.peer_listen_wallet.clone(),
                sess.peer_listen_route_pgp.clone(),
            ) {
                if response_written_at.is_some() {
                    let first = if let Some(chunk) = pending_resume.first() {
                        let framed = frame::encode(next_seq, chunk);
                        match duplex::seal_frame(&key, &session_id, &framed) {
                            Ok(blob) => {
                                pending_resume.remove(0);
                                next_seq = next_seq.saturating_add(1);
                                Some(blob)
                            }
                            Err(err) => {
                                tracing::warn!(
                                    session = %session_id,
                                    error = %err,
                                    "failed to seal resume first blob"
                                );
                                None
                            }
                        }
                    } else {
                        None
                    };
                    tracing::info!(
                        session = %session_id,
                        port,
                        resume_first = first.is_some(),
                        pending = pending_resume.len(),
                        "occupying after responseChunk; local resume optional"
                    );
                    spawn_l0_pipe(
                        wire.clone(),
                        route,
                        target,
                        first,
                        sess,
                        duplex.clone(),
                        extras.clone(),
                    );
                    occupy_spawned = true;
                }
            }
        }

        tokio::select! {
            incoming = return_rx.recv() => {
                let Some(incoming) = incoming else {
                    if response_written_at.is_none() {
                        local_streams
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .remove(&session_id);
                        return Err(L0dError::L0(
                            "duplex response channel closed before responseChunk".into(),
                        ));
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                };
                writer.write_all(&incoming).await?;
                writer.flush().await?;
                if response_written_at.is_none() {
                    response_written_at = Some(tokio::time::Instant::now());
                    tracing::info!(
                        session = %session_id,
                        port,
                        bytes = incoming.len(),
                        "wrote duplex_accept responseChunk to local TCP before occupy"
                    );
                }
            }
            read = reader.read(&mut read_buf), if !local_eof => {
                let n = read?;
                if n == 0 {
                    local_eof = true;
                    if response_written_at.is_none() {
                        local_streams
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .remove(&session_id);
                        return Err(L0dError::L0(
                            "local TCP closed before responseChunk".into(),
                        ));
                    }
                    if !occupy_spawned {
                        tracing::info!(
                            session = %session_id,
                            port,
                            "local TCP EOF after responseChunk; occupy still proceeds"
                        );
                    }
                    continue;
                }
                pending_resume.push(read_buf[..n].to_vec());
                tracing::info!(
                    session = %session_id,
                    port,
                    bytes = n,
                    buffered = pending_resume.len(),
                    "buffered local TCP resume bytes before occupy"
                );
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    };

    for chunk in pending_resume {
        tracing::info!(
            session = %session_id,
            port,
            bytes = chunk.len(),
            "local client TCP bytes entering duplex pipe"
        );
        let framed = frame::encode(next_seq, &chunk);
        let blob = duplex::seal_frame(&key, &session_id, &framed)?;
        pipe_tx
            .send(blob)
            .await
            .map_err(|_| L0dError::L0("occupied duplex pipe closed".into()))?;
        next_seq = next_seq.saturating_add(1);
    }

    let result = async {
        let mut buf = vec![0u8; 16 * 1024];
        let mut seq = next_seq;
        loop {
            tokio::select! {
                read = reader.read(&mut buf), if !local_eof => {
                    let n = read?;
                    if n == 0 {
                        break;
                    }
                    tracing::info!(
                        session = %session_id,
                        port,
                        bytes = n,
                        "local client TCP bytes entering duplex pipe"
                    );
                    let framed = frame::encode(seq, &buf[..n]);
                    let blob = duplex::seal_frame(&key, &session_id, &framed)?;
                    pipe_tx
                        .send(blob)
                        .await
                        .map_err(|_| L0dError::L0("occupied duplex pipe closed".into()))?;
                    seq = seq.saturating_add(1);
                }
                incoming = return_rx.recv() => {
                    let Some(incoming) = incoming else { break };
                    writer.write_all(&incoming).await?;
                }
            }
        }
        Ok::<(), L0dError>(())
    }
    .await;

    local_streams
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&session_id);
    let mut guard = duplex.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(mut session) = guard.remove(&duplex_key(dest, port, &session_id)) {
        cancel_duplex_pipe(&session);
        session.rejected = true;
        drop(session.pipe_tx.take());
    }
    result
}

/// When this endpoint is a proxy server for `port`, attach one upstream line to
/// the newly installed occupy pipe and drain upstream → AES frames.
fn maybe_start_proxy_drain(
    extras: &PipeExtras,
    duplex: Arc<Mutex<HashMap<DuplexKey, DuplexSession>>>,
    session_id: String,
    port: u16,
    cancel: Arc<AtomicBool>,
) {
    if extras.proxy_registry.mode(port) != Some(ProxyMode::Duplex) {
        tracing::debug!(
            session = %session_id,
            port,
            "request/response proxy does not attach a persistent duplex drain"
        );
        return;
    }
    // Lines are independent by pipe_handle; do not treat `port` as a global
    // "this daemon is proxying" switch. Only sessions allocated by the proxy
    // mainWallet:port handshake may dial local upstream.
    let role = {
        let guard = duplex.lock().unwrap_or_else(|p| p.into_inner());
        guard
            .values()
            .find(|session| session.session_id == session_id)
            .map(|session| session.role)
    };
    match role {
        Some(DuplexLineRole::Proxy) => {}
        Some(DuplexLineRole::Peer) => {
            tracing::debug!(
                session = %session_id,
                port,
                "skip proxy drain; peer/client duplex line shares port with proxy_duplex"
            );
            return;
        }
        None => {
            tracing::debug!(
                session = %session_id,
                port,
                "skip proxy drain; session not in map yet"
            );
            return;
        }
    }
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
    let receiver_registry = extras.proxy_receivers.clone();
    let session_registry = duplex.clone();
    tokio::spawn(async move {
        tracing::info!(session = %sid, port, "proxy TCP line started");
        if let Err(err) = proxy::run_proxy_line(line, from_peer, from_upstream).await {
            tracing::warn!(session = %sid, error = %err, "proxy line closed");
        } else {
            tracing::info!(session = %sid, "proxy TCP line closed");
        }
        receiver_registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&sid);
        // The upstream socket is the lifetime boundary of a proxy line.  Do
        // not leave the occupied duplex session behind after that socket has
        // closed: clients otherwise find the stale pipe, attach a local TCP
        // stream to it, and send frames after proxy_receivers was removed.
        let mut sessions = session_registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        retain_duplex_except_session_id(&mut sessions, &sid);
        cancel.store(true, Ordering::Release);
        tracing::info!(
            session = %sid,
            port,
            "proxy duplex session retired after upstream close"
        );
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

fn maybe_start_proxy_drain_with_initial(
    extras: &PipeExtras,
    duplex: Arc<Mutex<HashMap<DuplexKey, DuplexSession>>>,
    session_id: String,
    port: u16,
    cancel: Arc<AtomicBool>,
    initial: Vec<u8>,
) {
    maybe_start_proxy_drain(extras, duplex, session_id.clone(), port, cancel);
    if let Some(tx) = extras
        .proxy_receivers
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&session_id)
        .cloned()
    {
        if tx.try_send(initial).is_err() {
            tracing::warn!(session = %session_id, "proxy firstChunk queue is full");
        }
    } else {
        tracing::warn!(session = %session_id, "proxy firstChunk receiver unavailable");
    }
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

fn duplex_duplicate_offer_should_ignore(
    sess: &DuplexSession,
    had_key: bool,
    offered_key: [u8; aes::KEY_LEN],
) -> bool {
    // Chat and idle-L0 listens can deliver the same user-PGP offer. Once the
    // mainWallet handler has allocated the keyed session, every non-rejected
    // copy is idempotent—even while temporary route propagation or the first
    // l0_connect is still pending. Rejecting that second copy tears down the
    // valid first handshake.
    had_key && !sess.rejected && sess.key == Some(offered_key)
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
        let Some(target) = sess.peer_listen_wallet.clone() else {
            continue;
        };
        let peer_route_pgp = sess.peer_listen_route_pgp.clone().or_else(|| {
            ctx.peers
                .get(&(sess.dest, sess.port))
                .map(|keys| keys.route.0.clone())
        });
        let Some(peer_route_pgp) = peer_route_pgp else {
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
            peer_route_pgp,
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

fn load_channel_wires(
    cfg: &ValidatedConfig,
    si_pool: Option<Arc<SiPool>>,
) -> HashMap<u16, ChannelWire> {
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
                    si_pool: si_pool.clone(),
                    user_pub: user_pub.clone(),
                    rpc: cfg.l0.rpc.clone(),
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
                si_pool: si_pool.clone(),
                user_pub: user_pub.clone(),
                rpc: cfg.l0.rpc.clone(),
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
                    // Explicit client endpoints own this logical port. Plain
                    // `--client` is P1 only and must not inherit the peer
                    // duplex seed; `--clientDuplex` is seeded below.
                    if cfg.clients.iter().chain(cfg.client_duplex.iter()).any(|c| {
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
                            role: DuplexLineRole::Peer,
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
                            peer_listen_route_pgp: None,
                            peer_listen_wallet: None,
                            peer_listen_mailbox_wallet: None,
                            accept_identity: None,
                            peer_return_attached: false,
                            response_chunk_delivered: false,
                            pipe_tx: None,
                            pipe_gen: 0,
                            pipe_connect_inflight: false,
                            pipe_cancel: None,
                        },
                    );
                }
            }
        }
        // `--clientDuplex` is connection-driven.  Do not seed one session per
        // logical port here: the local TCP listener allocates a fresh
        // temporary identity and pipe for every accepted socket.
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
                keys.route.0.clone(),
                peer_eoa.clone(),
                sess,
                duplex.clone(),
                None,
                String::new(),
                listen::ListenOwnerRegistry::default(),
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

async fn post_control_armor_with_retry(
    entries: &[String],
    si_pool: Option<&Arc<SiPool>>,
    armor: &str,
    label: &'static str,
) {
    let Ok(client) = post::http_client() else {
        tracing::warn!(label, "duplex control POST: no HTTP client");
        return;
    };
    loop {
        let result = if let Some(pool) = si_pool {
            post::send_via_pool(&client, pool, armor).await
        } else {
            post::send_via_entries(&client, entries, armor).await
        };
        match result {
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
    peer_mailbox_si_pgp: String,
    peer_eoa: String,
    sess: DuplexSession,
    duplex: Arc<Mutex<HashMap<DuplexKey, DuplexSession>>>,
    first_chunk: Option<Vec<u8>>,
    own_mailbox_si_wallet: String,
    listen_owners: listen::ListenOwnerRegistry,
) {
    let Some(handle) = tokio::runtime::Handle::try_current().ok() else {
        return;
    };
    let entries = wire_post_entries(&wire);
    let dest = sess.dest;
    let port = sess.port;
    let session_id = sess.session_id.clone();
    let (initiator_wallet, listen_wallet, listen_user_pgp) = sess
        .accept_identity
        .as_ref()
        .map(|identity| {
            (
                identity.wallet_address().to_owned(),
                identity.wallet_address().to_owned(),
                identity.user_public_armor.clone(),
            )
        })
        .unwrap_or_else(|| (wire.eoa.clone(), wire.eoa.clone(), wire.user_pub.clone()));
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
            let Some(key) = duplex_session_by_id(&duplex, dest, port, &session_id)
                .and_then(|live| live.key)
            else {
                tokio::time::sleep(Duration::from_secs(DUPLEX_OFFER_RESEND_SECS)).await;
                continue;
            };
            let ts = chrono::Utc::now().timestamp().max(0) as u64;
            let mailbox_si_wallet = listen_owners
                .find_by_wallet(&listen_wallet)
                .and_then(|owner| owner.mailbox_si_wallet())
                .unwrap_or_else(|| own_mailbox_si_wallet.clone());
            match duplex::encode_offer_command_for_port(
                &initiator_wallet,
                wire.eth.address(),
                &peer_eoa,
                &peer_eoa,
                &listen_wallet,
                &listen_user_pgp,
                &wire.route_pgp,
                &mailbox_si_wallet,
                sess.port,
                &session_id,
                &key,
                ts,
                first_chunk.as_deref(),
            )
            .and_then(|cmd| duplex::wrap_offer_for_user_pgp(&cmd, &peer_user_pgp, &wire.eth))
            .and_then(|inner| pgp::wrap_user_armor_for_mailbox_si(&inner, &peer_mailbox_si_pgp))
            {
                Ok(armor) => {
                    let expected = pgp::transport_key_id_armored(&peer_user_pgp).ok();
                    let recipients = pgp::pkesk_recipient_key_ids(&armor).unwrap_or_default();
                    tracing::info!(
                        session = %session_id,
                        expected_peer_key_id = ?expected,
                        pkesk_recipients = ?recipients,
                        "duplex_offer POST (periodic until accept)"
                    );
                    post_control_armor_with_retry(&entries, wire.si_pool.as_ref(), &armor, "duplex_offer").await;
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
    response_chunk: Option<Vec<u8>>,
    listen_owners: listen::ListenOwnerRegistry,
) {
    let Some(handle) = tokio::runtime::Handle::try_current().ok() else {
        return;
    };
    let entries = wire_post_entries(&wire);
    let dest = sess.dest;
    let port = sess.port;
    let session_id = sess.session_id.clone();
    let initiator_mailbox_si_pgp = sess.peer_listen_route_pgp.clone().unwrap_or_default();
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
            let Some(key) = duplex_session_by_id(&duplex, dest, port, &session_id)
                .and_then(|live| live.key)
            else {
                tokio::time::sleep(Duration::from_secs(DUPLEX_ACCEPT_RESEND_SECS)).await;
                continue;
            };
            let ts = chrono::Utc::now().timestamp().max(0) as u64;
            let mailbox_si_wallet = listen_owners
                .find_by_wallet(&accept_wallet)
                .and_then(|owner| owner.mailbox_si_wallet())
                .unwrap_or_default();
            match duplex::encode_accept_command(
                &accept_wallet,
                wire.eth.address(),
                &accept_wallet,
                &accept_user_pgp,
                &wire.route_pgp,
                &mailbox_si_wallet,
                &session_id,
                &key,
                ts,
                response_chunk.as_deref(),
            )
            .and_then(|cmd| duplex::wrap_accept_for_user_pgp(&cmd, &initiator_pipe_pgp, &wire.eth))
            .and_then(|inner| {
                if initiator_mailbox_si_pgp.trim().is_empty() {
                    Err(L0dError::L0(
                        "duplex_accept missing initiator mailbox SI PGP".into(),
                    ))
                } else {
                    pgp::wrap_user_armor_for_mailbox_si(&inner, &initiator_mailbox_si_pgp)
                }
            })
            {
                Ok(armor) => {
                    tracing::info!(
                        session = %session_id,
                        "duplex_accept POST (periodic until l0_connect pipe up)"
                    );
                    post_control_armor_with_retry(&entries, wire.si_pool.as_ref(), &armor, "duplex_accept").await;
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
    let static_entries = if wire.entries.is_empty() {
        wire.listen_entries.clone()
    } else {
        wire.entries.clone()
    };
    let si_pool = wire.si_pool.clone();
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
            let entries = if let Some(pool) = si_pool.as_ref() { match pool.acquire(None).await {
                Ok(entry) => vec![entry], Err(error) => { tracing::warn!(session = %session_id, %error, "l0_connect SI pool acquire failed; retrying"); tokio::time::sleep(Duration::from_secs(LISTEN_RECONNECT_SECS)).await; continue; }
            }} else { static_entries.clone() };
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
            let cancel = Arc::new(AtomicBool::new(false));
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
                live.pipe_cancel = Some(cancel.clone());
                Some(live.pipe_gen)
            };
            let duplex_up = duplex.clone();
            let session_up = session_id.clone();
            let extras_up = extras.clone();
            // Install the proxy receiver before opening the occupied pipe.
            // The peer may send its first duplex frame immediately after the
            // HTTP 200 response; waiting until pipe_tx is installed creates a
            // receive-side race where apply_duplex_frame has nowhere to queue
            // that first payload.
            maybe_start_proxy_drain(
                &extras_up,
                duplex_up.clone(),
                session_up.clone(),
                port,
                cancel.clone(),
            );
            match pipe::run_occupied_pipe(
                &entries,
                &connect_armor,
                &session_id,
                {
                    let duplex_hb = duplex.clone();
                    let sid_hb = session_id.clone();
                    move || duplex_pipe_heartbeat(&duplex_hb, dest, port, &sid_hb)
                },
                first_blob.take(),
                rx,
                extras.inbound_tx.clone(),
                cancel.clone(),
                {
                    let cancel_up = cancel.clone();
                    move || {
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
                                    cancel_up.clone(),
                                );
                            }
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
                    tracing::warn!(
                        session = %session_id,
                        error = %err,
                        "l0_connect pipe occupation failed; terminating duplex incarnation"
                    );
                    if oneshot_reject || gen.is_none() {
                        return;
                    }
                    let _gen = gen.expect("tracked pipe");
                    // A failed occupation means this SSE/duplex pair is no
                    // longer a valid transport.  Do not reuse its wallet,
                    // pipe handle, or l0_listen worker: that combination was
                    // the source of the 3-second storm.
                    // Give the peer one final, explicit control-plane
                    // rejection.  This is a single best-effort occupation
                    // carrying the reject blob, not a retry of the failed
                    // duplex; failure of this notification is harmless
                    // because the local APP socket is closed below.
                    if let Some(key) = sess.key {
                        if let Ok(json) = duplex::encode_reject_command(
                            &listen_wallet,
                            &session_id,
                            chrono::Utc::now().timestamp().max(0) as u64,
                            "pipe_failed",
                            true,
                        ) {
                            if let Ok(first) = aes::seal(&key, json.as_bytes()) {
                                let mut reject_sess = sess.clone();
                                reject_sess.rejected = true;
                                reject_sess.pipe_tx = None;
                                reject_sess.pipe_cancel = None;
                                spawn_l0_pipe(
                                    wire.clone(),
                                    peer_route_pgp.clone(),
                                    target_wallet.clone(),
                                    Some(first),
                                    reject_sess,
                                    duplex.clone(),
                                    PipeExtras::empty(),
                                );
                            }
                        }
                    }
                    let mut guard = duplex.lock().unwrap_or_else(|p| p.into_inner());
                    if let Some(live) = guard.get(&duplex_key(dest, port, &session_id)) {
                        cancel_duplex_pipe(live);
                    }
                    retain_duplex_except_session_id(&mut guard, &session_id);
                    tracing::warn!(
                        session = %session_id,
                        reason = "pipe_failed",
                        "duplex rejected locally; application must create a new connection"
                    );
                    return;
                }
            }
        }
    });
}

fn spawn_ready_identity_warmers(
    pools: &HashMap<u16, Arc<ReadyIdentityPool>>,
    wires: &HashMap<u16, ChannelWire>,
    inbound_feed: Option<mpsc::Sender<listen::InboundChunk>>,
    listen_owners: listen::ListenOwnerRegistry,
) {
    let Some(handle) = tokio::runtime::Handle::try_current().ok() else {
        return;
    };
    let Some(inbound_tx) = inbound_feed else {
        return;
    };
    for (port, pool) in pools {
        let Some(wire) = wires.get(port).cloned() else {
            continue;
        };
        let port = *port;
        let pool = pool.clone();
        let inbound_tx = inbound_tx.clone();
        let listen_owners = listen_owners.clone();
        handle.spawn(async move {
            loop {
                let claimed = pool.ready_len() + pool.warming.load(Ordering::Relaxed) as usize;
                if claimed >= READY_IDENTITY_POOL_TARGET {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                pool.warming.fetch_add(1, Ordering::Relaxed);
                match warm_one_ready_identity(&wire, inbound_tx.clone(), listen_owners.clone())
                    .await
                {
                    Ok(identity) => {
                        tracing::info!(
                            port,
                            temporary_wallet = %identity.wallet_address(),
                            ready = pool.ready_len() + 1,
                            "pre-warmed temporary identity is listen-ready"
                        );
                        pool.push(identity);
                    }
                    Err(err) => {
                        tracing::warn!(port, error = %err, "temporary identity pre-warm failed");
                        tokio::time::sleep(Duration::from_secs(LISTEN_RECONNECT_SECS)).await;
                    }
                }
                pool.warming.fetch_sub(1, Ordering::Relaxed);
            }
        });
    }
}

async fn warm_one_ready_identity(
    wire: &ChannelWire,
    inbound_tx: mpsc::Sender<listen::InboundChunk>,
    listen_owners: listen::ListenOwnerRegistry,
) -> Result<crate::l0::identity::TemporaryIdentity, L0dError> {
    let identity = crate::l0::identity::TemporaryIdentity::generate()?;
    let (ready_tx, ready_rx) = oneshot::channel();
    if !spawn_listen_worker_with_ready(
        wire.listen_entries.clone(),
        wire.si_pool.clone(),
        wire.route_pgp.clone(),
        identity.wallet_address().to_owned(),
        wire.si_eth.clone(),
        inbound_tx,
        true,
        None,
        Some(wire.main_wallet.clone()),
        Some(wire.eth.clone()),
        Some(identity.clone()),
        // Pre-warm keeps TemporaryIdentity.session_id until duplex allocate
        // rebinds via spawn_dynamic_accept_listen.
        None,
        Some(ready_tx),
        listen_owners.clone(),
    ) {
        return Err(L0dError::L0(
            "temporary identity pre-warm listen failed to start".into(),
        ));
    }
    if !matches!(
        tokio::time::timeout(
            Duration::from_secs(DYNAMIC_LISTEN_READY_TIMEOUT_SECS),
            ready_rx,
        )
        .await,
        Ok(Ok(()))
    ) {
        let _ = listen_owners.release_by_wallet(identity.wallet_address());
        return Err(L0dError::L0(
            "temporary identity pre-warm listen did not become ready".into(),
        ));
    }
    Ok(identity)
}

fn spawn_post_worker(
    si_pool: Option<Arc<SiPool>>,
    entries: Vec<String>,
) -> Option<mpsc::Sender<PostJob>> {
    let handle = tokio::runtime::Handle::try_current().ok()?;
    let client = post::http_client().ok()?;
    let (tx, mut rx) = mpsc::channel::<PostJob>(POST_QUEUE);
    handle.spawn(async move {
        let client = Arc::new(client);
        let entries = Arc::new(entries);
        let si_pool = si_pool;
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
            let si_pool = si_pool.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let result = if let Some(pool) = si_pool.as_ref() {
                    post::send_via_pool(&client, pool, &job.armor).await
                } else {
                    post::send_via_entries(&client, &entries, &job.armor).await
                };
                match result {
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
            listen_owners: listen::ListenOwnerRegistry::default(),
            proxy_registry: proxy::ProxyRegistry::new(Vec::new()),
            proxy_receivers: Arc::new(Mutex::new(HashMap::new())),
            proxy_seq: Arc::new(AtomicU64::new(1)),
            local_streams: Arc::new(Mutex::new(HashMap::new())),
            ready_identities: HashMap::new(),
        }
    }

    #[test]
    fn explicit_peer_port_pgp_is_not_clobbered_by_same_wallet_supplement() {
        let dest = Ipv4Addr::new(100, 64, 0, 6);
        let geth = PeerPgp {
            user: ArmoredCert("geth-user".into()),
            route: ArmoredCert("geth-route".into()),
            peer_eoa: "0x1111111111111111111111111111111111111111".into(),
        };
        let beacon = PeerPgp {
            user: ArmoredCert("beacon-user".into()),
            route: ArmoredCert("beacon-route".into()),
            peer_eoa: "0x1111111111111111111111111111111111111111".into(),
        };

        for reverse in [false, true] {
            let mut peers = HashMap::new();
            let rows = if reverse {
                vec![(4200, beacon.clone()), (8400, geth.clone())]
            } else {
                vec![(8400, geth.clone()), (4200, beacon.clone())]
            };
            for (explicit_port, keys) in rows {
                insert_peer_pgp_ports(&mut peers, dest, [explicit_port], &keys);
            }

            assert_eq!(peers[&(dest, 8400)].user.0, "geth-user");
            assert_eq!(peers[&(dest, 4200)].user.0, "beacon-user");
        }

        let mut only_beacon = HashMap::new();
        insert_peer_pgp_ports(&mut only_beacon, dest, [4200], &beacon);
        assert!(only_beacon.get(&(dest, 8400)).is_none());
        assert_eq!(only_beacon[&(dest, 4200)].user.0, "beacon-user");
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
                role: DuplexLineRole::Peer,
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
                peer_listen_route_pgp: None,
                peer_listen_wallet: None,
                peer_listen_mailbox_wallet: None,
                accept_identity: None,
                peer_return_attached: false,
                response_chunk_delivered: false,
                pipe_tx: None,
                pipe_gen: 0,
                pipe_connect_inflight: false,
                pipe_cancel: None,
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
                role: DuplexLineRole::Peer,
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
                peer_listen_route_pgp: None,
                peer_listen_wallet: Some("0x2222222222222222222222222222222222222222".into()),
                peer_listen_mailbox_wallet: None,
                accept_identity: None,
                peer_return_attached: false,
                response_chunk_delivered: false,
                pipe_tx: Some(tx),
                pipe_gen: 1,
                pipe_connect_inflight: false,
                pipe_cancel: None,
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
                role: DuplexLineRole::Peer,
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
                peer_listen_route_pgp: None,
                peer_listen_wallet: None,
                peer_listen_mailbox_wallet: None,
                accept_identity: None,
                peer_return_attached: false,
                response_chunk_delivered: false,
                pipe_tx: None,
                pipe_gen: 0,
                pipe_connect_inflight: false,
                pipe_cancel: None,
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
        let owner = listen::OwnedListenSession::new(
            "0x1111111111111111111111111111111111111111",
            Some(sid.to_string()),
            "l0",
        );
        let owner_id = owner.id.clone();
        assert!(client.listen_owners.register(owner));
        assert_eq!(
            client
                .apply_inbound_chunk(listen::InboundChunk::new(
                    owner_id,
                    Some(sid.to_string()),
                    blob,
                ))
                .unwrap(),
            pkt.len()
        );
        assert_eq!(client.inbound_ready, 2);
    }

    #[test]
    fn anonymous_duplex_aes_blob_is_rejected_without_key_trial() {
        let key = aes::generate_key();
        let sid = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let blob = duplex::seal_frame(&key, sid, &frame::encode(1, b"payload")).unwrap();
        let mut client = L0Client {
            enabled: true,
            ..L0Client::disabled()
        };
        let err = client
            .apply_inbound_chunk(listen::InboundChunk::new("unowned-sse", None, blob))
            .expect_err("anonymous AES must not try process-wide keys");
        assert!(err.to_string().contains("listen owner is missing"));
    }

    #[test]
    fn wrong_key_cancels_only_the_bound_duplex_pipe() {
        let sid = "wrong-key-session";
        let dest = Ipv4Addr::new(100, 64, 0, 6);
        let cancel = Arc::new(AtomicBool::new(false));
        let mut session = sample_duplex_session(false);
        session.session_id = sid.to_owned();
        session.dest = dest;
        session.pipe_cancel = Some(cancel.clone());
        let duplex = Arc::new(Mutex::new(HashMap::from([(
            duplex_key(dest, session.port, sid),
            session,
        )])));
        let owner = listen::OwnedListenSession::new("temporary-wallet", Some(sid.to_owned()), "l0");
        let owner_id = owner.id.clone();
        let mut client = L0Client {
            enabled: true,
            duplex,
            ..L0Client::disabled()
        };
        assert!(client.listen_owners.register(owner));

        let wrong_blob = duplex::seal_frame(
            &[0xabu8; aes::KEY_LEN],
            sid,
            &frame::encode(1, b"wrong-key"),
        )
        .unwrap();
        let err = client
            .apply_inbound_chunk(listen::InboundChunk::new(
                owner_id,
                Some(sid.to_owned()),
                wrong_blob,
            ))
            .expect_err("wrong-key frame must be rejected");

        assert!(err.to_string().contains("duplex AES session"));
        assert!(cancel.load(Ordering::Acquire));
        assert!(client
            .duplex
            .lock()
            .unwrap()
            .get(&duplex_key(dest, 8400, sid))
            .map(|s| s.rejected)
            .unwrap_or(false));
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
            user_secrets: vec![SecretCert::unscoped(user)],
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
            user_secrets: vec![SecretCert::unscoped(user)],
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
            path_and_query: "/p2p/geth".into(),
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
            path_and_query: "/p2p/geth".into(),
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
            path_and_query: "/p2p/geth".into(),
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
            user_secrets: vec![SecretCert::unscoped(first), SecretCert::unscoped(second)],
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

        let tx = spawn_post_worker(None, vec![server.uri()]).expect("worker");
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

    #[test]
    fn retain_duplex_stops_pipe_cancel() {
        let dest = Ipv4Addr::new(100, 64, 0, 6);
        let port = 4200;
        let sid = "retain-sid";
        let cancel = Arc::new(AtomicBool::new(false));
        let mut sess = sample_duplex_session(true);
        sess.session_id = sid.into();
        sess.dest = dest;
        sess.port = port;
        sess.pipe_cancel = Some(cancel.clone());
        let mut map = HashMap::new();
        map.insert(duplex_key(dest, port, sid), sess);
        retain_duplex_except_session_id(&mut map, sid);
        assert!(map.is_empty());
        assert!(cancel.load(Ordering::Acquire));
    }

    #[test]
    fn heartbeat_reads_current_map_key_not_spawn_snapshot() {
        let dest = Ipv4Addr::new(100, 64, 0, 6);
        let port = 4200;
        let sid = "hb-sid";
        let key_a = [1u8; aes::KEY_LEN];
        let key_b = [2u8; aes::KEY_LEN];
        let mut sess = sample_duplex_session(false);
        sess.session_id = sid.into();
        sess.dest = dest;
        sess.port = port;
        sess.key = Some(key_a);
        let duplex = Arc::new(Mutex::new(HashMap::new()));
        duplex
            .lock()
            .unwrap()
            .insert(duplex_key(dest, port, sid), sess);
        assert_eq!(
            duplex_pipe_heartbeat(&duplex, dest, port, sid),
            crate::l0::pipe::PipeHeartbeat::Key(key_a)
        );
        duplex
            .lock()
            .unwrap()
            .get_mut(&duplex_key(dest, port, sid))
            .expect("session")
            .key = Some(key_b);
        assert_eq!(
            duplex_pipe_heartbeat(&duplex, dest, port, sid),
            crate::l0::pipe::PipeHeartbeat::Key(key_b)
        );
        retain_duplex_except_session_id(&mut duplex.lock().unwrap(), sid);
        assert_eq!(
            duplex_pipe_heartbeat(&duplex, dest, port, sid),
            crate::l0::pipe::PipeHeartbeat::Stop
        );
    }

    fn sample_duplex_session(pipe_active: bool) -> DuplexSession {
        DuplexSession {
            session_id: "sess".into(),
            role: DuplexLineRole::Peer,
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
            peer_listen_route_pgp: None,
            peer_listen_wallet: Some("0x2222222222222222222222222222222222222222".into()),
            peer_listen_mailbox_wallet: None,
            accept_identity: None,
            peer_return_attached: false,
            response_chunk_delivered: false,
            pipe_tx: if pipe_active {
                let (tx, _rx) = mpsc::channel(1);
                Some(tx)
            } else {
                None
            },
            pipe_gen: 0,
            pipe_connect_inflight: false,
            pipe_cancel: None,
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
        let key = sess.key.unwrap();
        assert!(duplex_duplicate_offer_should_ignore(&sess, true, key));
        sess.pipe_tx = None;
        sess.pipe_connect_inflight = true;
        assert!(duplex_duplicate_offer_should_ignore(&sess, true, key));
        sess.pipe_connect_inflight = false;
        assert!(duplex_duplicate_offer_should_ignore(&sess, true, key));
        sess.rejected = true;
        assert!(!duplex_duplicate_offer_should_ignore(&sess, true, key));
        assert!(!duplex_duplicate_offer_should_ignore(&sess, false, key));
        sess.rejected = false;
        assert!(!duplex_duplicate_offer_should_ignore(
            &sess,
            true,
            [8; aes::KEY_LEN]
        ));
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
    fn rebuild_skips_proxy_handshake_temp_listen() {
        let routing = "0x1111111111111111111111111111111111111111";
        let mut sess = sample_duplex_session(false);
        sess.dest = Ipv4Addr::UNSPECIFIED;
        sess.accept_identity = Some(crate::l0::identity::TemporaryIdentity::generate().unwrap());
        assert!(!should_rebuild_l0_pipe_after_listen_up(&sess, routing));
    }

    #[test]
    fn rebuild_skips_spoke_first_occupy_until_resume() {
        let mut sess = sample_duplex_session(false);
        sess.accept_identity = Some(crate::l0::identity::TemporaryIdentity::generate().unwrap());
        sess.pipe_gen = 0;
        assert!(!should_rebuild_l0_pipe_after_listen_up(
            &sess,
            sess.accept_identity.as_ref().unwrap().wallet_address()
        ));
        sess.pipe_gen = 1;
        assert!(should_rebuild_l0_pipe_after_listen_up(
            &sess,
            sess.accept_identity.as_ref().unwrap().wallet_address()
        ));
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
