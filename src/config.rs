use crate::error::L0dError;
use crate::locator::{next_client_bind_port, Locator, LocatorHost};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
    #[serde(default = "default_overlay_cidr")]
    pub overlay_cidr: String,
    /// Local overlay VIP. `auto` selects a free-looking address in the overlay.
    #[serde(default = "default_local_vip")]
    pub local_vip: String,
    #[serde(default = "default_chain")]
    pub iptables_chain: String,
    #[serde(default = "default_state_path")]
    pub state_path: PathBuf,
    pub validator_uid: Option<u32>,
    pub identity: IdentityConfig,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    #[serde(default)]
    pub l0: L0Config,
    #[serde(default)]
    pub gateway: Option<GatewayConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    #[serde(default = "default_gateway_rpc")]
    pub rpc: String,
    pub upstream: String,
    pub listen_entries: Vec<String>,
    pub post_entries: Vec<String>,
    pub routing_eoa: String,
    pub routing_key_file: PathBuf,
    pub routing_eth_key_file: PathBuf,
    pub mailbox_route_pgp_file: PathBuf,
    #[serde(default = "default_gateway_methods")]
    pub allowed_methods: Vec<String>,
    #[serde(default = "default_gateway_max_body_bytes")]
    pub max_body_bytes: usize,
    #[serde(default = "default_gateway_timeout_seconds")]
    pub request_timeout_seconds: u64,
}

fn default_gateway_rpc() -> String {
    "https://rpc1.conet.network".into()
}

fn default_gateway_methods() -> Vec<String> {
    vec!["GET".into(), "HEAD".into()]
}

fn default_gateway_max_body_bytes() -> usize {
    8 * 1024 * 1024
}

fn default_gateway_timeout_seconds() -> u64 {
    15
}

fn default_route_register_url() -> String {
    "https://beamio.app/api/regiestChatRoute".into()
}

fn default_si_pool_from_contract() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L0Config {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_l0_rpc")]
    pub rpc: String,
    #[serde(default = "default_address_pgp")]
    pub address_pgp: String,
    #[serde(default)]
    pub entries: Vec<String>,
    #[serde(default)]
    pub listen_entries: Vec<String>,
    /// Discover qualified SI hosts from GuardianNodesInfoV6; static entries are optional fallbacks.
    #[serde(default = "default_si_pool_from_contract")]
    pub si_pool_from_contract: bool,
    pub routing_eoa: Option<String>,
    #[serde(default)]
    pub routing_key_file: Option<PathBuf>,
    /// Hex secp256k1 key for EIP-191 listen. Not an OpenPGP cert.
    #[serde(default)]
    pub routing_eth_key_file: Option<PathBuf>,
    /// This host's mailbox **B route public** key. Not the peer route file.
    #[serde(default)]
    pub mailbox_route_pgp_file: Option<PathBuf>,
    /// Main paid account used to sign L0 mailbox commands. Channel identities
    /// remain the route/PGP identities and must not be used for billing.
    #[serde(default)]
    pub billing_eoa: Option<String>,
    #[serde(default)]
    pub billing_eth_key_file: Option<PathBuf>,
    /// Optional main-wallet OpenPGP secret cert used for mailbox control.
    #[serde(default)]
    pub billing_pgp_file: Option<PathBuf>,
    /// Per-port listen identities. Empty = one legacy routing EOA for all overlay ports.
    #[serde(default)]
    pub channels: Vec<L0ChannelConfig>,
    /// Server-side logical proxy targets. Each incoming L0 line gets its own
    /// temporary communication identity and occupied pipe.
    #[serde(default)]
    pub proxies: Vec<L0ProxyConfig>,
    /// Server-side persistent bidirectional proxy targets.
    #[serde(default)]
    pub proxy_duplex: Vec<L0ProxyConfig>,
    /// Local request/response client targets: `web3://<wallet|tag.web3>:<port>`.
    #[serde(default)]
    pub clients: Vec<String>,
    /// Duplex client targets. These seed an occupied bidirectional channel.
    #[serde(default)]
    pub client_duplex: Vec<String>,
    /// Public API used to register ephemeral per-line AddressPGP routes.
    #[serde(default = "default_route_register_url")]
    pub route_register_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L0ProxyConfig {
    /// Upstream host reached after the occupied L0 pipe is established.
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L0ChannelConfig {
    /// Exactly one local overlay port per duplex channel. A channel must
    /// never be reused by two ports.
    pub port: u16,
    pub routing_eoa: String,
    pub routing_key_file: PathBuf,
    pub routing_eth_key_file: PathBuf,
    pub mailbox_route_pgp_file: PathBuf,
    /// Listen entry C. Empty inherits `[l0].listen_entries`.
    #[serde(default)]
    pub listen_entries: Vec<String>,
}

impl Default for L0Config {
    fn default() -> Self {
        Self {
            enabled: false,
            rpc: default_l0_rpc(),
            address_pgp: default_address_pgp(),
            entries: Vec::new(),
            listen_entries: Vec::new(),
            si_pool_from_contract: true,
            routing_eoa: None,
            routing_key_file: None,
            routing_eth_key_file: None,
            mailbox_route_pgp_file: None,
            billing_eoa: None,
            billing_eth_key_file: None,
            billing_pgp_file: None,
            channels: Vec::new(),
            proxies: Vec::new(),
            proxy_duplex: Vec::new(),
            clients: Vec::new(),
            client_duplex: Vec::new(),
            route_register_url: default_route_register_url(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    pub locator: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    pub locator: String,
    pub vip: String,
    #[serde(default)]
    pub tcp_ports: Vec<u16>,
    #[serde(default)]
    pub udp_ports: Vec<u16>,
    /// Optional lab override: armored user public key file. Do not log contents.
    #[serde(default)]
    pub user_pgp_file: Option<PathBuf>,
    /// Optional lab override: mailbox B route public key file. Do not log contents.
    #[serde(default)]
    pub route_pgp_file: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    pub raw: DaemonConfig,
    pub overlay: Ipv4Cidr,
    pub local_vip: Ipv4Addr,
    pub identity: Locator,
    pub peers: Vec<ValidatedPeer>,
    pub l0: L0Settings,
    pub clients: Vec<crate::locator::ClientTarget>,
    pub client_duplex: Vec<crate::locator::ClientTarget>,
    pub gateway: Option<ValidatedGateway>,
}

impl ValidatedConfig {
    /// Proxy-only server: proxies configured, no client intercept. Skip TUN.
    pub fn proxy_server_only(&self) -> bool {
        (!self.l0.proxies.is_empty() || !self.l0.proxy_duplex.is_empty())
            && self.clients.is_empty()
            && self.client_duplex.is_empty()
    }

    /// Legacy packet mode is required only by request/response `--client`.
    /// Duplex clients use local TCP listeners and raw stream frames.
    pub fn packet_mode_required(&self) -> bool {
        !self.clients.is_empty()
    }

    /// Resolve the local virtual endpoint used by a client target.
    ///
    /// A client application connects to this daemon's `local_vip:port`.
    /// The packet loop must then select the configured remote web3 peer rather
    /// than treating the packet as traffic for this daemon's own identity.
    pub fn lookup_client_target(&self, dest: Ipv4Addr, port: u16) -> Option<Locator> {
        if dest != self.local_vip {
            return None;
        }
        let target = self
            .clients
            .iter()
            .chain(self.client_duplex.iter())
            .find(|target| target.port == port)?;
        self.lookup_peer_for_target(target)
    }

    /// Resolve a configured peer for one client target.
    ///
    /// The same EOA may expose more than one protocol port (for example Geth
    /// and Beacon).  Port matching is therefore part of identity resolution;
    /// selecting the first EOA entry can attach a Beacon socket to the Geth
    /// PGP/route key.
    pub fn lookup_peer_for_target(&self, target: &crate::locator::ClientTarget) -> Option<Locator> {
        match &target.host {
            LocatorHost::Eoa(eoa) => self
                .peers
                .iter()
                .find(|peer| {
                    let port_matches = peer.tcp_ports.contains(&target.port)
                        || peer.udp_ports.contains(&target.port)
                        // Non-standard client ports are logical proxy ports and
                        // may intentionally be absent from peers.*.tcp_ports.
                        || target.service().is_none();
                    port_matches
                        && match &peer.locator.host {
                            LocatorHost::Eoa(peer_eoa) => crate::l0::eip191::eoa_eq(eoa, peer_eoa),
                            LocatorHost::Tag(_) => false,
                        }
                })
                .map(|peer| peer.locator.clone()),
            LocatorHost::Tag(_) => None,
        }
    }

    /// Human-readable local endpoint mappings for startup/status output.
    ///
    /// Packet clients stay on the overlay VIP. Duplex clients bind
    /// `127.0.0.1:<bind_port>`. The same logical PORT may map to several
    /// remotes; each remote gets its own loopback listener.
    pub fn client_mappings(&self) -> Vec<(String, String)> {
        let packet: Vec<(String, String)> = self
            .clients
            .iter()
            .map(|target| {
                (
                    target.display(),
                    format!("{}:{}", self.local_vip, target.port),
                )
            })
            .collect();
        let duplex: Vec<(String, String)> = self
            .client_duplex
            .iter()
            .map(|target| {
                (
                    target.display(),
                    format!("{}:{}", Ipv4Addr::LOCALHOST, target.bind_port),
                )
            })
            .collect();
        packet.into_iter().chain(duplex).collect()
    }
}

#[derive(Debug, Clone)]
pub struct ValidatedGateway {
    pub rpc: String,
    pub upstream: String,
    pub listen_entries: Vec<String>,
    pub post_entries: Vec<String>,
    pub routing_eoa: String,
    pub routing_key_file: PathBuf,
    pub routing_eth_key_file: PathBuf,
    pub mailbox_route_pgp_file: PathBuf,
    pub allowed_methods: HashSet<String>,
    pub max_body_bytes: usize,
    pub request_timeout_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct L0Settings {
    pub enabled: bool,
    pub rpc: String,
    pub address_pgp: String,
    pub entries: Vec<String>,
    pub listen_entries: Vec<String>,
    pub si_pool_from_contract: bool,
    pub routing_eoa: Option<String>,
    /// OpenPGP secret cert for inbound user-PGP decrypt. Unused when `[l0]` is off.
    pub routing_key_file: Option<PathBuf>,
    /// Hex secp256k1 key for EIP-191 listen. Unused when `[l0]` is off.
    pub routing_eth_key_file: Option<PathBuf>,
    /// This host's mailbox B route **public** cert. Unused when `[l0]` is off.
    pub mailbox_route_pgp_file: Option<PathBuf>,
    pub billing_eoa: Option<String>,
    pub billing_eth_key_file: Option<PathBuf>,
    pub billing_pgp_file: Option<PathBuf>,
    pub channels: Vec<ValidatedL0Channel>,
    pub proxies: Vec<ValidatedL0Proxy>,
    pub proxy_duplex: Vec<ValidatedL0Proxy>,
}

#[derive(Debug, Clone)]
pub struct ValidatedL0Channel {
    pub port: u16,
    pub routing_eoa: String,
    pub routing_key_file: PathBuf,
    pub routing_eth_key_file: PathBuf,
    pub mailbox_route_pgp_file: PathBuf,
    pub listen_entries: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ValidatedL0Proxy {
    pub host: String,
    pub port: u16,
    pub mode: ProxyMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyMode {
    RequestResponse,
    Duplex,
}

#[derive(Debug, Clone)]
pub struct ValidatedPeer {
    pub locator: Locator,
    pub vip: Ipv4Addr,
    #[allow(dead_code)]
    pub tcp_ports: Vec<u16>,
    #[allow(dead_code)]
    pub udp_ports: Vec<u16>,
    pub user_pgp_file: Option<PathBuf>,
    pub route_pgp_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy)]
pub struct Ipv4Cidr {
    pub network: Ipv4Addr,
    pub prefix: u8,
}

impl Ipv4Cidr {
    pub fn parse(raw: &str) -> Result<Self, L0dError> {
        let (net, prefix) = raw
            .split_once('/')
            .ok_or_else(|| L0dError::Config("overlay_cidr must look like 100.64.0.0/10".into()))?;
        let network: Ipv4Addr = net
            .parse()
            .map_err(|_| L0dError::Config(format!("invalid overlay network {net}")))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| L0dError::Config("invalid CIDR prefix".into()))?;
        if prefix > 32 {
            return Err(L0dError::Config("CIDR prefix must be 0..=32".into()));
        }
        Ok(Self { network, prefix })
    }

    pub fn contains(self, ip: Ipv4Addr) -> bool {
        let mask = if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix)
        };
        (u32::from(ip) & mask) == (u32::from(self.network) & mask)
    }

    pub fn display(self) -> String {
        format!("{}/{}", self.network, self.prefix)
    }
}

fn default_tun_name() -> String {
    "conet-l0".into()
}
fn default_overlay_cidr() -> String {
    "100.64.0.0/10".into()
}

fn default_local_vip() -> String {
    "auto".into()
}

fn select_local_vip(overlay: Ipv4Cidr, peers: &[PeerConfig]) -> Result<Ipv4Addr, L0dError> {
    let used: HashSet<Ipv4Addr> = peers
        .iter()
        .filter_map(|peer| peer.vip.parse().ok())
        .collect();
    let network = u32::from(overlay.network);
    let host_count = if overlay.prefix >= 31 {
        0
    } else {
        (1u32 << (32 - overlay.prefix)).saturating_sub(2)
    };
    for offset in 5..host_count.saturating_add(1) {
        let candidate = Ipv4Addr::from(network.saturating_add(offset));
        if overlay.contains(candidate) && !used.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err(L0dError::Config(
        "unable to automatically allocate a local overlay VIP".into(),
    ))
}
fn default_chain() -> String {
    "CONET_L0D".into()
}
fn default_state_path() -> PathBuf {
    PathBuf::from("/run/conet-l0d/state.json")
}

fn default_l0_rpc() -> String {
    "https://rpc1.conet.network".into()
}

fn default_address_pgp() -> String {
    crate::l0::address_pgp::ADDRESS_PGP.into()
}

fn normalize_eoa(raw: &str) -> Result<String, L0dError> {
    let hex = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .ok_or_else(|| L0dError::Config("routing_eoa / address_pgp must be 0x + 40 hex".into()))?;
    if hex.len() != 40 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(L0dError::Config(
            "routing_eoa / address_pgp must be 0x + 40 hex".into(),
        ));
    }
    Ok(format!("0x{}", hex.to_ascii_lowercase()))
}

fn allow_existing_http_host(url: &str) -> Result<(), L0dError> {
    let trimmed = url.trim().trim_end_matches('/');
    let rest = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .ok_or_else(|| {
            L0dError::Config(
                "l0 entry must be http(s) on an existing CoNET / beamio.app host".into(),
            )
        })?;
    if rest.contains('?') || rest.contains('#') {
        return Err(L0dError::Config(
            "l0 entry must not carry query or fragment mailbox instructions".into(),
        ));
    }
    let host = rest
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");
    let host_l = host.to_ascii_lowercase();
    if host_l == "beamio.app" || host_l == "www.beamio.app" || host_l.ends_with(".conet.network") {
        return Ok(());
    }
    Err(L0dError::Config(format!(
        "l0 entry host {host} is not an existing CoNET / beamio.app hostname"
    )))
}

impl DaemonConfig {
    pub fn load(path: &Path) -> Result<Self, L0dError> {
        let text = std::fs::read_to_string(path)?;
        toml::from_str(&text).map_err(|e| L0dError::Config(e.to_string()))
    }

    pub fn apply_cli_overrides(
        &mut self,
        main_wallet: Option<String>,
        main_wallet_pgp: Option<PathBuf>,
        main_wallet_key: Option<PathBuf>,
        proxy_specs: &[String],
        proxy_duplex_specs: &[String],
        client_specs: &[String],
        client_duplex_specs: &[String],
    ) -> Result<(), L0dError> {
        if let Some(wallet) = main_wallet {
            self.l0.billing_eoa = Some(wallet);
        }
        if let Some(path) = main_wallet_pgp {
            self.l0.billing_pgp_file = Some(path);
        }
        if let Some(path) = main_wallet_key {
            self.l0.billing_eth_key_file = Some(path);
        }
        if !proxy_specs.is_empty() {
            self.l0.proxies = proxy_specs
                .iter()
                .map(|spec| parse_proxy_spec(spec))
                .collect::<Result<Vec<_>, _>>()?;
        }
        if !proxy_duplex_specs.is_empty() {
            self.l0.proxy_duplex = proxy_duplex_specs
                .iter()
                .map(|spec| parse_proxy_spec(spec))
                .collect::<Result<Vec<_>, _>>()?;
        }
        if !client_specs.is_empty() {
            self.l0.clients = client_specs
                .iter()
                .map(|spec| crate::locator::ClientTarget::parse(spec).map(|t| t.display()))
                .collect::<Result<Vec<_>, _>>()?;
        }
        if !client_duplex_specs.is_empty() {
            self.l0.client_duplex = client_duplex_specs
                .iter()
                .map(|spec| crate::locator::ClientTarget::parse(spec).map(|t| t.display()))
                .collect::<Result<Vec<_>, _>>()?;
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<ValidatedConfig, L0dError> {
        if self.tun_name.is_empty() || self.tun_name.contains('/') {
            return Err(L0dError::Config("tun_name is invalid".into()));
        }
        if self.iptables_chain.is_empty()
            || !self
                .iptables_chain
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(L0dError::Config(
                "iptables_chain must be alphanumeric or _".into(),
            ));
        }

        let overlay = Ipv4Cidr::parse(&self.overlay_cidr)?;
        let local_vip: Ipv4Addr =
            if self.local_vip.eq_ignore_ascii_case("auto") || self.local_vip.trim().is_empty() {
                select_local_vip(overlay, &self.peers)?
            } else {
                self.local_vip.parse().map_err(|_| {
                    L0dError::Config(format!("invalid local_vip {}", self.local_vip))
                })?
            };
        if !overlay.contains(local_vip) {
            return Err(L0dError::Config(
                "local_vip must sit inside overlay_cidr".into(),
            ));
        }
        if local_vip.is_loopback() {
            return Err(L0dError::Config("local_vip must not be loopback".into()));
        }

        let identity = Locator::parse(&self.identity.locator)?;
        let mut peers = Vec::new();
        let mut ports_by_vip: std::collections::HashMap<Ipv4Addr, HashSet<u16>> =
            std::collections::HashMap::new();
        for peer in &self.peers {
            let locator = Locator::parse(&peer.locator)?;
            let vip: Ipv4Addr = peer
                .vip
                .parse()
                .map_err(|_| L0dError::Config(format!("invalid peer vip {}", peer.vip)))?;
            if !overlay.contains(vip) {
                return Err(L0dError::Config(format!(
                    "peer vip {vip} is outside overlay_cidr"
                )));
            }
            if peer.tcp_ports.is_empty() && peer.udp_ports.is_empty() {
                return Err(L0dError::Config(format!(
                    "peer {} needs at least one tcp or udp port",
                    peer.locator
                )));
            }
            for port in peer.tcp_ports.iter().chain(peer.udp_ports.iter()) {
                if *port == 0 {
                    return Err(L0dError::Config("overlay port 0 is not allowed".into()));
                }
            }
            let used = ports_by_vip.entry(vip).or_default();
            for port in peer.tcp_ports.iter().chain(peer.udp_ports.iter()) {
                if !used.insert(*port) {
                    return Err(L0dError::Config(format!(
                        "duplicate overlay port {port} on peer vip {vip}"
                    )));
                }
            }
            if peers
                .iter()
                .any(|p: &ValidatedPeer| p.locator == locator && p.vip == vip)
            {
                return Err(L0dError::Config(format!(
                    "duplicate peer {}",
                    locator.display()
                )));
            }
            peers.push(ValidatedPeer {
                locator,
                vip,
                tcp_ports: peer.tcp_ports.clone(),
                udp_ports: peer.udp_ports.clone(),
                user_pgp_file: peer.user_pgp_file.clone(),
                route_pgp_file: peer.route_pgp_file.clone(),
            });
        }

        let rpc = self.l0.rpc.trim().trim_end_matches('/').to_string();
        if rpc != "https://rpc1.conet.network" && rpc != "https://publicrpc.conet.network" {
            return Err(L0dError::Config(
                "l0.rpc must be https://rpc1.conet.network or https://publicrpc.conet.network"
                    .into(),
            ));
        }
        let address_pgp = normalize_eoa(&self.l0.address_pgp)?;
        if address_pgp != crate::l0::address_pgp::ADDRESS_PGP.to_ascii_lowercase() {
            return Err(L0dError::Config(
                "l0.address_pgp must be the live AddressPGP contract".into(),
            ));
        }
        for entry in self
            .l0
            .entries
            .iter()
            .chain(self.l0.listen_entries.iter())
            .chain(
                self.l0
                    .channels
                    .iter()
                    .flat_map(|c| c.listen_entries.iter()),
            )
        {
            allow_existing_http_host(entry)?;
        }
        let gateway = self.gateway.as_ref().map(validate_gateway).transpose()?;
        let routing_eoa = match &self.l0.routing_eoa {
            Some(raw) => Some(normalize_eoa(raw)?),
            None => None,
        };
        let billing_eoa = match &self.l0.billing_eoa {
            Some(raw) => Some(normalize_eoa(raw)?),
            None if self.l0.channels.is_empty() => routing_eoa.clone(),
            None => None,
        };
        if !self.l0.channels.is_empty()
            && (billing_eoa.is_none() || self.l0.billing_eth_key_file.is_none())
        {
            return Err(L0dError::Config(
                "l0.billing_eoa and l0.billing_eth_key_file are required when channels are configured"
                    .into(),
            ));
        }
        let mut channels = Vec::new();
        let mut channel_ports = HashSet::new();
        let mut channel_eoas = HashSet::new();
        for ch in &self.l0.channels {
            if ch.port == 0 {
                return Err(L0dError::Config("l0.channels port 0 is not allowed".into()));
            }
            if !channel_ports.insert(ch.port) {
                return Err(L0dError::Config(format!(
                    "l0.channels overlay port {} is assigned twice",
                    ch.port
                )));
            }
            let eoa = normalize_eoa(&ch.routing_eoa)?;
            if !channel_eoas.insert(eoa.clone()) {
                return Err(L0dError::Config(
                    "l0.channels routing_eoa must be unique per listen SSE".into(),
                ));
            }
            // billing_eoa may equal one channel (common: geth channel == paid
            // mainWallet). Distinct ports still need distinct channel EOAs above
            // so SI exclusive occupy does not 409 across :8400/:4200.
            let mut listen_entries = if ch.listen_entries.is_empty() {
                self.l0.listen_entries.clone()
            } else {
                ch.listen_entries.clone()
            };
            listen_entries.retain(|e| !e.trim().is_empty());
            channels.push(ValidatedL0Channel {
                port: ch.port,
                routing_eoa: eoa,
                routing_key_file: ch.routing_key_file.clone(),
                routing_eth_key_file: ch.routing_eth_key_file.clone(),
                mailbox_route_pgp_file: ch.mailbox_route_pgp_file.clone(),
                listen_entries,
            });
        }
        let mut proxies = Vec::new();
        let mut proxy_duplex = Vec::new();
        let mut proxy_ports = HashSet::new();
        for (mode, raw_targets) in [
            (ProxyMode::RequestResponse, &self.l0.proxies),
            (ProxyMode::Duplex, &self.l0.proxy_duplex),
        ] {
            for proxy in raw_targets {
                let host = proxy.host.trim().to_string();
                if host.is_empty()
                    || host.chars().any(char::is_whitespace)
                    || host.contains('/')
                    || host.contains('#')
                    || host.contains('?')
                {
                    return Err(L0dError::Config(format!(
                        "l0 proxy host is invalid: {}",
                        proxy.host
                    )));
                }
                if proxy.port == 0 {
                    return Err(L0dError::Config("l0 proxy port 0 is not allowed".into()));
                }
                if !proxy_ports.insert(proxy.port) {
                    return Err(L0dError::Config(format!(
                        "l0 proxy port {} is assigned twice across proxy modes",
                        proxy.port
                    )));
                }
                let target = ValidatedL0Proxy {
                    host,
                    port: proxy.port,
                    mode,
                };
                match mode {
                    ProxyMode::RequestResponse => proxies.push(target),
                    ProxyMode::Duplex => proxy_duplex.push(target),
                }
            }
        }
        let mut clients = Vec::new();
        let mut packet_client_ports = HashSet::new();
        for raw in &self.l0.clients {
            let target = crate::locator::ClientTarget::parse(raw)?;
            if !packet_client_ports.insert(target.port) {
                return Err(L0dError::Config(format!(
                    "l0 client port {} is assigned twice",
                    target.port
                )));
            }
            clients.push(target);
        }
        if !clients.is_empty() && !self.l0.enabled {
            return Err(L0dError::Config(
                "l0.enabled must be true when l0 clients are configured".into(),
            ));
        }
        let mut client_duplex = Vec::new();
        let mut duplex_targets = HashSet::new();
        let mut client_bind_ports = HashSet::new();
        for raw in &self.l0.client_duplex {
            let mut target = crate::locator::ClientTarget::parse(raw)?;
            if !duplex_targets.insert((target.host.clone(), target.port)) {
                return Err(L0dError::Config(format!(
                    "l0 client target {} is assigned twice",
                    target.display()
                )));
            }
            target.bind_port = if let Some(local) = target.local_port {
                if !client_bind_ports.insert(local) {
                    return Err(L0dError::Config(format!(
                        "l0 client local bind {local} is assigned twice"
                    )));
                }
                local
            } else {
                let Some(bind) = next_client_bind_port(target.port, &client_bind_ports) else {
                    return Err(L0dError::Config(format!(
                        "l0 client port {} has no free local bind",
                        target.port
                    )));
                };
                client_bind_ports.insert(bind);
                bind
            };
            client_duplex.push(target);
        }
        if !client_duplex.is_empty() && !self.l0.enabled {
            return Err(L0dError::Config(
                "l0.enabled must be true when l0 duplex clients are configured".into(),
            ));
        }

        if !proxies.is_empty() || !proxy_duplex.is_empty() {
            if !self.l0.enabled {
                return Err(L0dError::Config(
                    "l0.enabled must be true when l0 proxy targets are configured".into(),
                ));
            }
            if billing_eoa.is_none() || self.l0.billing_eth_key_file.is_none() {
                return Err(L0dError::Config(
                    "l0.billing_eoa and l0.billing_eth_key_file are required for proxy targets"
                        .into(),
                ));
            }
        }
        match (&billing_eoa, &self.l0.billing_eth_key_file) {
            (Some(expected), Some(path)) => {
                let secret = crate::l0::eip191::load_eth_secret(path).map_err(|err| {
                    L0dError::Config(format!(
                        "billing_eth_key_file {} is invalid: {err}",
                        path.display()
                    ))
                })?;
                if !crate::l0::eip191::eoa_eq(expected, secret.address()) {
                    return Err(L0dError::Config(
                        "billing_eth_key_file does not match billing_eoa".into(),
                    ));
                }
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(L0dError::Config(
                    "billing_eoa and billing_eth_key_file must be provided together".into(),
                ));
            }
            (None, None) => {}
        }
        if let Some(path) = &self.l0.billing_pgp_file {
            if !path.is_file() {
                return Err(L0dError::Config(format!(
                    "billing_pgp_file does not exist: {}",
                    path.display()
                )));
            }
        }

        Ok(ValidatedConfig {
            raw: self.clone(),
            overlay,
            local_vip,
            identity,
            peers,
            l0: L0Settings {
                enabled: self.l0.enabled,
                rpc,
                address_pgp,
                entries: self.l0.entries.clone(),
                listen_entries: self.l0.listen_entries.clone(),
                si_pool_from_contract: self.l0.si_pool_from_contract,
                routing_eoa,
                routing_key_file: self.l0.routing_key_file.clone(),
                routing_eth_key_file: self.l0.routing_eth_key_file.clone(),
                mailbox_route_pgp_file: self.l0.mailbox_route_pgp_file.clone(),
                billing_eoa,
                billing_eth_key_file: self.l0.billing_eth_key_file.clone(),
                billing_pgp_file: self.l0.billing_pgp_file.clone(),
                channels,
                proxies,
                proxy_duplex,
            },
            clients,
            client_duplex,
            gateway,
        })
    }
}

fn parse_proxy_spec(raw: &str) -> Result<L0ProxyConfig, L0dError> {
    let value = raw.trim();
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| L0dError::Config(format!("proxy must be HOST:PORT: {raw}")))?;
    let port = port
        .parse::<u16>()
        .map_err(|_| L0dError::Config(format!("proxy port is invalid: {raw}")))?;
    Ok(L0ProxyConfig {
        host: host.trim().trim_matches(['[', ']']).to_string(),
        port,
    })
}

fn validate_gateway(raw: &GatewayConfig) -> Result<ValidatedGateway, L0dError> {
    let rpc = raw.rpc.trim().trim_end_matches('/').to_string();
    if rpc != "https://rpc1.conet.network" && rpc != "https://publicrpc.conet.network" {
        return Err(L0dError::Config(
            "gateway.rpc must be https://rpc1.conet.network or https://publicrpc.conet.network"
                .into(),
        ));
    }
    let upstream = raw.upstream.trim().trim_end_matches('/').to_string();
    if !(upstream.starts_with("http://127.0.0.1")
        || upstream.starts_with("http://localhost")
        || upstream.starts_with("http://[::1]")
        || upstream.starts_with("https://127.0.0.1")
        || upstream.starts_with("https://localhost")
        || upstream.starts_with("https://[::1]"))
    {
        return Err(L0dError::Config(
            "gateway.upstream must target localhost/loopback; refusing remote upstream".into(),
        ));
    }
    if raw.listen_entries.is_empty() || raw.post_entries.is_empty() {
        return Err(L0dError::Config(
            "gateway listen_entries and post_entries must not be empty".into(),
        ));
    }
    for entry in raw.listen_entries.iter().chain(raw.post_entries.iter()) {
        allow_existing_http_host(entry)?;
    }
    let routing_eoa = normalize_eoa(&raw.routing_eoa)?;
    let methods: HashSet<String> = raw
        .allowed_methods
        .iter()
        .map(|method| method.trim().to_ascii_uppercase())
        .filter(|method| !method.is_empty())
        .collect();
    if methods.is_empty()
        || methods
            .iter()
            .any(|method| method != "GET" && method != "HEAD")
    {
        return Err(L0dError::Config(
            "gateway.allowed_methods may contain only GET and HEAD".into(),
        ));
    }
    if raw.max_body_bytes == 0 || raw.max_body_bytes > 64 * 1024 * 1024 {
        return Err(L0dError::Config(
            "gateway.max_body_bytes must be between 1 and 67108864".into(),
        ));
    }
    if raw.request_timeout_seconds == 0 || raw.request_timeout_seconds > 120 {
        return Err(L0dError::Config(
            "gateway.request_timeout_seconds must be between 1 and 120".into(),
        ));
    }
    Ok(ValidatedGateway {
        rpc,
        upstream,
        listen_entries: raw.listen_entries.clone(),
        post_entries: raw.post_entries.clone(),
        routing_eoa,
        routing_key_file: raw.routing_key_file.clone(),
        routing_eth_key_file: raw.routing_eth_key_file.clone(),
        mailbox_route_pgp_file: raw.mailbox_route_pgp_file.clone(),
        allowed_methods: methods,
        max_body_bytes: raw.max_body_bytes,
        request_timeout_seconds: raw.request_timeout_seconds,
    })
}

impl ValidatedConfig {
    pub fn lookup_locator(&self, locator: &Locator) -> Option<Ipv4Addr> {
        if &self.identity == locator {
            return Some(self.local_vip);
        }
        self.peers
            .iter()
            .find(|p| &p.locator == locator)
            .map(|p| p.vip)
    }

    pub fn lookup_peer(&self, dest: Ipv4Addr, port: u16) -> Option<&ValidatedPeer> {
        if dest == self.local_vip {
            return None;
        }
        self.peers.iter().find(|p| {
            if p.vip != dest {
                return false;
            }
            if p.tcp_ports.contains(&port) || p.udp_ports.contains(&port) {
                return true;
            }
            // `--client web3://<peerEoa>:port` may address a port that is not
            // listed under peers.*.ports (independent multiline / proxy line).
            self.clients.iter().any(|c| {
                c.port == port
                    && match &c.host {
                        LocatorHost::Eoa(eoa) => match &p.locator.host {
                            LocatorHost::Eoa(peer) => crate::l0::eip191::eoa_eq(eoa, peer),
                            LocatorHost::Tag(_) => false,
                        },
                        LocatorHost::Tag(_) => false,
                    }
            })
        })
    }

    pub fn overlay_ports(&self) -> HashSet<u16> {
        let mut ports: HashSet<u16> = if !self.l0.channels.is_empty() {
            self.l0.channels.iter().map(|c| c.port).collect()
        } else {
            let mut from_peers: HashSet<u16> = self
                .peers
                .iter()
                .flat_map(|p| p.tcp_ports.iter().chain(p.udp_ports.iter()).copied())
                .collect();
            if from_peers.is_empty() {
                from_peers = crate::packet::default_overlay_port_set();
            }
            from_peers
        };
        for client in self.clients.iter().chain(self.client_duplex.iter()) {
            ports.insert(client.port);
        }
        for proxy in &self.l0.proxies {
            ports.insert(proxy.port);
        }
        for proxy in &self.l0.proxy_duplex {
            ports.insert(proxy.port);
        }
        ports
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_config_with_test_peers() -> DaemonConfig {
        let mut cfg: DaemonConfig =
            toml::from_str(include_str!("../config/conet-l0d.example.toml"))
                .expect("parse example");
        cfg.peers = vec![
            PeerConfig {
                locator: "web3://HubTag.web3/p2p/geth".into(),
                vip: "100.64.0.1".into(),
                tcp_ports: vec![8400],
                udp_ports: Vec::new(),
                user_pgp_file: None,
                route_pgp_file: None,
            },
            PeerConfig {
                locator: "web3://HubTag.web3/p2p/beacon".into(),
                vip: "100.64.0.1".into(),
                tcp_ports: vec![4200],
                udp_ports: Vec::new(),
                user_pgp_file: None,
                route_pgp_file: None,
            },
        ];
        cfg
    }

    #[test]
    fn default_overlay_contains_example_vips() {
        let cidr = Ipv4Cidr::parse("100.64.0.0/10").unwrap();
        assert!(cidr.contains("100.64.0.5".parse().unwrap()));
        assert!(cidr.contains("100.127.255.255".parse().unwrap()));
        assert!(!cidr.contains("100.128.0.1".parse().unwrap()));
        assert!(!cidr.contains("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn auto_vip_skips_configured_peer_vips() {
        let mut cfg = example_config_with_test_peers();
        cfg.local_vip = "auto".into();
        cfg.peers[0].vip = "100.64.0.5".into();
        let validated = cfg.validate().expect("auto vip");
        assert_eq!(
            validated.local_vip,
            "100.64.0.6".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn example_toml_validates_with_l0_disabled() {
        let raw = include_str!("../config/conet-l0d.example.toml");
        let cfg: DaemonConfig = toml::from_str(raw).expect("parse example");
        let validated = cfg.validate().expect("validate example");
        assert!(!validated.l0.enabled);
        assert_eq!(validated.l0.rpc, "https://rpc1.conet.network");
        assert!(validated.l0.routing_eth_key_file.is_none());
        assert!(validated.l0.channels.is_empty());
        assert!(raw.contains("routing_eth_key_file"));
        assert!(raw.contains("l0.channels"));
    }

    #[test]
    fn same_vip_two_ports_is_ok() {
        let mut cfg = example_config_with_test_peers();
        cfg.peers[1].udp_ports = vec![4300];
        let validated = cfg.validate().expect("same vip geth+beacon");
        assert_eq!(validated.peers.len(), 2);
        assert!(validated
            .lookup_peer("100.64.0.1".parse().unwrap(), 8400)
            .is_some());
        assert!(validated
            .lookup_peer("100.64.0.1".parse().unwrap(), 4200)
            .is_some());
        assert!(validated
            .lookup_peer("100.64.0.1".parse().unwrap(), 4300)
            .is_some());
    }

    #[test]
    fn reject_duplicate_port_on_same_vip() {
        let mut cfg = example_config_with_test_peers();
        cfg.peers[1].tcp_ports = vec![8400];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn reject_duplicate_channel_eoa() {
        let mut cfg: DaemonConfig =
            toml::from_str(include_str!("../config/conet-l0d.example.toml"))
                .expect("parse example");
        cfg.l0.channels = vec![
            L0ChannelConfig {
                port: 8400,
                routing_eoa: "0x1111111111111111111111111111111111111111".into(),
                routing_key_file: "/tmp/a.key".into(),
                routing_eth_key_file: "/tmp/a.eth".into(),
                mailbox_route_pgp_file: "/tmp/a.asc".into(),
                listen_entries: vec!["https://node.conet.network".into()],
            },
            L0ChannelConfig {
                port: 4200,
                routing_eoa: "0x1111111111111111111111111111111111111111".into(),
                routing_key_file: "/tmp/b.key".into(),
                routing_eth_key_file: "/tmp/b.eth".into(),
                mailbox_route_pgp_file: "/tmp/b.asc".into(),
                listen_entries: vec!["https://node.conet.network".into()],
            },
        ];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn reject_unknown_l0_entry_host() {
        let mut cfg: DaemonConfig =
            toml::from_str(include_str!("../config/conet-l0d.example.toml"))
                .expect("parse example");
        cfg.l0.enabled = true;
        cfg.l0.entries = vec!["https://assets.conet.example/post".into()];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn billing_key_must_match_billing_eoa() {
        let mut cfg: DaemonConfig =
            toml::from_str(include_str!("../config/conet-l0d.example.toml"))
                .expect("parse example");
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("billing.eth");
        std::fs::write(
            &key_file,
            "0000000000000000000000000000000000000000000000000000000000000001\n",
        )
        .unwrap();
        cfg.l0.billing_eth_key_file = Some(key_file);
        cfg.l0.billing_eoa = Some("0x0000000000000000000000000000000000000001".into());
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn proxy_server_only_when_proxies_without_clients() {
        let mut cfg: DaemonConfig =
            toml::from_str(include_str!("../config/conet-l0d.example.toml"))
                .expect("parse example");
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("billing.eth");
        // secp256k1 secret 1 → 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
        std::fs::write(
            &key_file,
            "0000000000000000000000000000000000000000000000000000000000000001\n",
        )
        .unwrap();
        cfg.l0.enabled = true;
        cfg.l0.entries = vec!["http://20ab90fe82d0e9e3.conet.network".into()];
        cfg.l0.billing_eoa = Some("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf".into());
        cfg.l0.billing_eth_key_file = Some(key_file);
        cfg.l0.proxies = vec![L0ProxyConfig {
            host: "127.0.0.1".into(),
            port: 8400,
        }];
        let validated = cfg.validate().expect("proxy-only config");
        assert!(validated.proxy_server_only());
        assert!(validated.overlay_ports().contains(&8400));
    }

    #[test]
    fn proxy_modes_share_port_namespace() {
        let mut cfg: DaemonConfig =
            toml::from_str(include_str!("../config/conet-l0d.example.toml"))
                .expect("parse example");
        cfg.l0.enabled = true;
        cfg.l0.entries = vec!["http://20ab90fe82d0e9e3.conet.network".into()];
        cfg.l0.proxies = vec![L0ProxyConfig {
            host: "127.0.0.1".into(),
            port: 8400,
        }];
        cfg.l0.proxy_duplex = cfg.l0.proxies.clone();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn clients_extend_overlay_ports_and_lookup_peer() {
        let mut cfg = example_config_with_test_peers();
        cfg.peers[0].locator = "web3://0x2222222222222222222222222222222222222222/p2p/geth".into();
        cfg.peers[0].tcp_ports = vec![8400];
        cfg.peers[1].locator =
            "web3://0x2222222222222222222222222222222222222222/p2p/beacon".into();
        cfg.peers[1].tcp_ports = vec![4200];
        cfg.l0.enabled = true;
        cfg.l0.entries = vec!["http://20ab90fe82d0e9e3.conet.network".into()];
        cfg.l0.clients = vec!["web3://0x2222222222222222222222222222222222222222:9999".into()];
        cfg.l0.client_duplex =
            vec!["web3://0x2222222222222222222222222222222222222222:4200".into()];
        let validated = cfg.validate().expect("clients with l0 on");
        assert!(!validated.proxy_server_only());
        assert!(validated.overlay_ports().contains(&9999));
        assert!(validated
            .lookup_peer("100.64.0.1".parse().unwrap(), 9999)
            .is_some());
        assert!(validated
            .lookup_peer("100.64.0.1".parse().unwrap(), 8400)
            .is_some());
        assert_eq!(
            validated
                .lookup_client_target("100.64.0.5".parse().unwrap(), 9999)
                .expect("local client endpoint")
                .display(),
            "web3://0x2222222222222222222222222222222222222222/p2p/geth"
        );
        assert_eq!(
            validated
                .lookup_client_target("100.64.0.5".parse().unwrap(), 4200)
                .expect("local beacon endpoint")
                .display(),
            "web3://0x2222222222222222222222222222222222222222/p2p/beacon"
        );
    }

    #[test]
    fn allow_two_remotes_on_one_logical_client_port() {
        let mut cfg = example_config_with_test_peers();
        cfg.l0.enabled = true;
        cfg.l0.entries = vec!["http://20ab90fe82d0e9e3.conet.network".into()];
        cfg.l0.client_duplex = vec![
            "web3://0x2222222222222222222222222222222222222222:8400".into(),
            "web3://0x3333333333333333333333333333333333333333:8400".into(),
        ];
        let validated = cfg.validate().expect("one logical port, many remotes");
        assert_eq!(
            validated.client_mappings(),
            vec![
                (
                    "web3://0x2222222222222222222222222222222222222222:8400".into(),
                    "127.0.0.1:8400".into()
                ),
                (
                    "web3://0x3333333333333333333333333333333333333333:8400".into(),
                    "127.0.0.1:18400".into()
                ),
            ]
        );
    }

    #[test]
    fn reject_duplicate_duplex_client_target() {
        let mut cfg = example_config_with_test_peers();
        cfg.l0.enabled = true;
        cfg.l0.entries = vec!["http://20ab90fe82d0e9e3.conet.network".into()];
        cfg.l0.client_duplex = vec![
            "web3://0x2222222222222222222222222222222222222222:8400".into(),
            "web3://0x2222222222222222222222222222222222222222:8400".into(),
        ];
        let err = cfg.validate().expect_err("same remote twice");
        assert!(
            err.to_string().contains("l0 client target")
                && err.to_string().contains("is assigned twice"),
            "{err}"
        );
    }

    #[test]
    fn reject_duplicate_client_local_bind() {
        let mut cfg = example_config_with_test_peers();
        cfg.l0.enabled = true;
        cfg.l0.entries = vec!["http://20ab90fe82d0e9e3.conet.network".into()];
        cfg.l0.client_duplex = vec![
            "web3://0x2222222222222222222222222222222222222222:8400".into(),
            "web3://0x2222222222222222222222222222222222222222:4200@8400".into(),
        ];
        let err = cfg.validate().expect_err("unique loopback binds");
        assert!(
            err.to_string()
                .contains("l0 client local bind 8400 is assigned twice"),
            "{err}"
        );
    }

    #[test]
    fn duplex_clients_map_one_logical_port_to_one_loopback() {
        let mut cfg = example_config_with_test_peers();
        cfg.l0.enabled = true;
        cfg.l0.entries = vec!["http://20ab90fe82d0e9e3.conet.network".into()];
        cfg.l0.client_duplex = vec![
            "web3://0x2222222222222222222222222222222222222222:8400".into(),
            "web3://0x2222222222222222222222222222222222222222:4200".into(),
        ];
        let validated = cfg.validate().expect("distinct logical ports");
        assert_eq!(
            validated.client_mappings(),
            vec![
                (
                    "web3://0x2222222222222222222222222222222222222222:8400".into(),
                    "127.0.0.1:8400".into()
                ),
                (
                    "web3://0x2222222222222222222222222222222222222222:4200".into(),
                    "127.0.0.1:4200".into()
                ),
            ]
        );
    }

    #[test]
    fn allow_packet_and_duplex_same_logical_port() {
        let mut cfg = example_config_with_test_peers();
        cfg.l0.enabled = true;
        cfg.l0.entries = vec!["http://20ab90fe82d0e9e3.conet.network".into()];
        cfg.l0.clients = vec!["web3://0x2222222222222222222222222222222222222222:8400".into()];
        cfg.l0.client_duplex =
            vec!["web3://0x3333333333333333333333333333333333333333:8400".into()];
        let validated = cfg
            .validate()
            .expect("packet VIP and duplex loopback may share a logical port");
        assert_eq!(
            validated.client_mappings(),
            vec![
                (
                    "web3://0x2222222222222222222222222222222222222222:8400".into(),
                    format!("{}:8400", validated.local_vip)
                ),
                (
                    "web3://0x3333333333333333333333333333333333333333:8400".into(),
                    "127.0.0.1:8400".into()
                ),
            ]
        );
    }
}
