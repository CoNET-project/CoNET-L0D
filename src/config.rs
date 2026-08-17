use crate::error::L0dError;
use crate::locator::Locator;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
    #[serde(default = "default_overlay_cidr")]
    pub overlay_cidr: String,
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
    pub routing_eoa: Option<String>,
    #[serde(default)]
    pub routing_key_file: Option<PathBuf>,
    /// Hex secp256k1 key for EIP-191 listen. Not an OpenPGP cert.
    #[serde(default)]
    pub routing_eth_key_file: Option<PathBuf>,
    /// This host's mailbox **B route public** key. Not the peer route file.
    #[serde(default)]
    pub mailbox_route_pgp_file: Option<PathBuf>,
}

impl Default for L0Config {
    fn default() -> Self {
        Self {
            enabled: false,
            rpc: default_l0_rpc(),
            address_pgp: default_address_pgp(),
            entries: Vec::new(),
            listen_entries: Vec::new(),
            routing_eoa: None,
            routing_key_file: None,
            routing_eth_key_file: None,
            mailbox_route_pgp_file: None,
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
    pub tcp_ports: Vec<u16>,
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
}

#[derive(Debug, Clone)]
pub struct L0Settings {
    pub enabled: bool,
    pub rpc: String,
    pub address_pgp: String,
    pub entries: Vec<String>,
    pub listen_entries: Vec<String>,
    pub routing_eoa: Option<String>,
    /// OpenPGP secret cert for inbound user-PGP decrypt. Unused when `[l0]` is off.
    pub routing_key_file: Option<PathBuf>,
    /// Hex secp256k1 key for EIP-191 listen. Unused when `[l0]` is off.
    pub routing_eth_key_file: Option<PathBuf>,
    /// This host's mailbox B route **public** cert. Unused when `[l0]` is off.
    pub mailbox_route_pgp_file: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct ValidatedPeer {
    pub locator: Locator,
    pub vip: Ipv4Addr,
    #[allow(dead_code)]
    pub tcp_ports: Vec<u16>,
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
            L0dError::Config("l0 entry must be http(s) on an existing CoNET / beamio.app host".into())
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
    if host_l == "beamio.app"
        || host_l == "www.beamio.app"
        || host_l.ends_with(".conet.network")
    {
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
        let local_vip: Ipv4Addr = self
            .local_vip
            .parse()
            .map_err(|_| L0dError::Config(format!("invalid local_vip {}", self.local_vip)))?;
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
        let mut seen_vips = vec![local_vip];
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
            if peer.tcp_ports.is_empty() {
                return Err(L0dError::Config(format!(
                    "peer {} needs at least one tcp port",
                    peer.locator
                )));
            }
            for port in &peer.tcp_ports {
                if *port == 0 {
                    return Err(L0dError::Config("tcp port 0 is not allowed".into()));
                }
            }
            if seen_vips.contains(&vip) && vip != local_vip {
                // same vip may host geth+beacon; only reject if identical locator+vip duplicated
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
            seen_vips.push(vip);
            peers.push(ValidatedPeer {
                locator,
                vip,
                tcp_ports: peer.tcp_ports.clone(),
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
        {
            allow_existing_http_host(entry)?;
        }
        let routing_eoa = match &self.l0.routing_eoa {
            Some(raw) => Some(normalize_eoa(raw)?),
            None => None,
        };

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
                routing_eoa,
                routing_key_file: self.l0.routing_key_file.clone(),
                routing_eth_key_file: self.l0.routing_eth_key_file.clone(),
                mailbox_route_pgp_file: self.l0.mailbox_route_pgp_file.clone(),
            },
        })
    }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_overlay_contains_example_vips() {
        let cidr = Ipv4Cidr::parse("100.64.0.0/10").unwrap();
        assert!(cidr.contains("100.64.0.5".parse().unwrap()));
        assert!(cidr.contains("100.127.255.255".parse().unwrap()));
        assert!(!cidr.contains("100.128.0.1".parse().unwrap()));
        assert!(!cidr.contains("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn example_toml_validates_with_l0_disabled() {
        let raw = include_str!("../config/conet-l0d.example.toml");
        let cfg: DaemonConfig = toml::from_str(raw).expect("parse example");
        let validated = cfg.validate().expect("validate example");
        assert!(!validated.l0.enabled);
        assert_eq!(validated.l0.rpc, "https://rpc1.conet.network");
        assert!(validated.l0.routing_eth_key_file.is_none());
        assert!(raw.contains("routing_eth_key_file"));
    }

    #[test]
    fn reject_unknown_l0_entry_host() {
        let mut cfg: DaemonConfig = toml::from_str(include_str!("../config/conet-l0d.example.toml"))
            .expect("parse example");
        cfg.l0.enabled = true;
        cfg.l0.entries = vec!["https://assets.conet.example/post".into()];
        assert!(cfg.validate().is_err());
    }
}
