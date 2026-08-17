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
}

#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    pub raw: DaemonConfig,
    pub overlay: Ipv4Cidr,
    pub local_vip: Ipv4Addr,
    pub identity: Locator,
    pub peers: Vec<ValidatedPeer>,
}

#[derive(Debug, Clone)]
pub struct ValidatedPeer {
    pub locator: Locator,
    pub vip: Ipv4Addr,
    #[allow(dead_code)]
    pub tcp_ports: Vec<u16>,
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
            });
        }

        Ok(ValidatedConfig {
            raw: self.clone(),
            overlay,
            local_vip,
            identity,
            peers,
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
}
