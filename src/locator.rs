use crate::error::L0dError;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Wallet-addressed application resource locator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Locator {
    pub host: LocatorHost,
    /// Absolute application path with an optional query string.
    ///
    /// Compatibility paths such as `/p2p/geth` remain parseable, but ordinary
    /// application resources are not restricted to a fixed service catalog.
    pub path_and_query: String,
}

/// Client address for a persistent application stream: `web3://<host>:<port>`.
///
/// Port `8400` maps to geth, `4200` to beacon. Other ports stay numeric-only
/// (no OverlayService) so proxy lines can use arbitrary logical ports.
///
/// Optional `@LOCAL` is a Linux-runtime loopback bind, not part of the
/// public `web3://` locator contract: `web3://HOST:PORT@18400`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientTarget {
    pub host: LocatorHost,
    pub port: u16,
    /// Explicit `127.0.0.1` bind from `web3://HOST:PORT@LOCAL`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_port: Option<u16>,
    /// Assigned `127.0.0.1` listener after config validation.
    #[serde(default)]
    pub bind_port: u16,
}

/// Local bind candidates walk `port`, `port+10000`, `port+20000`, …
pub const CLIENT_LOCAL_PORT_STRIDE: u16 = 10_000;

/// Preferred loopback bind, then documented stride fallbacks.
///
/// An explicit `@LOCAL` bind is a single candidate and must not walk.
pub fn client_bind_candidates(start: u16, explicit: bool) -> impl Iterator<Item = u16> {
    std::iter::successors(Some(start), move |port| {
        if explicit {
            None
        } else {
            port.checked_add(CLIENT_LOCAL_PORT_STRIDE)
        }
    })
}

/// Next unused loopback bind for a logical port (`PORT`, `PORT+10000`, …).
pub fn next_client_bind_port(logical: u16, claimed: &HashSet<u16>) -> Option<u16> {
    client_bind_candidates(logical, false).find(|port| !claimed.contains(port))
}

impl ClientTarget {
    pub fn parse(raw: &str) -> Result<Self, L0dError> {
        let trimmed = raw.trim();
        let rest = trimmed
            .strip_prefix("web3://")
            .or_else(|| trimmed.strip_prefix("WEB3://"))
            .ok_or_else(|| L0dError::Locator("client target must start with web3://".into()))?;
        if rest.contains("://") {
            return Err(L0dError::Locator("unexpected extra scheme".into()));
        }
        if rest.contains('/') {
            return Err(L0dError::Locator(
                "client target is web3://<host>:<port>[@LOCAL], not /p2p/<service>".into(),
            ));
        }
        let (host_raw, port_raw) = rest.rsplit_once(':').ok_or_else(|| {
            L0dError::Locator("client target must look like web3://0x…:8400".into())
        })?;
        if host_raw.is_empty() || host_raw.contains(':') {
            return Err(L0dError::Locator(
                "client target host is empty or contains ':'".into(),
            ));
        }
        let (logical_raw, local_raw) = match port_raw.split_once('@') {
            Some((logical, local)) => (logical, Some(local)),
            None => (port_raw, None),
        };
        if logical_raw.is_empty() || local_raw.is_some_and(|s| s.is_empty() || s.contains('@')) {
            return Err(L0dError::Locator(
                "client target local bind must look like web3://HOST:PORT@LOCAL".into(),
            ));
        }
        let port: u16 = logical_raw.parse().map_err(|_| {
            L0dError::Locator(format!("client target port is invalid: {logical_raw}"))
        })?;
        if port == 0 {
            return Err(L0dError::Locator(
                "client target port 0 is not allowed".into(),
            ));
        }
        let local_port = match local_raw {
            None => None,
            Some(raw) => {
                let local: u16 = raw.parse().map_err(|_| {
                    L0dError::Locator(format!("client target local bind port is invalid: {raw}"))
                })?;
                if local == 0 {
                    return Err(L0dError::Locator(
                        "client target local bind port 0 is not allowed".into(),
                    ));
                }
                Some(local)
            }
        };
        Ok(Self {
            host: parse_host(host_raw)?,
            port,
            local_port,
            bind_port: local_port.unwrap_or(port),
        })
    }

    pub fn service(&self) -> Option<OverlayService> {
        match self.port {
            8400 => Some(OverlayService::Geth),
            4200 => Some(OverlayService::Beacon),
            _ => None,
        }
    }

    pub fn display(&self) -> String {
        match &self.host {
            LocatorHost::Eoa(eoa) => format!("web3://{eoa}:{}", self.port),
            LocatorHost::Tag(tag) => format!("web3://{tag}.web3:{}", self.port),
        }
    }

    /// Config / CLI form including an explicit loopback bind when present.
    pub fn display_with_local(&self) -> String {
        match self.local_port {
            Some(local) => format!("{}@{local}", self.display()),
            None => self.display(),
        }
    }

    /// Compatibility locator when the port is a known overlay service.
    pub fn as_service_locator(&self) -> Option<Locator> {
        self.service().map(|service| Locator {
            host: self.host.clone(),
            path_and_query: format!("/p2p/{}", service.as_str()),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LocatorHost {
    Eoa(String),
    Tag(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OverlayService {
    Geth,
    Beacon,
}

impl OverlayService {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Geth => "geth",
            Self::Beacon => "beacon",
        }
    }
}

impl Locator {
    pub fn parse(raw: &str) -> Result<Self, L0dError> {
        let trimmed = raw.trim();
        let rest = trimmed
            .strip_prefix("web3://")
            .or_else(|| trimmed.strip_prefix("WEB3://"))
            .ok_or_else(|| L0dError::Locator("must start with web3://".into()))?;

        if rest.contains("://") {
            return Err(L0dError::Locator("unexpected extra scheme".into()));
        }

        let (host_raw, resource_raw) = rest.split_once('/').ok_or_else(|| {
            L0dError::Locator(
                "resource locator must look like web3://<host>/<path>; use web3://<host>:<port> for a stream"
                    .into(),
            )
        })?;
        if host_raw.is_empty() || host_raw.contains(':') {
            return Err(L0dError::Locator(
                "resource locator host is empty or contains a logical port".into(),
            ));
        }
        if resource_raw.contains('#') {
            return Err(L0dError::Locator(
                "resource locator fragments are client-local and must not be sent to the host"
                    .into(),
            ));
        }
        if resource_raw
            .chars()
            .any(|c| c.is_ascii_control() || c.is_ascii_whitespace() || c == '\\')
        {
            return Err(L0dError::Locator(
                "resource path and query must not contain whitespace, controls, or backslashes"
                    .into(),
            ));
        }

        let mut path_and_query = format!("/{resource_raw}");
        if path_and_query.eq_ignore_ascii_case("/p2p/geth") {
            path_and_query = "/p2p/geth".into();
        } else if path_and_query.eq_ignore_ascii_case("/p2p/beacon") {
            path_and_query = "/p2p/beacon".into();
        }

        Ok(Self {
            host: parse_host(host_raw)?,
            path_and_query,
        })
    }

    pub fn display(&self) -> String {
        match &self.host {
            LocatorHost::Eoa(eoa) => format!("web3://{eoa}{}", self.path_and_query),
            LocatorHost::Tag(tag) => {
                format!("web3://{tag}.web3{}", self.path_and_query)
            }
        }
    }

    pub fn service(&self) -> Option<OverlayService> {
        match self.path_and_query.as_str() {
            "/p2p/geth" => Some(OverlayService::Geth),
            "/p2p/beacon" => Some(OverlayService::Beacon),
            _ => None,
        }
    }
}

fn parse_host(host: &str) -> Result<LocatorHost, L0dError> {
    if host.contains('@') {
        return Err(L0dError::Locator(
            "do not put @ in the host; use ExactTag.web3".into(),
        ));
    }
    if host.eq_ignore_ascii_case("results[0]") || host.contains("search-users") {
        return Err(L0dError::Locator(
            "never use search-users results[0] as a destination".into(),
        ));
    }

    if let Some(tag) = host
        .strip_suffix(".web3")
        .or_else(|| host.strip_suffix(".WEB3"))
        .or_else(|| host.strip_suffix(".Web3"))
    {
        if tag.is_empty() {
            return Err(L0dError::Locator("empty BeamioTag".into()));
        }
        if tag.starts_with("0x") || tag.starts_with("0X") {
            return Err(L0dError::Locator(
                "tag.web3 host must be an exact BeamioTag, not an address".into(),
            ));
        }
        if !tag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(L0dError::Locator(
                "BeamioTag may contain only ASCII letters, digits, _ or -".into(),
            ));
        }
        return Ok(LocatorHost::Tag(tag.to_string()));
    }

    parse_eoa(host).map(LocatorHost::Eoa)
}

fn parse_eoa(raw: &str) -> Result<String, L0dError> {
    let hex = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .ok_or_else(|| L0dError::Locator("EOA host must be 0x + 40 hex or <tag>.web3".into()))?;
    if hex.len() != 40 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(L0dError::Locator(
            "EOA must be 0x followed by exactly 40 hex characters".into(),
        ));
    }
    Ok(format!("0x{}", hex.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_eoa_resource_with_query() {
        let loc =
            Locator::parse("web3://0x1111111111111111111111111111111111111111/dashboard?range=7d")
                .expect("parse");
        assert_eq!(
            loc.host,
            LocatorHost::Eoa("0x1111111111111111111111111111111111111111".into())
        );
        assert_eq!(loc.path_and_query, "/dashboard?range=7d");
        assert_eq!(loc.service(), None);
        assert_eq!(
            loc.display(),
            "web3://0x1111111111111111111111111111111111111111/dashboard?range=7d"
        );
    }

    #[test]
    fn parse_compatibility_service() {
        let loc = Locator::parse("web3://0x1111111111111111111111111111111111111111/p2p/geth")
            .expect("parse");
        assert_eq!(loc.path_and_query, "/p2p/geth");
        assert_eq!(loc.service(), Some(OverlayService::Geth));
    }

    #[test]
    fn parse_tag_preserves_case() {
        let a = Locator::parse("web3://CoNET.web3/p2p/beacon").unwrap();
        let b = Locator::parse("web3://CONET.web3/p2p/beacon").unwrap();
        assert_eq!(a.host, LocatorHost::Tag("CoNET".into()));
        assert_eq!(b.host, LocatorHost::Tag("CONET".into()));
        assert_ne!(a, b);
    }

    #[test]
    fn reject_results_zero() {
        let err = Locator::parse("web3://results[0]/p2p/geth").unwrap_err();
        assert!(err.to_string().contains("results[0]"));
    }

    #[test]
    fn parse_arbitrary_application_path() {
        let loc = Locator::parse("web3://ExampleMerchant.web3/api/orders?id=42").expect("parse");
        assert_eq!(loc.host, LocatorHost::Tag("ExampleMerchant".into()));
        assert_eq!(loc.path_and_query, "/api/orders?id=42");
    }

    #[test]
    fn parse_root_resource() {
        let loc = Locator::parse("web3://ExampleMerchant.web3/").expect("parse root resource");
        assert_eq!(loc.path_and_query, "/");
    }

    #[test]
    fn reject_resource_fragment() {
        assert!(Locator::parse("web3://ExampleMerchant.web3/app#section").is_err());
    }

    #[test]
    fn reject_short_hex() {
        assert!(Locator::parse("web3://0x1111/p2p/geth").is_err());
    }

    #[test]
    fn parse_client_eoa_port() {
        let t = ClientTarget::parse("web3://0x1111111111111111111111111111111111111111:8400")
            .expect("parse");
        assert_eq!(
            t.host,
            LocatorHost::Eoa("0x1111111111111111111111111111111111111111".into())
        );
        assert_eq!(t.port, 8400);
        assert_eq!(t.local_port, None);
        assert_eq!(t.bind_port, 8400);
        assert_eq!(t.service(), Some(OverlayService::Geth));
        assert_eq!(
            t.display(),
            "web3://0x1111111111111111111111111111111111111111:8400"
        );
        assert_eq!(t.display_with_local(), t.display());
    }

    #[test]
    fn parse_client_explicit_local_bind() {
        let t = ClientTarget::parse("web3://CoNET.web3:8400@18400").unwrap();
        assert_eq!(t.port, 8400);
        assert_eq!(t.local_port, Some(18400));
        assert_eq!(t.bind_port, 18400);
        assert_eq!(t.display(), "web3://CoNET.web3:8400");
        assert_eq!(t.display_with_local(), "web3://CoNET.web3:8400@18400");
        assert_eq!(
            client_bind_candidates(t.bind_port, t.local_port.is_some()).collect::<Vec<_>>(),
            vec![18400]
        );
    }

    #[test]
    fn reject_client_zero_local_bind() {
        assert!(ClientTarget::parse("web3://CoNET.web3:8400@0").is_err());
    }

    #[test]
    fn parse_client_tag_beacon() {
        let t = ClientTarget::parse("web3://CoNET.web3:4200").unwrap();
        assert_eq!(t.host, LocatorHost::Tag("CoNET".into()));
        assert_eq!(t.service(), Some(OverlayService::Beacon));
        assert_eq!(t.bind_port, 4200);
        assert_eq!(
            client_bind_candidates(t.bind_port, false)
                .take(3)
                .collect::<Vec<_>>(),
            vec![4200, 14200, 24200]
        );
    }

    #[test]
    fn reject_client_p2p_shape() {
        assert!(
            ClientTarget::parse("web3://0x1111111111111111111111111111111111111111/p2p/geth")
                .is_err()
        );
    }

    #[test]
    fn next_bind_skips_claimed_logical_port() {
        let claimed = HashSet::from([8400]);
        assert_eq!(next_client_bind_port(8400, &claimed), Some(18400));
        assert_eq!(next_client_bind_port(4200, &claimed), Some(4200));
    }
}
