use crate::error::L0dError;
use serde::{Deserialize, Serialize};

/// Peer locator, not an ERC-4804 content URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Locator {
    pub host: LocatorHost,
    pub service: OverlayService,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

        let parts: Vec<&str> = rest.split('/').filter(|p| !p.is_empty()).collect();
        if parts.len() != 3 {
            return Err(L0dError::Locator(
                "expected web3://<host>/p2p/<geth|beacon>".into(),
            ));
        }
        if !parts[1].eq_ignore_ascii_case("p2p") {
            return Err(L0dError::Locator("second path segment must be p2p".into()));
        }

        let service = match parts[2].to_ascii_lowercase().as_str() {
            "geth" => OverlayService::Geth,
            "beacon" => OverlayService::Beacon,
            other => {
                return Err(L0dError::Locator(format!(
                    "service must be geth or beacon, not {other}"
                )))
            }
        };

        let host = parse_host(parts[0])?;
        Ok(Self { host, service })
    }

    pub fn display(&self) -> String {
        match &self.host {
            LocatorHost::Eoa(eoa) => format!("web3://{eoa}/p2p/{}", self.service.as_str()),
            LocatorHost::Tag(tag) => format!("web3://{tag}.web3/p2p/{}", self.service.as_str()),
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
    fn parse_eoa_geth() {
        let loc = Locator::parse("web3://0x1111111111111111111111111111111111111111/p2p/geth")
            .expect("parse");
        assert_eq!(
            loc.host,
            LocatorHost::Eoa("0x1111111111111111111111111111111111111111".into())
        );
        assert_eq!(loc.service, OverlayService::Geth);
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
    fn reject_validator_service() {
        assert!(Locator::parse("web3://0x1111111111111111111111111111111111111111/p2p/validator")
            .is_err());
    }

    #[test]
    fn reject_short_hex() {
        assert!(Locator::parse("web3://0x1111/p2p/geth").is_err());
    }
}
