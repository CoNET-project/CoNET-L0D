//! Overlay JSON envelope. Encrypt this to the peer **user PGP**, then POST `{ "data" }`.
//!
//! No EIP-191 field yet — do not invent a signature.

use crate::error::L0dError;
use serde::{Deserialize, Serialize};

pub const ENVELOPE_TYPE: &str = "conet_l0d_overlay_v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayEnvelope {
    #[serde(rename = "type")]
    pub kind: String,
    pub from: String,
    pub seq: u64,
    /// Standard base64 of the raw IPv4 packet (not OpenPGP armor).
    pub ipv4: String,
}

pub fn encode(from: &str, seq: u64, ipv4: &[u8]) -> Result<String, L0dError> {
    let env = OverlayEnvelope {
        kind: ENVELOPE_TYPE.into(),
        from: from.to_ascii_lowercase(),
        seq,
        ipv4: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ipv4),
    };
    serde_json::to_string(&env).map_err(|e| L0dError::L0(e.to_string()))
}

#[allow(dead_code)]
pub fn decode(json: &str) -> Result<(OverlayEnvelope, Vec<u8>), L0dError> {
    let env: OverlayEnvelope =
        serde_json::from_str(json).map_err(|e| L0dError::L0(e.to_string()))?;
    if env.kind != ENVELOPE_TYPE {
        return Err(L0dError::L0(format!(
            "unexpected overlay envelope type {}",
            env.kind
        )));
    }
    let ipv4 = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &env.ipv4)
        .map_err(|e| L0dError::L0(format!("overlay ipv4 base64: {e}")))?;
    Ok((env, ipv4))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_preserves_ipv4() {
        let pkt = b"\x45\x00fake-ipv4";
        let json = encode("0x1111111111111111111111111111111111111111", 3, pkt).unwrap();
        assert!(json.contains(ENVELOPE_TYPE));
        assert!(!json.contains("signMessage"));
        let (env, rest) = decode(&json).unwrap();
        assert_eq!(env.seq, 3);
        assert_eq!(rest, pkt);
    }
}
