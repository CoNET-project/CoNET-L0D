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
    /// Standard base64 of one IPv4 datagram, or several concatenated
    /// datagrams split by IPv4 `tot_len`. Not OpenPGP armor.
    pub ipv4: String,
}

/// Walk one or more IPv4 datagrams packed into `conet_l0d_overlay_v1.ipv4`.
/// A single short / fixture blob with a bogus `tot_len` stays one packet.
pub fn split_ipv4_datagrams(buf: &[u8]) -> Result<Vec<Vec<u8>>, L0dError> {
    if buf.is_empty() {
        return Err(L0dError::L0("overlay ipv4 is empty".into()));
    }
    if buf.len() < 20 || (buf[0] >> 4) != 4 {
        return Ok(vec![buf.to_vec()]);
    }
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < buf.len() {
        let rest = &buf[i..];
        if rest.len() < 20 || (rest[0] >> 4) != 4 {
            out.push(rest.to_vec());
            break;
        }
        let tot = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        if tot < 20 || tot > rest.len() {
            out.push(rest.to_vec());
            break;
        }
        out.push(rest[..tot].to_vec());
        i += tot;
    }
    Ok(out)
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

    fn mini_ipv4(id: u8) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2] = 0;
        p[3] = 20;
        p[9] = 6;
        p[19] = id;
        p
    }

    #[test]
    fn round_trip_preserves_ipv4() {
        let pkt = b"\x45\x00fake-ipv4";
        let json = encode("0x1111111111111111111111111111111111111111", 3, pkt).unwrap();
        assert!(json.contains(ENVELOPE_TYPE));
        assert!(!json.contains("signMessage"));
        let (env, rest) = decode(&json).unwrap();
        assert_eq!(env.seq, 3);
        assert_eq!(rest, pkt);
        assert_eq!(split_ipv4_datagrams(&rest).unwrap(), vec![pkt.to_vec()]);
    }

    #[test]
    fn split_concatenated_ipv4_datagrams() {
        let a = mini_ipv4(1);
        let b = mini_ipv4(2);
        let mut raw = a.clone();
        raw.extend_from_slice(&b);
        assert_eq!(split_ipv4_datagrams(&raw).unwrap(), vec![a, b]);
    }
}
