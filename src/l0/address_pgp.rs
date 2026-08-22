//! AddressPGP `searchKey(address)` encoder / decoder.
//!
//! Live RPC is optional P1 work. This module does not log armored keys.

use crate::error::L0dError;
use tiny_keccak::{Hasher, Keccak};

pub const ADDRESS_PGP: &str = "0x684b0ac760cEE9c9b85de36d69746420648Cf9e2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchKey {
    pub user_pgp_key_id: String,
    pub user_public_key_armored: String,
    pub route_pgp_key_id: String,
    pub route_public_key_armored: String,
    pub route_online: bool,
}

pub fn search_key_selector() -> [u8; 4] {
    let mut hasher = Keccak::v256();
    hasher.update(b"searchKey(address)");
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    [out[0], out[1], out[2], out[3]]
}

pub fn encode_search_key_call(eoa: &str) -> Result<String, L0dError> {
    let hex = eoa
        .strip_prefix("0x")
        .or_else(|| eoa.strip_prefix("0X"))
        .ok_or_else(|| L0dError::L0("searchKey EOA must be 0x + 40 hex".into()))?;
    if hex.len() != 40 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(L0dError::L0("searchKey EOA must be 0x + 40 hex".into()));
    }
    let addr = hex::decode(hex).map_err(|e| L0dError::L0(e.to_string()))?;
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&search_key_selector());
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(&addr);
    Ok(format!("0x{}", hex::encode(data)))
}

pub fn decode_search_key_result(hex_data: &str) -> Result<SearchKey, L0dError> {
    let raw = hex_data.trim().trim_start_matches("0x");
    let data = hex::decode(raw).map_err(|e| L0dError::L0(format!("searchKey hex: {e}")))?;
    if data.len() < 160 {
        return Err(L0dError::L0("searchKey ABI result is too short".into()));
    }
    let off0 = read_offset(&data, 0)?;
    let off1 = read_offset(&data, 32)?;
    let off2 = read_offset(&data, 64)?;
    let off3 = read_offset(&data, 96)?;
    let route_online = data[127] != 0;
    Ok(SearchKey {
        user_pgp_key_id: read_string(&data, off0)?,
        user_public_key_armored: read_string(&data, off1)?,
        route_pgp_key_id: read_string(&data, off2)?,
        route_public_key_armored: read_string(&data, off3)?,
        route_online,
    })
}

fn read_offset(data: &[u8], at: usize) -> Result<usize, L0dError> {
    if at + 32 > data.len() {
        return Err(L0dError::L0("searchKey offset word is truncated".into()));
    }
    let mut word = [0u8; 8];
    word.copy_from_slice(&data[at + 24..at + 32]);
    Ok(u64::from_be_bytes(word) as usize)
}

fn read_string(data: &[u8], offset: usize) -> Result<String, L0dError> {
    if offset + 32 > data.len() {
        return Err(L0dError::L0("searchKey string header is truncated".into()));
    }
    let mut word = [0u8; 8];
    word.copy_from_slice(&data[offset + 24..offset + 32]);
    let len = u64::from_be_bytes(word) as usize;
    let start = offset + 32;
    let end = start
        .checked_add(len)
        .ok_or_else(|| L0dError::L0("searchKey string length overflow".into()))?;
    if end > data.len() {
        return Err(L0dError::L0("searchKey string payload is truncated".into()));
    }
    String::from_utf8(data[start..end].to_vec())
        .map_err(|_| L0dError::L0("searchKey string is not UTF-8".into()))
}

/// Compare AddressPGP `routeKeyID` values (ignore `0x` and case).
pub fn route_key_id_eq(on_chain: &str, expected: &str) -> bool {
    let a = on_chain
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_ascii_uppercase();
    let b = expected
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_ascii_uppercase();
    !a.is_empty() && !b.is_empty() && a == b
}

/// Live `searchKey(eoa)` on `l0.rpc`. Does not log armored keys.
pub async fn search_key(rpc: &str, eoa: &str) -> Result<SearchKey, L0dError> {
    let call = encode_search_key_call(eoa)?;
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [{"to": ADDRESS_PGP, "data": call}, "latest"]
    });
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(8))
        .timeout(std::time::Duration::from_secs(12))
        .build()
        .map_err(|e| L0dError::L0(format!("AddressPGP RPC client: {e}")))?;
    let response = client
        .post(rpc)
        .json(&body)
        .send()
        .await
        .map_err(|e| L0dError::L0(format!("AddressPGP RPC: {e}")))?;
    let value: serde_json::Value = response
        .json()
        .await
        .map_err(|e| L0dError::L0(format!("AddressPGP RPC JSON: {e}")))?;
    if let Some(err) = value.get("error") {
        return Err(L0dError::L0(format!("AddressPGP RPC error: {err}")));
    }
    let result = value
        .get("result")
        .and_then(|v| v.as_str())
        .ok_or_else(|| L0dError::L0("AddressPGP searchKey returned no result".into()))?;
    decode_search_key_result(result)
}

/// `regiestChatRoute` HTTP 200 is not enough: SI `isMyRoute` reads chain.
pub async fn wait_until_route_visible(
    rpc: &str,
    eoa: &str,
    expected_route_key_id: &str,
) -> Result<(), L0dError> {
    const ATTEMPTS: u32 = 24;
    const SLEEP_SECS: u64 = 2;
    for attempt in 1..=ATTEMPTS {
        match search_key(rpc, eoa).await {
            Ok(key) if route_key_id_eq(&key.route_pgp_key_id, expected_route_key_id) => {
                tracing::info!(
                    eoa,
                    route_key_id = %expected_route_key_id,
                    attempt,
                    "AddressPGP searchKey route is visible"
                );
                return Ok(());
            }
            Ok(key) => {
                tracing::info!(
                    eoa,
                    attempt,
                    on_chain_route = %key.route_pgp_key_id,
                    expected_route = %expected_route_key_id,
                    "AddressPGP searchKey not yet matching; waiting"
                );
            }
            Err(err) => {
                tracing::warn!(
                    eoa,
                    attempt,
                    error = %err,
                    "AddressPGP searchKey poll failed"
                );
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(SLEEP_SECS)).await;
    }
    Err(L0dError::L0(format!(
        "AddressPGP searchKey did not show route {expected_route_key_id} for {eoa} after {ATTEMPTS} polls"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word_u64(n: u64) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&n.to_be_bytes());
        w
    }

    fn encode_string(s: &str) -> Vec<u8> {
        let bytes = s.as_bytes();
        let mut out = word_u64(bytes.len() as u64).to_vec();
        out.extend_from_slice(bytes);
        let pad = (32 - (bytes.len() % 32)) % 32;
        out.extend(std::iter::repeat(0u8).take(pad));
        out
    }

    #[test]
    fn encode_call_is_36_bytes() {
        let call = encode_search_key_call("0x1111111111111111111111111111111111111111").unwrap();
        let raw = hex::decode(call.trim_start_matches("0x")).unwrap();
        assert_eq!(raw.len(), 36);
        assert_eq!(&raw[0..4], &search_key_selector());
        assert_eq!(&raw[16..], &hex::decode("11".repeat(20)).unwrap());
    }

    #[test]
    fn decode_fixture() {
        let s0 = encode_string("user-id");
        let s1 = encode_string("USER-ARMOR");
        let s2 = encode_string("route-id");
        let s3 = encode_string("ROUTE-ARMOR");
        let mut data = Vec::new();
        let mut cursor = 160usize;
        data.extend_from_slice(&word_u64(cursor as u64));
        cursor += s0.len();
        data.extend_from_slice(&word_u64(cursor as u64));
        cursor += s1.len();
        data.extend_from_slice(&word_u64(cursor as u64));
        cursor += s2.len();
        data.extend_from_slice(&word_u64(cursor as u64));
        let mut flag = [0u8; 32];
        flag[31] = 1;
        data.extend_from_slice(&flag);
        data.extend_from_slice(&s0);
        data.extend_from_slice(&s1);
        data.extend_from_slice(&s2);
        data.extend_from_slice(&s3);
        let parsed = decode_search_key_result(&hex::encode(data)).unwrap();
        assert_eq!(parsed.user_pgp_key_id, "user-id");
        assert_eq!(parsed.route_pgp_key_id, "route-id");
        assert!(parsed.route_online);
        assert_eq!(parsed.user_public_key_armored, "USER-ARMOR");
    }

    #[test]
    fn route_key_id_eq_ignores_prefix_and_case() {
        assert!(route_key_id_eq("0ad95da2e8bb7a0d", "0AD95DA2E8BB7A0D"));
        assert!(route_key_id_eq("0x0AD95DA2E8BB7A0D", "0ad95da2e8bb7a0d"));
        assert!(!route_key_id_eq("", "0AD95DA2E8BB7A0D"));
        assert!(!route_key_id_eq("0AD95DA2E8BB7A0D", "9977E9A45187DD80"));
    }
}
