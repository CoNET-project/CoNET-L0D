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

#[allow(dead_code)]
pub fn search_key_selector() -> [u8; 4] {
    let mut hasher = Keccak::v256();
    hasher.update(b"searchKey(address)");
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    [out[0], out[1], out[2], out[3]]
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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
}
