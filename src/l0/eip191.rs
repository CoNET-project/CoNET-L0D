//! EIP-191 `personal_sign` for SI `checkSign`.
//!
//! The ETH key is **not** `routing_key_file` (OpenPGP). Do not log the key.

use crate::error::L0dError;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use std::fmt;
use std::path::Path;
use tiny_keccak::{Hasher, Keccak};

#[derive(Clone)]
pub struct EthSecret {
    signing_key: SigningKey,
    address: String,
}

impl fmt::Debug for EthSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EthSecret")
            .field("address", &self.address)
            .field("key", &"redacted")
            .finish()
    }
}

impl EthSecret {
    pub fn from_bytes(secret: &[u8; 32]) -> Result<Self, L0dError> {
        let signing_key = SigningKey::from_bytes(secret.into())
            .map_err(|e| L0dError::L0(format!("secp256k1 key: {e}")))?;
        let address = address_from_verifying_key(signing_key.verifying_key())?;
        Ok(Self {
            signing_key,
            address,
        })
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    /// Return the raw key only to in-process protocol adapters (for example
    /// the route-registration payload). Callers must never log or persist it.
    pub(crate) fn secret_bytes(&self) -> [u8; 32] {
        let bytes = self.signing_key.to_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes.as_slice());
        out
    }

    /// EIP-191 `personal_sign`. Returns `0x` + 65-byte hex (`r || s || v`, `v = 27/28`).
    pub fn personal_sign(&self, message: &[u8]) -> Result<String, L0dError> {
        let digest = eip191_hash(message);
        let (sig, recid) = self
            .signing_key
            .sign_prehash_recoverable(&digest)
            .map_err(|e| L0dError::L0(format!("EIP-191 sign: {e}")))?;
        let mut packed = [0u8; 65];
        packed[..64].copy_from_slice(&sig.to_bytes());
        packed[64] = u8::from(recid) + 27;
        Ok(format!("0x{}", hex::encode(packed)))
    }
}

pub fn load_eth_secret(path: &Path) -> Result<EthSecret, L0dError> {
    let text = std::fs::read_to_string(path)?;
    parse_eth_secret(&text)
}

pub fn parse_eth_secret(raw: &str) -> Result<EthSecret, L0dError> {
    if raw.contains("BEGIN PGP") {
        return Err(L0dError::L0(
            "routing_eth_key_file must be a hex secp256k1 key, not an OpenPGP cert".into(),
        ));
    }
    let hex = raw.trim().trim_start_matches("0x").trim_start_matches("0X");
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(L0dError::L0(
            "routing_eth_key_file must be 32-byte hex (optional 0x prefix)".into(),
        ));
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(hex, &mut bytes)
        .map_err(|e| L0dError::L0(format!("routing_eth_key_file hex: {e}")))?;
    EthSecret::from_bytes(&bytes)
}

pub fn eoa_eq(a: &str, b: &str) -> bool {
    normalize_eoa(a).ok().as_deref() == normalize_eoa(b).ok().as_deref()
}

pub fn normalize_eoa(raw: &str) -> Result<String, L0dError> {
    let hex = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .ok_or_else(|| L0dError::L0("ETH address must be 0x + 40 hex".into()))?;
    if hex.len() != 40 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(L0dError::L0("ETH address must be 0x + 40 hex".into()));
    }
    Ok(format!("0x{}", hex.to_ascii_lowercase()))
}

/// Recover the signer of an EIP-191 `personal_sign` (SI `verifyMessage` path).
#[allow(dead_code)]
pub fn recover_personal_sign(message: &[u8], sig_hex: &str) -> Result<String, L0dError> {
    let raw = parse_signature(sig_hex)?;
    let sig = Signature::from_slice(&raw[..64])
        .map_err(|e| L0dError::L0(format!("EIP-191 signature: {e}")))?;
    let v = raw[64];
    let recid_byte = if v >= 27 { v - 27 } else { v };
    let recid = RecoveryId::from_byte(recid_byte)
        .ok_or_else(|| L0dError::L0("EIP-191 recovery id is invalid".into()))?;
    let digest = eip191_hash(message);
    let vk = VerifyingKey::recover_from_prehash(&digest, &sig, recid)
        .map_err(|e| L0dError::L0(format!("EIP-191 recover: {e}")))?;
    address_from_verifying_key(&vk)
}

#[allow(dead_code)]
fn parse_signature(sig_hex: &str) -> Result<[u8; 65], L0dError> {
    let hex = sig_hex
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    if hex.len() != 130 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(L0dError::L0("EIP-191 signature must be 65-byte hex".into()));
    }
    let mut raw = [0u8; 65];
    hex::decode_to_slice(hex, &mut raw)
        .map_err(|e| L0dError::L0(format!("EIP-191 signature hex: {e}")))?;
    Ok(raw)
}

fn address_from_verifying_key(vk: &VerifyingKey) -> Result<String, L0dError> {
    let point = vk.to_encoded_point(false);
    let encoded = point.as_bytes();
    if encoded.len() != 65 || encoded[0] != 0x04 {
        return Err(L0dError::L0(
            "secp256k1 public key is not uncompressed".into(),
        ));
    }
    let hash = keccak256(&encoded[1..]);
    Ok(format!("0x{}", hex::encode(&hash[12..])))
}

fn eip191_hash(message: &[u8]) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut hasher = Keccak::v256();
    hasher.update(prefix.as_bytes());
    hasher.update(message);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// secp256k1 private key = 1. Address is public test material, not a lab secret.
    fn key_one() -> EthSecret {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        EthSecret::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn address_of_key_one() {
        assert_eq!(
            key_one().address(),
            "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
    }

    #[test]
    fn personal_sign_recovers_signer() {
        let secret = key_one();
        let message = br#"{"command":"mining","listenKind":"chat"}"#;
        let sig = secret.personal_sign(message).unwrap();
        assert_eq!(
            recover_personal_sign(message, &sig).unwrap(),
            secret.address()
        );
    }

    #[test]
    fn refuse_openpgp_as_eth_key() {
        let err = parse_eth_secret("-----BEGIN PGP PRIVATE KEY BLOCK-----\n").unwrap_err();
        assert!(err.to_string().contains("not an OpenPGP"));
    }
}
