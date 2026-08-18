//! Overlay e2e AES-256-GCM. Mailbox B must never hold this key.
//!
//! Wire: standard base64 of `nonce(12) || ciphertext || tag(16)`.

use crate::error::L0dError;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use rand::RngCore;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

pub fn generate_key() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

pub fn key_from_standard_b64(raw: &str) -> Result<[u8; KEY_LEN], L0dError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .map_err(|e| L0dError::L0(format!("duplex Securitykey base64: {e}")))?;
    if bytes.len() != KEY_LEN {
        return Err(L0dError::L0("duplex Securitykey must be 32 bytes".into()));
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&bytes);
    Ok(key)
}

pub fn key_to_standard_b64(key: &[u8; KEY_LEN]) -> String {
    base64::engine::general_purpose::STANDARD.encode(key)
}

pub fn seal(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<String, L0dError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| L0dError::L0(format!("AES-256-GCM key: {e}")))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| L0dError::L0("AES-256-GCM encrypt failed".into()))?;
    let mut packed = Vec::with_capacity(NONCE_LEN + ct.len());
    packed.extend_from_slice(&nonce_bytes);
    packed.extend_from_slice(&ct);
    Ok(base64::engine::general_purpose::STANDARD.encode(packed))
}

pub fn open(key: &[u8; KEY_LEN], payload_b64: &str) -> Result<Vec<u8>, L0dError> {
    let packed = base64::engine::general_purpose::STANDARD
        .decode(payload_b64.trim())
        .map_err(|e| L0dError::L0(format!("duplex payload base64: {e}")))?;
    if packed.len() <= NONCE_LEN {
        return Err(L0dError::L0("duplex payload shorter than nonce".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| L0dError::L0(format!("AES-256-GCM key: {e}")))?;
    let nonce = Nonce::from_slice(&packed[..NONCE_LEN]);
    cipher
        .decrypt(nonce, &packed[NONCE_LEN..])
        .map_err(|_| L0dError::L0("AES-256-GCM decrypt failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = generate_key();
        let pt = b"L0D1-overlay-ipv4";
        let b64 = seal(&key, pt).unwrap();
        assert!(!b64.contains("L0D1"));
        assert_eq!(open(&key, &b64).unwrap(), pt);
    }

    #[test]
    fn wrong_key_fails() {
        let a = generate_key();
        let mut b = a;
        b[0] ^= 1;
        let b64 = seal(&a, b"pkt").unwrap();
        assert!(open(&b, &b64).is_err());
    }

    #[test]
    fn key_b64_is_32_bytes() {
        let key = generate_key();
        let s = key_to_standard_b64(&key);
        assert_eq!(key_from_standard_b64(&s).unwrap(), key);
    }
}
