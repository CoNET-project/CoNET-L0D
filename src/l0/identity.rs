//! Ephemeral per-line identities.
//!
//! A temporary identity is deliberately process-memory-only.  It is the
//! routing subject of one duplex line; the configured main wallet remains the
//! billing/signing identity and is never reused as the line identity.

use crate::error::L0dError;
use crate::l0::{aes, eip191::EthSecret, pgp};
use base64::Engine;
use rand::{rngs::OsRng, RngCore};
use sequoia_openpgp::cert::prelude::*;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct TemporaryIdentity {
    pub wallet: EthSecret,
    pub user_cert: Cert,
    pub user_public_armor: String,
    pub user_secret_armor: String,
    pub user_key_id: String,
    pub session_id: String,
    pub aes_key: [u8; aes::KEY_LEN],
}

impl TemporaryIdentity {
    pub fn generate() -> Result<Self, L0dError> {
        let mut eth_bytes = [0u8; 32];
        let wallet = loop {
            OsRng.fill_bytes(&mut eth_bytes);
            if let Ok(wallet) = EthSecret::from_bytes(&eth_bytes) {
                break wallet;
            }
        };

        let cert = CertBuilder::new()
            .add_userid(wallet.address())
            .add_transport_encryption_subkey()
            .generate()
            .map_err(|e| L0dError::L0(format!("temporary OpenPGP generation: {e}")))?
            .0;
        let user_public_armor = pgp::public_cert_armored(&cert)?;
        let user_secret_armor = pgp::secret_cert_armored(&cert)?;
        let user_key_id = pgp::transport_key_id(&cert)?;

        let mut session_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut session_bytes);
        let mut aes_key = [0u8; aes::KEY_LEN];
        OsRng.fill_bytes(&mut aes_key);

        Ok(Self {
            wallet,
            user_cert: cert,
            user_public_armor,
            user_secret_armor,
            user_key_id,
            session_id: hex::encode(session_bytes),
            aes_key,
        })
    }

    pub fn wallet_address(&self) -> &str {
        self.wallet.address()
    }

    /// Register this ephemeral route in AddressPGP through the public API.
    ///
    /// The private OpenPGP cert is encrypted exactly as the existing
    /// `regiestChatRoute` client contract expects: AES-256-GCM with a
    /// SHA-256-derived key from the temporary Ethereum private key.
    pub async fn register_route(
        &self,
        register_url: &str,
        route_key_id: &str,
    ) -> Result<(), L0dError> {
        let mut key = [0u8; aes::KEY_LEN];
        let digest = Sha256::digest(self.wallet.secret_bytes());
        key.copy_from_slice(&digest);
        let encrypted_private = aes::seal(&key, self.user_secret_armor.as_bytes())?;
        let body = serde_json::json!({
            "wallet": self.wallet_address(),
            "keyID": self.user_key_id,
            "publicKeyArmored": base64::engine::general_purpose::STANDARD
                .encode(self.user_public_armor.as_bytes()),
            "encrypKeyArmored": encrypted_private,
            "routeKeyID": route_key_id.to_uppercase(),
        });
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(12))
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| L0dError::L0(format!("route registration client: {e}")))?;
        let response = client
            .post(register_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| L0dError::L0(format!("route registration failed: {e}")))?;
        let status = response.status();
        let payload: serde_json::Value = response.json().await.unwrap_or_default();
        if !status.is_success() || payload.get("ok").and_then(|v| v.as_bool()) == Some(false) {
            let error = payload
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown registration error");
            return Err(L0dError::L0(format!(
                "route registration HTTP {}: {}",
                status.as_u16(),
                error
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_generated_identity_is_unique_and_routable() {
        let first = TemporaryIdentity::generate().unwrap();
        let second = TemporaryIdentity::generate().unwrap();
        assert_ne!(first.wallet_address(), second.wallet_address());
        assert_ne!(first.session_id, second.session_id);
        assert_ne!(first.user_key_id, second.user_key_id);
        assert!(first.user_public_armor.contains("BEGIN PGP PUBLIC KEY"));
        assert!(first.user_secret_armor.contains("BEGIN PGP PRIVATE KEY"));
    }
}
