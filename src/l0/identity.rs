//! Ephemeral per-line identities.
//!
//! A temporary identity is deliberately process-memory-only.  It is the
//! routing subject of one duplex line; the configured main wallet remains the
//! billing/signing identity and is never reused as the line identity.
//! Temporary wallets and user PGP are not registered in AddressPGP. The
//! mailbox SI that accepted `l0_listen` is announced in offer/accept.

use crate::error::L0dError;
use crate::l0::{aes, eip191::EthSecret, pgp};
use rand::{rngs::OsRng, RngCore};
use sequoia_openpgp::cert::prelude::*;

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
