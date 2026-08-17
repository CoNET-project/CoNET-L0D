//! OpenPGP helpers. Do not log armor, keys, or plaintext.

use crate::error::L0dError;
use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::stream::{Armorer, Encryptor2, LiteralWriter, Message};
#[cfg(test)]
use sequoia_openpgp::serialize::SerializeInto;
use std::io::Write;

pub fn is_pgp_message_armor(raw: &str) -> bool {
    raw.contains("-----BEGIN PGP MESSAGE-----")
}

pub fn refuse_plaintext_data(raw: &str) -> Result<(), L0dError> {
    let trimmed = raw.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return Err(L0dError::L0(
            "refusing to POST plaintext JSON as data".into(),
        ));
    }
    if !is_pgp_message_armor(raw) {
        return Err(L0dError::L0("data must be OpenPGP message armor".into()));
    }
    Ok(())
}

pub fn mailbox_work_json(inner_armor: &str) -> Result<String, L0dError> {
    refuse_plaintext_data(inner_armor)?;
    serde_json::to_string(&serde_json::json!({
        "data": inner_armor,
        "NoPush": true
    }))
    .map_err(|e| L0dError::L0(e.to_string()))
}

/// Encrypt UTF-8 to `recipient` (armored public cert). Output is message armor.
pub fn encrypt_utf8(plaintext: &str, recipient_armored: &str) -> Result<String, L0dError> {
    let cert = Cert::from_bytes(recipient_armored.as_bytes())
        .map_err(|e| L0dError::L0(format!("recipient OpenPGP cert: {e}")))?;
    let policy = StandardPolicy::new();
    let recipients: Vec<_> = cert
        .keys()
        .with_policy(&policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .collect();
    if recipients.is_empty() {
        return Err(L0dError::L0(
            "recipient cert has no usable encryption key".into(),
        ));
    }

    let mut sink = Vec::new();
    {
        let message = Message::new(&mut sink);
        let message = Armorer::new(message)
            .build()
            .map_err(|e| L0dError::L0(format!("OpenPGP armor: {e}")))?;
        let message = Encryptor2::for_recipients(message, recipients)
            .build()
            .map_err(|e| L0dError::L0(format!("OpenPGP encrypt: {e}")))?;
        let mut literal = LiteralWriter::new(message)
            .build()
            .map_err(|e| L0dError::L0(format!("OpenPGP literal: {e}")))?;
        literal
            .write_all(plaintext.as_bytes())
            .map_err(|e| L0dError::L0(format!("OpenPGP write: {e}")))?;
        literal
            .finalize()
            .map_err(|e| L0dError::L0(format!("OpenPGP finalize: {e}")))?;
    }
    let armor = String::from_utf8(sink)
        .map_err(|_| L0dError::L0("OpenPGP armor is not UTF-8".into()))?;
    refuse_plaintext_data(&armor)?;
    Ok(armor)
}

/// User-PGP inner armor, then mailbox-work wrap encrypted to B route PGP.
pub fn wrap_overlay_for_post(
    envelope_json: &str,
    user_pub_armored: &str,
    route_pub_armored: &str,
) -> Result<String, L0dError> {
    let inner = encrypt_utf8(envelope_json, user_pub_armored)?;
    let work = mailbox_work_json(&inner)?;
    encrypt_utf8(&work, route_pub_armored)
}

#[cfg(test)]
pub fn public_cert_armored(cert: &Cert) -> Result<String, L0dError> {
    String::from_utf8(
        cert.armored()
            .to_vec()
            .map_err(|e| L0dError::L0(format!("serialize cert: {e}")))?,
    )
    .map_err(|_| L0dError::L0("serialized cert is not UTF-8".into()))
}

#[cfg(test)]
pub fn generate_test_cert() -> Cert {
    CertBuilder::new()
        .add_userid("conet-l0d-test")
        .add_transport_encryption_subkey()
        .generate()
        .expect("generate test OpenPGP cert")
        .0
}

#[cfg(test)]
pub fn decrypt_utf8(armor: &str, secret: &Cert) -> Result<String, L0dError> {
    use sequoia_openpgp::crypto::SessionKey;
    use sequoia_openpgp::packet::{PKESK, SKESK};
    use sequoia_openpgp::parse::stream::{
        DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper,
    };
    use sequoia_openpgp::types::SymmetricAlgorithm;
    use sequoia_openpgp::KeyHandle;
    use std::io::Read;

    struct Helper {
        cert: Cert,
    }

    impl VerificationHelper for Helper {
        fn get_certs(
            &mut self,
            _ids: &[KeyHandle],
        ) -> sequoia_openpgp::Result<Vec<Cert>> {
            Ok(Vec::new())
        }

        fn check(&mut self, _structure: MessageStructure) -> sequoia_openpgp::Result<()> {
            Ok(())
        }
    }

    impl DecryptionHelper for Helper {
        fn decrypt<D>(
            &mut self,
            pkesks: &[PKESK],
            _skesks: &[SKESK],
            sym_algo: Option<SymmetricAlgorithm>,
            mut decrypt: D,
        ) -> sequoia_openpgp::Result<Option<sequoia_openpgp::Fingerprint>>
        where
            D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
        {
            let policy = StandardPolicy::new();
            for ka in self
                .cert
                .keys()
                .secret()
                .with_policy(&policy, None)
                .supported()
                .for_transport_encryption()
            {
                let mut pair = match ka.key().clone().into_keypair() {
                    Ok(pair) => pair,
                    Err(_) => continue,
                };
                for pkesk in pkesks {
                    if pkesk
                        .decrypt(&mut pair, sym_algo)
                        .map(|(algo, session)| decrypt(algo, &session))
                        .unwrap_or(false)
                    {
                        return Ok(Some(ka.fingerprint()));
                    }
                }
            }
            Err(anyhow::anyhow!("no test key decrypted the message"))
        }
    }

    let policy = StandardPolicy::new();
    let helper = Helper {
        cert: secret.clone(),
    };
    let mut decryptor = DecryptorBuilder::from_bytes(armor.as_bytes())
        .map_err(|e| L0dError::L0(format!("decrypt parse: {e}")))?
        .with_policy(&policy, None, helper)
        .map_err(|e| L0dError::L0(format!("decrypt policy: {e}")))?;
    let mut out = Vec::new();
    decryptor
        .read_to_end(&mut out)
        .map_err(|e| L0dError::L0(format!("decrypt read: {e}")))?;
    String::from_utf8(out).map_err(|_| L0dError::L0("decrypted payload is not UTF-8".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuse_json_as_http_data() {
        assert!(refuse_plaintext_data(r#"{"type":"conet_l0d_overlay_v1"}"#).is_err());
        assert!(refuse_plaintext_data("not-armor").is_err());
    }

    #[test]
    fn encrypt_round_trip() {
        let cert = generate_test_cert();
        let pub_armor = public_cert_armored(&cert).unwrap();
        let armor = encrypt_utf8("hello-overlay", &pub_armor).unwrap();
        assert!(is_pgp_message_armor(&armor));
        assert!(!armor.contains("hello-overlay"));
        assert_eq!(decrypt_utf8(&armor, &cert).unwrap(), "hello-overlay");
    }

    #[test]
    fn mailbox_work_is_not_http_body() {
        let cert = generate_test_cert();
        let pub_armor = public_cert_armored(&cert).unwrap();
        let inner = encrypt_utf8("inner", &pub_armor).unwrap();
        let work = mailbox_work_json(&inner).unwrap();
        assert!(work.contains("NoPush"));
        assert!(refuse_plaintext_data(&work).is_err());
    }

    #[test]
    fn wrap_then_unwrap() {
        let user = generate_test_cert();
        let route = generate_test_cert();
        let user_pub = public_cert_armored(&user).unwrap();
        let route_pub = public_cert_armored(&route).unwrap();
        let outer = wrap_overlay_for_post(r#"{"type":"conet_l0d_overlay_v1"}"#, &user_pub, &route_pub)
            .unwrap();
        let work: serde_json::Value =
            serde_json::from_str(&decrypt_utf8(&outer, &route).unwrap()).unwrap();
        assert_eq!(work["NoPush"], true);
        let inner = work["data"].as_str().expect("inner armor");
        assert_eq!(decrypt_utf8(inner, &user).unwrap(), r#"{"type":"conet_l0d_overlay_v1"}"#);
    }
}
