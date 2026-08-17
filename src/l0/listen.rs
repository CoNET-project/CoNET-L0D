//! Inbound overlay: decrypt user-PGP armor and recover raw IPv4 for TUN write-back.
#![allow(dead_code)]
//!
//! Mailbox SSE would deliver armor encrypted to **this host's user PGP**.
//! This module does not open a live SI listen (no EIP-191, no `Securitykey`
//! in a B-decryptable command, no `p2p_stream_*`).

use crate::error::L0dError;
use crate::l0::{envelope, pgp};
use sequoia_openpgp::Cert;
use serde_json::Value;

/// `command: mining` + `listenKind: chat` on a dedicated routing EOA.
/// Do not put `Securitykey` in this object (B can decrypt listen).
pub fn encode_listen_command(wallet: &str, timestamp: u64) -> Result<String, L0dError> {
    let json = serde_json::json!({
        "command": "mining",
        "listenKind": "chat",
        "walletAddress": wallet.to_ascii_lowercase(),
        "timestamp": timestamp,
    });
    let text = serde_json::to_string(&json).map_err(|e| L0dError::L0(e.to_string()))?;
    if text.contains("Securitykey") || text.contains("signMessage") {
        return Err(L0dError::L0(
            "listen command must not carry Securitykey or signMessage".into(),
        ));
    }
    Ok(text)
}

/// Encrypt the listen command to mailbox **B route PGP**. HTTP body is still `{ data }`.
pub fn wrap_listen_for_post(command_json: &str, route_pub_armored: &str) -> Result<String, L0dError> {
    if command_json.contains("Securitykey") {
        return Err(L0dError::L0(
            "refusing to encrypt a listen command that contains Securitykey".into(),
        ));
    }
    pgp::encrypt_utf8(command_json, route_pub_armored)
}

pub fn looks_like_ipv4(pkt: &[u8]) -> bool {
    pkt.len() >= 20 && (pkt[0] >> 4) == 4
}

/// Decrypt user-PGP armor → overlay envelope → raw IPv4.
pub fn inbound_ipv4_from_user_armor(armor: &str, secret: &Cert) -> Result<Vec<u8>, L0dError> {
    let plain = pgp::decrypt_utf8(armor, secret)?;
    let trimmed = plain.trim_start();
    if trimmed.starts_with('{') {
        let v: Value = serde_json::from_str(trimmed)
            .map_err(|e| L0dError::L0(format!("inbound JSON: {e}")))?;
        if v.get("NoPush").is_some() {
            return Err(L0dError::L0(
                "inbound decrypt produced mailbox work; expected user-PGP envelope".into(),
            ));
        }
    }
    let (_env, ipv4) = envelope::decode(&plain)?;
    if !looks_like_ipv4(&ipv4) {
        return Err(L0dError::L0("inbound payload is not IPv4".into()));
    }
    Ok(ipv4)
}

/// Collect OpenPGP message armor from SSE `data:` lines. Do not log armor.
pub fn extract_pgp_armors_from_sse(chunk: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_armor = false;
    for raw_line in chunk.lines() {
        let line = raw_line
            .strip_prefix("data:")
            .map(str::trim_start)
            .unwrap_or(raw_line);
        if line.contains("-----BEGIN PGP MESSAGE-----") {
            in_armor = true;
            current.clear();
            current.push_str(line);
            current.push('\n');
            continue;
        }
        if in_armor {
            current.push_str(line);
            current.push('\n');
            if line.contains("-----END PGP MESSAGE-----") {
                if pgp::is_pgp_message_armor(&current) {
                    out.push(current.clone());
                }
                current.clear();
                in_armor = false;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l0::pgp::{encrypt_utf8, generate_test_cert, mailbox_work_json, public_cert_armored};

    #[test]
    fn listen_command_is_chat_kind_without_secrets() {
        let cmd = encode_listen_command("0x1111111111111111111111111111111111111111", 1_710_000_000)
            .unwrap();
        assert!(cmd.contains("\"mining\""));
        assert!(cmd.contains("\"chat\""));
        assert!(!cmd.contains("Securitykey"));
        assert!(!cmd.contains("signMessage"));
        assert!(!cmd.contains("l1p2p"));
    }

    #[test]
    fn listen_encrypts_to_route_only() {
        let route = generate_test_cert();
        let route_pub = public_cert_armored(&route).unwrap();
        let cmd = encode_listen_command("0x2222222222222222222222222222222222222222", 9).unwrap();
        let armor = wrap_listen_for_post(&cmd, &route_pub).unwrap();
        assert!(pgp::is_pgp_message_armor(&armor));
        assert_eq!(pgp::decrypt_utf8(&armor, &route).unwrap(), cmd);
    }

    #[test]
    fn inbound_round_trip_ipv4() {
        let user = generate_test_cert();
        let user_pub = public_cert_armored(&user).unwrap();
        let pkt = b"\x45\x00fake-ipv4-header!!";
        let json = envelope::encode("0x1111111111111111111111111111111111111111", 4, pkt).unwrap();
        let armor = encrypt_utf8(&json, &user_pub).unwrap();
        let got = inbound_ipv4_from_user_armor(&armor, &user).unwrap();
        assert_eq!(got, pkt);
    }

    #[test]
    fn refuse_mailbox_work_as_inbound() {
        let user = generate_test_cert();
        let user_pub = public_cert_armored(&user).unwrap();
        let inner = encrypt_utf8("inner", &user_pub).unwrap();
        let work = mailbox_work_json(&inner).unwrap();
        let armor = encrypt_utf8(&work, &user_pub).unwrap();
        let err = inbound_ipv4_from_user_armor(&armor, &user).unwrap_err();
        assert!(err.to_string().contains("mailbox work"));
    }

    #[test]
    fn sse_extracts_armor() {
        let chunk = "event: message\ndata: -----BEGIN PGP MESSAGE-----\ndata: \ndata: xxxx\ndata: -----END PGP MESSAGE-----\n\n";
        let found = extract_pgp_armors_from_sse(chunk);
        assert_eq!(found.len(), 1);
        assert!(pgp::is_pgp_message_armor(&found[0]));
    }
}
