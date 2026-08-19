//! Application-layer duplex on the L0 exclusive occupancy pipe.
//!
//! SI implements **`l0_listen` / `l0_connect`** (or `mining` + `listenKind: "l0"`):
//! idle L0 SSE may still receive user-PGP gossip; the first `l0_connect` occupies
//! the SSE, SI pipes remaining TCP, then rejects later inflows (409).
//! Application JSON `duplex_offer` / `duplex_accept` / `duplex_reject` /
//! `duplex_frame` is **not** an SI command. Offer stays user-PGP Chat gossip
//! so it cannot occupy the exclusive L0 listen. Accept / reject / frames are
//! AES-256-GCM blobs on the occupied pipe. Missing accept keeps P1 gossip.
//! Do not send `listenKind: "duplex"` or SI `duplex_*`.

use crate::error::L0dError;
use crate::l0::aes;
use crate::l0::eip191::EthSecret;
use crate::l0::pgp;
use base64::Engine;
use serde_json::Value;
use tiny_keccak::{Hasher, Keccak};

const SESSION_DOMAIN: &[u8] = b"l0d-duplex-v1|";

pub fn normalize_eoa(raw: &str) -> Result<String, L0dError> {
    let t = raw.trim();
    if t.len() != 42 || !t.starts_with("0x") && !t.starts_with("0X") {
        let lower = t.to_ascii_lowercase();
        if lower.len() == 40 && lower.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(format!("0x{lower}"));
        }
        return Err(L0dError::L0("duplex wallet must be 0x + 40 hex".into()));
    }
    let hex = &t[2..];
    if hex.len() != 40 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(L0dError::L0("duplex wallet must be 0x + 40 hex".into()));
    }
    Ok(format!("0x{}", hex.to_ascii_lowercase()))
}

/// Deterministic session id shared by both ends (64 hex, no 0x).
pub fn session_id(own_eoa: &str, peer_eoa: &str, port: u16) -> Result<String, L0dError> {
    let a = normalize_eoa(own_eoa)?;
    let b = normalize_eoa(peer_eoa)?;
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut hasher = Keccak::v256();
    hasher.update(SESSION_DOMAIN);
    hasher.update(lo.as_bytes());
    hasher.update(b"|");
    hasher.update(hi.as_bytes());
    hasher.update(b"|");
    hasher.update(&port.to_be_bytes());
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    Ok(hex::encode(out))
}

pub fn we_are_initiator(own_eoa: &str, peer_eoa: &str) -> Result<bool, L0dError> {
    Ok(normalize_eoa(own_eoa)? < normalize_eoa(peer_eoa)?)
}

pub fn encode_offer_command(
    initiator_wallet: &str,
    peer_wallet: &str,
    listen_wallet: &str,
    listen_user_pgp: &str,
    session_id: &str,
    key: &[u8; aes::KEY_LEN],
    timestamp: u64,
) -> Result<String, L0dError> {
    let json = serde_json::json!({
        "command": "duplex_offer",
        "walletAddress": normalize_eoa(initiator_wallet)?,
        "peerWallet": normalize_eoa(peer_wallet)?,
        "listenWallet": normalize_eoa(listen_wallet)?,
        "listenUserPgp": listen_user_pgp,
        "sessionId": session_id,
        "algorithm": "aes-256-gcm",
        "Securitykey": aes::key_to_standard_b64(key),
        "timestamp": timestamp,
    });
    serde_json::to_string(&json).map_err(|e| L0dError::L0(e.to_string()))
}

pub fn encode_accept_command(
    responder_wallet: &str,
    listen_wallet: &str,
    listen_user_pgp: &str,
    session_id: &str,
    key: &[u8; aes::KEY_LEN],
    timestamp: u64,
) -> Result<String, L0dError> {
    let json = serde_json::json!({
        "command": "duplex_accept",
        "walletAddress": normalize_eoa(responder_wallet)?,
        "listenWallet": normalize_eoa(listen_wallet)?,
        "listenUserPgp": listen_user_pgp,
        "sessionId": session_id,
        "algorithm": "aes-256-gcm",
        "Securitykey": aes::key_to_standard_b64(key),
        "timestamp": timestamp,
    });
    serde_json::to_string(&json).map_err(|e| L0dError::L0(e.to_string()))
}

pub fn encode_reject_command(
    responder_wallet: &str,
    session_id: &str,
    timestamp: u64,
) -> Result<String, L0dError> {
    let json = serde_json::json!({
        "command": "duplex_reject",
        "walletAddress": normalize_eoa(responder_wallet)?,
        "sessionId": session_id,
        "reason": "unsupported",
        "timestamp": timestamp,
    });
    let text = serde_json::to_string(&json).map_err(|e| L0dError::L0(e.to_string()))?;
    if text.contains("Securitykey") {
        return Err(L0dError::L0(
            "duplex_reject must not carry Securitykey".into(),
        ));
    }
    Ok(text)
}

pub fn encode_frame_json(session_id: &str, payload_b64: &str) -> Result<String, L0dError> {
    let json = serde_json::json!({
        "type": "duplex_frame",
        "sessionId": session_id,
        "payload": payload_b64,
    });
    let text = serde_json::to_string(&json).map_err(|e| L0dError::L0(e.to_string()))?;
    if text.contains("Securitykey") {
        return Err(L0dError::L0("duplex_frame must not carry Securitykey".into()));
    }
    Ok(text)
}

/// AES-GCM wire blob of `duplex_frame` JSON for the occupied L0 SSE.
/// Inner JSON: `{ "type":"duplex_frame","sessionId","payload" }` where `payload`
/// is standard base64 of the `L0D1||IPv4` buffer (JSON cannot carry raw bytes).
/// Outer wire: standard base64 of `nonce(12) || ciphertext || tag(16)`. No OpenPGP.
pub fn seal_frame(
    key: &[u8; aes::KEY_LEN],
    session_id: &str,
    framed: &[u8],
) -> Result<String, L0dError> {
    let payload = Engine::encode(&base64::engine::general_purpose::STANDARD, framed);
    let json = encode_frame_json(session_id, &payload)?;
    aes::seal(key, json.as_bytes())
}

pub fn looks_like_aes_blob(raw: &str) -> bool {
    let t = raw.trim();
    t.len() >= 32
        && !t.starts_with('{')
        && !t.starts_with("-----")
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
}

pub fn parse_l0_occupied(payload: &str) -> bool {
    let v: Value = match serde_json::from_str(payload.trim()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    v.get("type").and_then(Value::as_str) == Some("l0_occupied")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L0PipeEndInfo {
    pub wallet: String,
    pub reason: String,
    pub connector: Option<String>,
}

/// SI teardown notice on the occupied `l0_connect` TCP (one JSON line + `\n`).
pub fn parse_l0_pipe_end(payload: &str) -> Option<L0PipeEndInfo> {
    let v: Value = serde_json::from_str(payload.trim()).ok()?;
    if v.get("type").and_then(Value::as_str) != Some("l0_pipe_end") {
        return None;
    }
    let wallet = v.get("wallet").and_then(Value::as_str)?.to_string();
    let reason = v
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("pipe_end")
        .to_string();
    let connector = v
        .get("connector")
        .and_then(Value::as_str)
        .map(str::to_string);
    Some(L0PipeEndInfo {
        wallet,
        reason,
        connector,
    })
}

/// Optional SSE notice when SI releases an occupied L0 listen before drop.
pub fn parse_l0_listen_released(payload: &str) -> Option<String> {
    let v: Value = serde_json::from_str(payload.trim()).ok()?;
    if v.get("type").and_then(Value::as_str) != Some("l0_listen_released") {
        return None;
    }
    v.get("wallet").and_then(Value::as_str).map(str::to_string)
}

/// Sign application JSON and encrypt to the peer **user PGP** only (Chat gossip).
pub fn wrap_app_for_user_pgp(
    command_json: &str,
    user_pub_armored: &str,
    eth: &EthSecret,
) -> Result<String, L0dError> {
    let parsed: Value = serde_json::from_str(command_json)
        .map_err(|e| L0dError::L0(format!("duplex app JSON: {e}")))?;
    let wallet = parsed
        .get("walletAddress")
        .and_then(Value::as_str)
        .ok_or_else(|| L0dError::L0("duplex app JSON needs walletAddress".into()))?;
    if !crate::l0::eip191::eoa_eq(wallet, eth.address()) {
        return Err(L0dError::L0(
            "routing ETH key does not match duplex walletAddress".into(),
        ));
    }
    let sign_message = eth.personal_sign(command_json.as_bytes())?;
    let envelope = serde_json::json!({
        "message": command_json,
        "signMessage": sign_message,
    });
    let text = serde_json::to_string(&envelope).map_err(|e| L0dError::L0(e.to_string()))?;
    let b64 = Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        text.as_bytes(),
    );
    pgp::encrypt_utf8(&b64, user_pub_armored)
}

pub fn wrap_offer_for_user_pgp(
    command_json: &str,
    user_pub_armored: &str,
    eth: &EthSecret,
) -> Result<String, L0dError> {
    if !command_json.contains("\"duplex_offer\"") {
        return Err(L0dError::L0("wrap_offer_for_user_pgp is only for duplex_offer".into()));
    }
    wrap_app_for_user_pgp(command_json, user_pub_armored, eth)
}

/// Chat-path delivery of `duplex_accept` (control plane). The occupied L0 pipe
/// still carries the same accept as the first AES blob when possible; Chat is
/// the reliable return-path trigger when SSE occupancy data is not ingested.
pub fn wrap_accept_for_user_pgp(
    command_json: &str,
    user_pub_armored: &str,
    eth: &EthSecret,
) -> Result<String, L0dError> {
    if !command_json.contains("\"duplex_accept\"") {
        return Err(L0dError::L0(
            "wrap_accept_for_user_pgp is only for duplex_accept".into(),
        ));
    }
    wrap_app_for_user_pgp(command_json, user_pub_armored, eth)
}

pub fn parse_offer_plain(plain: &str) -> Result<DuplexOffer, L0dError> {
    let v: Value = serde_json::from_str(plain.trim())
        .map_err(|e| L0dError::L0(format!("duplex_offer plaintext: {e}")))?;
    if v.get("command").and_then(Value::as_str) != Some("duplex_offer") {
        return Err(L0dError::L0("not a duplex_offer".into()));
    }
    let session_id = v
        .get("sessionId")
        .and_then(Value::as_str)
        .ok_or_else(|| L0dError::L0("duplex_offer missing sessionId".into()))?
        .to_string();
    let key = aes::key_from_standard_b64(
        v.get("Securitykey")
            .and_then(Value::as_str)
            .ok_or_else(|| L0dError::L0("duplex_offer missing Securitykey".into()))?,
    )?;
    let listen_wallet = normalize_eoa(
        v.get("listenWallet")
            .and_then(Value::as_str)
            .or_else(|| v.get("walletAddress").and_then(Value::as_str))
            .ok_or_else(|| L0dError::L0("duplex_offer missing listenWallet".into()))?,
    )?;
    let from = normalize_eoa(
        v.get("walletAddress")
            .and_then(Value::as_str)
            .ok_or_else(|| L0dError::L0("duplex_offer missing walletAddress".into()))?,
    )?;
    let listen_user_pgp = v
        .get("listenUserPgp")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    Ok(DuplexOffer {
        session_id,
        key,
        listen_wallet,
        listen_user_pgp,
        from,
    })
}

/// Gossip inbound: raw offer JSON, signed `{ message, signMessage }`, or base64 of that wrapper.
pub fn parse_offer_from_inbound_plain(plain: &str) -> Result<DuplexOffer, L0dError> {
    parse_signed_or_raw(plain, |inner| parse_offer_plain(inner))
}

fn parse_signed_or_raw<T>(
    plain: &str,
    parse_inner: impl Fn(&str) -> Result<T, L0dError>,
) -> Result<T, L0dError> {
    let trimmed = plain.trim();
    if trimmed.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
            if let Some(msg) = v.get("message").and_then(Value::as_str) {
                if let Ok(got) = parse_inner(msg) {
                    return Ok(got);
                }
            }
            if let Ok(got) = parse_inner(trimmed) {
                return Ok(got);
            }
        }
    }
    if let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(trimmed) {
        if let Ok(inner) = String::from_utf8(raw) {
            let inner_trim = inner.trim();
            if inner_trim.starts_with('{') {
                return parse_signed_or_raw(inner_trim, parse_inner);
            }
        }
    }
    Err(L0dError::L0("inbound plaintext is not duplex app JSON".into()))
}

#[derive(Clone)]
pub struct DuplexOffer {
    pub session_id: String,
    pub key: [u8; aes::KEY_LEN],
    pub listen_wallet: String,
    pub listen_user_pgp: String,
    pub from: String,
}

#[derive(Clone)]
pub struct DuplexAccept {
    pub session_id: String,
    pub listen_wallet: String,
    pub listen_user_pgp: String,
    pub key: [u8; aes::KEY_LEN],
}

pub fn parse_duplex_frame_json(payload: &str) -> Option<(String, String)> {
    let v: Value = serde_json::from_str(payload.trim()).ok()?;
    if v.get("type").and_then(Value::as_str) != Some("duplex_frame") {
        return None;
    }
    let session_id = v.get("sessionId")?.as_str()?.to_string();
    let b64 = v.get("payload")?.as_str()?.to_string();
    Some((session_id, b64))
}

/// App-layer accept on the initiator's session listen SSE (not an SI event).
pub fn parse_accept(payload: &str) -> Option<DuplexAccept> {
    parse_signed_or_raw(payload, |inner| {
        let v: Value = serde_json::from_str(inner.trim())
            .map_err(|e| L0dError::L0(format!("duplex_accept: {e}")))?;
        if v.get("command").and_then(Value::as_str) != Some("duplex_accept") {
            return Err(L0dError::L0("not duplex_accept".into()));
        }
        let session_id = v
            .get("sessionId")
            .and_then(Value::as_str)
            .ok_or_else(|| L0dError::L0("duplex_accept missing sessionId".into()))?
            .to_string();
        let listen_wallet = normalize_eoa(
            v.get("listenWallet")
                .and_then(Value::as_str)
                .or_else(|| v.get("walletAddress").and_then(Value::as_str))
                .ok_or_else(|| L0dError::L0("duplex_accept missing listenWallet".into()))?,
        )?;
        let key = aes::key_from_standard_b64(
            v.get("Securitykey")
                .and_then(Value::as_str)
                .ok_or_else(|| L0dError::L0("duplex_accept missing Securitykey".into()))?,
        )?;
        let listen_user_pgp = v
            .get("listenUserPgp")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        Ok(DuplexAccept {
            session_id,
            listen_wallet,
            listen_user_pgp,
            key,
        })
    })
    .ok()
}

pub fn parse_reject(payload: &str) -> Option<String> {
    parse_signed_or_raw(payload, |inner| {
        let v: Value = serde_json::from_str(inner.trim())
            .map_err(|e| L0dError::L0(format!("duplex_reject: {e}")))?;
        if v.get("command").and_then(Value::as_str) != Some("duplex_reject") {
            return Err(L0dError::L0("not duplex_reject".into()));
        }
        v.get("sessionId")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| L0dError::L0("duplex_reject missing sessionId".into()))
    })
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l0::eip191::EthSecret;
    use crate::l0::pgp::{decrypt_utf8, generate_test_cert, public_cert_armored};

    fn test_eth() -> EthSecret {
        let mut bytes = [0u8; 32];
        bytes[31] = 7;
        EthSecret::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn session_id_is_order_independent() {
        let a = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let b = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        assert_eq!(session_id(a, b, 8400).unwrap(), session_id(b, a, 8400).unwrap());
        assert_ne!(session_id(a, b, 8400).unwrap(), session_id(a, b, 4200).unwrap());
        assert_eq!(session_id(a, b, 8400).unwrap().len(), 64);
    }

    #[test]
    fn accept_echoes_key_reject_and_frame_do_not() {
        let key = aes::generate_key();
        let cmd = encode_accept_command(
            "0x1111111111111111111111111111111111111111",
            "0x1111111111111111111111111111111111111111",
            "",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &key,
            1,
        )
        .unwrap();
        assert!(cmd.contains("duplex_accept"));
        assert!(cmd.contains("Securitykey"));
        assert!(!cmd.contains("p2p_stream"));
        let reject = encode_reject_command(
            "0x1111111111111111111111111111111111111111",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            2,
        )
        .unwrap();
        assert!(reject.contains("duplex_reject"));
        assert!(!reject.contains("Securitykey"));
        let frame = encode_frame_json(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "YmFzZQ==",
        )
        .unwrap();
        assert!(frame.contains("duplex_frame"));
        assert!(!frame.contains("Securitykey"));
        assert!(!frame.contains("duplex_relay"));
    }

    #[test]
    fn offer_contains_key_and_wrap_is_user_pgp() {
        let eth = test_eth();
        let user = generate_test_cert();
        let user_pub = public_cert_armored(&user).unwrap();
        let key = aes::generate_key();
        let cmd = encode_offer_command(
            eth.address(),
            "0x2222222222222222222222222222222222222222",
            eth.address(),
            &user_pub,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            &key,
            9,
        )
        .unwrap();
        assert!(cmd.contains("Securitykey"));
        let armor = wrap_offer_for_user_pgp(&cmd, &user_pub, &eth).unwrap();
        let b64 = decrypt_utf8(&armor, &user).unwrap();
        let raw = Engine::decode(&base64::engine::general_purpose::STANDARD, b64.trim()).unwrap();
        let wrapper: Value = serde_json::from_slice(&raw).unwrap();
        let message = wrapper["message"].as_str().unwrap();
        let offer = parse_offer_plain(message).unwrap();
        assert_eq!(offer.key, key);
    }

    #[test]
    fn inbound_plain_parses_signed_offer_and_accept() {
        let eth = test_eth();
        let key = aes::generate_key();
        let cmd = encode_offer_command(
            eth.address(),
            "0x2222222222222222222222222222222222222222",
            eth.address(),
            "",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            &key,
            3,
        )
        .unwrap();
        let sign = eth.personal_sign(cmd.as_bytes()).unwrap();
        let wrapper = serde_json::json!({ "message": cmd, "signMessage": sign }).to_string();
        let offer = parse_offer_from_inbound_plain(&wrapper).unwrap();
        assert_eq!(offer.key, key);
        let accept = encode_accept_command(
            eth.address(),
            eth.address(),
            "",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            &key,
            4,
        )
        .unwrap();
        let sign_a = eth.personal_sign(accept.as_bytes()).unwrap();
        let wrap_a = serde_json::json!({ "message": accept, "signMessage": sign_a }).to_string();
        let got = parse_accept(&wrap_a).expect("accept");
        assert_eq!(
            got.session_id,
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        );
        assert_eq!(got.key, key);
        let reject = encode_reject_command(eth.address(), &got.session_id, 5).unwrap();
        let sign_r = eth.personal_sign(reject.as_bytes()).unwrap();
        let wrap_r = serde_json::json!({ "message": reject, "signMessage": sign_r }).to_string();
        assert_eq!(parse_reject(&wrap_r).as_deref(), Some(got.session_id.as_str()));
    }

    #[test]
    fn seal_frame_is_aes_blob_not_pgp() {
        let key = aes::generate_key();
        let blob = seal_frame(&key, "aa", b"L0D1xxxx").unwrap();
        assert!(looks_like_aes_blob(&blob));
        assert!(!blob.contains("BEGIN PGP"));
        let plain = String::from_utf8(aes::open(&key, &blob).unwrap()).unwrap();
        let (sid, payload) = parse_duplex_frame_json(&plain).unwrap();
        assert_eq!(sid, "aa");
        assert!(!payload.contains("Securitykey"));
    }

    #[test]
    fn parse_l0_pipe_end_and_listen_released() {
        let end = parse_l0_pipe_end(
            r#"{"type":"l0_pipe_end","wallet":"0xAbC","connector":"0xdef","reason":"inbound_close"}"#,
        )
        .unwrap();
        assert_eq!(end.wallet, "0xAbC");
        assert_eq!(end.reason, "inbound_close");
        assert_eq!(end.connector.as_deref(), Some("0xdef"));
        assert!(parse_l0_pipe_end(r#"{"type":"l0_occupied"}"#).is_none());
        assert_eq!(
            parse_l0_listen_released(
                r#"{"type":"l0_listen_released","wallet":"0x1111111111111111111111111111111111111111"}"#
            )
            .as_deref(),
            Some("0x1111111111111111111111111111111111111111")
        );
    }
}
