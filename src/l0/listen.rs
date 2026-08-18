//! Inbound overlay: decrypt user-PGP armor and recover raw IPv4 for TUN write-back.
//!
//! In-crate listen worker: EIP-191-sign `mining` + `listenKind: chat`, wrap
//! `base64({ message, signMessage })` to **this host's** mailbox B route PGP,
//! `POST { "data" }` to entry **C**, read the listen stream, extract user-PGP armor.
//!
//! Live SI mailbox `forWardPGPMessageToClient` writes raw JSON
//! `{"data":"<armor>"}\r\n\r\n` (no SSE `data:` prefix). Handshake / mining
//! heartbeats use SSE `data: {status,epoch}`. Ingest matches Chat
//! `handleInbound`: JSON `{ data }` armor, SSE-wrapped JSON, or classic SSE
//! armor lines. No `Securitykey`. Tests use wiremock only. Do not POST
//! production SI from tests.
#![allow(dead_code)]

use crate::error::L0dError;
use crate::l0::eip191::EthSecret;
use crate::l0::{eip191, envelope, pgp, post};
use base64::Engine;
use sequoia_openpgp::Cert;
use serde_json::Value;
use std::time::Duration;
use tokio::sync::mpsc;

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

/// SI inner plaintext: `base64(JSON.stringify({ message, signMessage }))`.
/// `message` is the unsigned command JSON. `signMessage` is EIP-191 of that exact string.
pub fn encode_signed_listen_plaintext(
    command_json: &str,
    eth: &EthSecret,
) -> Result<String, L0dError> {
    if command_json.contains("Securitykey") {
        return Err(L0dError::L0(
            "refusing to encrypt a listen command that contains Securitykey".into(),
        ));
    }
    if command_json.contains("signMessage") {
        return Err(L0dError::L0(
            "listen command JSON must not embed signMessage; it belongs in the SI wrapper".into(),
        ));
    }
    let parsed: Value = serde_json::from_str(command_json)
        .map_err(|e| L0dError::L0(format!("listen command JSON: {e}")))?;
    let wallet = parsed
        .get("walletAddress")
        .and_then(Value::as_str)
        .ok_or_else(|| L0dError::L0("listen command needs walletAddress".into()))?;
    if !eip191::eoa_eq(wallet, eth.address()) {
        return Err(L0dError::L0(
            "routing ETH key does not match listen walletAddress".into(),
        ));
    }
    let sign_message = eth.personal_sign(command_json.as_bytes())?;
    let envelope = serde_json::json!({
        "message": command_json,
        "signMessage": sign_message,
    });
    let text = serde_json::to_string(&envelope).map_err(|e| L0dError::L0(e.to_string()))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(text.as_bytes()))
}

/// Encrypt the SI listen wrapper to mailbox **B route PGP**. HTTP body is still `{ data }`.
pub fn wrap_listen_for_post(
    command_json: &str,
    route_pub_armored: &str,
    eth: &EthSecret,
) -> Result<String, L0dError> {
    let plaintext = encode_signed_listen_plaintext(command_json, eth)?;
    pgp::encrypt_utf8(&plaintext, route_pub_armored)
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

/// Wrap a listen command and build the `/post` URL. HTTP body is still `{ data }`.
pub fn prepare_listen_post(
    wallet: &str,
    timestamp: u64,
    route_pub_armored: &str,
    entry: &str,
    eth: &EthSecret,
) -> Result<(String, String), L0dError> {
    let cmd = encode_listen_command(wallet, timestamp)?;
    let armor = wrap_listen_for_post(&cmd, route_pub_armored, eth)?;
    let url = post::post_url(entry)?;
    Ok((url, armor))
}

/// Prefer an entry that is not the last failed host. One-entry lists stay usable.
pub fn pick_listen_entry<'a>(entries: &'a [String], last_failed: Option<&str>) -> Option<&'a str> {
    if entries.is_empty() {
        return None;
    }
    entries
        .iter()
        .map(String::as_str)
        .find(|entry| last_failed != Some(*entry))
        .or_else(|| entries.first().map(String::as_str))
}

/// Long-lived SSE client. Connect timeout starts at `fetch` (12s).
/// Do not set an overall request timeout — that would cut a live SSE.
pub fn listen_http_client() -> Result<reqwest::Client, L0dError> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(12))
        .pool_max_idle_per_host(0)
        .tcp_nodelay(true)
        .http1_only()
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("conet-l0d/0.1")
        .build()
        .map_err(|e| L0dError::L0(format!("listen http client: {e}")))
}

/// POST listen armor. Require HTTP 2xx. Do not treat a non-2xx as a live SSE.
pub async fn open_listen_sse(
    client: &reqwest::Client,
    url: &str,
    listen_armor: &str,
) -> Result<reqwest::Response, L0dError> {
    let body = post::json_body(listen_armor)?;
    let obj = body
        .as_object()
        .ok_or_else(|| L0dError::L0("POST body must be a JSON object".into()))?;
    if obj.len() != 1 || !obj.contains_key("data") {
        return Err(L0dError::L0("POST body must be exactly { data }".into()));
    }
    let send = client.post(url).json(&body).send();
    let response = tokio::time::timeout(Duration::from_secs(15), send)
        .await
        .map_err(|_| L0dError::L0("listen POST timed out waiting for headers (15s)".into()))?
        .map_err(|e| L0dError::L0(post::format_reqwest_error("listen POST failed", e)))?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(L0dError::L0(format!("listen POST HTTP {status}")));
    }
    if response.content_length() == Some(0) {
        return Err(L0dError::L0("listen POST returned empty body".into()));
    }
    Ok(response)
}

/// Complete Chat/SI frames end with `\r\n\r\n` or `\n\n`.
fn find_frame_end(buffer: &str) -> Option<(usize, usize)> {
    let crlf = buffer.find("\r\n\r\n").map(|i| (i, 4));
    let lf = buffer.find("\n\n").map(|i| (i, 2));
    match (crlf, lf) {
        (Some(a), Some(b)) => Some(if a.0 <= b.0 { a } else { b }),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

/// Chat `handleInbound` payload: join `data:` lines, else the whole block.
fn sse_or_raw_payload(block: &str) -> String {
    let mut data_lines = Vec::new();
    for raw in block.lines() {
        if let Some(rest) = raw.strip_prefix("data:") {
            data_lines.push(rest.trim_start().to_string());
        }
    }
    if data_lines.is_empty() {
        block.trim().to_string()
    } else {
        data_lines.join("\n")
    }
}

fn clip_pgp_armor(raw: &str) -> Option<String> {
    let start = raw.find("-----BEGIN PGP MESSAGE-----")?;
    let rest = &raw[start..];
    let end_mark = "-----END PGP MESSAGE-----";
    let end = rest.find(end_mark)? + end_mark.len();
    let mut armor = rest[..end].to_string();
    if !armor.ends_with('\n') {
        armor.push('\n');
    }
    pgp::is_pgp_message_armor(&armor).then_some(armor)
}

/// SI gossip / Chat: `{ "data": "<armor>" }`. Ignore listing/liveness JSON.
fn armor_from_si_json(payload: &str) -> Option<String> {
    let v: Value = serde_json::from_str(payload.trim()).ok()?;
    let data = v.get("data")?.as_str()?;
    clip_pgp_armor(data)
}

fn extract_armors_from_frame(frame: &str) -> Vec<String> {
    let payload = sse_or_raw_payload(frame);
    if let Some(armor) = armor_from_si_json(&payload) {
        return vec![armor];
    }
    extract_pgp_armors_from_sse(frame)
}

/// Extract user-PGP armors from SI gossip JSON and/or SSE. Do not log armor.
pub fn extract_inbound_armors(chunk: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = chunk;
    while let Some((end, sep)) = find_frame_end(rest) {
        out.extend(extract_armors_from_frame(&rest[..end]));
        rest = &rest[end + sep..];
    }
    if !rest.trim().is_empty() {
        out.extend(extract_armors_from_frame(rest));
    }
    out
}

/// Extract complete frames and drop them from `buffer`. Do not log armor.
pub fn drain_sse_armors(buffer: &mut String) -> Vec<String> {
    let mut out = Vec::new();
    while let Some((end, sep)) = find_frame_end(buffer) {
        let frame: String = buffer.drain(..end + sep).collect();
        let body_len = frame.len().saturating_sub(sep);
        out.extend(extract_armors_from_frame(&frame[..body_len]));
    }
    if out.is_empty()
        && buffer.len() > 64_000
        && !buffer.contains("BEGIN PGP")
        && !buffer.contains('{')
    {
        buffer.clear();
    }
    out
}

pub async fn pump_sse_armors(
    mut response: reqwest::Response,
    armor_tx: &mpsc::Sender<String>,
) -> Result<(), L0dError> {
    let mut buf = String::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                buf.push_str(&String::from_utf8_lossy(&chunk));
                for armor in drain_sse_armors(&mut buf) {
                    if armor_tx.send(armor).await.is_err() {
                        return Ok(());
                    }
                }
            }
            Ok(None) => {
                for armor in extract_inbound_armors(&buf) {
                    if armor_tx.send(armor).await.is_err() {
                        return Ok(());
                    }
                }
                return Ok(());
            }
            Err(err) => return Err(L0dError::L0(format!("listen SSE read: {err}"))),
        }
    }
}

/// One listen POST + SSE drain. Tests use wiremock. Do not call production SI from tests.
pub async fn run_listen_once(
    client: &reqwest::Client,
    url: &str,
    listen_armor: &str,
    armor_tx: &mpsc::Sender<String>,
) -> Result<u16, L0dError> {
    let response = open_listen_sse(client, url, listen_armor).await?;
    let status = response.status().as_u16();
    pump_sse_armors(response, armor_tx).await?;
    Ok(status)
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
            if line.contains("-----END PGP MESSAGE-----") {
                if pgp::is_pgp_message_armor(&current) {
                    out.push(current.clone());
                }
                current.clear();
                in_armor = false;
            }
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
    use crate::l0::eip191::{recover_personal_sign, EthSecret};
    use crate::l0::pgp::{encrypt_utf8, generate_test_cert, mailbox_work_json, public_cert_armored};

    fn test_eth() -> EthSecret {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        EthSecret::from_bytes(&bytes).unwrap()
    }

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
    fn listen_wrap_is_si_checksign_shape() {
        let eth = test_eth();
        let route = generate_test_cert();
        let route_pub = public_cert_armored(&route).unwrap();
        let cmd = encode_listen_command(eth.address(), 9).unwrap();
        let armor = wrap_listen_for_post(&cmd, &route_pub, &eth).unwrap();
        assert!(pgp::is_pgp_message_armor(&armor));
        let b64 = pgp::decrypt_utf8(&armor, &route).unwrap();
        assert!(!b64.contains("Securitykey"));
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .expect("si wrapper is base64");
        let wrapper: Value = serde_json::from_slice(&raw).unwrap();
        let message = wrapper["message"].as_str().unwrap();
        let sig = wrapper["signMessage"].as_str().unwrap();
        assert_eq!(message, cmd);
        assert!(!message.contains("Securitykey"));
        assert_eq!(recover_personal_sign(message.as_bytes(), sig).unwrap(), eth.address());
    }

    #[test]
    fn listen_wrap_refuses_key_mismatch() {
        let eth = test_eth();
        let route = generate_test_cert();
        let route_pub = public_cert_armored(&route).unwrap();
        let cmd = encode_listen_command("0x2222222222222222222222222222222222222222", 9).unwrap();
        let err = wrap_listen_for_post(&cmd, &route_pub, &eth).unwrap_err();
        assert!(err.to_string().contains("does not match"));
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
        assert_eq!(extract_inbound_armors(chunk).len(), 1);
    }

    #[test]
    fn drain_keeps_incomplete_armor() {
        let mut buf = String::from("data: -----BEGIN PGP MESSAGE-----\ndata: partial\n");
        assert!(drain_sse_armors(&mut buf).is_empty());
        assert!(buf.contains("BEGIN PGP"));
    }

    #[test]
    fn si_gossip_json_recovers_ipv4() {
        let user = generate_test_cert();
        let user_pub = public_cert_armored(&user).unwrap();
        let pkt = b"\x45\x00si-gossip-ipv4!!!!";
        let json = envelope::encode("0x1111111111111111111111111111111111111111", 5, pkt).unwrap();
        let inbound = encrypt_utf8(&json, &user_pub).unwrap();
        let frame = format!("{}\r\n\r\n", serde_json::json!({ "data": inbound }));
        let found = extract_inbound_armors(&frame);
        assert_eq!(found.len(), 1);
        assert_eq!(inbound_ipv4_from_user_armor(&found[0], &user).unwrap(), pkt);

        let mut buf = frame;
        let drained = drain_sse_armors(&mut buf);
        assert_eq!(drained.len(), 1);
        assert!(buf.is_empty());
        assert_eq!(inbound_ipv4_from_user_armor(&drained[0], &user).unwrap(), pkt);
    }

    #[test]
    fn sse_wrapped_si_json_and_liveness_are_ignored_or_extracted() {
        let user = generate_test_cert();
        let user_pub = public_cert_armored(&user).unwrap();
        let pkt = b"\x45\x00sse-json-ipv4!!!!!";
        let json = envelope::encode("0x1111111111111111111111111111111111111111", 6, pkt).unwrap();
        let inbound = encrypt_utf8(&json, &user_pub).unwrap();
        let heartbeat = "data: {\"status\":200,\"epoch\":1}\r\n\r\n";
        let gossip = format!("data: {}\r\n\r\n", serde_json::json!({ "data": inbound }));
        let chunk = format!("{heartbeat}{gossip}");
        let found = extract_inbound_armors(&chunk);
        assert_eq!(found.len(), 1);
        assert_eq!(inbound_ipv4_from_user_armor(&found[0], &user).unwrap(), pkt);
    }

    #[test]
    fn pick_listen_skips_last_failed() {
        let entries = vec![
            "https://a.conet.network".into(),
            "https://b.conet.network".into(),
        ];
        assert_eq!(
            pick_listen_entry(&entries, Some("https://a.conet.network")),
            Some("https://b.conet.network")
        );
        assert_eq!(
            pick_listen_entry(&entries[..1], Some("https://a.conet.network")),
            Some("https://a.conet.network")
        );
        assert!(pick_listen_entry(&[], None).is_none());
    }

    fn armor_to_sse(armor: &str) -> String {
        let mut out = String::from("event: message\n");
        for line in armor.lines() {
            out.push_str("data: ");
            out.push_str(line);
            out.push('\n');
        }
        out.push('\n');
        out
    }

    #[tokio::test]
    async fn listen_once_reads_sse_and_recovers_ipv4() {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let route = generate_test_cert();
        let user = generate_test_cert();
        let route_pub = public_cert_armored(&route).unwrap();
        let user_pub = public_cert_armored(&user).unwrap();
        let pkt = b"\x45\x00listen-sse-ipv4!!!!";
        let json = envelope::encode("0x1111111111111111111111111111111111111111", 3, pkt).unwrap();
        let inbound = encrypt_utf8(&json, &user_pub).unwrap();

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/post"))
            .and(body_string_contains("\"data\""))
            .and(body_string_contains("BEGIN PGP MESSAGE"))
            .respond_with(ResponseTemplate::new(200).set_body_string(armor_to_sse(&inbound)))
            .expect(1)
            .mount(&server)
            .await;

        let eth = test_eth();
        let (url, listen_armor) = prepare_listen_post(
            eth.address(),
            1_710_000_000,
            &route_pub,
            &server.uri(),
            &eth,
        )
        .unwrap();
        assert!(url.ends_with("/post"));
        assert!(!pgp::decrypt_utf8(&listen_armor, &route).unwrap().contains("Securitykey"));

        let (tx, mut rx) = mpsc::channel::<String>(4);
        let client = listen_http_client().unwrap();
        let status = run_listen_once(&client, &url, &listen_armor, &tx)
            .await
            .expect("mock listen");
        assert_eq!(status, 200);
        let got_armor = rx.recv().await.expect("sse armor");
        assert_eq!(inbound_ipv4_from_user_armor(&got_armor, &user).unwrap(), pkt);
    }

    fn armor_to_si_gossip(armor: &str) -> String {
        format!("{}\r\n\r\n", serde_json::json!({ "data": armor }))
    }

    #[tokio::test]
    async fn listen_once_reads_si_gossip_json_and_recovers_ipv4() {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let route = generate_test_cert();
        let user = generate_test_cert();
        let route_pub = public_cert_armored(&route).unwrap();
        let user_pub = public_cert_armored(&user).unwrap();
        let pkt = b"\x45\x00listen-json-ipv4!!!";
        let json = envelope::encode("0x1111111111111111111111111111111111111111", 7, pkt).unwrap();
        let inbound = encrypt_utf8(&json, &user_pub).unwrap();

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/post"))
            .and(body_string_contains("\"data\""))
            .and(body_string_contains("BEGIN PGP MESSAGE"))
            .respond_with(ResponseTemplate::new(200).set_body_string(armor_to_si_gossip(&inbound)))
            .expect(1)
            .mount(&server)
            .await;

        let eth = test_eth();
        let (url, listen_armor) = prepare_listen_post(
            eth.address(),
            1_710_000_000,
            &route_pub,
            &server.uri(),
            &eth,
        )
        .unwrap();

        let (tx, mut rx) = mpsc::channel::<String>(4);
        let client = listen_http_client().unwrap();
        let status = run_listen_once(&client, &url, &listen_armor, &tx)
            .await
            .expect("mock listen");
        assert_eq!(status, 200);
        let got_armor = rx.recv().await.expect("si gossip armor");
        assert_eq!(inbound_ipv4_from_user_armor(&got_armor, &user).unwrap(), pkt);
    }

    fn test_eth_b() -> EthSecret {
        let mut bytes = [0u8; 32];
        bytes[31] = 2;
        EthSecret::from_bytes(&bytes).unwrap()
    }

    #[tokio::test]
    async fn two_listen_streams_share_one_queue() {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let route = generate_test_cert();
        let user_a = generate_test_cert();
        let user_b = generate_test_cert();
        let route_pub = public_cert_armored(&route).unwrap();
        let pkt_a = b"\x45\x00listen-chan-a-ipv4";
        let pkt_b = b"\x45\x00listen-chan-b-ipv4";
        let json_a = envelope::encode("0x1111111111111111111111111111111111111111", 1, pkt_a).unwrap();
        let json_b = envelope::encode("0x2222222222222222222222222222222222222222", 2, pkt_b).unwrap();
        let inbound_a = encrypt_utf8(&json_a, &public_cert_armored(&user_a).unwrap()).unwrap();
        let inbound_b = encrypt_utf8(&json_b, &public_cert_armored(&user_b).unwrap()).unwrap();

        let server_a = MockServer::start().await;
        let server_b = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/post"))
            .and(body_string_contains("BEGIN PGP MESSAGE"))
            .respond_with(ResponseTemplate::new(200).set_body_string(armor_to_si_gossip(&inbound_a)))
            .expect(1)
            .mount(&server_a)
            .await;
        Mock::given(method("POST"))
            .and(path("/post"))
            .and(body_string_contains("BEGIN PGP MESSAGE"))
            .respond_with(ResponseTemplate::new(200).set_body_string(armor_to_si_gossip(&inbound_b)))
            .expect(1)
            .mount(&server_b)
            .await;

        let eth_a = test_eth();
        let eth_b = test_eth_b();
        let (url_a, armor_a) = prepare_listen_post(
            eth_a.address(),
            1_710_000_000,
            &route_pub,
            &server_a.uri(),
            &eth_a,
        )
        .unwrap();
        let (url_b, armor_b) = prepare_listen_post(
            eth_b.address(),
            1_710_000_000,
            &route_pub,
            &server_b.uri(),
            &eth_b,
        )
        .unwrap();
        assert_ne!(eth_a.address(), eth_b.address());

        let (tx, mut rx) = mpsc::channel::<String>(8);
        let client = listen_http_client().unwrap();
        let (status_a, status_b) = tokio::join!(
            run_listen_once(&client, &url_a, &armor_a, &tx),
            run_listen_once(&client, &url_b, &armor_b, &tx),
        );
        assert_eq!(status_a.unwrap(), 200);
        assert_eq!(status_b.unwrap(), 200);
        let first = rx.recv().await.expect("first armor");
        let second = rx.recv().await.expect("second armor");
        let mut recovered = vec![
            inbound_ipv4_from_user_armor(&first, &user_a)
                .or_else(|_| inbound_ipv4_from_user_armor(&first, &user_b))
                .unwrap(),
            inbound_ipv4_from_user_armor(&second, &user_a)
                .or_else(|_| inbound_ipv4_from_user_armor(&second, &user_b))
                .unwrap(),
        ];
        recovered.sort();
        let mut expected = vec![pkt_a.to_vec(), pkt_b.to_vec()];
        expected.sort();
        assert_eq!(recovered, expected);
    }

    #[tokio::test]
    async fn listen_does_not_post_plaintext() {
        let client = listen_http_client().unwrap();
        let (tx, _rx) = mpsc::channel::<String>(1);
        let err = run_listen_once(
            &client,
            "https://example.conet.network/post",
            r#"{"command":"mining"}"#,
            &tx,
        )
        .await
        .expect_err("plaintext must not POST");
        assert!(err.to_string().contains("plaintext"));
    }
}
