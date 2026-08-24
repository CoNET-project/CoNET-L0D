//! Mailbox-SSE to localhost HTTP gateway.
//!
//! The inbound SSE is receive-only: responses are encrypted for the requester
//! and POSTed to the requester's mailbox through an Entry node.

use crate::config::ValidatedGateway;
use crate::error::L0dError;
use crate::l0::{address_pgp, eip191, listen, pgp, post};
use base64::Engine;
use reqwest::header::{HeaderName, HeaderValue};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use url::Url;

#[derive(Debug, serde::Serialize, Deserialize)]
struct GatewayRequest {
    v: u8,
    #[serde(rename = "type")]
    request_type: String,
    #[serde(rename = "requestId")]
    request_id: String,
    from: String,
    target: String,
    method: String,
    path: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(rename = "bodyBase64", skip_serializing_if = "Option::is_none")]
    body_base64: Option<String>,
    #[serde(rename = "contentType", skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    nonce: String,
    #[serde(rename = "expiresAt")]
    expires_at: u64,
}

#[derive(Debug, Deserialize)]
struct SignedGatewayRequest {
    request: GatewayRequest,
    #[serde(rename = "signMessage")]
    sign_message: String,
}

#[derive(Debug, serde::Serialize)]
struct GatewayResponse {
    v: u8,
    #[serde(rename = "type")]
    response_type: String,
    #[serde(rename = "requestId")]
    request_id: String,
    status: u16,
    headers: BTreeMap<String, String>,
    #[serde(rename = "contentType")]
    content_type: String,
    #[serde(rename = "bodyBase64")]
    body_base64: String,
    nonce: String,
    #[serde(rename = "expiresAt")]
    expires_at: u64,
}

#[derive(Clone)]
struct GatewayRuntime {
    config: ValidatedGateway,
    gateway_user_secret: Arc<sequoia_openpgp::Cert>,
    gateway_eth: Arc<eip191::EthSecret>,
    gateway_route_public: Arc<String>,
    http: reqwest::Client,
}

pub async fn run(path: &Path) -> anyhow::Result<()> {
    let cfg = crate::config::DaemonConfig::load(path)?.validate()?;
    let gateway = cfg
        .gateway
        .clone()
        .ok_or_else(|| anyhow::anyhow!("gateway section is missing from config"))?;
    let runtime = GatewayRuntime::load(gateway)?;
    tracing::info!(
        eoa = %runtime.config.routing_eoa,
        upstream = %runtime.config.upstream,
        "conet-l0d web3 application gateway started"
    );

    let (tx, mut rx) = mpsc::channel::<listen::InboundChunk>(256);
    let owner =
        listen::OwnedListenSession::new(runtime.config.routing_eoa.clone(), None, "gateway");
    let owners = listen::ListenOwnerRegistry::default();
    owners.register(owner.clone());
    let listener_runtime = runtime.clone();
    let listener_owner = owner.clone();
    tokio::spawn(async move {
        if let Err(err) = listen_loop(listener_runtime, tx, listener_owner).await {
            tracing::error!(error = %err, "gateway SSE listener stopped");
        }
    });

    while let Some(chunk) = rx.recv().await {
        let runtime = runtime.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_request(&runtime, &chunk.payload).await {
                tracing::warn!(error = %err, "gateway request rejected");
            }
        });
    }
    Ok(())
}

impl GatewayRuntime {
    fn load(config: ValidatedGateway) -> Result<Self, L0dError> {
        let user_secret = pgp::load_secret_cert(&config.routing_key_file)?;
        let eth = eip191::load_eth_secret(&config.routing_eth_key_file)?;
        if !eip191::eoa_eq(eth.address(), &config.routing_eoa) {
            return Err(L0dError::L0(
                "gateway routing_eth_key_file does not match gateway routing_eoa".into(),
            ));
        }
        let route_public = pgp::load_public_cert_armored(&config.mailbox_route_pgp_file)?;
        let http = listen::listen_http_client()?;
        Ok(Self {
            config,
            gateway_user_secret: Arc::new(user_secret),
            gateway_eth: Arc::new(eth),
            gateway_route_public: Arc::new(route_public),
            http,
        })
    }
}

async fn listen_loop(
    runtime: GatewayRuntime,
    armor_tx: mpsc::Sender<listen::InboundChunk>,
    owner: Arc<listen::OwnedListenSession>,
) -> Result<(), L0dError> {
    loop {
        for entry in &runtime.config.listen_entries {
            let timestamp = chrono::Utc::now().timestamp().max(0) as u64;
            let (url, armor) = listen::prepare_listen_post(
                &runtime.config.routing_eoa,
                timestamp,
                &runtime.gateway_route_public,
                entry,
                &runtime.gateway_eth,
            )?;
            tracing::info!(entry = %entry, "gateway opening mailbox SSE");
            match listen::open_listen_sse(&runtime.http, &url, &armor).await {
                Ok(response) => {
                    owner.set_entry(entry);
                    if let Err(err) = listen::pump_sse_armors_owned_session(
                        response,
                        &armor_tx,
                        owner.clone(),
                        None,
                    )
                    .await
                    {
                        tracing::warn!(entry = %entry, error = %err, "gateway SSE closed");
                    }
                }
                Err(err) => tracing::warn!(entry = %entry, error = %err, "gateway SSE failed"),
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

async fn handle_request(runtime: &GatewayRuntime, armor: &str) -> Result<(), L0dError> {
    let plaintext = listen::inbound_plain_from_user_armor(armor, &runtime.gateway_user_secret)?;
    let signed: SignedGatewayRequest = serde_json::from_str(&plaintext)
        .map_err(|e| L0dError::L0(format!("gateway request JSON: {e}")))?;
    validate_request(runtime, &signed)?;
    let sender_key = resolve_sender_key(runtime, &signed.request.from).await?;
    let response = fetch_upstream(runtime, &signed.request).await?;
    let response_json = serde_json::to_string(&response)
        .map_err(|e| L0dError::L0(format!("gateway response: {e}")))?;
    let response_armor = pgp::encrypt_utf8(&response_json, &sender_key)?;
    post::send_via_entries(&runtime.http, &runtime.config.post_entries, &response_armor).await?;
    Ok(())
}

fn validate_request(
    runtime: &GatewayRuntime,
    signed: &SignedGatewayRequest,
) -> Result<(), L0dError> {
    let request = &signed.request;
    if request.v != 1 || request.request_type != "conet_web3_request_v1" {
        return Err(L0dError::L0("unsupported gateway request version".into()));
    }
    if request.request_id.trim().is_empty() || request.nonce.trim().is_empty() {
        return Err(L0dError::L0(
            "gateway request identifiers are required".into(),
        ));
    }
    if request.expires_at < chrono::Utc::now().timestamp().max(0) as u64 {
        return Err(L0dError::L0("gateway request has expired".into()));
    }
    if !runtime
        .config
        .allowed_methods
        .contains(&request.method.to_ascii_uppercase())
    {
        return Err(L0dError::L0("gateway method is not allowed".into()));
    }
    if !eip191::eoa_eq(
        &eip191::recover_personal_sign(
            serde_json::to_string(request)
                .map_err(|e| L0dError::L0(format!("gateway request serialization: {e}")))?
                .as_bytes(),
            &signed.sign_message,
        )?,
        &request.from,
    ) {
        return Err(L0dError::L0(
            "gateway request signature does not match from".into(),
        ));
    }
    if !target_matches(&request.target, &runtime.config.routing_eoa) {
        return Err(L0dError::L0(
            "gateway request target is not this EOA".into(),
        ));
    }
    if !request.path.starts_with('/')
        || request.path.contains("://")
        || request.path.contains('\\')
        || request.path.contains('\0')
    {
        return Err(L0dError::L0("gateway path is invalid".into()));
    }
    Ok(())
}

fn target_matches(target: &str, eoa: &str) -> bool {
    let Some(rest) = target.strip_prefix("web3://") else {
        return false;
    };
    let host = rest
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");
    eip191::eoa_eq(host, eoa)
}

async fn resolve_sender_key(runtime: &GatewayRuntime, sender: &str) -> Result<String, L0dError> {
    let call = address_pgp::encode_search_key_call(sender)?;
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [{"to": address_pgp::ADDRESS_PGP, "data": call}, "latest"]
    });
    let response = runtime
        .http
        .post(&runtime.config.rpc)
        .json(&body)
        .send()
        .await
        .map_err(|e| L0dError::L0(format!("AddressPGP RPC: {e}")))?;
    let value: Value = response
        .json()
        .await
        .map_err(|e| L0dError::L0(format!("AddressPGP RPC JSON: {e}")))?;
    let result = value
        .get("result")
        .and_then(Value::as_str)
        .ok_or_else(|| L0dError::L0("AddressPGP searchKey returned no result".into()))?;
    let key = address_pgp::decode_search_key_result(result)?;
    if key.user_public_key_armored.trim().is_empty() {
        return Err(L0dError::L0(
            "requester has no registered user PGP key".into(),
        ));
    }
    Ok(decode_registered_armored(&key.user_public_key_armored))
}

fn decode_registered_armored(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.starts_with("-----BEGIN PGP") {
        return trimmed.to_owned();
    }
    base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .filter(|decoded| decoded.trim_start().starts_with("-----BEGIN PGP"))
        .unwrap_or_else(|| trimmed.to_owned())
}

async fn fetch_upstream(
    runtime: &GatewayRuntime,
    request: &GatewayRequest,
) -> Result<GatewayResponse, L0dError> {
    let mut url = Url::parse(&format!("{}/", runtime.config.upstream))
        .map_err(|e| L0dError::L0(format!("gateway upstream URL: {e}")))?;
    url.set_path(&request.path);
    url.set_query(if request.query.is_empty() {
        None
    } else {
        Some(request.query.trim_start_matches('?'))
    });
    let mut builder = runtime.http.request(
        request
            .method
            .parse()
            .map_err(|_| L0dError::L0("gateway method is invalid".into()))?,
        url,
    );
    for (name, value) in &request.headers {
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "accept" | "content-type" | "if-none-match" | "if-modified-since"
        ) {
            let header_name = HeaderName::from_bytes(lower.as_bytes())
                .map_err(|_| L0dError::L0("gateway request header is invalid".into()))?;
            let header_value = HeaderValue::from_str(value)
                .map_err(|_| L0dError::L0("gateway request header value is invalid".into()))?;
            builder = builder.header(header_name, header_value);
        }
    }
    if let Some(body) = &request.body_base64 {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(body)
            .map_err(|e| L0dError::L0(format!("gateway request body base64: {e}")))?;
        if bytes.len() > runtime.config.max_body_bytes {
            return Err(L0dError::L0("gateway request body exceeds limit".into()));
        }
        builder = builder.body(bytes);
    }
    let response = tokio::time::timeout(
        Duration::from_secs(runtime.config.request_timeout_seconds),
        builder.send(),
    )
    .await
    .map_err(|_| L0dError::L0("gateway upstream timed out".into()))?
    .map_err(|e| L0dError::L0(format!("gateway upstream request: {e}")))?;
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let bytes = response
        .bytes()
        .await
        .map_err(|e| L0dError::L0(format!("gateway upstream body: {e}")))?;
    if bytes.len() > runtime.config.max_body_bytes {
        return Err(L0dError::L0("gateway upstream body exceeds limit".into()));
    }
    Ok(GatewayResponse {
        v: 1,
        response_type: "conet_web3_response_v1".into(),
        request_id: request.request_id.clone(),
        status,
        headers: BTreeMap::new(),
        content_type,
        body_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
        nonce: request.nonce.clone(),
        expires_at: chrono::Utc::now().timestamp().max(0) as u64 + 60,
    })
}
