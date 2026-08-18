//! HTTP `/post` body shape. Only `{ "data": "<armor>" }`.
//!
//! Do not POST to production SI from unit tests.

use crate::error::L0dError;
use crate::l0::pgp;
use serde_json::{json, Value};
use std::error::Error;
use std::time::Duration;

/// Walk the reqwest/hyper chain. SI mimic-404 is a status; this is connect/IO/reset.
pub fn format_reqwest_error(prefix: &str, err: reqwest::Error) -> String {
    let mut out = format!("{prefix}: {err}");
    let mut src = err.source();
    while let Some(inner) = src {
        out.push_str(&format!("; caused by: {inner}"));
        src = inner.source();
    }
    out
}

pub fn json_body(armor: &str) -> Result<Value, L0dError> {
    pgp::refuse_plaintext_data(armor)?;
    Ok(json!({ "data": armor }))
}

pub fn http_client() -> Result<reqwest::Client, L0dError> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .connect_timeout(Duration::from_secs(5))
        // SI distorySocket() writes keep-alive then destroy(). Reuse desyncs
        // the next POST into "error sending request" while curl Connection:close works.
        .pool_max_idle_per_host(0)
        .tcp_nodelay(true)
        .http1_only()
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("conet-l0d/0.1")
        .build()
        .map_err(|e| L0dError::L0(format!("http client: {e}")))
}

/// Try each configured entry once. Fail-closed if the list is empty or every POST fails.
/// Same host list as `[l0].entries`; this is not a listen fallback onto `listen_entries`.
pub async fn send_via_entries(
    client: &reqwest::Client,
    entries: &[String],
    armor: &str,
) -> Result<(u16, String), L0dError> {
    if entries.is_empty() {
        return Err(L0dError::L0("l0.entries is empty; refusing POST".into()));
    }
    let mut last_err = L0dError::L0("P1 POST /post failed".into());
    for entry in entries {
        let url = match post_url(entry) {
            Ok(url) => url,
            Err(err) => {
                last_err = err;
                continue;
            }
        };
        match send(client, &url, armor).await {
            Ok(status) => return Ok((status, entry.clone())),
            Err(err) => {
                last_err = err;
                // Every entry forwards to the same mailbox B. A timeout is B/C hang,
                // not a bad A; walking the rest only multiplies SI load.
                let msg = last_err.to_string();
                if msg.contains("timed out") || msg.contains("timeout") {
                    break;
                }
            }
        }
    }
    Err(last_err)
}

/// POST `{ "data": armor }` to `url`. Logs must not include armor.
pub async fn send(client: &reqwest::Client, url: &str, armor: &str) -> Result<u16, L0dError> {
    let body = json_body(armor)?;
    let obj = body
        .as_object()
        .ok_or_else(|| L0dError::L0("POST body must be a JSON object".into()))?;
    if obj.len() != 1 || !obj.contains_key("data") {
        return Err(L0dError::L0("POST body must be exactly { data }".into()));
    }
    let response = client
        .post(url)
        .header("Connection", "close")
        .json(&body)
        .send()
        .await
        .map_err(|e| L0dError::L0(format_reqwest_error("POST /post failed", e)))?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(L0dError::L0(format!("POST /post HTTP {status}")));
    }
    Ok(status)
}

pub fn json_body_bytes(armor: &str) -> Result<Vec<u8>, L0dError> {
    let body = json_body(armor)?;
    serde_json::to_vec(&body).map_err(|e| L0dError::L0(format!("POST JSON: {e}")))
}

pub fn post_url(entry: &str) -> Result<String, L0dError> {
    let trimmed = entry.trim().trim_end_matches('/');
    if !(trimmed.starts_with("https://") || trimmed.starts_with("http://")) {
        return Err(L0dError::L0(
            "entry must be an http(s) URL on an existing CoNET / beamio.app host".into(),
        ));
    }
    if trimmed.contains('?') || trimmed.contains('#') {
        return Err(L0dError::L0(
            "entry URL must not carry query or fragment mailbox instructions".into(),
        ));
    }
    Ok(format!("{trimmed}/post"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_is_data_only() {
        let v = json_body("-----BEGIN PGP MESSAGE-----\n…").expect("armor");
        let obj = v.as_object().expect("object");
        assert_eq!(obj.len(), 1);
        assert!(obj.contains_key("data"));
        assert!(!obj.contains_key("NoPush"));
        assert!(!obj.contains_key("beamioNoPush"));
    }

    #[test]
    fn refuse_plaintext_json_body() {
        assert!(json_body(r#"{"type":"conet_l0d_overlay_v1"}"#).is_err());
    }

    #[tokio::test]
    async fn send_posts_data_only_to_mock() {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/post"))
            .and(body_string_contains("\"data\""))
            .and(body_string_contains("BEGIN PGP MESSAGE"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .expect(1)
            .mount(&server)
            .await;

        let client = http_client().unwrap();
        let status = send(
            &client,
            &format!("{}/post", server.uri()),
            "-----BEGIN PGP MESSAGE-----\n\nxxxx\n-----END PGP MESSAGE-----\n",
        )
        .await
        .expect("mock POST");
        assert_eq!(status, 200);
    }

    #[tokio::test]
    async fn send_via_entries_tries_next_host() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let dead = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/post"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&dead)
            .await;

        let live = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/post"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .expect(1)
            .mount(&live)
            .await;

        let client = http_client().unwrap();
        let (status, entry) = send_via_entries(
            &client,
            &[dead.uri(), live.uri()],
            "-----BEGIN PGP MESSAGE-----\n\nxxxx\n-----END PGP MESSAGE-----\n",
        )
        .await
        .expect("fallback POST");
        assert_eq!(status, 200);
        assert_eq!(entry, live.uri());
    }

    #[tokio::test]
    async fn send_does_not_hit_network_with_plaintext() {
        let client = http_client().unwrap();
        let err = send(
            &client,
            "https://example.conet.network/post",
            r#"{"type":"conet_l0d_overlay_v1"}"#,
        )
        .await
        .expect_err("plaintext must not POST");
        assert!(err.to_string().contains("plaintext"));
    }

    #[test]
    fn post_url_strips_slash() {
        assert_eq!(
            post_url("https://example.conet.network/").unwrap(),
            "https://example.conet.network/post"
        );
    }

    #[test]
    fn reject_query_bypass() {
        assert!(post_url("https://example.conet.network/post?NoPush=1").is_err());
    }
}
