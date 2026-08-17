//! HTTP `/post` body shape. Only `{ "data": "<armor>" }`.
//!
//! Do not POST to production SI from unit tests.

use crate::error::L0dError;
use crate::l0::pgp;
use serde_json::{json, Value};
use std::time::Duration;

pub fn json_body(armor: &str) -> Result<Value, L0dError> {
    pgp::refuse_plaintext_data(armor)?;
    Ok(json!({ "data": armor }))
}

pub fn http_client() -> Result<reqwest::Client, L0dError> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .user_agent("conet-l0d/0.1")
        .build()
        .map_err(|e| L0dError::L0(format!("http client: {e}")))
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
        .json(&body)
        .send()
        .await
        .map_err(|e| L0dError::L0(format!("POST /post failed: {e}")))?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(L0dError::L0(format!("POST /post HTTP {status}")));
    }
    Ok(status)
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
