//! Client for KrakenWAF's Rule Management API (the CMC control plane).
//!
//! KrakenWAF authenticates rule-management requests with a *Rorschach* token: a
//! per-request, time-windowed BLAKE2b-256 keyed MAC that binds the HTTP method,
//! path and body. Kraken UI deliberately mirrors KrakenWAF's secret names and
//! file-first resolution (`RORSCHACH_SECRET_EVEN` / `RORSCHACH_SECRET_ODD`), so
//! when both services share a container the same `/run/secrets/krakenwaf/<NAME>`
//! mount feeds both. See `docs/rule-management.md`.
//!
//! The token, the decoded secrets and the MAC key are never written to logs:
//! the `Authorization` header is marked sensitive, secrets are held in
//! `Zeroizing` buffers, and error messages carry only HTTP status codes.

use std::{collections::BTreeMap, path::Path, sync::Arc, time::Duration};

use anyhow::{Context, anyhow, bail};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use dryoc::classic::crypto_generichash::crypto_generichash;
use reqwest::{
    Certificate, Client,
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue},
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use zeroize::Zeroizing;

/// Canonical message domain separator, identical to KrakenWAF's.
const CANONICAL_DOMAIN: &str = "rorschach-v1";
/// Token scheme prefix in the `Authorization` header.
const TOKEN_SCHEME: &str = "rch1";
/// Width of the time window, in seconds (`floor(unix_time / 300)`).
const STEP_SECONDS: i64 = 300;
/// BLAKE2b key length KrakenWAF uses: the first 64 bytes of the decoded secret.
const MAC_KEY_BYTES: usize = 64;
/// BLAKE2b-256 output size for both the body hash and the MAC tag.
const DIGEST_BYTES: usize = 32;
/// Random nonce length per request.
const NONCE_BYTES: usize = 64;

const LIST_PATH: &str = "/rule/control/cmc/list";
const UPDATE_PATH: &str = "/rule/control/cmc/update";

/// A configured client for the KrakenWAF rule-management endpoint.
#[derive(Clone)]
pub struct RuleManagementService {
    client: Client,
    endpoint: String,
    client_id: String,
    /// Decoded secret used when the time step is even.
    secret_even: Arc<Zeroizing<Vec<u8>>>,
    /// Decoded secret used when the time step is odd.
    secret_odd: Arc<Zeroizing<Vec<u8>>>,
}

/// Outcome reported by KrakenWAF after a CMC update, echoed back to the UI so the
/// operator sees exactly which modules changed.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CmcUpdateOutcome {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub updated: CmcUpdated,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CmcUpdated {
    #[serde(default)]
    pub enabled: Vec<String>,
    #[serde(default)]
    pub disabled: Vec<String>,
}

#[derive(Deserialize)]
struct CmcListResponse {
    #[serde(default)]
    modules: CmcListModules,
}

#[derive(Default, Deserialize)]
struct CmcListModules {
    #[serde(rename = "CMC-Rules", default)]
    cmc_rules: BTreeMap<String, bool>,
}

#[derive(Serialize)]
struct CmcUpdateRequest {
    modules: CmcUpdateModules,
}

#[derive(Serialize)]
struct CmcUpdateModules {
    #[serde(rename = "CMC-Rules")]
    cmc_rules: BTreeMap<String, bool>,
}

impl RuleManagementService {
    /// Builds a production client that pins TLS to the configured KrakenWAF CA,
    /// exactly like the metrics channel, so the control plane cannot be
    /// intercepted by any other publicly trusted CA.
    pub async fn from_config(
        endpoint: &str,
        certificate_path: &Path,
        client_id: &str,
        secret_even_encoded: &str,
        secret_odd_encoded: &str,
    ) -> anyhow::Result<Self> {
        let certificate_bytes = tokio::fs::read(certificate_path).await.with_context(|| {
            format!(
                "failed to read WAF rule-management CA {}",
                certificate_path.display()
            )
        })?;
        let certificate = Certificate::from_pem(&certificate_bytes)
            .context("failed to parse WAF rule-management CA PEM")?;
        let client = Client::builder()
            .https_only(true)
            .tls_built_in_root_certs(false)
            .add_root_certificate(certificate)
            .timeout(Duration::from_secs(5))
            .build()
            .context("failed to build WAF rule-management HTTPS client")?;
        Self::with_client(
            client,
            endpoint,
            client_id,
            secret_even_encoded,
            secret_odd_encoded,
        )
    }

    /// Builds a client that trusts the system roots and does not force HTTPS.
    /// Intended for local development and the isolated integration tests that
    /// drive Kraken UI against a plain-HTTP mock WAF on loopback; production uses
    /// [`Self::from_config`], which pins the CA.
    pub fn without_pinned_ca(
        endpoint: &str,
        client_id: &str,
        secret_even_encoded: &str,
        secret_odd_encoded: &str,
    ) -> anyhow::Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .context("failed to build WAF rule-management client")?;
        Self::with_client(
            client,
            endpoint,
            client_id,
            secret_even_encoded,
            secret_odd_encoded,
        )
    }

    fn with_client(
        client: Client,
        endpoint: &str,
        client_id: &str,
        secret_even_encoded: &str,
        secret_odd_encoded: &str,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            client,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
            client_id: validate_client_id(client_id)?,
            secret_even: Arc::new(decode_secret(secret_even_encoded, "RORSCHACH_SECRET_EVEN")?),
            secret_odd: Arc::new(decode_secret(secret_odd_encoded, "RORSCHACH_SECRET_ODD")?),
        })
    }

    /// Fetches the current enable/disable state of every CMC module.
    pub async fn list_cmc(&self) -> anyhow::Result<BTreeMap<String, bool>> {
        let url = format!("{}{LIST_PATH}", self.endpoint);
        let authorization = self.rorschach_token("GET", LIST_PATH, b"")?;
        let response = self
            .client
            .get(&url)
            .header(AUTHORIZATION, authorization)
            .header(ACCEPT, "application/json")
            .send()
            .await
            .context("failed to reach the WAF rule-management list endpoint")?;
        if !response.status().is_success() {
            bail!(
                "WAF rule-management list returned HTTP {}",
                response.status()
            );
        }
        let payload: CmcListResponse = response
            .json()
            .await
            .context("invalid JSON from the WAF rule-management list endpoint")?;
        Ok(payload.modules.cmc_rules)
    }

    /// Applies a partial patch: each `(module, desired_state)` pair enables the
    /// module when `true` and disables it when `false`.
    pub async fn update_cmc(
        &self,
        desired: BTreeMap<String, bool>,
    ) -> anyhow::Result<CmcUpdateOutcome> {
        let url = format!("{}{UPDATE_PATH}", self.endpoint);
        let request = CmcUpdateRequest {
            modules: CmcUpdateModules { cmc_rules: desired },
        };
        // Serialise exactly once and hash *these* bytes: the MAC binds the body,
        // so the wire bytes and the hashed bytes must be identical.
        let body = serde_json::to_vec(&request).context("failed to encode the CMC update body")?;
        let authorization = self.rorschach_token("POST", UPDATE_PATH, &body)?;
        let response = self
            .client
            .post(&url)
            .header(AUTHORIZATION, authorization)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .body(body)
            .send()
            .await
            .context("failed to reach the WAF rule-management update endpoint")?;
        if !response.status().is_success() {
            bail!(
                "WAF rule-management update returned HTTP {}",
                response.status()
            );
        }
        // A success status with an unexpected/empty body still counts: the change
        // was applied. Default the outcome rather than failing the operator's
        // request over a cosmetic response-shape mismatch.
        Ok(response.json().await.unwrap_or_default())
    }

    /// Builds the `Authorization: Bearer rch1.<id>.<step>.<nonce>.<tag>` header
    /// for one request, mirroring KrakenWAF's canonical message exactly.
    fn rorschach_token(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> anyhow::Result<HeaderValue> {
        let step = OffsetDateTime::now_utc()
            .unix_timestamp()
            .div_euclid(STEP_SECONDS);
        let mut nonce = [0_u8; NONCE_BYTES];
        dryoc::rng::copy_randombytes(&mut nonce);
        let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce);
        let body_hash = URL_SAFE_NO_PAD.encode(blake2b256(body, None)?);
        let canonical =
            canonical_message(&self.client_id, step, &nonce_b64, method, path, &body_hash);
        let key = self.mac_key_for_step(step);
        let tag = blake2b256(canonical.as_bytes(), Some(key))?;
        let token_b64 = URL_SAFE_NO_PAD.encode(tag);
        let header = format!(
            "Bearer {TOKEN_SCHEME}.{}.{step}.{nonce_b64}.{token_b64}",
            self.client_id
        );
        let mut value = HeaderValue::from_str(&header)
            .context("constructed an invalid Rorschach Authorization header")?;
        value.set_sensitive(true);
        Ok(value)
    }

    /// Selects the secret for the window and returns its 64-byte MAC key prefix.
    fn mac_key_for_step(&self, step: i64) -> &[u8] {
        let secret = if step.rem_euclid(2) == 0 {
            &self.secret_even
        } else {
            &self.secret_odd
        };
        &secret[..MAC_KEY_BYTES]
    }
}

/// Builds the newline-delimited canonical message KrakenWAF authenticates.
fn canonical_message(
    client_id: &str,
    step: i64,
    nonce_b64: &str,
    method: &str,
    path: &str,
    body_hash: &str,
) -> String {
    format!("{CANONICAL_DOMAIN}\n{client_id}\n{step}\n{nonce_b64}\n{method}\n{path}\n{body_hash}")
}

/// Computes BLAKE2b-256 over `input`, keyed when `key` is supplied. libsodium's
/// `crypto_generichash` (via dryoc) is plain keyed/unkeyed BLAKE2b with no salt
/// or personalisation, byte-identical to the `orion` primitives KrakenWAF uses.
fn blake2b256(input: &[u8], key: Option<&[u8]>) -> anyhow::Result<[u8; DIGEST_BYTES]> {
    let mut output = [0_u8; DIGEST_BYTES];
    crypto_generichash(&mut output, input, key)
        .map_err(|_| anyhow!("BLAKE2b-256 computation failed"))?;
    Ok(output)
}

/// The client id is embedded between `.` delimiters in the token, so it must not
/// contain `.`; KrakenWAF restricts it to `[A-Za-z0-9_-]`.
fn validate_client_id(client_id: &str) -> anyhow::Result<String> {
    let trimmed = client_id.trim();
    if trimmed.is_empty()
        || trimmed.len() > 64
        || !trimmed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        bail!("RORSCHACH_CLIENT_ID must be 1 to 64 characters of [A-Za-z0-9_-]");
    }
    Ok(trimmed.to_owned())
}

/// Decodes a Rorschach secret, accepting both the URL-safe (KrakenWAF's default)
/// and standard base64 alphabets, with or without padding. The decoded secret
/// must be at least 64 bytes so the MAC key prefix is fully covered.
fn decode_secret(encoded: &str, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let trimmed = encoded.trim();
    let decoded = [URL_SAFE_NO_PAD, URL_SAFE, STANDARD_NO_PAD, STANDARD]
        .into_iter()
        .find_map(|engine| engine.decode(trimmed).ok())
        .map(Zeroizing::new)
        .with_context(|| format!("{name} must be valid base64"))?;
    if decoded.len() < MAC_KEY_BYTES {
        bail!("{name} must decode to at least {MAC_KEY_BYTES} bytes");
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 64 deterministic key bytes, base64url-encoded, for reproducible tokens.
    fn test_secret(byte: u8) -> String {
        URL_SAFE_NO_PAD.encode([byte; 72])
    }

    fn service() -> RuleManagementService {
        RuleManagementService::without_pinned_ca(
            "http://127.0.0.1:4342",
            "kraken-ui",
            &test_secret(0x11),
            &test_secret(0x22),
        )
        .expect("rule-management client must build")
    }

    /// Known-answer test: BLAKE2b-256("abc") fixes dryoc's digest to the standard
    /// vector, proving byte-compatibility with KrakenWAF's `orion::hash`.
    #[test]
    fn blake2b256_matches_the_standard_test_vector() {
        let digest = blake2b256(b"abc", None).expect("digest");
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            hex,
            "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
        );
    }

    #[test]
    fn canonical_message_is_newline_delimited_in_order() {
        let message = canonical_message("kraken-ui", 42, "nonce", "POST", "/p", "bh");
        assert_eq!(message, "rorschach-v1\nkraken-ui\n42\nnonce\nPOST\n/p\nbh");
    }

    #[test]
    fn token_has_the_documented_five_part_shape() {
        let header = service()
            .rorschach_token("GET", LIST_PATH, b"")
            .expect("token");
        let header = header.to_str().expect("ascii header");
        let token = header
            .strip_prefix("Bearer ")
            .expect("bearer scheme prefix");
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 5, "rch1.<id>.<step>.<nonce>.<tag>");
        assert_eq!(parts[0], "rch1");
        assert_eq!(parts[1], "kraken-ui");
        // The MAC tag is 32 bytes -> 43 base64url (no-pad) characters.
        assert_eq!(parts[4].len(), 43);
        assert!(header.parse::<HeaderValue>().is_ok());
    }

    #[test]
    fn even_and_odd_steps_select_different_secrets() {
        let service = service();
        // Distinct keys give distinct MACs for the same canonical message, so a
        // mismatched parity is observable as a different tag.
        let even = blake2b256(b"m", Some(service.mac_key_for_step(2))).expect("even tag");
        let odd = blake2b256(b"m", Some(service.mac_key_for_step(3))).expect("odd tag");
        assert_ne!(even, odd);
        assert_eq!(
            service.mac_key_for_step(10),
            service.mac_key_for_step(2),
            "all even steps share the even secret"
        );
    }

    #[test]
    fn update_body_matches_the_documented_shape() {
        let mut desired = BTreeMap::new();
        desired.insert("HPP_detect".to_owned(), false);
        desired.insert("Silent_sql_errors".to_owned(), false);
        let request = CmcUpdateRequest {
            modules: CmcUpdateModules { cmc_rules: desired },
        };
        let json = serde_json::to_string(&request).expect("serialise");
        assert_eq!(
            json,
            r#"{"modules":{"CMC-Rules":{"HPP_detect":false,"Silent_sql_errors":false}}}"#
        );
    }

    #[test]
    fn list_response_extracts_the_cmc_group() {
        let payload: CmcListResponse = serde_json::from_str(
            r#"{"status":"ok","modules":{"CMC-Rules":{"HPP_detect":true,"Overflow_detect":false}}}"#,
        )
        .expect("parse list");
        assert_eq!(payload.modules.cmc_rules.get("HPP_detect"), Some(&true));
        assert_eq!(
            payload.modules.cmc_rules.get("Overflow_detect"),
            Some(&false)
        );
    }

    #[test]
    fn rejects_short_secrets_and_bad_client_ids() {
        assert!(decode_secret(&URL_SAFE_NO_PAD.encode([0_u8; 32]), "X").is_err());
        assert!(decode_secret("not base64 !!!", "X").is_err());
        assert!(validate_client_id("has.dot").is_err());
        assert!(validate_client_id("").is_err());
        assert!(validate_client_id("kraken-ui_1").is_ok());
    }
}
