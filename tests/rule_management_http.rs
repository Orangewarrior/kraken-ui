//! Isolated, real-HTTP coverage of the rule-management console.
//!
//! This test stands up two genuine servers on loopback — a mock KrakenWAF
//! rule-management endpoint and the full Kraken UI router — and drives the new
//! feature end to end with `reqwest`: it logs in, lists the CMC modules through
//! the UI's proxy, and submits a toggle. It asserts the UI mints a Rorschach
//! `Authorization` token, forwards the documented `{"modules":{"CMC-Rules":...}}`
//! body to the WAF, and reflects the WAF's outcome back to the operator.
//!
//! The UI router is served over plain HTTP (TLS is added by `main` in
//! production), so cookies are managed by hand rather than through reqwest's jar,
//! which would drop the `Secure` `__Host-` cookies over HTTP.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Client, header};
use serde_json::{Value, json};

use kraken_ui::{
    AppFactory,
    config::AppConfig,
    services::{
        password_crypto::DryocPasswordCryptoService,
        rate_limit::{BackendKind, RateLimitConfig, RedisConfig, SqliteConfig},
        rule_management::RuleManagementService,
        waf_metrics::WafMetricsService,
    },
};

const ADMIN_PASSWORD: &str = "Reliable-Console9Key";
const SESSION_COOKIE: &str = "__Host-kraken_session";
const CSRF_COOKIE: &str = "__Host-kraken_csrf";

/// What the mock WAF recorded about the requests the UI sent it.
#[derive(Default)]
struct Captured {
    list_auth: Option<String>,
    update_auth: Option<String>,
    update_body: Option<String>,
}

fn disabled_rate_limit() -> RateLimitConfig {
    RateLimitConfig {
        enabled: false,
        requests_per_second: 5,
        burst_size: 5,
        max_coroutines_per_ip: 32,
        tls_handshake_timeout_secs: 10,
        connection_timeout_secs: 30,
        max_tracked_ips: 1000,
        backend: BackendKind::Sqlite,
        fail_open: false,
        sqlite: SqliteConfig {
            path: std::path::PathBuf::from("db/unused-rule-mgmt-ratelimit.sqlite"),
            busy_timeout_ms: 1000,
            cleanup_interval_requests: 1000,
        },
        redis: RedisConfig {
            host: "127.0.0.1".to_owned(),
            port: 6379,
            database: 0,
            tls: true,
            key_prefix: "kraken-ui:test:".to_owned(),
            connect_timeout_secs: 1,
            response_timeout_secs: 1,
            retries: 0,
        },
    }
}

async fn mock_cmc_list(
    State(captured): State<Arc<Mutex<Captured>>>,
    headers: HeaderMap,
) -> Json<Value> {
    captured.lock().expect("capture lock").list_auth = authorization(&headers);
    Json(json!({
        "status": "ok",
        "modules": { "CMC-Rules": { "HPP_detect": true, "Silent_sql_errors": false } }
    }))
}

async fn mock_cmc_update(
    State(captured): State<Arc<Mutex<Captured>>>,
    headers: HeaderMap,
    body: String,
) -> Json<Value> {
    {
        let mut capture = captured.lock().expect("capture lock");
        capture.update_auth = authorization(&headers);
        capture.update_body = Some(body);
    }
    Json(json!({
        "status": "ok",
        "context": "cmc_update",
        "updated": { "enabled": ["Silent_sql_errors"], "disabled": ["HPP_detect"] }
    }))
}

fn authorization(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

/// Spawns the mock WAF on an ephemeral port; returns its base URL and the capture.
async fn spawn_mock_waf() -> (String, Arc<Mutex<Captured>>) {
    let captured = Arc::new(Mutex::new(Captured::default()));
    let app = Router::new()
        .route("/rule/control/cmc/list", get(mock_cmc_list))
        .route("/rule/control/cmc/update", post(mock_cmc_update))
        .with_state(captured.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock WAF listener");
    let address = listener.local_addr().expect("mock WAF address");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve mock WAF");
    });
    (format!("http://{address}"), captured)
}

/// Builds and serves the full Kraken UI router; returns its base URL.
async fn spawn_kraken_ui(waf_url: &str) -> String {
    let directory = tempfile::tempdir().expect("temporary directory");
    // Leak the temp dir guard for the lifetime of the test process so the SQLite
    // files survive while the spawned server uses them.
    let directory = Box::leak(Box::new(directory));

    let config = AppConfig {
        certificate_path: "unused-cert.pem".into(),
        private_key_path: "unused-key.pem".into(),
        listen: "127.0.0.1:3443".to_owned(),
        database_path: directory.path().join("kraken-ui.sqlite"),
        waf_database_path: None,
        waf_endpoint: "https://127.0.0.1:4343".to_owned(),
        waf_certificate_path: None,
        waf_rule_endpoint: Some(waf_url.to_owned()),
        waf_rule_certificate_path: None,
        log_directory: directory.path().to_path_buf(),
        session_timeout_minutes: 30,
    };

    let crypto = Arc::new(
        DryocPasswordCryptoService::from_base64_key(
            "test-v1",
            &base64::engine::general_purpose::STANDARD.encode([9_u8; 32]),
        )
        .expect("password crypto service"),
    );

    // 72 bytes -> >= 64 after decode, the minimum Rorschach key length.
    let secret = URL_SAFE_NO_PAD.encode([0x5A_u8; 72]);
    let rule_management =
        RuleManagementService::without_pinned_ca(waf_url, "kraken-ui", &secret, &secret)
            .expect("rule-management client");

    // SAFETY: this is the only test in this binary, so no other test races the
    // process environment.
    unsafe {
        std::env::set_var("KRAKEN_UI_ADMIN_PASSWORD", ADMIN_PASSWORD);
        std::env::set_var("KRAKEN_UI_ADMIN_EMAIL", "admin@example.invalid");
    }
    let app = AppFactory::new(config)
        .with_password_crypto(crypto)
        .with_rate_limit_config(disabled_rate_limit())
        .with_waf_metrics(
            WafMetricsService::without_custom_ca("https://127.0.0.1:4343").expect("metrics client"),
        )
        .with_rule_management(rule_management)
        .build()
        .await
        .expect("application must build");
    unsafe {
        std::env::remove_var("KRAKEN_UI_ADMIN_PASSWORD");
        std::env::remove_var("KRAKEN_UI_ADMIN_EMAIL");
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("UI listener");
    let address = listener.local_addr().expect("UI address");
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("serve Kraken UI");
    });
    format!("http://{address}")
}

fn cookie_value(response: &reqwest::Response, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| {
            value
                .strip_prefix(&prefix)
                .map(|rest| rest.split(';').next().unwrap_or_default().to_owned())
        })
}

/// Extracts the value of an HTML attribute such as `name="csrf_token" value="X"`
/// or `data-csrf-token="X"`.
fn attribute_value(html: &str, marker: &str) -> String {
    let start = html.find(marker).expect("attribute marker present") + marker.len();
    let end = html[start..].find('"').expect("attribute terminator");
    html[start..start + end].to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cmc_rules_list_and_submit_round_trip() {
    let (waf_url, captured) = spawn_mock_waf().await;
    let base = spawn_kraken_ui(&waf_url).await;
    // Generous timeout: the login path runs a real Argon2id (moderate) hash.
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .expect("reqwest client");

    // 1. Log in: collect the CSRF pair, then the session cookie.
    let login_page = client
        .get(format!("{base}/kraken_ui/login"))
        .send()
        .await
        .expect("login page");
    let login_csrf = cookie_value(&login_page, CSRF_COOKIE).expect("login csrf cookie");
    let login_token = attribute_value(
        &login_page.text().await.expect("login html"),
        "name=\"csrf_token\" value=\"",
    );

    let login = client
        .post(format!("{base}/kraken_ui/login"))
        .header(header::COOKIE, format!("{CSRF_COOKIE}={login_csrf}"))
        .form(&[
            ("login", "admin"),
            ("password", ADMIN_PASSWORD),
            ("csrf_token", &login_token),
        ])
        .send()
        .await
        .expect("login submit");
    assert!(login.status().is_redirection(), "login should redirect");
    let session = cookie_value(&login, SESSION_COOKIE).expect("session cookie");

    // 2. The CMC rules page renders and carries a fresh CSRF pair for the POST.
    let page = client
        .get(format!("{base}/kraken_ui/auth/rule_management/cmc"))
        .header(header::COOKIE, format!("{SESSION_COOKIE}={session}"))
        .send()
        .await
        .expect("cmc page");
    assert_eq!(page.status(), reqwest::StatusCode::OK);
    let page_csrf = cookie_value(&page, CSRF_COOKIE).expect("page csrf cookie");
    let page_html = page.text().await.expect("cmc html");
    assert!(page_html.contains("List CMC rules"));
    let csrf_token = attribute_value(&page_html, "data-csrf-token=\"");

    // 3. The list proxy returns the WAF's modules, sorted, with a Rorschach token
    //    on the upstream request.
    let list = client
        .get(format!("{base}/kraken_ui/auth/api/rule_management/cmc"))
        .header(header::COOKIE, format!("{SESSION_COOKIE}={session}"))
        .send()
        .await
        .expect("list api");
    assert_eq!(list.status(), reqwest::StatusCode::OK);
    let list_body: Value = list.json().await.expect("list json");
    assert_eq!(
        list_body,
        json!({ "data": [
            { "name": "HPP_detect", "status": true },
            { "name": "Silent_sql_errors", "status": false },
        ] })
    );

    // 4. A forged CSRF token is rejected *before any action*: the request is
    //    refused with 403 and the WAF is never called.
    let forged = client
        .post(format!("{base}/kraken_ui/auth/rule_management/cmc/update"))
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={session}; {CSRF_COOKIE}={page_csrf}"),
        )
        .json(&json!({
            "csrf_token": "not-the-real-token",
            "modules": { "HPP_detect": true }
        }))
        .send()
        .await
        .expect("forged update request");
    assert_eq!(forged.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(
        captured.lock().expect("capture lock").update_body.is_none(),
        "CSRF must be validated before the WAF is contacted"
    );

    // 5. Submit a toggle with the valid token: enable Silent_sql_errors, disable
    //    HPP_detect.
    let update = client
        .post(format!("{base}/kraken_ui/auth/rule_management/cmc/update"))
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={session}; {CSRF_COOKIE}={page_csrf}"),
        )
        .json(&json!({
            "csrf_token": csrf_token,
            "modules": { "HPP_detect": false, "Silent_sql_errors": true }
        }))
        .send()
        .await
        .expect("update api");
    assert_eq!(update.status(), reqwest::StatusCode::OK);
    let update_body: Value = update.json().await.expect("update json");
    assert_eq!(
        update_body,
        json!({ "status": "ok", "enabled": ["Silent_sql_errors"], "disabled": ["HPP_detect"] })
    );

    // 6. The WAF saw Rorschach-authenticated requests and the documented body.
    let capture = captured.lock().expect("capture lock");
    let list_auth = capture.list_auth.as_deref().expect("list authorization");
    assert!(
        list_auth.starts_with("Bearer rch1.kraken-ui."),
        "unexpected list token: {list_auth}"
    );
    let update_auth = capture
        .update_auth
        .as_deref()
        .expect("update authorization");
    assert!(
        update_auth.starts_with("Bearer rch1.kraken-ui."),
        "unexpected update token: {update_auth}"
    );
    assert_eq!(
        capture.update_body.as_deref(),
        Some(r#"{"modules":{"CMC-Rules":{"HPP_detect":false,"Silent_sql_errors":true}}}"#)
    );
}
