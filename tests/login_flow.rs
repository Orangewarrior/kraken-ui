//! End-to-end coverage of the authentication path: a real CSRF + session round
//! trip from the login page through a protected page to logout, driven over the
//! assembled router. This exercises the layers (CSRF, sessions, auth guard) and
//! the controllers together — the critical path where a regression is costly and
//! the unit tests, by design, cannot see the interaction.

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Request, StatusCode, header},
    response::Response,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use tower::ServiceExt;

use kraken_ui::{
    AppFactory,
    config::AppConfig,
    services::{
        password_crypto::DryocPasswordCryptoService,
        rate_limit::{BackendKind, RateLimitConfig, RedisConfig, SqliteConfig},
        waf_metrics::WafMetricsService,
    },
};

const ADMIN_PASSWORD: &str = "Reliable-Console9Key";
const PEER: &str = "127.0.0.1:50555";
const SESSION_COOKIE: &str = "__Host-kraken_session";
const CSRF_COOKIE: &str = "__Host-kraken_csrf";

/// A rate-limit configuration with the global limiter disabled, so the test
/// exercises authentication without the governor or the persistent SQLite
/// backend. The per-IP concurrency ceiling and request timeout are still built
/// from these values, so they must be sane.
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
            path: PathBuf::from("db/unused-login-flow-ratelimit.sqlite"),
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

fn connect_info() -> ConnectInfo<SocketAddr> {
    ConnectInfo(PEER.parse().expect("valid test peer"))
}

/// Percent-encodes a value for an `application/x-www-form-urlencoded` body. The
/// CSRF authenticity token is Base64 and routinely contains `+`, `/` and `=`,
/// which a form decoder would otherwise mistranslate (`+` becomes a space),
/// corrupting the token before it reaches the CSRF check.
fn form_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char)
            }
            other => encoded.push_str(&format!("%{other:02X}")),
        }
    }
    encoded
}

/// Returns the value of the first `Set-Cookie` header for `name`.
fn set_cookie(response: &Response, name: &str) -> Option<String> {
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

/// Extracts the hidden `csrf_token` form value from a rendered page.
fn csrf_token(html: &str) -> String {
    let marker = "name=\"csrf_token\" value=\"";
    let start = html.find(marker).expect("page must embed a csrf token") + marker.len();
    let end = html[start..].find('"').expect("csrf token must terminate");
    html[start..start + end].to_owned()
}

async fn body_string(response: Response) -> String {
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    String::from_utf8(bytes.to_vec()).expect("utf-8 response body")
}

fn location(response: &Response) -> Option<String> {
    response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

#[tokio::test]
async fn login_dashboard_logout_round_trip() {
    // A securely named temporary directory holds the UI database and logs; its
    // TempDir guard removes everything (including SQLite WAL sidecars) on drop.
    let directory = tempfile::tempdir().expect("temporary directory");

    let config = AppConfig {
        certificate_path: "unused-cert.pem".into(),
        private_key_path: "unused-key.pem".into(),
        listen: "127.0.0.1:3443".to_owned(),
        database_path: directory.path().join("kraken-ui.sqlite"),
        waf_database_path: None,
        waf_endpoint: "https://127.0.0.1:4343".to_owned(),
        waf_certificate_path: None,
        waf_rule_endpoint: None,
        waf_rule_certificate_path: None,
        log_directory: directory.path().to_path_buf(),
        session_timeout_minutes: 30,
        trusted_proxy_ips: Vec::new(),
    };

    // Real password crypto so the bootstrapped admin password actually verifies.
    let crypto = Arc::new(
        DryocPasswordCryptoService::from_base64_key("test-v1", &STANDARD.encode([9_u8; 32]))
            .expect("password crypto service"),
    );

    // SAFETY: this is the only test in this binary, so the process environment is
    // not shared with another concurrently running test.
    unsafe {
        std::env::set_var("KRAKEN_UI_ADMIN_PASSWORD", ADMIN_PASSWORD);
        std::env::set_var("KRAKEN_UI_ADMIN_EMAIL", "admin@example.invalid");
    }
    let app: Router = AppFactory::new(config)
        .with_password_crypto(crypto)
        .with_rate_limit_config(disabled_rate_limit())
        .with_waf_metrics(
            WafMetricsService::without_custom_ca("https://127.0.0.1:4343").expect("metrics client"),
        )
        .build()
        .await
        .expect("application must build");
    unsafe {
        std::env::remove_var("KRAKEN_UI_ADMIN_PASSWORD");
        std::env::remove_var("KRAKEN_UI_ADMIN_EMAIL");
    }

    // 1. GET the login page: capture the CSRF cookie and the matching token.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/kraken_ui/login")
                .extension(connect_info())
                .body(Body::empty())
                .expect("login page request"),
        )
        .await
        .expect("login page response");
    assert_eq!(response.status(), StatusCode::OK);
    let login_csrf_cookie = set_cookie(&response, CSRF_COOKIE).expect("login csrf cookie");
    let login_token = csrf_token(&body_string(response).await);

    // 2. POST the credentials: expect a redirect to the dashboard and a session.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/kraken_ui/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("{CSRF_COOKIE}={login_csrf_cookie}"))
                .extension(connect_info())
                .body(Body::from(format!(
                    "login=admin&password={}&csrf_token={}",
                    form_encode(ADMIN_PASSWORD),
                    form_encode(&login_token)
                )))
                .expect("login submit request"),
        )
        .await
        .expect("login submit response");
    assert!(
        response.status().is_redirection(),
        "login should redirect, got {}",
        response.status()
    );
    assert_eq!(
        location(&response).as_deref(),
        Some("/kraken_ui/auth/admin_panel")
    );
    let session_cookie = set_cookie(&response, SESSION_COOKIE).expect("session cookie");

    // 3. GET a protected page with the session cookie: it must render.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/kraken_ui/auth/admin_panel")
                .header(header::COOKIE, format!("{SESSION_COOKIE}={session_cookie}"))
                .extension(connect_info())
                .body(Body::empty())
                .expect("dashboard request"),
        )
        .await
        .expect("dashboard response");
    assert_eq!(response.status(), StatusCode::OK);
    let logout_csrf_cookie = set_cookie(&response, CSRF_COOKIE).expect("dashboard csrf cookie");
    let logout_token = csrf_token(&body_string(response).await);

    // 4. POST logout with the session and a fresh CSRF pair: redirect to login.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/kraken_ui/auth/logout")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    header::COOKIE,
                    format!(
                        "{SESSION_COOKIE}={session_cookie}; {CSRF_COOKIE}={logout_csrf_cookie}"
                    ),
                )
                .extension(connect_info())
                .body(Body::from(format!(
                    "csrf_token={}",
                    form_encode(&logout_token)
                )))
                .expect("logout request"),
        )
        .await
        .expect("logout response");
    assert!(response.status().is_redirection());
    assert_eq!(location(&response).as_deref(), Some("/kraken_ui/login"));

    // 5. The flushed session no longer authorises the protected page.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/kraken_ui/auth/admin_panel")
                .header(header::COOKIE, format!("{SESSION_COOKIE}={session_cookie}"))
                .extension(connect_info())
                .body(Body::empty())
                .expect("post-logout request"),
        )
        .await
        .expect("post-logout response");
    assert!(response.status().is_redirection());
    assert_eq!(location(&response).as_deref(), Some("/kraken_ui/login"));
}
