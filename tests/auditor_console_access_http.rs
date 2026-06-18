//! Isolated, real-HTTP coverage of the auditor role's console boundary.
//!
//! The full Kraken UI router is stood up over loopback and driven end to end with
//! `reqwest`. An auditor account is created directly in the UI database, signs in
//! over real HTTP, and the test pins exactly which routes the read-only role may
//! reach and which it may not:
//!
//!   * **Allowed** (HTTP 200, never a redirect to login): the dashboard, the
//!     attacks monitor table and the self-service account pages (password and
//!     two-factor). The single-attack detail view is reachable too (it answers
//!     `503` here only because no WAF database is configured — crucially, it is
//!     *not* bounced to login).
//!   * **Denied** (redirected to `/kraken_ui/login`): every administrator surface
//!     (ACL, updates) and every operator surface (rule management). The guard
//!     fails closed regardless of what the sidebar advertises.
//!
//! The UI router is served over plain HTTP (TLS is added by `main` in
//! production), so cookies are managed by hand rather than through reqwest's jar,
//! which would drop the `Secure` `__Host-` cookies over HTTP.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{Client, StatusCode, header};

use kraken_ui::{
    AppFactory,
    config::AppConfig,
    models::{
        database,
        operator_repository::{NewOperator, OperatorRepository},
    },
    services::{
        password_crypto::DryocPasswordCryptoService,
        rate_limit::{BackendKind, RateLimitConfig, RedisConfig, SqliteConfig},
        waf_metrics::WafMetricsService,
    },
};

const ADMIN_PASSWORD: &str = "Reliable-Console9Key";
const AUDITOR_PASSWORD: &str = "Watchful-Ledger4Read";
const SESSION_COOKIE: &str = "__Host-kraken_session";
const CSRF_COOKIE: &str = "__Host-kraken_csrf";

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
            path: std::path::PathBuf::from("db/unused-auditor-ratelimit.sqlite"),
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

fn attribute_value(html: &str, marker: &str) -> String {
    let start = html.find(marker).expect("attribute marker present") + marker.len();
    let end = html[start..].find('"').expect("attribute terminator");
    html[start..start + end].to_owned()
}

/// Logs in as `username`/`password` over real HTTP and returns the session cookie.
async fn login(client: &Client, base: &str, username: &str, password: &str) -> String {
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
    let response = client
        .post(format!("{base}/kraken_ui/login"))
        .header(header::COOKIE, format!("{CSRF_COOKIE}={login_csrf}"))
        .form(&[
            ("login", username),
            ("password", password),
            ("csrf_token", &login_token),
        ])
        .send()
        .await
        .expect("login submit");
    assert!(
        response.status().is_redirection(),
        "login for {username} should redirect, got {}",
        response.status()
    );
    cookie_value(&response, SESSION_COOKIE).expect("session cookie")
}

/// Spawns the full Kraken UI router (no WAF database) and seeds an auditor
/// account, returning the base URL.
async fn spawn_kraken_ui() -> String {
    let directory = tempfile::tempdir().expect("temporary directory");
    let directory = Box::leak(Box::new(directory));

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
    };

    // One shared crypto instance so the auditor we create out-of-band verifies
    // against the same key the app uses on login.
    let crypto = Arc::new(
        DryocPasswordCryptoService::from_base64_key("test-v1", &STANDARD.encode([9_u8; 32]))
            .expect("password crypto service"),
    );

    // SAFETY: this is the only test in this binary, so no other test races the
    // process environment.
    unsafe {
        std::env::set_var("KRAKEN_UI_ADMIN_PASSWORD", ADMIN_PASSWORD);
        std::env::set_var("KRAKEN_UI_ADMIN_EMAIL", "admin@example.invalid");
    }
    let app = AppFactory::new(config.clone())
        .with_password_crypto(crypto.clone())
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

    let ui_database = database::connect(&config.database_path)
        .await
        .expect("UI database connection");
    OperatorRepository::new(ui_database, crypto)
        .create(NewOperator {
            username: "auditor1",
            email: "auditor1@example.invalid",
            operator_type: "auditor",
            password: AUDITOR_PASSWORD,
        })
        .await
        .expect("create auditor");

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auditor_reaches_only_the_read_only_console_surface() {
    let base = spawn_kraken_ui().await;
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .expect("reqwest client");

    let session = login(&client, &base, "auditor1", AUDITOR_PASSWORD).await;
    let cookie = format!("{SESSION_COOKIE}={session}");

    // Pages within the auditor's remit render normally (never a redirect to
    // login). The dashboard, attacks table and self-service account pages all
    // answer 200.
    for path in [
        "/kraken_ui/auth/dashboard",
        "/kraken_ui/auth/admin_panel",
        "/kraken_ui/auth/show_attacks",
        "/kraken_ui/auth/update_password",
        "/kraken_ui/auth/mfa",
    ] {
        let response = client
            .get(format!("{base}{path}"))
            .header(header::COOKIE, &cookie)
            .send()
            .await
            .expect("allowed request");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "{path} must be reachable by an auditor"
        );
    }

    // The single-attack detail view is authorised for the auditor: with no WAF
    // database configured it answers 503, which proves the guard let the auditor
    // through rather than bouncing them to login.
    let detail = client
        .get(format!("{base}/kraken_ui/auth/view_waf_request/?id=1"))
        .header(header::COOKIE, &cookie)
        .send()
        .await
        .expect("detail request");
    assert_eq!(
        detail.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "the detail view must be authorised (503 without a WAF db), not redirected"
    );

    // Every administrator and operator surface is denied: the guard redirects the
    // auditor to the login page.
    for path in [
        // Administrator (ACL + updates).
        "/kraken_ui/auth/insert_user",
        "/kraken_ui/auth/show_user_table",
        "/kraken_ui/auth/delete_user",
        "/kraken_ui/auth/edit_user",
        "/kraken_ui/auth/update_kraken_ui",
        "/kraken_ui/auth/api/operators",
        // Operator (rule management).
        "/kraken_ui/auth/rule_management/cmc",
        "/kraken_ui/auth/rule_management/regex",
        "/kraken_ui/auth/api/rule_management/cmc",
    ] {
        let response = client
            .get(format!("{base}{path}"))
            .header(header::COOKIE, &cookie)
            .send()
            .await
            .expect("denied request");
        assert!(
            response.status().is_redirection(),
            "{path} must be denied to an auditor, got {}",
            response.status()
        );
        assert_eq!(
            response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/kraken_ui/login"),
            "{path} must redirect the auditor to the login page"
        );
    }
}
