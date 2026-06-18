//! Isolated, real-HTTP coverage of secret redaction on the single-attack detail
//! view (`/kraken_ui/auth/view_waf_request/`).
//!
//! This test stands up the full Kraken UI router over loopback, backed by a real
//! read-only WAF SQLite database seeded with one finding whose captured request
//! and response carry credentials (`password=...`, `token=...`, `senha=...`). It
//! then drives the page end to end with `reqwest`:
//!
//!   * an **administrator** sees the captured bytes in clear, and
//!   * an **operator** and an **auditor** (every non-admin console role) see every
//!     secret value replaced with `+++++`, while non-sensitive parameters stay
//!     visible.
//!
//! The UI router is served over plain HTTP (TLS is added by `main` in
//! production), so cookies are managed by hand rather than through reqwest's jar,
//! which would drop the `Secure` `__Host-` cookies over HTTP.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{Client, header};

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
const OPERATOR_PASSWORD: &str = "Operator-Console9Key";
const AUDITOR_PASSWORD: &str = "Watchful-Ledger4Read";
const SESSION_COOKIE: &str = "__Host-kraken_session";
const CSRF_COOKIE: &str = "__Host-kraken_csrf";

// The seeded finding's secret values, and the non-sensitive ones that must stay
// visible to every role.
const SECRET_PASSWORD: &str = "SuperSecret123";
const SECRET_TOKEN: &str = "ABCD-TOKEN-9999";
const SECRET_SENHA: &str = "minhaSenhaSecreta";
const VISIBLE_USER: &str = "alice";

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
            path: std::path::PathBuf::from("db/unused-view-waf-ratelimit.sqlite"),
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

/// Creates the read-only WAF SQLite the UI reads, with one finding whose request
/// and response evidence carry credentials. Mirrors the `vulnerabilities` table
/// the `vulnerability` SeaORM entity maps.
fn seed_waf_database(path: &std::path::Path) {
    let connection = rusqlite::Connection::open(path).expect("create WAF sqlite");
    connection
        .execute_batch(
            r#"
            CREATE TABLE vulnerabilities (
                id INTEGER PRIMARY KEY,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                cwe TEXT NOT NULL,
                description TEXT NOT NULL,
                reference_url TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                rule_match TEXT NOT NULL,
                rule_line_match TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                country TEXT NOT NULL,
                continent_name TEXT NOT NULL,
                http_method TEXT NOT NULL,
                request_uri TEXT NOT NULL,
                fullpath_evidence TEXT NOT NULL,
                engine TEXT NOT NULL,
                request_payload TEXT NOT NULL,
                request_id TEXT NOT NULL
            );
            "#,
        )
        .expect("create vulnerabilities table");
    connection
        .execute(
            "INSERT INTO vulnerabilities (
                id, title, severity, cwe, description, reference_url, occurred_at,
                rule_match, rule_line_match, client_ip, country, continent_name,
                http_method, request_uri, fullpath_evidence, engine, request_payload,
                request_id
            ) VALUES (
                1, 'Credential stuffing attempt', 'high', 'CWE-307', 'Brute force',
                'https://example.test/cwe-307', '2024-01-15T13:45:30Z',
                'cmc::auth:brute', 'line 7', '203.0.113.7', 'BR', 'South America',
                'POST', ?1, ?2, 'cmc', ?3, 'req-0001'
            )",
            rusqlite::params![
                format!("/login?token={SECRET_TOKEN}&user={VISIBLE_USER}"),
                format!("senha={SECRET_SENHA}"),
                format!("user={VISIBLE_USER}&password={SECRET_PASSWORD}&remember=1"),
            ],
        )
        .expect("insert seeded finding");
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
    let login = client
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
        login.status().is_redirection(),
        "login for {username} should redirect, got {}",
        login.status()
    );
    cookie_value(&login, SESSION_COOKIE).expect("session cookie")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn view_waf_request_masks_secrets_for_non_admins_only() {
    let directory = tempfile::tempdir().expect("temporary directory");
    // Leak the guard so the SQLite files outlive the spawned server.
    let directory = Box::leak(Box::new(directory));
    let waf_path = directory.path().join("waf-alerts.sqlite");
    seed_waf_database(&waf_path);

    let config = AppConfig {
        certificate_path: "unused-cert.pem".into(),
        private_key_path: "unused-key.pem".into(),
        listen: "127.0.0.1:3443".to_owned(),
        database_path: directory.path().join("kraken-ui.sqlite"),
        waf_database_path: Some(waf_path),
        waf_endpoint: "https://127.0.0.1:4343".to_owned(),
        waf_certificate_path: None,
        waf_rule_endpoint: None,
        waf_rule_certificate_path: None,
        log_directory: directory.path().to_path_buf(),
        session_timeout_minutes: 30,
    };

    // One shared crypto instance so the operator we create out-of-band verifies
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

    // Create a non-admin operator directly in the UI database (the bootstrap only
    // creates the admin). Login verifies it against the same crypto key.
    let ui_database = database::connect(&config.database_path)
        .await
        .expect("UI database connection");
    let operator_repository = OperatorRepository::new(ui_database, crypto);
    operator_repository
        .create(NewOperator {
            username: "operator1",
            email: "operator1@example.invalid",
            operator_type: "operator",
            password: OPERATOR_PASSWORD,
        })
        .await
        .expect("create operator");
    operator_repository
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
    let base = format!("http://{address}");

    // Generous timeout: the login path runs a real Argon2id (moderate) hash.
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .expect("reqwest client");

    let detail_url = format!("{base}/kraken_ui/auth/view_waf_request/?id=1");

    // 1. The administrator sees every captured byte in clear.
    let admin_session = login(&client, &base, "admin", ADMIN_PASSWORD).await;
    let admin_page = client
        .get(&detail_url)
        .header(header::COOKIE, format!("{SESSION_COOKIE}={admin_session}"))
        .send()
        .await
        .expect("admin detail page");
    assert_eq!(admin_page.status(), reqwest::StatusCode::OK);
    let admin_html = admin_page.text().await.expect("admin html");
    assert!(
        admin_html.contains(SECRET_PASSWORD),
        "admin must see the password value"
    );
    assert!(
        admin_html.contains(SECRET_TOKEN),
        "admin must see the token value"
    );
    assert!(
        admin_html.contains(SECRET_SENHA),
        "admin must see the senha value"
    );
    assert!(
        !admin_html.contains("+++++"),
        "nothing should be masked for the admin"
    );

    // 2. The operator (and, by the same guard, the reserved auditor role) sees
    //    every secret value masked, while non-sensitive parameters survive.
    let operator_session = login(&client, &base, "operator1", OPERATOR_PASSWORD).await;
    let operator_page = client
        .get(&detail_url)
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={operator_session}"),
        )
        .send()
        .await
        .expect("operator detail page");
    assert_eq!(operator_page.status(), reqwest::StatusCode::OK);
    let operator_html = operator_page.text().await.expect("operator html");
    assert!(
        operator_html.contains("+++++"),
        "the operator must see masked values"
    );
    assert!(
        !operator_html.contains(SECRET_PASSWORD),
        "the password value must not leak to the operator"
    );
    assert!(
        !operator_html.contains(SECRET_TOKEN),
        "the token value must not leak to the operator"
    );
    assert!(
        !operator_html.contains(SECRET_SENHA),
        "the senha value must not leak to the operator"
    );
    assert!(
        operator_html.contains(VISIBLE_USER),
        "non-sensitive parameters must remain visible to the operator"
    );

    // 3. The auditor — a first-class read-only console role — also sees every
    //    secret value masked, exactly as the operator does.
    let auditor_session = login(&client, &base, "auditor1", AUDITOR_PASSWORD).await;
    let auditor_page = client
        .get(&detail_url)
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={auditor_session}"),
        )
        .send()
        .await
        .expect("auditor detail page");
    assert_eq!(auditor_page.status(), reqwest::StatusCode::OK);
    let auditor_html = auditor_page.text().await.expect("auditor html");
    assert!(
        auditor_html.contains("+++++"),
        "the auditor must see masked values"
    );
    assert!(
        !auditor_html.contains(SECRET_PASSWORD),
        "the password value must not leak to the auditor"
    );
    assert!(
        !auditor_html.contains(SECRET_TOKEN),
        "the token value must not leak to the auditor"
    );
    assert!(
        !auditor_html.contains(SECRET_SENHA),
        "the senha value must not leak to the auditor"
    );
    assert!(
        auditor_html.contains(VISIBLE_USER),
        "non-sensitive parameters must remain visible to the auditor"
    );
}
