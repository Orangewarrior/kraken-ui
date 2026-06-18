//! Isolated, real-HTTP coverage of the regex rule editor.
//!
//! Two genuine loopback servers are stood up — a mock KrakenWAF rule-management
//! endpoint and the full Kraken UI router — and the feature is driven end to end
//! with `reqwest`: an administrator logs in, opens the rule picker, views a rule
//! list (whose content the UI fetches server-side via a Rorschach-authenticated
//! `POST /rule/control/regex/view`), and submits an edit (forwarded to
//! `POST /rule/control/regex/update/<name>`).
//!
//! It also pins the security properties the feature must hold: an empty file is
//! refused with an actionable message, a forged CSRF token is rejected before the
//! WAF is contacted, an auditor cannot authenticate to the console at all, and an
//! unauthenticated client is bounced from the editor routes.
//!
//! The UI router is served over plain HTTP (TLS is added by `main` in
//! production), so cookies are managed by hand rather than through reqwest's jar.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::post,
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
const AUDITOR_PASSWORD: &str = "Watchful-Ledger4Read";
const SESSION_COOKIE: &str = "__Host-kraken_session";
const CSRF_COOKIE: &str = "__Host-kraken_csrf";

/// A small, valid body_regex bundle the mock WAF returns from the view endpoint.
const SAMPLE_RULE: &str = r#"{
  "rules": [
    {
      "enable": 1,
      "http_action": "Request",
      "title": "Command injection separators body",
      "severity": "critical",
      "cwe": "CWE-78",
      "description": "Detects shell metacharacters.",
      "url": "https://cwe.mitre.org/data/definitions/78.html",
      "rule_match": "(?i)(?:;\\s*(?:wget|curl))",
      "id": "00001",
      "score": 1000
    }
  ]
}"#;

/// What the mock WAF recorded about the requests the UI sent it.
#[derive(Default)]
struct Captured {
    view_auth: Option<String>,
    view_body: Option<String>,
    update_auth: Option<String>,
    update_rule: Option<String>,
    update_body: Option<String>,
    update_count: usize,
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
            path: std::path::PathBuf::from("db/unused-regex-ratelimit.sqlite"),
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

async fn mock_regex_view(
    State(captured): State<Arc<Mutex<Captured>>>,
    headers: HeaderMap,
    body: String,
) -> Json<Value> {
    {
        let mut capture = captured.lock().expect("capture lock");
        capture.view_auth = authorization(&headers);
        capture.view_body = Some(body);
    }
    Json(json!({
        "status": "ok",
        "context": "regex_view",
        "rule": "body_regex",
        "content": SAMPLE_RULE,
    }))
}

async fn mock_regex_update(
    State(captured): State<Arc<Mutex<Captured>>>,
    Path(rule): Path<String>,
    headers: HeaderMap,
    body: String,
) -> Json<Value> {
    {
        let mut capture = captured.lock().expect("capture lock");
        capture.update_auth = authorization(&headers);
        capture.update_rule = Some(rule.clone());
        capture.update_body = Some(body);
        capture.update_count += 1;
    }
    Json(json!({
        "status": "ok",
        "context": "regex_update",
        "rule": rule,
        "rules_written": 1,
    }))
}

fn authorization(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

async fn spawn_mock_waf() -> (String, Arc<Mutex<Captured>>) {
    let captured = Arc::new(Mutex::new(Captured::default()));
    let app = Router::new()
        .route("/rule/control/regex/view", post(mock_regex_view))
        .route("/rule/control/regex/update/{rule}", post(mock_regex_update))
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

async fn spawn_kraken_ui(waf_url: &str) -> String {
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

fn attribute_value(html: &str, marker: &str) -> String {
    let start = html.find(marker).expect("attribute marker present") + marker.len();
    let end = html[start..].find('"').expect("attribute terminator");
    html[start..start + end].to_owned()
}

/// Logs in with the given credentials; returns the session cookie on success or
/// `None` when the console refused to authenticate the account.
async fn login(client: &Client, base: &str, user: &str, password: &str) -> Option<String> {
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
            ("login", user),
            ("password", password),
            ("csrf_token", &login_token),
        ])
        .send()
        .await
        .expect("login submit");
    cookie_value(&response, SESSION_COOKIE)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn regex_rules_view_and_update_round_trip() {
    let (waf_url, captured) = spawn_mock_waf().await;
    let base = spawn_kraken_ui(&waf_url).await;
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .expect("reqwest client");

    // 1. An unauthenticated client cannot reach the editor: it is redirected to
    //    the login page and the WAF is never contacted.
    let anonymous = client
        .get(format!(
            "{base}/kraken_ui/auth/rule_management/regex/edit?rule=body_regex"
        ))
        .send()
        .await
        .expect("anonymous edit request");
    assert!(
        anonymous.status().is_redirection(),
        "anonymous access must redirect, got {}",
        anonymous.status()
    );
    assert_eq!(
        captured.lock().expect("capture lock").view_auth,
        None,
        "the WAF must not be contacted for an unauthenticated request"
    );

    // 2. Log in as the bootstrapped administrator.
    let session = login(&client, &base, "admin", ADMIN_PASSWORD)
        .await
        .expect("admin session cookie");

    // 3. The rule picker renders with every allowlisted rule list.
    let picker = client
        .get(format!("{base}/kraken_ui/auth/rule_management/regex"))
        .header(header::COOKIE, format!("{SESSION_COOKIE}={session}"))
        .send()
        .await
        .expect("picker page");
    assert_eq!(picker.status(), reqwest::StatusCode::OK);
    let picker_html = picker.text().await.expect("picker html");
    assert!(picker_html.contains("Rule editor"));
    assert!(picker_html.contains("submit rule to edit"));
    for name in [
        "body_regex",
        "path_regex",
        "header_regex",
        "vectorscan_list",
        "scanners",
    ] {
        assert!(picker_html.contains(name), "picker should list rule {name}");
    }

    // 4. The editor for body_regex renders the content fetched from the WAF, the
    //    vendored ACE editor, and the mandatory ReDoS caution.
    let editor = client
        .get(format!(
            "{base}/kraken_ui/auth/rule_management/regex/edit?rule=body_regex"
        ))
        .header(header::COOKIE, format!("{SESSION_COOKIE}={session}"))
        .send()
        .await
        .expect("editor page");
    assert_eq!(editor.status(), reqwest::StatusCode::OK);
    let editor_csrf = cookie_value(&editor, CSRF_COOKIE).expect("editor csrf cookie");
    let editor_html = editor.text().await.expect("editor html");
    let csrf_token = attribute_value(&editor_html, "data-csrf-token=\"");
    assert!(editor_html.contains("/static/vendor/ace/ace.js"));
    assert!(editor_html.contains("Update rule"));
    assert!(editor_html.contains("take care with ReDOS"));
    // The rule content is present in a visible textarea; ACE is progressive
    // enhancement, so operators can still edit when the browser blocks it.
    assert!(editor_html.contains("Command injection separators body"));
    assert!(editor_html.contains(r#"<textarea id="rule-source" class="rule-source-editor""#));

    // The WAF view request carried a Rorschach token and the documented body.
    {
        let capture = captured.lock().expect("capture lock");
        let view_auth = capture.view_auth.as_deref().expect("view authorization");
        assert!(
            view_auth.starts_with("Bearer rch1.kraken-ui."),
            "unexpected view token: {view_auth}"
        );
        assert_eq!(
            capture.view_body.as_deref(),
            Some(r#"{"rule_view":"body_regex"}"#)
        );
    }

    // 5. An unknown rule name bounces back to the picker.
    let unknown = client
        .get(format!(
            "{base}/kraken_ui/auth/rule_management/regex/edit?rule=etc_passwd"
        ))
        .header(header::COOKIE, format!("{SESSION_COOKIE}={session}"))
        .send()
        .await
        .expect("unknown rule request");
    assert!(unknown.status().is_redirection());
    assert_eq!(
        unknown.headers().get(header::LOCATION).unwrap(),
        "/kraken_ui/auth/rule_management/regex"
    );

    // 6. A forged CSRF token is rejected before the WAF update is contacted.
    let forged = client
        .post(format!(
            "{base}/kraken_ui/auth/rule_management/regex/update?rule=body_regex"
        ))
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={session}; {CSRF_COOKIE}={editor_csrf}"),
        )
        .json(&json!({ "csrf_token": "not-the-real-token", "content": SAMPLE_RULE }))
        .send()
        .await
        .expect("forged update");
    assert_eq!(forged.status(), reqwest::StatusCode::FORBIDDEN);
    assert_eq!(
        captured.lock().expect("capture lock").update_count,
        0,
        "CSRF must be validated before the WAF is contacted"
    );

    // 7. An empty file is refused with an actionable message, before the WAF.
    let empty = client
        .post(format!(
            "{base}/kraken_ui/auth/rule_management/regex/update?rule=body_regex"
        ))
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={session}; {CSRF_COOKIE}={editor_csrf}"),
        )
        .json(&json!({ "csrf_token": csrf_token, "content": "   \n  " }))
        .send()
        .await
        .expect("empty update");
    assert_eq!(empty.status(), reqwest::StatusCode::BAD_REQUEST);
    let empty_body: Value = empty.json().await.expect("empty json");
    assert_eq!(empty_body["error"], "The rule file cannot be empty.");
    assert_eq!(
        captured.lock().expect("capture lock").update_count,
        0,
        "an empty file must never reach the WAF"
    );

    // 8. A missing required field is reported with its rule index and field name.
    let invalid = client
        .post(format!(
            "{base}/kraken_ui/auth/rule_management/regex/update?rule=body_regex"
        ))
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={session}; {CSRF_COOKIE}={editor_csrf}"),
        )
        .json(&json!({
            "csrf_token": csrf_token,
            "content": r#"{"rules":[{"enable":1}]}"#
        }))
        .send()
        .await
        .expect("invalid update");
    assert_eq!(invalid.status(), reqwest::StatusCode::BAD_REQUEST);
    let invalid_body: Value = invalid.json().await.expect("invalid json");
    assert_eq!(
        invalid_body["error"],
        "Rule #1 is missing the required \"http_action\" field."
    );

    // 9. A valid edit is forwarded to the WAF on the documented path and body.
    let update = client
        .post(format!(
            "{base}/kraken_ui/auth/rule_management/regex/update?rule=body_regex"
        ))
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={session}; {CSRF_COOKIE}={editor_csrf}"),
        )
        .json(&json!({ "csrf_token": csrf_token, "content": SAMPLE_RULE }))
        .send()
        .await
        .expect("valid update");
    assert_eq!(update.status(), reqwest::StatusCode::OK);
    let update_body: Value = update.json().await.expect("update json");
    assert_eq!(
        update_body,
        json!({ "status": "ok", "rule": "body_regex", "rules_written": 1 })
    );

    {
        let capture = captured.lock().expect("capture lock");
        assert_eq!(capture.update_count, 1);
        assert_eq!(capture.update_rule.as_deref(), Some("body_regex"));
        let update_auth = capture
            .update_auth
            .as_deref()
            .expect("update authorization");
        assert!(
            update_auth.starts_with("Bearer rch1.kraken-ui."),
            "unexpected update token: {update_auth}"
        );
        // The exact (trimmed) editor bytes are written to the rule file.
        assert_eq!(capture.update_body.as_deref(), Some(SAMPLE_RULE.trim()));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auditor_cannot_authenticate_or_reach_the_regex_editor() {
    let (waf_url, captured) = spawn_mock_waf().await;
    let base = spawn_kraken_ui(&waf_url).await;
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .expect("reqwest client");

    // The administrator provisions an auditor account.
    let session = login(&client, &base, "admin", ADMIN_PASSWORD)
        .await
        .expect("admin session cookie");
    let add_page = client
        .get(format!("{base}/kraken_ui/auth/insert_user"))
        .header(header::COOKIE, format!("{SESSION_COOKIE}={session}"))
        .send()
        .await
        .expect("add user page");
    let add_csrf = cookie_value(&add_page, CSRF_COOKIE).expect("add csrf cookie");
    let add_token = attribute_value(
        &add_page.text().await.expect("add html"),
        "name=\"csrf_token\" value=\"",
    );
    let created = client
        .post(format!("{base}/kraken_ui/auth/insert_user_action"))
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={session}; {CSRF_COOKIE}={add_csrf}"),
        )
        .form(&[
            ("username", "auditor1"),
            ("email", "auditor1@example.invalid"),
            ("user_type", "auditor"),
            ("password", AUDITOR_PASSWORD),
            ("csrf_token", &add_token),
        ])
        .send()
        .await
        .expect("create auditor");
    assert!(
        created.status().is_success() || created.status().is_redirection(),
        "auditor creation should succeed, got {}",
        created.status()
    );

    // The auditor's correct credentials do not yield a session: the console only
    // admits admins and operators, so an auditor can never view or edit rules.
    let auditor_session = login(&client, &base, "auditor1", AUDITOR_PASSWORD).await;
    assert!(
        auditor_session.is_none(),
        "an auditor must not receive a console session"
    );

    // And with no session, the editor routes redirect to login without ever
    // contacting the WAF.
    for path in [
        "/kraken_ui/auth/rule_management/regex",
        "/kraken_ui/auth/rule_management/regex/edit?rule=body_regex",
    ] {
        let response = client
            .get(format!("{base}{path}"))
            .send()
            .await
            .expect("guarded request");
        assert!(
            response.status().is_redirection(),
            "{path} must redirect an unauthenticated client"
        );
    }
    assert_eq!(
        captured.lock().expect("capture lock").view_auth,
        None,
        "the WAF must never be contacted for an unauthorised client"
    );
}
