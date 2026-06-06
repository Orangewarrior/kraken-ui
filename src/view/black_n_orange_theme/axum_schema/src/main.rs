use askama::Template;
use axum::{
    extract::{Path, Query},
    http::{HeaderName, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    Json, Router,
};
use serde::Serialize;
use std::{collections::HashMap, net::SocketAddr};
use tower_http::{
    services::ServeDir,
    set_header::SetResponseHeaderLayer,
    trace::TraceLayer,
};

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests";
const DEMO_CSRF: &str = "replace-with-server-generated-token";

#[derive(Clone)]
struct FeatureCard { icon: &'static str, title: &'static str, body: &'static str }

#[derive(Clone)]
struct MetricCard { title: &'static str, value: &'static str, delta: &'static str, chart_key: &'static str, negative: bool }

#[derive(Clone, Serialize)]
struct AlertRow { time: &'static str, method: &'static str, url: &'static str, ip: &'static str, country: &'static str, status: u16, rule: &'static str, severity: &'static str, severity_class: &'static str, action: &'static str }

#[derive(Clone)]
struct RoleOption { value: &'static str, label: &'static str }

#[derive(Clone, Serialize)]
struct UserRow { id: u64, username: &'static str, email: &'static str, user_type: &'static str, status: &'static str, created_at: &'static str, edit_url: String, delete_url: String }

#[derive(Clone, Serialize)]
struct AttackRow { id: u64, time: &'static str, ip: &'static str, method: &'static str, url: &'static str, rule: &'static str, severity: &'static str, action: &'static str, view_url: String }

#[derive(Template)]
#[template(path = "index.htmlx", ext = "html", escape = "html")]
struct IndexTemplate { product_name: &'static str, active_page: &'static str, features: Vec<FeatureCard>, metrics: Vec<MetricCard>, alerts: Vec<AlertRow> }

#[derive(Template)]
#[template(path = "dashboard.html", escape = "html")]
struct DashboardTemplate { product_name: &'static str, active_page: &'static str, metrics: Vec<MetricCard>, alerts: Vec<AlertRow> }

#[derive(Template)]
#[template(path = "login.htmlx", ext = "html", escape = "html")]
struct LoginTemplate { product_name: &'static str, csrf_token: &'static str, error_message: &'static str }

#[derive(Template)]
#[template(path = "acl.htmlx", ext = "html", escape = "html")]
struct AclTemplate { product_name: &'static str }

#[derive(Template)]
#[template(path = "add_user.htmlx", ext = "html", escape = "html")]
struct AddUserTemplate { product_name: &'static str, csrf_token: &'static str, roles: Vec<RoleOption> }

#[derive(Template)]
#[template(path = "edit_user.htmlx", ext = "html", escape = "html")]
struct EditUserTemplate { product_name: &'static str, csrf_token: &'static str, roles: Vec<RoleOption>, user_id: u64, username: &'static str, email: &'static str, user_type: &'static str }

#[derive(Template)]
#[template(path = "delete_user.htmlx", ext = "html", escape = "html")]
struct DeleteUserTemplate { product_name: &'static str, csrf_token: &'static str, user_id: String, email: String }

#[derive(Template)]
#[template(path = "update_data_operator.htmlx", ext = "html", escape = "html")]
struct UpdateDataOperatorTemplate { product_name: &'static str, csrf_token: &'static str, email: &'static str }

#[derive(Template)]
#[template(path = "audit_update_data.htmlx", ext = "html", escape = "html")]
struct AuditUpdateDataTemplate { product_name: &'static str, csrf_token: &'static str, email: &'static str }

#[derive(Template)]
#[template(path = "show_user_table.htmlx", ext = "html", escape = "html")]
struct ShowUserTableTemplate { product_name: &'static str }

#[derive(Template)]
#[template(path = "show_attacks.htmlx", ext = "html", escape = "html")]
struct ShowAttacksTemplate { product_name: &'static str }

#[derive(Template)]
#[template(path = "attack_evidence.htmlx", ext = "html", escape = "html")]
struct AttackEvidenceTemplate { product_name: &'static str, attack_id: u64, title: &'static str, subtitle: &'static str, evidence: &'static str }

#[derive(Serialize)]
struct PagedData<T: Serialize> { draw: u64, #[serde(rename = "recordsTotal")] records_total: usize, #[serde(rename = "recordsFiltered")] records_filtered: usize, data: Vec<T> }

#[derive(Serialize)]
struct PagedAlerts { page: usize, page_size: usize, records_total: usize, records_filtered: usize, data: Vec<AlertRow> }

#[derive(Serialize)]
struct SummaryMetrics { requests_per_second: u64, blocked_requests: u64, allowed_requests: u64, error_rate: f32 }

fn role_options() -> Vec<RoleOption> { vec![RoleOption { value: "operator", label: "Operator" }, RoleOption { value: "admin", label: "Admin" }, RoleOption { value: "auditor", label: "Auditor" }] }

fn feature_cards() -> Vec<FeatureCard> { vec![FeatureCard { icon: "inspect", title: "Real-time Inspection", body: "Inspect and analyze every HTTP request in real time with a high-performance Rust engine." }, FeatureCard { icon: "shield", title: "ACL Control", body: "Manage IP allowlists, blocklists, and rate limits to control who can access your apps." }, FeatureCard { icon: "warning", title: "Threat Detection", body: "Detect SQLi, XSS, LFI, RCE and other common attack patterns using managed rules." }, FeatureCard { icon: "audit", title: "Audit Logging", body: "Comprehensive logs for alerts, requests, and admin actions with tamper-resistant records." }, FeatureCard { icon: "rules", title: "Rule Engine", body: "Powerful, extensible rule engine with support for custom and regex-based rules." }, FeatureCard { icon: "speed", title: "Rate Limiting", body: "Protect resources and stop abuse with flexible per-IP and per-route rate limiting." }] }

fn metrics() -> Vec<MetricCard> { vec![MetricCard { title: "Requests/sec", value: "2,842", delta: "↑ 18.7%", chart_key: "requests", negative: false }, MetricCard { title: "Blocked Requests", value: "482", delta: "↑ 32.4%", chart_key: "blocked", negative: true }, MetricCard { title: "Allowed Requests", value: "18,392", delta: "↑ 12.1%", chart_key: "allowed", negative: false }, MetricCard { title: "Error Rate", value: "1.23%", delta: "↑ 0.35%", chart_key: "errors", negative: true }] }

fn alerts() -> Vec<AlertRow> { vec![AlertRow { time: "18:43:01", method: "GET", url: "/api/users?role=admin", ip: "203.0.113.45", country: "US", status: 403, rule: "SQLi Detected", severity: "High", severity_class: "high", action: "Blocked" }, AlertRow { time: "18:42:31", method: "POST", url: "/login", ip: "198.51.100.23", country: "DE", status: 403, rule: "XSS Detected", severity: "High", severity_class: "high", action: "Blocked" }, AlertRow { time: "18:42:03", method: "GET", url: "/search?q=test", ip: "203.0.113.200", country: "IN", status: 200, rule: "-", severity: "Low", severity_class: "low", action: "Allowed" }, AlertRow { time: "18:41:50", method: "GET", url: "/admin", ip: "192.0.2.55", country: "GB", status: 403, rule: "RCE Attempt", severity: "High", severity_class: "high", action: "Blocked" }, AlertRow { time: "18:41:29", method: "GET", url: "/assets/app.js", ip: "198.51.100.77", country: "SG", status: 200, rule: "-", severity: "Low", severity_class: "low", action: "Allowed" }, AlertRow { time: "18:40:22", method: "POST", url: "/xmlrpc.php", ip: "203.0.113.91", country: "BR", status: 403, rule: "Brute Force", severity: "Medium", severity_class: "medium", action: "Blocked" }, AlertRow { time: "18:39:18", method: "GET", url: "/wp-admin", ip: "198.51.100.89", country: "FR", status: 403, rule: "ACL Blocklist", severity: "Medium", severity_class: "medium", action: "Blocked" }, AlertRow { time: "18:38:42", method: "GET", url: "/health", ip: "192.0.2.100", country: "CA", status: 200, rule: "-", severity: "Low", severity_class: "low", action: "Allowed" }] }

fn users() -> Vec<UserRow> {
    vec![
        UserRow { id: 1, username: "admin01", email: "admin01@example.local", user_type: "admin", status: "active", created_at: "2026-05-02", edit_url: "/acl/users/edit/1".into(), delete_url: "/acl/users/delete?user_id=1".into() },
        UserRow { id: 2, username: "operator02", email: "operator02@example.local", user_type: "operator", status: "active", created_at: "2026-05-03", edit_url: "/acl/users/edit/2".into(), delete_url: "/acl/users/delete?user_id=2".into() },
        UserRow { id: 3, username: "auditor03", email: "auditor03@example.local", user_type: "auditor", status: "active", created_at: "2026-05-04", edit_url: "/acl/users/edit/3".into(), delete_url: "/acl/users/delete?user_id=3".into() },
        UserRow { id: 4, username: "operator04", email: "operator04@example.local", user_type: "operator", status: "locked", created_at: "2026-05-05", edit_url: "/acl/users/edit/4".into(), delete_url: "/acl/users/delete?user_id=4".into() },
        UserRow { id: 5, username: "auditor05", email: "auditor05@example.local", user_type: "auditor", status: "pending", created_at: "2026-05-06", edit_url: "/acl/users/edit/5".into(), delete_url: "/acl/users/delete?user_id=5".into() },
        UserRow { id: 6, username: "admin06", email: "admin06@example.local", user_type: "admin", status: "active", created_at: "2026-05-07", edit_url: "/acl/users/edit/6".into(), delete_url: "/acl/users/delete?user_id=6".into() },
        UserRow { id: 7, username: "operator07", email: "operator07@example.local", user_type: "operator", status: "active", created_at: "2026-05-08", edit_url: "/acl/users/edit/7".into(), delete_url: "/acl/users/delete?user_id=7".into() },
        UserRow { id: 8, username: "auditor08", email: "auditor08@example.local", user_type: "auditor", status: "active", created_at: "2026-05-09", edit_url: "/acl/users/edit/8".into(), delete_url: "/acl/users/delete?user_id=8".into() },
        UserRow { id: 9, username: "operator09", email: "operator09@example.local", user_type: "operator", status: "active", created_at: "2026-05-10", edit_url: "/acl/users/edit/9".into(), delete_url: "/acl/users/delete?user_id=9".into() },
        UserRow { id: 10, username: "auditor10", email: "auditor10@example.local", user_type: "auditor", status: "locked", created_at: "2026-05-11", edit_url: "/acl/users/edit/10".into(), delete_url: "/acl/users/delete?user_id=10".into() },
        UserRow { id: 11, username: "admin11", email: "admin11@example.local", user_type: "admin", status: "active", created_at: "2026-05-12", edit_url: "/acl/users/edit/11".into(), delete_url: "/acl/users/delete?user_id=11".into() },
        UserRow { id: 12, username: "operator12", email: "operator12@example.local", user_type: "operator", status: "pending", created_at: "2026-05-13", edit_url: "/acl/users/edit/12".into(), delete_url: "/acl/users/delete?user_id=12".into() },
    ]
}

fn attacks() -> Vec<AttackRow> {
    vec![
        AttackRow { id: 1, time: "2026-06-02 18:43:01", ip: "203.0.113.45", method: "GET", url: "/api/users?role=admin", rule: "SQLi Detected", severity: "high", action: "Blocked", view_url: "/attacks/evidence/1".into() },
        AttackRow { id: 2, time: "2026-06-02 18:42:31", ip: "198.51.100.23", method: "POST", url: "/login", rule: "XSS Detected", severity: "high", action: "Blocked", view_url: "/attacks/evidence/2".into() },
        AttackRow { id: 3, time: "2026-06-02 18:42:03", ip: "203.0.113.200", method: "GET", url: "/search?q=test", rule: "LFI Detected", severity: "medium", action: "Blocked", view_url: "/attacks/evidence/3".into() },
        AttackRow { id: 4, time: "2026-06-02 18:41:50", ip: "192.0.2.55", method: "GET", url: "/admin", rule: "RCE Attempt", severity: "critical", action: "Blocked", view_url: "/attacks/evidence/4".into() },
        AttackRow { id: 5, time: "2026-06-02 18:41:29", ip: "198.51.100.77", method: "GET", url: "/assets/app.js", rule: "Bad Bot", severity: "low", action: "Challenge", view_url: "/attacks/evidence/5".into() },
        AttackRow { id: 6, time: "2026-06-02 18:40:22", ip: "203.0.113.91", method: "POST", url: "/xmlrpc.php", rule: "Brute Force", severity: "medium", action: "Blocked", view_url: "/attacks/evidence/6".into() },
        AttackRow { id: 7, time: "2026-06-02 18:39:18", ip: "198.51.100.89", method: "GET", url: "/wp-admin", rule: "ACL Blocklist", severity: "medium", action: "Blocked", view_url: "/attacks/evidence/7".into() },
        AttackRow { id: 8, time: "2026-06-02 18:38:42", ip: "192.0.2.100", method: "GET", url: "/health", rule: "-", severity: "low", action: "Allowed", view_url: "/attacks/evidence/8".into() },
        AttackRow { id: 9, time: "2026-06-02 18:37:19", ip: "203.0.113.65", method: "PUT", url: "/api/rules", rule: "Unauthorized Admin API", severity: "high", action: "Blocked", view_url: "/attacks/evidence/9".into() },
        AttackRow { id: 10, time: "2026-06-02 18:36:11", ip: "198.51.100.88", method: "GET", url: "/../../etc/passwd", rule: "Path Traversal", severity: "critical", action: "Blocked", view_url: "/attacks/evidence/10".into() },
    ]
}

fn render<T: Template>(template: T) -> Response { match template.render() { Ok(html) => Html(html).into_response(), Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Template rendering failed: {error}")).into_response() } }

async fn index() -> Response { render(IndexTemplate { product_name: "KrakenWaf", active_page: "dashboard", features: feature_cards(), metrics: metrics(), alerts: alerts().into_iter().take(5).collect() }) }
async fn dashboard() -> Response { render(DashboardTemplate { product_name: "KrakenWaf", active_page: "dashboard", metrics: metrics(), alerts: alerts() }) }
async fn login() -> Response { render(LoginTemplate { product_name: "KrakenWaf", csrf_token: DEMO_CSRF, error_message: "" }) }
async fn login_submit() -> Redirect { Redirect::to("/dashboard") }
async fn acl() -> Response { render(AclTemplate { product_name: "KrakenWaf" }) }
async fn add_user() -> Response { render(AddUserTemplate { product_name: "KrakenWaf", csrf_token: DEMO_CSRF, roles: role_options() }) }
async fn edit_user(Path(user_id): Path<u64>) -> Response { let user = users().into_iter().find(|u| u.id == user_id).unwrap_or_else(|| UserRow { id: user_id, username: "unknown", email: "unknown@example.local", user_type: "operator", status: "pending", created_at: "2026-06-02", edit_url: format!("/acl/users/edit/{user_id}"), delete_url: format!("/acl/users/delete?user_id={user_id}") }); render(EditUserTemplate { product_name: "KrakenWaf", csrf_token: DEMO_CSRF, roles: role_options(), user_id: user.id, username: user.username, email: user.email, user_type: user.user_type }) }
async fn delete_user(Query(params): Query<HashMap<String, String>>) -> Response { render(DeleteUserTemplate { product_name: "KrakenWaf", csrf_token: DEMO_CSRF, user_id: params.get("user_id").cloned().unwrap_or_default(), email: params.get("email").cloned().unwrap_or_default() }) }
async fn operator_update() -> Response { render(UpdateDataOperatorTemplate { product_name: "KrakenWaf", csrf_token: DEMO_CSRF, email: "operator@example.local" }) }
async fn auditor_update() -> Response { render(AuditUpdateDataTemplate { product_name: "KrakenWaf", csrf_token: DEMO_CSRF, email: "auditor@example.local" }) }
async fn show_user_table() -> Response { render(ShowUserTableTemplate { product_name: "KrakenWaf" }) }
async fn show_attacks() -> Response { render(ShowAttacksTemplate { product_name: "KrakenWaf" }) }
async fn attack_evidence(Path(attack_id): Path<u64>) -> Response { let title = "HTTP request / response evidence"; let subtitle = "Captured WAF evidence. Replace demo data with persisted attack evidence loaded by ID."; let evidence = "GET /api/users?role=admin%27%20OR%201=1-- HTTP/1.1\nHost: app.example.local\nUser-Agent: sqlmap/1.8\nAccept: */*\nX-Forwarded-For: 203.0.113.45\n\nHTTP/1.1 403 Forbidden\nContent-Type: application/json\nX-KrakenWaf-Rule: SQLi Detected\n\n{\"blocked\":true,\"rule\":\"SQLi Detected\",\"severity\":\"high\"}"; render(AttackEvidenceTemplate { product_name: "KrakenWaf", attack_id, title, subtitle, evidence }) }
async fn post_redirect_acl() -> Redirect { Redirect::to("/acl") }
async fn post_redirect_users() -> Redirect { Redirect::to("/acl/users") }

async fn api_summary() -> Json<SummaryMetrics> { Json(SummaryMetrics { requests_per_second: 2842, blocked_requests: 482, allowed_requests: 18_392, error_rate: 1.23 }) }

async fn api_alerts(Query(params): Query<HashMap<String, String>>) -> Json<PagedAlerts> {
    let page_size = params.get("page_size").and_then(|v| v.parse::<usize>().ok()).unwrap_or(6).clamp(1, 50);
    let page = params.get("page").and_then(|v| v.parse::<usize>().ok()).unwrap_or(1).max(1);
    let search = params.get("search").cloned().unwrap_or_default().to_lowercase();
    let all = alerts();
    let filtered: Vec<AlertRow> = all.iter().cloned().filter(|row| search.is_empty() || format!("{} {} {} {} {} {} {}", row.time, row.method, row.url, row.ip, row.country, row.rule, row.action).to_lowercase().contains(&search)).collect();
    let start = page.saturating_sub(1) * page_size;
    let data = filtered.iter().cloned().skip(start).take(page_size).collect();
    Json(PagedAlerts { page, page_size, records_total: all.len(), records_filtered: filtered.len(), data })
}

fn datatable_params(params: &HashMap<String, String>) -> (u64, usize, usize, String) {
    let draw = params.get("draw").and_then(|v| v.parse::<u64>().ok()).unwrap_or(1);
    let start = params.get("start").and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);
    let length = params.get("length").and_then(|v| v.parse::<usize>().ok()).unwrap_or(10).clamp(1, 100);
    let search = params.get("search[value]").or_else(|| params.get("search")).cloned().unwrap_or_default().to_lowercase();
    (draw, start, length, search)
}

async fn api_users(Query(params): Query<HashMap<String, String>>) -> Json<PagedData<UserRow>> {
    let (draw, start, length, search) = datatable_params(&params);
    let all = users();
    let filtered: Vec<UserRow> = all.iter().cloned().filter(|u| search.is_empty() || format!("{} {} {} {} {}", u.id, u.username, u.email, u.user_type, u.status).to_lowercase().contains(&search)).collect();
    let data = filtered.iter().cloned().skip(start).take(length).collect();
    Json(PagedData { draw, records_total: all.len(), records_filtered: filtered.len(), data })
}

async fn api_attacks(Query(params): Query<HashMap<String, String>>) -> Json<PagedData<AttackRow>> {
    let (draw, start, length, search) = datatable_params(&params);
    let all = attacks();
    let filtered: Vec<AttackRow> = all.iter().cloned().filter(|a| search.is_empty() || format!("{} {} {} {} {} {} {}", a.id, a.time, a.ip, a.method, a.url, a.rule, a.severity).to_lowercase().contains(&search)).collect();
    let data = filtered.iter().cloned().skip(start).take(length).collect();
    Json(PagedData { draw, records_total: all.len(), records_filtered: filtered.len(), data })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter("krakenwaf_ui_template=info,tower_http=info").init();
    let app = Router::new()
        .route("/", get(index))
        .route("/login", get(login).post(login_submit))
        .route("/dashboard", get(dashboard))
        .route("/acl", get(acl))
        .route("/acl/users", get(show_user_table))
        .route("/acl/users/add", get(add_user).post(post_redirect_users))
        .route("/acl/users/edit/{user_id}", get(edit_user).post(post_redirect_users))
        .route("/acl/users/delete", get(delete_user).post(post_redirect_acl))
        .route("/operator/update", get(operator_update).post(post_redirect_acl))
        .route("/auditor/update", get(auditor_update).post(post_redirect_acl))
        .route("/attacks", get(show_attacks))
        .route("/attacks/evidence/{attack_id}", get(attack_evidence))
        .route("/api/metrics/summary", get(api_summary))
        .route("/api/alerts", get(api_alerts))
        .route("/api/users", get(api_users))
        .route("/api/attacks", get(api_attacks))
        .nest_service("/static", ServeDir::new("static"))
        .layer(TraceLayer::new_for_http())
        .layer(SetResponseHeaderLayer::if_not_present(HeaderName::from_static("content-security-policy"), HeaderValue::from_static(CSP)))
        .layer(SetResponseHeaderLayer::if_not_present(HeaderName::from_static("x-content-type-options"), HeaderValue::from_static("nosniff")))
        .layer(SetResponseHeaderLayer::if_not_present(HeaderName::from_static("referrer-policy"), HeaderValue::from_static("no-referrer")))
        .layer(SetResponseHeaderLayer::if_not_present(HeaderName::from_static("permissions-policy"), HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()")));
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("KrakenWaf UI running at http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
