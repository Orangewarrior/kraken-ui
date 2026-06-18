//! Standalone probe for the auditor role's console boundary.
//!
//! This is a self-contained `reqwest` client — it does not link any Kraken UI
//! internals — that signs in to a *running* Kraken UI instance as an auditor and
//! checks, route by route, that the read-only role can reach only what it should:
//!
//!   * the dashboard, the attacks monitor and its own account pages are reachable
//!     (the single-attack detail view is reachable too — it may answer `503` when
//!     no WAF database is configured, which still counts as authorised), and
//!   * every administrator surface (ACL, updates) and operator surface (rule
//!     management) is denied with a redirect to the login page.
//!
//! Use it to verify the control against a live deployment (for example after an
//! upgrade). It exits `0` when every boundary holds and `1` when any route is
//! reachable that should not be (or any allowed route is unexpectedly blocked).
//!
//! ```bash
//! cargo run --example auditor_access_probe -- \
//!     https://kraken-ui.example.test auditor1 'Watchful-Ledger4Read'
//! ```
//!
//! Arguments: `<base-url> <login> <password>`. For a self-signed development
//! certificate, set `KRAKEN_UI_PROBE_INSECURE=1` to skip TLS verification.

use std::time::Duration;

use reqwest::{StatusCode, header};

const SESSION_COOKIE: &str = "__Host-kraken_session";
const CSRF_COOKIE: &str = "__Host-kraken_csrf";
const LOGIN_PATH: &str = "/kraken_ui/login";

/// Routes the auditor must be able to reach (rendered, not redirected to login).
/// `503` is tolerated on the detail view: it means "authorised, but no WAF data".
const ALLOWED: &[&str] = &[
    "/kraken_ui/auth/dashboard",
    "/kraken_ui/auth/admin_panel",
    "/kraken_ui/auth/show_attacks",
    "/kraken_ui/auth/update_password",
    "/kraken_ui/auth/mfa",
    "/kraken_ui/auth/view_waf_request/?id=1",
];

/// Routes the auditor must NOT reach: every admin (ACL, updates) and operator
/// (rule management) surface. Each must redirect to the login page.
const DENIED: &[&str] = &[
    "/kraken_ui/auth/insert_user",
    "/kraken_ui/auth/show_user_table",
    "/kraken_ui/auth/delete_user",
    "/kraken_ui/auth/edit_user",
    "/kraken_ui/auth/update_kraken_ui",
    "/kraken_ui/auth/api/operators",
    "/kraken_ui/auth/rule_management/cmc",
    "/kraken_ui/auth/rule_management/regex",
    "/kraken_ui/auth/api/rule_management/cmc",
];

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Plain CLI flag parsing; argv drives no security decision (it only selects
    // this manual probe's target and credentials), so the semgrep args advisory
    // does not apply.
    let mut args = std::env::args().skip(1); // nosemgrep
    let base = args.next().unwrap_or_else(|| usage_and_exit());
    let login_name = args.next().unwrap_or_else(|| usage_and_exit());
    let password = args.next().unwrap_or_else(|| usage_and_exit());
    let base = base.trim_end_matches('/').to_owned();

    let insecure = std::env::var("KRAKEN_UI_PROBE_INSECURE").is_ok();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(insecure)
        .timeout(Duration::from_secs(30))
        .build()?;

    // 1. Fetch the login page for the CSRF cookie and the matching form token.
    let login_page = client.get(format!("{base}{LOGIN_PATH}")).send().await?;
    let csrf_cookie =
        cookie_value(&login_page, CSRF_COOKIE).ok_or("login page returned no CSRF cookie")?;
    let csrf_token = attribute_value(&login_page.text().await?, "name=\"csrf_token\" value=\"")
        .ok_or("login page returned no CSRF token")?;

    // 2. Sign in and capture the session cookie.
    let signed_in = client
        .post(format!("{base}{LOGIN_PATH}"))
        .header(header::COOKIE, format!("{CSRF_COOKIE}={csrf_cookie}"))
        .form(&[
            ("login", login_name.as_str()),
            ("password", password.as_str()),
            ("csrf_token", csrf_token.as_str()),
        ])
        .send()
        .await?;
    if !signed_in.status().is_redirection() {
        return Err(format!(
            "login did not succeed (status {}); check the credentials and role",
            signed_in.status()
        )
        .into());
    }
    let session =
        cookie_value(&signed_in, SESSION_COOKIE).ok_or("login returned no session cookie")?;
    let cookie = format!("{SESSION_COOKIE}={session}");

    println!("base   : {base}");
    println!("login  : {login_name}");
    println!("signed in: OK\n");

    let mut violations = 0_usize;

    println!("allowed routes (must render):");
    for path in ALLOWED {
        let status = client
            .get(format!("{base}{path}"))
            .header(header::COOKIE, &cookie)
            .send()
            .await?
            .status();
        // 503 is tolerated only on the detail view (no WAF database configured).
        let ok = status == StatusCode::OK
            || (status == StatusCode::SERVICE_UNAVAILABLE && path.contains("view_waf_request"));
        if ok {
            println!("  PASS  {path}  ({status})");
        } else {
            println!("  FAIL  {path}  ({status}, expected the page to render)");
            violations += 1;
        }
    }

    println!("\ndenied routes (must redirect to login):");
    for path in DENIED {
        let response = client
            .get(format!("{base}{path}"))
            .header(header::COOKIE, &cookie)
            .send()
            .await?;
        let status = response.status();
        let location = response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        if status.is_redirection() && location == LOGIN_PATH {
            println!("  PASS  {path}  ({status} -> {location})");
        } else {
            println!(
                "  FAIL  {path}  ({status} -> {location}, expected a redirect to {LOGIN_PATH})"
            );
            violations += 1;
        }
    }

    if violations == 0 {
        println!("\nresult: PASS — the auditor boundary holds.");
        Ok(())
    } else {
        Err(format!("{violations} boundary violation(s) detected").into())
    }
}

fn usage_and_exit() -> ! {
    eprintln!(
        "usage: auditor_access_probe <base-url> <login> <password>\n\
         e.g.   auditor_access_probe https://kraken-ui.example.test auditor1 'pass'"
    );
    std::process::exit(2);
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

fn attribute_value(html: &str, marker: &str) -> Option<String> {
    let start = html.find(marker)? + marker.len();
    let end = html[start..].find('"')?;
    Some(html[start..start + end].to_owned())
}
