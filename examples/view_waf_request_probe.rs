//! Standalone probe for the secret redaction on the single-attack detail view.
//!
//! This is a self-contained client — it does not link any Kraken UI internals —
//! that signs in to a *running* Kraken UI instance and fetches
//! `/kraken_ui/auth/view_waf_request/?id=<id>` as the given operator, then
//! reports whether the response masks secret parameter values (`+++++`).
//!
//! Use it to verify the control against a live deployment (for example after an
//! upgrade): sign in once as an `admin` and once as an `operator`/`auditor` and
//! confirm only the non-admin response is masked.
//!
//! ```bash
//! cargo run --example view_waf_request_probe -- \
//!     https://kraken-ui.example.test admin 'AdminPassw0rd!' 1
//! ```
//!
//! Arguments: `<base-url> <login> <password> [attack-id]` (attack-id defaults to
//! 1). For a self-signed development certificate, set
//! `KRAKEN_UI_PROBE_INSECURE=1` to skip TLS verification.

use std::time::Duration;

use reqwest::{Client, header};

const SESSION_COOKIE: &str = "__Host-kraken_session";
const CSRF_COOKIE: &str = "__Host-kraken_csrf";
const MASK: &str = "+++++";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let base = args.next().unwrap_or_else(|| usage_and_exit());
    let login = args.next().unwrap_or_else(|| usage_and_exit());
    let password = args.next().unwrap_or_else(|| usage_and_exit());
    let attack_id = args.next().unwrap_or_else(|| "1".to_owned());
    let base = base.trim_end_matches('/').to_owned();

    let insecure = std::env::var("KRAKEN_UI_PROBE_INSECURE").is_ok();
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(insecure)
        .timeout(Duration::from_secs(30))
        .build()?;

    // 1. Fetch the login page for the CSRF cookie and the matching form token.
    let login_page = client.get(format!("{base}/kraken_ui/login")).send().await?;
    let csrf_cookie =
        cookie_value(&login_page, CSRF_COOKIE).ok_or("login page returned no CSRF cookie")?;
    let csrf_token = attribute_value(&login_page.text().await?, "name=\"csrf_token\" value=\"")
        .ok_or("login page returned no CSRF token")?;

    // 2. Sign in and capture the session cookie.
    let signed_in = client
        .post(format!("{base}/kraken_ui/login"))
        .header(header::COOKIE, format!("{CSRF_COOKIE}={csrf_cookie}"))
        .form(&[
            ("login", login.as_str()),
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

    // 3. Fetch the single-attack detail view as the signed-in operator.
    let detail = client
        .get(format!(
            "{base}/kraken_ui/auth/view_waf_request/?id={attack_id}"
        ))
        .header(header::COOKIE, format!("{SESSION_COOKIE}={session}"))
        .send()
        .await?;
    let status = detail.status();
    let body = detail.text().await?;
    if !status.is_success() {
        return Err(format!("detail view returned status {status}").into());
    }

    let masked = body.matches(MASK).count();
    println!("base        : {base}");
    println!("login        : {login}");
    println!("attack id    : {attack_id}");
    println!("status       : {status}");
    if masked > 0 {
        println!("result       : MASKED ({masked} `{MASK}` placeholder(s) present)");
        println!("               secret parameter values are hidden for this role.");
    } else {
        println!("result       : CLEAR (no `{MASK}` placeholder present)");
        println!("               this role sees secret values in clear (expected for admin).");
    }
    Ok(())
}

fn usage_and_exit() -> ! {
    eprintln!(
        "usage: view_waf_request_probe <base-url> <login> <password> [attack-id]\n\
         e.g.   view_waf_request_probe https://kraken-ui.example.test admin 'pass' 1"
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
