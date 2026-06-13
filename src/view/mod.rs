use anyhow::anyhow;
use askama::Template;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use axum_csrf::CsrfToken;

use crate::error::AppError;

/// Identifiers for the active navigation section, shared by the controllers and
/// matched against in `admin_sidebar.html`. Keeping them as named constants
/// avoids silent typos drifting from the template.
pub mod nav {
    pub const DASHBOARD: &str = "dashboard";
    pub const ACL: &str = "acl";
    pub const MONITOR: &str = "monitor";
    pub const UPDATES: &str = "updates";
    pub const USER_STATUS: &str = "user_status";
}

#[derive(Template)]
#[template(path = "login.html", escape = "html")]
pub struct LoginTemplate<'a> {
    pub product_name: &'a str,
    pub csrf_token: &'a str,
    pub error_message: &'a str,
}

#[derive(Clone)]
pub struct RoleOption {
    pub value: &'static str,
    pub label: &'static str,
    pub selected: bool,
}

#[derive(Template)]
#[template(path = "dashboard.htmlx", escape = "html")]
pub struct DashboardTemplate {
    pub active_page: &'static str,
    pub csrf_token: String,
    pub show_acl: bool,
}

#[derive(Template)]
#[template(path = "add_user.htmlx", escape = "html")]
pub struct AddUserTemplate {
    pub active_page: &'static str,
    pub csrf_token: String,
    pub show_acl: bool,
    pub roles: Vec<RoleOption>,
    pub show_form: bool,
    pub message: String,
    pub message_class: &'static str,
}

#[derive(Template)]
#[template(path = "delete_user.htmlx", escape = "html")]
pub struct DeleteUserTemplate {
    pub active_page: &'static str,
    pub csrf_token: String,
    pub show_acl: bool,
    pub user_identity: String,
    pub message: String,
    pub message_class: &'static str,
}

#[derive(Template)]
#[template(path = "edit_user.htmlx", escape = "html")]
pub struct EditUserTemplate {
    pub active_page: &'static str,
    pub csrf_token: String,
    pub show_acl: bool,
    pub has_user: bool,
    pub id_user: i32,
    pub username: String,
    pub email: String,
    pub roles: Vec<RoleOption>,
    pub show_form: bool,
    pub message: String,
    pub message_class: &'static str,
}

#[derive(Template)]
#[template(path = "show_user_table.htmlx", escape = "html")]
pub struct ShowUserTableTemplate {
    pub active_page: &'static str,
    pub csrf_token: String,
    pub show_acl: bool,
}

#[derive(Template)]
#[template(path = "update_kraken_ui.htmlx", escape = "html")]
pub struct UpdateKrakenUiTemplate {
    pub active_page: &'static str,
    pub csrf_token: String,
    pub show_acl: bool,
    pub current_version: &'static str,
}

#[derive(Template)]
#[template(path = "update_password.htmlx", escape = "html")]
pub struct UpdatePasswordTemplate {
    pub active_page: &'static str,
    pub csrf_token: String,
    pub show_acl: bool,
    pub id_user: i32,
    pub username: String,
    pub email: String,
    pub show_form: bool,
    pub message: String,
    pub message_class: &'static str,
}

#[derive(Template)]
#[template(path = "mfa.htmlx", escape = "html")]
pub struct MfaTemplate {
    pub active_page: &'static str,
    pub csrf_token: String,
    pub show_acl: bool,
    /// Whether two-factor is currently active for the signed-in operator.
    pub enabled: bool,
    pub remaining_recovery_codes: u64,
    /// Shown after starting enrollment: the secret and provisioning URI plus the
    /// code-confirmation form.
    pub show_enroll: bool,
    pub secret_base32: String,
    pub otpauth_uri: String,
    pub otpauth_qr_data_url: String,
    /// Shown exactly once after confirmation (or regeneration): the recovery codes.
    pub show_recovery: bool,
    pub recovery_codes: Vec<String>,
    pub recovery_codes_download_url: String,
    pub recovery_codes_download_name: String,
    pub message: String,
    pub message_class: &'static str,
}

#[derive(Template)]
#[template(path = "mfa_challenge.html", escape = "html")]
pub struct MfaChallengeTemplate<'a> {
    pub product_name: &'a str,
    pub csrf_token: &'a str,
    pub error_message: &'a str,
}

#[derive(Template)]
#[template(path = "show_attacks.htmlx", escape = "html")]
pub struct ShowAttacksTemplate {
    pub active_page: &'static str,
    pub csrf_token: String,
    pub show_acl: bool,
    pub database_available: bool,
}

#[derive(Template)]
#[template(path = "view_waf_request.htmlx", escape = "html")]
pub struct ViewWafRequestTemplate {
    pub attack_id: i32,
    pub title: String,
    pub severity: String,
    pub severity_class: &'static str,
    pub cwe: String,
    pub description: String,
    pub reference_url: String,
    pub occurred_at: String,
    pub rule_match: String,
    pub rule_line_match: String,
    pub client_ip: String,
    pub request_uri: String,
    pub fullpath_evidence: String,
    /// Attacker-controlled WAF payload, rendered through the template's default
    /// HTML escaping. The client highlighter reads it back via `textContent`, so
    /// the analyst sees the exact bytes with no loss of fidelity and no markup
    /// can execute under the strict CSP.
    pub request_payload: String,
}

pub fn render<T: Template>(template: T) -> Result<Response, AppError> {
    template
        .render()
        .map(|html| Html(html).into_response())
        .map_err(AppError::internal)
}

/// Renders a CSRF-protected page: mints an authenticity token, hands it to the
/// `template` builder, renders the result and attaches the matching CSRF cookie.
/// Shared by every controller that returns a form so the token plumbing lives in
/// one place.
pub fn render_with_csrf<T, F>(token: CsrfToken, template: F) -> Result<Response, AppError>
where
    T: Template,
    F: FnOnce(String) -> T,
{
    let csrf_token = token
        .authenticity_token()
        .map_err(|error| AppError::internal(anyhow!("failed to create CSRF token: {error}")))?;
    let response = render(template(csrf_token))?;
    Ok((token, response).into_response())
}

pub fn csrf_error_response() -> Response {
    (
        StatusCode::FORBIDDEN,
        "The form expired or the CSRF token is invalid",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use askama::Template;

    use super::{DashboardTemplate, ViewWafRequestTemplate};

    #[test]
    fn escapes_attacker_controlled_request_payload() {
        let template = ViewWafRequestTemplate {
            attack_id: 1,
            title: "Stored XSS attempt".to_owned(),
            severity: "high".to_owned(),
            severity_class: "sev-high",
            cwe: "CWE-79".to_owned(),
            description: String::new(),
            reference_url: String::new(),
            occurred_at: String::new(),
            rule_match: String::new(),
            rule_line_match: String::new(),
            client_ip: "203.0.113.7".to_owned(),
            request_uri: "/".to_owned(),
            fullpath_evidence: String::new(),
            request_payload: "<script>alert(document.cookie)</script>".to_owned(),
        };

        let html = template
            .render()
            .unwrap_or_else(|error| panic!("template must render: {error}"));

        // The exact bytes survive, but as inert text rather than an active tag:
        // Askama emits numeric HTML entities the browser decodes back to the
        // original characters inside `textContent`.
        assert!(html.contains("&#60;script&#62;alert(document.cookie)&#60;/script&#62;"));
        assert!(!html.contains("<script>alert(document.cookie)</script>"));
    }

    #[test]
    fn updates_menu_is_visible_only_for_administrators() {
        let admin = DashboardTemplate {
            active_page: "dashboard",
            csrf_token: "csrf".to_owned(),
            show_acl: true,
        }
        .render()
        .expect("admin dashboard");
        let operator = DashboardTemplate {
            active_page: "dashboard",
            csrf_token: "csrf".to_owned(),
            show_acl: false,
        }
        .render()
        .expect("operator dashboard");

        assert!(admin.contains("Update Kraken UI"));
        assert!(!operator.contains("Update Kraken UI"));
    }
}
