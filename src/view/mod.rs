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
    pub const RULE_MANAGEMENT: &str = "rule_management";
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
#[template(path = "rule_management_cmc.htmlx", escape = "html")]
pub struct RuleManagementCmcTemplate {
    pub active_page: &'static str,
    pub csrf_token: String,
    pub show_acl: bool,
    /// Whether `waf-rule-endpoint` and the Rorschach secrets are configured. When
    /// `false`, the page explains what to set instead of rendering the table.
    pub configured: bool,
}

#[derive(Template)]
#[template(path = "rule_management_regex_select.htmlx", escape = "html")]
pub struct RuleManagementRegexSelectTemplate {
    pub active_page: &'static str,
    pub csrf_token: String,
    pub show_acl: bool,
    /// Whether the rule-management channel is configured; when `false` the page
    /// explains what to set instead of rendering the form.
    pub configured: bool,
    /// The allowlisted rule-list names shown in the select box.
    pub rule_lists: Vec<&'static str>,
}

#[derive(Template)]
#[template(path = "rule_management_regex_edit.htmlx", escape = "html")]
pub struct RuleManagementRegexEditTemplate {
    pub active_page: &'static str,
    pub csrf_token: String,
    pub show_acl: bool,
    /// The allowlisted rule name being edited (also the update query parameter).
    pub rule_name: &'static str,
    /// The ACE syntax-highlighting mode (`ace/mode/json` or `ace/mode/text`).
    pub editor_mode: &'static str,
    /// The current rule content fetched from KrakenWAF, rendered through the
    /// template's HTML escaping and read back by ACE via the textarea `value`.
    pub content: String,
    /// `true` when the content was fetched successfully and the editor should
    /// render; `false` when `error_message` explains why it could not.
    pub loaded: bool,
    /// A non-empty, operator-facing message shown in an error banner.
    pub error_message: String,
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

    use super::{DashboardTemplate, RuleManagementRegexEditTemplate, ViewWafRequestTemplate};

    #[test]
    fn regex_editor_escapes_rule_content_and_shows_the_caution() {
        let html = RuleManagementRegexEditTemplate {
            active_page: "rule_management",
            csrf_token: "csrf".to_owned(),
            show_acl: true,
            rule_name: "body_regex",
            editor_mode: "ace/mode/json",
            content: "<script>alert(1)</script>".to_owned(),
            loaded: true,
            error_message: String::new(),
        }
        .render()
        .expect("regex editor must render");

        // Rule content is inert text in the source textarea, never live markup.
        assert!(html.contains("&#60;script&#62;alert(1)&#60;/script&#62;"));
        assert!(!html.contains("<script>alert(1)</script>"));
        // The mandatory ReDoS / PCRE caution is always present on the editor.
        assert!(html.contains("take care with ReDOS"));
        assert!(html.contains("CMC modules is something superior"));
        // ACE is loaded from the strict-CSP, same-origin vendor bundle.
        assert!(html.contains("/static/vendor/ace/ace.js"));
    }

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
