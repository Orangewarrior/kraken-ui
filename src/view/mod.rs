use askama::Template;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

use crate::error::AppError;

/// Identifiers for the active navigation section, shared by the controllers and
/// matched against in `admin_sidebar.html`. Keeping them as named constants
/// avoids silent typos drifting from the template.
pub mod nav {
    pub const DASHBOARD: &str = "dashboard";
    pub const ACL: &str = "acl";
    pub const MONITOR: &str = "monitor";
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
    /// Already sanitised with Ammonia; rendered without further escaping so the
    /// payload reads naturally and the client highlighter can tokenise it.
    pub request_payload: String,
}

pub fn render<T: Template>(template: T) -> Result<Response, AppError> {
    template
        .render()
        .map(|html| Html(html).into_response())
        .map_err(AppError::internal)
}

pub fn csrf_error_response() -> Response {
    (
        StatusCode::FORBIDDEN,
        "The form expired or the CSRF token is invalid",
    )
        .into_response()
}
