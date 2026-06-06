use askama::Template;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

use crate::error::AppError;

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
}

#[derive(Template)]
#[template(path = "add_user.htmlx", escape = "html")]
pub struct AddUserTemplate {
    pub active_page: &'static str,
    pub csrf_token: String,
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
    pub user_identity: String,
    pub message: String,
    pub message_class: &'static str,
}

#[derive(Template)]
#[template(path = "edit_user.htmlx", escape = "html")]
pub struct EditUserTemplate {
    pub active_page: &'static str,
    pub csrf_token: String,
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
}

#[derive(Template)]
#[template(path = "update_password.htmlx", escape = "html")]
pub struct UpdatePasswordTemplate {
    pub active_page: &'static str,
    pub csrf_token: String,
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
    pub database_available: bool,
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
