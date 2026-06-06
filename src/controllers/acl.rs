use std::collections::HashMap;

use anyhow::anyhow;
use axum::{
    Form, Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum_csrf::CsrfToken;
use memchr::{memchr, memrchr};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;

use crate::{
    controllers::auth,
    error::AppError,
    models::operator_repository::{NewOperator, OperatorRepository, UpdateOperator},
    security::sanitize,
    state::AppState,
    view::{
        AddUserTemplate, DeleteUserTemplate, EditUserTemplate, RoleOption, ShowUserTableTemplate,
        UpdatePasswordTemplate, csrf_error_response, render,
    },
};

#[derive(Deserialize)]
pub struct OperatorForm {
    username: String,
    email: String,
    user_type: String,
    password: String,
    csrf_token: String,
}

#[derive(Deserialize)]
pub struct DeleteUserForm {
    user_identity: String,
    csrf_token: String,
}

#[derive(Deserialize)]
pub struct EditLookupForm {
    id_user: String,
    csrf_token: String,
}

#[derive(Deserialize)]
pub struct UpdateUserForm {
    id_user: String,
    username: String,
    email: String,
    user_type: String,
    password: String,
    csrf_token: String,
}

#[derive(Deserialize)]
pub struct UpdatePasswordForm {
    id_user: String,
    password: String,
    csrf_token: String,
}

#[derive(Serialize)]
pub struct OperatorRow {
    id: i32,
    username: String,
    email: String,
    user_type: String,
    status: &'static str,
    created_at: String,
}

#[derive(Serialize)]
pub struct OperatorPageResponse {
    draw: u64,
    #[serde(rename = "recordsTotal")]
    records_total: u64,
    #[serde(rename = "recordsFiltered")]
    records_filtered: u64,
    data: Vec<OperatorRow>,
}

pub async fn insert_user(token: CsrfToken) -> Result<Response, AppError> {
    render_add_user(token, String::new(), "")
}

pub async fn insert_user_action(
    State(state): State<AppState>,
    token: CsrfToken,
    Form(form): Form<OperatorForm>,
) -> Result<Response, AppError> {
    if !valid_csrf(&token, &form.csrf_token) {
        return Ok(csrf_error_response());
    }
    let input = match validate_operator(
        &state,
        &form.username,
        &form.email,
        &form.user_type,
        &form.password,
        false,
    ) {
        Ok(input) => input,
        Err(message) => return render_add_user(token, message, "error"),
    };
    let repository = repository(&state);
    if repository.find_by_email(&input.email).await?.is_some() {
        return render_add_user(
            token,
            "That email address is already registered.".to_owned(),
            "error",
        );
    }
    if repository
        .find_by_username(&input.username)
        .await?
        .is_some()
    {
        return render_add_user(token, "That username is already taken.".to_owned(), "error");
    }
    repository
        .create(NewOperator {
            username: &input.username,
            email: &input.email,
            operator_type: &input.operator_type,
            password: input
                .password
                .as_deref()
                .ok_or_else(|| AppError::internal(anyhow!("validated password is missing")))?,
        })
        .await?;
    render_add_user(token, "User created successfully.".to_owned(), "success")
}

pub async fn delete_user(token: CsrfToken) -> Result<Response, AppError> {
    render_delete_user(token, String::new(), String::new(), "")
}

pub async fn delete_user_action(
    State(state): State<AppState>,
    token: CsrfToken,
    session: Session,
    Form(form): Form<DeleteUserForm>,
) -> Result<Response, AppError> {
    if !valid_csrf(&token, &form.csrf_token) {
        return Ok(csrf_error_response());
    }
    let identity = sanitize::plain_text(&form.user_identity).to_ascii_lowercase();
    if identity.is_empty() || identity.len() > 128 {
        return render_delete_user(
            token,
            identity,
            "Enter a valid ID or email address.".to_owned(),
            "error",
        );
    }
    let repository = repository(&state);
    let target = if let Ok(id_user) = identity.parse::<i32>() {
        repository.find_by_id(id_user).await?
    } else if valid_email(&identity) {
        repository.find_by_email(&identity).await?
    } else {
        return render_delete_user(
            token,
            identity,
            "Enter a numeric ID or a valid email address.".to_owned(),
            "error",
        );
    };
    let Some(target) = target else {
        return render_delete_user(token, identity, "User not found.".to_owned(), "error");
    };
    if auth::authenticated_user_id(&session).await? == Some(target.id_user) {
        return render_delete_user(
            token,
            identity,
            "The signed-in administrator cannot remove their own account.".to_owned(),
            "error",
        );
    }
    repository.delete_by_id(target.id_user).await?;
    render_delete_user(token, String::new(), "User removed.".to_owned(), "error")
}

pub async fn edit_user(token: CsrfToken) -> Result<Response, AppError> {
    render_edit_search(token, String::new(), "")
}

pub async fn edit_user_lookup(
    State(state): State<AppState>,
    token: CsrfToken,
    Form(form): Form<EditLookupForm>,
) -> Result<Response, AppError> {
    if !valid_csrf(&token, &form.csrf_token) {
        return Ok(csrf_error_response());
    }
    let id_user = match sanitize::plain_text(&form.id_user).parse::<i32>() {
        Ok(id_user) if id_user > 0 => id_user,
        _ => {
            return render_edit_search(token, "Enter a valid ID.".to_owned(), "error");
        }
    };
    let Some(operator) = repository(&state).find_by_id(id_user).await? else {
        return render_edit_search(token, "User not found.".to_owned(), "error");
    };
    render_edit_operator(token, operator, String::new(), "")
}

pub async fn update_user_action(
    State(state): State<AppState>,
    token: CsrfToken,
    session: Session,
    Form(form): Form<UpdateUserForm>,
) -> Result<Response, AppError> {
    if !valid_csrf(&token, &form.csrf_token) {
        return Ok(csrf_error_response());
    }
    let id_user = match sanitize::plain_text(&form.id_user).parse::<i32>() {
        Ok(id_user) if id_user > 0 => id_user,
        _ => return render_edit_search(token, "Invalid user ID.".to_owned(), "error"),
    };
    let repository = repository(&state);
    let Some(existing) = repository.find_by_id(id_user).await? else {
        return render_edit_search(token, "User not found.".to_owned(), "error");
    };
    let input = match validate_operator(
        &state,
        &form.username,
        &form.email,
        &form.user_type,
        &form.password,
        true,
    ) {
        Ok(input) => input,
        Err(message) => return render_edit_operator(token, existing, message, "error"),
    };
    if auth::authenticated_user_id(&session).await? == Some(id_user)
        && input.operator_type != "admin"
    {
        return render_edit_operator(
            token,
            existing,
            "The signed-in administrator cannot change their own role.".to_owned(),
            "error",
        );
    }
    if repository
        .find_by_email(&input.email)
        .await?
        .is_some_and(|operator| operator.id_user != id_user)
    {
        return render_edit_operator(
            token,
            existing,
            "That email address is already registered.".to_owned(),
            "error",
        );
    }
    if repository
        .find_by_username(&input.username)
        .await?
        .is_some_and(|operator| operator.id_user != id_user)
    {
        return render_edit_operator(
            token,
            existing,
            "That username is already taken.".to_owned(),
            "error",
        );
    }
    let updated = repository
        .update(
            existing,
            UpdateOperator {
                username: &input.username,
                email: &input.email,
                operator_type: &input.operator_type,
                password: input.password.as_deref(),
            },
        )
        .await?;
    render_edit_operator(
        token,
        updated,
        "User details updated successfully.".to_owned(),
        "success",
    )
}

pub async fn show_user_table(token: CsrfToken) -> Result<Response, AppError> {
    render_with_csrf(token, |csrf_token| ShowUserTableTemplate {
        active_page: "acl",
        csrf_token,
    })
}

pub async fn api_operators(
    State(state): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<OperatorPageResponse>, AppError> {
    let draw = parse_query_u64(&query, "draw", 1);
    let start = parse_query_u64(&query, "start", 0);
    let length = parse_query_u64(&query, "length", 50).clamp(1, 100);
    let search = query
        .get("search[value]")
        .or_else(|| query.get("search"))
        .map(|value| sanitize::plain_text(value))
        .unwrap_or_default();
    let page = repository(&state).page(start, length, &search).await?;
    let data = page
        .operators
        .into_iter()
        .map(|operator| OperatorRow {
            id: operator.id_user,
            username: operator.username,
            email: operator.email,
            user_type: operator.operator_type,
            status: "active",
            created_at: operator.created_at,
        })
        .collect();
    Ok(Json(OperatorPageResponse {
        draw,
        records_total: page.records_total,
        records_filtered: page.records_filtered,
        data,
    }))
}

pub async fn update_password(
    State(state): State<AppState>,
    token: CsrfToken,
    session: Session,
) -> Result<Response, AppError> {
    let Some(id_user) = auth::authenticated_user_id(&session).await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };
    let Some(operator) = repository(&state).find_by_id(id_user).await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };
    render_password(token, operator, true, String::new(), "")
}

pub async fn update_password_action(
    State(state): State<AppState>,
    token: CsrfToken,
    session: Session,
    Form(form): Form<UpdatePasswordForm>,
) -> Result<Response, AppError> {
    if !valid_csrf(&token, &form.csrf_token) {
        return Ok(csrf_error_response());
    }
    let Some(authenticated_id) = auth::authenticated_user_id(&session).await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };
    let submitted_id = sanitize::plain_text(&form.id_user)
        .parse::<i32>()
        .unwrap_or_default();
    let repository = repository(&state);
    let Some(existing) = repository.find_by_id(authenticated_id).await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };
    if submitted_id != authenticated_id {
        return render_password(
            token,
            existing,
            true,
            "The submitted ID does not match the signed-in session.".to_owned(),
            "error",
        );
    }
    if sanitize::secret_has_rejected_markup(&form.password) {
        return render_password(token, existing, true, password_example(), "error");
    }
    if !password_is_acceptable(&state, &form.password, &existing.username, &existing.email) {
        return render_password(token, existing, true, password_example(), "error");
    }
    let updated = repository.update_password(existing, &form.password).await;
    let updated = match updated {
        Ok(updated) => updated,
        Err(error) => return Err(AppError::internal(error)),
    };
    render_password(
        token,
        updated,
        false,
        "Password changed successfully.".to_owned(),
        "success",
    )
}

struct ValidatedOperator {
    username: String,
    email: String,
    operator_type: String,
    password: Option<String>,
}

fn validate_operator(
    state: &AppState,
    raw_username: &str,
    raw_email: &str,
    raw_operator_type: &str,
    raw_password: &str,
    password_optional: bool,
) -> Result<ValidatedOperator, String> {
    let username = sanitize::plain_text(raw_username).to_ascii_lowercase();
    let email = sanitize::plain_text(raw_email).to_ascii_lowercase();
    let operator_type = sanitize::plain_text(raw_operator_type).to_ascii_lowercase();
    if !valid_username(&username) {
        return Err("The username must be 3 to 32 safe characters.".to_owned());
    }
    if !valid_email(&email) {
        return Err("The email address is invalid or longer than 128 characters.".to_owned());
    }
    if !matches!(operator_type.as_str(), "admin" | "operator" | "auditor") {
        return Err("Invalid user type.".to_owned());
    }
    let password = if raw_password.is_empty() && password_optional {
        None
    } else {
        if sanitize::secret_has_rejected_markup(raw_password)
            || !password_is_acceptable(state, raw_password, &username, &email)
        {
            return Err(password_example());
        }
        Some(raw_password.to_owned())
    };
    Ok(ValidatedOperator {
        username,
        email,
        operator_type,
        password,
    })
}

pub(crate) fn valid_username(username: &str) -> bool {
    (3..=32).contains(&username.len())
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

pub(crate) fn valid_email(email: &str) -> bool {
    if email.is_empty() || email.len() > 128 || memchr(b' ', email.as_bytes()).is_some() {
        return false;
    }
    let first_at = memchr(b'@', email.as_bytes());
    let last_at = memrchr(b'@', email.as_bytes());
    matches!((first_at, last_at), (Some(first), Some(last)) if first == last && first > 0 && first + 1 < email.len())
}

fn password_example() -> String {
    "Weak password. Use at least 14 characters with upper- and lower-case letters, a number and a symbol. For example: More-Than-14!Characters9.".to_owned()
}

fn password_is_acceptable(state: &AppState, password: &str, username: &str, email: &str) -> bool {
    let email_identity = email.split('@').next().unwrap_or(email);
    state.password_policy.validate(password, username).is_ok()
        && state
            .password_policy
            .validate(password, email_identity)
            .is_ok()
}

fn repository(state: &AppState) -> OperatorRepository {
    OperatorRepository::new(state.database.clone(), state.password_crypto.clone())
}

fn valid_csrf(token: &CsrfToken, submitted_token: &str) -> bool {
    sanitize::plain_text(submitted_token) == submitted_token
        && token.verify(submitted_token).is_ok()
}

fn render_add_user(
    token: CsrfToken,
    message: String,
    message_class: &'static str,
) -> Result<Response, AppError> {
    render_with_csrf(token, |csrf_token| AddUserTemplate {
        active_page: "acl",
        csrf_token,
        roles: role_options(None),
        show_form: message_class != "success",
        message,
        message_class,
    })
}

fn render_delete_user(
    token: CsrfToken,
    user_identity: String,
    message: String,
    message_class: &'static str,
) -> Result<Response, AppError> {
    render_with_csrf(token, |csrf_token| DeleteUserTemplate {
        active_page: "acl",
        csrf_token,
        user_identity,
        message,
        message_class,
    })
}

fn render_edit_search(
    token: CsrfToken,
    message: String,
    message_class: &'static str,
) -> Result<Response, AppError> {
    render_with_csrf(token, |csrf_token| EditUserTemplate {
        active_page: "acl",
        csrf_token,
        has_user: false,
        id_user: 0,
        username: String::new(),
        email: String::new(),
        roles: role_options(None),
        show_form: true,
        message,
        message_class,
    })
}

fn render_edit_operator(
    token: CsrfToken,
    operator: crate::models::operator::Model,
    message: String,
    message_class: &'static str,
) -> Result<Response, AppError> {
    render_with_csrf(token, |csrf_token| EditUserTemplate {
        active_page: "acl",
        csrf_token,
        has_user: true,
        id_user: operator.id_user,
        username: operator.username,
        email: operator.email,
        roles: role_options(Some(&operator.operator_type)),
        show_form: message_class != "success",
        message,
        message_class,
    })
}

fn render_password(
    token: CsrfToken,
    operator: crate::models::operator::Model,
    show_form: bool,
    message: String,
    message_class: &'static str,
) -> Result<Response, AppError> {
    render_with_csrf(token, |csrf_token| UpdatePasswordTemplate {
        active_page: "user_status",
        csrf_token,
        id_user: operator.id_user,
        username: operator.username,
        email: operator.email,
        show_form,
        message,
        message_class,
    })
}

fn render_with_csrf<T, F>(token: CsrfToken, template: F) -> Result<Response, AppError>
where
    T: askama::Template,
    F: FnOnce(String) -> T,
{
    let csrf_token = token
        .authenticity_token()
        .map_err(|error| AppError::internal(anyhow!("failed to create CSRF token: {error}")))?;
    let response = render(template(csrf_token))?;
    Ok((token, response).into_response())
}

fn role_options(selected: Option<&str>) -> Vec<RoleOption> {
    [
        ("admin", "Admin"),
        ("operator", "Operator"),
        ("auditor", "Auditor"),
    ]
    .into_iter()
    .map(|(value, label)| RoleOption {
        value,
        label,
        selected: selected == Some(value),
    })
    .collect()
}

fn parse_query_u64(query: &HashMap<String, String>, key: &str, fallback: u64) -> u64 {
    query
        .get(key)
        .map(|value| sanitize::plain_text(value))
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(fallback)
}
