use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, anyhow};
use axum::{
    Form,
    extract::{ConnectInfo, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_csrf::CsrfToken;
use serde::Deserialize;
use tower_sessions::Session;
use tracing::{info, warn};

use crate::{
    error::AppError,
    models::operator_repository::OperatorRepository,
    security::sanitize,
    services::password_crypto::{PasswordCryptoService, PasswordVerification},
    state::AppState,
    view::{LoginTemplate, csrf_error_response, render},
};

const AUTHENTICATED_USER_ID: &str = "authenticated_user_id";
const AUTHENTICATED_USERNAME: &str = "authenticated_username";
const AUTHENTICATED_OPERATOR_TYPE: &str = "authenticated_operator_type";

#[derive(Deserialize)]
pub struct LoginForm {
    login: String,
    password: String,
    csrf_token: String,
}

#[derive(Deserialize)]
pub struct CsrfForm {
    csrf_token: String,
}

pub async fn login_page(token: CsrfToken, session: Session) -> Result<Response, AppError> {
    if authenticated_operator_type(&session).await?.as_deref() == Some("admin") {
        return Ok(Redirect::to("/kraken_ui/auth/admin_panel").into_response());
    }
    login_response(token, "").await
}

pub async fn login_submit(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    token: CsrfToken,
    session: Session,
    Form(form): Form<LoginForm>,
) -> Result<Response, AppError> {
    if !is_unchanged_by_sanitizer(&form.csrf_token) || token.verify(&form.csrf_token).is_err() {
        return Ok(csrf_error_response());
    }

    let client_ip = peer.ip().to_string();
    let ip_key = format!("ip:{client_ip}");

    // Throttle by source IP before doing any expensive work.
    if let Some(remaining) = state.login_throttle.locked_for(&ip_key) {
        audit_login(&client_ip, "", "locked");
        return locked_login_response(token, remaining).await;
    }

    let username = sanitize::plain_text(&form.login).to_ascii_lowercase();
    let password = form.password;
    let user_key = format!("user:{username}");

    // Throttle by account so a single account cannot be hammered from many IPs.
    if let Some(remaining) = state.login_throttle.locked_for(&user_key) {
        audit_login(&client_ip, &username, "locked");
        return locked_login_response(token, remaining).await;
    }

    if username.len() > 128
        || password.len() > 256
        || sanitize::secret_has_rejected_markup(&password)
    {
        register_login_failure(&state, &ip_key, &user_key);
        audit_login(&client_ip, &username, "invalid_input");
        return invalid_login_response(token).await;
    }
    let repository = OperatorRepository::new(state.database.clone(), state.password_crypto.clone());
    let Some(operator) = repository.find_by_username(&username).await? else {
        // Spend the same time as a real verification so unknown usernames are
        // not distinguishable by response latency.
        run_dummy_verification(state.password_crypto.clone(), password).await;
        register_login_failure(&state, &ip_key, &user_key);
        audit_login(&client_ip, &username, "unknown_user");
        return invalid_login_response(token).await;
    };
    let verification = verify_password(
        state.password_crypto.clone(),
        operator.id_user,
        operator.encrypted_password_hash.clone(),
        password,
    )
    .await;
    let verification = match verification {
        Ok(result) => result,
        Err(error) => {
            warn!(
                operator_id = operator.id_user,
                error = %error,
                "password crypto service rejected the stored record"
            );
            register_login_failure(&state, &ip_key, &user_key);
            audit_login(&client_ip, &username, "crypto_error");
            return invalid_login_response(token).await;
        }
    };
    if !verification.valid {
        register_login_failure(&state, &ip_key, &user_key);
        audit_login(&client_ip, &username, "bad_password");
        return invalid_login_response(token).await;
    }
    if let Some(replacement_record) = verification.replacement_record {
        repository
            .update_encrypted_password(operator.id_user, replacement_record)
            .await?;
    }
    if operator.operator_type != "admin" {
        audit_login(&client_ip, &username, "not_admin");
        return login_response(token, "Operator and auditor access is not enabled yet").await;
    }

    // Successful admin authentication: clear any recorded failures.
    state.login_throttle.record_success(&ip_key);
    state.login_throttle.record_success(&user_key);

    session
        .cycle_id()
        .await
        .map_err(|error| AppError::internal(anyhow!("failed to rotate session id: {error}")))?;
    session
        .insert(AUTHENTICATED_USER_ID, operator.id_user)
        .await
        .map_err(|error| AppError::internal(anyhow!("failed to persist user session: {error}")))?;
    session
        .insert(
            AUTHENTICATED_USERNAME,
            sanitize::plain_text(&operator.username),
        )
        .await
        .map_err(|error| {
            AppError::internal(anyhow!("failed to persist session identity: {error}"))
        })?;
    session
        .insert(
            AUTHENTICATED_OPERATOR_TYPE,
            sanitize::plain_text(&operator.operator_type),
        )
        .await
        .map_err(|error| AppError::internal(anyhow!("failed to persist operator type: {error}")))?;

    audit_login(&client_ip, &username, "success");
    Ok(Redirect::to("/kraken_ui/auth/admin_panel").into_response())
}

pub async fn logout(
    token: CsrfToken,
    session: Session,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    if !is_unchanged_by_sanitizer(&form.csrf_token) || token.verify(&form.csrf_token).is_err() {
        return Ok(csrf_error_response());
    }
    let username = authenticated_username(&session).await.unwrap_or_default();
    session
        .flush()
        .await
        .map_err(|error| AppError::internal(anyhow!("failed to destroy session: {error}")))?;
    info!(target: "audit", event = "logout", username = %username, "operator logged out");
    Ok(Redirect::to("/kraken_ui/login").into_response())
}

pub async fn authenticated_user_id(session: &Session) -> Result<Option<i32>, AppError> {
    session
        .get::<i32>(AUTHENTICATED_USER_ID)
        .await
        .map_err(|error| {
            AppError::internal(anyhow!("failed to read authentication session: {error}"))
        })
}

pub async fn authenticated_operator_type(session: &Session) -> Result<Option<String>, AppError> {
    session
        .get::<String>(AUTHENTICATED_OPERATOR_TYPE)
        .await
        .map_err(|error| {
            AppError::internal(anyhow!(
                "failed to read operator type from session: {error}"
            ))
        })
}

pub async fn authenticated_username(session: &Session) -> Option<String> {
    session.get::<String>(AUTHENTICATED_USERNAME).await.ok()?
}

fn register_login_failure(state: &AppState, ip_key: &str, user_key: &str) {
    state.login_throttle.record_failure(ip_key);
    state.login_throttle.record_failure(user_key);
}

async fn run_dummy_verification(password_crypto: Arc<dyn PasswordCryptoService>, password: String) {
    let _ = tokio::task::spawn_blocking(move || {
        password_crypto.run_dummy_verification(&password);
    })
    .await;
}

fn audit_login(client_ip: &str, username: &str, outcome: &str) {
    info!(
        target: "audit",
        event = "login",
        client_ip = %client_ip,
        username = %username,
        outcome = %outcome,
        "login attempt"
    );
}

async fn locked_login_response(
    token: CsrfToken,
    remaining: Duration,
) -> Result<Response, AppError> {
    let minutes = remaining.as_secs().div_ceil(60).max(1);
    login_response(
        token,
        &format!("Too many attempts. Try again in about {minutes} minute(s)."),
    )
    .await
}

async fn invalid_login_response(token: CsrfToken) -> Result<Response, AppError> {
    login_response(token, "Invalid credentials").await
}

async fn login_response(token: CsrfToken, error_message: &str) -> Result<Response, AppError> {
    let authenticity_token = token
        .authenticity_token()
        .map_err(|error| AppError::internal(anyhow!("failed to create CSRF token: {error}")))?;
    let response = render(LoginTemplate {
        product_name: "KrakenWAF",
        csrf_token: &authenticity_token,
        error_message,
    })?;
    Ok((token, response).into_response())
}

fn is_unchanged_by_sanitizer(value: &str) -> bool {
    sanitize::plain_text(value) == value
}

async fn verify_password(
    password_crypto: Arc<dyn PasswordCryptoService>,
    user_id: i32,
    encrypted_record: String,
    password: String,
) -> anyhow::Result<PasswordVerification> {
    tokio::task::spawn_blocking(move || {
        password_crypto.verify_password(user_id, &encrypted_record, &password)
    })
    .await
    .context("password verification task failed")?
}
