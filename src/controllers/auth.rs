use std::sync::Arc;

use anyhow::{Context, anyhow};
use axum::{
    Form,
    extract::State,
    response::{IntoResponse, Redirect, Response},
};
use axum_csrf::CsrfToken;
use serde::Deserialize;
use tower_sessions::Session;
use tracing::warn;

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
        return Ok(Redirect::to("/kraken_ui/auth/painel_admin").into_response());
    }
    login_response(token, "").await
}

pub async fn login_submit(
    State(state): State<AppState>,
    token: CsrfToken,
    session: Session,
    Form(form): Form<LoginForm>,
) -> Result<Response, AppError> {
    if !is_unchanged_by_sanitizer(&form.csrf_token) || token.verify(&form.csrf_token).is_err() {
        return Ok(csrf_error_response());
    }

    let username = sanitize::plain_text(&form.login).to_ascii_lowercase();
    let password = form.password;
    if username.len() > 128 || password.len() > 256 {
        return invalid_login_response(token).await;
    }
    if sanitize::secret_has_rejected_markup(&password) {
        return invalid_login_response(token).await;
    }
    let repository = OperatorRepository::new(state.database.clone(), state.password_crypto.clone());
    let Some(operator) = repository.find_by_username(&username).await? else {
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
            return invalid_login_response(token).await;
        }
    };
    if !verification.valid {
        return invalid_login_response(token).await;
    }
    if let Some(replacement_record) = verification.replacement_record {
        repository
            .update_encrypted_password(operator.id_user, replacement_record)
            .await?;
    }
    if operator.operator_type != "admin" {
        return login_response(token, "Operator and auditor access is not enabled yet").await;
    }

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

    Ok(Redirect::to("/kraken_ui/auth/painel_admin").into_response())
}

pub async fn logout(
    token: CsrfToken,
    session: Session,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    if !is_unchanged_by_sanitizer(&form.csrf_token) || token.verify(&form.csrf_token).is_err() {
        return Ok(csrf_error_response());
    }
    session
        .flush()
        .await
        .map_err(|error| AppError::internal(anyhow!("failed to destroy session: {error}")))?;
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
