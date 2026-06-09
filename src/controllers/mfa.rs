use anyhow::anyhow;
use axum::{
    Form,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum_csrf::CsrfToken;
use serde::Deserialize;
use tower_sessions::Session;
use zeroize::Zeroizing;

use crate::{
    controllers::auth,
    error::AppError,
    models::{
        operator::Model as Operator, operator_mfa_repository::OperatorMfaRepository,
        operator_repository::OperatorRepository,
    },
    security::{csrf, sanitize},
    services::password_crypto::spawn_verify,
    state::AppState,
    view::{MfaTemplate, csrf_error_response, nav, render},
};

#[derive(Deserialize)]
pub struct CsrfForm {
    csrf_token: String,
}

#[derive(Deserialize)]
pub struct ConfirmForm {
    code: String,
    csrf_token: String,
}

#[derive(Deserialize)]
pub struct DisableForm {
    current_password: String,
    csrf_token: String,
}

/// The two-factor management page for the signed-in operator (admin or operator).
pub async fn mfa_overview(
    State(state): State<AppState>,
    token: CsrfToken,
    session: Session,
) -> Result<Response, AppError> {
    let Some(operator) = current_operator(&state, &session).await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };
    render_overview(&state, token, &operator, String::new(), "").await
}

/// Starts (or restarts) enrollment and shows the secret plus the confirm form.
pub async fn mfa_enroll(
    State(state): State<AppState>,
    token: CsrfToken,
    session: Session,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    if !csrf::verify(&token, &form.csrf_token) {
        return Ok(csrf_error_response());
    }
    let Some(operator) = current_operator(&state, &session).await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };
    let mfa = mfa_repository(&state);
    if mfa.is_enabled(operator.id_user).await? {
        return render_overview(
            &state,
            token,
            &operator,
            "Two-factor authentication is already enabled.".to_owned(),
            "error",
        )
        .await;
    }
    let enrollment = mfa
        .begin_enrollment(operator.id_user, &operator.username)
        .await?;
    render_enroll(
        token,
        &operator,
        enrollment.secret_base32,
        enrollment.otpauth_uri,
        "Add the account to your authenticator, then enter the current code.".to_owned(),
        "",
    )
}

/// Confirms a pending enrollment with a code from the authenticator app.
pub async fn mfa_confirm(
    State(state): State<AppState>,
    token: CsrfToken,
    session: Session,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, AppError> {
    if !csrf::verify(&token, &form.csrf_token) {
        return Ok(csrf_error_response());
    }
    let Some(operator) = current_operator(&state, &session).await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };
    let mfa = mfa_repository(&state);
    let code = sanitize::plain_text(&form.code);
    use crate::models::operator_mfa_repository::ConfirmOutcome;
    match mfa.confirm(operator.id_user, &code).await? {
        ConfirmOutcome::Confirmed { recovery_codes } => {
            audit_mfa_event("enable", operator.id_user, &operator.username);
            render_recovery(
                token,
                &operator,
                recovery_codes,
                "Two-factor authentication enabled.".to_owned(),
            )
        }
        ConfirmOutcome::InvalidCode => {
            // Re-show the same secret so the operator can retry without
            // re-registering the account in their app.
            match mfa
                .pending_enrollment(operator.id_user, &operator.username)
                .await?
            {
                Some(enrollment) => render_enroll(
                    token,
                    &operator,
                    enrollment.secret_base32,
                    enrollment.otpauth_uri,
                    "That code was not correct. Check the time on your device and try again."
                        .to_owned(),
                    "error",
                ),
                None => {
                    render_overview(
                        &state,
                        token,
                        &operator,
                        "Enrollment expired. Start again.".to_owned(),
                        "error",
                    )
                    .await
                }
            }
        }
        ConfirmOutcome::NoPendingEnrollment => {
            render_overview(
                &state,
                token,
                &operator,
                "Start enrollment before confirming a code.".to_owned(),
                "error",
            )
            .await
        }
    }
}

/// Disables two-factor after re-confirming the operator's password.
pub async fn mfa_disable(
    State(state): State<AppState>,
    token: CsrfToken,
    session: Session,
    Form(form): Form<DisableForm>,
) -> Result<Response, AppError> {
    if !csrf::verify(&token, &form.csrf_token) {
        return Ok(csrf_error_response());
    }
    let Some(operator) = current_operator(&state, &session).await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };
    if !verify_password(&state, &operator, &form.current_password).await? {
        return render_overview(
            &state,
            token,
            &operator,
            "The current password is incorrect.".to_owned(),
            "error",
        )
        .await;
    }
    mfa_repository(&state).disable(operator.id_user).await?;
    audit_mfa_event("disable", operator.id_user, &operator.username);
    render_overview(
        &state,
        token,
        &operator,
        "Two-factor authentication disabled.".to_owned(),
        "success",
    )
    .await
}

/// Mints a fresh set of single-use recovery codes for an enabled account.
pub async fn mfa_regenerate(
    State(state): State<AppState>,
    token: CsrfToken,
    session: Session,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    if !csrf::verify(&token, &form.csrf_token) {
        return Ok(csrf_error_response());
    }
    let Some(operator) = current_operator(&state, &session).await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };
    match mfa_repository(&state)
        .regenerate_recovery_codes(operator.id_user)
        .await?
    {
        Some(recovery_codes) => {
            audit_mfa_event("regenerate_recovery", operator.id_user, &operator.username);
            render_recovery(
                token,
                &operator,
                recovery_codes,
                "New recovery codes generated. The previous codes no longer work.".to_owned(),
            )
        }
        None => {
            render_overview(
                &state,
                token,
                &operator,
                "Enable two-factor authentication first.".to_owned(),
                "error",
            )
            .await
        }
    }
}

async fn current_operator(
    state: &AppState,
    session: &Session,
) -> Result<Option<Operator>, AppError> {
    let Some(id_user) = auth::authenticated_user_id(session).await? else {
        return Ok(None);
    };
    Ok(
        OperatorRepository::new(state.database.clone(), state.password_crypto.clone())
            .find_by_id(id_user)
            .await?,
    )
}

async fn verify_password(
    state: &AppState,
    operator: &Operator,
    password: &str,
) -> Result<bool, AppError> {
    let verification = spawn_verify(
        state.password_crypto.clone(),
        operator.id_user,
        operator.encrypted_password_hash.clone(),
        Zeroizing::new(password.to_owned()),
    )
    .await
    .map_err(AppError::internal)?;
    Ok(verification.valid)
}

fn mfa_repository(state: &AppState) -> OperatorMfaRepository {
    OperatorMfaRepository::new(state.database.clone(), state.password_crypto.clone())
}

fn is_admin(operator: &Operator) -> bool {
    operator.operator_type == "admin"
}

async fn render_overview(
    state: &AppState,
    token: CsrfToken,
    operator: &Operator,
    message: String,
    message_class: &'static str,
) -> Result<Response, AppError> {
    let status = mfa_repository(state).status(operator.id_user).await?;
    render_with_csrf(token, |csrf_token| MfaTemplate {
        active_page: nav::USER_STATUS,
        csrf_token,
        show_acl: is_admin(operator),
        enabled: status.enabled,
        remaining_recovery_codes: status.remaining_recovery_codes,
        show_enroll: false,
        secret_base32: String::new(),
        otpauth_uri: String::new(),
        show_recovery: false,
        recovery_codes: Vec::new(),
        message,
        message_class,
    })
}

fn render_enroll(
    token: CsrfToken,
    operator: &Operator,
    secret_base32: String,
    otpauth_uri: String,
    message: String,
    message_class: &'static str,
) -> Result<Response, AppError> {
    render_with_csrf(token, |csrf_token| MfaTemplate {
        active_page: nav::USER_STATUS,
        csrf_token,
        show_acl: is_admin(operator),
        enabled: false,
        remaining_recovery_codes: 0,
        show_enroll: true,
        secret_base32,
        otpauth_uri,
        show_recovery: false,
        recovery_codes: Vec::new(),
        message,
        message_class,
    })
}

fn render_recovery(
    token: CsrfToken,
    operator: &Operator,
    recovery_codes: Vec<String>,
    message: String,
) -> Result<Response, AppError> {
    render_with_csrf(token, |csrf_token| MfaTemplate {
        active_page: nav::USER_STATUS,
        csrf_token,
        show_acl: is_admin(operator),
        enabled: true,
        remaining_recovery_codes: recovery_codes.len() as u64,
        show_enroll: false,
        secret_base32: String::new(),
        otpauth_uri: String::new(),
        show_recovery: true,
        recovery_codes,
        message,
        message_class: "success",
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

fn audit_mfa_event(action: &str, id_user: i32, username: &str) {
    tracing::info!(
        target: "audit",
        event = "mfa",
        action = %action,
        id_user,
        username = %username,
        "two-factor administration action"
    );
}
