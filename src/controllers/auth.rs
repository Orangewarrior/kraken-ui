use std::{net::SocketAddr, time::Duration};

use anyhow::anyhow;
use axum::{
    Form,
    extract::{ConnectInfo, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};
use axum_csrf::CsrfToken;
use serde::Deserialize;
use time::OffsetDateTime;
use tower_sessions::Session;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::{
    error::AppError,
    models::{
        operator::OperatorRole, operator_mfa_repository::OperatorMfaRepository,
        operator_repository::OperatorRepository, session_store::USER_ID_FIELD,
    },
    security::{csrf, sanitize},
    services::password_crypto::{spawn_dummy, spawn_verify},
    state::AppState,
    view::{LoginTemplate, MfaChallengeTemplate, csrf_error_response, render},
};

// Shared with the session store, which mirrors this value into an indexed column
// so an operator's sessions can be revoked the moment their authority changes.
const AUTHENTICATED_USER_ID: &str = USER_ID_FIELD;
const AUTHENTICATED_USERNAME: &str = "authenticated_username";
const AUTHENTICATED_OPERATOR_TYPE: &str = "authenticated_operator_type";
// Set when an operator has passed the password check but still owes a second
// factor. It grants nothing on its own: the route guards only ever read
// `AUTHENTICATED_OPERATOR_TYPE`, which stays unset until the code is verified.
const MFA_PENDING_USER_ID: &str = "mfa_pending_user_id";
// Timestamp (unix seconds) stored next to the pending marker so the second factor
// must be supplied promptly. This window is deliberately short and independent of
// the session's idle expiry, which may be hours.
const MFA_PENDING_AT: &str = "mfa_pending_at";
const MFA_PENDING_TTL_SECONDS: i64 = 5 * 60;

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

#[derive(Deserialize)]
pub struct MfaCodeForm {
    code: String,
    csrf_token: String,
}

pub async fn login_page(token: CsrfToken, session: Session) -> Result<Response, AppError> {
    if authenticated_operator_type(&session)
        .await?
        .as_deref()
        .is_some_and(is_console_role)
    {
        return Ok(Redirect::to("/kraken_ui/auth/admin_panel").into_response());
    }
    login_response(token, "").await
}

/// Whether `operator_type` may hold an interactive console session. Administrators
/// and operators get the full console; auditors get a read-only subset (dashboard,
/// attacks monitor and their own account settings). Any other stored role — even
/// with valid credentials — is refused at sign-in.
pub fn is_console_role(operator_type: &str) -> bool {
    OperatorRole::parse(operator_type).is_some_and(OperatorRole::can_use_console)
}

pub async fn login_submit(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    token: CsrfToken,
    session: Session,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Result<Response, AppError> {
    if !csrf::verify(&token, &form.csrf_token) {
        return Ok(csrf_error_response());
    }

    let client_ip = crate::security::client_ip::effective_client_ip(
        peer.ip(),
        &headers,
        &state.config.trusted_proxy_ips,
    )
    .to_string();
    let ip_key = format!("ip:{client_ip}");

    // Throttle by source IP before doing any expensive work.
    if let Some(remaining) = state.rate_limiting.login_throttle.locked_for(&ip_key) {
        audit_login(&client_ip, "", "locked");
        return locked_login_response(token, remaining).await;
    }
    if let Some(remaining) = persistent_login_retry_after(&state, &format!("login:{ip_key}")).await
    {
        audit_login(&client_ip, "", "persistent_locked");
        return locked_login_response(token, remaining).await;
    }

    let username = sanitize::plain_text(&form.login).to_ascii_lowercase();
    let password = Zeroizing::new(form.password);
    // Key the per-account counter by IP *and* account. This still slows focused
    // guessing from one source, but means an attacker cannot lock a victim out
    // of their account from unrelated addresses (an account-lockout DoS).
    let ip_user_key = format!("ip:{client_ip}|user:{username}");

    if let Some(remaining) = state.rate_limiting.login_throttle.locked_for(&ip_user_key) {
        audit_login(&client_ip, &username, "locked");
        return locked_login_response(token, remaining).await;
    }
    if let Some(remaining) =
        persistent_login_retry_after(&state, &format!("login:{ip_user_key}")).await
    {
        audit_login(&client_ip, &username, "persistent_locked");
        return locked_login_response(token, remaining).await;
    }

    if username.len() > 128
        || password.len() > 256
        || sanitize::secret_has_rejected_markup(&password)
    {
        register_login_failure(&state, &ip_key, &ip_user_key, &username, &client_ip);
        audit_login(&client_ip, &username, "invalid_input");
        return invalid_login_response(token).await;
    }
    let repository = OperatorRepository::new(state.database.clone(), state.password_crypto.clone());
    let Some(operator) = repository.find_by_username(&username).await? else {
        // Spend the same time as a real verification so unknown usernames are
        // not distinguishable by response latency.
        spawn_dummy(state.password_crypto.clone(), password).await;
        register_login_failure(&state, &ip_key, &ip_user_key, &username, &client_ip);
        audit_login(&client_ip, &username, "unknown_user");
        return invalid_login_response(token).await;
    };
    let verification = spawn_verify(
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
            register_login_failure(&state, &ip_key, &ip_user_key, &username, &client_ip);
            audit_login(&client_ip, &username, "crypto_error");
            return invalid_login_response(token).await;
        }
    };
    if !verification.valid {
        register_login_failure(&state, &ip_key, &ip_user_key, &username, &client_ip);
        audit_login(&client_ip, &username, "bad_password");
        return invalid_login_response(token).await;
    }
    if let Some(replacement_record) = verification.replacement_record {
        repository
            .update_encrypted_password(operator.id_user, replacement_record)
            .await?;
    }
    if !is_console_role(&operator.operator_type) {
        // Do not reveal that valid credentials exist for roles that cannot use the
        // console: return the same generic failure response a wrong password gets.
        audit_login(&client_ip, &username, "forbidden_role");
        return invalid_login_response(token).await;
    }

    // Successful password authentication: clear any recorded failures.
    state.rate_limiting.login_throttle.record_success(&ip_key);
    state
        .rate_limiting
        .login_throttle
        .record_success(&ip_user_key);

    // If the account has two-factor enabled, the password is only the first step.
    // Park a "pending" marker on a fresh session id and send the operator to the
    // code challenge; do not grant any authenticated role yet.
    let mfa = OperatorMfaRepository::new(state.database.clone(), state.password_crypto.clone());
    if mfa.is_enabled(operator.id_user).await? {
        session
            .cycle_id()
            .await
            .map_err(|error| AppError::internal(anyhow!("failed to rotate session id: {error}")))?;
        session
            .insert(MFA_PENDING_USER_ID, operator.id_user)
            .await
            .map_err(|error| {
                AppError::internal(anyhow!(
                    "failed to persist pending two-factor state: {error}"
                ))
            })?;
        session
            .insert(MFA_PENDING_AT, OffsetDateTime::now_utc().unix_timestamp())
            .await
            .map_err(|error| {
                AppError::internal(anyhow!(
                    "failed to persist pending two-factor timestamp: {error}"
                ))
            })?;
        audit_login(&client_ip, &username, "password_ok_mfa_required");
        return Ok(Redirect::to("/kraken_ui/auth/mfa_challenge").into_response());
    }

    establish_session(&session, &operator).await?;
    audit_login(&client_ip, &username, "success");
    Ok(Redirect::to("/kraken_ui/auth/admin_panel").into_response())
}

/// The two-factor challenge form, shown after a correct password to an operator
/// with two-factor enabled. Reachable only while a pending marker is on the
/// session; otherwise it bounces to the login page.
pub async fn mfa_challenge_page(token: CsrfToken, session: Session) -> Result<Response, AppError> {
    if mfa_pending_user_id(&session).await?.is_none() {
        return Ok(Redirect::to("/kraken_ui/login").into_response());
    }
    mfa_challenge_response(token, "").await
}

pub async fn mfa_verify(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    token: CsrfToken,
    session: Session,
    headers: HeaderMap,
    Form(form): Form<MfaCodeForm>,
) -> Result<Response, AppError> {
    if !csrf::verify(&token, &form.csrf_token) {
        return Ok(csrf_error_response());
    }
    let Some(id_user) = mfa_pending_user_id(&session).await? else {
        return Ok(Redirect::to("/kraken_ui/login").into_response());
    };

    let client_ip = crate::security::client_ip::effective_client_ip(
        peer.ip(),
        &headers,
        &state.config.trusted_proxy_ips,
    )
    .to_string();
    // Throttle code guessing per source IP and pending account, mirroring the
    // password path, so a six-digit code cannot be brute-forced online.
    let throttle_key = format!("mfa:{client_ip}|user:{id_user}");
    if let Some(remaining) = state.rate_limiting.login_throttle.locked_for(&throttle_key) {
        audit_login(&client_ip, "", "mfa_locked");
        return locked_mfa_response(token, remaining).await;
    }
    if let Some(remaining) =
        persistent_login_retry_after(&state, &format!("login:{throttle_key}")).await
    {
        audit_login(&client_ip, "", "mfa_persistent_locked");
        return locked_mfa_response(token, remaining).await;
    }

    let code = sanitize::plain_text(&form.code);
    let repository = OperatorRepository::new(state.database.clone(), state.password_crypto.clone());
    let Some(operator) = repository.find_by_id(id_user).await? else {
        // The account disappeared between the two steps; abandon the half-login.
        let _ = session.flush().await;
        return Ok(Redirect::to("/kraken_ui/login").into_response());
    };

    let mfa = OperatorMfaRepository::new(state.database.clone(), state.password_crypto.clone());
    if code.len() > 32 || !mfa.verify_login_code(id_user, &code).await? {
        state
            .rate_limiting
            .login_throttle
            .record_failure(&throttle_key);
        audit_login(&client_ip, &operator.username, "mfa_failed");
        return mfa_challenge_response(token, "Invalid or expired code").await;
    }

    // Re-check the role at finalisation, exactly as the password path does, in
    // case it changed while the challenge was outstanding.
    if !is_console_role(&operator.operator_type) {
        audit_login(&client_ip, &operator.username, "forbidden_role");
        let _ = session.flush().await;
        return Ok(Redirect::to("/kraken_ui/login").into_response());
    }

    state
        .rate_limiting
        .login_throttle
        .record_success(&throttle_key);
    clear_mfa_pending(&session).await?;
    establish_session(&session, &operator).await?;
    audit_login(&client_ip, &operator.username, "success");
    Ok(Redirect::to("/kraken_ui/auth/admin_panel").into_response())
}

/// Promotes a session to fully authenticated: rotates the id to prevent fixation
/// and records the operator identity the route guards read.
async fn establish_session(
    session: &Session,
    operator: &crate::models::operator::Model,
) -> Result<(), AppError> {
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
    Ok(())
}

async fn mfa_pending_user_id(session: &Session) -> Result<Option<i32>, AppError> {
    let Some(id_user) = session
        .get::<i32>(MFA_PENDING_USER_ID)
        .await
        .map_err(|error| {
            AppError::internal(anyhow!("failed to read pending two-factor state: {error}"))
        })?
    else {
        return Ok(None);
    };
    let started_at = session
        .get::<i64>(MFA_PENDING_AT)
        .await
        .map_err(|error| {
            AppError::internal(anyhow!(
                "failed to read pending two-factor timestamp: {error}"
            ))
        })?
        .unwrap_or(0);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    // Expire a half-finished login left sitting on the challenge, independently of
    // the (much longer) session idle timeout.
    if started_at == 0 || now.saturating_sub(started_at) > MFA_PENDING_TTL_SECONDS {
        clear_mfa_pending(session).await?;
        return Ok(None);
    }
    Ok(Some(id_user))
}

/// Removes the pending two-factor markers (id and timestamp) from the session.
async fn clear_mfa_pending(session: &Session) -> Result<(), AppError> {
    session
        .remove::<i32>(MFA_PENDING_USER_ID)
        .await
        .map_err(|error| {
            AppError::internal(anyhow!("failed to clear pending two-factor state: {error}"))
        })?;
    session
        .remove::<i64>(MFA_PENDING_AT)
        .await
        .map_err(|error| {
            AppError::internal(anyhow!(
                "failed to clear pending two-factor timestamp: {error}"
            ))
        })?;
    Ok(())
}

pub async fn logout(
    token: CsrfToken,
    session: Session,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    if !csrf::verify(&token, &form.csrf_token) {
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

pub async fn authenticated_role(session: &Session) -> Result<Option<OperatorRole>, AppError> {
    Ok(authenticated_operator_type(session)
        .await?
        .as_deref()
        .and_then(OperatorRole::parse))
}

/// Whether the current session belongs to an administrator. Controllers use this
/// to decide if the ACL section of the sidebar should be rendered.
pub async fn is_admin(session: &Session) -> Result<bool, AppError> {
    Ok(authenticated_role(session)
        .await?
        .is_some_and(OperatorRole::can_administer))
}

/// Whether the current session belongs to an auditor. Auditors get a deliberately
/// narrow console — dashboard, attacks monitor and their own account settings — so
/// controllers use this to hide the rule-management section of the sidebar (the
/// routes behind it stay guarded server-side regardless).
pub async fn is_auditor(session: &Session) -> Result<bool, AppError> {
    Ok(authenticated_role(session).await? == Some(OperatorRole::Auditor))
}

pub async fn authenticated_username(session: &Session) -> Option<String> {
    session.get::<String>(AUTHENTICATED_USERNAME).await.ok()?
}

fn register_login_failure(
    state: &AppState,
    ip_key: &str,
    ip_user_key: &str,
    username: &str,
    client_ip: &str,
) {
    state.rate_limiting.login_throttle.record_failure(ip_key);
    state
        .rate_limiting
        .login_throttle
        .record_failure(ip_user_key);
    // Detection only: surface a single account drawing failures from many sources,
    // which per-IP throttling (deliberately) cannot see. This never locks anything.
    if !username.is_empty()
        && state
            .rate_limiting
            .account_failure_monitor
            .note_failure(username)
    {
        warn!(
            target: "audit",
            event = "account_guessing_suspected",
            username = %username,
            client_ip = %client_ip,
            "elevated authentication failures for a single account across sources"
        );
    }
}

async fn persistent_login_retry_after(state: &AppState, key: &str) -> Option<Duration> {
    let limiter = state.rate_limiting.login_persistent.as_ref()?;
    let decision = limiter.check(key).await;
    (!decision.allowed).then_some(decision.retry_after)
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

async fn locked_mfa_response(token: CsrfToken, remaining: Duration) -> Result<Response, AppError> {
    let minutes = remaining.as_secs().div_ceil(60).max(1);
    mfa_challenge_response(
        token,
        &format!("Too many attempts. Try again in about {minutes} minute(s)."),
    )
    .await
}

async fn mfa_challenge_response(
    token: CsrfToken,
    error_message: &str,
) -> Result<Response, AppError> {
    let authenticity_token = token
        .authenticity_token()
        .map_err(|error| AppError::internal(anyhow!("failed to create CSRF token: {error}")))?;
    let response = render(MfaChallengeTemplate {
        product_name: "KrakenWAF",
        csrf_token: &authenticity_token,
        error_message,
    })?;
    Ok((token, response).into_response())
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

#[cfg(test)]
mod tests {
    use super::is_console_role;

    #[test]
    fn admin_operator_and_auditor_may_hold_a_console_session() {
        assert!(is_console_role("admin"));
        assert!(is_console_role("operator"));
        assert!(is_console_role("auditor"));
    }

    #[test]
    fn unknown_or_future_roles_are_refused_at_sign_in() {
        assert!(!is_console_role("viewer"));
        assert!(!is_console_role("Auditor")); // the stored value is lower-cased
        assert!(!is_console_role(""));
        assert!(!is_console_role("administrator"));
    }
}
