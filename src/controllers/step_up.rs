use tower_sessions::Session;
use zeroize::Zeroizing;

use crate::{
    controllers::auth,
    error::AppError,
    models::{
        operator::Model as Operator, operator_mfa_repository::OperatorMfaRepository,
        operator_repository::OperatorRepository,
    },
    security::sanitize,
    services::password_crypto::spawn_verify,
    state::AppState,
};

pub enum StepUpOutcome {
    Verified(Operator),
    Unauthorized,
    Rejected(&'static str),
}

/// Re-authenticates the current session before a sensitive self-service or admin
/// operation. A password is always required. If two-factor is already enabled on
/// the account, a fresh TOTP/recovery code is required too and is consumed by the
/// normal MFA verifier.
pub async fn verify(
    state: &AppState,
    session: &Session,
    current_password: &str,
    mfa_code: &str,
) -> Result<StepUpOutcome, AppError> {
    let Some(id_user) = auth::authenticated_user_id(session).await? else {
        return Ok(StepUpOutcome::Unauthorized);
    };
    let repository = OperatorRepository::new(state.database.clone(), state.password_crypto.clone());
    let Some(operator) = repository.find_by_id(id_user).await? else {
        return Ok(StepUpOutcome::Unauthorized);
    };

    if current_password.is_empty()
        || current_password.len() > 256
        || sanitize::secret_has_rejected_markup(current_password)
    {
        return Ok(StepUpOutcome::Rejected(
            "The current password is incorrect.",
        ));
    }
    let verification = spawn_verify(
        state.password_crypto.clone(),
        operator.id_user,
        operator.encrypted_password_hash.clone(),
        Zeroizing::new(current_password.to_owned()),
    )
    .await
    .map_err(AppError::internal)?;
    if !verification.valid {
        return Ok(StepUpOutcome::Rejected(
            "The current password is incorrect.",
        ));
    }

    let mfa = OperatorMfaRepository::new(state.database.clone(), state.password_crypto.clone());
    if mfa.is_enabled(operator.id_user).await? {
        let code = sanitize::plain_text(mfa_code);
        if code.is_empty() {
            return Ok(StepUpOutcome::Rejected(
                "Enter your current two-factor code.",
            ));
        }
        if code.len() > 32 || !mfa.verify_login_code(operator.id_user, &code).await? {
            return Ok(StepUpOutcome::Rejected(
                "The two-factor code is invalid or expired.",
            ));
        }
    }

    Ok(StepUpOutcome::Verified(operator))
}
