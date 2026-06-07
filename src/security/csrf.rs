use axum_csrf::CsrfToken;

use crate::security::sanitize;

/// Validates a submitted CSRF token against the session token.
///
/// This is the single source of truth for CSRF validation. It first rejects any
/// token that the sanitiser would alter (so only well-formed tokens are
/// considered) and then defers to `axum_csrf` for the cryptographic check.
pub fn verify(token: &CsrfToken, submitted: &str) -> bool {
    sanitize::plain_text(submitted) == submitted && token.verify(submitted).is_ok()
}
