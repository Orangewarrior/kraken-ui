use axum_csrf::CsrfToken;

/// Validates a submitted CSRF token against the session token.
///
/// This is the single source of truth for CSRF validation. It first rejects any
/// token that is not well formed (so a malformed or markup-bearing value never
/// reaches the cryptographic check) and then defers to `axum_csrf` for the
/// authenticated comparison. The well-formedness gate is a cheap byte scan: the
/// authenticity token is Base64, so a full HTML sanitiser pass — one per POST —
/// would be wasted work where a character-class check is exact and constant-cost.
pub fn verify(token: &CsrfToken, submitted: &str) -> bool {
    is_well_formed(submitted) && token.verify(submitted).is_ok()
}

/// Accepts only a non-empty, bounded, Base64-shaped token: ASCII alphanumerics
/// plus the Base64 and URL-safe Base64 symbols. This excludes whitespace, control
/// bytes and the `<`, `>`, `&` markup characters the previous sanitiser guarded
/// against, without parsing the value as HTML.
fn is_well_formed(submitted: &str) -> bool {
    !submitted.is_empty()
        && submitted.len() <= 512
        && submitted.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
        })
}

#[cfg(test)]
mod tests {
    use super::is_well_formed;

    #[test]
    fn accepts_base64_shaped_tokens() {
        assert!(is_well_formed("dGVzdA=="));
        assert!(is_well_formed("abc-DEF_123"));
    }

    #[test]
    fn rejects_empty_markup_and_oversized_tokens() {
        assert!(!is_well_formed(""));
        assert!(!is_well_formed("<script>"));
        assert!(!is_well_formed("has space"));
        assert!(!is_well_formed(&"a".repeat(513)));
    }
}
