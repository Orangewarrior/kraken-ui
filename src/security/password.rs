use memchr::memmem;

const MINIMUM_PASSWORD_LENGTH: usize = 14;

pub trait PasswordPolicy: Send + Sync {
    fn validate(&self, password: &str, identity: &str) -> Result<(), PasswordPolicyError>;
}

#[derive(Clone, Default)]
pub struct MediumOrStrongPasswordPolicy;

#[derive(Debug)]
pub struct PasswordPolicyError {
    message: &'static str,
}

impl std::fmt::Display for PasswordPolicyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for PasswordPolicyError {}

impl PasswordPolicy for MediumOrStrongPasswordPolicy {
    fn validate(&self, password: &str, identity: &str) -> Result<(), PasswordPolicyError> {
        let bytes = password.as_bytes();
        let has_uppercase = bytes.iter().any(u8::is_ascii_uppercase);
        let has_lowercase = bytes.iter().any(u8::is_ascii_lowercase);
        let has_digit = bytes.iter().any(u8::is_ascii_digit);
        let has_symbol = bytes.iter().any(|byte| !byte.is_ascii_alphanumeric());
        let character_classes = [has_uppercase, has_lowercase, has_digit, has_symbol]
            .into_iter()
            .filter(|present| *present)
            .count();
        let lowercase_password = password.to_ascii_lowercase();
        let lowercase_identity = identity.to_ascii_lowercase();
        let contains_identity =
            memmem::find(lowercase_password.as_bytes(), lowercase_identity.as_bytes()).is_some();

        if password.chars().count() < MINIMUM_PASSWORD_LENGTH {
            return Err(policy_error("password must contain at least 14 characters"));
        }
        if character_classes < 3 {
            return Err(policy_error(
                "password must include at least three character classes",
            ));
        }
        if identity.len() >= 3 && contains_identity {
            return Err(policy_error("password cannot contain the login identifier"));
        }
        Ok(())
    }
}

fn policy_error(message: &'static str) -> PasswordPolicyError {
    PasswordPolicyError { message }
}

#[cfg(test)]
mod tests {
    use super::{MediumOrStrongPasswordPolicy, PasswordPolicy};

    #[test]
    fn accepts_a_strong_password() {
        let policy = MediumOrStrongPasswordPolicy;
        assert!(policy.validate("Long&Random#Pass9", "admin").is_ok());
    }

    #[test]
    fn rejects_password_with_identity() {
        let policy = MediumOrStrongPasswordPolicy;
        assert!(policy.validate("Admin&Random#Pass9", "admin").is_err());
    }

    #[test]
    fn accepts_a_medium_password_with_three_character_classes() {
        let policy = MediumOrStrongPasswordPolicy;
        assert!(policy.validate("long-random-pass9", "admin").is_ok());
    }

    #[test]
    fn accepts_a_passphrase_containing_spaces() {
        let policy = MediumOrStrongPasswordPolicy;
        // Spaces are allowed (NIST 800-63B) so long passphrases are practical.
        assert!(policy.validate("correct horse battery 9", "admin").is_ok());
    }
}
