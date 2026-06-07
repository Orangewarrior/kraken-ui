use std::{env, path::Path, sync::Arc};

use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use dryoc::{
    classic::crypto_pwhash::{
        crypto_pwhash_str, crypto_pwhash_str_needs_rehash, crypto_pwhash_str_verify,
    },
    constants::{CRYPTO_PWHASH_MEMLIMIT_MODERATE, CRYPTO_PWHASH_OPSLIMIT_MODERATE},
};
use zeroize::Zeroizing;

const KEY_BYTES: usize = 32;
const KEY_ID_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const AAD_PREFIX: &str = "kraken_ui:v1:user:";
const DUMMY_USER_ID: i32 = 0;
const DUMMY_PASSWORD: &str = "kraken-ui::timing-equaliser::v1";

pub trait PasswordCryptoService: Send + Sync {
    fn encrypt_password(&self, user_id: i32, password: &str) -> anyhow::Result<String>;
    fn verify_password(
        &self,
        user_id: i32,
        encrypted_record: &str,
        password: &str,
    ) -> anyhow::Result<PasswordVerification>;

    /// Runs a verification of equivalent cost against a throwaway record so that
    /// a login attempt for a non-existent account takes the same time as one for
    /// a real account. This closes the username-enumeration timing side channel.
    ///
    /// The default is a no-op, which is appropriate for in-test doubles.
    fn run_dummy_verification(&self, _password: &str) {}
}

#[derive(Debug, PartialEq)]
pub struct PasswordVerification {
    pub valid: bool,
    pub replacement_record: Option<String>,
}

pub struct DryocPasswordCryptoService {
    key_id: [u8; KEY_ID_BYTES],
    key: Zeroizing<[u8; KEY_BYTES]>,
    dummy_record: String,
}

impl DryocPasswordCryptoService {
    pub fn from_environment() -> anyhow::Result<Self> {
        let key_id =
            env::var("KRAKEN_UI_PASSWORD_KEY_ID").unwrap_or_else(|_| "primary-v1".to_owned());
        let encoded_key = match env::var("KRAKEN_UI_PASSWORD_KEY") {
            Ok(value) => value,
            Err(_) => {
                let key_file = env::var("KRAKEN_UI_PASSWORD_KEY_FILE")
                    .context("set KRAKEN_UI_PASSWORD_KEY or KRAKEN_UI_PASSWORD_KEY_FILE")?;
                crate::security::read_protected_file(Path::new(&key_file))?
            }
        };
        Self::from_base64_key(&key_id, encoded_key.trim())
    }

    pub fn from_base64_key(key_id: &str, encoded_key: &str) -> anyhow::Result<Self> {
        let key_bytes = STANDARD
            .decode(encoded_key)
            .context("password encryption key must be valid base64")?;
        let key_array: [u8; KEY_BYTES] = key_bytes.try_into().map_err(|_| {
            anyhow::anyhow!("password encryption key must decode to exactly {KEY_BYTES} bytes")
        })?;
        let mut service = Self {
            key_id: normalize_key_id(key_id)?,
            key: Zeroizing::new(key_array),
            dummy_record: String::new(),
        };
        // Precompute a real encrypted Argon2id record once, so the dummy
        // verification path has the same cost as a genuine one.
        service.dummy_record = service.encrypt_password(DUMMY_USER_ID, DUMMY_PASSWORD)?;
        Ok(service)
    }

    fn encrypt_hash(&self, user_id: i32, hash_record: &str) -> anyhow::Result<String> {
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| anyhow::anyhow!("unable to construct XChaCha20-Poly1305 key"))?;
        let mut nonce_bytes = [0_u8; NONCE_BYTES];
        dryoc::rng::copy_randombytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let aad = password_aad(user_id);
        let encrypted = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: hash_record.as_bytes(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("XChaCha20-Poly1305 encryption failed"))?;
        let mut envelope = Vec::with_capacity(KEY_ID_BYTES + NONCE_BYTES + encrypted.len());
        envelope.extend_from_slice(&self.key_id);
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&encrypted);
        Ok(STANDARD.encode(envelope))
    }

    fn decrypt_hash(&self, user_id: i32, encrypted_record: &str) -> anyhow::Result<String> {
        let envelope = STANDARD
            .decode(encrypted_record)
            .context("encrypted password record is not valid base64")?;
        let minimum_length = KEY_ID_BYTES + NONCE_BYTES + TAG_BYTES;
        if envelope.len() < minimum_length {
            bail!("encrypted password record is truncated");
        }
        if envelope[..KEY_ID_BYTES] != self.key_id {
            bail!("encrypted password record references an unavailable key id");
        }
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| anyhow::anyhow!("unable to construct XChaCha20-Poly1305 key"))?;
        let nonce = XNonce::from_slice(&envelope[KEY_ID_BYTES..KEY_ID_BYTES + NONCE_BYTES]);
        let ciphertext = &envelope[KEY_ID_BYTES + NONCE_BYTES..];
        let aad = password_aad(user_id);
        let hash_bytes = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("password record authentication failed"))?;
        String::from_utf8(hash_bytes).context("decrypted password hash is not UTF-8")
    }
}

impl PasswordCryptoService for DryocPasswordCryptoService {
    fn encrypt_password(&self, user_id: i32, password: &str) -> anyhow::Result<String> {
        let hash_record = crypto_pwhash_str(
            password.as_bytes(),
            CRYPTO_PWHASH_OPSLIMIT_MODERATE,
            CRYPTO_PWHASH_MEMLIMIT_MODERATE,
        )
        .context("dryoc could not hash the password")?;
        self.encrypt_hash(user_id, &hash_record)
    }

    fn verify_password(
        &self,
        user_id: i32,
        encrypted_record: &str,
        password: &str,
    ) -> anyhow::Result<PasswordVerification> {
        let hash_record = self.decrypt_hash(user_id, encrypted_record)?;
        if crypto_pwhash_str_verify(&hash_record, password.as_bytes()).is_err() {
            return Ok(PasswordVerification {
                valid: false,
                replacement_record: None,
            });
        }

        let needs_rehash = crypto_pwhash_str_needs_rehash(
            &hash_record,
            CRYPTO_PWHASH_OPSLIMIT_MODERATE,
            CRYPTO_PWHASH_MEMLIMIT_MODERATE,
        )
        .context("unable to evaluate password hash parameters")?;
        let replacement_record = if needs_rehash {
            Some(self.encrypt_password(user_id, password)?)
        } else {
            None
        };
        Ok(PasswordVerification {
            valid: true,
            replacement_record,
        })
    }

    fn run_dummy_verification(&self, password: &str) {
        // The result is intentionally discarded; only the timing matters.
        let _ = self.verify_password(DUMMY_USER_ID, &self.dummy_record, password);
    }
}

/// Verifies a password on the blocking pool, so the Argon2id work never stalls
/// the async runtime. The plaintext is held in `Zeroizing` and wiped when the
/// task finishes.
pub async fn spawn_verify(
    service: Arc<dyn PasswordCryptoService>,
    user_id: i32,
    encrypted_record: String,
    password: Zeroizing<String>,
) -> anyhow::Result<PasswordVerification> {
    tokio::task::spawn_blocking(move || {
        service.verify_password(user_id, &encrypted_record, password.as_str())
    })
    .await
    .context("password verification task failed")?
}

/// Encrypts a password on the blocking pool. See [`spawn_verify`].
pub async fn spawn_encrypt(
    service: Arc<dyn PasswordCryptoService>,
    user_id: i32,
    password: Zeroizing<String>,
) -> anyhow::Result<String> {
    tokio::task::spawn_blocking(move || service.encrypt_password(user_id, password.as_str()))
        .await
        .context("password encryption task failed")?
}

/// Runs the timing-equalising dummy verification on the blocking pool.
pub async fn spawn_dummy(service: Arc<dyn PasswordCryptoService>, password: Zeroizing<String>) {
    let _ = tokio::task::spawn_blocking(move || service.run_dummy_verification(password.as_str()))
        .await;
}

fn normalize_key_id(key_id: &str) -> anyhow::Result<[u8; KEY_ID_BYTES]> {
    if key_id.is_empty() || key_id.len() > KEY_ID_BYTES || !key_id.is_ascii() {
        bail!("KRAKEN_UI_PASSWORD_KEY_ID must contain 1 to {KEY_ID_BYTES} ASCII bytes");
    }
    let mut normalized = [0_u8; KEY_ID_BYTES];
    normalized[..key_id.len()].copy_from_slice(key_id.as_bytes());
    Ok(normalized)
}

fn password_aad(user_id: i32) -> String {
    format!("{AAD_PREFIX}{user_id}:password_hash")
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use dryoc::{
        classic::crypto_pwhash::crypto_pwhash_str,
        constants::{CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE, CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE},
    };

    use super::{DryocPasswordCryptoService, PasswordCryptoService};

    fn service() -> DryocPasswordCryptoService {
        DryocPasswordCryptoService::from_base64_key("test-v1", &STANDARD.encode([7_u8; 32]))
            .unwrap_or_else(|error| panic!("test crypto service must initialize: {error}"))
    }

    #[test]
    fn encrypts_and_verifies_password_for_the_bound_user() {
        let service = service();
        let encrypted = service
            .encrypt_password(42, "Long&Random#Pass9")
            .unwrap_or_else(|error| panic!("password must encrypt: {error}"));

        assert!(memchr::memmem::find(encrypted.as_bytes(), b"$argon2").is_none());
        let verified = service
            .verify_password(42, &encrypted, "Long&Random#Pass9")
            .unwrap_or_else(|error| panic!("password must verify: {error}"));
        assert!(verified.valid);
        assert!(verified.replacement_record.is_none());
    }

    #[test]
    fn aad_prevents_moving_a_record_to_another_user() {
        let service = service();
        let encrypted = service
            .encrypt_password(42, "Long&Random#Pass9")
            .unwrap_or_else(|error| panic!("password must encrypt: {error}"));
        assert!(
            service
                .verify_password(43, &encrypted, "Long&Random#Pass9")
                .is_err()
        );
    }

    #[test]
    fn replaces_a_valid_hash_when_parameters_need_upgrade() {
        let service = service();
        let old_hash = crypto_pwhash_str(
            b"Long&Random#Pass9",
            CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        )
        .unwrap_or_else(|error| panic!("interactive password hash must be generated: {error}"));
        let encrypted = service
            .encrypt_hash(42, &old_hash)
            .unwrap_or_else(|error| panic!("old password hash must encrypt: {error}"));
        let verified = service
            .verify_password(42, &encrypted, "Long&Random#Pass9")
            .unwrap_or_else(|error| panic!("password must verify: {error}"));

        assert!(verified.valid);
        assert!(verified.replacement_record.is_some());
    }
}
