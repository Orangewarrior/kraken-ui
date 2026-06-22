use std::sync::Arc;

use anyhow::Context;
use sea_orm::{
    ActiveModelTrait, ActiveValue::NotSet, ColumnTrait, ConnectionTrait, DatabaseConnection,
    DbBackend, EntityTrait, PaginatorTrait, QueryFilter, Set, Statement, TransactionTrait, Value,
};
use time::OffsetDateTime;

use crate::{
    models::{
        current_timestamp, operator_mfa_recovery_code as recovery, operator_mfa_totp as totp,
    },
    services::password_crypto::PasswordCryptoService,
};

/// The TOTP step, in seconds. Matches the default of every common authenticator
/// app, so a freshly enrolled secret works without further configuration.
const TOTP_PERIOD: u64 = 30;
/// Issuer shown in the authenticator app and embedded in the provisioning URI.
const ISSUER: &str = "KrakenWAF";
/// AAD domains keep a sealed TOTP secret and a sealed recovery code from being
/// substituted for one another, even though both use the same envelope.
const TOTP_DOMAIN: &str = "totp";
const RECOVERY_DOMAIN: &str = "mfa_recovery";
/// How many single-use recovery codes are minted when two-factor is confirmed.
const RECOVERY_CODE_COUNT: usize = 10;
/// Unambiguous alphabet for recovery codes: no `0/O` or `1/I` confusion. 32
/// symbols, so each byte maps to exactly eight symbols (256 / 32) with no bias.
const RECOVERY_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Clone)]
pub struct OperatorMfaRepository {
    database: DatabaseConnection,
    password_crypto: Arc<dyn PasswordCryptoService>,
}

/// What an operator needs to add the account to their authenticator: the base32
/// secret for manual entry and the `otpauth://` provisioning URI.
pub struct MfaEnrollment {
    pub secret_base32: String,
    pub otpauth_uri: String,
}

/// The two-factor state shown on the management page.
pub struct MfaStatus {
    pub enabled: bool,
    pub remaining_recovery_codes: u64,
}

/// The result of confirming a pending enrollment.
#[derive(Debug)]
pub enum ConfirmOutcome {
    /// There is no pending enrollment to confirm (or it was already confirmed).
    NoPendingEnrollment,
    /// The supplied code did not match the pending secret.
    InvalidCode,
    /// Two-factor is now enabled; these freshly minted recovery codes are shown
    /// to the operator exactly once.
    Confirmed { recovery_codes: Vec<String> },
}

impl OperatorMfaRepository {
    pub fn new(
        database: DatabaseConnection,
        password_crypto: Arc<dyn PasswordCryptoService>,
    ) -> Self {
        Self {
            database,
            password_crypto,
        }
    }

    async fn totp_row(&self, id_user: i32) -> anyhow::Result<Option<totp::Model>> {
        totp::Entity::find()
            .filter(totp::Column::IdUser.eq(id_user))
            .one(&self.database)
            .await
            .context("failed to query the operator TOTP record")
    }

    /// Returns the operator's TOTP row only when two-factor is confirmed; `None`
    /// for a pending or absent enrollment.
    async fn confirmed_totp_row(&self, id_user: i32) -> anyhow::Result<Option<totp::Model>> {
        Ok(self
            .totp_row(id_user)
            .await?
            .filter(|row| row.confirmed != 0))
    }

    pub async fn status(&self, id_user: i32) -> anyhow::Result<MfaStatus> {
        let enabled = self
            .totp_row(id_user)
            .await?
            .is_some_and(|row| row.confirmed != 0);
        let remaining_recovery_codes = if enabled {
            self.remaining_recovery_count(id_user).await?
        } else {
            0
        };
        Ok(MfaStatus {
            enabled,
            remaining_recovery_codes,
        })
    }

    pub async fn is_enabled(&self, id_user: i32) -> anyhow::Result<bool> {
        Ok(self
            .totp_row(id_user)
            .await?
            .is_some_and(|row| row.confirmed != 0))
    }

    async fn remaining_recovery_count(&self, id_user: i32) -> anyhow::Result<u64> {
        recovery::Entity::find()
            .filter(recovery::Column::IdUser.eq(id_user))
            .filter(recovery::Column::Used.eq(0))
            .count(&self.database)
            .await
            .context("failed to count remaining recovery codes")
    }

    /// Starts (or restarts) enrollment: generates a fresh secret, stores it
    /// unconfirmed, and returns the data the operator needs to register it. The
    /// secret is not active until [`Self::confirm`] succeeds.
    pub async fn begin_enrollment(
        &self,
        id_user: i32,
        account_label: &str,
    ) -> anyhow::Result<MfaEnrollment> {
        let mut secret_bytes = [0_u8; 20];
        dryoc::rng::copy_randombytes(&mut secret_bytes);
        let generator = otpauth::TOTP::from_bytes(&secret_bytes);
        let secret_base32 = generator.base32_secret();
        let otpauth_uri = generator.to_uri(format!("{ISSUER}:{account_label}"), ISSUER.to_owned());
        let encrypted_secret =
            self.password_crypto
                .encrypt_secret(id_user, TOTP_DOMAIN, &secret_base32)?;

        let transaction = self
            .database
            .begin()
            .await
            .context("failed to start TOTP enrollment transaction")?;

        // `id_user` is unique, so any previous (pending or stale) enrollment must
        // go before the new one is inserted. Keep the delete and insert in one
        // transaction so a storage failure cannot leave the account without either
        // the old or the new enrollment row.
        totp::Entity::delete_many()
            .filter(totp::Column::IdUser.eq(id_user))
            .exec(&transaction)
            .await
            .context("failed to clear the previous TOTP enrollment")?;
        totp::ActiveModel {
            id_totp: NotSet,
            id_user: Set(id_user),
            encrypted_secret: Set(encrypted_secret),
            confirmed: Set(0),
            created_at: Set(current_timestamp()),
            confirmed_at: Set(None),
            last_used_step: NotSet,
        }
        .insert(&transaction)
        .await
        .context("failed to store the pending TOTP enrollment")?;
        transaction
            .commit()
            .await
            .context("failed to commit TOTP enrollment")?;

        Ok(MfaEnrollment {
            secret_base32,
            otpauth_uri,
        })
    }

    /// Returns the in-progress (unconfirmed) enrollment, if any, so the setup form
    /// can be redrawn — for example after a mistyped code — without minting a new
    /// secret that would invalidate what the operator already added to their app.
    pub async fn pending_enrollment(
        &self,
        id_user: i32,
        account_label: &str,
    ) -> anyhow::Result<Option<MfaEnrollment>> {
        let Some(row) = self.totp_row(id_user).await? else {
            return Ok(None);
        };
        if row.confirmed != 0 {
            return Ok(None);
        }
        let secret_base32 =
            self.password_crypto
                .decrypt_secret(id_user, TOTP_DOMAIN, &row.encrypted_secret)?;
        let Some(generator) = otpauth::TOTP::from_base32(secret_base32.clone()) else {
            return Ok(None);
        };
        let otpauth_uri = generator.to_uri(format!("{ISSUER}:{account_label}"), ISSUER.to_owned());
        Ok(Some(MfaEnrollment {
            secret_base32,
            otpauth_uri,
        }))
    }

    /// Confirms a pending enrollment by checking a code against the pending
    /// secret. On success two-factor becomes active and recovery codes are minted.
    pub async fn confirm(&self, id_user: i32, code: &str) -> anyhow::Result<ConfirmOutcome> {
        let Some(row) = self.totp_row(id_user).await? else {
            return Ok(ConfirmOutcome::NoPendingEnrollment);
        };
        if row.confirmed != 0 {
            return Ok(ConfirmOutcome::NoPendingEnrollment);
        }
        let secret_base32 =
            self.password_crypto
                .decrypt_secret(id_user, TOTP_DOMAIN, &row.encrypted_secret)?;
        let Some(step) = verify_totp_code(&secret_base32, code) else {
            return Ok(ConfirmOutcome::InvalidCode);
        };

        let transaction = self
            .database
            .begin()
            .await
            .context("failed to start TOTP confirmation transaction")?;
        let statement = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "UPDATE operator_mfa_totp \
             SET confirmed = 1, confirmed_at = ?, last_used_step = ? \
             WHERE id_totp = ? AND id_user = ? AND confirmed = 0",
            [
                Value::from(current_timestamp()),
                Value::from(step as i64),
                Value::from(row.id_totp),
                Value::from(id_user),
            ],
        );
        let result = transaction
            .execute(statement)
            .await
            .context("failed to confirm the TOTP enrollment")?;
        if result.rows_affected() != 1 {
            transaction
                .rollback()
                .await
                .context("failed to roll back stale TOTP confirmation")?;
            return Ok(ConfirmOutcome::NoPendingEnrollment);
        }
        self.set_operator_flag_in(&transaction, id_user, true)
            .await?;
        let recovery_codes = self
            .replace_recovery_codes_in(&transaction, id_user)
            .await?;
        transaction
            .commit()
            .await
            .context("failed to commit TOTP confirmation")?;
        Ok(ConfirmOutcome::Confirmed { recovery_codes })
    }

    /// Disables two-factor for an operator, removing the secret and every recovery
    /// code and clearing the displayed flag.
    pub async fn disable(&self, id_user: i32) -> anyhow::Result<()> {
        let transaction = self
            .database
            .begin()
            .await
            .context("failed to start MFA disable transaction")?;
        totp::Entity::delete_many()
            .filter(totp::Column::IdUser.eq(id_user))
            .exec(&transaction)
            .await
            .context("failed to remove the TOTP secret")?;
        recovery::Entity::delete_many()
            .filter(recovery::Column::IdUser.eq(id_user))
            .exec(&transaction)
            .await
            .context("failed to remove recovery codes")?;
        self.set_operator_flag_in(&transaction, id_user, false)
            .await?;
        transaction
            .commit()
            .await
            .context("failed to commit MFA disable")?;
        Ok(())
    }

    /// Mints a fresh set of recovery codes for an already-enabled operator,
    /// invalidating any earlier set. `None` if two-factor is not enabled.
    pub async fn regenerate_recovery_codes(
        &self,
        id_user: i32,
    ) -> anyhow::Result<Option<Vec<String>>> {
        let transaction = self
            .database
            .begin()
            .await
            .context("failed to start recovery-code regeneration transaction")?;
        let enabled = totp::Entity::find()
            .filter(totp::Column::IdUser.eq(id_user))
            .filter(totp::Column::Confirmed.eq(1))
            .one(&transaction)
            .await
            .context("failed to query confirmed TOTP state")?
            .is_some();
        if !enabled {
            transaction
                .rollback()
                .await
                .context("failed to roll back skipped recovery-code regeneration")?;
            return Ok(None);
        }
        let recovery_codes = self
            .replace_recovery_codes_in(&transaction, id_user)
            .await?;
        self.bump_operator_authz_version_in(&transaction, id_user)
            .await?;
        transaction
            .commit()
            .await
            .context("failed to commit recovery-code regeneration")?;
        Ok(Some(recovery_codes))
    }

    /// Verifies a code presented at the login challenge: first as a live TOTP code,
    /// then as a single-use recovery code (which is burned on success).
    pub async fn verify_login_code(&self, id_user: i32, code: &str) -> anyhow::Result<bool> {
        if let Some(row) = self.confirmed_totp_row(id_user).await? {
            let secret_base32 =
                self.password_crypto
                    .decrypt_secret(id_user, TOTP_DOMAIN, &row.encrypted_secret)?;
            if let Some(step) = verify_totp_code(&secret_base32, code) {
                // A correct code whose step was already consumed is a replay: refuse
                // it. A six-digit numeric can never match a recovery code, so there
                // is nothing to gain by falling through.
                if (step as i64) <= row.last_used_step {
                    return Ok(false);
                }
                return self.consume_totp_step(row.id_totp, id_user, step).await;
            }
        }
        self.consume_recovery_code(id_user, code).await
    }

    async fn consume_totp_step(
        &self,
        id_totp: i32,
        id_user: i32,
        step: u64,
    ) -> anyhow::Result<bool> {
        let step = step as i64;
        let statement = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "UPDATE operator_mfa_totp \
             SET last_used_step = ? \
             WHERE id_totp = ? \
               AND id_user = ? \
               AND confirmed = 1 \
               AND last_used_step < ?",
            [
                Value::from(step),
                Value::from(id_totp),
                Value::from(id_user),
                Value::from(step),
            ],
        );
        let result = self
            .database
            .execute(statement)
            .await
            .context("failed to record the used TOTP step")?;
        Ok(result.rows_affected() == 1)
    }

    async fn replace_recovery_codes_in<C>(
        &self,
        executor: &C,
        id_user: i32,
    ) -> anyhow::Result<Vec<String>>
    where
        C: ConnectionTrait,
    {
        recovery::Entity::delete_many()
            .filter(recovery::Column::IdUser.eq(id_user))
            .exec(executor)
            .await
            .context("failed to clear previous recovery codes")?;
        let mut plaintext = Vec::with_capacity(RECOVERY_CODE_COUNT);
        for _ in 0..RECOVERY_CODE_COUNT {
            let code = generate_recovery_code();
            let encrypted_code =
                self.password_crypto
                    .encrypt_secret(id_user, RECOVERY_DOMAIN, &code)?;
            recovery::ActiveModel {
                id_code: NotSet,
                id_user: Set(id_user),
                encrypted_code: Set(encrypted_code),
                used: Set(0),
                created_at: Set(current_timestamp()),
                used_at: Set(None),
            }
            .insert(executor)
            .await
            .context("failed to store a recovery code")?;
            plaintext.push(code);
        }
        Ok(plaintext)
    }

    async fn consume_recovery_code(&self, id_user: i32, code: &str) -> anyhow::Result<bool> {
        let candidate = normalize_recovery(code);
        if candidate.is_empty() {
            return Ok(false);
        }
        let rows = recovery::Entity::find()
            .filter(recovery::Column::IdUser.eq(id_user))
            .filter(recovery::Column::Used.eq(0))
            .all(&self.database)
            .await
            .context("failed to load recovery codes")?;
        for row in rows {
            let stored = self.password_crypto.decrypt_secret(
                id_user,
                RECOVERY_DOMAIN,
                &row.encrypted_code,
            )?;
            if crate::security::constant_time_eq(
                normalize_recovery(&stored).as_bytes(),
                candidate.as_bytes(),
            ) {
                return self.consume_recovery_code_row(id_user, row.id_code).await;
            }
        }
        Ok(false)
    }

    async fn consume_recovery_code_row(&self, id_user: i32, id_code: i32) -> anyhow::Result<bool> {
        let statement = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "UPDATE operator_mfa_recovery_codes \
             SET used = 1, used_at = ? \
             WHERE id_code = ? AND id_user = ? AND used = 0",
            [
                Value::from(current_timestamp()),
                Value::from(id_code),
                Value::from(id_user),
            ],
        );
        let result = self
            .database
            .execute(statement)
            .await
            .context("failed to burn the used recovery code")?;
        Ok(result.rows_affected() == 1)
    }

    async fn set_operator_flag_in<C>(
        &self,
        executor: &C,
        id_user: i32,
        enabled: bool,
    ) -> anyhow::Result<()>
    where
        C: ConnectionTrait,
    {
        let statement = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "UPDATE operators \
             SET mfa_enabled = ?, updated_at = ?, authz_version = authz_version + 1 \
             WHERE id_user = ?",
            [
                Value::from(i32::from(enabled)),
                Value::from(current_timestamp()),
                Value::from(id_user),
            ],
        );
        executor
            .execute(statement)
            .await
            .context("failed to update the operator two-factor flag")?;
        Ok(())
    }

    async fn bump_operator_authz_version_in<C>(
        &self,
        executor: &C,
        id_user: i32,
    ) -> anyhow::Result<()>
    where
        C: ConnectionTrait,
    {
        let statement = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "UPDATE operators SET updated_at = ?, authz_version = authz_version + 1 WHERE id_user = ?",
            [Value::from(current_timestamp()), Value::from(id_user)],
        );
        executor
            .execute(statement)
            .await
            .context("failed to bump the operator authorization epoch")?;
        Ok(())
    }
}

/// Verifies a six-digit TOTP code against a base32 secret, tolerating one step of
/// clock skew on either side so a code entered near a period boundary still works.
/// Returns the matching time-step (`unix_time / period`) so the caller can record
/// it and refuse a later replay of the same code; `None` if it does not match.
///
/// Steps are tried current-first (`0`, then `-step`, then `+step`), so a code is
/// attributed to the current window whenever it is valid there. The `+step`
/// (future) window is only reached when the authenticator's clock runs ahead;
/// recording that future step is still correct for replay prevention of that
/// exact code. The only side effect is that, if a future-window code is consumed,
/// a *different* current-window code presented moments later is rejected until the
/// clock advances — a deliberate, sub-period trade-off that favours strict replay
/// prevention over accepting a second code inside the same skew window.
fn verify_totp_code(secret_base32: &str, code: &str) -> Option<u64> {
    let trimmed = code.trim();
    if trimmed.len() != 6 || !trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let code_num = trimmed.parse::<u32>().ok()?;
    let totp = otpauth::TOTP::from_base32(secret_base32.to_owned())?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let step = TOTP_PERIOD as i64;
    [0, -step, step].into_iter().find_map(|delta| {
        let timestamp = now + delta;
        if timestamp >= 0 && totp.verify(code_num, TOTP_PERIOD, timestamp as u64) {
            Some(timestamp as u64 / TOTP_PERIOD)
        } else {
            None
        }
    })
}

fn generate_recovery_code() -> String {
    let mut bytes = [0_u8; 10];
    dryoc::rng::copy_randombytes(&mut bytes);
    let mut code = String::with_capacity(11);
    for (index, byte) in bytes.iter().enumerate() {
        if index == 5 {
            code.push('-');
        }
        code.push(RECOVERY_ALPHABET[(*byte as usize) % RECOVERY_ALPHABET.len()] as char);
    }
    code
}

/// Normalises a recovery code for comparison: drops separators and case, so a
/// user may type `abcde-fghjk`, `ABCDEFGHJK` or with stray spaces and still match.
fn normalize_recovery(input: &str) -> String {
    input
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|character| character.to_ascii_uppercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use sea_orm::{ConnectionTrait, DbBackend, Statement};
    use tokio::sync::Barrier;

    use super::{
        ConfirmOutcome, OperatorMfaRepository, RECOVERY_CODE_COUNT, RECOVERY_DOMAIN, TOTP_PERIOD,
    };
    use crate::{
        models::{
            database,
            operator_repository::{NewOperator, OperatorRepository},
        },
        services::password_crypto::{PasswordCryptoService, PasswordVerification},
    };

    struct TestCrypto;

    impl PasswordCryptoService for TestCrypto {
        fn encrypt_password(&self, user_id: i32, password: &str) -> anyhow::Result<String> {
            Ok(format!("encrypted:{user_id}:{}", password.len()))
        }

        fn verify_password(
            &self,
            _user_id: i32,
            _encrypted_record: &str,
            _password: &str,
        ) -> anyhow::Result<PasswordVerification> {
            Ok(PasswordVerification {
                valid: true,
                replacement_record: None,
            })
        }

        fn encrypt_secret(
            &self,
            user_id: i32,
            domain: &str,
            plaintext: &str,
        ) -> anyhow::Result<String> {
            Ok(format!("sec:{user_id}:{domain}:{plaintext}"))
        }

        fn decrypt_secret(
            &self,
            user_id: i32,
            domain: &str,
            ciphertext: &str,
        ) -> anyhow::Result<String> {
            let prefix = format!("sec:{user_id}:{domain}:");
            Ok(ciphertext
                .strip_prefix(&prefix)
                .unwrap_or(ciphertext)
                .to_owned())
        }
    }

    struct FailingRecoveryCrypto {
        fail_recovery_encrypt: AtomicBool,
    }

    impl FailingRecoveryCrypto {
        fn new() -> Self {
            Self {
                fail_recovery_encrypt: AtomicBool::new(false),
            }
        }
    }

    impl PasswordCryptoService for FailingRecoveryCrypto {
        fn encrypt_password(&self, user_id: i32, password: &str) -> anyhow::Result<String> {
            Ok(format!("encrypted:{user_id}:{}", password.len()))
        }

        fn verify_password(
            &self,
            _user_id: i32,
            _encrypted_record: &str,
            _password: &str,
        ) -> anyhow::Result<PasswordVerification> {
            Ok(PasswordVerification {
                valid: true,
                replacement_record: None,
            })
        }

        fn encrypt_secret(
            &self,
            user_id: i32,
            domain: &str,
            plaintext: &str,
        ) -> anyhow::Result<String> {
            if domain == RECOVERY_DOMAIN && self.fail_recovery_encrypt.load(Ordering::SeqCst) {
                anyhow::bail!("forced recovery-code encryption failure");
            }
            Ok(format!("sec:{user_id}:{domain}:{plaintext}"))
        }

        fn decrypt_secret(
            &self,
            user_id: i32,
            domain: &str,
            ciphertext: &str,
        ) -> anyhow::Result<String> {
            let prefix = format!("sec:{user_id}:{domain}:");
            Ok(ciphertext
                .strip_prefix(&prefix)
                .unwrap_or(ciphertext)
                .to_owned())
        }
    }

    /// Connects a database inside a securely named temporary directory and seeds
    /// one admin operator. The returned `TempDir` guard must outlive the database;
    /// it removes the directory (and any SQLite WAL sidecars) on drop.
    async fn fixture() -> (sea_orm::DatabaseConnection, tempfile::TempDir, i32) {
        fixture_with_crypto(Arc::new(TestCrypto)).await
    }

    async fn fixture_with_crypto(
        crypto: Arc<dyn PasswordCryptoService>,
    ) -> (sea_orm::DatabaseConnection, tempfile::TempDir, i32) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = database::connect(&directory.path().join("kraken-ui-mfa.sqlite"))
            .await
            .unwrap_or_else(|error| panic!("test database must connect: {error}"));
        let operators = OperatorRepository::new(database.clone(), crypto);
        let created = operators
            .create(NewOperator {
                username: "admin",
                email: "admin@example.invalid",
                operator_type: "admin",
                password: "Long&Random#Pass9",
            })
            .await
            .unwrap_or_else(|error| panic!("operator must be created: {error}"));
        (database, directory, created.id_user)
    }

    fn current_code(secret_base32: &str) -> String {
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
        code_at(secret_base32, now)
    }

    fn code_at(secret_base32: &str, timestamp: u64) -> String {
        let totp = otpauth::TOTP::from_base32(secret_base32.to_owned())
            .unwrap_or_else(|| panic!("secret must decode"));
        format!("{:06}", totp.generate(TOTP_PERIOD, timestamp))
    }

    async fn operator_flag(database: &sea_orm::DatabaseConnection, id_user: i32) -> i32 {
        let row = database
            .query_one(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT mfa_enabled FROM operators WHERE id_user = ?",
                [id_user.into()],
            ))
            .await
            .unwrap_or_else(|error| panic!("flag query must run: {error}"))
            .unwrap_or_else(|| panic!("operator row must exist"));
        row.try_get::<i32>("", "mfa_enabled")
            .unwrap_or_else(|error| panic!("flag must read: {error}"))
    }

    async fn totp_confirmed(database: &sea_orm::DatabaseConnection, id_user: i32) -> i32 {
        let row = database
            .query_one(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT confirmed FROM operator_mfa_totp WHERE id_user = ?",
                [id_user.into()],
            ))
            .await
            .unwrap_or_else(|error| panic!("TOTP query must run: {error}"))
            .unwrap_or_else(|| panic!("TOTP row must exist"));
        row.try_get::<i32>("", "confirmed")
            .unwrap_or_else(|error| panic!("confirmed flag must read: {error}"))
    }

    #[tokio::test]
    async fn enrolls_confirms_and_mints_recovery_codes() {
        let (database, _directory, id_user) = fixture().await;
        let mfa = OperatorMfaRepository::new(database.clone(), Arc::new(TestCrypto));

        assert!(!mfa.status(id_user).await.unwrap().enabled);
        let enrollment = mfa
            .begin_enrollment(id_user, "admin")
            .await
            .unwrap_or_else(|error| panic!("enrollment must start: {error}"));
        assert!(enrollment.otpauth_uri.contains("otpauth://totp/"));
        // Still pending until confirmed.
        assert!(!mfa.status(id_user).await.unwrap().enabled);
        assert_eq!(operator_flag(&database, id_user).await, 0);

        // A wrong code does not confirm.
        assert!(matches!(
            mfa.confirm(id_user, "000000").await.unwrap(),
            ConfirmOutcome::InvalidCode
        ));

        let code = current_code(&enrollment.secret_base32);
        let outcome = mfa.confirm(id_user, &code).await.unwrap();
        let ConfirmOutcome::Confirmed { recovery_codes } = outcome else {
            panic!("a valid code must confirm enrollment");
        };
        assert_eq!(recovery_codes.len(), RECOVERY_CODE_COUNT);
        assert!(mfa.status(id_user).await.unwrap().enabled);
        assert_eq!(operator_flag(&database, id_user).await, 1);
    }

    #[tokio::test]
    async fn verifies_totp_and_burns_recovery_codes() {
        let (database, _directory, id_user) = fixture().await;
        let mfa = OperatorMfaRepository::new(database.clone(), Arc::new(TestCrypto));
        let enrollment = mfa.begin_enrollment(id_user, "admin").await.unwrap();
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
        // Confirm with the current code; confirmation also burns its time-step.
        let ConfirmOutcome::Confirmed { recovery_codes } = mfa
            .confirm(id_user, &code_at(&enrollment.secret_base32, now))
            .await
            .unwrap()
        else {
            panic!("enrollment must confirm");
        };

        // Replaying the confirming code at the login challenge is refused, because
        // its step was already consumed.
        assert!(
            !mfa.verify_login_code(id_user, &code_at(&enrollment.secret_base32, now))
                .await
                .unwrap()
        );

        // A code from the next time-step authenticates once...
        let fresh = code_at(&enrollment.secret_base32, now + TOTP_PERIOD);
        assert!(mfa.verify_login_code(id_user, &fresh).await.unwrap());
        // ...and then it, too, cannot be replayed.
        assert!(!mfa.verify_login_code(id_user, &fresh).await.unwrap());

        // A recovery code works once, and only once.
        let recovery = recovery_codes[0].clone();
        assert!(mfa.verify_login_code(id_user, &recovery).await.unwrap());
        assert!(!mfa.verify_login_code(id_user, &recovery).await.unwrap());
        // Case and separators do not matter for an unused code.
        let lowered = recovery_codes[1].to_lowercase();
        assert!(mfa.verify_login_code(id_user, &lowered).await.unwrap());

        let status = mfa.status(id_user).await.unwrap();
        assert_eq!(
            status.remaining_recovery_codes,
            (RECOVERY_CODE_COUNT - 2) as u64
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_totp_verification_consumes_a_step_once() {
        let (database, _directory, id_user) = fixture().await;
        let mfa = OperatorMfaRepository::new(database.clone(), Arc::new(TestCrypto));
        let enrollment = mfa.begin_enrollment(id_user, "admin").await.unwrap();
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
        let ConfirmOutcome::Confirmed { .. } = mfa
            .confirm(id_user, &code_at(&enrollment.secret_base32, now))
            .await
            .unwrap()
        else {
            panic!("enrollment must confirm");
        };
        let fresh = code_at(&enrollment.secret_base32, now + TOTP_PERIOD);
        let barrier = Arc::new(Barrier::new(2));

        let first = {
            let mfa = mfa.clone();
            let barrier = barrier.clone();
            let fresh = fresh.clone();
            async move {
                barrier.wait().await;
                mfa.verify_login_code(id_user, &fresh).await.unwrap()
            }
        };
        let second = {
            let mfa = mfa.clone();
            let barrier = barrier.clone();
            let fresh = fresh.clone();
            async move {
                barrier.wait().await;
                mfa.verify_login_code(id_user, &fresh).await.unwrap()
            }
        };

        let (first, second) = tokio::join!(first, second);
        assert_eq!(
            [first, second]
                .into_iter()
                .filter(|accepted| *accepted)
                .count(),
            1
        );
        assert!(!mfa.verify_login_code(id_user, &fresh).await.unwrap());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_recovery_code_verification_consumes_a_code_once() {
        let (database, _directory, id_user) = fixture().await;
        let mfa = OperatorMfaRepository::new(database.clone(), Arc::new(TestCrypto));
        let enrollment = mfa.begin_enrollment(id_user, "admin").await.unwrap();
        let ConfirmOutcome::Confirmed { recovery_codes } = mfa
            .confirm(id_user, &current_code(&enrollment.secret_base32))
            .await
            .unwrap()
        else {
            panic!("enrollment must confirm");
        };
        let recovery = recovery_codes[0].clone();
        let barrier = Arc::new(Barrier::new(2));

        let first = {
            let mfa = mfa.clone();
            let barrier = barrier.clone();
            let recovery = recovery.clone();
            async move {
                barrier.wait().await;
                mfa.verify_login_code(id_user, &recovery).await.unwrap()
            }
        };
        let second = {
            let mfa = mfa.clone();
            let barrier = barrier.clone();
            let recovery = recovery.clone();
            async move {
                barrier.wait().await;
                mfa.verify_login_code(id_user, &recovery).await.unwrap()
            }
        };

        let (first, second) = tokio::join!(first, second);
        assert_eq!(
            [first, second]
                .into_iter()
                .filter(|accepted| *accepted)
                .count(),
            1
        );
        assert!(!mfa.verify_login_code(id_user, &recovery).await.unwrap());
        assert_eq!(
            mfa.status(id_user).await.unwrap().remaining_recovery_codes,
            (RECOVERY_CODE_COUNT - 1) as u64
        );
    }

    #[tokio::test]
    async fn confirm_rolls_back_when_recovery_code_generation_fails() {
        let crypto = Arc::new(FailingRecoveryCrypto::new());
        let (database, _directory, id_user) = fixture_with_crypto(crypto.clone()).await;
        let mfa = OperatorMfaRepository::new(database.clone(), crypto.clone());
        let enrollment = mfa.begin_enrollment(id_user, "admin").await.unwrap();
        crypto.fail_recovery_encrypt.store(true, Ordering::SeqCst);

        let error = mfa
            .confirm(id_user, &current_code(&enrollment.secret_base32))
            .await
            .expect_err("forced recovery-code encryption failure must abort confirmation");
        assert!(error.to_string().contains("forced recovery-code"));
        assert_eq!(operator_flag(&database, id_user).await, 0);
        assert_eq!(totp_confirmed(&database, id_user).await, 0);
        assert!(!mfa.status(id_user).await.unwrap().enabled);
    }

    #[tokio::test]
    async fn disable_removes_secret_and_codes() {
        let (database, _directory, id_user) = fixture().await;
        let mfa = OperatorMfaRepository::new(database.clone(), Arc::new(TestCrypto));
        let enrollment = mfa.begin_enrollment(id_user, "admin").await.unwrap();
        mfa.confirm(id_user, &current_code(&enrollment.secret_base32))
            .await
            .unwrap();

        mfa.disable(id_user)
            .await
            .unwrap_or_else(|error| panic!("disable must succeed: {error}"));
        assert!(!mfa.status(id_user).await.unwrap().enabled);
        assert_eq!(operator_flag(&database, id_user).await, 0);
        // No recovery code authenticates once two-factor is off.
        assert!(!mfa.verify_login_code(id_user, "AAAAA-AAAAA").await.unwrap());
    }
}
