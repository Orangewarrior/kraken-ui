use std::sync::Arc;

use anyhow::Context;
use sea_orm::{
    ActiveModelTrait, ActiveValue::NotSet, ColumnTrait, Condition, ConnectionTrait,
    DatabaseConnection, DbBackend, EntityTrait, IntoActiveModel, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, Set, Statement, TransactionTrait, Value,
};
use zeroize::Zeroizing;

use crate::{
    models::{current_timestamp, like_contains, operator},
    services::password_crypto::{PasswordCryptoService, spawn_encrypt},
};

/// Upper bound on the pagination offset, to stop a hostile `start` value forcing
/// SQLite into an enormous and expensive row scan.
const MAX_OFFSET: u64 = 100_000;

#[derive(Clone)]
pub struct OperatorRepository {
    database: DatabaseConnection,
    password_crypto: Arc<dyn PasswordCryptoService>,
}

pub struct NewOperator<'a> {
    pub username: &'a str,
    pub email: &'a str,
    pub operator_type: &'a str,
    pub password: &'a str,
}

pub struct UpdateOperator<'a> {
    pub username: &'a str,
    pub email: &'a str,
    pub operator_type: &'a str,
    pub password: Option<&'a str>,
}

pub struct OperatorPage {
    pub records_total: u64,
    pub records_filtered: u64,
    pub operators: Vec<operator::Model>,
}

impl OperatorRepository {
    pub fn new(
        database: DatabaseConnection,
        password_crypto: Arc<dyn PasswordCryptoService>,
    ) -> Self {
        Self {
            database,
            password_crypto,
        }
    }

    pub async fn find_by_username(
        &self,
        username: &str,
    ) -> anyhow::Result<Option<operator::Model>> {
        operator::Entity::find()
            .filter(operator::Column::Username.eq(username.to_owned()))
            .one(&self.database)
            .await
            .context("failed to query operator by username")
    }

    pub async fn find_by_id(&self, id_user: i32) -> anyhow::Result<Option<operator::Model>> {
        operator::Entity::find_by_id(id_user)
            .one(&self.database)
            .await
            .context("failed to query operator by id")
    }

    pub async fn find_by_email(&self, email: &str) -> anyhow::Result<Option<operator::Model>> {
        operator::Entity::find()
            .filter(operator::Column::Email.eq(email.to_owned()))
            .one(&self.database)
            .await
            .context("failed to query operator by email")
    }

    pub async fn count(&self) -> anyhow::Result<u64> {
        operator::Entity::find()
            .count(&self.database)
            .await
            .context("failed to count operators")
    }

    pub async fn create(&self, input: NewOperator<'_>) -> anyhow::Result<operator::Model> {
        let transaction = self
            .database
            .begin()
            .await
            .context("failed to start operator creation transaction")?;
        let timestamp = current_timestamp();
        let pending_operator = operator::ActiveModel {
            id_user: NotSet,
            username: Set(input.username.to_owned()),
            email: Set(input.email.to_owned()),
            operator_type: Set(input.operator_type.to_owned()),
            encrypted_password_hash: Set("transaction-pending".to_owned()),
            mfa_enabled: NotSet,
            authz_version: NotSet,
            authenticated_at: NotSet,
            reauthenticated_at: NotSet,
            created_at: Set(timestamp.clone()),
            updated_at: Set(timestamp),
        }
        .insert(&transaction)
        .await
        .context("failed to insert operator")?;

        let encrypted_password_hash = spawn_encrypt(
            self.password_crypto.clone(),
            pending_operator.id_user,
            Zeroizing::new(input.password.to_owned()),
        )
        .await?;
        let mut active_operator = pending_operator.into_active_model();
        active_operator.encrypted_password_hash = Set(encrypted_password_hash);
        let operator = active_operator
            .update(&transaction)
            .await
            .context("failed to store encrypted operator password")?;
        transaction
            .commit()
            .await
            .context("failed to commit operator creation")?;
        Ok(operator)
    }

    pub async fn update(
        &self,
        existing: operator::Model,
        input: UpdateOperator<'_>,
    ) -> anyhow::Result<operator::Model> {
        let user_id = existing.id_user;
        let encrypted_password_hash = if let Some(password) = input.password {
            Some(
                spawn_encrypt(
                    self.password_crypto.clone(),
                    user_id,
                    Zeroizing::new(password.to_owned()),
                )
                .await?,
            )
        } else {
            None
        };
        let transaction = self
            .database
            .begin()
            .await
            .context("failed to start operator update transaction")?;
        if let Some(encrypted_password_hash) = encrypted_password_hash {
            let statement = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE operators \
                 SET username = ?, email = ?, type = ?, encrypted_password_hash = ?, \
                     updated_at = ?, authz_version = authz_version + 1 \
                 WHERE id_user = ?",
                [
                    Value::from(input.username.to_owned()),
                    Value::from(input.email.to_owned()),
                    Value::from(input.operator_type.to_owned()),
                    Value::from(encrypted_password_hash),
                    Value::from(current_timestamp()),
                    Value::from(user_id),
                ],
            );
            transaction
                .execute(statement)
                .await
                .context("failed to update operator")?;
        } else {
            let statement = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE operators \
                 SET username = ?, email = ?, type = ?, \
                     updated_at = ?, authz_version = authz_version + 1 \
                 WHERE id_user = ?",
                [
                    Value::from(input.username.to_owned()),
                    Value::from(input.email.to_owned()),
                    Value::from(input.operator_type.to_owned()),
                    Value::from(current_timestamp()),
                    Value::from(user_id),
                ],
            );
            transaction
                .execute(statement)
                .await
                .context("failed to update operator")?;
        }
        let operator = operator::Entity::find_by_id(user_id)
            .one(&transaction)
            .await
            .context("failed to load updated operator")?
            .context("updated operator disappeared before commit")?;
        transaction
            .commit()
            .await
            .context("failed to commit operator update")?;
        Ok(operator)
    }

    pub async fn record_authenticated(&self, id_user: i32) -> anyhow::Result<()> {
        self.record_authentication_timestamp(id_user, "authenticated_at")
            .await
    }

    pub async fn record_reauthenticated(&self, id_user: i32) -> anyhow::Result<()> {
        self.record_authentication_timestamp(id_user, "reauthenticated_at")
            .await
    }

    async fn record_authentication_timestamp(
        &self,
        id_user: i32,
        column: &'static str,
    ) -> anyhow::Result<()> {
        let statement = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            format!("UPDATE operators SET {column} = ? WHERE id_user = ?"),
            [Value::from(current_timestamp()), Value::from(id_user)],
        );
        self.database
            .execute(statement)
            .await
            .context("failed to record operator authentication timestamp")?;
        Ok(())
    }

    pub async fn update_encrypted_password(
        &self,
        id_user: i32,
        encrypted_password_hash: String,
    ) -> anyhow::Result<()> {
        let Some(operator) = self.find_by_id(id_user).await? else {
            return Ok(());
        };
        let mut active_operator = operator.into_active_model();
        active_operator.encrypted_password_hash = Set(encrypted_password_hash);
        active_operator.updated_at = Set(current_timestamp());
        active_operator
            .update(&self.database)
            .await
            .context("failed to update rehashed password")?;
        Ok(())
    }

    pub async fn update_password(
        &self,
        existing: operator::Model,
        password: &str,
    ) -> anyhow::Result<operator::Model> {
        let user_id = existing.id_user;
        let encrypted_password_hash = spawn_encrypt(
            self.password_crypto.clone(),
            user_id,
            Zeroizing::new(password.to_owned()),
        )
        .await?;
        let transaction = self
            .database
            .begin()
            .await
            .context("failed to start password update transaction")?;
        let statement = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "UPDATE operators \
             SET encrypted_password_hash = ?, updated_at = ?, authz_version = authz_version + 1 \
             WHERE id_user = ?",
            [
                Value::from(encrypted_password_hash),
                Value::from(current_timestamp()),
                Value::from(user_id),
            ],
        );
        transaction
            .execute(statement)
            .await
            .context("failed to update operator password")?;
        let operator = operator::Entity::find_by_id(user_id)
            .one(&transaction)
            .await
            .context("failed to load updated operator")?
            .context("updated operator disappeared before commit")?;
        transaction
            .commit()
            .await
            .context("failed to commit password update")?;
        Ok(operator)
    }

    pub async fn delete_by_id(&self, id_user: i32) -> anyhow::Result<u64> {
        let result = operator::Entity::delete_by_id(id_user)
            .exec(&self.database)
            .await
            .context("failed to delete operator")?;
        Ok(result.rows_affected)
    }

    pub async fn page(
        &self,
        start: u64,
        length: u64,
        search: &str,
    ) -> anyhow::Result<OperatorPage> {
        let records_total = operator::Entity::find()
            .count(&self.database)
            .await
            .context("failed to count operators")?;
        let mut query = operator::Entity::find();
        if !search.is_empty() {
            let pattern = like_contains(search);
            let mut condition = Condition::any()
                .add(operator::Column::Username.like(pattern.clone()))
                .add(operator::Column::Email.like(pattern));
            if let Ok(id_user) = search.parse::<i32>() {
                condition = condition.add(operator::Column::IdUser.eq(id_user));
            }
            query = query.filter(condition);
        }
        let start = start.min(MAX_OFFSET);
        let records_filtered = query
            .clone()
            .count(&self.database)
            .await
            .context("failed to count filtered operators")?;
        let operators = query
            .order_by_asc(operator::Column::IdUser)
            .offset(start)
            .limit(length)
            .all(&self.database)
            .await
            .context("failed to list operators")?;
        Ok(OperatorPage {
            records_total,
            records_filtered,
            operators,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        models::{
            database,
            operator_repository::{NewOperator, OperatorRepository, UpdateOperator},
        },
        services::password_crypto::{PasswordCryptoService, PasswordVerification},
    };

    struct TestPasswordCrypto;

    impl PasswordCryptoService for TestPasswordCrypto {
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

    #[tokio::test]
    async fn creates_updates_lists_and_deletes_operator() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = database::connect(&directory.path().join("kraken-ui-operators.sqlite"))
            .await
            .unwrap_or_else(|error| panic!("test database must connect: {error}"));
        let repository = OperatorRepository::new(database, Arc::new(TestPasswordCrypto));

        let created = repository
            .create(NewOperator {
                username: "admin",
                email: "admin@example.invalid",
                operator_type: "admin",
                password: "Long&Random#Pass9",
            })
            .await
            .unwrap_or_else(|error| panic!("operator must be created: {error}"));
        assert_eq!(created.id_user, 1);
        assert_eq!(created.encrypted_password_hash, "encrypted:1:17");
        assert_eq!(created.authz_version, 0);
        let created_authz_version = created.authz_version;

        repository
            .record_authenticated(created.id_user)
            .await
            .unwrap_or_else(|error| panic!("authenticated_at must be recorded: {error}"));
        repository
            .record_reauthenticated(created.id_user)
            .await
            .unwrap_or_else(|error| panic!("reauthenticated_at must be recorded: {error}"));
        let audited = repository
            .find_by_id(created.id_user)
            .await
            .unwrap_or_else(|error| panic!("operator must load: {error}"))
            .expect("operator exists");
        assert!(audited.authenticated_at.is_some());
        assert!(audited.reauthenticated_at.is_some());
        assert_eq!(audited.authz_version, created_authz_version);

        let updated = repository
            .update(
                created,
                UpdateOperator {
                    username: "admin2",
                    email: "admin2@example.invalid",
                    operator_type: "admin",
                    password: None,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("operator must be updated: {error}"));
        assert_eq!(updated.username, "admin2");
        assert_eq!(updated.authz_version, created_authz_version + 1);
        let updated_authz_version = updated.authz_version;

        let updated = repository
            .update_password(updated, "Another&Random#Pass9")
            .await
            .unwrap_or_else(|error| panic!("operator password must be updated: {error}"));
        assert_eq!(updated.authz_version, updated_authz_version + 1);

        let page = repository
            .page(0, 10, "admin2")
            .await
            .unwrap_or_else(|error| panic!("operators must be listed: {error}"));
        assert_eq!(page.records_filtered, 1);

        let rows = repository
            .delete_by_id(updated.id_user)
            .await
            .unwrap_or_else(|error| panic!("operator must be deleted: {error}"));
        assert_eq!(rows, 1);
    }
}
