use anyhow::Context;
use async_trait::async_trait;
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement, Value};
use time::OffsetDateTime;
use tower_sessions::session::{Id, Record};
use tower_sessions::session_store::{self, SessionStore};

/// Session-data key under which the authenticated operator id is stored. Defined
/// here, next to the store that mirrors it into an indexed column, and reused by
/// the authentication controller so the two can never drift apart.
pub const USER_ID_FIELD: &str = "authenticated_user_id";

/// A persistent session store backed by the application's own SQLite database
/// via SeaORM.
///
/// Replacing the previous in-memory store means sessions survive a restart and
/// can be revoked centrally, which the in-memory store could not offer. The whole
/// `Record` is serialised to JSON; an `expiry_utc` column lets expired rows be
/// filtered and pruned cheaply, and a `user_id` column mirrors the signed-in
/// operator so every session belonging to one account can be revoked at once.
#[derive(Clone, Debug)]
pub struct SeaOrmSessionStore {
    database: DatabaseConnection,
}

impl SeaOrmSessionStore {
    pub async fn new(database: DatabaseConnection) -> anyhow::Result<Self> {
        let store = Self { database };
        store.initialize_schema().await?;
        Ok(store)
    }

    async fn initialize_schema(&self) -> anyhow::Result<()> {
        self.database
            .execute(Statement::from_string(
                self.database.get_database_backend(),
                r#"
                CREATE TABLE IF NOT EXISTS kraken_sessions (
                    id TEXT PRIMARY KEY NOT NULL,
                    record TEXT NOT NULL,
                    expiry_utc INTEGER NOT NULL,
                    user_id INTEGER NOT NULL DEFAULT 0
                )
                "#,
            ))
            .await
            .context("unable to initialize the sessions table")?;
        // Bring forward tables created before the user_id column existed. SQLite
        // has no "ADD COLUMN IF NOT EXISTS", so a duplicate-column error on an
        // already-migrated table is expected and ignored.
        let _ = self
            .database
            .execute(Statement::from_string(
                self.database.get_database_backend(),
                "ALTER TABLE kraken_sessions ADD COLUMN user_id INTEGER NOT NULL DEFAULT 0",
            ))
            .await;
        // The revocation queries filter by user_id; index it so "log this
        // operator out everywhere" stays cheap as the table grows.
        self.database
            .execute(Statement::from_string(
                self.database.get_database_backend(),
                "CREATE INDEX IF NOT EXISTS idx_kraken_sessions_user_id \
                 ON kraken_sessions (user_id)",
            ))
            .await
            .context("unable to create the sessions user_id index")?;
        Ok(())
    }

    fn backend(&self) -> DbBackend {
        self.database.get_database_backend()
    }

    /// Removes every expired session row. Called opportunistically on each new
    /// session so the table cannot accumulate dead rows indefinitely.
    pub async fn delete_expired(&self) -> session_store::Result<u64> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let statement = Statement::from_sql_and_values(
            self.backend(),
            "DELETE FROM kraken_sessions WHERE expiry_utc <= ?",
            [Value::from(now)],
        );
        let result = self
            .database
            .execute(statement)
            .await
            .map_err(backend_error)?;
        Ok(result.rows_affected())
    }

    async fn id_exists(&self, id: &Id) -> session_store::Result<bool> {
        let statement = Statement::from_sql_and_values(
            self.backend(),
            "SELECT 1 FROM kraken_sessions WHERE id = ?",
            [Value::from(id.to_string())],
        );
        let row = self
            .database
            .query_one(statement)
            .await
            .map_err(backend_error)?;
        Ok(row.is_some())
    }

    async fn upsert(&self, record: &Record) -> session_store::Result<()> {
        let encoded = serde_json::to_string(record).map_err(encode_error)?;
        let statement = Statement::from_sql_and_values(
            self.backend(),
            "INSERT INTO kraken_sessions (id, record, expiry_utc, user_id) VALUES (?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET record = excluded.record, \
             expiry_utc = excluded.expiry_utc, user_id = excluded.user_id",
            [
                Value::from(record.id.to_string()),
                Value::from(encoded),
                Value::from(record.expiry_date.unix_timestamp()),
                Value::from(authenticated_user_id(record)),
            ],
        );
        self.database
            .execute(statement)
            .await
            .map_err(backend_error)?;
        Ok(())
    }

    /// Deletes every session belonging to an operator. Called when their
    /// privileges change or their account is removed, so a live session can never
    /// outlast the authority that granted it.
    pub async fn delete_by_user_id(&self, user_id: i32) -> anyhow::Result<u64> {
        let statement = Statement::from_sql_and_values(
            self.backend(),
            "DELETE FROM kraken_sessions WHERE user_id = ?",
            [Value::from(i64::from(user_id))],
        );
        let result = self
            .database
            .execute(statement)
            .await
            .context("failed to revoke operator sessions")?;
        Ok(result.rows_affected())
    }

    /// Like [`Self::delete_by_user_id`], but spares one session — the caller's
    /// own — so an operator changing their password keeps the tab they are using
    /// while every other session of theirs is revoked.
    pub async fn delete_by_user_id_except(&self, user_id: i32, keep: &Id) -> anyhow::Result<u64> {
        let statement = Statement::from_sql_and_values(
            self.backend(),
            "DELETE FROM kraken_sessions WHERE user_id = ? AND id <> ?",
            [
                Value::from(i64::from(user_id)),
                Value::from(keep.to_string()),
            ],
        );
        let result = self
            .database
            .execute(statement)
            .await
            .context("failed to revoke other operator sessions")?;
        Ok(result.rows_affected())
    }
}

/// Pulls the signed-in operator id out of the session payload so it can be
/// mirrored into an indexed column. Sessions with no authenticated operator
/// (e.g. a pre-login visitor) map to 0, which the revocation queries never match.
fn authenticated_user_id(record: &Record) -> i64 {
    record
        .data
        .get(USER_ID_FIELD)
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0)
}

#[async_trait]
impl SessionStore for SeaOrmSessionStore {
    async fn create(&self, record: &mut Record) -> session_store::Result<()> {
        // Opportunistically prune dead rows so the table stays bounded.
        let _ = self.delete_expired().await;
        // Resolve any id collision before inserting, rather than overwriting an
        // unrelated session.
        while self.id_exists(&record.id).await? {
            record.id = Id::default();
        }
        self.upsert(record).await
    }

    async fn save(&self, record: &Record) -> session_store::Result<()> {
        self.upsert(record).await
    }

    async fn load(&self, session_id: &Id) -> session_store::Result<Option<Record>> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let statement = Statement::from_sql_and_values(
            self.backend(),
            "SELECT record FROM kraken_sessions WHERE id = ? AND expiry_utc > ?",
            [Value::from(session_id.to_string()), Value::from(now)],
        );
        let Some(row) = self
            .database
            .query_one(statement)
            .await
            .map_err(backend_error)?
        else {
            return Ok(None);
        };
        let encoded: String = row.try_get("", "record").map_err(backend_error)?;
        let record = serde_json::from_str(&encoded).map_err(decode_error)?;
        Ok(Some(record))
    }

    async fn delete(&self, session_id: &Id) -> session_store::Result<()> {
        let statement = Statement::from_sql_and_values(
            self.backend(),
            "DELETE FROM kraken_sessions WHERE id = ?",
            [Value::from(session_id.to_string())],
        );
        self.database
            .execute(statement)
            .await
            .map_err(backend_error)?;
        Ok(())
    }
}

fn backend_error(error: impl std::fmt::Display) -> session_store::Error {
    session_store::Error::Backend(error.to_string())
}

fn encode_error(error: impl std::fmt::Display) -> session_store::Error {
    session_store::Error::Encode(error.to_string())
}

fn decode_error(error: impl std::fmt::Display) -> session_store::Error {
    session_store::Error::Decode(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::SeaOrmSessionStore;
    use crate::models::database;
    use time::{Duration, OffsetDateTime};
    use tower_sessions::session::{Id, Record};
    use tower_sessions::session_store::SessionStore;

    #[tokio::test]
    async fn round_trips_create_load_and_delete() {
        let database_path = std::env::temp_dir().join(format!(
            "kraken-ui-sessions-{}-{}.sqlite",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        let database = database::connect(&database_path)
            .await
            .unwrap_or_else(|error| panic!("test database must connect: {error}"));
        let store = SeaOrmSessionStore::new(database)
            .await
            .unwrap_or_else(|error| panic!("session store must initialise: {error}"));

        let mut record = Record {
            id: Id::default(),
            data: Default::default(),
            expiry_date: OffsetDateTime::now_utc() + Duration::hours(1),
        };
        store
            .create(&mut record)
            .await
            .unwrap_or_else(|error| panic!("record must be created: {error}"));

        let loaded = store
            .load(&record.id)
            .await
            .unwrap_or_else(|error| panic!("record must load: {error}"));
        assert_eq!(loaded.map(|loaded| loaded.id), Some(record.id));

        store
            .delete(&record.id)
            .await
            .unwrap_or_else(|error| panic!("record must delete: {error}"));
        let missing = store
            .load(&record.id)
            .await
            .unwrap_or_else(|error| panic!("load after delete must succeed: {error}"));
        assert!(missing.is_none());

        let _ignored = tokio::fs::remove_file(database_path).await;
    }

    #[tokio::test]
    async fn revokes_every_session_for_an_operator() {
        let store = store_for("revoke").await;
        let (mut first, mut second, mut other) = (record_for(7), record_for(7), record_for(9));
        for record in [&mut first, &mut second, &mut other] {
            store
                .create(record)
                .await
                .unwrap_or_else(|error| panic!("record must be created: {error}"));
        }

        let removed = store
            .delete_by_user_id(7)
            .await
            .unwrap_or_else(|error| panic!("sessions must be revoked: {error}"));

        assert_eq!(removed, 2);
        assert!(load(&store, &first.id).await.is_none());
        assert!(load(&store, &second.id).await.is_none());
        // A different operator's session is untouched.
        assert!(load(&store, &other.id).await.is_some());
    }

    #[tokio::test]
    async fn revokes_every_session_except_the_current_one() {
        let store = store_for("revoke-except").await;
        let (mut current, mut stale) = (record_for(7), record_for(7));
        for record in [&mut current, &mut stale] {
            store
                .create(record)
                .await
                .unwrap_or_else(|error| panic!("record must be created: {error}"));
        }

        let removed = store
            .delete_by_user_id_except(7, &current.id)
            .await
            .unwrap_or_else(|error| panic!("other sessions must be revoked: {error}"));

        assert_eq!(removed, 1);
        assert!(load(&store, &current.id).await.is_some());
        assert!(load(&store, &stale.id).await.is_none());
    }

    async fn store_for(label: &str) -> SeaOrmSessionStore {
        let database_path = std::env::temp_dir().join(format!(
            "kraken-ui-sessions-{label}-{}-{}.sqlite",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        let database = database::connect(&database_path)
            .await
            .unwrap_or_else(|error| panic!("test database must connect: {error}"));
        SeaOrmSessionStore::new(database)
            .await
            .unwrap_or_else(|error| panic!("session store must initialise: {error}"))
    }

    async fn load(store: &SeaOrmSessionStore, id: &Id) -> Option<Record> {
        store
            .load(id)
            .await
            .unwrap_or_else(|error| panic!("load must succeed: {error}"))
    }

    fn record_for(user_id: i64) -> Record {
        let mut data = std::collections::HashMap::new();
        data.insert(super::USER_ID_FIELD.to_owned(), serde_json::json!(user_id));
        Record {
            id: Id::default(),
            data,
            expiry_date: OffsetDateTime::now_utc() + Duration::hours(1),
        }
    }

    #[tokio::test]
    async fn does_not_load_expired_records() {
        let database_path = std::env::temp_dir().join(format!(
            "kraken-ui-sessions-expired-{}-{}.sqlite",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        let database = database::connect(&database_path)
            .await
            .unwrap_or_else(|error| panic!("test database must connect: {error}"));
        let store = SeaOrmSessionStore::new(database)
            .await
            .unwrap_or_else(|error| panic!("session store must initialise: {error}"));

        let mut record = Record {
            id: Id::default(),
            data: Default::default(),
            expiry_date: OffsetDateTime::now_utc() - Duration::hours(1),
        };
        store
            .create(&mut record)
            .await
            .unwrap_or_else(|error| panic!("record must be created: {error}"));

        let loaded = store
            .load(&record.id)
            .await
            .unwrap_or_else(|error| panic!("load must succeed: {error}"));
        assert!(loaded.is_none());

        let _ignored = tokio::fs::remove_file(database_path).await;
    }
}
