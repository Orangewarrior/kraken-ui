use std::{path::Path, time::Duration};

use anyhow::Context;
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DbBackend, SqlxSqliteConnector, Statement,
    sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use tokio::fs;

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn connect(database_path: &Path) -> anyhow::Result<DatabaseConnection> {
    if let Some(parent) = database_path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("unable to create database directory {}", parent.display()))?;
    }

    // WAL lets readers and the single writer proceed concurrently; busy_timeout
    // absorbs brief write contention instead of failing with SQLITE_BUSY. These
    // are applied to every pooled connection by sqlx.
    let options = SqliteConnectOptions::new()
        .filename(database_path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(BUSY_TIMEOUT)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .min_connections(1)
        .connect_with(options)
        .await
        .context("unable to connect to SQLite through SeaORM")?;
    let database = SqlxSqliteConnector::from_sqlx_sqlite_pool(pool);

    initialize_schema(&database).await?;
    Ok(database)
}

pub async fn connect_read_only(database_path: &Path) -> anyhow::Result<DatabaseConnection> {
    let options = SqliteConnectOptions::new()
        .filename(database_path)
        .read_only(true)
        .busy_timeout(BUSY_TIMEOUT);
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .min_connections(1)
        .connect_with(options)
        .await
        .with_context(|| format!("unable to open WAF SQLite {}", database_path.display()))?;
    Ok(SqlxSqliteConnector::from_sqlx_sqlite_pool(pool))
}

async fn initialize_schema(database: &DatabaseConnection) -> anyhow::Result<()> {
    database
        .execute(Statement::from_string(
            DbBackend::Sqlite,
            r#"
            CREATE TABLE IF NOT EXISTS operators (
                id_user INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(32) NOT NULL UNIQUE,
                email VARCHAR(128) NOT NULL UNIQUE,
                type VARCHAR(32) NOT NULL
                    CHECK (type IN ('admin', 'operator', 'auditor')),
                encrypted_password_hash VARCHAR(1024) NOT NULL,
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL
            )
            "#,
        ))
        .await
        .context("unable to initialize operators table")?;
    Ok(())
}
