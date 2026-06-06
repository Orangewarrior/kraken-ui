use std::path::Path;

use anyhow::Context;
use sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseConnection, Statement};
use tokio::fs;

pub async fn connect(database_path: &Path) -> anyhow::Result<DatabaseConnection> {
    if let Some(parent) = database_path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("unable to create database directory {}", parent.display()))?;
    }

    let database_url = format!("sqlite://{}?mode=rwc", database_path.display());
    let mut options = ConnectOptions::new(database_url);
    options
        .sqlx_logging(false)
        .max_connections(10)
        .min_connections(1);
    let database = Database::connect(options)
        .await
        .context("unable to connect to SQLite through SeaORM")?;

    initialize_schema(&database).await?;
    Ok(database)
}

pub async fn connect_read_only(database_path: &Path) -> anyhow::Result<DatabaseConnection> {
    let database_url = format!("sqlite://{}?mode=ro", database_path.display());
    let mut options = ConnectOptions::new(database_url);
    options
        .sqlx_logging(false)
        .max_connections(5)
        .min_connections(1);
    Database::connect(options)
        .await
        .with_context(|| format!("unable to open WAF SQLite {}", database_path.display()))
}

async fn initialize_schema(database: &DatabaseConnection) -> anyhow::Result<()> {
    database
        .execute(Statement::from_string(
            database.get_database_backend(),
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
