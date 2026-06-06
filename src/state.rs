use std::sync::Arc;

use axum::http::HeaderMap;
use sea_orm::DatabaseConnection;
use tokio::sync::Mutex;

use crate::{
    config::AppConfig, security::password::PasswordPolicy,
    services::password_crypto::PasswordCryptoService, services::waf_metrics::WafMetricsService,
};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub database: DatabaseConnection,
    pub waf_database: Option<DatabaseConnection>,
    pub security_headers: Arc<HeaderMap>,
    pub password_policy: Arc<dyn PasswordPolicy>,
    pub password_crypto: Arc<dyn PasswordCryptoService>,
    pub waf_metrics: WafMetricsService,
    pub first_time_lock: Arc<Mutex<()>>,
}
