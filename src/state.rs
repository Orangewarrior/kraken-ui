use std::sync::Arc;

use axum::http::HeaderMap;
use sea_orm::DatabaseConnection;
use tokio::sync::Mutex;

use crate::{
    config::AppConfig,
    middleware::rate_limit::IpConcurrencyLimiter,
    models::session_store::SeaOrmSessionStore,
    security::{
        password::PasswordPolicy,
        rate_limit::{AccountFailureMonitor, LoginThrottle},
    },
    services::password_crypto::PasswordCryptoService,
    services::rate_limit::PersistentRateLimiter,
    services::source_update::SourceUpdateService,
    services::waf_metrics::WafMetricsService,
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
    pub session_store: SeaOrmSessionStore,
    pub login_throttle: Arc<LoginThrottle>,
    pub persistent_rate_limiter: Option<PersistentRateLimiter>,
    pub ip_concurrency_limiter: Arc<IpConcurrencyLimiter>,
    pub request_timeout: std::time::Duration,
    /// Detection-only counter for distributed guessing against a single account.
    pub account_failure_monitor: Arc<AccountFailureMonitor>,
    pub first_time_lock: Arc<Mutex<()>>,
    pub source_update: Arc<SourceUpdateService>,
}
