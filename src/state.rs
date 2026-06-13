use std::{sync::Arc, time::Duration};

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

/// All the throttling and concurrency controls, grouped so they travel together
/// and the call sites read `state.rate_limiting.<control>`. Splits cleanly into
/// the two layers that consume it: the login/account guards (`auth`) and the
/// per-request guards (`middleware::rate_limit`).
#[derive(Clone)]
pub struct RateLimiting {
    /// Per-IP and per-account login failure throttle with temporary lockout.
    pub login_throttle: Arc<LoginThrottle>,
    /// Detection-only counter for distributed guessing against a single account.
    pub account_failure_monitor: Arc<AccountFailureMonitor>,
    /// Persistent GCRA request limiter (SQLite or Redis); `None` when disabled.
    pub persistent: Option<PersistentRateLimiter>,
    /// Active, non-queuing per-IP concurrency ceiling.
    pub ip_concurrency: Arc<IpConcurrencyLimiter>,
    /// Maximum time a single request may run before it is timed out.
    pub request_timeout: Duration,
}

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
    pub rate_limiting: RateLimiting,
    pub first_time_lock: Arc<Mutex<()>>,
    pub source_update: Arc<SourceUpdateService>,
}
