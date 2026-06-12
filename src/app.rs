use std::{env, fs, net::SocketAddr, path::Path, sync::Arc};

use anyhow::{Context, bail};
use axum::{Router, middleware};
use axum_csrf::{CsrfConfig, CsrfLayer, SameSite};
use axum_server::Handle;
use base64::{Engine, engine::general_purpose::STANDARD};
use time::Duration;
use tower_http::trace::TraceLayer;
use tower_sessions::{
    Expiry, SessionManagerLayer,
    cookie::{Key, SameSite as SessionSameSite},
};
use tracing::{info, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

use crate::{
    config::AppConfig,
    middleware::{rate_limit, security_headers},
    models::{
        database,
        operator_repository::{NewOperator, OperatorRepository},
        session_store::SeaOrmSessionStore,
    },
    routes, secrets,
    security::{
        headers,
        password::{MediumOrStrongPasswordPolicy, PasswordPolicy},
        rate_limit::{AccountFailureMonitor, IpRateLimiter, LoginThrottle},
        sanitize,
    },
    services::{
        password_crypto::{DryocPasswordCryptoService, PasswordCryptoService},
        source_update::SourceUpdateService,
        waf_metrics::WafMetricsService,
    },
    state::AppState,
};

pub struct AppFactory {
    config: AppConfig,
    password_crypto: Option<Arc<dyn PasswordCryptoService>>,
    waf_metrics: Option<WafMetricsService>,
    server_handle: Option<Handle<SocketAddr>>,
}

impl AppFactory {
    pub fn new(config: AppConfig) -> Self {
        Self {
            config,
            password_crypto: None,
            waf_metrics: None,
            server_handle: None,
        }
    }

    pub fn with_password_crypto(mut self, password_crypto: Arc<dyn PasswordCryptoService>) -> Self {
        self.password_crypto = Some(password_crypto);
        self
    }

    pub fn with_waf_metrics(mut self, waf_metrics: WafMetricsService) -> Self {
        self.waf_metrics = Some(waf_metrics);
        self
    }

    pub fn with_server_handle(mut self, server_handle: Handle<SocketAddr>) -> Self {
        self.server_handle = Some(server_handle);
        self
    }

    pub async fn build(self) -> anyhow::Result<Router> {
        let database = database::connect(&self.config.database_path).await?;
        let waf_database = match &self.config.waf_database_path {
            Some(path) if path.exists() => Some(database::connect_read_only(path).await?),
            Some(path) => {
                warn!(path = %path.display(), "WAF database does not exist; attack views will be empty");
                None
            }
            None => {
                warn!("db_local is not configured; attack views will be empty");
                None
            }
        };
        let password_policy: Arc<dyn PasswordPolicy> = Arc::new(MediumOrStrongPasswordPolicy);
        let password_crypto = match self.password_crypto {
            Some(service) => service,
            None => Arc::new(DryocPasswordCryptoService::from_environment()?),
        };
        bootstrap_administrator(&database, password_policy.as_ref(), password_crypto.clone())
            .await?;
        let waf_metrics = match self.waf_metrics {
            Some(service) => service,
            None => {
                let bearer_token = secrets::load_secret("BEARER_PASSWORD");
                if bearer_token.is_some() {
                    info!(
                        "WAF observability bearer authentication enabled for the metrics channel"
                    );
                } else {
                    warn!(
                        "BEARER_PASSWORD is not configured; WAF metrics requests will be sent \
                         without Authorization and only work when KrakenWAF's bearer gate is disabled"
                    );
                }
                if self.config.waf_certificate_path.is_none() {
                    warn!(
                        "waf-cert-ca is not set; trusting the UI's own cert-ca for the WAF metrics \
                         channel. Set waf-cert-ca explicitly if KrakenWAF presents a different CA."
                    );
                }
                WafMetricsService::new_with_bearer_token(
                    &self.config.waf_endpoint,
                    self.config.waf_certificate_path(),
                    bearer_token.as_deref(),
                )
                .await?
            }
        };
        let security_headers = headers::load("conf/headers_sec.txt").await?;
        let session_store = SeaOrmSessionStore::new(database.clone()).await?;
        let source_update = Arc::new(SourceUpdateService::new(self.server_handle)?);
        let state = AppState {
            config: Arc::new(self.config.clone()),
            database,
            waf_database,
            security_headers: Arc::new(security_headers),
            password_policy,
            password_crypto,
            waf_metrics,
            session_store: session_store.clone(),
            login_throttle: Arc::new(LoginThrottle::with_defaults()),
            request_rate_limiter: Arc::new(IpRateLimiter::with_defaults()),
            account_failure_monitor: Arc::new(AccountFailureMonitor::with_defaults()),
            first_time_lock: Arc::new(tokio::sync::Mutex::new(())),
            source_update,
        };

        let session_minutes = i64::try_from(self.config.session_timeout_minutes)
            .context("session timeout does not fit in i64")?;
        let session_layer = SessionManagerLayer::new(session_store)
            .with_name("__Host-kraken_session")
            .with_path("/")
            .with_http_only(true)
            .with_secure(true)
            .with_same_site(SessionSameSite::Strict)
            .with_expiry(Expiry::OnInactivity(Duration::minutes(session_minutes)))
            .with_signed(load_session_signing_key()?);
        let csrf_config = CsrfConfig::default()
            .with_cookie_name("kraken_csrf")
            .with_cookie_path("/")
            .with_cookie_same_site(SameSite::Strict)
            .with_http_only(true)
            .with_secure(true)
            .with_prefix_with_host(true);

        let rate_limit_state = state.clone();
        let application = routes::create(state.clone())
            .layer(TraceLayer::new_for_http())
            .layer(CsrfLayer::new(csrf_config))
            .layer(session_layer)
            .layer(middleware::from_fn_with_state(
                state,
                security_headers::apply,
            ))
            // Outermost layer: a global per-IP request cap, applied before any
            // other work is done.
            .layer(middleware::from_fn_with_state(
                rate_limit_state,
                rate_limit::apply,
            ));
        Ok(application)
    }
}

/// Loads the cookie signing key from `KRAKEN_UI_SESSION_KEY` or
/// `KRAKEN_UI_SESSION_KEY_FILE` (Base64, at least 64 bytes). A stable key lets
/// sessions survive a restart and be validated across replicas. If no source is
/// configured, an ephemeral key is generated with a warning — acceptable for
/// development only.
fn load_session_signing_key() -> anyhow::Result<Key> {
    let encoded = match env::var("KRAKEN_UI_SESSION_KEY") {
        Ok(value) => Some(value),
        Err(_) => match env::var("KRAKEN_UI_SESSION_KEY_FILE") {
            Ok(path) => Some(crate::security::read_protected_file(Path::new(&path))?),
            Err(_) => None,
        },
    };
    match encoded {
        Some(value) => {
            let bytes = STANDARD
                .decode(value.trim())
                .context("KRAKEN_UI_SESSION_KEY must be valid base64")?;
            if bytes.len() < 64 {
                bail!("session signing key must decode to at least 64 bytes");
            }
            Ok(Key::from(&bytes))
        }
        None => {
            // Fail closed in release builds: a missing signing key in production
            // silently breaks session continuity and cross-replica validation, the
            // opposite of this project's "refuse to boot when misconfigured" stance.
            // Debug builds (or an explicit opt-in) keep the convenient ephemeral key
            // for local development.
            if cfg!(debug_assertions) || env::var("KRAKEN_UI_ALLOW_EPHEMERAL_SESSION_KEY").is_ok() {
                warn!(
                    "no session signing key configured; generating an ephemeral one. Sessions will \
                     not survive a restart or work across replicas. Set KRAKEN_UI_SESSION_KEY or \
                     KRAKEN_UI_SESSION_KEY_FILE in production."
                );
                Ok(Key::generate())
            } else {
                bail!(
                    "no session signing key configured: set KRAKEN_UI_SESSION_KEY or \
                     KRAKEN_UI_SESSION_KEY_FILE (Base64, at least 64 bytes). To allow an ephemeral \
                     development key in a release build, set KRAKEN_UI_ALLOW_EPHEMERAL_SESSION_KEY=1."
                )
            }
        }
    }
}

pub fn initialize_logging(config: &AppConfig) -> anyhow::Result<Vec<WorkerGuard>> {
    use tracing_subscriber::{Layer, filter::filter_fn, fmt, prelude::*};

    fs::create_dir_all(&config.log_directory).with_context(|| {
        format!(
            "unable to create log directory {}",
            config.log_directory.display()
        )
    })?;

    // Application log: everything, governed by RUST_LOG. Rolled daily so the file
    // cannot grow without bound on a long-running service.
    let (app_writer, app_guard) = tracing_appender::non_blocking(tracing_appender::rolling::daily(
        &config.log_directory,
        "kraken-ui.jsonl",
    ));
    let app_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("kraken_ui=info,tower_http=info"));
    let app_layer = fmt::layer()
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .with_writer(app_writer)
        .with_filter(app_filter);

    // Dedicated, tamper-isolated audit log: only events on the `audit` target,
    // rolled daily like the application log.
    let (audit_writer, audit_guard) = tracing_appender::non_blocking(
        tracing_appender::rolling::daily(&config.log_directory, "audit.jsonl"),
    );
    let audit_layer = fmt::layer()
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .with_writer(audit_writer)
        .with_filter(filter_fn(|metadata| metadata.target() == "audit"));

    tracing_subscriber::registry()
        .with(app_layer)
        .with(audit_layer)
        .try_init()
        .map_err(|error| {
            anyhow::anyhow!("global tracing subscriber was already initialized: {error}")
        })?;
    Ok(vec![app_guard, audit_guard])
}

async fn bootstrap_administrator(
    database: &sea_orm::DatabaseConnection,
    password_policy: &dyn PasswordPolicy,
    password_crypto: Arc<dyn PasswordCryptoService>,
) -> anyhow::Result<()> {
    let repository = OperatorRepository::new(database.clone(), password_crypto);
    if repository.find_by_username("admin").await?.is_some() {
        return Ok(());
    }

    let Ok(raw_password) = env::var("KRAKEN_UI_ADMIN_PASSWORD") else {
        warn!("no administrator exists; set KRAKEN_UI_ADMIN_PASSWORD before the first startup");
        return Ok(());
    };
    let password = raw_password;
    if sanitize::secret_has_rejected_markup(&password) {
        bail!("KRAKEN_UI_ADMIN_PASSWORD contains rejected markup");
    }
    if password_policy.validate(&password, "admin").is_err() {
        bail!("KRAKEN_UI_ADMIN_PASSWORD does not satisfy the password policy");
    }
    let email =
        env::var("KRAKEN_UI_ADMIN_EMAIL").unwrap_or_else(|_| "admin@localhost.invalid".to_owned());
    repository
        .create(NewOperator {
            username: "admin",
            email: &email,
            operator_type: "admin",
            password: &password,
        })
        .await?;
    info!("bootstrap administrator created");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use anyhow::bail;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use super::AppFactory;
    use crate::{
        config::AppConfig,
        services::{
            password_crypto::{PasswordCryptoService, PasswordVerification},
            waf_metrics::WafMetricsService,
        },
    };

    struct TestPasswordCrypto;

    impl PasswordCryptoService for TestPasswordCrypto {
        fn encrypt_password(&self, _user_id: i32, _password: &str) -> anyhow::Result<String> {
            Ok("test-envelope".to_owned())
        }

        fn verify_password(
            &self,
            _user_id: i32,
            _encrypted_record: &str,
            _password: &str,
        ) -> anyhow::Result<PasswordVerification> {
            bail!("not used in this test")
        }

        fn encrypt_secret(
            &self,
            _user_id: i32,
            _domain: &str,
            plaintext: &str,
        ) -> anyhow::Result<String> {
            Ok(plaintext.to_owned())
        }

        fn decrypt_secret(
            &self,
            _user_id: i32,
            _domain: &str,
            ciphertext: &str,
        ) -> anyhow::Result<String> {
            Ok(ciphertext.to_owned())
        }
    }

    #[tokio::test]
    async fn applies_configured_security_headers_to_public_responses() {
        let database_path =
            std::env::temp_dir().join(format!("kraken-ui-test-{}.sqlite", std::process::id()));
        let config = AppConfig {
            certificate_path: "unused-cert.pem".into(),
            private_key_path: "unused-key.pem".into(),
            listen: "127.0.0.1:3443".to_owned(),
            database_path: database_path.clone(),
            waf_database_path: None,
            waf_endpoint: "https://127.0.0.1:4343".to_owned(),
            waf_certificate_path: None,
            log_directory: std::env::temp_dir(),
            session_timeout_minutes: 30,
        };
        let application = AppFactory::new(config)
            .with_password_crypto(Arc::new(TestPasswordCrypto))
            .with_waf_metrics(
                WafMetricsService::without_custom_ca("https://127.0.0.1:4343")
                    .unwrap_or_else(|error| panic!("test metrics client must build: {error}")),
            )
            .build()
            .await
            .unwrap_or_else(|error| panic!("test application must build: {error}"));
        let request = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap_or_else(|error| panic!("health request must be valid: {error}"));
        let response = application
            .oneshot(request)
            .await
            .unwrap_or_else(|error| panic!("health request must complete: {error}"));

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("x-frame-options")
                .and_then(|value| value.to_str().ok()),
            Some("DENY")
        );
        assert!(response.headers().contains_key("content-security-policy"));
        assert!(response.headers().contains_key("strict-transport-security"));

        let _ignored = tokio::fs::remove_file(database_path).await;
    }

    #[tokio::test]
    async fn mfa_challenge_redirects_without_a_pending_session() {
        let database_path = std::env::temp_dir().join(format!(
            "kraken-ui-mfa-challenge-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or_default()
        ));
        let config = AppConfig {
            certificate_path: "unused-cert.pem".into(),
            private_key_path: "unused-key.pem".into(),
            listen: "127.0.0.1:3443".to_owned(),
            database_path: database_path.clone(),
            waf_database_path: None,
            waf_endpoint: "https://127.0.0.1:4343".to_owned(),
            waf_certificate_path: None,
            log_directory: std::env::temp_dir(),
            session_timeout_minutes: 30,
        };
        let application = AppFactory::new(config)
            .with_password_crypto(Arc::new(TestPasswordCrypto))
            .with_waf_metrics(
                WafMetricsService::without_custom_ca("https://127.0.0.1:4343")
                    .unwrap_or_else(|error| panic!("test metrics client must build: {error}")),
            )
            .build()
            .await
            .unwrap_or_else(|error| panic!("test application must build: {error}"));
        let request = Request::builder()
            .uri("/kraken_ui/auth/mfa_challenge")
            .body(Body::empty())
            .unwrap_or_else(|error| panic!("challenge request must be valid: {error}"));
        let response = application
            .oneshot(request)
            .await
            .unwrap_or_else(|error| panic!("challenge request must complete: {error}"));

        // With no half-authenticated session there is nothing to challenge, so the
        // page must send the visitor back to the login form rather than render.
        assert!(response.status().is_redirection());
        assert_eq!(
            response
                .headers()
                .get("location")
                .and_then(|value| value.to_str().ok()),
            Some("/kraken_ui/login")
        );

        let _ignored = tokio::fs::remove_file(database_path).await;
    }
}
