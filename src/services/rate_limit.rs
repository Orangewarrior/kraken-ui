use std::{
    num::NonZeroU32,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, bail};
use async_trait::async_trait;
use axum_governor::{GovernorConfigBuilder, GovernorLayer, Quota, extractor::PeerIp};
use redis::{
    Client, ConnectionAddr, IntoConnectionInfo, RedisConnectionInfo, Script,
    aio::{ConnectionManager, ConnectionManagerConfig},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::Deserialize;
use tokio::fs;
use tracing::{info, warn};

use crate::secrets;

const REDIS_GCRA_SCRIPT: &str = r#"
local clock = redis.call('TIME')
local now = (clock[1] * 1000000) + clock[2]
local interval = tonumber(ARGV[1])
local tolerance = tonumber(ARGV[2])
local tat = tonumber(redis.call('GET', KEYS[1])) or now
local allow_at = tat - tolerance
if now < allow_at then
    return {0, math.ceil((allow_at - now) / 1000)}
end
local new_tat = math.max(tat, now) + interval
local ttl = math.max(1000, math.ceil((new_tat - now + tolerance) / 1000))
redis.call('SET', KEYS[1], new_tat, 'PX', ttl)
return {1, 0}
"#;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_second: u32,
    pub burst_size: u32,
    pub max_coroutines_per_ip: usize,
    pub tls_handshake_timeout_secs: u64,
    pub connection_timeout_secs: u64,
    pub max_tracked_ips: usize,
    pub backend: BackendKind,
    pub fail_open: bool,
    pub sqlite: SqliteConfig,
    pub redis: RedisConfig,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    Sqlite,
    Redis,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SqliteConfig {
    pub path: PathBuf,
    pub busy_timeout_ms: u64,
    pub cleanup_interval_requests: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisConfig {
    pub host: String,
    pub port: u16,
    pub database: i64,
    pub tls: bool,
    pub key_prefix: String,
    pub connect_timeout_secs: u64,
    pub response_timeout_secs: u64,
    pub retries: usize,
}

impl RateLimitConfig {
    pub async fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let bytes = fs::read(path)
            .await
            .with_context(|| format!("unable to read rate-limit config {}", path.display()))?;
        let config: Self = serde_yaml::from_slice(&bytes)
            .with_context(|| format!("invalid YAML in {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn tls_handshake_timeout(&self) -> Duration {
        Duration::from_secs(self.tls_handshake_timeout_secs)
    }

    pub fn connection_timeout(&self) -> Duration {
        Duration::from_secs(self.connection_timeout_secs)
    }

    pub fn governor_layer(&self) -> anyhow::Result<GovernorLayer<std::net::IpAddr>> {
        let rate = NonZeroU32::new(self.requests_per_second)
            .context("requests_per_second must be greater than zero")?;
        let burst =
            NonZeroU32::new(self.burst_size).context("burst_size must be greater than zero")?;
        let config = GovernorConfigBuilder::default()
            .with_extractor(PeerIp::ipv6_prefix(128))
            .expect_connect_info()
            .quota_default(Quota::requests_per_second(rate).burst(burst))
            .max_keys(self.max_tracked_ips)
            .redact_keys(true)
            .finish()
            .context("invalid axum-governor configuration")?;
        Ok(GovernorLayer::new(config))
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.requests_per_second == 0
            || self.burst_size == 0
            || self.max_coroutines_per_ip == 0
            || self.tls_handshake_timeout_secs == 0
            || self.connection_timeout_secs == 0
            || self.max_tracked_ips == 0
        {
            bail!("rate-limit numeric limits must be greater than zero");
        }
        if self.sqlite.path.as_os_str().is_empty()
            || self.sqlite.busy_timeout_ms == 0
            || self.sqlite.cleanup_interval_requests == 0
        {
            bail!("SQLite rate-limit settings must be non-empty and greater than zero");
        }
        if self.redis.host.trim().is_empty()
            || self.redis.key_prefix.is_empty()
            || self.redis.connect_timeout_secs == 0
            || self.redis.response_timeout_secs == 0
        {
            bail!("Redis rate-limit settings must be non-empty and greater than zero");
        }
        if !self
            .redis
            .key_prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_'))
        {
            bail!("redis.key_prefix may contain only ASCII letters, digits, ':', '-' and '_'");
        }
        if self.backend == BackendKind::Redis && !self.redis.tls {
            bail!("Redis rate-limit backend requires TLS; redis.tls must be true");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimitDecision {
    pub allowed: bool,
    pub retry_after: Duration,
}

impl RateLimitDecision {
    fn allowed() -> Self {
        Self {
            allowed: true,
            retry_after: Duration::ZERO,
        }
    }

    fn rejected(retry_after: Duration) -> Self {
        Self {
            allowed: false,
            retry_after,
        }
    }
}

#[async_trait]
trait RateLimitBackend: Send + Sync {
    async fn check(&self, key: &str) -> anyhow::Result<RateLimitDecision>;
}

#[derive(Clone)]
pub struct PersistentRateLimiter {
    backend: Arc<dyn RateLimitBackend>,
    fail_open: bool,
}

impl PersistentRateLimiter {
    pub async fn from_config(config: &RateLimitConfig) -> anyhow::Result<Self> {
        let rate = GcraRate::new(config.requests_per_second, config.burst_size)?;
        let backend: Arc<dyn RateLimitBackend> = match config.backend {
            BackendKind::Sqlite => Arc::new(SqliteBackend::open(&config.sqlite, rate)?),
            BackendKind::Redis => Arc::new(RedisBackend::connect(&config.redis, rate).await?),
        };
        info!(
            backend = ?config.backend,
            fail_open = config.fail_open,
            "persistent GCRA rate limiter initialized"
        );
        Ok(Self {
            backend,
            fail_open: config.fail_open,
        })
    }

    pub async fn check(&self, key: &str) -> RateLimitDecision {
        match self.backend.check(key).await {
            Ok(decision) => decision,
            Err(error) if self.fail_open => {
                warn!(%error, "persistent rate-limit backend failed; allowing request");
                RateLimitDecision::allowed()
            }
            Err(error) => {
                warn!(%error, "persistent rate-limit backend failed; rejecting request");
                RateLimitDecision::rejected(Duration::from_secs(1))
            }
        }
    }
}

#[derive(Clone, Copy)]
struct GcraRate {
    interval_us: i64,
    tolerance_us: i64,
}

impl GcraRate {
    fn new(requests_per_second: u32, burst_size: u32) -> anyhow::Result<Self> {
        if requests_per_second == 0 || burst_size == 0 {
            bail!("GCRA rate and burst must be greater than zero");
        }
        let interval_us = i64::from(1_000_000 / requests_per_second);
        if interval_us == 0 {
            bail!("requests_per_second cannot exceed 1,000,000");
        }
        let tolerance_us = interval_us
            .checked_mul(i64::from(burst_size - 1))
            .context("GCRA burst is too large")?;
        Ok(Self {
            interval_us,
            tolerance_us,
        })
    }
}

struct SqliteBackend {
    connection: Arc<Mutex<Connection>>,
    rate: GcraRate,
    cleanup_interval_requests: u64,
    requests: AtomicU64,
}

impl SqliteBackend {
    fn open(config: &SqliteConfig, rate: GcraRate) -> anyhow::Result<Self> {
        if let Some(parent) = config.path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "unable to create rate-limit database directory {}",
                    parent.display()
                )
            })?;
        }
        let connection = Connection::open(&config.path).with_context(|| {
            format!(
                "unable to open rate-limit database {}",
                config.path.display()
            )
        })?;
        connection.busy_timeout(Duration::from_millis(config.busy_timeout_ms))?;
        connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA trusted_schema = OFF;
             CREATE TABLE IF NOT EXISTS rate_limit_gcra (
                 key TEXT PRIMARY KEY NOT NULL,
                 tat_us INTEGER NOT NULL,
                 expires_at_us INTEGER NOT NULL
             ) WITHOUT ROWID;",
        )?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            rate,
            cleanup_interval_requests: config.cleanup_interval_requests,
            requests: AtomicU64::new(0),
        })
    }
}

#[async_trait]
impl RateLimitBackend for SqliteBackend {
    async fn check(&self, key: &str) -> anyhow::Result<RateLimitDecision> {
        let connection = Arc::clone(&self.connection);
        let key = key.to_owned();
        let rate = self.rate;
        let cleanup = self
            .requests
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
            .is_multiple_of(self.cleanup_interval_requests);
        tokio::task::spawn_blocking(move || {
            let mut connection = connection
                .lock()
                .map_err(|_| anyhow::anyhow!("SQLite rate-limit mutex poisoned"))?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let now = unix_time_us()?;
            if cleanup {
                transaction.execute(
                    "DELETE FROM rate_limit_gcra WHERE expires_at_us <= ?1",
                    params![now],
                )?;
            }
            let tat = transaction
                .query_row(
                    "SELECT tat_us FROM rate_limit_gcra WHERE key = ?1",
                    params![key],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .unwrap_or(now);
            let allow_at = tat.saturating_sub(rate.tolerance_us);
            if now < allow_at {
                transaction.commit()?;
                return Ok(RateLimitDecision::rejected(Duration::from_micros(
                    u64::try_from(allow_at - now).unwrap_or(u64::MAX),
                )));
            }
            let new_tat = tat.max(now).saturating_add(rate.interval_us);
            let expires_at = new_tat.saturating_add(rate.tolerance_us);
            transaction.execute(
                "INSERT INTO rate_limit_gcra (key, tat_us, expires_at_us)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET
                    tat_us = excluded.tat_us,
                    expires_at_us = excluded.expires_at_us",
                params![key, new_tat, expires_at],
            )?;
            transaction.commit()?;
            Ok(RateLimitDecision::allowed())
        })
        .await
        .context("SQLite rate-limit task failed")?
    }
}

struct RedisBackend {
    connection: ConnectionManager,
    key_prefix: String,
    rate: GcraRate,
}

impl RedisBackend {
    async fn connect(config: &RedisConfig, rate: GcraRate) -> anyhow::Result<Self> {
        let username = secrets::load_secret("REDIS_USERNAME")
            .context("Redis backend requires REDIS_USERNAME or REDIS_USERNAME_FILE")?;
        let password = secrets::load_secret("REDIS_PASSWORD")
            .context("Redis backend requires REDIS_PASSWORD or REDIS_PASSWORD_FILE")?;
        let address = ConnectionAddr::TcpTls {
            host: config.host.clone(),
            port: config.port,
            insecure: false,
            tls_params: None,
        };
        let redis_settings = RedisConnectionInfo::default()
            .set_username(username)
            .set_password(password)
            .set_db(config.database)
            .set_skip_set_lib_name();
        let connection_info = (config.host.as_str(), config.port)
            .into_connection_info()?
            .set_addr(address)
            .set_redis_settings(redis_settings);
        let client = Client::open(connection_info)?;
        let manager_config = ConnectionManagerConfig::new()
            .set_connection_timeout(Some(Duration::from_secs(config.connect_timeout_secs)))
            .set_response_timeout(Some(Duration::from_secs(config.response_timeout_secs)))
            .set_number_of_retries(config.retries)
            .set_concurrency_limit(64);
        let connection = ConnectionManager::new_with_config(client, manager_config)
            .await
            .context("unable to connect to hardened Redis rate-limit backend")?;
        Ok(Self {
            connection,
            key_prefix: config.key_prefix.clone(),
            rate,
        })
    }
}

#[async_trait]
impl RateLimitBackend for RedisBackend {
    async fn check(&self, key: &str) -> anyhow::Result<RateLimitDecision> {
        let mut connection = self.connection.clone();
        let result: (i64, i64) = Script::new(REDIS_GCRA_SCRIPT)
            .key(format!("{}{}", self.key_prefix, key))
            .arg(self.rate.interval_us)
            .arg(self.rate.tolerance_us)
            .invoke_async(&mut connection)
            .await?;
        if result.0 == 1 {
            Ok(RateLimitDecision::allowed())
        } else {
            Ok(RateLimitDecision::rejected(Duration::from_millis(
                u64::try_from(result.1.max(1)).unwrap_or(u64::MAX),
            )))
        }
    }
}

fn unix_time_us() -> anyhow::Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?;
    i64::try_from(duration.as_micros()).context("system clock does not fit in i64 microseconds")
}

#[cfg(test)]
mod tests {
    use super::{BackendKind, GcraRate, RateLimitConfig};

    #[test]
    fn rejects_insecure_redis_transport() {
        let yaml = r#"
enabled: true
requests_per_second: 5
burst_size: 10
max_coroutines_per_ip: 4
tls_handshake_timeout_secs: 10
connection_timeout_secs: 30
max_tracked_ips: 100
backend: redis
fail_open: false
sqlite:
  path: db/test.sqlite
  busy_timeout_ms: 100
  cleanup_interval_requests: 10
redis:
  host: redis.example.invalid
  port: 6379
  database: 0
  tls: false
  key_prefix: "kraken-ui:ratelimit:"
  connect_timeout_secs: 3
  response_timeout_secs: 2
  retries: 2
"#;
        let config: RateLimitConfig = serde_yaml::from_str(yaml).expect("deserialize");
        assert_eq!(config.backend, BackendKind::Redis);
        assert!(config.validate().is_err());
    }

    #[test]
    fn gcra_rate_uses_requested_burst_tolerance() {
        let rate = GcraRate::new(5, 300).expect("valid GCRA");
        assert_eq!(rate.interval_us, 200_000);
        assert_eq!(rate.tolerance_us, 59_800_000);
    }
}
