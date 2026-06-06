use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, bail};
use serde::Deserialize;
use tokio::fs;

const MINIMUM_SESSION_MINUTES: u64 = 5;
const MAXIMUM_SESSION_MINUTES: u64 = 1_440;

#[derive(Clone, Debug, Deserialize)]
pub struct AppConfig {
    #[serde(rename = "cert-ca")]
    pub certificate_path: PathBuf,
    #[serde(rename = "key")]
    pub private_key_path: PathBuf,
    pub listen: String,
    #[serde(rename = "db-local")]
    pub database_path: PathBuf,
    #[serde(rename = "db_local", default)]
    pub waf_database_path: Option<PathBuf>,
    #[serde(rename = "waf-endpoint")]
    pub waf_endpoint: String,
    #[serde(rename = "waf-cert-ca", default)]
    pub waf_certificate_path: Option<PathBuf>,
    #[serde(rename = "log-dir")]
    pub log_directory: PathBuf,
    #[serde(rename = "session-timeout-minutes")]
    pub session_timeout_minutes: u64,
}

impl AppConfig {
    pub async fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let bytes = fs::read(path)
            .await
            .with_context(|| format!("unable to read configuration file {}", path.display()))?;
        let config: Self = serde_yaml::from_slice(&bytes)
            .with_context(|| format!("invalid YAML in {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn session_timeout(&self) -> Duration {
        Duration::from_secs(self.session_timeout_minutes * 60)
    }

    pub fn waf_certificate_path(&self) -> &Path {
        self.waf_certificate_path
            .as_deref()
            .unwrap_or(&self.certificate_path)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.listen.trim().is_empty() {
            bail!("listen cannot be empty");
        }
        if self.certificate_path.as_os_str().is_empty() {
            bail!("cert-ca cannot be empty");
        }
        if self.private_key_path.as_os_str().is_empty() {
            bail!("key cannot be empty");
        }
        if self
            .waf_database_path
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            bail!("db_local cannot be empty when configured");
        }
        if self
            .waf_certificate_path
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            bail!("waf-cert-ca cannot be empty when configured");
        }
        if !(MINIMUM_SESSION_MINUTES..=MAXIMUM_SESSION_MINUTES)
            .contains(&self.session_timeout_minutes)
        {
            bail!(
                "session-timeout-minutes must be between {MINIMUM_SESSION_MINUTES} and {MAXIMUM_SESSION_MINUTES}"
            );
        }
        if !self.waf_endpoint.starts_with("https://") {
            bail!("waf-endpoint must use https://");
        }
        Ok(())
    }
}
