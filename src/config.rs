use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
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
    /// The UI's own read-write SQLite database (operators, sessions, two-factor
    /// state). The canonical key is `db-ui`; `db-local` is accepted as a
    /// deprecated alias for configurations written before the rename.
    #[serde(rename = "db-ui", alias = "db-local")]
    pub database_path: PathBuf,
    /// The KrakenWAF alerts database, opened strictly read-only. The canonical key
    /// is `db-waf-alerts`; `db_local` is accepted as a deprecated alias. Keeping
    /// this distinct from `db-ui` (rather than the previous `db_local`, a single
    /// underscore away from `db-local`) removes a dangerous typo class where the
    /// credential store and the read-only alerts file could be swapped silently.
    #[serde(rename = "db-waf-alerts", alias = "db_local", default)]
    pub waf_database_path: Option<PathBuf>,
    #[serde(rename = "waf-endpoint")]
    pub waf_endpoint: String,
    #[serde(rename = "waf-cert-ca", default)]
    pub waf_certificate_path: Option<PathBuf>,
    /// KrakenWAF's rule-management (CMC control plane) listener, which runs on a
    /// separate port from metrics (KrakenWAF default `4342`). Optional: when
    /// unset, the rule-management UI is shown as not configured.
    #[serde(rename = "waf-rule-endpoint", default)]
    pub waf_rule_endpoint: Option<String>,
    /// CA that signs the rule-management listener's certificate. Falls back to
    /// `waf-cert-ca`, then `cert-ca`, when not set.
    #[serde(rename = "waf-rule-cert-ca", default)]
    pub waf_rule_certificate_path: Option<PathBuf>,
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

    pub fn waf_certificate_path(&self) -> &Path {
        self.waf_certificate_path
            .as_deref()
            .unwrap_or(&self.certificate_path)
    }

    /// CA for the rule-management channel: the dedicated `waf-rule-cert-ca` if
    /// set, otherwise the same CA used for the metrics channel.
    pub fn waf_rule_certificate_path(&self) -> &Path {
        self.waf_rule_certificate_path
            .as_deref()
            .unwrap_or_else(|| self.waf_certificate_path())
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.listen.trim().is_empty() {
            bail!("listen cannot be empty");
        }
        // Validate the listen address shape here, at load time, so a malformed
        // value fails with the rest of the configuration rather than later in
        // `main`, consistent with this project's "refuse to boot when
        // misconfigured" stance.
        if self.listen.parse::<SocketAddr>().is_err() {
            bail!(
                "listen must be a valid socket address such as 127.0.0.1:3443, got {:?}",
                self.listen
            );
        }
        if self.certificate_path.as_os_str().is_empty() {
            bail!("cert-ca cannot be empty");
        }
        if self.private_key_path.as_os_str().is_empty() {
            bail!("key cannot be empty");
        }
        if self.database_path.as_os_str().is_empty() {
            bail!("db-ui cannot be empty");
        }
        if self
            .waf_database_path
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            bail!("db-waf-alerts cannot be empty when configured");
        }
        // The UI's credential store and the read-only WAF alerts database must
        // never be the same file: pointing both at one path would let the alerts
        // reader and the operator/session writer collide on a single database.
        if self
            .waf_database_path
            .as_ref()
            .is_some_and(|path| path == &self.database_path)
        {
            bail!("db-ui and db-waf-alerts must reference different files");
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
        if self
            .waf_rule_endpoint
            .as_ref()
            .is_some_and(|endpoint| !endpoint.starts_with("https://"))
        {
            bail!("waf-rule-endpoint must use https:// when configured");
        }
        if self
            .waf_rule_certificate_path
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            bail!("waf-rule-cert-ca cannot be empty when configured");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::AppConfig;

    const VALID: &str = r#"
cert-ca: certs/ca.pem
key: certs/key.pem
listen: "127.0.0.1:3443"
db-ui: db/kraken-ui.sqlite
db-waf-alerts: db/vulns_alert.db
waf-endpoint: "https://127.0.0.1:4343"
log-dir: log
session-timeout-minutes: 30
"#;

    fn parse(yaml: &str) -> anyhow::Result<AppConfig> {
        let config: AppConfig = serde_yaml::from_str(yaml)?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn accepts_a_well_formed_configuration() {
        let config = parse(VALID).expect("valid configuration");
        assert_eq!(config.database_path.to_str(), Some("db/kraken-ui.sqlite"));
        assert_eq!(
            config.waf_database_path.as_deref().and_then(|p| p.to_str()),
            Some("db/vulns_alert.db")
        );
    }

    #[test]
    fn accepts_the_deprecated_database_aliases() {
        let yaml = VALID
            .replace("db-ui:", "db-local:")
            .replace("db-waf-alerts:", "db_local:");
        let config = parse(&yaml).expect("deprecated aliases must still load");
        assert_eq!(config.database_path.to_str(), Some("db/kraken-ui.sqlite"));
        assert_eq!(
            config.waf_database_path.as_deref().and_then(|p| p.to_str()),
            Some("db/vulns_alert.db")
        );
    }

    #[test]
    fn rejects_an_invalid_listen_address() {
        let yaml = VALID.replace("\"127.0.0.1:3443\"", "\"not-a-socket\"");
        assert!(parse(&yaml).is_err());
    }

    #[test]
    fn accepts_an_optional_rule_management_endpoint() {
        let yaml = format!("{VALID}waf-rule-endpoint: \"https://127.0.0.1:4342\"\n");
        let config = parse(&yaml).expect("rule endpoint must load");
        assert_eq!(
            config.waf_rule_endpoint.as_deref(),
            Some("https://127.0.0.1:4342")
        );
    }

    #[test]
    fn rejects_a_plaintext_rule_management_endpoint() {
        let yaml = format!("{VALID}waf-rule-endpoint: \"http://127.0.0.1:4342\"\n");
        assert!(parse(&yaml).is_err());
    }

    #[test]
    fn rejects_identical_ui_and_waf_databases() {
        let yaml = VALID.replace("db/vulns_alert.db", "db/kraken-ui.sqlite");
        let error = parse(&yaml).expect_err("identical database paths must be rejected");
        assert!(error.to_string().contains("different files"));
    }
}
