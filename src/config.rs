use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use serde::{Deserialize, Deserializer};
use tokio::fs as tokio_fs;

const MINIMUM_SESSION_MINUTES: u64 = 5;
const MAXIMUM_SESSION_MINUTES: u64 = 1_440;
const DEFAULT_ADMIN_SESSION_TIME_LIMIT_SECONDS: u64 = 60 * 60;
const MAXIMUM_ADMIN_SESSION_TIME_LIMIT_SECONDS: u64 = 12 * 60 * 60;

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
    /// Absolute lifetime for authenticated console sessions. The YAML key keeps
    /// the requested spelling, while the correctly-spelled alias is accepted for
    /// future configurations.
    #[serde(
        rename = "admin-session-time-limmit",
        alias = "admin-session-time-limit",
        default = "default_admin_session_time_limit_seconds",
        deserialize_with = "deserialize_human_duration_seconds"
    )]
    pub admin_session_time_limit_seconds: u64,
    /// Exact TCP peer IPs trusted to provide forwarding headers. Empty by default:
    /// Kraken UI uses the direct socket peer and ignores `Forwarded` /
    /// `X-Forwarded-For`.
    #[serde(rename = "trusted-proxy-ips", default)]
    pub trusted_proxy_ips: Vec<IpAddr>,
}

impl AppConfig {
    pub async fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let bytes = tokio_fs::read(path)
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
            .is_some_and(|path| paths_may_reference_same_file(&self.database_path, path))
        {
            bail!("db-ui and db-waf-alerts must reference different files");
        }
        validate_private_key_permissions(&self.private_key_path)?;
        validate_persistent_directory(&self.database_path, "db-ui")?;
        validate_persistent_directory(&self.log_directory, "log-dir")?;
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
        if self.admin_session_time_limit_seconds == 0
            || self.admin_session_time_limit_seconds > MAXIMUM_ADMIN_SESSION_TIME_LIMIT_SECONDS
        {
            bail!("admin-session-time-limmit must be greater than 0s and no more than 12h");
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
        if self.trusted_proxy_ips.iter().any(IpAddr::is_unspecified) {
            bail!("trusted-proxy-ips cannot contain unspecified addresses");
        }
        Ok(())
    }
}

fn default_admin_session_time_limit_seconds() -> u64 {
    DEFAULT_ADMIN_SESSION_TIME_LIMIT_SECONDS
}

fn deserialize_human_duration_seconds<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    parse_human_duration_seconds(&value).map_err(serde::de::Error::custom)
}

fn parse_human_duration_seconds(raw: &str) -> Result<u64, String> {
    let mut seconds = 0_u64;
    let mut digits = String::new();
    let mut saw_unit = false;
    for character in raw.trim().chars() {
        if character.is_ascii_digit() {
            digits.push(character);
            continue;
        }
        if character.is_ascii_whitespace() {
            continue;
        }
        if digits.is_empty() {
            return Err("duration must place a number before each unit".to_owned());
        }
        let amount = digits
            .parse::<u64>()
            .map_err(|_| "duration component is too large".to_owned())?;
        let multiplier = match character {
            's' | 'S' => 1,
            'm' | 'M' => 60,
            'h' | 'H' => 60 * 60,
            _ => {
                return Err("duration units must be s, m or h, for example 30m or 1h".to_owned());
            }
        };
        seconds = seconds
            .checked_add(
                amount
                    .checked_mul(multiplier)
                    .ok_or_else(|| "duration is too large".to_owned())?,
            )
            .ok_or_else(|| "duration is too large".to_owned())?;
        digits.clear();
        saw_unit = true;
    }
    if !digits.is_empty() || !saw_unit {
        return Err("duration must include a unit, for example 30m or 1h".to_owned());
    }
    Ok(seconds)
}

fn paths_may_reference_same_file(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    if let (Ok(left_meta), Ok(right_meta)) = (fs::metadata(left), fs::metadata(right))
        && same_file_metadata(&left_meta, &right_meta)
    {
        return true;
    }
    normalized_with_existing_parent(left)
        .zip(normalized_with_existing_parent(right))
        .is_some_and(|(left, right)| left == right)
}

#[cfg(unix)]
fn same_file_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    let _ = (left, right);
    false
}

fn normalized_with_existing_parent(path: &Path) -> Option<PathBuf> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())?;
    let file_name = path.file_name()?;
    let parent = parent.canonicalize().ok()?;
    Some(parent.join(file_name))
}

fn validate_private_key_permissions(path: &Path) -> anyhow::Result<()> {
    let Ok(metadata) = fs::metadata(path) else {
        return Ok(());
    };
    if crate::security::file_has_loose_permissions(&metadata) {
        bail!(
            "TLS private key {} must not be accessible by group or others",
            path.display()
        );
    }
    Ok(())
}

fn validate_persistent_directory(path: &Path, field: &str) -> anyhow::Result<()> {
    let directory = if path.extension().is_some() {
        path.parent().unwrap_or_else(|| Path::new("."))
    } else {
        path
    };
    let Ok(metadata) = fs::metadata(directory) else {
        return Ok(());
    };
    if directory_has_loose_write_permissions(&metadata) {
        bail!(
            "{field} directory {} must not be writable by group or others",
            directory.display()
        );
    }
    Ok(())
}

fn directory_has_loose_write_permissions(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o022 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

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

    fn config_with_paths(key: &Path, db_ui: &Path, db_waf: &Path, log_dir: &Path) -> String {
        format!(
            r#"
cert-ca: {cert}
key: {key}
listen: "127.0.0.1:3443"
db-ui: {db_ui}
db-waf-alerts: {db_waf}
waf-endpoint: "https://127.0.0.1:4343"
log-dir: {log_dir}
session-timeout-minutes: 30
"#,
            cert = key.with_file_name("ca.pem").display(),
            key = key.display(),
            db_ui = db_ui.display(),
            db_waf = db_waf.display(),
            log_dir = log_dir.display(),
        )
    }

    #[test]
    fn accepts_a_well_formed_configuration() {
        let config = parse(VALID).expect("valid configuration");
        assert_eq!(config.database_path.to_str(), Some("db/kraken-ui.sqlite"));
        assert_eq!(
            config.waf_database_path.as_deref().and_then(|p| p.to_str()),
            Some("db/vulns_alert.db")
        );
        assert!(config.trusted_proxy_ips.is_empty());
        assert_eq!(config.admin_session_time_limit_seconds, 60 * 60);
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

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_ui_and_waf_databases() {
        let temp = tempfile::tempdir().expect("tempdir");
        let db = temp.path().join("ui.sqlite");
        let alias = temp.path().join("alerts.sqlite");
        std::fs::write(&db, b"sqlite").expect("db");
        std::os::unix::fs::symlink(&db, &alias).expect("symlink");
        let yaml = config_with_paths(&temp.path().join("key.pem"), &db, &alias, temp.path());

        let error = parse(&yaml).expect_err("symlinked database paths must be rejected");
        assert!(error.to_string().contains("different files"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_loose_tls_private_key_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let key = temp.path().join("key.pem");
        std::fs::write(&key, b"private key").expect("key");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644))
            .expect("permissions");
        let yaml = config_with_paths(
            &key,
            &temp.path().join("ui.sqlite"),
            &temp.path().join("alerts.sqlite"),
            temp.path(),
        );

        let error = parse(&yaml).expect_err("loose private key must be rejected");
        assert!(error.to_string().contains("TLS private key"));
    }

    #[test]
    fn accepts_explicit_trusted_proxy_ips() {
        let yaml = format!("{VALID}trusted-proxy-ips: [\"127.0.0.1\", \"::1\"]\n");
        let config = parse(&yaml).expect("trusted proxies");
        assert_eq!(config.trusted_proxy_ips.len(), 2);
    }

    #[test]
    fn accepts_human_admin_session_time_limits() {
        let config =
            parse(&format!("{VALID}admin-session-time-limmit: 1h30m\n")).expect("duration");
        assert_eq!(config.admin_session_time_limit_seconds, 90 * 60);

        let config =
            parse(&format!("{VALID}admin-session-time-limit: 45m\n")).expect("alias duration");
        assert_eq!(config.admin_session_time_limit_seconds, 45 * 60);
    }

    #[test]
    fn rejects_admin_session_time_limits_above_the_ceiling() {
        let error = parse(&format!("{VALID}admin-session-time-limmit: 13h\n"))
            .expect_err("absolute session limit must have a ceiling");
        assert!(error.to_string().contains("admin-session-time-limmit"));
    }

    #[test]
    fn rejects_unspecified_trusted_proxy_ips() {
        let yaml = format!("{VALID}trusted-proxy-ips: [\"0.0.0.0\"]\n");
        let error = parse(&yaml).expect_err("unspecified proxy must be rejected");
        assert!(error.to_string().contains("trusted-proxy-ips"));
    }
}
