//! Secret loading compatible with KrakenWAF.
//!
//! Secrets are resolved file-first so Kraken UI can reuse credentials mounted
//! for KrakenWAF without copying them into process environment variables.

use std::path::{Path, PathBuf};

/// Conventional directory shared with KrakenWAF file-based secrets.
pub const SECRETS_DIR: &str = "/run/secrets/krakenwaf";

/// Resolve `NAME` in the same order used by KrakenWAF:
///
/// 1. `<NAME>_FILE`
/// 2. `/run/secrets/krakenwaf/<NAME>`
/// 3. `NAME`
#[must_use]
pub fn load_secret(name: &str) -> Option<String> {
    let explicit_path = std::env::var(format!("{name}_FILE"))
        .ok()
        .map(|value| PathBuf::from(value.trim()))
        .filter(|path| !path.as_os_str().is_empty());

    load_secret_from_sources(
        explicit_path.as_deref(),
        &Path::new(SECRETS_DIR).join(name),
        std::env::var(name).ok().as_deref(),
    )
}

/// How loose permissions on a secret file are treated for a given source.
#[derive(Clone, Copy)]
enum Enforcement {
    /// Refuse the file (fail closed). Used for an explicitly configured `*_FILE`:
    /// the admin pointed at it and can fix its mode.
    Strict,
    /// Use the file but warn. Used for the conventional `/run/secrets/...` mount,
    /// where the platform (Docker/systemd) owns the permissions and 0444-style
    /// modes are common and intended.
    WarnOnly,
}

enum SecretFile {
    /// A usable, non-empty secret was read.
    Loaded(String),
    /// The file exists but its permissions are too open under `Strict`.
    Rejected,
    /// The file is absent or empty; the caller should fall through to the next
    /// source.
    Absent,
}

fn load_secret_from_sources(
    explicit_path: Option<&Path>,
    conventional_path: &Path,
    environment_value: Option<&str>,
) -> Option<String> {
    if let Some(path) = explicit_path {
        match classify_secret_file(path, Enforcement::Strict) {
            SecretFile::Loaded(secret) => return Some(secret),
            // An explicit file that exists but is world/group-readable fails
            // closed: do not silently fall back to a weaker source.
            SecretFile::Rejected => return None,
            // Absent or empty: fall through, so a `*_FILE` that is set but missing
            // still allows the conventional mount or the environment value.
            SecretFile::Absent => {}
        }
    }
    match classify_secret_file(conventional_path, Enforcement::WarnOnly) {
        SecretFile::Loaded(secret) => Some(secret),
        _ => non_empty_secret(environment_value),
    }
}

fn classify_secret_file(path: &Path, enforcement: Enforcement) -> SecretFile {
    let Ok(metadata) = std::fs::metadata(path) else {
        return SecretFile::Absent;
    };
    if crate::security::file_has_loose_permissions(&metadata) {
        match enforcement {
            Enforcement::Strict => {
                tracing::error!(
                    path = %path.display(),
                    "refusing secret file readable by group or others"
                );
                return SecretFile::Rejected;
            }
            Enforcement::WarnOnly => {
                tracing::warn!(
                    path = %path.display(),
                    "secret file is readable by group or others"
                );
            }
        }
    }
    match std::fs::read_to_string(path) {
        Ok(content) => match non_empty_secret(Some(&content)) {
            Some(secret) => SecretFile::Loaded(secret),
            None => SecretFile::Absent,
        },
        Err(_) => SecretFile::Absent,
    }
}

fn non_empty_secret(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::load_secret_from_sources;

    /// Tightens a file to `0600` on Unix so the strict-permission check accepts it.
    /// A no-op elsewhere, where the check does not apply.
    fn restrict_permissions(path: &std::path::Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .expect("restrict secret permissions");
        }
        let _ = path;
    }

    #[test]
    fn explicit_file_wins_and_is_trimmed() {
        let directory = std::env::temp_dir().join(format!(
            "kraken-ui-secret-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&directory).expect("create test directory");
        let explicit = directory.join("explicit");
        let conventional = directory.join("conventional");
        std::fs::write(&explicit, " explicit-token \n").expect("write explicit secret");
        std::fs::write(&conventional, "conventional-token").expect("write conventional secret");
        restrict_permissions(&explicit);

        let value =
            load_secret_from_sources(Some(&explicit), &conventional, Some("environment-token"));

        std::fs::remove_dir_all(directory).expect("remove test directory");
        assert_eq!(value.as_deref(), Some("explicit-token"));
    }

    #[test]
    fn empty_files_fall_back_to_environment() {
        let missing =
            std::env::temp_dir().join(format!("kraken-ui-missing-secret-{}", std::process::id()));

        let value = load_secret_from_sources(Some(&missing), &missing, Some(" environment-token "));

        assert_eq!(value.as_deref(), Some("environment-token"));
    }

    /// An explicitly configured `*_FILE` with group/other-readable permissions is
    /// refused outright on Unix, rather than silently falling back to the
    /// environment value.
    #[cfg(unix)]
    #[test]
    fn loose_explicit_file_is_refused_without_fallback() {
        use std::os::unix::fs::PermissionsExt;

        let directory = std::env::temp_dir().join(format!(
            "kraken-ui-loose-secret-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&directory).expect("create test directory");
        let explicit = directory.join("explicit");
        std::fs::write(&explicit, "explicit-token").expect("write explicit secret");
        std::fs::set_permissions(&explicit, std::fs::Permissions::from_mode(0o644))
            .expect("loosen permissions");

        let value = load_secret_from_sources(Some(&explicit), &explicit, Some("environment-token"));

        std::fs::remove_dir_all(directory).expect("remove test directory");
        assert_eq!(value, None);
    }
}
