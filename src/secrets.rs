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

fn load_secret_from_sources(
    explicit_path: Option<&Path>,
    conventional_path: &Path,
    environment_value: Option<&str>,
) -> Option<String> {
    explicit_path
        .and_then(read_secret_file)
        .or_else(|| read_secret_file(conventional_path))
        .or_else(|| non_empty_secret(environment_value))
}

fn read_secret_file(path: &Path) -> Option<String> {
    let value = std::fs::read_to_string(path).ok()?;
    non_empty_secret(Some(&value))
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

    #[test]
    fn explicit_file_wins_and_is_trimmed() {
        let directory =
            std::env::temp_dir().join(format!("kraken-ui-secret-test-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("create test directory");
        let explicit = directory.join("explicit");
        let conventional = directory.join("conventional");
        std::fs::write(&explicit, " explicit-token \n").expect("write explicit secret");
        std::fs::write(&conventional, "conventional-token").expect("write conventional secret");

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
}
