pub mod csrf;
pub mod headers;
pub mod password;
pub mod rate_limit;
pub mod sanitize;

use std::{fs, path::Path};

use anyhow::{Context, bail};

/// Reads a secret-bearing file, refusing it on Unix if it is readable by group
/// or others. Used for both the password-encryption key and the session signing
/// key, so the permission policy lives in one place.
pub fn read_protected_file(path: &Path) -> anyhow::Result<String> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("unable to read key metadata from {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "key file {} must not be accessible by group or others",
                path.display()
            );
        }
    }
    let _ = &metadata;
    fs::read_to_string(path).with_context(|| format!("unable to read key file {}", path.display()))
}
