pub mod csrf;
pub mod headers;
pub mod password;
pub mod rate_limit;
pub mod redact;
pub mod sanitize;

use std::{fs, path::Path};

use anyhow::{Context, bail};

/// Whether a secret-bearing file is readable by group or others. On Unix this
/// inspects the permission bits; on other platforms there is no comparable mode,
/// so it always reports `false`. Centralised here so every secret source — key
/// files and the file-based secret loader — applies one definition of "too open".
pub fn file_has_loose_permissions(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o077 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

/// Reads a secret-bearing file, refusing it on Unix if it is readable by group
/// or others. Used for both the password-encryption key and the session signing
/// key, so the permission policy lives in one place.
pub fn read_protected_file(path: &Path) -> anyhow::Result<String> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("unable to read key metadata from {}", path.display()))?;
    if file_has_loose_permissions(&metadata) {
        bail!(
            "key file {} must not be accessible by group or others",
            path.display()
        );
    }
    fs::read_to_string(path).with_context(|| format!("unable to read key file {}", path.display()))
}

/// Compares two byte slices in time that depends only on their length, not their
/// contents, so a configured secret cannot be recovered by timing a comparison.
/// Shared by the `first_time` bootstrap token check and recovery-code matching.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}
