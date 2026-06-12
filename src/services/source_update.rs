use std::{
    ffi::OsStr,
    fs,
    io::Cursor,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, bail};
use axum_server::Handle;
use flate2::read::GzDecoder;
use reqwest::{
    Client,
    header::{ACCEPT, USER_AGENT},
};
use semver::Version;
use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use tokio::{process::Command, sync::RwLock, time::sleep};

const LATEST_RELEASE_URL: &str =
    "https://api.github.com/repos/Orangewarrior/kraken-ui/releases/latest";
const ARCHIVE_URL_PREFIX: &str = "https://api.github.com/repos/Orangewarrior/kraken-ui/tarball/";
const MAX_ARCHIVE_BYTES: u64 = 100 * 1024 * 1024;
const MAX_EXTRACTED_BYTES: u64 = 500 * 1024 * 1024;
const MAX_LOG_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct SourceUpdateService {
    client: Client,
    state: Arc<RwLock<UpdateStatus>>,
    running: Arc<AtomicBool>,
    source_root: PathBuf,
    executable: PathBuf,
    server_handle: Option<Handle<SocketAddr>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct UpdateStatus {
    pub phase: UpdatePhase,
    pub current_version: String,
    pub target_version: Option<String>,
    pub log: String,
    pub in_progress: bool,
    pub redirect_after_seconds: Option<u64>,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpdatePhase {
    Idle,
    Checking,
    Downloading,
    Extracting,
    Compiling,
    Installing,
    Restarting,
    Complete,
    Failed,
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
}

#[derive(Debug, Deserialize)]
struct CargoManifest {
    package: CargoPackage,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
}

impl SourceUpdateService {
    pub fn new(server_handle: Option<Handle<SocketAddr>>) -> anyhow::Result<Self> {
        let source_root = std::env::var_os("KRAKEN_UI_SOURCE_DIR")
            .map(PathBuf::from)
            .unwrap_or(std::env::current_dir().context("failed to resolve the working directory")?);
        let source_root = source_root.canonicalize().with_context(|| {
            format!(
                "failed to resolve source directory {}",
                source_root.display()
            )
        })?;
        let executable =
            std::env::current_exe().context("failed to resolve the running executable")?;
        let client = Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::limited(5))
            .timeout(Duration::from_secs(60))
            .build()
            .context("failed to build the source-update HTTPS client")?;
        Ok(Self {
            client,
            state: Arc::new(RwLock::new(UpdateStatus {
                phase: UpdatePhase::Idle,
                current_version: env!("CARGO_PKG_VERSION").to_owned(),
                target_version: None,
                log: "Ready to check the latest stable Kraken UI release.\n".to_owned(),
                in_progress: false,
                redirect_after_seconds: None,
            })),
            running: Arc::new(AtomicBool::new(false)),
            source_root,
            executable,
            server_handle,
        })
    }

    pub async fn status(&self) -> UpdateStatus {
        self.state.read().await.clone()
    }

    pub async fn start(self: &Arc<Self>) -> bool {
        if self
            .running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        self.reset_for_update().await;
        let service = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(error) = service.run_update().await {
                service
                    .finish_failed(&format!("Update failed: {error:#}"))
                    .await;
            }
            service.running.store(false, Ordering::Release);
        });
        true
    }

    async fn run_update(&self) -> anyhow::Result<()> {
        self.set_phase(
            UpdatePhase::Checking,
            "Checking the latest published GitHub release...",
        )
        .await;
        validate_source_root(&self.source_root)?;

        let release = self.fetch_latest_release().await?;
        let target = stable_version_from_release(&release)?;
        {
            let mut state = self.state.write().await;
            state.target_version = Some(target.to_string());
        }
        let current = Version::parse(env!("CARGO_PKG_VERSION"))
            .context("the running package version is not semantic versioning")?;
        if target <= current {
            self.finish_complete(&format!(
                "No update installed. Running version {current} is already at or newer than the latest stable release {target}."
            ))
            .await;
            return Ok(());
        }

        self.set_phase(
            UpdatePhase::Downloading,
            &format!("Downloading Kraken UI v{target} source package..."),
        )
        .await;
        let archive = self.download_archive(&release.tag_name).await?;

        self.set_phase(
            UpdatePhase::Extracting,
            "Validating and extracting the release into an isolated staging directory...",
        )
        .await;
        let staging = TempDir::new_in(self.source_root.parent().unwrap_or_else(|| Path::new(".")))
            .context("failed to create the update staging directory")?;
        let staged_source = staging.path().join("source");
        let archive_for_unpack = archive;
        let staged_for_unpack = staged_source.clone();
        tokio::task::spawn_blocking(move || {
            unpack_release_archive(&archive_for_unpack, &staged_for_unpack)
        })
        .await
        .context("release extraction task failed")??;
        validate_staged_release(&staged_source, &target)?;

        self.set_phase(
            UpdatePhase::Compiling,
            "Release validated. Downloading Rust packages and compiling the new web UI. This can take several minutes...",
        )
        .await;
        let output = Command::new("cargo")
            .args(["build", "--release", "--locked"])
            .current_dir(&staged_source)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("failed to start cargo build for the staged release")?;
        self.append_command_output(&output.stdout, &output.stderr)
            .await;
        if !output.status.success() {
            bail!("the staged release did not compile successfully");
        }

        let staged_binary = staged_source.join("target/release/kraken-ui");
        if !staged_binary.is_file() {
            bail!(
                "compiled binary was not found at {}",
                staged_binary.display()
            );
        }
        self.set_phase(
            UpdatePhase::Installing,
            "Compilation succeeded. Installing source and executable while preserving databases and configuration files...",
        )
        .await;
        let source = staged_source.clone();
        let destination = self.source_root.clone();
        let staged_executable = staged_binary.clone();
        let running_executable = self.executable.clone();
        tokio::task::spawn_blocking(move || {
            prepare_executable(&staged_executable, &running_executable)?;
            copy_release_source(&source, &destination)?;
            activate_executable(&running_executable)
        })
        .await
        .context("release installation task failed")??;

        let Some(server_handle) = self.server_handle.clone() else {
            bail!("automatic restart is unavailable in this runtime");
        };
        self.set_restarting(&target).await;
        spawn_replacement(&self.executable, &self.source_root)?;
        sleep(Duration::from_millis(750)).await;
        server_handle.shutdown();
        Ok(())
    }

    async fn fetch_latest_release(&self) -> anyhow::Result<GitHubRelease> {
        let response = self
            .client
            .get(LATEST_RELEASE_URL)
            .header(ACCEPT, "application/vnd.github+json")
            .header(USER_AGENT, concat!("kraken-ui/", env!("CARGO_PKG_VERSION")))
            .header("X-GitHub-Api-Version", "2026-03-10")
            .send()
            .await
            .context("failed to query the GitHub releases API")?
            .error_for_status()
            .context("GitHub rejected the latest-release request")?;
        response
            .json()
            .await
            .context("GitHub returned invalid latest-release metadata")
    }

    async fn download_archive(&self, tag: &str) -> anyhow::Result<Vec<u8>> {
        validate_release_tag(tag)?;
        let response = self
            .client
            .get(format!("{ARCHIVE_URL_PREFIX}{tag}"))
            .header(ACCEPT, "application/vnd.github+json")
            .header(USER_AGENT, concat!("kraken-ui/", env!("CARGO_PKG_VERSION")))
            .header("X-GitHub-Api-Version", "2026-03-10")
            .send()
            .await
            .context("failed to download the release archive")?
            .error_for_status()
            .context("GitHub rejected the release archive request")?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_ARCHIVE_BYTES)
        {
            bail!("release archive exceeds the 100 MiB download limit");
        }
        let mut response = response;
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .context("failed while downloading the release archive")?
        {
            if bytes.len().saturating_add(chunk.len()) > MAX_ARCHIVE_BYTES as usize {
                bail!("release archive exceeds the 100 MiB download limit");
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    async fn reset_for_update(&self) {
        let mut state = self.state.write().await;
        state.phase = UpdatePhase::Checking;
        state.target_version = None;
        state.log.clear();
        state.in_progress = true;
        state.redirect_after_seconds = None;
    }

    async fn set_phase(&self, phase: UpdatePhase, message: &str) {
        let mut state = self.state.write().await;
        state.phase = phase;
        append_log(&mut state.log, message);
    }

    async fn append_command_output(&self, stdout: &[u8], stderr: &[u8]) {
        let mut state = self.state.write().await;
        for output in [stdout, stderr] {
            let output = String::from_utf8_lossy(output);
            if !output.trim().is_empty() {
                append_log(&mut state.log, output.trim());
            }
        }
    }

    async fn finish_complete(&self, message: &str) {
        let mut state = self.state.write().await;
        state.phase = UpdatePhase::Complete;
        state.in_progress = false;
        append_log(&mut state.log, message);
    }

    async fn finish_failed(&self, message: &str) {
        let mut state = self.state.write().await;
        state.phase = UpdatePhase::Failed;
        state.in_progress = false;
        append_log(&mut state.log, message);
    }

    async fn set_restarting(&self, target: &Version) {
        let mut state = self.state.write().await;
        state.phase = UpdatePhase::Restarting;
        state.in_progress = true;
        state.redirect_after_seconds = Some(120);
        append_log(
            &mut state.log,
            &format!(
                "Kraken UI {target} installed successfully. Restarting the web UI now. Keep this page open; it will redirect to login in two minutes."
            ),
        );
    }
}

fn stable_version_from_release(release: &GitHubRelease) -> anyhow::Result<Version> {
    if release.draft || release.prerelease {
        bail!("GitHub returned a draft or prerelease as the latest stable release");
    }
    validate_release_tag(&release.tag_name)
}

fn validate_release_tag(tag: &str) -> anyhow::Result<Version> {
    let Some(version) = tag.strip_prefix('v') else {
        bail!("release tag must use the vMAJOR.MINOR.PATCH format");
    };
    let version = Version::parse(version).context("release tag is not a semantic version")?;
    if !version.pre.is_empty() || !version.build.is_empty() {
        bail!("release tag is not a stable semantic version");
    }
    Ok(version)
}

fn validate_source_root(root: &Path) -> anyhow::Result<()> {
    let manifest = root.join("Cargo.toml");
    if !manifest.is_file() {
        bail!(
            "KRAKEN_UI_SOURCE_DIR does not contain Cargo.toml: {}",
            root.display()
        );
    }
    Ok(())
}

fn validate_staged_release(root: &Path, expected: &Version) -> anyhow::Result<()> {
    let manifest_path = root.join("Cargo.toml");
    let manifest_text = fs::read_to_string(&manifest_path)
        .with_context(|| format!("failed to read {}", manifest_path.display()))?;
    let manifest: CargoManifest =
        toml::from_str(&manifest_text).context("release Cargo.toml is invalid")?;
    if manifest.package.name != "kraken-ui" {
        bail!("release archive contains the wrong Cargo package");
    }
    let version =
        Version::parse(&manifest.package.version).context("release package version is invalid")?;
    if &version != expected {
        bail!("release tag version {expected} does not match Cargo.toml version {version}");
    }
    if !root.join("Cargo.lock").is_file() || !root.join("src/main.rs").is_file() {
        bail!("release archive is missing required Kraken UI source files");
    }
    Ok(())
}

fn unpack_release_archive(bytes: &[u8], destination: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(destination).context("failed to create extraction directory")?;
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = tar::Archive::new(decoder);
    let mut total_size = 0_u64;
    for entry in archive.entries().context("invalid release tar archive")? {
        let mut entry = entry.context("invalid release archive entry")?;
        let path = entry.path().context("invalid release archive path")?;
        let relative = strip_archive_root(&path)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        total_size = total_size.saturating_add(entry.header().size().unwrap_or(u64::MAX));
        if total_size > MAX_EXTRACTED_BYTES {
            bail!("release archive exceeds the 500 MiB extraction limit");
        }
        let output = destination.join(relative);
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            fs::create_dir_all(&output)
                .with_context(|| format!("failed to create {}", output.display()))?;
        } else if entry_type.is_file() {
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            entry
                .unpack(&output)
                .with_context(|| format!("failed to extract {}", output.display()))?;
        } else {
            bail!("release archive contains an unsupported link or special file");
        }
    }
    Ok(())
}

fn strip_archive_root(path: &Path) -> anyhow::Result<PathBuf> {
    let mut components = path.components();
    let Some(Component::Normal(_)) = components.next() else {
        bail!("release archive path has no package root");
    };
    let mut relative = PathBuf::new();
    for component in components {
        match component {
            Component::Normal(value) => relative.push(value),
            _ => bail!("release archive contains an unsafe path"),
        }
    }
    Ok(relative)
}

fn copy_release_source(source: &Path, destination: &Path) -> anyhow::Result<()> {
    copy_directory(source, destination, Path::new(""))
}

fn copy_directory(source: &Path, destination: &Path, relative: &Path) -> anyhow::Result<()> {
    for entry in fs::read_dir(source)
        .with_context(|| format!("failed to read release directory {}", source.display()))?
    {
        let entry = entry.context("failed to read release directory entry")?;
        let file_type = entry
            .file_type()
            .context("failed to inspect release entry")?;
        if file_type.is_symlink() {
            bail!("release source contains an unsupported symbolic link");
        }
        let child_relative = relative.join(entry.file_name());
        if protected_path(&child_relative, &destination.join(&child_relative)) {
            continue;
        }
        let target = destination.join(&child_relative);
        ensure_destination_safe(destination, &target)?;
        if file_type.is_dir() {
            fs::create_dir_all(&target)
                .with_context(|| format!("failed to create {}", target.display()))?;
            copy_directory(&entry.path(), destination, &child_relative)?;
        } else if file_type.is_file() {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            fs::copy(entry.path(), &target)
                .with_context(|| format!("failed to install {}", target.display()))?;
        }
    }
    Ok(())
}

fn ensure_destination_safe(root: &Path, target: &Path) -> anyhow::Result<()> {
    let relative = target
        .strip_prefix(root)
        .context("update target escaped the source root")?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            bail!("update target contains an unsafe path component");
        };
        current.push(component);
        if current.exists()
            && fs::symlink_metadata(&current)
                .with_context(|| format!("failed to inspect {}", current.display()))?
                .file_type()
                .is_symlink()
        {
            bail!(
                "refusing to update through symbolic link {}",
                current.display()
            );
        }
    }
    Ok(())
}

fn protected_path(relative: &Path, target: &Path) -> bool {
    let first = relative
        .components()
        .next()
        .and_then(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        });
    if matches!(
        first,
        Some(".git" | "target" | "db" | "conf" | "certs" | "log" | "logs")
    ) {
        return true;
    }
    if !target.exists() {
        return false;
    }
    matches!(
        relative.extension().and_then(OsStr::to_str),
        Some("yaml" | "yml" | "conf" | "db" | "sqlite" | "sqlite3")
    )
}

fn prepared_executable_path(executable: &Path) -> PathBuf {
    executable.with_extension("update-new")
}

fn previous_executable_path(executable: &Path) -> PathBuf {
    executable.with_extension("update-previous")
}

fn prepare_executable(staged: &Path, executable: &Path) -> anyhow::Result<()> {
    let prepared = prepared_executable_path(executable);
    fs::copy(staged, &prepared)
        .with_context(|| format!("failed to stage executable at {}", prepared.display()))?;
    fs::set_permissions(&prepared, fs::metadata(staged)?.permissions())
        .context("failed to preserve executable permissions")?;
    Ok(())
}

fn activate_executable(executable: &Path) -> anyhow::Result<()> {
    let prepared = prepared_executable_path(executable);
    let previous = previous_executable_path(executable);
    if previous.exists() {
        fs::remove_file(&previous).context("failed to remove the previous update backup")?;
    }
    fs::rename(executable, &previous).with_context(|| {
        format!(
            "failed to preserve the running executable as {}",
            previous.display()
        )
    })?;
    if let Err(error) = fs::rename(&prepared, executable) {
        let _ = fs::rename(&previous, executable);
        return Err(error).context("failed to activate the updated executable");
    }
    Ok(())
}

fn spawn_replacement(executable: &Path, source_root: &Path) -> anyhow::Result<()> {
    let mut command = std::process::Command::new(executable);
    command
        .args(std::env::args_os().skip(1))
        .current_dir(source_root)
        .env("KRAKEN_UI_RESTART_DELAY_MS", "2000")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    command
        .spawn()
        .context("failed to start the updated Kraken UI process")?;
    Ok(())
}

fn append_log(log: &mut String, message: &str) {
    if !log.is_empty() && !log.ends_with('\n') {
        log.push('\n');
    }
    log.push_str(message);
    if !log.ends_with('\n') {
        log.push('\n');
    }
    if log.len() > MAX_LOG_BYTES {
        let keep_from = log.len() - MAX_LOG_BYTES;
        let boundary = log
            .char_indices()
            .find_map(|(index, _)| (index >= keep_from).then_some(index))
            .unwrap_or(keep_from);
        log.drain(..boundary);
        log.insert_str(0, "[earlier update output truncated]\n");
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use super::{
        GitHubRelease, UpdatePhase, append_log, copy_release_source, protected_path,
        stable_version_from_release, strip_archive_root, unpack_release_archive,
    };

    #[test]
    fn accepts_only_stable_semantic_release_tags() {
        let release = GitHubRelease {
            tag_name: "v1.2.3".to_owned(),
            draft: false,
            prerelease: false,
        };
        assert_eq!(
            stable_version_from_release(&release)
                .expect("stable release")
                .to_string(),
            "1.2.3"
        );

        let prerelease = GitHubRelease {
            tag_name: "v1.3.0-rc.1".to_owned(),
            draft: false,
            prerelease: true,
        };
        assert!(stable_version_from_release(&prerelease).is_err());
    }

    #[test]
    fn strips_one_archive_root_and_rejects_traversal() {
        assert_eq!(
            strip_archive_root(Path::new("owner-repo/src/main.rs")).expect("safe path"),
            Path::new("src/main.rs")
        );
        assert!(strip_archive_root(Path::new("owner-repo/../secret")).is_err());
        assert!(strip_archive_root(Path::new("/absolute/path")).is_err());
    }

    #[test]
    fn preserves_runtime_state_and_existing_configuration() {
        assert!(protected_path(
            Path::new("db/kraken-ui.sqlite"),
            Path::new("/tmp/missing")
        ));
        assert!(protected_path(
            Path::new("conf/setup.yaml"),
            Path::new("/tmp/missing")
        ));
        assert!(protected_path(
            Path::new("certs/key.pem"),
            Path::new("/tmp/missing")
        ));
        assert!(!protected_path(
            Path::new("src/main.rs"),
            Path::new("/tmp/missing")
        ));
    }

    #[test]
    fn source_copy_keeps_database_and_configuration_contents() {
        let source = tempfile::tempdir().expect("source tempdir");
        let destination = tempfile::tempdir().expect("destination tempdir");
        fs::create_dir_all(source.path().join("src")).expect("source src");
        fs::create_dir_all(source.path().join("conf")).expect("source conf");
        fs::create_dir_all(source.path().join("db")).expect("source db");
        fs::create_dir_all(destination.path().join("src")).expect("destination src");
        fs::create_dir_all(destination.path().join("conf")).expect("destination conf");
        fs::create_dir_all(destination.path().join("db")).expect("destination db");
        fs::write(source.path().join("src/main.rs"), "new source").expect("new source");
        fs::write(source.path().join("conf/setup.yaml"), "new config").expect("new config");
        fs::write(source.path().join("db/ui.sqlite"), "new database").expect("new db");
        fs::write(destination.path().join("src/main.rs"), "old source").expect("old source");
        fs::write(destination.path().join("conf/setup.yaml"), "user config").expect("user config");
        fs::write(destination.path().join("db/ui.sqlite"), "user database").expect("user db");

        copy_release_source(source.path(), destination.path()).expect("copy release");

        assert_eq!(
            fs::read_to_string(destination.path().join("src/main.rs")).expect("installed source"),
            "new source"
        );
        assert_eq!(
            fs::read_to_string(destination.path().join("conf/setup.yaml")).expect("kept config"),
            "user config"
        );
        assert_eq!(
            fs::read_to_string(destination.path().join("db/ui.sqlite")).expect("kept db"),
            "user database"
        );
    }

    #[test]
    fn archive_rejects_symbolic_links() {
        let mut bytes = Vec::new();
        {
            let encoder = flate2::write::GzEncoder::new(&mut bytes, flate2::Compression::default());
            let mut archive = tar::Builder::new(encoder);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            header.set_cksum();
            archive
                .append_link(
                    &mut header,
                    "owner-repo/src/escape",
                    Path::new("../../outside"),
                )
                .expect("append symlink");
            archive
                .into_inner()
                .expect("finish tar")
                .finish()
                .expect("gzip");
        }
        let destination = tempfile::tempdir().expect("destination tempdir");

        assert!(unpack_release_archive(&bytes, destination.path()).is_err());
        assert!(!bytes.is_empty());
    }

    #[test]
    fn update_log_is_bounded() {
        let mut log = String::new();
        append_log(&mut log, &"x".repeat(70 * 1024));
        assert!(log.len() < 66 * 1024);
        assert!(log.starts_with("[earlier update output truncated]"));
    }

    #[test]
    fn update_phase_serializes_for_the_frontend() {
        assert_eq!(
            serde_json::to_string(&UpdatePhase::Restarting).expect("serialize"),
            "\"restarting\""
        );
    }
}
