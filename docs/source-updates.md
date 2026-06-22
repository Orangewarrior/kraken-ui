# Source updates

Kraken UI 0.13.0 adds an administrator-only source updater. The **Updates**
section in the left navigation contains **Update Kraken UI**, which opens:

```text
/kraken_ui/auth/update_kraken_ui
```

Operators and auditors cannot see the menu and cannot access its page, start
endpoint or status endpoint. All updater routes are protected by the same
`require_admin` middleware used for ACL administration. Starting an update also
requires the administrator's current password and, when enabled on the account,
a current two-factor code. Successful starts write a `source_update_started`
event to the audit log.

## User flow

The page shows the running package version, a read-only update console and the
**Update to last stable version** button. After submission:

1. Kraken UI queries the latest published release from the official GitHub API.
2. It rejects drafts, prereleases, malformed tags and releases that would
   downgrade the running version.
3. It downloads the release tar archive with `reqwest` over HTTPS.
4. It rejects unsafe paths, symbolic links, special files and oversized
   archives before extracting into an isolated temporary directory.
5. It verifies that the archive is the `kraken-ui` Cargo package and that its
   `Cargo.toml` version matches the release tag.
6. It runs `cargo build --release --locked` inside staging.
7. Only after a successful build does it copy source files and activate the new
   executable.
8. The replacement process waits briefly for the old listener to close, then
   starts the updated UI.

The browser keeps polling status once per second. During restart it displays a
120-second standby countdown and then redirects to `/kraken_ui/login`. A stable
`KRAKEN_UI_SESSION_KEY` is still recommended, although the deliberate redirect
requires the administrator to sign in again.

## Release source

The updater uses GitHub's public latest-release endpoint:

```text
https://api.github.com/repos/Orangewarrior/kraken-ui/releases/latest
```

The accepted tag must have the exact stable semantic form
`vMAJOR.MINOR.PATCH`. The archive URL is constructed locally from that validated
tag rather than accepting an arbitrary download URL from response data.

The updater follows at most five HTTPS redirects, caps the compressed download
at 100 MiB and caps extracted regular-file content at 500 MiB. GitHub source
archives are transport-authenticated by TLS; deployments requiring artifact
signatures should continue using an externally managed, signed package pipeline
instead of enabling in-application source updates.

Unsigned in-application source updates are disabled by default. Set
`KRAKEN_UI_ALLOW_UNSIGNED_SOURCE_UPDATE=1` only after an external release
verification process has already made the trust decision for this deployment.
Without that opt-in the update page remains visible to administrators, but a
start request fails closed before contacting GitHub.

## Preserved local state

The updater never copies release content over these top-level paths:

```text
.git/
target/
db/
conf/
certs/
log/
logs/
```

It also preserves every existing file ending in:

```text
.yaml
.yml
.conf
.db
.sqlite
.sqlite3
```

This keeps the operator database, sessions, WAF database references,
certificates, logs and local configuration intact. New non-conflicting
configuration files may be introduced by a release, but existing configuration
content is never overwritten.

The source deployment is an overlay: files removed by a release can remain in
the source directory, but the installed executable is always built from the
clean staged archive.

## Runtime requirements

The process account needs:

- outbound HTTPS access to `api.github.com` and GitHub's archive host;
- a stable Rust toolchain with `cargo`;
- write access to the Kraken UI source directory;
- write access to the running executable and its parent directory;
- enough disk space for the archive, a release build and one executable backup.

The source directory defaults to the process working directory. Set an explicit
path when Kraken UI starts elsewhere:

```bash
export KRAKEN_UI_SOURCE_DIR=/opt/kraken-ui
```

The directory must contain the current `Cargo.toml`. For systemd, set
`WorkingDirectory=` to the source checkout or define `KRAKEN_UI_SOURCE_DIR`.

## Executable activation and recovery

Before activation, the updater places the new executable beside the running
binary. The previous executable is retained with the suffix:

```text
.update-previous
```

If executable activation fails, the updater attempts to restore the previous
binary and reports the error in the console. Errors during release lookup,
download, validation or compilation leave the running installation untouched.

For production environments where the application user must not modify its own
executable, leave this feature inaccessible at the filesystem-permission layer
and deploy releases through the system package manager or CI/CD pipeline.

## Troubleshooting

| Console result | Meaning |
|---|---|
| Already at or newer than latest stable | GitHub's current stable release is not newer; no downgrade occurs. |
| GitHub rejected the request | Network, API availability or rate-limit failure. |
| Archive rejected | Unsafe paths, links, special files, size limit or malformed package. |
| Cargo build failed | The full captured Cargo output is appended to the update console. |
| Automatic restart unavailable | The application was constructed without the server lifecycle handle, normally only in embedded/test use. |
| Permission denied | The process cannot write the source tree or executable directory. |

Update output is limited to 64 KiB so repeated compiler diagnostics cannot grow
application memory without bound.
