# Changelog

All notable changes to this project are recorded in this file.

## 0.18.0 - 2026-06-17

### Added

- **Regex rule editor (Rule management → Regex rules).** Administrators and
  operators can now view and replace the content of KrakenWAF's regex and keyword
  rule files at runtime — `body_regex`, `path_regex`, `header_regex`,
  `vectorscan_list` and `scanners` — from a new console surface. The picker
  (`/kraken_ui/auth/rule_management/regex`) chooses a rule list; the editor
  (`/kraken_ui/auth/rule_management/regex/edit`) fetches its content server-side
  from KrakenWAF `POST /rule/control/regex/view` and renders it in a
  syntax-highlighting editor; **Update rule**
  (`/kraken_ui/auth/rule_management/regex/update`) validates the content and
  forwards it to KrakenWAF `POST /rule/control/regex/update/<name>`. As with CMC,
  the browser never holds a Rorschach secret and never contacts the WAF directly;
  each upstream call is minted server-side and bound to its method, path and body.
- **Per-shape validation via a factory.** A new `services::regex_rules` module
  maps each rule list (an allowlisted enum) to the codec that knows its on-disk
  shape: the JSON regex bundles require a non-empty `rules` array whose elements
  carry every required field and a non-empty `rule_match`; the Vectorscan keyword
  bundle requires only the non-empty `rules` envelope; the scanner allowlist is
  line-delimited text wrapped as `{ "lines": [...] }`. Validation runs before the
  WAF is contacted and returns a specific, operator-facing message (empty file,
  broken JSON, or the exact rule index and missing field).
- **Vendored ACE editor.** The official `ace-builds` 1.36.5 editor is vendored
  under `src/view/static/vendor/ace` (with its `LICENSE`). The integration stays
  within the strict CSP: ACE stylesheets are linked as static files with runtime
  style injection disabled (`useStrictCSP`), the JSON worker loads from a
  same-origin URL rather than a blob (`loadWorkerFromBlob = false`), and no
  `innerHTML` is used. The editor highlights JSON with the *Clouds Midnight*
  theme (plain text for the scanner list), shows the gutter, line numbers, indent
  guides, the active line and the selected word, uses full-line selection and the
  browser spell checker. Every regex editor page carries a fixed ReDoS / PCRE
  caution below the editor.

### Security

- The regex rule name is always re-validated against a closed allowlist before it
  is used, so a forged name can never become part of an upstream path or reach the
  WAF. Updates are CSRF-protected and validated before any upstream call; the
  routes sit behind `require_operator`, so auditors (who cannot authenticate to
  the console at all) can neither view nor edit rules.

### Tests

- Unit tests for `services::regex_rules` (allowlist parsing, editor mode
  selection, and every codec: valid input, empty input, broken JSON, missing
  `rules`, empty `rules`, missing/empty fields, keyword envelope, and scanner line
  wrapping) and for the new service shapes (`regex_view` body and response).
- A view test that the editor template HTML-escapes rule content and always
  renders the ReDoS caution and the same-origin ACE bundle.
- A new isolated, real-HTTP integration test
  (`tests/regex_rule_management_http.rs`): an admin views and updates a rule over
  two real loopback servers (asserting the Rorschach token, the documented view
  body, the update path and the verbatim written bytes), an empty file and a
  missing field are refused with actionable messages before the WAF, a forged CSRF
  token is rejected, an auditor cannot obtain a session, and an unauthenticated
  client is bounced from the editor routes.

### Documentation

- [docs/rule-management.md](docs/rule-management.md) gains a **Regex rule editor**
  section: the managed rule lists, the flow, the upstream endpoints and bodies,
  and the CSP-compatible ACE integration.
- README updated with the new feature, route table entries and version.

### CI

- Cleared the pre-existing `rust.lang.security.args` Semgrep finding on the
  `view_waf_request_probe` example by adding the same justified `// nosemgrep`
  suppression the codebase already uses for benign CLI argv parsing (the probe's
  argv selects only its target and credentials and drives no security decision).

## 0.17.0 - 2026-06-16

### Security

- **Secret redaction on the single-attack detail view.** The captured
  request/response evidence shown by `/kraken_ui/auth/view_waf_request/` (the
  request URI, the full-path evidence and the matched payload) often carries
  credentials. From now on **only an administrator** sees those bytes in clear:
  for an operator or auditor, the value of any parameter whose name matches a
  well-known secret word — in many languages (`password`, `passe`, `token`,
  `jeton`, `bearer`, `senha`, `clave`, `пароль`, `密码`, `パスワード`, `kunci`, …)
  — is replaced with `+++++` before the page is rendered. The decision is made
  server-side from the session's operator type, so the masked bytes never leave
  the server for a non-admin. Non-sensitive parameters and describing metadata
  (title, CWE, rule match, …) are unchanged.
- New `security::redact` module with the authoritative `SENSITIVE_WORDS` list and
  a structure-preserving redactor that handles form-urlencoded, JSON and quoted
  values, compound and localized parameter names, and parameters nested inside a
  value, while leaving empty values empty.

### Tests

- Unit tests for the redactor (`src/security/redact.rs`): form-urlencoded, JSON
  and spaced keys, several languages, compound names, nested values, empty
  values, idempotency and the case-insensitive name classifier.
- A new isolated, real-HTTP integration test
  (`tests/view_waf_request_redaction_http.rs`) drives the full router over a real
  read-only WAF SQLite seeded with a credential-bearing finding: it signs in as
  `admin` (sees the values) and as `operator` (sees `+++++`, while non-sensitive
  parameters survive).
- A standalone probe (`examples/view_waf_request_probe.rs`) that signs in to a
  running instance and reports whether the detail view masks values for a role.

### Documentation

- New [docs/sensitive-data-redaction.md](docs/sensitive-data-redaction.md), and
  updated README (roles table and the single-attack detail view section).

## 0.16.0 - 2026-06-16

### Added

- **Rule management console.** A new **Rule management → CMC rules** sidebar
  menu, open to administrators and operators, lists KrakenWAF's CMC detection
  modules and lets an operator enable or disable them at runtime. The page
  renders a datatable (CMC module name, status, and a checkbox ticked when the
  module is on) populated from `GET /rule/control/cmc/list`; **Submit all** posts
  the full desired state to `POST /rule/control/cmc/update`. Success and failure
  each raise a message box ("error in WAF server" on failure), and the table
  reloads from the live state after a successful update.
- **Rule-management API client** (`services::rule_management`). Authenticates to
  KrakenWAF's rule-management API with a per-request *Rorschach* token: a
  time-windowed (`floor(unix/300)`) BLAKE2b-256 keyed MAC over a canonical
  message binding the method, path and body hash, encoded base64url without
  padding. The secret is selected by step parity. TLS is pinned to the configured
  CA, the `Authorization` header is marked sensitive, and the token and secrets
  never reach logs. KrakenWAF computes the same MAC with `orion`; Kraken UI uses
  libsodium BLAKE2b via `dryoc`, which is byte-identical (verified by a BLAKE2b
  known-answer test).
- **Shared Rorschach secrets**, reusing KrakenWAF's names and file-first
  resolution (`<NAME>_FILE` → `/run/secrets/krakenwaf/<NAME>` → `<NAME>`):
  `RORSCHACH_SECRET_EVEN`, `RORSCHACH_SECRET_ODD` and `RORSCHACH_CLIENT_ID`. A
  co-located deployment reuses KrakenWAF's mount; otherwise the new
  `rorschach_keygen` binary generates a random pair (64 bytes, base64url) and can
  write CIS-style secret files (dir `0750`, files `0440`).
- New configuration keys `waf-rule-endpoint` (must be `https://`) and the
  optional `waf-rule-cert-ca`, validated at load time. When unset, the console
  reports itself as not configured rather than failing.
- New documentation: [docs/rule-management.md](docs/rule-management.md). The new
  secrets and how to fill them with random values are documented in
  [docs/security.md](docs/security.md).

### Tests

- Unit tests for the Rorschach token (canonical message order, five-part header
  shape, even/odd secret selection, the documented update body) and a BLAKE2b-256
  known-answer test pinning `dryoc` to the standard vector.
- A new isolated integration test (`tests/rule_management_http.rs`) drives the
  full Kraken UI router and a mock KrakenWAF over real HTTP with `reqwest`: it
  logs in, lists modules through the proxy and submits a toggle, asserting the
  Rorschach `Authorization` token and the exact upstream JSON body.

## 0.15.0 - 2026-06-13

### Security

- Require `KRAKEN_UI_FIRST_TIME_TOKEN` for the `first_time` bootstrap endpoint in
  release builds (fail closed); debug builds keep it optional.
- Refuse an explicitly configured `*_FILE` secret (such as `BEARER_PASSWORD_FILE`)
  when it is readable by group or others, while still warning — rather than
  failing — for the platform-managed `/run/secrets/krakenwaf` mount.
- Validate the `listen` socket address at configuration load time so a malformed
  value is rejected at startup.
- Stop using the shared system temporary directory with predictable names in the
  test suite (Semgrep `rust.lang.security.temp-dir.temp-dir`); each test now uses
  a uniquely named `tempfile` directory that is removed on drop.

### Changed

- Rename the database configuration keys to `db-ui` (the UI's read-write
  database) and `db-waf-alerts` (the read-only WAF alerts database), removing the
  dangerous `db-local` / `db_local` near-collision. The previous names remain
  accepted as deprecated aliases, and the two keys are validated to point at
  different files.
- Remove the unused legacy `conf/setup.conf`; `conf/setup.yaml` is the single
  configuration file.
- Replace the Ammonia HTML sanitiser on the CSRF and pagination request paths
  with a constant-cost character check and direct integer parsing; the
  cryptographic CSRF verification is unchanged.
- Try the TOTP skew window current-step-first and document the replay-window
  trade-off.
- Group the request-throttling state in `AppState` behind a `RateLimiting`
  struct, and amortise the per-IP concurrency limiter's dead-entry cleanup.

### Removed

- Delete the unused `AppError::unauthorized` / `AppError::bad_request` constructors
  and `AppConfig::session_timeout`, and de-duplicate the constant-time comparison
  and CSRF render helpers.

### Added

- Add an end-to-end integration test for the login, protected-page and logout
  flow over the assembled router.

## 0.14.0 - 2026-06-12

### Added

- Replace the process-local token bucket with `axum-governor` and governor's
  GCRA algorithm, keyed by the direct TCP peer IP.
- Add persistent GCRA state through SQLite by default and an optional shared
  Redis backend for multi-replica deployments.
- Add active per-IP concurrency, TLS handshake and accepted-request timeouts,
  all configured in `conf/ratelimit.yaml`.
- Add a real HTTP integration test that sends repeated requests with `reqwest`
  and verifies SQLite-backed burst rejection.

### Security

- Require verified TLS and ACL credentials for Redis; plaintext Redis
  connections are rejected at startup.
- Resolve `REDIS_USERNAME` and `REDIS_PASSWORD` through `_FILE`,
  `/run/secrets/krakenwaf/` and environment sources without storing secrets in
  YAML or connection URLs.
- Use bounded Redis connection/response timeouts, bounded retries, a validated
  key prefix and fail-closed behavior by default.
- Configure SQLite WAL, immediate transactions, busy timeout and
  `trusted_schema=OFF` for durable, atomic GCRA decisions.

### Changed

- Add `conf/ratelimit.yaml` as the authoritative runtime configuration for
  request rate, burst, concurrency and connection-related timeouts.
- Require Rust 1.95 and bump the package version from `0.13.0` to `0.14.0`.

### Documentation

- Add `docs/rate-limiting.md` with SQLite operations, Redis systemd credentials,
  CIS-aligned server hardening guidance and failure semantics.
- Update the README quick start and security overview.

## 0.13.0 - 2026-06-12

### Added

- Add an administrator-only **Updates → Update Kraken UI** navigation section
  and update page with running-version details, a live console and a stable
  release action.
- Query the official GitHub latest-release API with `reqwest`, download the
  validated release archive, compile it in staging with
  `cargo build --release --locked`, install it and restart the TLS listener.
- Poll update status in the browser and show a 120-second restart standby before
  redirecting to login.
- Retain the previous executable beside the active binary for manual recovery.

### Security

- Protect the page, update action and status API with `require_admin`; operators
  and auditors neither see nor reach the feature.
- Require stable `vMAJOR.MINOR.PATCH` release tags and refuse downgrades,
  prereleases and drafts.
- Reject archive traversal, symbolic links, special files and oversized
  downloads/extractions.
- Preserve databases, sessions, certificates, logs, `conf/` and all existing
  YAML, `.conf` and SQLite files.
- Bound update console output to 64 KiB and audit every accepted update start.

### Documentation

- Add `docs/source-updates.md` with runtime requirements, trust boundaries,
  preservation rules, restart behavior and recovery instructions.
- Document the new routes, environment variable and architecture in the README
  and operations/database/architecture guides.

## 0.12.0 - 2026-06-12

Kraken UI now supports the authenticated observability channel introduced by
current KrakenWAF releases.

### Added

- Authenticate `/metrics` and the compatibility `/__kwaf/metrics` request with
  `Authorization: Bearer <token>`.
- Resolve `BEARER_PASSWORD` with the same file-first contract as KrakenWAF:
  `BEARER_PASSWORD_FILE`, `/run/secrets/krakenwaf/BEARER_PASSWORD`, then the
  plain environment variable.
- Add a systemd credential drop-in that lets Kraken UI and KrakenWAF use the
  same root-owned token source without placing the token itself in
  `Environment=`.
- Add a dedicated deployment and troubleshooting guide at
  `docs/waf-bearer-auth.md`.

### Security

- Reject empty or non-ASCII bearer tokens before building the HTTP client.
- Mark the generated `Authorization` header as sensitive so its value is
  redacted by HTTP-layer diagnostics.
- Keep the existing pinned TLS trust for the WAF metrics connection.

### Changed

- Standardize the KrakenWAF observability endpoint examples on
  `https://127.0.0.1:4343`.
- Expand dashboard diagnostics to mention `BEARER_PASSWORD` when observability
  data is unavailable.
- Bump the package version from `0.11.0` to `0.12.0`.

## 0.11.0 - 2026-06-09

A security and quality hardening pass spanning AppSec, the runtime, Rust quality
and the CI supply chain.

### Security

- **TOTP codes can no longer be replayed inside their validity window.** Each
  account records the highest TOTP time-step that has authenticated it
  (`operator_mfa_totp.last_used_step`); a code is accepted only when its step is
  strictly greater (RFC 6238 §5.2).
- **Password hashing is bounded.** Argon2id work runs under a semaphore sized to
  the available parallelism, so a burst of logins — each `*_MODERATE` hash needs
  ~256 MiB, including the unknown-user timing-equaliser path — can no longer
  exhaust host memory.
- **The two-factor challenge expires after five minutes,** independently of the
  longer session idle timeout, so a half-finished login cannot linger.
- **Distributed guessing is surfaced.** A new detection-only monitor emits an
  `account_guessing_suspected` audit event when one account draws failures from
  many source IPs. It never locks an account (the IP throttle stays per-IP on
  purpose).
- **The session signing key fails closed in release builds:** the server refuses
  to start without `KRAKEN_UI_SESSION_KEY` / `_FILE` unless
  `KRAKEN_UI_ALLOW_EPHEMERAL_SESSION_KEY` is set (debug builds still allow it).

### Changed

- `#![forbid(unsafe_code)]` is enforced crate-wide.
- The login form posts to `POST /kraken_ui/login` (the old `/kraken_ui/test_login`
  path is gone); `GET /kraken_ui/login` still serves the form.
- The XChaCha20-Poly1305 cipher is built once and reused, deriving the key
  schedule a single time instead of on every encrypt/decrypt.

### Removed

- The vestigial `src/view/black_n_orange_theme` mock-up (including an
  `innerHTML`-based script) and a dead legacy front-end module in `app.js`.

### Documentation

- Corrected the single-attack detail-view description: the `request_payload` is
  HTML-escaped, not Ammonia-stripped (the README and architecture docs were
  stale; the code was already correct).
- Documented the direct-TLS / no-reverse-proxy expectation for the per-IP
  controls and the audited client IP.

### CI / supply chain

- Least-privilege workflow permissions, `persist-credentials: false` on
  checkouts, a concurrency guard, Semgrep promoted to a blocking gate, and a new
  Dependabot config for GitHub Actions and Cargo.

## 0.10.1 - 2026-06-09

A follow-up release that finishes the MFA enrolment UX and documents the new
behaviour.

### Added

- **Server-rendered QR code for TOTP enrolment.** The two-factor setup page now
  shows the `otpauth://` secret as a scannable QR image, rendered locally as an
  inline SVG instead of relying on a third-party QR service or client-side
  JavaScript.
- **Optional recovery-code download.** Right after two-factor is confirmed (and
  after recovery-code regeneration), the recovery-code page now offers a
  `Download codes (.txt)` action that downloads the exact one-time codes being
  shown on screen.

### Changed

- **Pending MFA enrolments survive a page revisit.** Returning to
  `/kraken_ui/auth/mfa` while an enrolment is still unconfirmed now re-shows the
  same QR code, provisioning URI and base32 secret instead of dropping the
  in-progress setup.
- **`GET /kraken_ui/auth/mfa_enroll` is no longer a dead-end URL.** Opening it
  directly now redirects to `/kraken_ui/auth/mfa`, which makes manual navigation
  and stale bookmarks land on the correct page.

### Documentation

- `docs/mfa.md` now documents the embedded QR code, the optional recovery-code
  download, the pending-enrolment replay behaviour and the `GET /mfa_enroll`
  redirect.

## 0.10.0 - 2026-06-09

A feature release that adds optional two-factor authentication (TOTP) for every
operator, and makes stored timestamps compact and uniform.

### Added

- **Two-factor authentication (TOTP).** Operators and administrators can now
  protect their account with a time-based one-time password from any standard
  authenticator app, built on the [`otpauth`](https://crates.io/crates/otpauth)
  crate. A new **User status → Two-factor auth** page lets each operator enrol
  (scan/enter the secret, confirm a code), regenerate recovery codes, and
  disable two-factor after re-confirming their password. Enrolling mints ten
  single-use recovery codes, shown exactly once.
- **A second step at sign-in.** When two-factor is enabled, a correct password
  no longer completes the login on its own: it parks a half-authenticated
  marker on the session and redirects to a code challenge. No authenticated role
  is granted until a valid TOTP code — or a single-use recovery code — is
  entered. The challenge is throttled per source IP and account, exactly like
  the password step.
- **Two new tables.** `operator_mfa_totp` holds one TOTP secret per operator and
  `operator_mfa_recovery_codes` holds the single-use recovery codes; both
  reference `operators(id_user)` with `ON DELETE CASCADE`. The TOTP secret and
  every recovery code are sealed at rest in the same XChaCha20-Poly1305 envelope
  used for password hashes, bound to the user id and a purpose-specific AAD so a
  record cannot be replayed against another account or repurposed.
- **A `2MFA` column** on `operators` (`mfa_enabled`, integer, default `0`) and in
  the **ACL → Users table**, so an administrator can see at a glance which
  accounts have two-factor enabled. The column is included in the CSV export.

### Changed

- **Timestamps are stored as `YYYY-MM-DD HH:MM:SS`.** Every `created_at` /
  `updated_at` (and the new `confirmed_at` / `used_at`) column is now written in
  a fixed-width, second-precision UTC form instead of RFC 3339. This keeps the
  DataTables date columns compact on the users table. Existing databases are
  migrated in place (the new columns are added with safe defaults on startup).

### Documentation

- New [`docs/mfa.md`](docs/mfa.md) covering the enrolment, challenge and recovery
  flows, the storage model and the security properties. `docs/database.md` and
  the README are updated for the new tables, column and routes.

## 0.9.0 - 2026-06-08

A security-hardening release: live sessions can no longer outlast the authority
that granted them, attack payloads are shown with full fidelity instead of being
stripped, and logs are bounded.

### Security

- **Sessions are revoked the moment an operator's authority changes.** Each
  session row now carries the signed-in operator id in an indexed `user_id`
  column. Deleting an operator, or changing their role, revokes every live
  session they hold — so a removed account stops working immediately and a
  demotion takes effect without waiting for re-login (the route guards read the
  role from the session). Changing a password revokes the operator's other
  sessions, sparing only the one making the change. Previously a deleted or
  demoted operator kept their existing access until the session happened to
  expire.
- **WAF request payloads are shown inert, not stripped.** The single-attack
  detail view renders the attacker-controlled `request_payload` through the
  template's HTML escaping instead of passing it through Ammonia. The analyst now
  sees the exact attack bytes (the client highlighter reads them back via
  `textContent`), and nothing can execute under the strict CSP / Trusted Types.
- **Logs roll daily.** The application and audit logs now rotate per day so they
  cannot grow without bound on a long-running service.

### Changed

- The password policy now **allows spaces**, so passphrases are practical
  (aligned with NIST SP 800-63B). All other requirements are unchanged.
- Dropped the deprecated `block-all-mixed-content` directive from the
  Content-Security-Policy; it is already covered by `upgrade-insecure-requests`.

### Documentation

- `docs/security.md` now documents the **client-IP trust boundary**: the login
  throttle and global rate limiter key on the TCP peer address, never on a
  spoofable forwarding header, so Kraken UI is designed to be exposed directly at
  the edge. The implications of running behind a reverse proxy are spelled out.

## 0.8.0 - 2026-06-08

### Added

- The attacks and users tables can now export the **current page to CSV** via a
  Download CSV button in the table footer. The file is built client-side from the
  rows on screen (untruncated values, action columns excluded) and downloaded
  with a UTF-8 BOM. On the users table the button is rendered for administrators
  only.
- The attacks table **Rule match** column is truncated to its trailing 13
  characters, prefixed with `...` (16 total), to free horizontal space; the full
  rule is shown on hover as a tooltip.
- Hovering any **Request URI** cell now shows the full, untruncated URI as a
  tooltip (previously only present on truncated cells).

### Changed

- The attacks table now loads **100 rows per page** (was 50).

### Added

- The attacks table now has a sortable **Occurred at** column. The first click
  orders by the most recent attack (newest first); clicking again reverses to
  oldest first. The header is keyboard-operable and the ordering is applied
  server-side alongside the existing severity sort.
- A column **select box** in front of the attacks search input scopes the lookup
  to a single field — ID, Title, Client IP, Request URI, Rule match, Occurred at
  or Country — or all columns (the default), making the section more useful for
  auditing. The filter is enforced server-side via the repository query.

### Changed

- Long **Request URI** values in the attacks table are truncated to their
  trailing 61 characters, prefixed with `...` (64 characters total), so the
  column stays compact and leaves room for the others. The full value remains
  available on hover and search still matches the untruncated URI.
- The attacks page lead now documents the Occurred-at sort behaviour and notes
  that clicking an attack's ID or Client IP opens its full request/response
  detail in a new tab.
- `GET /kraken_ui/auth/api/attacks` accepts new `search_field`, `sort` and
  `order` query parameters (replacing `severity_order`). All three features work
  for both `admin` and `operator` sessions.

## 0.6.0 - 2026-06-08

### Added

- Operators (`type = operator`) can now sign in to the console. Their session
  renders the same dashboard, attacks table and self-service password change as
  administrators, but the left navigation drops the ACL section entirely.
- New authenticated detail page `GET /kraken_ui/auth/view_waf_request/?id=<id>`.
  Clicking the ID or client-IP column of the attacks table opens the full WAF
  finding in a new tab: title, severity (colour-coded), CWE, description,
  reference, human-readable timestamp, rule match, client IP, URI, fullpath
  evidence and, last, the request/response payload in a light-themed,
  syntax-highlighted code box. The page is available to `admin`, `operator` and
  `auditor` sessions only.
- The attacker-controlled `request_payload` is sanitised with Ammonia before it
  is rendered, and tokenised client-side without `innerHTML` to honour the
  Trusted-Types CSP.

### Changed

- Authorization is now split into three role-aware middleware layers:
  `require_admin` (ACL management), `require_operator` (admin + operator console)
  and `require_attack_viewer` (admin + operator + auditor detail view).

## 0.5.0 - 2026-06-07

### Security

- Added a global, per-IP request rate limiter (token bucket) as defence in
  depth across every route.
- Pinned the WAF metrics channel to the configured `waf-cert-ca` only, no longer
  trusting the system root store, so it cannot be intercepted by another
  publicly trusted CA.
- Reworked login throttling to key the per-account counter by IP *and* account,
  removing the account-lockout denial-of-service vector.
- A successful login by a non-admin operator now returns the same generic
  response as a failed login, closing a credential-validity oracle.
- Bounded the pagination offset so a hostile `start` value cannot force an
  expensive SQLite scan.
- Enabled SQLite WAL, `busy_timeout`, `synchronous=NORMAL` and `foreign_keys`
  on every connection; expired session rows are now garbage-collected.
- Split logging into a dedicated `audit.jsonl` sink for `audit`-target events,
  separate from the application log.
- Plaintext passwords now flow through `Zeroizing` on the verification and
  hashing paths.

### Changed

- Refactoring with no behavioural change: shared `PageResponse<T>` and query
  helpers, a single `LIKE`-escaping helper, one CSRF-verification function,
  centralised async crypto helpers, a shared protected-file reader, navigation
  constants, and RFC 3339 timestamps via the `time` crate.
- Removed the unused `OperatorRepository::delete_by_email`.

### Fixed

- Corrected the declared licence to **MIT** (in `Cargo.toml`, the README and the
  docs) to match the `LICENSE` file, which has always been MIT.

### Documentation

- Documented the persistent session store and the `kraken_sessions` table,
  the dedicated `audit.jsonl` log, the login throttle and global rate limiter,
  WAF certificate pinning, and the new helper modules across `docs/architecture.md`,
  `docs/database.md`, `docs/operations.md` and `docs/security.md`.
- Refreshed the README's feature highlights, project layout and docs index.

## 0.4.0 - 2026-06-06

### Security

Mitigations for every finding in `docs/security-review.md`:

- **Login rate limiting and lockout (H-1):** failed logins are now throttled per
  source IP and per account (5 failures in 5 minutes triggers a 15-minute
  lockout), closing the online password-guessing window.
- **Constant-time login (H-2):** an unknown username now triggers a dummy
  Argon2id verification, so login latency no longer reveals whether an account
  exists.
- **Persistent sessions and a stable signing key (M-1):** sessions are stored in
  SQLite via SeaORM (surviving restarts and allowing central revocation) and the
  cookie signing key is loaded from `KRAKEN_UI_SESSION_KEY` /
  `KRAKEN_UI_SESSION_KEY_FILE`.
- **Re-authentication on password change (M-2):** the change-password form now
  requires and verifies the current password.
- **Hardened `first_time` bootstrap (M-3):** requests carrying proxy forwarding
  headers are rejected, and an optional `KRAKEN_UI_FIRST_TIME_TOKEN` adds a
  shared-secret check on top of the loopback guard.
- **No caching of authenticated pages (M-4):** admin responses now send
  `Cache-Control: no-store`.
- **Blocking `cargo-audit` (L-1):** the advisory job no longer continues on
  error.
- **Authentication audit trail (L-2):** structured `audit`-target log events are
  emitted for login outcomes, logout, the `first_time` bootstrap and operator
  create/update/delete/password-change actions (never including secrets).
- **Explicit WAF trust (L-3):** a warning is logged when `waf-cert-ca` is unset
  and the UI falls back to its own certificate for the metrics channel.
- **Escaped search wildcards (L-4):** `%` and `_` in operator/attack searches are
  escaped and matched literally via `LIKE ... ESCAPE`.

### Changed

- Translated the entire user interface, source comments, documentation and
  changelog from Portuguese to English.
- Renamed the dashboard route from `/kraken_ui/auth/painel_admin` to
  `/kraken_ui/auth/admin_panel`. **Breaking:** update any bookmarks or
  integrations that referenced the old path.

### Removed

- Deleted unused legacy templates (`acl.html`, `dashboard.html`,
  `operators.html` and the `operator_*.html` set) that referenced routes which
  no longer exist.

## 0.3.0 - 2026-06-06

### Added

- A global administrative menu shared by every authenticated template.
- The requested insert, delete, search, edit and change-password endpoints.
- A one-shot public `first_time` bootstrap, limited to loopback addresses.
- An AJAX operators table with 50 records per page and CSRF-protected POST
  actions.
- Read-only access to `vulns_alert.db`, an AJAX attacks table and severity
  sorting.
- A dashboard fed by the KrakenWAF HTTPS metrics and by country, IP and CMC
  aggregations.
- Pie and bar charts rendered as local SVG, with no external JavaScript
  library.

### Changed

- Aligned the password policy to accept medium or strong complexity.

## 0.2.0 - 2026-06-06

### Added

- A SQLite `operators` table with `admin`, `operator` and `auditor` types.
- libsodium-compatible Argon2id password hashing via `dryoc`, wrapped in an
  XChaCha20-Poly1305 envelope with a per-user AAD.
- A cryptographic key loaded from an environment variable or a protected file.
- Automatic hash upgrade after login when the parameters require a rehash.
- Full administrative CRUD for operators, protected by an admin session and
  CSRF.
- The `/kraken_ui/login`, `/kraken_ui/test_login` and
  `/kraken_ui/auth/painel_admin` routes.

### Changed

- The previous `users` model was replaced by the `operators` model.
- Operators and auditors remain without an enabled panel in this version.
- Transitive licence exceptions of the mandatory stack were documented in
  `docs/dependency-licenses.md`.

## 0.1.0 - 2026-06-06

### Added

- A modular Rust application with Axum, Askama and mandatory TLS.
- Loading of the certificate, key, endpoint and SQLite path from
  `conf/setup.yaml`.
- Global hardening headers loaded from `conf/headers_sec.txt`.
- Login with Argon2id, a signed session, secure cookies and `axum_csrf`
  protection.
- Centralised sanitisation with Ammonia and a password policy on both the
  front end and back end.
- SQLite persistence via SeaORM and a secure bootstrap for the first
  administrator.
- Structured JSONL logs at `log/kraken-ui.jsonl`.
- An integrated black-and-orange theme with no CDN or inline JavaScript.
- A SAST/SCA CI pipeline with Clippy, Semgrep, CodeQL, cargo-audit, cargo-deny
  and OSV Scanner.
