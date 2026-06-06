# Changelog

All notable changes to this project are recorded in this file.

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
