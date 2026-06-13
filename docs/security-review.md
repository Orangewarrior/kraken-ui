# Security review

A standing review of Kraken UI's security posture. It records what is done
well, the gaps that were found, and how each was addressed. Severities use a
simple High / Medium / Low scale based on exploitability and impact for a
TLS-only, admin-authenticated console.

_Last reviewed: 2026-06-06. All findings below were mitigated in 0.4.0._

## What is already strong

The codebase gets the fundamentals right, and that is worth stating plainly:

- TLS is mandatory; there is no HTTP listener to misconfigure.
- Cookies use the `__Host-` prefix with `Secure`, `HttpOnly` and
  `SameSite=Strict`.
- All mutations are POST and CSRF-protected; the session id is rotated on login
  (`session.cycle_id()`), which defeats session fixation.
- Passwords are Argon2id-hashed and then encrypted in an XChaCha20-Poly1305
  envelope whose AAD is bound to the user id, so a ciphertext cannot be moved
  between accounts.
- SQL is built with SeaORM's expression API (bound parameters), and the WAF
  database is opened strictly read-only.
- A strict CSP forbids inline scripts/styles and requires Trusted Types; the
  header file is validated at start-up and the server refuses to boot if it is
  malformed.
- The dependency surface is locked down with `cargo-deny`, and CI runs Clippy,
  Semgrep, CodeQL, cargo-audit, cargo-deny and OSV Scanner.

## Findings

### H-1 — No rate limiting or lockout on login _(High)_

`POST /kraken_ui/test_login` had no throttling, so Argon2id cost was the only
brake on online password-guessing and credential stuffing.

**Status: Mitigated in 0.4.0.** `security::rate_limit::LoginThrottle` counts
failures per source IP *and* per account; reaching the threshold (5 failures in
5 minutes) locks the key for 15 minutes, and a successful login clears it. A
locked client receives a generic "too many attempts" message.

**Follow-up:** the throttle is process-local. For a multi-replica deployment,
back it with a shared store.

### H-2 — Username enumeration via login timing _(High)_

A missing username returned immediately, whereas an existing one triggered a
full Argon2id verification — a measurable timing oracle.

**Status: Mitigated in 0.4.0.** When the username is not found, the handler now
runs `PasswordCryptoService::run_dummy_verification`, a real Argon2id
verification against a precomputed throwaway record, so both paths take
comparable time before returning the generic "Invalid credentials" response.

### M-1 — In-memory session store and per-restart signing key _(Medium)_

`MemoryStore` plus `Key::generate()` meant sessions were lost on restart, could
not be shared across replicas, and could not be revoked centrally.

**Status: Mitigated in 0.4.0.** Sessions are now persisted by
`models::session_store::SeaOrmSessionStore` (SQLite via SeaORM, with expiry
filtering), so they survive restarts and a row can be deleted to revoke a
session. The cookie signing key is loaded from `KRAKEN_UI_SESSION_KEY` or
`KRAKEN_UI_SESSION_KEY_FILE` (Base64, ≥ 64 bytes); if none is set an ephemeral
key is generated with a clear warning for development only.

### M-2 — No re-authentication before changing a password _(Medium)_

`update_password_action` did not require the current password, so a hijacked
session could lock out the owner.

**Status: Mitigated in 0.4.0.** The change-password form now has a current
password field, which is verified against the stored record before the new
password is accepted.

### M-3 — `first_time` trust depends on the peer socket address _(Medium)_

Behind a reverse proxy that forwards to loopback, every request looked local,
bypassing the loopback guard while the operators table was empty.

**Status: Mitigated in 0.4.0.** `first_time` now rejects any request carrying
proxy forwarding headers (`X-Forwarded-For`, `Forwarded`, `X-Real-IP`,
`X-Forwarded-Host`), and an optional `KRAKEN_UI_FIRST_TIME_TOKEN` adds a
constant-time shared-secret check on top of the loopback requirement. The
existing `count() > 0` guard still closes the endpoint after first use.

### M-4 — Authenticated pages are cacheable _(Medium)_

Admin pages (operators, attack data) could be stored by the browser or shared
caches.

**Status: Mitigated in 0.4.0.** The `require_admin` middleware now sets
`Cache-Control: no-store` on every authenticated response.

### L-1 — `cargo-audit` is non-blocking in CI _(Low)_

The job used `continue-on-error: true`, so a new advisory did not fail the
pipeline.

**Status: Mitigated in 0.4.0.** `continue-on-error` was removed; `cargo audit`
now blocks, alongside `cargo-deny check advisories`.

### L-2 — Limited authentication audit trail _(Low)_

Only crypto-service errors were logged, with no queryable record of normal
authentication or administrative events.

**Status: Mitigated in 0.4.0.** Structured events are emitted on the `audit`
tracing target for login outcomes (success, bad password, unknown user, locked,
invalid input, crypto error, non-admin), logout, the `first_time` bootstrap and
operator create/update/delete/password-change. No secrets are included.

### L-3 — `waf-cert-ca` falls back to the server certificate _(Low)_

When `waf-cert-ca` was unset, the metrics client silently trusted the UI's own
`cert-ca`, which is a confusing failure mode if the WAF presents a different CA.

**Status: Mitigated in 0.4.0.** A warning is now logged at start-up when the
fallback is used, and the behaviour is documented in `docs/operations.md`.

### L-4 — `LIKE` wildcards in search are not escaped _(Low)_

`SeaORM::contains` interpolated user-supplied `%` and `_` into the pattern, so a
search term could act as a wildcard (not injection, but surprising).

**Status: Mitigated in 0.4.0.** Both repositories now build the pattern with
`security::sanitize::escape_like` and a `LIKE ... ESCAPE '\'` clause, so
metacharacters are matched literally.

## Hardening added in 0.5.0

A second pass addressed the deeper findings raised after the 0.4.0 review:

- **WAF metrics channel pinned.** The metrics client trusts only the configured
  `waf-cert-ca`, not the system root store.
- **Account-lockout DoS removed.** The per-account failure counter is now keyed
  by IP *and* account, so a victim cannot be locked out from unrelated
  addresses.
- **Credential-validity oracle closed.** A valid non-admin login returns the
  same generic response as a failed one.
- **Pagination offset bounded** to stop hostile `start` values forcing large
  scans.
- **SQLite hardened**: WAL, `busy_timeout`, `synchronous=NORMAL`,
  `foreign_keys`, and garbage collection of expired session rows.
- **Dedicated audit log** (`audit.jsonl`) separate from the application log.
- **Global per-IP request rate limiter** as defence in depth.
- **Passwords wrapped in `Zeroizing`** on the verification and hashing paths.

## Hardening added in 0.11.0

A further pass after the 0.10.x two-factor work:

- **TOTP replay window closed.** A verified code's time-step is recorded in
  `operator_mfa_totp.last_used_step`; a code is accepted only when its step is
  strictly greater, so the same code cannot be reused inside its ±1-step skew
  window (RFC 6238 §5.2).
- **Bounded password-hashing concurrency.** Argon2id work runs under a semaphore
  sized to the available parallelism, so a burst of logins — each `*_MODERATE`
  hash transiently needs ~256 MiB, including the unknown-user dummy path — can no
  longer exhaust host memory.
- **Short two-factor challenge window.** The half-authenticated "password OK,
  awaiting code" state expires after five minutes, independently of the longer
  session idle timeout.
- **Distributed-guessing detection.** `AccountFailureMonitor` emits an audit
  alert when one account draws failures from many source IPs — visibility the
  per-IP throttle (kept per-IP on purpose) cannot provide. It never locks.
- **Session signing key fails closed.** Release builds refuse to start without
  `KRAKEN_UI_SESSION_KEY` / `_FILE` unless `KRAKEN_UI_ALLOW_EPHEMERAL_SESSION_KEY`
  is set, matching the password-key behaviour.
- **`#![forbid(unsafe_code)]`** is now enforced crate-wide.
- **Docs corrected.** The detail-view payload is HTML-escaped, not Ammonia-
  stripped; the README and architecture docs were brought in line with the code.
- **Dead code removed.** The vestigial `black_n_orange_theme` mock-up (which
  included an `innerHTML`-based script) and a legacy front-end module were
  deleted.
- **CI / supply chain.** Least-privilege workflow permissions, `persist-credentials:
  false` on checkouts, a concurrency guard, Semgrep promoted to a blocking gate,
  and Dependabot for GitHub Actions and Cargo.

## Hardening added in 0.15.0

A refactoring and AppSec pass focused on configuration safety and removing
expensive work from request hot paths:

- **Database keys disambiguated.** The UI credential store and the read-only WAF
  alerts database were configured by `db-local` and `db_local`, one underscore
  apart. They are now `db-ui` and `db-waf-alerts` (the old names remain as
  deprecated aliases), the load step validates that they reference different
  files, and the stray legacy `conf/setup.conf` was removed.
- **`first_time` token mandatory in release.** The bootstrap endpoint now fails
  closed without `KRAKEN_UI_FIRST_TIME_TOKEN` in release builds, matching the
  session-signing-key policy; debug builds keep it optional.
- **Secret-file permissions enforced consistently.** An explicitly configured
  `*_FILE` secret (e.g. `BEARER_PASSWORD_FILE`) is refused when it is readable by
  group or others, rather than only the encryption and session keys; the
  conventional `/run/secrets/krakenwaf` mount warns instead, so platform-managed
  secrets are not broken.
- **HTML parsing removed from hot paths.** CSRF token validation and numeric
  pagination parameters no longer run the Ammonia HTML sanitiser on every request;
  a constant-cost character-class check and direct integer parsing replace it,
  with the cryptographic CSRF check unchanged.
- **TOTP verification documented and ordered current-first.** The skew window is
  now tried current-step-first, and the interaction between recording a used step
  and the ±1 skew window is documented.
- **End-to-end auth test.** A new integration test drives the full login → CSRF →
  session → protected page → logout round trip over the assembled router.
- **Dead code removed.** Unused `AppError` constructors and `AppConfig::session_timeout`
  were deleted; the `listen` address is now validated at load time; and the
  duplicated constant-time comparison and CSRF render helpers were unified.

## Remaining follow-ups

Intentionally out of scope, tracked for later:

- Back the login throttle and the request rate limiter (and optionally sessions)
  with a shared store for multi-replica deployments; today they are
  process-local.
- Add an explicit trusted-proxy mode so the per-IP controls and the audited
  client IP work correctly behind a load balancer; today they require direct TLS
  termination.
- Consider TLS 1.3-only and/or mutual TLS for the console. The current rustls
  defaults (TLS 1.2+1.3 with strong cipher suites) are already safe, so this is
  a deployment-policy choice rather than a fix.
- Consider a CSP `report-to` endpoint to collect violation reports (needs a
  collector to be useful).
- The markup check on secrets (`secret_has_rejected_markup`) is kept as a
  deliberate defensive control; passwords are hashed and never reflected, so it
  is not a vulnerability, only a small reduction of the password character set.
