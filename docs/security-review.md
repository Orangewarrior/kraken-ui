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

## Remaining follow-ups

These are intentionally out of scope for 0.4.0 and tracked for later:

- Back the login throttle (H-1) and, optionally, sessions with a shared store
  for multi-replica deployments.
- Periodically prune expired rows from the `kraken_sessions` table (expired rows
  are already ignored on load, but not yet garbage-collected).
- Consider a CSP `report-to` endpoint to collect violation reports.
