# Security review

A standing review of Kraken UI's security posture. It records what is done
well, the gaps that remain, and concrete remediation for each. Severities use a
simple High / Medium / Low scale based on exploitability and impact for a
TLS-only, admin-authenticated console.

_Last reviewed: 2026-06-06._

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

`POST /kraken_ui/test_login` has no throttling, lockout or backoff. Argon2id
("moderate") raises the cost per attempt, but a determined attacker can still
mount online password-guessing or credential-stuffing attacks. The login page
itself already warns that rate limiting is a prerequisite for production.

**Remediation:** add per-IP and per-account rate limiting (for example a
`tower_governor` layer), plus temporary lockout / exponential backoff after
repeated failures. Record failed attempts in the audit log (see L-2).

### H-2 — Username enumeration via login timing _(High)_

In `controllers/auth.rs`, when the username is not found the handler returns
immediately, whereas an existing username triggers a full Argon2id verification.
The measurable timing difference lets an attacker enumerate valid usernames.

**Remediation:** when the user is not found, verify the supplied password
against a fixed dummy Argon2id record so both paths take comparable time, then
return the generic "Invalid credentials" response.

### M-1 — In-memory session store and per-restart signing key _(Medium)_

`app.rs` uses `MemoryStore::default()` and `Key::generate()`. Sessions live only
in process memory and the signing key is regenerated on every start. This is
fine for a single dev instance but is a problem in production: sessions cannot
be shared across replicas or survive a restart, and there is no central place
to revoke a session.

**Remediation:** for production, back sessions with a shared, persistent store
and load a stable signing key from the existing key-management mechanism
(env var or `0600` file) rather than generating one at boot.

### M-2 — No re-authentication before changing a password _(Medium)_

`update_password_action` correctly restricts a user to their own account, but it
does not require the current password. If a session is hijacked (for example via
a stolen cookie), the attacker can set a new password and lock out the owner.

**Remediation:** require and verify the current password before accepting a new
one.

### M-3 — `first_time` trust depends on the peer socket address _(Medium)_

The bootstrap endpoint authorises callers solely by `ConnectInfo<SocketAddr>`
being a loopback address. Behind a reverse proxy that terminates TLS and
forwards to `127.0.0.1`, every request appears to originate from loopback, so
the loopback guard is bypassed for as long as the operators table is empty.

**Remediation:** document that the first administrator must be created *before*
the service is exposed through any proxy; or gate `first_time` behind a
one-time secret in addition to the loopback check. The existing `count() > 0`
guard limits the window but does not eliminate it.

### M-4 — Authenticated pages are cacheable _(Medium)_

Neither `conf/headers_sec.txt` nor the responses set `Cache-Control: no-store`.
Sensitive admin pages (the operators table, attack data) may be cached by the
browser or shared caches.

**Remediation:** add `Cache-Control: no-store` (and `Pragma: no-cache`) to
authenticated responses, or globally in the header middleware.

### L-1 — `cargo-audit` is non-blocking in CI _(Low)_

The `cargo-audit` job sets `continue-on-error: true`, so a new advisory will not
fail the pipeline. Advisory coverage is largely preserved because
`cargo-deny check advisories` *does* block, but the redundancy is misleading.

**Remediation:** either make `cargo-audit` blocking, or drop it and rely on
`cargo-deny` for advisories to avoid a false sense of coverage.

### L-2 — Limited authentication audit trail _(Low)_

Failed logins are only logged (`warn`) when the crypto service itself errors,
not on an ordinary wrong password. There is no structured, queryable record of
authentication successes and failures.

**Remediation:** emit structured audit events for login success/failure, logout
and operator CRUD (never including secrets), which also feeds H-1's lockout
logic.

### L-3 — `waf-cert-ca` falls back to the server certificate _(Low)_

When `waf-cert-ca` is unset, `config.waf_certificate_path()` falls back to the
UI's own `cert-ca`. If the WAF presents a different CA, the metrics client will
fail to connect — a confusing failure mode rather than a vulnerability.

**Remediation:** make `waf-cert-ca` explicit (or clearly document the fallback)
so trust for the metrics channel is always intentional.

### L-4 — `LIKE` wildcards in search are not escaped _(Low)_

The operators/attacks search uses SeaORM's `contains`, so user-supplied `%` and
`_` act as wildcards. This is not SQL injection (values are bound), but it lets
a user broaden a search unexpectedly.

**Remediation:** escape `%` and `_` in the search term if exact substring
matching is intended.

## Suggested priority

1. **H-1** and **H-2** — they directly affect the authentication boundary and
   are the highest-value hardening for an internet-reachable console.
2. **M-1** and **M-2** — important before any multi-instance or
   higher-assurance deployment.
3. **M-3**, **M-4** and the Low-severity items as follow-ups.
