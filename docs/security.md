# Security

This document describes the controls Kraken UI relies on and the reasoning
behind them. For a running list of known gaps and proposed improvements, see
[security-review.md](security-review.md).

## Controls

- **TLS is mandatory.** The process serves HTTPS only — there is no HTTP
  option to misconfigure.
- **Hardened cookies.** Session and CSRF cookies use `Secure`, `HttpOnly`,
  `SameSite=Strict`, a `/` path and the `__Host-` prefix.
- **CSRF on every mutation.** Login, logout and all state-changing requests use
  POST with a CSRF token.
- **Strong password storage.** Passwords are hashed with `dryoc` using the
  libsodium-compatible Argon2id "moderate" profile, then encrypted. They are
  never logged.
- **Input sanitisation.** Free-text input passes through Ammonia. Secrets are
  *rejected* if the sanitiser would alter them, rather than being silently
  modified — so a password is never quietly changed under the user's feet.
- **A strict CSP.** Inline scripts and styles are forbidden. The local
  JavaScript never uses `innerHTML`, which keeps it compatible with Trusted
  Types.
- **Login throttling.** Failed logins are rate-limited per source IP and per
  account; reaching the threshold locks the key for a cool-off period. Unknown
  usernames trigger a dummy verification so login timing does not reveal whether
  an account exists.
- **Persistent, revocable sessions.** Sessions are stored in SQLite and signed
  with a stable key (see *Keys*), so they survive restarts and can be revoked by
  deleting the row.
- **Role-based access control.** Every authenticated route sits behind one of
  three middleware guards keyed on the session's operator type: `require_admin`
  (ACL management), `require_operator` (admin or operator console) and
  `require_attack_viewer` (admin, operator or auditor — the read-only attack
  detail view). A session lacking the required role is redirected to the login
  page, never shown the resource. Sign-in itself is restricted to roles that can
  use the console: a valid login by a role that cannot (e.g. `auditor`) returns
  the same generic failure as a wrong password, so it is not a credential oracle.
- **Untrusted WAF payloads are neutralised before display.** The single-attack
  detail view passes the attacker-controlled `request_payload` through Ammonia
  before rendering it, and the client-side syntax highlighter builds DOM nodes
  only (never `innerHTML`), so it cannot reintroduce active markup under the
  strict CSP / Trusted Types.
- **No caching of authenticated pages.** Authenticated responses send
  `Cache-Control: no-store`.
- **Audit trail.** Structured events on the `audit` tracing target record login
  outcomes, logout, the `first_time` bootstrap and operator administration —
  never including secrets.
- **Privacy-preserving logs.** Logs are JSONL, and events never include a
  password, hash, CSRF token or session contents.

## Licence policy

Direct dependencies must offer MIT, BSD-2-Clause or BSD-3-Clause. The
transitive tree cannot be satisfied with only those three, because:

- Ammonia depends on MPL-2.0 components.
- Axum depends on the Apache-2.0 `sync_wrapper`.
- Rustls and SQLite (via SeaORM) pull in ISC, Apache-2.0, Unicode-3.0 and
  CDLA-Permissive components.

These permissive and weak-copyleft exceptions are listed explicitly in
`deny.toml`. `cargo-deny` fails on any new licence outside that list, which
prevents the policy from quietly expanding over time.

## Bootstrapping the first administrator

If no administrator exists, the application reads `KRAKEN_UI_ADMIN_PASSWORD`
and `KRAKEN_UI_ADMIN_EMAIL`. The password must be at least 14 characters and
include upper- and lower-case letters, a number and a symbol, with no spaces
and without containing the username.

Alternatively, the one-shot `first_time` endpoint accepts a single loopback POST
while the operators table is empty. It rejects requests that carry proxy
forwarding headers, and when `KRAKEN_UI_FIRST_TIME_TOKEN` is set it additionally
requires that token (sent as a `token` form field, compared in constant time).

## The password envelope

The value stored in `encrypted_password_hash` is:

```text
base64(key_id[16] || nonce[24] || xchacha20poly1305_ciphertext)
```

The encrypted plaintext is the complete record returned by `crypto_pwhash_str`,
including the salt and parameters. The AAD (additional authenticated data) is:

```text
kraken_ui:v1:user:<id_user>:password_hash
```

Binding the AAD to the user id means a ciphertext copied from one operator to
another will fail authentication. At login the service decrypts the envelope,
runs `crypto_pwhash_str_verify`, and compares the stored Argon2id parameters
against the current "moderate" policy. If they are out of date, it transparently
generates and persists a fresh envelope.

## Keys

- `KRAKEN_UI_PASSWORD_KEY` — a 32-byte key, Base64-encoded.
- `KRAKEN_UI_PASSWORD_KEY_FILE` — a file containing the Base64 key. On Unix it
  must not be readable by group or others.
- `KRAKEN_UI_PASSWORD_KEY_ID` — an ASCII identifier of up to 16 bytes
  (default `primary-v1`).

The application will not start without a password key source. The key never
reaches the database, templates, sessions or logs.

### Session signing key

- `KRAKEN_UI_SESSION_KEY` — a Base64 key of at least 64 bytes used to sign
  session cookies.
- `KRAKEN_UI_SESSION_KEY_FILE` — a file containing that Base64 key; on Unix it
  must not be readable by group or others.

Generate one with `openssl rand -base64 64`. If neither is set, an ephemeral key
is generated and a warning is logged — acceptable for development only, since
sessions would then not survive a restart or work across replicas.
