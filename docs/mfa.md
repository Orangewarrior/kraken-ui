# Two-factor authentication (TOTP)

Kraken UI supports optional, per-operator two-factor authentication using
time-based one-time passwords (TOTP), implemented with the
[`otpauth`](https://crates.io/crates/otpauth) crate. It works with any standard
authenticator app (Google Authenticator, Aegis, 1Password, …) and is available
to both `admin` and `operator` accounts.

Two-factor is **opt-in per account**: each operator enables it for themselves
from the console. There is no global enforcement switch today.

## Storage model

Three pieces of state back the feature:

```sql
-- A flag on the operator, surfaced as the "2MFA" column in the users table.
ALTER TABLE operators ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0;

-- One TOTP secret per operator. `confirmed` is 1 only after the operator has
-- proven possession of the authenticator by entering a valid code.
CREATE TABLE operator_mfa_totp (
    id_totp INTEGER PRIMARY KEY AUTOINCREMENT,
    id_user INTEGER NOT NULL UNIQUE,
    encrypted_secret VARCHAR(1024) NOT NULL,
    confirmed INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL,
    confirmed_at TIMESTAMP,
    FOREIGN KEY (id_user) REFERENCES operators (id_user) ON DELETE CASCADE
);

-- Single-use recovery codes. Each is burned (`used` = 1) the first time it
-- authenticates a login.
CREATE TABLE operator_mfa_recovery_codes (
    id_code INTEGER PRIMARY KEY AUTOINCREMENT,
    id_user INTEGER NOT NULL,
    encrypted_code VARCHAR(1024) NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    FOREIGN KEY (id_user) REFERENCES operators (id_user) ON DELETE CASCADE
);
```

Both the base32 TOTP secret and every recovery code are **sealed at rest** in the
same XChaCha20-Poly1305 envelope used for password hashes
(`PasswordCryptoService::encrypt_secret` / `decrypt_secret`). Each record is bound
to the operator's `id_user` and a purpose-specific AAD domain (`totp` or
`mfa_recovery`), so a sealed record cannot be moved to another account or
reinterpreted as a value of the other kind. Recovery codes use a 32-symbol,
unambiguous alphabet (no `0/O` or `1/I`) and are compared in constant time after
normalising case and separators.

Deleting an operator removes their secret and recovery codes automatically via
`ON DELETE CASCADE`.

## Enabling two-factor (self-service)

From **User status → Two-factor auth** (`/kraken_ui/auth/mfa`):

1. **Enable** starts enrolment: a fresh 160-bit secret is generated, stored
   *unconfirmed*, and shown three ways:
   - as an inline QR code rendered locally by the server,
   - as a base32 secret for manual entry,
   - and as the raw `otpauth://totp/...` provisioning URI.
   Add the account to your authenticator app using any of the three.
2. **Verify and enable** confirms the enrolment by checking a current 6-digit
   code (±1 step of clock skew is tolerated). On success `mfa_enabled` flips to
   `1`, `confirmed` flips to `1`, and **ten single-use recovery codes** are
   minted and shown once. Save them — they are the only way back in if you lose
   your device. The page also offers an optional **Download codes (.txt)** link
   that downloads exactly the codes being shown in that moment.
3. **Regenerate recovery codes** mints a fresh set and invalidates the old one.
4. **Disable** removes the secret and all recovery codes after you re-confirm
   your password.

A mistyped confirmation code re-shows the *same* secret, so you never have to
re-register the account in your app to retry.

If an enrolment is still pending, revisiting `/kraken_ui/auth/mfa` re-shows that
same QR code / secret / URI instead of silently discarding the in-progress setup.

## Signing in with two-factor

When an account has two-factor enabled, the login is two steps:

1. `POST /kraken_ui/login` — on a correct password the server **does not** grant
   a role. It rotates the session id, stores a half-authenticated
   `mfa_pending_user_id` marker (with a timestamp), and redirects to the
   challenge. The pending state expires after five minutes, independently of the
   session idle timeout, so a half-finished login cannot linger.
2. `GET /kraken_ui/auth/mfa_challenge` — the code form, reachable only while the
   pending marker is present and unexpired (otherwise it redirects to the login
   page).
3. `POST /kraken_ui/auth/mfa_verify` — verifies a live TOTP code, or a single-use
   recovery code (which is burned on use). A correct TOTP code is bound to its
   time-step: once a step has authenticated, that code cannot be replayed inside
   its skew window. Only then is the session promoted to fully authenticated (the
   route guards read `authenticated_operator_type`, which stays unset until this
   point). Failures are throttled per source IP and account with the same lockout
   as the password step.

## Routes

All paths are under `/kraken_ui/auth`.

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET  | `/mfa` | operator/admin | Two-factor management page |
| GET  | `/mfa_enroll` | operator/admin | Redirect to `/mfa` (helps stray bookmarks / manual navigation) |
| POST | `/mfa_enroll` | operator/admin | Begin enrolment (generate secret) |
| POST | `/mfa_confirm` | operator/admin | Confirm a code and enable |
| POST | `/mfa_disable` | operator/admin | Disable (re-confirms password) |
| POST | `/mfa_regenerate` | operator/admin | Mint new recovery codes |
| GET  | `/mfa_challenge` | pending login | The sign-in code form |
| POST | `/mfa_verify` | pending login | Verify the code, finish sign-in |

Every mutation uses POST and a CSRF token. The JSON operators endpoint exposes
only the `mfa` on/off state, never the secret or recovery codes.

## Auditing

Two-factor administration is written to `audit.jsonl` under `event = "mfa"`
(`enable`, `disable`, `regenerate_recovery`). The login path logs
`password_ok_mfa_required`, `mfa_failed` and `mfa_locked` outcomes alongside the
existing login events.

## Notes and limitations

- The QR code is rendered locally as an inline SVG data URL. No third-party QR
  service, remote image host or client-side QR generator is involved, so the
  strict Content-Security-Policy and the no-CDN browser posture stay intact.
- The recovery-code download is generated as a one-shot `data:` URL in the page
  that already shows the codes. The server does not persist a separate export
  artifact.
- Throttling state is process-local, like the password throttle; a multi-replica
  deployment should front it with a shared store.
