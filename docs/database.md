# Database and ACL

## Schema

```sql
CREATE TABLE operators (
    id_user INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(32) NOT NULL UNIQUE,
    email VARCHAR(128) NOT NULL UNIQUE,
    type VARCHAR(32) NOT NULL
        CHECK (type IN ('admin', 'operator', 'auditor')),
    encrypted_password_hash VARCHAR(1024) NOT NULL,
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);
```

Beyond the unique email that was requested, `username` is unique too, which
makes authentication deterministic. `mfa_enabled` is the two-factor flag (0/1)
surfaced as the **2MFA** column in the users table; see
[Two-factor authentication](mfa.md).

All `created_at` / `updated_at` columns (and the MFA tables' `confirmed_at` /
`used_at`) are stored as fixed-width UTC text, `YYYY-MM-DD HH:MM:SS`, written by
`models::current_timestamp`.

## Two-factor authentication tables

```sql
CREATE TABLE operator_mfa_totp (
    id_totp INTEGER PRIMARY KEY AUTOINCREMENT,
    id_user INTEGER NOT NULL UNIQUE,
    encrypted_secret VARCHAR(1024) NOT NULL,
    confirmed INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL,
    confirmed_at TIMESTAMP,
    last_used_step INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (id_user) REFERENCES operators (id_user) ON DELETE CASCADE
);

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

The TOTP secret and recovery codes are sealed at rest in the password-crypto
envelope (bound to the user id and a purpose AAD). `last_used_step` records the
highest TOTP time-step that has already authenticated the account, so a code
cannot be replayed inside its validity window. Full details — the enrolment,
sign-in challenge and recovery flows — are in [docs/mfa.md](mfa.md).

## Sessions

Sessions are persisted by `SeaOrmSessionStore` in the same SQLite database:

```sql
CREATE TABLE kraken_sessions (
    id TEXT PRIMARY KEY NOT NULL,
    record TEXT NOT NULL,      -- the serialised session record (JSON)
    expiry_utc INTEGER NOT NULL,
    user_id INTEGER NOT NULL DEFAULT 0   -- mirrors the signed-in operator
);
```

Records past their `expiry_utc` are ignored on load and pruned whenever a new
session is created, so the table stays bounded. Deleting a row immediately
revokes that session, and the indexed `user_id` column lets every session for
one operator be revoked at once — on delete, role change or password change.

## Public routes

- `GET /kraken_ui/login` — the login form.
- `POST /kraken_ui/login` — validates CSRF, looks up the operator, calls the
  crypto service and creates a session (or, when two-factor is enabled, a
  half-authenticated challenge) for `admin` and `operator` accounts.
- `POST /kraken_ui/auth/first_time` — one-shot administrator bootstrap, limited
  to loopback clients and closed once any operator exists.
- `GET /kraken_ui/auth/mfa_challenge` — the two-factor code form, reachable only
  while a half-authenticated session marker is present.
- `POST /kraken_ui/auth/mfa_verify` — verifies the TOTP (or recovery) code and
  completes a two-factor sign-in.
- `GET /health` — liveness check.

## Authenticated routes

All of these are served under `/kraken_ui/auth`. Authorization is enforced by
three role-aware middleware layers.

### Administrator only (`require_admin`)

The full ACL management surface.

| Method | Path | Purpose |
|--------|------|---------|
| GET  | `/insert_user` | Add-user form |
| POST | `/insert_user_action` | Create an operator |
| GET  | `/delete_user` | Remove-user form |
| POST | `/delete_user_action` | Delete an operator |
| GET / POST | `/edit_user` | Find an operator to edit |
| POST | `/update_user_action` | Update an operator |
| GET  | `/show_user_table` | Operators table |
| GET  | `/api/operators` | Operators JSON (paginated) |
| GET  | `/update_kraken_ui` | Stable source update page |
| POST | `/update_kraken_ui/start` | Start a source update |
| GET  | `/api/update_kraken_ui` | Read update status |

### Administrator or operator (`require_operator`)

Rule management. Not available to auditors, whose remit is read-only.

| Method | Path | Purpose |
|--------|------|---------|
| GET  | `/rule_management/cmc` | CMC detection-module toggles |
| GET  | `/api/rule_management/cmc` | CMC modules JSON |
| POST | `/rule_management/cmc/update` | Apply a CMC toggle |
| GET  | `/rule_management/regex` | Regex rule-list picker |
| GET  | `/rule_management/regex/edit` | Regex rule editor |
| POST | `/rule_management/regex/update` | Push an edited regex rule |

### Administrator, operator or auditor (`require_console_viewer`)

The read-only console surface. For operators the sidebar drops the ACL and
Updates sections; for auditors it additionally drops Rule management. The pages
themselves are identical, except that the single-attack detail view masks secret
parameter values for everyone but an administrator.

| Method | Path | Purpose |
|--------|------|---------|
| GET  | `/admin_panel`, `/dashboard` | Dashboard view |
| GET  | `/api/dashboard` | Dashboard JSON metrics |
| GET  | `/show_attacks` | Observed-attacks table |
| GET  | `/api/attacks` | Attacks JSON (paginated) |
| GET  | `/view_waf_request/?id=<id>` | Single WAF finding detail (new tab) |
| GET  | `/update_password` | Change-password form |
| POST | `/update_password_action` | Change the current operator's password |
| GET  | `/mfa` | Two-factor management page |
| POST | `/mfa_enroll` | Begin two-factor enrolment |
| POST | `/mfa_confirm` | Confirm a code and enable two-factor |
| POST | `/mfa_disable` | Disable two-factor (re-confirms password) |
| POST | `/mfa_regenerate` | Mint new recovery codes |
| POST | `/logout` | Destroy the session |

All three roles — `admin`, `operator` and `auditor` — can sign in. The auditor is
a read-only role: dashboard, attacks monitor and its own account settings only.

Every mutation uses POST and a CSRF token. The JSON endpoints never return
`encrypted_password_hash`.

## The KrakenWAF database

`db-waf-alerts` (deprecated alias `db_local`) points at `vulns_alert.db`. The UI opens this file **read-only** and
queries `vulnerabilities` with parameterised filters for date, severity, IP,
country and title — it can read the WAF's findings but never write to them.
