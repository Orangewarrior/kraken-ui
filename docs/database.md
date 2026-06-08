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
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);
```

Beyond the unique email that was requested, `username` is unique too, which
makes authentication deterministic.

## Sessions

Sessions are persisted by `SeaOrmSessionStore` in the same SQLite database:

```sql
CREATE TABLE kraken_sessions (
    id TEXT PRIMARY KEY NOT NULL,
    record TEXT NOT NULL,      -- the serialised session record (JSON)
    expiry_utc INTEGER NOT NULL
);
```

Records past their `expiry_utc` are ignored on load and pruned whenever a new
session is created, so the table stays bounded. Deleting a row immediately
revokes that session.

## Public routes

- `GET /kraken_ui/login` — the login form.
- `POST /kraken_ui/test_login` — validates CSRF, looks up the operator, calls
  the crypto service and creates a session for `admin` accounts only.
- `POST /kraken_ui/auth/first_time` — one-shot administrator bootstrap, limited
  to loopback clients and closed once any operator exists.
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

### Administrator or operator (`require_operator`)

The day-to-day console. For operators the sidebar drops the ACL section; the
pages themselves are identical.

| Method | Path | Purpose |
|--------|------|---------|
| GET  | `/admin_panel`, `/dashboard` | Dashboard view |
| GET  | `/api/dashboard` | Dashboard JSON metrics |
| GET  | `/show_attacks` | Observed-attacks table |
| GET  | `/api/attacks` | Attacks JSON (paginated) |
| GET  | `/update_password` | Change-password form |
| POST | `/update_password_action` | Change the current operator's password |
| POST | `/logout` | Destroy the session |

### Administrator, operator or auditor (`require_attack_viewer`)

| Method | Path | Purpose |
|--------|------|---------|
| GET  | `/view_waf_request/?id=<id>` | Single WAF finding detail (new tab) |

Only `admin` and `operator` accounts can sign in today; the auditor role is
accepted by the detail-view middleware for forward compatibility.

Every mutation uses POST and a CSRF token. The JSON endpoints never return
`encrypted_password_hash`.

## The KrakenWAF database

`db_local` points at `vulns_alert.db`. The UI opens this file **read-only** and
queries `vulnerabilities` with parameterised filters for date, severity, IP,
country and title — it can read the WAF's findings but never write to them.
