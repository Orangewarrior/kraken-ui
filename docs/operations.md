# Operations

A practical guide to configuring and running Kraken UI.

## Configuration

`conf/setup.yaml` accepts the following keys:

| Key | Meaning |
|-----|---------|
| `cert-ca` | The PEM certificate or chain the server presents. |
| `key` | The matching PEM private key. |
| `listen` | The HTTPS address and port to bind. |
| `db-ui` | The UI's own SQLite database (read-write). Deprecated alias: `db-local`. |
| `db-waf-alerts` | The KrakenWAF alerts database (opened read-only). Deprecated alias: `db_local`. |
| `waf-endpoint` | The KrakenWAF HTTPS metrics endpoint. |
| `waf-cert-ca` | The PEM to trust when the WAF presents its own certificate. |
| `log-dir` | The directory for the JSONL logs. |
| `session-timeout-minutes` | Idle expiry, between 5 and 1440 minutes. |

Relative paths are resolved from the working directory the process is started
in.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `KRAKEN_UI_PASSWORD_KEY` / `KRAKEN_UI_PASSWORD_KEY_FILE` | The 32-byte (Base64) key that encrypts password hashes. Required. |
| `KRAKEN_UI_PASSWORD_KEY_ID` | Key identifier, default `primary-v1`. |
| `KRAKEN_UI_SESSION_KEY` / `KRAKEN_UI_SESSION_KEY_FILE` | The ≥ 64-byte (Base64) cookie signing key. **Required in release builds**: the server refuses to start without it (or the opt-in below). |
| `KRAKEN_UI_ALLOW_EPHEMERAL_SESSION_KEY` | Allows a generated ephemeral signing key in a release build (development only; debug builds always allow it). Sessions then do not survive a restart. |
| `KRAKEN_UI_ADMIN_PASSWORD` / `KRAKEN_UI_ADMIN_EMAIL` | Bootstrap the first administrator at start-up. |
| `KRAKEN_UI_FIRST_TIME_TOKEN` | Optional shared secret required by the `first_time` endpoint, in addition to the loopback check. |
| `KRAKEN_UI_SOURCE_DIR` | Source checkout updated by the admin-only updater. Defaults to the process working directory. |
| `BEARER_PASSWORD_FILE` / `BEARER_PASSWORD` | KrakenWAF observability bearer token. Uses the same names and resolution order as KrakenWAF. |
| `RUST_LOG` | Log level filter. |

Key files referenced by `*_KEY_FILE` must not be readable by group or others on
Unix, or the application refuses to start.

## WAF metrics trust

The metrics client connects to the dedicated KrakenWAF observability listener,
which defaults to `https://127.0.0.1:4343`. Set `waf-cert-ca` to the CA the WAF
presents. If it is left unset, the UI falls back to its own `cert-ca` and logs a
warning at start-up; this only works if both services share a CA, so prefer
setting it explicitly.

Every metrics request carries `Authorization: Bearer <token>` when
`BEARER_PASSWORD` is available. The token is resolved with the exact same
file-first chain used by KrakenWAF:

1. `BEARER_PASSWORD_FILE`
2. `/run/secrets/krakenwaf/BEARER_PASSWORD`
3. `BEARER_PASSWORD`

File contents are trimmed. Empty or unreadable files fall through to the next
source. The token is marked sensitive in the HTTP client and is never logged.
When no token is configured, Kraken UI starts with a warning and sends metrics
requests without the header for compatibility with a KrakenWAF instance whose
bearer gate is disabled.

For systemd, both services can load the same root-owned source file into their
own private credential directories:

```ini
[Service]
LoadCredential=BEARER_PASSWORD:/etc/krakenwaf/secrets/BEARER_PASSWORD
Environment=BEARER_PASSWORD_FILE=%d/BEARER_PASSWORD
```

See [`../deploy/systemd/kraken-ui-bearer.conf`](../deploy/systemd/kraken-ui-bearer.conf)
for a ready-to-install drop-in. The complete integration guide, including
development commands and `401`/`403` diagnosis, is in
[waf-bearer-auth.md](waf-bearer-auth.md).

## Database

The default path is `db/kraken-ui.sqlite`. The `operators` table is created
automatically on first start. See [database.md](database.md) for the schema and
the full route list.

## Source updater

Version `0.13.0` adds an administrator-only update page. It requires outbound
GitHub HTTPS access, `cargo`, a writable source checkout and permission to
replace the running executable. Existing databases, `conf/`, certificates,
logs, YAML files and `.conf` files are preserved. Unsigned in-application
source updates are disabled unless `KRAKEN_UI_ALLOW_UNSIGNED_SOURCE_UPDATE=1`
is set after an external release-provenance decision. See
[source-updates.md](source-updates.md) for the complete trust model, update
sequence and recovery procedure.

## Security headers

Each line of `conf/headers_sec.txt` uses the `Name: value` format. The file is
validated at start-up, and a single invalid line stops the server from
starting — this is deliberate, so the application can never run without its
hardening headers in place.

## Logs

Two JSONL logs are written to `log-dir`:

- `kraken-ui.jsonl` — the application log, governed by `RUST_LOG`.
- `audit.jsonl` — a dedicated security audit trail of login outcomes, logout,
  the `first_time` bootstrap and operator administration. It never contains
  secrets and is written regardless of `RUST_LOG`.

Do not enable payload logging in production.

## Rate limiting

Four controls protect the service:

- A login throttle locks a source IP (and IP+account) after repeated failures.
- A persistent login/MFA limiter shares authentication pressure across replicas
  through the configured SQLite or Redis rate-limit backend.
- A global per-IP request rate limiter (a generous token bucket) caps overall
  request volume as defence in depth and returns `429 Too Many Requests` when
  exceeded.
- An account-failure monitor raises a single `account_guessing_suspected` audit
  event when one account accumulates many failures across different IPs. It is
  detection only and never locks an account.

By default, all per-IP controls key on the **direct socket peer address**.
When Kraken UI sits behind a reverse proxy, set `trusted-proxy-ips` to the exact
proxy addresses that may supply `Forwarded`, `X-Forwarded-For` or `X-Real-IP`.
Never include broad or unspecified addresses.
