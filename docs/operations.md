# Operations

A practical guide to configuring and running Kraken UI.

## Configuration

`conf/setup.yaml` accepts the following keys:

| Key | Meaning |
|-----|---------|
| `cert-ca` | The PEM certificate or chain the server presents. |
| `key` | The matching PEM private key. |
| `listen` | The HTTPS address and port to bind. |
| `db-local` | The UI's own SQLite database. |
| `db_local` | The KrakenWAF alerts database (opened read-only). |
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
| `KRAKEN_UI_SESSION_KEY` / `KRAKEN_UI_SESSION_KEY_FILE` | The ≥ 64-byte (Base64) cookie signing key. Strongly recommended in production; an ephemeral key is used if unset. |
| `KRAKEN_UI_ADMIN_PASSWORD` / `KRAKEN_UI_ADMIN_EMAIL` | Bootstrap the first administrator at start-up. |
| `KRAKEN_UI_FIRST_TIME_TOKEN` | Optional shared secret required by the `first_time` endpoint, in addition to the loopback check. |
| `RUST_LOG` | Log level filter. |

Key files referenced by `*_KEY_FILE` must not be readable by group or others on
Unix, or the application refuses to start.

## WAF metrics trust

The metrics client connects to `waf-endpoint` over HTTPS. Set `waf-cert-ca` to
the CA the WAF presents. If it is left unset, the UI falls back to its own
`cert-ca` and logs a warning at start-up; this only works if both services share
a CA, so prefer setting it explicitly.

## Database

The default path is `db/kraken-ui.sqlite`. The `operators` table is created
automatically on first start. See [database.md](database.md) for the schema and
the full route list.

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

Two limiters protect the service, both process-local:

- A login throttle locks a source IP (and IP+account) after repeated failures.
- A global per-IP request rate limiter (a generous token bucket) caps overall
  request volume as defence in depth and returns `429 Too Many Requests` when
  exceeded.

For a multi-replica deployment these should be backed by a shared store.
