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

The default log file is `log/kraken-ui.jsonl`. Use `RUST_LOG` to adjust levels,
but do not enable payload logging in production.
