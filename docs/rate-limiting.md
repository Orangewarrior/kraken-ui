# Rate limiting

Kraken UI 0.14.0 applies rate limiting before sessions, CSRF processing and
route handlers. Runtime settings are loaded from `conf/ratelimit.yaml`; changing
that file and restarting the service changes the active limits.

## Request controls

| Field | Default | Runtime effect |
|---|---:|---|
| `enabled` | `true` | Enables all global request controls. |
| `requests_per_second` | `5` | Sustained GCRA rate per client IP. |
| `burst_size` | `300` | Maximum initial GCRA burst per client IP. |
| `max_coroutines_per_ip` | `32` | Maximum simultaneously executing requests per IP. Excess requests receive `429`; they are not queued. |
| `tls_handshake_timeout_secs` | `10` | Maximum time allowed for the TLS handshake. |
| `connection_timeout_secs` | `30` | Maximum lifetime of an accepted HTTP request after TLS. |
| `max_tracked_ips` | `10000` | Bounds axum-governor's process-local IP tracker. |
| `backend` | `sqlite` | Persistent backend: `sqlite` or `redis`. |
| `fail_open` | `false` | When `false`, backend errors reject requests. |

The local direct-peer layer is
[`axum-governor`](https://docs.rs/axum-governor/) using governor's GCRA
algorithm. A second GCRA decision is persisted in SQLite or Redis. This keeps a
restart from immediately resetting every allowance and lets Redis coordinate
multiple Kraken UI replicas.

`Retry-After` is returned with persistent and concurrency `429` responses.
Kraken UI uses the TCP peer address installed by Axum `ConnectInfo` by default.
If `trusted-proxy-ips` is set in `conf/setup.yaml`, forwarding headers
(`Forwarded`, `X-Forwarded-For`, `X-Real-IP`) are trusted only when the direct
peer matches one of those exact proxy IPs. Leave it empty for direct TLS
exposure. In trusted-proxy mode the direct-peer `axum-governor` layer is skipped
to avoid collapsing every client onto the proxy IP; the persistent limiter and
the concurrency limiter continue to use the effective forwarded client IP.

Login and MFA attempts also use a stricter persistent GCRA limiter
(1 request/second with a burst of 5) on the same SQLite or Redis backend, while
the existing process-local failure throttle still handles short lockouts.

## SQLite backend

SQLite is the default and needs no external service:

```yaml
backend: sqlite
sqlite:
  path: db/kraken-ui-ratelimit.sqlite
  busy_timeout_ms: 2000
  cleanup_interval_requests: 1024
```

Kraken UI creates the database and parent directory, enables WAL mode, disables
trusted schemas and performs each GCRA decision in an immediate transaction.
Expired keys are removed every `cleanup_interval_requests` checks. Keep this
database on a local filesystem; network filesystems weaken SQLite locking
semantics.

## Redis backend

Redis mode is optional:

```yaml
backend: redis
fail_open: false
redis:
  host: redis.internal.example
  port: 6379
  database: 0
  tls: true
  key_prefix: "kraken-ui:ratelimit:"
  connect_timeout_secs: 3
  response_timeout_secs: 2
  retries: 2
```

The application rejects `redis.tls: false`, verifies the server certificate and
hostname, uses bounded connection/response timeouts, and requires an ACL
username and password. Credentials are resolved file-first:

1. `REDIS_USERNAME_FILE` / `REDIS_PASSWORD_FILE`
2. `/run/secrets/krakenwaf/REDIS_USERNAME` /
   `/run/secrets/krakenwaf/REDIS_PASSWORD`
3. `REDIS_USERNAME` / `REDIS_PASSWORD`

Example systemd credentials:

```ini
[Service]
LoadCredential=REDIS_USERNAME:/etc/kraken-ui/secrets/redis-username
LoadCredential=REDIS_PASSWORD:/etc/kraken-ui/secrets/redis-password
Environment=REDIS_USERNAME_FILE=%d/REDIS_USERNAME
Environment=REDIS_PASSWORD_FILE=%d/REDIS_PASSWORD
```

These client controls are CIS-aligned hardening, not a claim of CIS
certification. Harden Redis itself separately: bind only private interfaces,
enable protected mode, disable the default user, use a dedicated least-privilege
ACL user, require TLS, rotate credentials, restrict administrative commands,
log authentication events and protect persistence/backup files. The dedicated
user must be allowed to authenticate and execute the Lua GCRA script and its
`TIME`, `GET` and `SET` operations against only the configured key prefix.
Follow the official [Redis security](https://redis.io/docs/latest/operate/oss_and_stack/management/security/)
and [TLS](https://redis.io/docs/latest/operate/oss_and_stack/management/security/encryption/)
guidance.

## Failure behavior

Keep `fail_open: false` for production. If SQLite or Redis is unavailable,
Kraken UI then returns a temporary rate-limit rejection rather than exposing an
unbounded administrative endpoint. `fail_open: true` is intended only for an
explicit availability-over-protection decision.

Invalid YAML, unknown fields, zero limits, unsafe Redis transport and malformed
key prefixes prevent startup.
