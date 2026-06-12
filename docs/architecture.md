# Architecture

This is a tour of how Kraken UI is put together. The goal is that you can open
any module and immediately know what it is responsible for.

## How the code is organised

| Module           | Responsibility |
|------------------|----------------|
| `src/routes`     | Declares every endpoint and forwards it to a controller. |
| `src/controllers`| Handles HTTP: CSRF, sessions and template rendering. |
| `src/models`     | The `operators` entity, schema and SeaORM repositories. |
| `src/view`       | Askama templates and the local CSS/JS assets. |
| `src/middleware` | Authentication, the global security-header layer and the per-IP request limiter. |
| `src/security`   | Sanitisation, password policy, header parser, CSRF check, rate limiting and the protected-file reader. |
| `src/services`   | The password-crypto and WAF-metrics boundaries. |
| `src/app.rs`     | `AppFactory` — wires up state, layers and the router. |

Some smaller building blocks are worth knowing by name:

| Item | Responsibility |
|------|----------------|
| `controllers::pagination` | `PageResponse<T>` and `parse_query_u64`, shared by every server-side table. |
| `security::csrf` | The single CSRF-verification function. |
| `security::rate_limit` | `LoginThrottle` (failure lockout) and `IpRateLimiter` (global token bucket). |
| `security::read_protected_file` | Reads a key file, refusing group/other-readable files on Unix. |
| `models::session_store` | `SeaOrmSessionStore`, the persistent SQLite session backend. |
| `models::like_contains` | Escapes `LIKE` metacharacters for search filters. |
| `view::nav` | Navigation-section constants shared with the sidebar template. |
| `services::password_crypto::spawn_*` | Run Argon2id work on the blocking pool, with plaintext held in `Zeroizing`. |

## Design choices worth knowing

**`AppFactory` is the single place the application is built.** State, session
and CSRF configuration, and middleware layers are all composed here, which
keeps `main.rs` tiny and makes the app easy to assemble in tests.

**The password policy is swappable.** `PasswordPolicy` is a small strategy
trait, so the validation rules can be replaced without touching the controllers
that depend on it.

**Cryptography sits behind a boundary.** `PasswordCryptoService` is a trait, and
the current implementation (`DryocPasswordCryptoService`) runs libsodium-compatible
Argon2id in-process via `dryoc`. Because controllers and repositories depend
only on the trait, you could later swap in an implementation backed by a Unix
socket, a sidecar service, an HSM or a KMS without changing the HTTP flow.

**Controllers never write SQL.** The operator repository uses SeaORM's
expression API, which produces bound parameters instead of concatenating user
input into a query string.

**Two databases, two postures.** The UI's own database (`db-local`) is opened
read-write. The KrakenWAF alerts database (`db_local`) is opened through a
second SeaORM connection in **read-only** mode, so the console can never modify
the WAF's data.

**Metrics are pulled over HTTPS, with the channel pinned.** `WafMetricsService`
uses the configured certificate to query `waf-endpoint/metrics` on KrakenWAF's
dedicated observability port (default `4343`), falling back to
`/__kwaf/metrics`. It attaches the `BEARER_PASSWORD` credential resolved through
the same file-first chain as KrakenWAF. When a custom CA is supplied it trusts
*only* that CA (the system root store is disabled), so the channel cannot be
intercepted by another publicly trusted CA. The parser understands the
Prometheus exposition format and never executes the content it receives.

**Sessions are persistent and server-side.** `SeaOrmSessionStore` keeps session
records in SQLite, so they survive a restart and can be revoked by deleting a
row; expired rows are pruned opportunistically. The cookie only carries a signed
id, with the signing key loaded from configuration.

**Source updates are staged before activation.** The admin-only update service
queries GitHub releases with `reqwest`, validates a stable semantic tag, rejects
unsafe archive entries and compiles with the locked dependency graph in a
temporary directory. Source and executable activation happen only after the
staged build succeeds. Persistent paths and existing configuration files are
excluded from the source overlay, and a server handle coordinates the
replacement process with listener shutdown.

## Cross-cutting concerns

- **Rate limiting.** `LoginThrottle` locks a source IP, and an IP+account pair,
  after repeated login failures; `IpRateLimiter` caps overall request volume per
  IP as a global outer layer; and `AccountFailureMonitor` raises a detection-only
  audit alert when one account draws failures from many IPs (it never locks, so a
  victim cannot be locked out from addresses they do not control). All three are
  process-local today, and all key on the **direct socket peer** — Kraken UI is
  meant to terminate TLS itself. Behind a reverse proxy every client would share
  the proxy's IP, collapsing both the per-IP limiter and the audited client IP, so
  do not deploy it that way without a trusted-proxy story.
- **Audit logging.** Authentication and operator-administration events are
  emitted on the `audit` tracing target and written to a dedicated `audit.jsonl`
  sink, separate from the application log, and never contain secrets.

## The HTTP request flow

Only four things are public: the login page, static assets, the health check
and the one-shot `first_time` bootstrap POST. `first_time` additionally
requires a loopback TCP connection, rejects requests carrying proxy forwarding
headers, optionally requires a bootstrap token, and closes itself the moment the
operators table contains a row.

Every request first passes the global per-IP rate limiter. Everything under
`/kraken_ui/auth` then requires a session and is returned with
`Cache-Control: no-store`. **Every** response — including errors, redirects and
static assets — passes through the middleware that applies
`conf/headers_sec.txt`, so there is no path that can escape the hardening
headers.

## Roles and authorization

There are three operator roles (`admin`, `operator`, `auditor`), enforced by
three thin middleware functions in `middleware::authentication`, all built on a
shared `guard` that checks the session's operator type against an allow-list:

| Middleware | Allowed roles | Protects |
|------------|---------------|----------|
| `require_admin` | `admin` | The ACL management surface (add/edit/delete/list operators). |
| `require_operator` | `admin`, `operator` | The day-to-day console: dashboard, attacks table, self-service password change, logout. |
| `require_attack_viewer` | `admin`, `operator`, `auditor` | The single-attack detail view only. |

The same dashboard, attacks and password-change controllers serve both admins
and operators; the controller computes `show_acl` (`auth::is_admin`) and passes
it to the template, which renders the ACL sidebar section only for admins. Today
only `admin` and `operator` accounts can sign in — the `auditor` role is already
authorised for the read-only detail view for forward compatibility.

## The single-attack detail view

`controllers::waf::view_waf_request` renders one WAF finding into the
`view_waf_request.htmlx` template (opened in a new tab from the attacks table).
It looks the row up read-only through `VulnerabilityRepository::find_by_id`,
maps the severity to a colour class, renders the stored timestamp in a
human-readable form, and renders the attacker-controlled `request_payload`
through Askama's default HTML escaping — it is **not** Ammonia-stripped, so the
exact attacker bytes survive as inert text instead of being silently altered.
Syntax highlighting is applied in `view/static/app.js` by building
DOM nodes only — never `innerHTML` — so it remains compatible with the strict
CSP and Trusted Types.
