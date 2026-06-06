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
| `src/middleware` | Authentication and the global security-header layer. |
| `src/security`   | Input sanitisation, the password policy and the header parser. |
| `src/services`   | The password-crypto and WAF-metrics boundaries. |
| `src/app.rs`     | `AppFactory` — wires up state, layers and the router. |

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

**Metrics are pulled over HTTPS.** `WafMetricsService` uses the configured
certificate to query `waf-endpoint/metrics`, falling back to `/__kwaf/metrics`.
The parser understands the Prometheus exposition format and never executes the
content it receives. When KrakenWAF presents its own certificate, point
`waf-cert-ca` at the trusted PEM.

## The HTTP request flow

Only four things are public: the login page, static assets, the health check
and the one-shot `first_time` bootstrap POST. `first_time` additionally
requires a loopback TCP connection and closes itself the moment the operators
table contains a row.

Everything under `/kraken_ui/auth` requires an `admin` session. **Every**
response — including errors, redirects and static assets — passes through the
middleware that applies `conf/headers_sec.txt`, so there is no path that can
escape the hardening headers.
