# KrakenWAF rule management

Kraken UI can drive KrakenWAF's **Rule Management API**, the control plane that
changes detection rules at runtime without restarting the WAF. The console
exposes two surfaces for administrators and operators:

- **Rule management → CMC rules** — toggle CMC detection modules on and off
  (since 0.16.0).
- **Rule management → Regex rules** — view and replace the content of the regex
  and keyword rule files (since 0.18.0).

This document describes how Kraken UI communicates with that API: the endpoints,
the request and response shapes, the Rorschach authentication token, and the
shared secrets it requires.

## Where it runs

KrakenWAF serves rule management on its own listener, separate from the metrics
port. KrakenWAF's default is port `4342`. Point Kraken UI at it in
`conf/setup.yaml`:

```yaml
waf-rule-endpoint: "https://127.0.0.1:4342"
# Optional. Falls back to waf-cert-ca, then cert-ca, when omitted.
waf-rule-cert-ca: "../KrakenWAF/certs/cert.pem"
```

The endpoint must use `https://`. The TLS channel is pinned to the configured CA
exactly like the metrics channel, so the control plane cannot be intercepted by
any other publicly trusted CA.

When `waf-rule-endpoint` is unset, or the Rorschach secrets are missing, the
console renders the page but reports itself as *not configured* rather than
failing — the rest of Kraken UI is unaffected.

## What the UI does

The browser never holds a Rorschach secret. The flow is always:

1. The page loads and the table issues `GET /kraken_ui/auth/api/rule_management/cmc`.
2. Kraken UI mints a Rorschach token server-side and calls KrakenWAF
   `GET /rule/control/cmc/list`.
3. The browser renders one row per module: the **CMC module name**, a **status**
   badge (`enable` when the module is on, `disable` when off) and a **checkbox**,
   ticked when the module's status is `true`.
4. **Submit all** collects every checkbox and POSTs the full desired state to
   `POST /kraken_ui/auth/rule_management/cmc/update` (with the CSRF token).
5. Kraken UI mints a fresh token and calls KrakenWAF
   `POST /rule/control/cmc/update`.
6. On success a message box confirms the change and the table reloads from the
   live state. On failure a message box reads **`error in WAF server`** and the
   details (HTTP status, transport error) are written to the application log —
   never the token or the secrets.

### Upstream endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET`  | `/rule/control/cmc/list`   | Current enable/disable state of every CMC module. |
| `POST` | `/rule/control/cmc/update` | Partial patch: each module is enabled (`true`) or disabled (`false`). |

`GET /rule/control/cmc/list` returns:

```json
{
  "status": "ok",
  "modules": { "CMC-Rules": { "HPP_detect": true, "Silent_sql_errors": false } }
}
```

`POST /rule/control/cmc/update` sends only the modules being changed. For
example, unticking `HPP_detect` and `Silent_sql_errors` sends:

```json
{ "modules": { "CMC-Rules": { "HPP_detect": false, "Silent_sql_errors": false } } }
```

and ticking them both sends the same object with `true` values. KrakenWAF replies
with the modules it changed, which Kraken UI surfaces in the confirmation box:

```json
{
  "status": "ok",
  "context": "cmc_update",
  "updated": { "disabled": ["Silent_sql_errors", "HPP_detect"], "enabled": [] }
}
```

## Regex rule editor

The regex editor lets an operator open a rule file, edit its content in a
syntax-highlighting editor and write it back. As with CMC, the browser never
holds a Rorschach secret and never talks to KrakenWAF directly: every upstream
call is minted and made server-side.

### Managed rule lists

Only this closed allowlist of rule lists can be viewed or edited. A name outside
the list is rejected before any request is built, so it can never become part of
an upstream path.

| Rule name | KrakenWAF file | Shape | Editor validation |
|---|---|---|---|
| `body_regex`      | `regex/body_regex.json`            | JSON regex bundle   | Non-empty `rules` array; every rule carries the required fields and a non-empty `rule_match`. |
| `path_regex`      | `regex/path_regex.json`            | JSON regex bundle   | As `body_regex`. |
| `header_regex`    | `regex/header_regex.json`          | JSON regex bundle   | As `body_regex`. |
| `vectorscan_list` | `Vectorscan/strings2block.json`    | JSON keyword bundle | Non-empty `rules` array (the keyword entries are not regex rules, so per-field checks do not apply). |
| `scanners`        | `user_agents/scanners.txt`         | Line-delimited text | At least one non-empty line. |

The required fields on a regex rule element are: `enable`, `http_action`,
`title`, `severity`, `cwe`, `description`, `url`, `rule_match`, `id`, `score`.

### The flow

1. **Rule management → Regex rules** opens the picker
   (`GET /kraken_ui/auth/rule_management/regex`): a select box of the rule lists
   above and a **submit rule to edit** button.
2. Choosing a list navigates to the editor
   (`GET /kraken_ui/auth/rule_management/regex/edit?rule=<name>`). The backend
   mints a token and calls KrakenWAF `POST /rule/control/regex/view`, then renders
   the returned content in the editor.
3. The operator edits the content and chooses **Update rule**. The browser POSTs
   the content (with the CSRF token) to
   `POST /kraken_ui/auth/rule_management/regex/update?rule=<name>`.
4. The backend validates the content for that rule list's shape (see the table).
   On failure it returns `400` with a specific message — for example
   *“The rule file cannot be empty.”* or *“Rule #2 is missing the required
   "rule_match" field.”* — and **never** contacts the WAF.
5. On success it mints a fresh token and calls KrakenWAF
   `POST /rule/control/regex/update/<name>`. A confirmation alert reports how many
   items were written; any upstream failure surfaces as **`error in WAF server`**,
   with the detail kept to the application log.

### Upstream endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/rule/control/regex/view`          | Retrieve the full content of one rule file. |
| `POST` | `/rule/control/regex/update/<name>` | Replace the content of one rule file (hot-reloaded). |

`POST /rule/control/regex/view` sends the rule name and receives the file content
as a single string:

```json
{ "rule_view": "body_regex" }
```

```json
{ "status": "ok", "context": "regex_view", "rule": "body_regex",
  "content": "{\n  \"rules\": [ ... ]\n}\n" }
```

`POST /rule/control/regex/update/<name>` carries the new content in the body. For
the JSON bundles it is the rule object itself, written verbatim so the operator's
formatting is preserved:

```json
{ "rules": [ { "enable": 1, "http_action": "Request", "title": "...",
  "severity": "critical", "cwe": "CWE-78", "description": "...", "url": "...",
  "rule_match": "(?i)...", "id": "00001", "score": 1000 } ] }
```

For the scanner allowlist the editor's lines are wrapped before sending:

```json
{ "lines": ["arachni", "sqlmap", "nikto"] }
```

KrakenWAF replies with the number of items written, surfaced in the confirmation:

```json
{ "status": "ok", "context": "regex_update", "rule": "body_regex", "rules_written": 1 }
```

### Editor and CSP

The editor uses the vendored [ACE](https://ace.c9.io/) build in
`src/view/static/vendor/ace` (its `LICENSE` is kept alongside it). To stay within
the app's strict Content-Security-Policy, ACE's stylesheets are linked as static
files and its runtime style injection is disabled (`useStrictCSP`), the JSON
worker is loaded from a same-origin URL rather than a blob
(`loadWorkerFromBlob = false`), and no `innerHTML` is used by the integration. It
highlights JSON, with the *Clouds Midnight* theme; the scanner list uses plain
text mode.

Every regex editor page carries a fixed caution about ReDoS and the dangers of
PCRE-style regex.

## Authentication: the Rorschach token

Every rule-management request carries a per-request bearer token:

```http
Authorization: Bearer rch1.<client_id>.<step>.<nonce_b64>.<token_b64>
```

- `client_id` — `RORSCHACH_CLIENT_ID` (default `kraken-ui`), restricted to
  `[A-Za-z0-9_-]` so `.` stays an unambiguous delimiter.
- `step` — `floor(unix_time_utc / 300)`, a 5-minute window index.
- `nonce_b64` — 64 random bytes per request, base64url without padding.
- `token_b64` — the 32-byte MAC tag, base64url without padding.

The MAC authenticates this newline-delimited canonical message, which binds the
method, path and body so a captured token cannot be replayed against a different
request:

```text
rorschach-v1\n{client_id}\n{step}\n{nonce_b64}\n{method}\n{path}\n{body_hash}
```

`body_hash` is the base64url (no-pad) BLAKE2b-256 of the raw request body
(empty for `GET`). The tag is a BLAKE2b-256 **keyed** MAC over the canonical
message, using the **first 64 bytes** of the decoded secret as the key.
KrakenWAF computes the same values with the `orion` crate; Kraken UI uses
libsodium BLAKE2b (via `dryoc`), which is byte-identical (plain keyed/unkeyed
BLAKE2b with no salt or personalisation). All encodings are base64url without
padding.

### Even/odd secret selection

The MAC key is chosen by the parity of `step`:

- even `step` → `RORSCHACH_SECRET_EVEN`
- odd `step` → `RORSCHACH_SECRET_ODD`

KrakenWAF tolerates ±60 seconds of clock skew and rejects a replayed
`(client_id, step, nonce)` triple, so the two services only need roughly
synchronised clocks.

The constructed `Authorization` header is marked sensitive in the HTTP client.
The token, the decoded secrets and the MAC key never appear in any log.

## Shared secrets

Kraken UI deliberately uses the **same secret names** and the **same file-first
resolution order** as KrakenWAF, so a co-located deployment shares one mount:

| Secret | Purpose |
|---|---|
| `RORSCHACH_SECRET_EVEN` | MAC key when the time window is even. |
| `RORSCHACH_SECRET_ODD`  | MAC key when the time window is odd. |
| `RORSCHACH_CLIENT_ID`   | Client identifier in the token (default `kraken-ui`, not secret). |

Each secret is resolved in this order (identical to `BEARER_PASSWORD`):

1. `<NAME>_FILE` — an explicit path to a file containing the value.
2. `/run/secrets/krakenwaf/<NAME>` — the conventional shared mount (CIS-style).
3. `<NAME>` — a plain environment variable.

Both secrets must decode (base64url, with or without padding is accepted) to at
least **64 bytes**. See [Security](security.md#rule-management-rorschach-secrets)
for how to generate them.

### Co-located deployment (same container/host)

Mount one secret pair where both services can read it; neither needs an
environment variable:

```bash
sudo install -d -m 0750 /run/secrets/krakenwaf
for name in RORSCHACH_SECRET_EVEN RORSCHACH_SECRET_ODD; do
  python3 -c "import os,base64;print(base64.urlsafe_b64encode(os.urandom(64)).decode().rstrip('='))" |
    sudo tee "/run/secrets/krakenwaf/$name" >/dev/null
  sudo chmod 0440 "/run/secrets/krakenwaf/$name"
done
```

### Split deployment (different containers)

When KrakenWAF runs elsewhere, generate the pair once with the bundled tool and
install the **same two files** on both sides:

```bash
# Print env-style lines:
cargo run --bin rorschach_keygen

# …or write CIS-style files (dir 0750, files 0440):
cargo run --bin rorschach_keygen -- --write          # /run/secrets/krakenwaf
cargo run --bin rorschach_keygen -- --dir /secure/dir # a custom directory
```

The generated values are 64 random bytes, base64url without padding — the exact
format KrakenWAF documents. The tool writes them only to stdout or the requested
files, never to a log.

## Roles and CSRF

The page and both API routes sit behind `require_operator`, so administrators and
operators can use them; other roles are redirected to the login page. The update
is a CSRF-protected POST: the page embeds an authenticity token that the browser
returns in the JSON body, validated against the `__Host-` CSRF cookie.

## Failure behaviour

| Result | Meaning | Action |
|---|---|---|
| HTTP `401` from KrakenWAF | Token rejected: wrong/missing secret, replayed nonce or altered request. | Verify both services resolve the same `RORSCHACH_SECRET_EVEN` / `RORSCHACH_SECRET_ODD` and that clocks are roughly in sync. |
| HTTP `403` from KrakenWAF | Client IP is outside KrakenWAF's rule-management allowlist. | Add the UI's address to `rules/addr/allowlist/allow_rule_management.txt`. |
| TLS error | `waf-rule-cert-ca` (or its fallback) does not trust the certificate on the rule port. | Configure the correct CA PEM. |
| `error in WAF server` in the UI | Any of the above, or the listener is down. | Check the Kraken UI application log for the status code; start KrakenWAF's rule listener. |
