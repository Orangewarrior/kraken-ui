# KrakenWaf Axum + Askama schema

## Structure

```text
axum_schema/
├── Cargo.toml
├── src/main.rs
├── static/
│   ├── style.css
│   └── app.js
└── templates/
    ├── index.htmlx
    └── dashboard.html
```

## Running

```bash
cargo run
```

Then open:

```text
http://127.0.0.1:3000/
http://127.0.0.1:3000/dashboard
http://127.0.0.1:3000/api/alerts
http://127.0.0.1:3000/api/metrics/summary
```

## Security

The example applies headers via `tower-http`:

```text
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
```

## Real integration

Replace the mocked data in `src/main.rs` with real KrakenWaf queries.

Recommendations:

- Implement real server-side pagination for `/api/alerts`.
- Normalise logs before rendering them.
- Never inject HTML coming from logs, rules or requests.
- Use strong types for severity, action and status.
- For production, serve over TLS behind your reverse proxy/WAF.


## Local PNG assets

This version intentionally allows local PNGs only from `static/img/`:

- `static/img/logo-mark.png` — local KrakenWaf mark.
- `static/img/kraken-hero.png` — decorative local hero artwork.
- `static/img/dashboard-preview.png` — local dashboard preview screenshot.
- `static/img/full-page-mockup.png` — reference-only full landing mockup.

No CDN, remote image, remote font, or external JavaScript is required. The CSP uses `img-src 'self'` so images must remain under the same origin, for example `/static/img/...` in Axum.


## Login screen

Added a local, responsive login page using the same dark/orange KrakenWaf design.

- Axum + Askama: `GET /login` renders `templates/login.htmlx`; `POST /login` is a demo redirect to `/dashboard`. Replace it with real authentication, CSRF validation, session rotation, password hashing, rate limiting, and audit logging before production.
- Simple HTML: `login.html` is a static mockup using only `static/style.css`, `static/app.js`, and local images from `static/img/`.
- CSP remains restricted to local resources with `default-src 'self'`, `script-src 'self'`, `style-src 'self'`, `img-src 'self'`, and `form-action 'self'`.


## ACL/User/Attack templates added

This package now includes ACL CRUD and attack evidence templates for both schemas.

### Axum + Askama routes

- `GET /acl`
- `GET|POST /acl/users/add`
- `GET|POST /acl/users/edit/{user_id}`
- `GET|POST /acl/users/delete`
- `GET|POST /operator/update`
- `GET|POST /auditor/update`
- `GET /acl/users`
- `GET /attacks`
- `GET /attacks/evidence/{attack_id}`
- `GET /api/users` — DataTables-style JSON: `draw`, `recordsTotal`, `recordsFiltered`, `data`
- `GET /api/attacks` — DataTables-style JSON: `draw`, `recordsTotal`, `recordsFiltered`, `data`

### Security notes

- Password validation in `static/app.js` is only a UX guard. The backend must enforce the same or stricter policy.
- Delete actions are routed to a form/confirmation instead of deleting via GET.
- Evidence views use local vanilla JS syntax highlighting and escape untrusted text before markup.
- No CDN, no NPM, no remote fonts, and no remote images are required.
- The local `KwDataTable` helper follows the DataTables server-side JSON shape but is custom local code, not the official DataTables distribution.
