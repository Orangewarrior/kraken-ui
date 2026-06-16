# Sensitive-data redaction on the attack detail view

The single-attack detail view (`/kraken_ui/auth/view_waf_request/?id=<id>`) shows
the raw bytes a KrakenWAF finding captured. The captured request and response
evidence routinely carries credentials — a login form body
(`user=alice&password=hunter2`), a bearer token in a query string
(`?token=ey…`), or a localized field name (`senha=…`, `пароль=…`, `密码=…`).

An auditor or operator investigating a finding has no operational need to read
those secret values in clear. From Kraken UI 0.17.0, **only an administrator**
sees them; for every other role the value of any parameter whose **name** matches
a well-known secret word is replaced with the placeholder `+++++` before the page
is rendered.

## What is masked

Three fields of the finding are treated as request/response evidence and run
through the redactor for non-administrators:

| Field | Example |
|-------|---------|
| `request_uri` | `/login?token=ABCD&user=alice` → `/login?token=+++++&user=alice` |
| `fullpath_evidence` | `senha=minhaSenha` → `senha=+++++` |
| `request_payload` | `user=alice&password=hunter2` → `user=alice&password=+++++` |

The describing metadata — title, severity, CWE, description, reference, timestamp,
rule match, rule line match and client IP — is shown unchanged to every viewer.

## Who sees what

| Role | Sees secret values |
|------|--------------------|
| `admin` | **Yes** — the original captured bytes, unmodified. |
| `operator` | No — secret values replaced with `+++++`. |
| `auditor` | No — secret values replaced with `+++++`. (Sign-in for `auditor` is reserved; the guard already covers it.) |

The decision is made server-side in `view_waf_request` from the session's
operator type (`auth::is_admin`); the masked bytes never leave the server for a
non-admin, so this is not a front-end-only hide.

## How a parameter is detected

The redactor (`src/security/redact.rs`) scans the text for a parameter:
a *name token* (Unicode letters/digits plus `_` and `-`) immediately followed —
allowing intervening spaces, tabs and quotes, as in JSON's `"password":` — by a
`=` or `:` delimiter and then a value. The value is then replaced:

- a **quoted** value keeps its quotes (`"token":"+++++"`);
- a **bare** value is replaced up to the next terminator (`&`, `;`, `,`,
  whitespace, `}`, `]`, `)`, `<`, `>`, `#` or end of input);
- an **empty** value is left empty (nothing is invented);
- values **nested** inside another value are scanned too, so a sensitive
  parameter inside a redirect URL is also masked.

A name matches when, lower-cased (Unicode-aware) and stripped of surrounding
quotes, it **contains** any of the sensitive words below as a substring. This is
deliberately broad: `user_password`, `X-Api-Key` and `motdepasse` (caught
transitively by `passe`) are all redacted. Over-masking is preferred to leaking,
and an administrator can always see the original value.

## Sensitive words

The match list covers many languages and spellings (French, German, Portuguese,
Spanish, English, Russian, Chinese, Japanese and Indonesian):

```
mot de passe, passe, code, jeton, token, bearer, porteur, clé, cle, clef,
passwort, kennwort, kode, träger, traeger, schlüssel, schlussel, palavra-passe,
palavrapasse, senha, código, codigo, portador, chave, contraseña, contrasena,
clave, password, passwd, pass, key, пароль, код, токен, носитель, ключ, 密码,
密碼, 代码, 代碼, 令牌, 持有者, 密钥, 密鑰, 钥匙, 鑰匙, パスワード, 暗号, コード,
トークン, ベアラー, 鍵, キー, kata sandi, katasandi, sandi, pembawa, kunci
```

The authoritative list lives in `redact::SENSITIVE_WORDS`.

## Tests

- **Unit tests** (`src/security/redact.rs`) cover form-urlencoded, JSON and spaced
  keys, several languages, compound names, nested values, empty values,
  idempotency and the case-insensitive name classifier.
- **Real-HTTP integration test**
  (`tests/view_waf_request_redaction_http.rs`) stands up the full router over a
  real read-only WAF SQLite seeded with a credential-bearing finding, then signs
  in as `admin` (sees the values) and as `operator` (sees `+++++`, while
  non-sensitive parameters survive).
- **Standalone probe** (`examples/view_waf_request_probe.rs`) signs in to a
  running instance and reports whether the detail view masks values for the given
  role:

  ```bash
  cargo run --example view_waf_request_probe -- \
      https://kraken-ui.example.test operator 'Passw0rd!' 1
  ```
