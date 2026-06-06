# Kraken UI

Interface web de administração para o [KrakenWAF](https://github.com/Orangewarrior/KrakenWaf), escrita em Rust com AXUM, Askama, SeaORM e TLS obrigatório.

## Preparação

1. Edite `conf/setup.yaml` com o certificado, a chave privada, o endereço TLS,
   o banco interno e o banco de alertas do KrakenWAF:

```yaml
cert-ca: certs/ca.pem
key: certs/key.pem
listen: "127.0.0.1:3443"
db-local: db/kraken-ui.sqlite
db_local: "../KrakenWAF/logs/db/vulns_alert.db"
waf-endpoint: "https://127.0.0.1:8443"
waf-cert-ca: "../KrakenWAF/certs/cert.pem"
```
2. Configure uma chave XChaCha20-Poly1305 de 32 bytes em Base64:

```bash
export KRAKEN_UI_PASSWORD_KEY="$(openssl rand -base64 32)"
export KRAKEN_UI_PASSWORD_KEY_ID='primary-v1'
```

Em produção, prefira arquivo com permissão `0600`:

```bash
openssl rand -base64 32 > /secure/path/kraken-ui-password.key
chmod 600 /secure/path/kraken-ui-password.key
export KRAKEN_UI_PASSWORD_KEY_FILE=/secure/path/kraken-ui-password.key
```

3. O administrador inicial pode ser criado por variáveis de ambiente:

```bash
export KRAKEN_UI_ADMIN_PASSWORD='Use-A-Unique!Strong9Password'
export KRAKEN_UI_ADMIN_EMAIL='admin@example.invalid'
cargo run
```

O usuário inicial é `admin`. A senha é processada por uma implementação Rust compatível com libsodium usando Argon2id, cifrada com XChaCha20-Poly1305 e nunca é registrada em log.

Alternativamente, com a tabela vazia, execute uma única requisição a partir do
localhost. O endpoint responde `410 Gone` depois que qualquer operador existir:

```bash
curl --cacert certs/ca.pem \
  --data-urlencode 'username=admin' \
  --data-urlencode 'email=admin@example.invalid' \
  --data-urlencode 'user_type=admin' \
  --data-urlencode 'password=Use-A-Unique!Strong9Password' \
  https://127.0.0.1:3443/kraken_ui/auth/first_time
```

Login: `https://host:porta/kraken_ui/login`.

## Administração

- `/kraken_ui/auth/painel_admin` e `/kraken_ui/auth/dashboard`
- `/kraken_ui/auth/insert_user`
- `/kraken_ui/auth/delete_user`
- `/kraken_ui/auth/edit_user`
- `/kraken_ui/auth/show_user_table`
- `/kraken_ui/auth/show_attacks`
- `/kraken_ui/auth/update_password`

O menu administrativo é definido uma única vez em
`src/view/templates/admin_sidebar.html`.

## Validação

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

Documentação adicional está em [`docs/`](docs/).
