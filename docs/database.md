# Banco de dados e ACL

## Schema

```sql
CREATE TABLE operators (
    id_user INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(32) NOT NULL UNIQUE,
    email VARCHAR(128) NOT NULL UNIQUE,
    type VARCHAR(32) NOT NULL
        CHECK (type IN ('admin', 'operator', 'auditor')),
    encrypted_password_hash VARCHAR(1024) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);
```

Além da unicidade de e-mail solicitada, `username` também é único para tornar a autenticação determinística.

## Rotas públicas

- `GET /kraken_ui/login`: formulário de login.
- `POST /kraken_ui/test_login`: valida CSRF, busca o operador, chama o serviço criptográfico e cria sessão somente para `admin`.

## Rotas admin

- `GET /kraken_ui/auth/painel_admin`
- `GET /kraken_ui/auth/acl`
- `GET /kraken_ui/auth/acl/operators`
- `GET|POST /kraken_ui/auth/acl/operators/add`
- `GET|POST /kraken_ui/auth/acl/operators/edit/{id_user}`
- `GET|POST /kraken_ui/auth/acl/operators/delete`

## Endpoints administrativos atuais

- `GET /kraken_ui/auth/insert_user`
- `POST /kraken_ui/auth/insert_user_action`
- `GET /kraken_ui/auth/delete_user`
- `POST /kraken_ui/auth/delete_user_action`
- `GET|POST /kraken_ui/auth/edit_user`
- `POST /kraken_ui/auth/update_user_action`
- `GET /kraken_ui/auth/show_user_table`
- `GET /kraken_ui/auth/api/operators`
- `GET /kraken_ui/auth/update_password`
- `POST /kraken_ui/auth/update_password_action`

## Banco do KrakenWAF

`db_local` aponta para `vulns_alert.db`. A UI abre esse arquivo em modo
somente leitura e consulta `vulnerabilities` com filtros parametrizados para
data, severidade, IP, país e título.
- `GET /kraken_ui/auth/api/operators`
- `POST /kraken_ui/auth/logout`

Todas as mutações usam POST e CSRF. O endpoint JSON nunca retorna `encrypted_password_hash`.
