# Segurança

## Controles

- TLS é obrigatório no processo; não existe opção HTTP.
- Cookies de sessão e CSRF usam `Secure`, `HttpOnly`, `SameSite=Strict`, path `/` e prefixo `__Host-`.
- Login e logout usam POST com token CSRF.
- Senhas são processadas com `dryoc` usando o formato Argon2id moderado compatível com libsodium e nunca são registradas.
- Entradas textuais passam por Ammonia. Segredos são rejeitados se o sanitizador os alteraria, sem modificar seus bytes.
- O CSP proíbe inline script/style. O JavaScript local não usa `innerHTML`, em conformidade com Trusted Types.
- Logs são JSONL e eventos não incluem senha, hash, token CSRF ou conteúdo de sessão.

## Política de licenças

Dependências diretas precisam oferecer MIT, BSD-2-Clause ou BSD-3-Clause. A árvore transitiva não consegue obedecer apenas a essas três licenças:

- Ammonia depende de componentes MPL-2.0.
- AXUM depende de `sync_wrapper` Apache-2.0.
- Rustls e SQLite via SeaORM usam componentes ISC, Apache-2.0, Unicode-3.0 e CDLA-Permissive.

Essas exceções permissivas ou de copyleft fraco estão explícitas em `deny.toml`. `cargo-deny` falhará para licenças novas fora da lista, evitando expansão silenciosa da política.

## Bootstrap

Se não houver administrador, a aplicação lê `KRAKEN_UI_ADMIN_PASSWORD` e `KRAKEN_UI_ADMIN_EMAIL`. A senha deve ter no mínimo 14 caracteres, letras maiúsculas e minúsculas, número e símbolo, sem espaço nem o nome do usuário.

## Envelope de senha

O valor persistido em `encrypted_password_hash` é:

```text
base64(key_id[16] || nonce[24] || xchacha20poly1305_ciphertext)
```

O plaintext cifrado é o registro completo retornado por `crypto_pwhash_str`, incluindo salt e parâmetros. O AAD é:

```text
kraken_ui:v1:user:<id_user>:password_hash
```

Isso impede copiar o ciphertext de um operador para outro. No login, o serviço decifra, executa `crypto_pwhash_str_verify` e compara os parâmetros Argon2id com a política moderada atual. Se estiverem antigos, gera e persiste um novo envelope.

## Chaves

- `KRAKEN_UI_PASSWORD_KEY`: chave de 32 bytes codificada em Base64.
- `KRAKEN_UI_PASSWORD_KEY_FILE`: arquivo contendo a chave Base64; no Unix deve ter permissão sem acesso para grupo ou outros.
- `KRAKEN_UI_PASSWORD_KEY_ID`: identificador ASCII de até 16 bytes, padrão `primary-v1`.

A aplicação não inicia sem uma fonte de chave. A chave nunca entra no banco, templates, sessão ou logs.
