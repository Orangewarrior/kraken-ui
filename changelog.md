# Changelog

Todas as mudanças relevantes deste projeto serão registradas neste arquivo.

## 0.3.0 - 2026-06-06

### Adicionado

- Menu administrativo global compartilhado por todos os templates autenticados.
- Endpoints de inserção, remoção, procura, edição e troca de senha solicitados.
- Bootstrap público one-shot `first_time`, limitado a IP loopback.
- Tabela AJAX de operadores com 50 registros por página e ações POST com CSRF.
- Leitura somente de `vulns_alert.db`, tabela AJAX de ataques e ordenação de severidade.
- Dashboard alimentado pelas métricas HTTPS do KrakenWAF e por agregações de país, IP e CMC.
- Pie plot e bar plot implementados em SVG local, sem biblioteca JavaScript externa.

### Alterado

- Política de senha alinhada para aceitar complexidade média ou forte.

## 0.2.0 - 2026-06-06

### Adicionado

- Tabela SQLite `operators` com tipos `admin`, `operator` e `auditor`.
- Hash de senha Argon2id compatível com libsodium via `dryoc` e envelope XChaCha20-Poly1305 com AAD por usuário.
- Chave criptográfica carregada por variável de ambiente ou arquivo protegido.
- Upgrade automático do hash após login quando os parâmetros exigem rehash.
- CRUD administrativo completo para operadores, protegido por sessão admin e CSRF.
- Rotas `/kraken_ui/login`, `/kraken_ui/test_login` e `/kraken_ui/auth/painel_admin`.

### Alterado

- O modelo anterior `users` foi substituído pelo modelo `operators`.
- Operadores e auditores permanecem sem painel habilitado nesta versão.
- Exceções de licença transitiva da stack obrigatória foram documentadas em
  `docs/dependency-licenses.md`.

## 0.1.0 - 2026-06-06

### Adicionado

- Aplicação Rust modular com AXUM, Askama e TLS obrigatório.
- Carregamento de certificado, chave, endpoint e SQLite por `conf/setup.yaml`.
- Headers globais de hardening carregados de `conf/headers_sec.txt`.
- Login com Argon2id, sessão assinada, cookies seguros e proteção `axum_csrf`.
- Sanitização centralizada com Ammonia e política de senha no frontend e backend.
- Persistência SQLite por SeaORM e bootstrap seguro do primeiro administrador.
- Logs estruturados JSONL em `log/kraken-ui.jsonl`.
- Tema black and orange integrado sem CDN ou JavaScript inline.
- CI de SAST/SCA com Clippy, Semgrep, CodeQL, cargo-audit, cargo-deny e OSV Scanner.
