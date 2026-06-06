# Arquitetura

## Organização

- `src/routes`: declara endpoints e encaminha para controllers.
- `src/controllers`: trata HTTP, CSRF, sessão e renderização.
- `src/models`: entidade `operators`, schema e repositório SeaORM.
- `src/view`: templates Askama e assets locais.
- `src/middleware`: autenticação e headers globais.
- `src/security`: sanitização, senha e parser de headers.
- `src/app.rs`: `AppFactory`, composição de estado e camadas.

## Padrões

`AppFactory` centraliza a construção da aplicação. `PasswordPolicy` é uma strategy substituível para validação de senha. Configurações de sessão e CSRF usam builders das próprias crates.

`PasswordCryptoService` é o boundary do serviço criptográfico isolado. A implementação atual usa `dryoc`, compatível com as funções de password hashing do libsodium, no mesmo processo. Controllers e repositórios dependem apenas do trait. Uma implementação por Unix socket, serviço sidecar, HSM ou KMS pode substituí-la sem mudar o fluxo HTTP.

Controllers não executam SQL. O repositório de usuário usa a API de expressão do SeaORM, que gera parâmetros vinculados em vez de concatenar entrada em SQL.

O banco interno configurado por `db-local` é gravável. O banco externo do
KrakenWAF configurado por `db_local` é aberto por uma segunda conexão SeaORM em
modo somente leitura.

`WafMetricsService` usa HTTPS e o certificado configurado para consultar
`waf-endpoint/metrics`, com fallback para `/__kwaf/metrics`. O parser aceita o
formato de exposição Prometheus e não executa conteúdo recebido.
Quando o KrakenWAF usa certificado próprio, `waf-cert-ca` deve apontar para o
PEM confiável apresentado pelo serviço.

## Fluxo HTTP

Apenas login, assets, health check e o POST one-shot `first_time` são públicos.
`first_time` exige conexão TCP loopback e fecha quando a tabela contém um
registro. O restante do namespace `/kraken_ui/auth` exige sessão do tipo
`admin`. Toda resposta, inclusive erro, redirect e asset estático, passa pelo
middleware que aplica `conf/headers_sec.txt`.
