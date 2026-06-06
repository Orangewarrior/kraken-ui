# Operação

## Configuração

O arquivo `conf/setup.yaml` aceita:

- `cert-ca`: certificado ou cadeia PEM apresentada pelo servidor.
- `key`: chave privada PEM correspondente.
- `listen`: endereço e porta HTTPS.
- `db-local`: banco SQLite da interface.
- `waf-endpoint`: endpoint HTTPS do KrakenWAF.
- `log-dir`: diretório dos logs JSONL.
- `session-timeout-minutes`: expiração por inatividade, entre 5 e 1440 minutos.

Paths relativos são resolvidos a partir do diretório de execução.

## Banco de dados

O caminho padrão é `db/kraken-ui.sqlite`. A tabela `operators` é criada automaticamente. Consulte `docs/database.md` para schema e endpoints.

## Headers

Cada linha de `conf/headers_sec.txt` usa o formato `Nome: valor`. O arquivo é validado na inicialização. Uma linha inválida impede o servidor de iniciar, evitando operação sem hardening.

## Logs

O arquivo padrão é `log/kraken-ui.jsonl`. Use `RUST_LOG` para ajustar níveis, sem habilitar logs de payload em produção.
