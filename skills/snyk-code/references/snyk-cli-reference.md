# Snyk Code CLI — Referência Rápida

## Comandos essenciais

| Comando | Descrição |
|---|---|
| `snyk code test` | Scan no diretório atual |
| `snyk code test <path>` | Scan em diretório específico |
| `snyk code test --json` | Output em JSON estruturado |
| `snyk code test --sarif` | Output em SARIF (padrão GitHub/VSCode) |
| `snyk code test --severity-threshold=<level>` | Filtrar por severidade mínima |
| `snyk code test --org=<org-id>` | Usar configuração de uma org Snyk específica |
| `snyk auth` | Autenticar com conta Snyk |
| `snyk auth <token>` | Autenticar com token direto |
| `snyk config set api=<token>` | Configurar token via config |

## Flags úteis

```
--json                    Saída em JSON
--sarif                   Saída em SARIF v2.1.0
--severity-threshold=     low | medium | high | critical
--org=                    ID da organização no Snyk
--exclude=                Diretórios/arquivos a excluir (glob)
--sarif-file-output=      Salvar SARIF em arquivo específico
--json-file-output=       Salvar JSON em arquivo específico
--quiet / -q              Suprimir mensagens de progresso
```

## Códigos de saída

| Código | Significado |
|---|---|
| 0 | Scan concluído sem vulnerabilidades |
| 1 | Vulnerabilidades encontradas |
| 2 | Falha de execução (ex: sem autenticação) |
| 3 | Sem arquivos suportados no diretório |

## Linguagens suportadas

JavaScript / TypeScript, Python, Java, C/C++, C#, Go, PHP, Ruby, Swift, Kotlin, Scala,
Apex, VB.NET, COBOL, HTML (templates), Terraform (limitado).

## Variáveis de ambiente

```bash
SNYK_TOKEN=<token>         # Token de autenticação
SNYK_ORG=<org-id>          # ID da organização padrão
SNYK_CFG_ORG=<org-id>      # Alternativa para org
```
