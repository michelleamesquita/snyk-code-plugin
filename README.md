# Plugin Snyk Code — Claude Code

Plugin de segurança SAST para Claude Code.
Agrupa skill de workflow + hooks automáticos num pacote instalável.

## Estrutura

```
snyk-plugin/
├── .claude-plugin/
│   └── plugin.json                    ← manifest do plugin
├── skills/
│   └── snyk-code/
│       ├── SKILL.md                   ← workflow e instruções
│       ├── scripts/
│       │   └── parse_snyk_report.py   ← parser multi-SO
│       └── references/
│           ├── snyk-cli-reference.md
│           └── cwe-owasp-llm-mapping.md
└── hooks/
    ├── snyk-post-edit.py              ← scan após edição
    ├── snyk-pre-commit.py             ← bloqueia commit com findings
    └── snyk-stop-report.py            ← relatório ao encerrar sessão
```

## Pré-requisitos

- Claude Code CLI instalado
- Node.js v14+ e npm
- Snyk CLI: `npm install -g snyk`
- Python 3.9+
- Token Snyk configurado

## Instalar o plugin

```bash
# Via GitHub (quando publicado)
/plugin install github.com/seu-usuario/snyk-plugin

# Via diretório local (desenvolvimento)
claude --plugin-dir ./snyk-plugin
```

## Configurar hooks manualmente

Se preferir configurar os hooks manualmente, copie os arquivos para `~/.claude/hooks/` e adicione a configuração ao `~/.claude/settings.json`:

```bash
# Copiar hooks
cp hooks/*.py ~/.claude/hooks/

# Copiar skills
cp -R skills/snyk-code ~/.claude/skills/
```

Use o arquivo `settings-example.json` como referência para configurar os hooks no seu `~/.claude/settings.json`.

## Configurar token

### Linux / macOS
```bash
export SNYK_TOKEN="seu-token"
# ou
snyk auth
```

### Windows PowerShell
```powershell
$env:SNYK_TOKEN = "seu-token"
# ou
snyk auth
```

## O que o plugin faz

### Skill (`/snyk-code:snyk-code`)
Ativada automaticamente quando você menciona "snyk", "scan de segurança",
"SAST", "vulnerabilidade no código" etc. Orienta o workflow completo:
instalação, scan, interpretação do JSON/SARIF, relatório e CI/CD.

### Hook 1 — Scan pós-edição (PostToolUse)
Toda vez que o Claude edita um arquivo de código, roda `snyk code test`
naquele arquivo. Se encontrar findings críticos, injeta um aviso no
contexto do Claude para que ele corrija imediatamente.

### Hook 2 — Bloqueio de commit (PreToolUse)
Intercepta `git commit` e `git push`. Roda o Snyk com
`--severity-threshold=high`. Se houver findings críticos, o commit é
bloqueado com a lista de problemas. Para forçar mesmo assim:
`git commit --no-verify`

### Hook 3 — Relatório final (Stop)
Quando o Claude encerra a sessão, gera `snyk-security-report.md` no
diretório do projeto com todos os findings organizados por severidade,
CWE e resumo por categoria.
