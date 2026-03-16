#!/usr/bin/env python3
"""
snyk-post-edit.py — PostToolUse Hook
Roda snyk code test no arquivo editado após cada edição do Claude.
Compatível com Linux, macOS e Windows.

Fluxo:
  Claude edita arquivo → PostToolUse dispara → este script lê stdin JSON
  → extrai o arquivo editado → roda snyk naquele arquivo
  → se findings críticos/altos: injeta aviso no contexto do Claude
  → se tudo ok: exit 0 silencioso
"""

import json
import sys
import os
import subprocess
import platform
from pathlib import Path

# Extensões de código suportadas pelo Snyk Code
SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".cs", ".go",
    ".php", ".rb", ".swift", ".kt", ".scala", ".cpp", ".c", ".h"
}

SEVERITY_EMOJI = {
    "error":   "🔴 CRÍTICO/ALTO",
    "warning": "🟡 MÉDIO",
    "note":    "🔵 BAIXO",
}


def get_snyk_cmd():
    """Retorna o comando snyk correto para o SO atual."""
    if platform.system() == "Windows":
        # No Windows, snyk pode estar como snyk.cmd
        for cmd in ["snyk.cmd", "snyk"]:
            if subprocess.run(
                ["where", cmd], capture_output=True
            ).returncode == 0:
                return cmd
    return "snyk"


def run_snyk(file_path: str) -> tuple:
    """
    Executa snyk code test no arquivo.
    Retorna (findings: list, error: str | None)
    """
    snyk_cmd = get_snyk_cmd()
    token = os.environ.get("SNYK_TOKEN", "")
    if not token:
        return [], "SNYK_TOKEN não configurado — pulando scan."

    try:
        result = subprocess.run(
            [snyk_cmd, "code", "test", file_path, "--json"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            env=os.environ.copy(),
        )
    except FileNotFoundError:
        return [], "snyk CLI não encontrado. Instale com: npm install -g snyk"
    except subprocess.TimeoutExpired:
        return [], "Snyk timeout (>60s) — arquivo grande ou problema de rede."

    # rc=0: sem findings | rc=1: findings encontrados | rc=2: erro de execução
    if result.returncode == 2:
        return [], f"Erro Snyk: {result.stderr.strip()[:200]}"

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return [], None  # sem output válido, ignora silenciosamente

    findings = []
    for run in data.get("runs", []):
        for r in run.get("results", []):
            level = r.get("level", "note")
            props = r.get("properties", {})
            findings.append({
                "rule_id":        r.get("ruleId", ""),
                "message":        r.get("message", {}).get("text", ""),
                "level":          level,
                "priority_score": props.get("priorityScore", 0),
                "cwe":            props.get("cwe", []),
                "line":           r.get("locations", [{}])[0]
                                   .get("physicalLocation", {})
                                   .get("region", {})
                                   .get("startLine", 0),
            })

    findings.sort(key=lambda x: x["priority_score"], reverse=True)
    return findings, None


def build_context_message(findings: list, file_path: str) -> str:
    """Monta a mensagem de contexto para o Claude."""
    high = [f for f in findings if f["level"] == "error"]
    med  = [f for f in findings if f["level"] == "warning"]

    lines = [f"⚠️  Snyk Code detectou vulnerabilidades em `{Path(file_path).name}`:"]
    lines.append("")

    for f in high[:3]:  # mostrar no máximo 3 críticos
        cwe = ", ".join(f["cwe"]) if f["cwe"] else "N/A"
        lines.append(f"  🔴 {f['rule_id']} — linha {f['line']}")
        lines.append(f"     {f['message'][:120]}")
        lines.append(f"     CWE: {cwe} | Score: {f['priority_score']}/1000")
        lines.append("")

    if len(high) > 3:
        lines.append(f"  ... e mais {len(high) - 3} findings críticos/altos.")
        lines.append("")

    if med:
        lines.append(f"  🟡 {len(med)} finding(s) de severidade média.")
        lines.append("")

    lines.append("💡 Considere corrigir os findings críticos antes de continuar.")
    return "\n".join(lines)


def main():
    # Ler evento JSON do stdin
    try:
        raw = sys.stdin.read()
        event = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)  # input inválido, sair silenciosamente

    tool_name = event.get("tool_name", "")

    # Só processar tools de edição de arquivo
    if tool_name not in ("Edit", "MultiEdit", "Write", "str_replace_based_edit_tool"):
        sys.exit(0)

    # Extrair caminho do arquivo
    tool_input = event.get("tool_input", {})
    file_path = tool_input.get("file_path") or tool_input.get("path", "")

    if not file_path:
        sys.exit(0)

    # Verificar se é extensão suportada
    if Path(file_path).suffix.lower() not in SUPPORTED_EXTENSIONS:
        sys.exit(0)

    # Verificar se o arquivo existe
    if not Path(file_path).exists():
        sys.exit(0)

    # Rodar Snyk
    findings, error = run_snyk(file_path)

    if error:
        # Erro não-crítico: logar no stderr e continuar
        print(f"[snyk-hook] {error}", file=sys.stderr)
        sys.exit(0)

    if not findings:
        sys.exit(0)  # tudo limpo, sair silenciosamente

    # Só alertar se houver findings críticos ou altos
    high_findings = [f for f in findings if f["level"] == "error"]
    if not high_findings:
        sys.exit(0)

    # Injetar contexto para o Claude via additionalContext
    context_msg = build_context_message(findings, file_path)

    # Imprimir no stderr para o usuário ver no terminal
    print(context_msg, file=sys.stderr)

    output = {
        "additionalContext": context_msg
    }
    print(json.dumps(output, ensure_ascii=False))
    sys.exit(0)


if __name__ == "__main__":
    main()
