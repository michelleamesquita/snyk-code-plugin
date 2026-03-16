#!/usr/bin/env python3
"""
snyk-pre-commit.py — PreToolUse Hook
Intercepta `git commit` e bloqueia se houver findings críticos/altos.
Compatível com Linux, macOS e Windows.

Fluxo:
  Claude tenta git commit → PreToolUse dispara → este script lê stdin JSON
  → verifica se é git commit → roda snyk no projeto atual
  → findings altos? → BLOQUEIA (exit 2) com mensagem clara
  → tudo ok?        → permite (exit 0)
"""

import json
import sys
import os
import subprocess
import platform
from pathlib import Path


def get_snyk_cmd():
    if platform.system() == "Windows":
        for cmd in ["snyk.cmd", "snyk"]:
            if subprocess.run(
                ["where", cmd], capture_output=True
            ).returncode == 0:
                return cmd
    return "snyk"


def is_git_commit(command: str) -> bool:
    """Verifica se o comando bash é um git commit."""
    cmd = command.strip().lower()
    return (
        cmd.startswith("git commit")
        or "git commit" in cmd
        or cmd.startswith("git push")  # também bloquear push direto
    )


def run_snyk_project(cwd: str) -> tuple:
    """
    Roda snyk code test no projeto inteiro com threshold=high.
    Retorna (high_count: int, findings: list, error: str | None)
    """
    snyk_cmd = get_snyk_cmd()
    token = os.environ.get("SNYK_TOKEN", "")
    if not token:
        return 0, [], "SNYK_TOKEN não configurado — commit permitido sem scan."

    try:
        result = subprocess.run(
            [
                snyk_cmd, "code", "test",
                "--severity-threshold=high",
                "--json",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            cwd=cwd,
            env=os.environ.copy(),
        )
    except FileNotFoundError:
        return 0, [], "snyk CLI não encontrado. Instale com: npm install -g snyk"
    except subprocess.TimeoutExpired:
        return 0, [], "Snyk timeout (>120s)."

    if result.returncode == 2:
        return 0, [], f"Erro Snyk: {result.stderr.strip()[:200]}"

    if result.returncode == 0:
        return 0, [], None  # nenhum finding acima do threshold

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return 0, [], None

    findings = []
    for run in data.get("runs", []):
        for r in run.get("results", []):
            if r.get("level") == "error":
                locs = r.get("locations", [{}])
                phys = locs[0].get("physicalLocation", {}) if locs else {}
                props = r.get("properties", {})
                findings.append({
                    "rule_id": r.get("ruleId", ""),
                    "message": r.get("message", {}).get("text", ""),
                    "file":    phys.get("artifactLocation", {}).get("uri", ""),
                    "line":    phys.get("region", {}).get("startLine", 0),
                    "cwe":     props.get("cwe", []),
                    "score":   props.get("priorityScore", 0),
                })

    findings.sort(key=lambda x: x["score"], reverse=True)
    return len(findings), findings, None


def build_block_message(findings: list, count: int) -> str:
    lines = [
        f"🚫 COMMIT BLOQUEADO — Snyk Code encontrou {count} finding(s) crítico(s)/alto(s).",
        "",
        "Corrija os seguintes problemas antes de fazer commit:",
        "",
    ]
    for i, f in enumerate(findings[:5], 1):
        cwe = ", ".join(f["cwe"]) if f["cwe"] else "N/A"
        lines.append(f"  [{i}] {f['rule_id']} — {f['file']}:{f['line']}")
        lines.append(f"       {f['message'][:120]}")
        lines.append(f"       CWE: {cwe} | Score: {f['score']}/1000")
        lines.append("")
    if count > 5:
        lines.append(f"  ... e mais {count - 5} finding(s).")
        lines.append("")
    lines.append("💡 Execute `snyk code test` para ver o relatório completo.")
    lines.append("   Para forçar o commit mesmo assim: git commit --no-verify")
    return "\n".join(lines)


def main():
    try:
        raw = sys.stdin.read()
        event = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)

    tool_name = event.get("tool_name", "")

    # Só processar tool Bash
    if tool_name != "Bash":
        sys.exit(0)

    command = event.get("tool_input", {}).get("command", "")
    if not is_git_commit(command):
        sys.exit(0)

    # Diretório de trabalho da sessão
    cwd = event.get("cwd", os.getcwd())

    count, findings, error = run_snyk_project(cwd)

    if error:
        # Erro não-crítico: avisar mas não bloquear
        print(f"[snyk-hook] Aviso: {error}", file=sys.stderr)
        sys.exit(0)

    if count == 0:
        # Tudo limpo — permitir commit
        output = {
            "additionalContext": "✅ Snyk Code: nenhum finding crítico/alto. Commit permitido."
        }
        print(json.dumps(output, ensure_ascii=False))
        sys.exit(0)

    # Findings críticos — BLOQUEAR
    block_msg = build_block_message(findings, count)
    output = {
        "hookSpecificOutput": {
            "hookEventName":            "PreToolUse",
            "permissionDecision":       "deny",
            "permissionDecisionReason": block_msg,
        }
    }
    print(json.dumps(output, ensure_ascii=False))
    sys.exit(0)


if __name__ == "__main__":
    main()
