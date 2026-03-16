#!/usr/bin/env python3
"""
snyk-stop-report.py — Stop Hook
Gera relatório final de segurança quando o Claude encerra a sessão.
Compatível com Linux, macOS e Windows.

Fluxo:
  Claude termina → Stop dispara → este script roda snyk no projeto
  → gera snyk-security-report.md no diretório do projeto
  → imprime resumo no terminal
"""

import json
import sys
import os
import subprocess
import platform
from pathlib import Path
from datetime import datetime
from collections import Counter


def get_snyk_cmd():
    if platform.system() == "Windows":
        for cmd in ["snyk.cmd", "snyk"]:
            if subprocess.run(
                ["where", cmd], capture_output=True
            ).returncode == 0:
                return cmd
    return "snyk"


def run_snyk_full(cwd: str) -> tuple:
    """Roda snyk code test completo (todas as severidades)."""
    snyk_cmd = get_snyk_cmd()
    token = os.environ.get("SNYK_TOKEN", "")
    if not token:
        return None, "SNYK_TOKEN não configurado."

    try:
        result = subprocess.run(
            [snyk_cmd, "code", "test", "--json"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
            cwd=cwd,
            env=os.environ.copy(),
        )
    except FileNotFoundError:
        return None, "snyk CLI não encontrado."
    except subprocess.TimeoutExpired:
        return None, "Snyk timeout (>180s)."

    if result.returncode == 2:
        return None, f"Erro: {result.stderr.strip()[:200]}"

    try:
        return json.loads(result.stdout), None
    except json.JSONDecodeError:
        return None, "Output do Snyk não é JSON válido."


def extract_findings(data: dict) -> list:
    findings = []
    for run in data.get("runs", []):
        for r in run.get("results", []):
            locs = r.get("locations", [{}])
            phys = locs[0].get("physicalLocation", {}) if locs else {}
            props = r.get("properties", {})
            findings.append({
                "rule_id":  r.get("ruleId", ""),
                "message":  r.get("message", {}).get("text", ""),
                "level":    r.get("level", "note"),
                "file":     str(Path(phys.get("artifactLocation", {}).get("uri", ""))),
                "line":     phys.get("region", {}).get("startLine", 0),
                "cwe":      props.get("cwe", []),
                "score":    props.get("priorityScore", 0),
                "autofix":  props.get("isAutofixable", False),
            })
    findings.sort(key=lambda x: x["score"], reverse=True)
    return findings


SEVERITY_LABEL = {
    "error":   "🔴 CRÍTICO/ALTO",
    "warning": "🟡 MÉDIO",
    "note":    "🔵 BAIXO",
}


def build_report(findings: list, project_name: str, cwd: str) -> str:
    now   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(findings)
    high  = sum(1 for f in findings if f["level"] == "error")
    med   = sum(1 for f in findings if f["level"] == "warning")
    low   = sum(1 for f in findings if f["level"] == "note")

    lines = [
        f"# Relatório de Segurança Snyk Code",
        f"",
        f"**Projeto:** `{project_name}`  ",
        f"**Diretório:** `{cwd}`  ",
        f"**Data:** {now}  ",
        f"**Total de findings:** {total}  ",
        f"**Críticos/Altos:** {high} | **Médios:** {med} | **Baixos:** {low}  ",
        f"",
    ]

    # Score de risco geral
    if high > 0:
        risk = "🔴 ALTO RISCO — corrija os findings críticos antes do próximo deploy."
    elif med > 0:
        risk = "🟡 RISCO MÉDIO — revise os findings antes da próxima release."
    else:
        risk = "🟢 BAIXO RISCO — nenhum finding crítico ou médio encontrado."

    lines += [f"**Status de risco:** {risk}", "", "---", ""]

    # Seções por severidade
    for level_key in ["error", "warning", "note"]:
        group = [f for f in findings if f["level"] == level_key]
        if not group:
            continue
        label = SEVERITY_LABEL[level_key]
        lines.append(f"## {label}\n")
        for i, f in enumerate(group, 1):
            cwe_str  = ", ".join(f["cwe"]) if f["cwe"] else "N/A"
            fix_str  = "✅ Sim" if f["autofix"] else "❌ Não"
            lines.append(f"### [{i}] `{f['rule_id']}` — `{f['file']}:{f['line']}`")
            lines.append(f"- **CWE:** {cwe_str}")
            lines.append(f"- **Priority Score:** {f['score']}/1000")
            lines.append(f"- **Descrição:** {f['message']}")
            lines.append(f"- **Autofixável (DeepCode AI):** {fix_str}")
            lines.append("")

    # Resumo por categoria
    rule_counts = Counter(f["rule_id"] for f in findings)
    lines += ["---", "", "## 📊 Resumo por categoria", ""]
    lines += ["| Categoria | Qtd |", "|---|---|"]
    for rule, count in rule_counts.most_common():
        lines.append(f"| `{rule}` | {count} |")

    lines += ["", "---", "", f"*Gerado automaticamente pelo hook snyk-stop-report.py*"]
    return "\n".join(lines)


def main():
    try:
        raw = sys.stdin.read()
        event = json.loads(raw) if raw.strip() else {}
    except (json.JSONDecodeError, ValueError):
        event = {}

    cwd = event.get("cwd", os.getcwd())
    project_name = Path(cwd).name

    print(f"\n[snyk-hook] Gerando relatório de segurança para `{project_name}`...",
          file=sys.stderr)

    data, error = run_snyk_full(cwd)

    if error:
        print(f"[snyk-hook] {error}", file=sys.stderr)
        sys.exit(0)

    if data is None:
        sys.exit(0)

    findings = extract_findings(data)
    report_md = build_report(findings, project_name, cwd)

    # Salvar relatório
    out_path = Path(cwd) / "snyk-security-report.md"
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(report_md)
        print(f"[snyk-hook] ✅ Relatório salvo em: {out_path}", file=sys.stderr)
    except IOError as e:
        print(f"[snyk-hook] Erro ao salvar relatório: {e}", file=sys.stderr)

    # Imprimir resumo no terminal
    high = sum(1 for f in findings if f["level"] == "error")
    med  = sum(1 for f in findings if f["level"] == "warning")
    total = len(findings)
    print(f"[snyk-hook] Total: {total} findings | 🔴 {high} críticos/altos | 🟡 {med} médios",
          file=sys.stderr)

    sys.exit(0)


if __name__ == "__main__":
    main()
