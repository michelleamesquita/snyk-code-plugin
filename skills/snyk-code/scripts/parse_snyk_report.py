#!/usr/bin/env python3
"""
parse_snyk_report.py
Parse do JSON gerado por `snyk code test --json` com suporte a Linux, macOS e Windows.

Uso:
  Linux/macOS:  python3 scripts/parse_snyk_report.py snyk-report.json
  Windows:      python  scripts\parse_snyk_report.py snyk-report.json

Flags:
  --output / -o    Salvar relatório em arquivo Markdown
  --min-severity   low | medium | high | critical (default: low)
"""

import json
import sys
import argparse
import os
import platform
from datetime import datetime
from pathlib import Path
from collections import Counter

# -------------------------------------------------------------------
# Compatibilidade de encoding para Windows (CMD/PowerShell antigo)
# -------------------------------------------------------------------
if platform.system() == "Windows":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

SEVERITY_MAP = {
    "error":   ("CRITICO/ALTO", 3),
    "warning": ("MEDIO",        2),
    "note":    ("BAIXO",        1),
}

SEVERITY_THRESHOLD = {
    "low":      1,
    "medium":   2,
    "high":     3,
    "critical": 3,
}


def normalize_path(uri: str) -> str:
    """Normaliza separadores de path para o SO atual."""
    return str(Path(uri))


def load_report(path: str) -> dict:
    """Carrega o JSON com fallback de encoding para Windows."""
    fpath = Path(path)
    if not fpath.exists():
        print(f"ERRO: Arquivo nao encontrado: {path}", file=sys.stderr)
        sys.exit(1)

    # Tentar UTF-8 primeiro, fallback para UTF-8-BOM (gerado pelo PowerShell)
    for enc in ("utf-8", "utf-8-sig", "utf-16"):
        try:
            with open(fpath, "r", encoding=enc) as f:
                content = f.read()
            return json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue

    print("ERRO: Nao foi possivel decodificar o JSON. "
          "No Windows/PowerShell, use: snyk code test --json | Out-File -Encoding utf8 snyk-report.json",
          file=sys.stderr)
    sys.exit(1)


def extract_findings(data: dict) -> list:
    findings = []
    runs = data.get("runs", [])
    for run in runs:
        for result in run.get("results", []):
            level = result.get("level", "note")
            location = {"file": "", "line": 0, "col": 0}
            locs = result.get("locations", [])
            if locs:
                phys = locs[0].get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri", "")
                location = {
                    "file": normalize_path(uri),
                    "line": phys.get("region", {}).get("startLine", 0),
                    "col":  phys.get("region", {}).get("startColumn", 0),
                }
            props = result.get("properties", {})
            findings.append({
                "rule_id":       result.get("ruleId", ""),
                "message":       result.get("message", {}).get("text", ""),
                "level":         level,
                "priority_score": props.get("priorityScore", 0),
                "cwe":           props.get("cwe", []),
                "autofixable":   props.get("isAutofixable", False),
                **location,
            })
    findings.sort(key=lambda x: x["priority_score"], reverse=True)
    return findings


def filter_by_severity(findings: list, min_severity: str) -> list:
    min_level = SEVERITY_THRESHOLD.get(min_severity, 1)
    return [f for f in findings if SEVERITY_MAP.get(f["level"], ("", 1))[1] >= min_level]


def build_report(findings: list, project_name: str) -> str:
    lines = []
    now   = datetime.now().strftime("%Y-%m-%d %H:%M")
    total = len(findings)
    high  = sum(1 for f in findings if f["level"] == "error")

    lines.append(f"# Relatorio Snyk Code - {project_name}")
    lines.append(f"Data: {now} | Total de issues: {total} | Criticos/Altos: {high}")
    lines.append("")

    grouped = {"error": [], "warning": [], "note": []}
    for f in findings:
        grouped.setdefault(f["level"], []).append(f)

    for level_key in ["error", "warning", "note"]:
        label, _ = SEVERITY_MAP.get(level_key, ("Outros", 0))
        group = grouped.get(level_key, [])
        if not group:
            continue
        lines.append(f"---\n### {label}\n")
        for i, f in enumerate(group, 1):
            cwe_str = ", ".join(f["cwe"]) if f["cwe"] else "N/A"
            fix_str = "Sim" if f["autofixable"] else "Nao"
            file_loc = f"{f.get('file', '')}:{f.get('line', '')}"
            lines.append(f"#### [{i}] {f['rule_id']} -- {file_loc}")
            lines.append(f"- CWE: {cwe_str}")
            lines.append(f"- Priority Score: {f['priority_score']}/1000")
            lines.append(f"- Descricao: {f['message']}")
            lines.append(f"- Autofixavel (Snyk DeepCode AI): {fix_str}")
            lines.append("")

    rule_counts = Counter(f["rule_id"] for f in findings)
    lines.append("---\n### Resumo por categoria\n")
    lines.append("| Categoria | Qtd |")
    lines.append("|---|---|")
    for rule, count in rule_counts.most_common():
        lines.append(f"| {rule} | {count} |")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Parse Snyk Code JSON report (Linux, macOS, Windows)"
    )
    parser.add_argument("report", help="Caminho para snyk-report.json")
    parser.add_argument("--output", "-o", help="Salvar relatorio em arquivo Markdown")
    parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Severidade minima (default: low)",
    )
    args = parser.parse_args()

    print(f"[INFO] Sistema: {platform.system()} {platform.release()}")
    print(f"[INFO] Python:  {sys.version.split()[0]}")
    print(f"[INFO] Arquivo: {args.report}")
    print()

    data     = load_report(args.report)
    findings = extract_findings(data)
    findings = filter_by_severity(findings, args.min_severity)

    project_name = Path(args.report).stem
    report_md    = build_report(findings, project_name)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(report_md)
        print(f"[OK] Relatorio salvo em: {out_path.resolve()}")
    else:
        print(report_md)


if __name__ == "__main__":
    main()
