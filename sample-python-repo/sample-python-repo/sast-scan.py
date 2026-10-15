"""
sast_scan.py — AI-Powered SAST Scanner
Phase 1: AI-Augmented DevOps Lifecycle
Model  : qwen2.5-coder:0.5b (Ollama local)
Repo   : c:\\labs\\ai-devops\\sample-python-repo
"""

import os
import sys
import json
import requests
from datetime import datetime
from pathlib import Path

# ===================
# CONFIG
# ===================
OLLAMA_URL  = "http://localhost:11434/api/generate"
MODEL       = "qwen2.5-coder:0.5b"
REPO_ROOT   = Path(__file__).parent          # adjust if running from elsewhere
SCAN_EXTS   = {".py"}                        # only Python files
SKIP_DIRS   = {"__pycache__", ".git", ".venv", "venv", "node_modules"}

# Files to scan (relative to REPO_ROOT)
TARGET_FILES = [
    "app.py",
    "database/db_handler.py",
    "utils/auth.py",
]

# ===================
# SAST PROMPT TEMPLATE
# ===================
SAST_PROMPT = """You are a security-focused code reviewer performing Static Application Security Testing (SAST).

Analyze the following Python source file and identify ALL security vulnerabilities and code quality issues.

For EACH issue found, respond ONLY in valid JSON using this exact schema:
{{
  "file": "<filename>",
  "issues": [
    {{
      "id": "SAST-001",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "category": "<e.g. SQL Injection, Hardcoded Secret, Insecure Deserialization>",
      "line_range": "<e.g. 12-15 or 12>",
      "description": "<what the issue is>",
      "recommendation": "<how to fix it>",
      "code": "<fixed code>"
    }}
  ],
  "summary": {{
    "total_issues": <int>,
    "critical": <int>,
    "high": <int>,
    "medium": <int>,
    "low": <int>
  }}
}}

Focus on:
- SQL Injection
- Hardcoded credentials / secrets
- Insecure deserialization (pickle, yaml.load)
- Weak cryptography / token generation
- Missing authentication or authorization
- Debug mode enabled in production
- Bare except clauses hiding errors
- Missing input validation
- Insecure network binding
- Plaintext password storage

File: {filename}
Source code:
```python
{source_code}
```

Respond ONLY with valid JSON. No markdown, no explanation outside the JSON."""


# ===================
# HELPERS
# ===================

def collect_files(repo_root: Path, targets: list) -> list:
    """Return list of Path objects for target files that exist."""
    files = []
    for rel in targets:
        p = repo_root / rel
        if p.exists():
            files.append(p)
        else:
            print(f"  [WARN] File not found, skipping: {p}")
    return files


def read_source(filepath: Path) -> str:
    """Read source file with line numbers prepended (helps LLM cite line_range)."""
    lines = filepath.read_text(encoding="utf-8", errors="replace").splitlines()
    numbered = [f"{i+1:>4}: {line}" for i, line in enumerate(lines)]
    return "\n".join(numbered)


def ask_ollama(prompt: str) -> str:
    """Send prompt to local Ollama and return raw response text."""
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,   # low temp -> deterministic security analysis
            "num_predict": 2048,
        }
    }
    try:
        resp = requests.post(OLLAMA_URL, json=payload, timeout=120)
        resp.raise_for_status()
        return resp.json().get("response", "")
    except requests.exceptions.ConnectionError:
        print("\n[ERROR] Cannot reach Ollama. Is it running? Try: ollama serve")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("\n[ERROR] Ollama timed out. Model may be loading -- retry.")
        sys.exit(1)


def parse_json_response(raw: str, filename: str) -> dict:
    """Extract JSON from LLM response, handling markdown fences."""
    text = raw.strip()

    # Strip ```json ... ``` fences if present
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(
            line for line in lines
            if not line.strip().startswith("```")
        ).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Fallback: return a minimal structure flagging the parse failure
        return {
            "file": filename,
            "issues": [{
                "id": "SAST-PARSE-ERR",
                "severity": "INFO",
                "category": "Parse Error",
                "line_range": "N/A",
                "description": "LLM response could not be parsed as JSON.",
                "recommendation": "Review raw output in sast_report.json under raw_responses.",
                "_raw": raw[:500]
            }],
            "summary": {"total_issues": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        }


def scan_file(filepath: Path, repo_root: Path) -> dict:
    """Run SAST scan on a single file via Ollama."""
    source   = read_source(filepath)
    rel_name = str(filepath.relative_to(repo_root))
    prompt   = SAST_PROMPT.format(filename=rel_name, source_code=source)

    print(f"  -> Scanning {rel_name} ... ", end="", flush=True)
    raw    = ask_ollama(prompt)
    result = parse_json_response(raw, rel_name)
    result["file"] = rel_name
    print(f"done  ({result['summary'].get('total_issues', '?')} issues)")
    return result


# ===================
# REPORT GENERATION
# ===================
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",   # bright red
    "HIGH":     "\033[33m",   # yellow
    "MEDIUM":   "\033[93m",   # light yellow
    "LOW":      "\033[94m",   # blue
    "INFO":     "\033[37m",   # grey
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def print_report(all_results: list):
    print("\n" + "=" * 70)
    print(f"{BOLD}  SAST SCAN REPORT -- {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print("=" * 70)

    grand_total = {"total_issues": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

    for result in all_results:
        file_path = result.get("file", "unknown")
        issues    = result.get("issues", [])
        summary   = result.get("summary", {})

        print(f"\n{BOLD}File: {file_path}{RESET}")
        print(f"  Issues: {summary.get('total_issues', 0)}  |  "
              f"Critical: {summary.get('critical', 0)}  "
              f"High: {summary.get('high', 0)}  "
              f"Medium: {summary.get('medium', 0)}  "
              f"Low: {summary.get('low', 0)}")
        print()

        # Sort issues by severity
        sorted_issues = sorted(
            issues,
            key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 99)
        )

        for issue in sorted_issues:
            sev   = issue.get("severity", "INFO")
            color = SEVERITY_COLOR.get(sev, "")
            print(f"  {color}[{sev}]{RESET}  {issue.get('id', '???')} -- {issue.get('category', '')}")
            print(f"         Line   : {issue.get('line_range', '?')}")
            print(f"         Issue  : {issue.get('description', '')}")
            print(f"         Fix    : {issue.get('recommendation', '')}")
            print()

        # Accumulate totals
        for key in grand_total:
            grand_total[key] += summary.get(key, 0)

    print("=" * 70)
    print(f"{BOLD}  GRAND TOTAL{RESET}")
    print(f"  Total   : {grand_total['total_issues']}")
    print(f"  {SEVERITY_COLOR['CRITICAL']}Critical: {grand_total['critical']}{RESET}")
    print(f"  {SEVERITY_COLOR['HIGH']}High    : {grand_total['high']}{RESET}")
    print(f"  {SEVERITY_COLOR['MEDIUM']}Medium  : {grand_total['medium']}{RESET}")
    print(f"  {SEVERITY_COLOR['LOW']}Low     : {grand_total['low']}{RESET}")
    print("=" * 70)


def save_json_report(all_results: list, output_path: Path):
    report = {
        "scan_timestamp": datetime.now().isoformat(),
        "model": MODEL,
        "repo": str(REPO_ROOT),
        "files_scanned": len(all_results),
        "results": all_results,
    }
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\n  [OK] JSON report saved -> {output_path}")


# ===================
# JENKINS EXIT CODE LOGIC
# ===================

def compute_exit_code(all_results: list) -> int:
    """
    Exit codes for Jenkins:
      0 -> no issues         (green  - build passes)
      1 -> critical/high     (red    - fail build)
      2 -> medium/low only   (yellow - mark unstable)
    """
    critical = sum(r.get("summary", {}).get("critical", 0) for r in all_results)
    high     = sum(r.get("summary", {}).get("high", 0)     for r in all_results)
    medium   = sum(r.get("summary", {}).get("medium", 0)   for r in all_results)
    low      = sum(r.get("summary", {}).get("low", 0)      for r in all_results)

    if critical > 0 or high > 0:
        return 1
    if medium > 0 or low > 0:
        return 2
    return 0


# ===================
# MAIN
# ===================

def main():
    print(f"\n{BOLD}AI-Powered SAST Scanner{RESET}")
    print(f"Model  : {MODEL}")
    print(f"Repo   : {REPO_ROOT}")
    print(f"Files  : {', '.join(TARGET_FILES)}")
    print()

    # Collect files
    files = collect_files(REPO_ROOT, TARGET_FILES)
    if not files:
        print("[ERROR] No target files found. Check REPO_ROOT and TARGET_FILES.")
        sys.exit(1)

    # Scan each file
    all_results = []
    for filepath in files:
        result = scan_file(filepath, REPO_ROOT)
        all_results.append(result)

    # Print human-readable report to console
    print_report(all_results)

    # Save JSON report (for Jenkins archiving / downstream pipeline stages)
    report_path = REPO_ROOT / "sast_report.json"
    save_json_report(all_results, report_path)

    # Exit with Jenkins-compatible code
    code = compute_exit_code(all_results)
    exit_labels = {
        0: "PASSED",
        1: "FAILED  (critical/high issues found)",
        2: "UNSTABLE (medium/low issues found)",
    }
    print(f"\n  Build status : {exit_labels[code]}  (exit {code})\n")
    sys.exit(code)


if __name__ == "__main__":
    main()