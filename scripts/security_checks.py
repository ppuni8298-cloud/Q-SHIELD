"""Automated Q-SHIELD static & security check suite (REQ-SEC-001, REQ-SEC-002)."""

from __future__ import annotations

import ast
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def run_security_checks() -> int:
    issues: list[str] = []

    # 1. Zero AI/ML imports across backend/ and track4_service.py
    banned = {
        "sklearn", "scikit-learn", "torch", "tensorflow", "keras", "transformers",
        "openai", "anthropic", "google.generativeai", "google.genai", "xgboost",
        "lightgbm", "catboost", "spacy", "nltk", "scipy", "statsmodels",
        "langchain", "llama_index",
    }
    py_files = list((ROOT / "backend").rglob("*.py")) + [ROOT / "track4_service.py"]
    for pf in py_files:
        tree = ast.parse(pf.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            mods = []
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods = [node.module]
            for mod in mods:
                if mod in banned or mod.split(".")[0] in banned:
                    issues.append(f"AI_ML_IMPORT: {pf}: {mod}")

    # 2. Adapter isolation check (track4_service.py imports only stdlib + pqcrypto)
    adapter_tree = ast.parse((ROOT / "track4_service.py").read_text(encoding="utf-8"))
    allowed_3p = {"pqcrypto"}
    stdlib_names = getattr(sys, "stdlib_module_names", set())
    for node in ast.walk(adapter_tree):
        top = None
        if isinstance(node, ast.Import):
            for a in node.names:
                top = a.name.split(".")[0]
                if top not in stdlib_names and top not in allowed_3p:
                    issues.append(f"ADAPTER_FORBIDDEN_IMPORT: {top}")
        elif isinstance(node, ast.ImportFrom) and node.module:
            top = node.module.split(".")[0]
            if top not in stdlib_names and top not in allowed_3p:
                issues.append(f"ADAPTER_FORBIDDEN_IMPORT: {top}")

    # 3. Secret / Private key leakage scan
    secret_patterns = [
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        re.compile(r"sk-[A-Za-z0-9]{20,}"),
        re.compile(r"AKIA[0-9A-Z]{16}"),
    ]
    for folder in ("backend/app", "docs", "scripts", "datasets"):
        d = ROOT / folder
        if not d.exists():
            continue
        for f in d.rglob("*"):
            if f.is_file() and f.suffix in {".py", ".md", ".csv", ".ini", ".jsonl", ".sh", ".json"}:
                txt = f.read_text(encoding="utf-8", errors="ignore")
                for pat in secret_patterns:
                    if pat.search(txt):
                        issues.append(f"SECRET_LEAK: {f}: {pat.pattern}")

    # 4. Validate root threat-model.json structure
    tm = json.loads((ROOT / "threat-model.json").read_text(encoding="utf-8"))
    if tm.get("ai_ml_runtime") is not False or tm.get("adapter_entrypoint") != "track4_service.py":
        issues.append("THREAT_MODEL_JSON_MISMATCH")

    if issues:
        for i in issues:
            print("FAIL:", i)
        return 1
    print("SECURITY_CHECKS_PASS: zero AI/ML imports, adapter stdlib+pqcrypto only, zero leaked secrets, threat-model.json valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_security_checks())
