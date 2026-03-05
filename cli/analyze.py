"""
OFBiz VAPT Agent — Phase 1: Vulnerability Analysis

Analyzes the vulnerability using the actual OFBiz codebase and an LLM.
Saves results so Phase 2 commands can pick up without re-running analysis.

Usage:
    python3 cli/analyze.py "vulnerability description here"

After this completes, choose one:
    python3 cli/reproduce.py --no-docker   → Reproduce + detailed report
    python3 cli/poc.py                     → Generate PoC exploit only
    python3 cli/patch.py                   → Generate security patch
"""

import argparse
import json
import sys
from pathlib import Path

from core.llm.client import OllamaClient, OllamaConnectionError
from core.codebase.retriever import get_code_context


def main():
    parser = argparse.ArgumentParser(
        description="OFBiz VAPT Agent — Phase 1: Vulnerability Analysis"
    )
    parser.add_argument("description", type=str, help="Vulnerability description")
    args = parser.parse_args()

    vuln_description = args.description
    print(f"[*] Input received. Starting Phase 1 — Analysis Only.")

    # ── Ollama Pre-flight ─────────────────────────────────────────────────────
    client = OllamaClient()
    try:
        client.health_check()
        print(f"[✓] Ollama is running. Model: {client.model}")
    except OllamaConnectionError as e:
        print(str(e))
        sys.exit(1)

    # ── Step 1: Codebase Context Retrieval ────────────────────────────────────
    print("[*] Retrieving codebase context...")
    code_context = get_code_context(vuln_description)

    # Save code context for Phase 2 commands
    Path("code_context.txt").write_text(code_context, encoding="utf-8")
    print(f"[✓] Code context saved ({len(code_context)} chars)")

    # ── Step 2: LLM Analysis ─────────────────────────────────────────────────
    print(f"[*] Starting LLM analysis with {client.model}...")
    try:
        analysis = client.analyze_vulnerability(vuln_description, code_context)
    except OllamaConnectionError as e:
        print(str(e))
        sys.exit(1)

    Path("vuln_understanding.md").write_text(analysis, encoding="utf-8")
    print(f"[✓] Analysis saved to vuln_understanding.md")

    # ── Save State for Phase 2 ───────────────────────────────────────────────
    state = {
        "description": vuln_description,
        "code_context_file": "code_context.txt",
        "analysis_file": "vuln_understanding.md",
    }
    Path(".vapt_state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    # ── Preview ──────────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("VULNERABILITY ANALYSIS REPORT")
    print("=" * 60)
    print(analysis[:800] + "\n..." if len(analysis) > 800 else analysis)
    print("=" * 60)

    # ── Next Steps Menu ──────────────────────────────────────────────────────
    print("\n[✓] Phase 1 Complete! Choose your next action:\n")
    print("  ┌─────────────────────────────────────────────────────────────┐")
    print("  │  python3 cli/reproduce.py --no-docker  → Reproduce & report│")
    print("  │  python3 cli/poc.py                    → PoC exploit only  │")
    print("  │  python3 cli/patch.py                  → Patch + git diff  │")
    print("  └─────────────────────────────────────────────────────────────┘")


if __name__ == "__main__":
    main()
