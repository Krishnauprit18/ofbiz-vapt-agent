"""
OFBiz VAPT Agent — Phase 1: Vulnerability Analysis (Agentic)

Uses an iterative agent to explore the codebase and understand the vulnerability.
"""

import argparse
import json
import sys
from pathlib import Path

from core.llm.agent import CodebaseAgent


def main():
    parser = argparse.ArgumentParser(
        description="OFBiz VAPT Agent — Phase 1: Vulnerability Analysis"
    )
    parser.add_argument("description", type=str, help="Vulnerability description")
    args = parser.parse_args()

    vuln_description = args.description
    print(f"[*] Starting Phase 1 — Agentic Exploration.")

    # ── Agentic Exploration ──────────────────────────────────────────────────
    agent = CodebaseAgent()
    try:
        analysis = agent.run(vuln_description)
    except Exception as e:
        print(f"[!] Agent error: {e}")
        sys.exit(1)

    # Save results
    Path("vuln_understanding.md").write_text(analysis, encoding="utf-8")
    
    # Save the exploration history as context for Phase 2
    history_str = ""
    for msg in agent.history:
        history_str += f"\n--- {msg['role'].upper()} ---\n{msg['content']}\n"
    Path("code_context.txt").write_text(history_str, encoding="utf-8")

    # ── Save State for Phase 2 ───────────────────────────────────────────────
    state = {
        "description": vuln_description,
        "code_context_file": "code_context.txt",
        "analysis_file": "vuln_understanding.md",
    }
    Path(".vapt_state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    print(f"\n[✓] Agentic exploration complete. Analysis saved to vuln_understanding.md")

    # ── Next Steps Menu ──────────────────────────────────────────────────────
    print("\n[✓] Phase 1 Complete! Choose your next action:\n")
    print("  ┌─────────────────────────────────────────────────────────────┐")
    print("  │  python3 cli/reproduce.py --no-docker  → Reproduce & report│")
    print("  │  python3 cli/poc.py                    → PoC exploit only  │")
    print("  │  python3 cli/patch.py                  → Patch + git diff  │")
    print("  └─────────────────────────────────────────────────────────────┘")


if __name__ == "__main__":
    main()
