"""
OFBiz VAPT Agent — Phase 2a: Vulnerability Reproduction

Reads cached analysis from Phase 1, deploys OFBiz, generates a minimal
reproduction test, runs it, and produces a detailed step-by-step report.

Usage:
    python3 cli/reproduce.py --no-docker
"""

import argparse
import json
import sys
from pathlib import Path

from core.llm.client import OllamaClient, OllamaConnectionError
from core.deployment.manager import DeployManager
from core.reproduction.reproducer import reproduce_vulnerability


def main():
    parser = argparse.ArgumentParser(
        description="OFBiz VAPT Agent — Phase 2a: Reproduce Vulnerability"
    )
    parser.add_argument(
        "--no-docker", action="store_true",
        help="Skip Docker, assume OFBiz already running on port 8443"
    )
    args = parser.parse_args()

    # ── Load cached state from Phase 1 ────────────────────────────────────────
    state_file = Path(".vapt_state.json")
    if not state_file.exists():
        print("[!] No analysis found. Run Phase 1 first:")
        print("    python3 cli/analyze.py \"<vulnerability description>\"")
        sys.exit(1)

    state = json.loads(state_file.read_text(encoding="utf-8"))
    vuln_desc = state["description"]
    code_context = Path(state["code_context_file"]).read_text(encoding="utf-8")
    analysis = Path(state["analysis_file"]).read_text(encoding="utf-8")

    print(f"[*] Loaded cached analysis ({len(analysis)} chars)")
    print(f"[*] Vulnerability: {vuln_desc[:100]}...")

    # ── Ollama Pre-flight ─────────────────────────────────────────────────────
    client = OllamaClient()
    try:
        client.health_check()
        print(f"[✓] Ollama running. Model: {client.model}")
    except OllamaConnectionError as e:
        print(str(e))
        sys.exit(1)

    # ── Deploy OFBiz ──────────────────────────────────────────────────────────
    print("\n[*] Checking target deployment...")
    deployer = DeployManager(use_docker=not args.no_docker)
    if not deployer.deploy():
        print("[!] Deployment failed. Cannot reproduce without a running target.")
        sys.exit(1)

    # ── Reproduce ─────────────────────────────────────────────────────────────
    print("\n[*] Starting reproduction...")
    report = reproduce_vulnerability(client, vuln_desc, code_context, analysis)

    Path("reproduction_report.md").write_text(report, encoding="utf-8")
    print(f"\n[✓] Reproduction report saved to reproduction_report.md")

    print("\n" + "=" * 60)
    print("REPRODUCTION REPORT")
    print("=" * 60)
    print(report[:1500] + "\n..." if len(report) > 1500 else report)
    print("=" * 60)


if __name__ == "__main__":
    main()
