import argparse
import sys
from pathlib import Path

from core.llm.client import OllamaClient, OllamaConnectionError, get_analysis
from core.codebase.retriever import get_code_context
from core.reproduction.poc_generator import generate_poc
from core.reproduction.executor import run_exploit
from core.deployment.manager import DeployManager

def main():
    parser = argparse.ArgumentParser(description="OFBiz VAPT Agent Input CLI")
    parser.add_argument("description", type=str, help="Vulnerability description as a string")
    parser.add_argument("--no-docker", action="store_true", help="Run in Manual Mode (No Docker, checks for existing OFBiz port 8443)")

    args = parser.parse_args()
    vuln_description = args.description
    print(f"[*] Input received.")

    # ── Phase 0: Ollama Pre-flight Check ──────────────────────────────────────
    client = OllamaClient()
    try:
        client.health_check()
        print(f"[✓] Ollama is running. Model: {client.model}")
    except OllamaConnectionError as e:
        print(str(e))
        print("[!] Aborting: Ollama must be running before starting analysis.")
        sys.exit(1)

    # ── Phase 1: Codebase Context Retrieval ───────────────────────────────────
    print(f"[*] Retrieving codebase context (Searching for files referenced in description)...")
    code_context = get_code_context(vuln_description)

    # ── Phase 2: LLM Analysis ─────────────────────────────────────────────────
    print(f"[*] Starting LLM analysis with {client.model} (using local code context)...")
    try:
        analysis_result = client.analyze_vulnerability(vuln_description, code_context)
    except OllamaConnectionError as e:
        print(str(e))
        print("[!] Aborting: LLM analysis failed.")
        sys.exit(1)

    # ── Phase 3: Save & Validate Analysis Output ──────────────────────────────
    output_file = Path("vuln_understanding.md")
    try:
        output_file.write_text(analysis_result, encoding="utf-8")
        print(f"[*] Analysis complete! Result saved to: {output_file}")
    except Exception as e:
        print(f"[!] Error saving analysis: {e}")
        sys.exit(1)

    print("-" * 50)
    print("Vulnerability Understanding Preview:")
    print("-" * 50)
    print(analysis_result[:500] + "..." if len(analysis_result) > 500 else analysis_result)
    print("-" * 50)

    # ── Phase 4: Target Deployment ────────────────────────────────────────────
    print("\n[*] Starting Target Deployment Phase...")
    deployer = DeployManager(use_docker=not args.no_docker)
    if not deployer.deploy():
        print("[!] Aborting exploitation due to deployment failure.")
        sys.exit(1)

    # ── Phase 5: PoC Generation & Execution ───────────────────────────────────
    print("\n[*] Starting Vulnerability Reproduction Phase (Auto-Exploitation)...")
    poc_script_path = generate_poc(vuln_description, code_context, analysis_result)

    if poc_script_path:
        run_exploit(poc_script_path)
    else:
        print("[!] Reproduction phase aborted due to PoC generation failure.")

if __name__ == "__main__":
    main()
