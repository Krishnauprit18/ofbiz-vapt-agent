"""
OFBiz VAPT Agent — Phase 2b: PoC Generation Only

Reads cached analysis from Phase 1 and generates an exploit PoC script.
Does NOT execute it — user reviews and runs manually.

Usage:
    python3 cli/poc.py
"""

import json
import sys
from pathlib import Path

from core.reproduction.poc_generator import generate_poc


def main():
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
    print(f"[*] Generating PoC only (will NOT execute)...\n")

    # ── Generate PoC ──────────────────────────────────────────────────────────
    poc_path = generate_poc(vuln_desc, code_context, analysis)

    if poc_path:
        print(f"\n[✓] PoC saved to: {poc_path}")
        print("[*] Review it, then run manually:")
        print(f"    python3 {poc_path}")

        # Show the generated code
        code = Path(poc_path).read_text(encoding="utf-8")
        print(f"\n{'=' * 60}")
        print("GENERATED EXPLOIT")
        print(f"{'=' * 60}")
        print(code)
        print(f"{'=' * 60}")
    else:
        print("[!] PoC generation failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
