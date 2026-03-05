"""
OFBiz VAPT Agent — Phase 2c: Security Patch Generation

Reads cached analysis from Phase 1, generates a security patch via LLM,
attempts to apply it to the OFBiz codebase, and outputs a git diff file.

Usage:
    python3 cli/patch.py
"""

import json
import sys
from pathlib import Path

from core.patching.patcher import generate_patch


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
    print(f"[*] Generating security patch...\n")

    # ── Generate Patch ────────────────────────────────────────────────────────
    patch_file = generate_patch(vuln_desc, code_context, analysis)

    if patch_file:
        print(f"\n[✓] Patch saved to: {patch_file}")
        print(f"[*] Apply manually: git apply {patch_file}")

        patch_content = Path(patch_file).read_text(encoding="utf-8")
        print(f"\n{'=' * 60}")
        print("GENERATED PATCH")
        print(f"{'=' * 60}")
        print(patch_content[:3000] + "\n..." if len(patch_content) > 3000 else patch_content)
        print(f"{'=' * 60}")
    else:
        print("[!] Patch generation failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
