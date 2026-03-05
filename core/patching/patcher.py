"""
Security Patch Generator

Uses the LLM to generate a unified diff patch that fixes the vulnerability.
Attempts to apply it to the OFBiz codebase and outputs a clean git diff.
"""

import os
import re
import subprocess
from pathlib import Path

from core.llm.client import OllamaClient, OllamaConnectionError


def generate_patch(vuln_description, code_context, analysis):
    """
    Generates a security patch for the described vulnerability.
    Returns the path to the patch file, or None on failure.
    """
    print("[*] Initializing Patch Generator...")
    client = OllamaClient()

    try:
        client.health_check()
        print(f"[✓] Ollama running. Model: {client.model}")
    except OllamaConnectionError as e:
        print(str(e))
        return None

    codebase_path = os.environ.get(
        "OFBIZ_CODEBASE_PATH", "/home/krishna/Pictures/ofbiz-framework"
    )

    system_prompt = """You are a Senior Security Engineer fixing a vulnerability in Apache OFBiz.
Generate a PATCH in unified diff format that fixes the described vulnerability.

CRITICAL RULES:
- Output the patch in unified diff format (like `git diff` output)
- File paths must be relative to the OFBiz root, prefixed with a/ and b/
  Example: a/framework/webapp/src/main/java/org/apache/ofbiz/webapp/control/RequestHandler.java
- Only change what is NECESSARY — minimal, focused fix
- Add a brief comment at the fix point explaining what was fixed
- The patch must produce valid, compilable Java code
- Output ONLY the diff inside a ```diff block. No explanations outside it.
"""

    prompt = f"""
### Vulnerability Description
{vuln_description}

### Affected Source Code (from OFBiz codebase)
{code_context}

### Vulnerability Analysis
{analysis}

Generate a unified diff patch that fixes this vulnerability. Use ```diff block.
"""

    print("[*] Generating patch with LLM...")
    try:
        response = client.analyze_vulnerability(prompt, system_prompt=system_prompt)
    except OllamaConnectionError as e:
        print(str(e))
        return None

    # Strip DeepSeek-R1 think tags
    clean = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL).strip()
    if len(clean) < 50:
        clean = response

    # Extract diff block
    match = re.search(r'```diff\s*\n(.*?)\n\s*```', clean, re.DOTALL)
    if not match:
        # Try ```patch or plain ``` block with diff-like content
        match = re.search(r'```(?:patch)?\s*\n(---\s+.*?\n\+\+\+.*?(?:\n.*?)*?)\n\s*```', clean, re.DOTALL)
    if not match:
        # Try raw diff content (no fences)
        match = re.search(r'(---\s+a/.*?\n\+\+\+\s+b/.*?\n@@.*)', clean, re.DOTALL)

    if not match:
        print("[!] Could not extract diff from LLM response.")
        print(f"[*] Raw response (first 500 chars):\n{response[:500]}")
        Path("failed_patch.md").write_text(response, encoding="utf-8")
        print("[*] Full response saved to failed_patch.md")
        return None

    diff_content = match.group(1).strip()

    patch_file = "security_fix.patch"
    Path(patch_file).write_text(diff_content + "\n", encoding="utf-8")
    print(f"[✓] Patch written to {patch_file}")

    # ── Try to apply ──────────────────────────────────────────────────────────
    print(f"[*] Checking if patch applies cleanly to {codebase_path}...")

    check_result = subprocess.run(
        ["git", "apply", "--check", patch_file],
        cwd=codebase_path,
        capture_output=True, text=True
    )

    if check_result.returncode == 0:
        # Apply for real
        apply_result = subprocess.run(
            ["git", "apply", patch_file],
            cwd=codebase_path,
            capture_output=True, text=True
        )
        if apply_result.returncode == 0:
            print("[✓] Patch applied successfully to OFBiz codebase!")

            # Generate clean git diff
            diff_result = subprocess.run(
                ["git", "diff"],
                cwd=codebase_path,
                capture_output=True, text=True
            )
            if diff_result.stdout:
                Path(patch_file).write_text(diff_result.stdout, encoding="utf-8")
                print(f"[✓] Clean git diff saved to {patch_file}")

            # Revert so codebase stays clean (user can apply manually)
            subprocess.run(
                ["git", "checkout", "."],
                cwd=codebase_path,
                capture_output=True
            )
            print("[*] Codebase reverted. Apply with: git apply security_fix.patch")
        else:
            print(f"[!] Apply failed: {apply_result.stderr[:300]}")
    else:
        print(f"[!] Patch does not apply cleanly: {check_result.stderr[:300]}")
        print("[*] The LLM-generated patch may need manual adjustment.")
        print(f"[*] Raw patch saved to {patch_file} for manual review.")

    return patch_file
