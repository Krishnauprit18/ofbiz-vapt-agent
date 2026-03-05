"""
Vulnerability Reproducer

Generates a MINIMAL reproduction test case via LLM, executes it against
a running OFBiz instance, and builds a detailed step-by-step report
with HTTP requests, responses, and evidence.
"""

import re
import subprocess

from core.llm.client import OllamaConnectionError
from core.reproduction.poc_generator import _patch_ssl_verify


def reproduce_vulnerability(client, vuln_description, code_context, analysis):
    """
    Generates a simple reproduction test, runs it, and returns a Markdown report.
    """
    print("[*] Generating minimal reproduction test case...")

    system_prompt = """You are a penetration tester writing a BLACK-BOX HTTP exploit script in Python 3.

ABSOLUTE RULES — VIOLATION WILL BREAK THE SCRIPT:
- This is a NETWORK exploit. You send HTTP requests to a running server. You do NOT import Java classes.
- NEVER import anything from 'com.*', 'org.*', 'java.*', or any Java package. Those are Java — not Python.
- ONLY use standard Python libraries: requests, urllib3, os, re, sys, time, pathlib, io, struct
- The server is already running. You only interact with it via HTTP.

REQUIRED SCRIPT STRUCTURE:
```python
import requests, urllib3, os, sys
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
session.verify = False

BASE = "https://localhost:8443"   # OFBiz default HTTPS port (verify=False handles self-signed cert)

# STEP 1: Login as admin
print("="*50)
print("STEP 1: Login to OFBiz as admin")
r = session.post(f"{BASE}/catalog/control/login",
    data={"USERNAME": "admin", "PASSWORD": "ofbiz", "JavaScriptEnabled": "Y"})
print(f"  → Status: {r.status_code}")
print(f"  → Cookies: {dict(session.cookies)}")

# STEP 2: <do the exploit>
...

# At the end:
print("\\n=== IMPACT EVIDENCE ===")
print(f"Session cookies: {dict(session.cookies)}")
print(f"Payload confirmed: <yes/no and what was found>")
print(f"Attacker can: <describe XSS/RCE/data theft impact>")
print(f"Affected URL: <URL victim visits to trigger exploit>")
print("RESULT: VULNERABLE")   # or RESULT: NOT VULNERABLE
```

For THIS specific XSS vulnerability, the exploit flow is:
1. POST https://localhost:8443/catalog/control/login → get session cookies
2. Upload a polyglot file (JPEG + HTML payload) with filename ending in .htm via multipart POST to https://localhost:8443/catalog/control/UploadProductImage?productId=<id>&up_load_file_type=original
3. GET https://localhost:8443/images/products/<productId>/original.htm → check if HTML payload is present in response
4. Print the response body snippet showing the XSS payload survived

Output ONLY the Python code in a ```python block.
"""

    prompt = f"""
### Vulnerability Description
{vuln_description}

### Relevant Source Code (READ THIS — understand HOW the server processes requests)
{code_context[:6000]}

### Vulnerability Analysis
{analysis[:2000]}

### Your Task
Write a Python 3 HTTP exploit script that:
1. Sends HTTP requests to https://localhost:8443 (the running OFBiz server, verify=False for self-signed cert)
2. Reproduces the vulnerability described above
3. Captures concrete evidence (response body, cookies, file content served back)

REMINDER: Pure Python HTTP client only. NO Java imports. Use requests.Session() with session.verify = False.
Output ONLY a ```python code block.
"""

    try:
        response = client.analyze_vulnerability(prompt, system_prompt=system_prompt)
    except OllamaConnectionError as e:
        return _error_report(vuln_description, f"Ollama error: {e}")

    # Extract code (same logic as poc_generator)
    clean = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL).strip()
    if len(clean) < 50:
        clean = response

    match = re.search(r'```python\s*\n(.*?)\n\s*```', clean, re.DOTALL)
    if not match:
        match = re.search(r'```python\s*\n(.*?)\n\s*```', response, re.DOTALL)
    if not match:
        match = re.search(r'```\s*\n(.*?)\n\s*```', clean, re.DOTALL)
    if not match:
        return _error_report(
            vuln_description,
            f"Could not extract test code from LLM.\n\nRaw response:\n{response[:1000]}"
        )

    test_code = _patch_ssl_verify(match.group(1).strip())

    # Safety check: reject if LLM hallucinated Java imports
    java_import = re.search(r'^\s*(?:from|import)\s+(?:com|org|java|javax)\.', test_code, re.MULTILINE)
    if java_import:
        return _error_report(
            vuln_description,
            f"LLM generated Java imports in Python script (e.g. `{java_import.group(0).strip()}`). "
            "This is invalid Python. Please re-run reproduction — the model needs to generate "
            "pure HTTP requests using the `requests` library only."
        )

    # Save test
    test_file = "repro_test.py"
    with open(test_file, "w", encoding="utf-8") as f:
        f.write(test_code)
    print(f"[✓] Test saved as {test_file}")

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
        print(f"[stderr] {stderr[:500]}")

    # Determine verdict
    upper_out = stdout.upper()
    if "RESULT: VULNERABLE" in upper_out or "VULNERABLE: YES" in upper_out:
        verdict = "VULNERABLE — Confirmed"
        verdict_icon = "🔴"
    elif "RESULT: NOT VULNERABLE" in upper_out or "VULNERABLE: NO" in upper_out:
        verdict = "NOT VULNERABLE"
        verdict_icon = "🟢"
    else:
        verdict = "INCONCLUSIVE — Review output manually"
        verdict_icon = "🟡"

    # Extract IMPACT EVIDENCE block from stdout if present
    impact_block = ""
    if "=== IMPACT EVIDENCE ===" in stdout:
        impact_start = stdout.index("=== IMPACT EVIDENCE ===")
        impact_raw = stdout[impact_start:]
        result_match = re.search(r'\nRESULT:', impact_raw)
        impact_block = impact_raw[:result_match.start()].strip() if result_match else impact_raw.strip()

    # Build report
    report = f"""# Vulnerability Reproduction Report

## Verdict: {verdict_icon} {verdict}

## Vulnerability
{vuln_description}

## Impact Evidence
{impact_block if impact_block else "_No structured impact block — see full output below._"}

## Reproduction Test Script
```python
{test_code}
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
    """Returns a failure report when reproduction could not proceed."""
    return f"""# Vulnerability Reproduction Report

## Verdict: ❌ FAILED

## Vulnerability
{vuln_description}

## Error
{error_msg}

## Recommendation
- Check that Ollama is running
- Check that OFBiz is accessible at https://localhost:8443
- Re-run Phase 1 analysis if needed
"""
