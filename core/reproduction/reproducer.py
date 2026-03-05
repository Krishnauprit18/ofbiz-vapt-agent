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

    system_prompt = """You are a penetration tester demonstrating a confirmed vulnerability in Apache OFBiz.
Generate a Python 3 exploit script that:
  1. Reproduces the vulnerability step-by-step
  2. Captures and prints CONCRETE EVIDENCE of exploitation (cookies, tokens, response bodies, file contents)
  3. Clearly shows the IMPACT — what an attacker can steal or execute

CRITICAL RULES:
- Target: https://localhost:8443  (HTTP fallback: http://localhost:18080)
- Import and use at the top:
    import urllib3, requests
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    session = requests.Session()
    session.verify = False
- Always use session.get/post (verify=False handled by session)
- Print each step with full details:
    print("="*50)
    print("STEP N: <description>")
    print(f"  → URL: <url>")
    print(f"  → Status: <status_code>")
    print(f"  → Response snippet: <first 500 chars of response>")
- After exploitation, print an IMPACT EVIDENCE block:
    print("\\n=== IMPACT EVIDENCE ===")
    print(f"Session cookies: {dict(session.cookies)}")
    print(f"Payload confirmed in response: <yes/no + what was found>")
    print(f"Attacker can: <describe impact — XSS execution, RCE, session theft, etc.>")
    print(f"Affected URL: <the URL the victim visits to trigger the exploit>")
- At the very end print exactly one of:
    RESULT: VULNERABLE
    RESULT: NOT VULNERABLE
- Output ONLY code in a ```python block. No explanations outside the block.
"""

    prompt = f"""
### Vulnerability Description
{vuln_description}

### Relevant Source Code
{code_context}

### Vulnerability Analysis
{analysis}

Write a minimal Python verification script in a ```python block.
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
