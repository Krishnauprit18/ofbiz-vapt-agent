import re
from core.llm.client import OllamaClient, OllamaConnectionError


def _patch_ssl_verify(code: str) -> str:
    """
    Post-processing safety net:
    OFBiz uses self-signed certs. Any requests call that lacks verify=False will crash.
    This function ensures verify=False is present on every requests call,
    and adds urllib3 warning suppression at the top.
    """
    # Add urllib3 warning suppression at top (after imports, before first non-import line)
    suppress_block = (
        "import urllib3\n"
        "urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)\n"
    )
    if "disable_warnings" not in code:
        # Insert after the last import line
        lines = code.splitlines()
        last_import_idx = 0
        for i, line in enumerate(lines):
            if line.startswith("import ") or line.startswith("from "):
                last_import_idx = i
        lines.insert(last_import_idx + 1, suppress_block.rstrip())
        code = "\n".join(lines)

    # Patch requests.get/post/put/delete/request calls missing verify=False
    # Pattern: requests.METHOD(... ) where verify= is not already present in that call
    # Strategy: add verify=False before the closing ) of each requests call
    def add_verify(m):
        call = m.group(0)
        if "verify=" in call:
            return call  # already has it
        # Insert verify=False before the last closing paren
        return call.rstrip(")") + ", verify=False)"

    # Match single-line requests calls
    code = re.sub(
        r'requests\.(get|post|put|delete|patch|request|Session)\([^)]+\)',
        add_verify,
        code
    )
    return code

def generate_poc(vuln_description, code_context, vuln_understanding):
    """
    Generates a Python PoC script using the LLM based on the vulnerability context.
    """
    print("[*] Initializing Exploit Developer persona...")
    client = OllamaClient()

    # Pre-flight: ensure Ollama is still alive before PoC generation
    try:
        client.health_check()
    except OllamaConnectionError as e:
        print(str(e))
        print("[!] PoC generation aborted: Ollama is not running.")
        return None
    
    system_prompt = """You are an Expert Exploit Developer and Penetration Tester. Your goal is to write a working Proof of Concept (PoC) exploit in Python 3.
You must analyze the provided vulnerability description, codebase context, and the vulnerability understanding report.
Based on this information, generate a single Python script that attempts to trigger the vulnerability.

CRITICAL RULES:
- The script MUST be robust, include necessary imports (like 'requests', 'urllib3'), and handle potential connection errors.
- Target URL must be "https://localhost:8443" by default.
- OFBiz uses a SELF-SIGNED SSL certificate. You MUST add these two lines near the top of the script:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
- Every single requests call (get, post, put, etc.) MUST include verify=False. Without this the script will crash.
- If the payload contains special characters like template expressions (${...}, #{...}, <%...%> etc.) define them as raw strings r'...' or assign to variables. NEVER use f-strings for payloads.
- The script must print clear success/failure output so results can be verified.
- Output ONLY Python code enclosed in a ```python block. Zero explanations outside the code block.
"""

    prompt = f"""
### Vulnerability Description
{vuln_description}

### Codebase Context (Relevant Files)
{code_context}

### Vulnerability Understanding (Analysis)
{vuln_understanding}

Write the Python PoC script inside a ```python block to exploit this vulnerability.
"""

    print("[*] Generating PoC script with LLM...")
    try:
        response = client.analyze_vulnerability(prompt, system_prompt=system_prompt)
    except OllamaConnectionError as e:
        print(str(e))
        print("[!] PoC generation aborted: Ollama connection lost.")
        return None

    # DeepSeek-R1 wraps output in <think>...</think> — strip it first
    clean_response = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL).strip()
    # If stripping leaves nothing useful, fallback to full response
    if len(clean_response) < 50:
        clean_response = response

    # Flexible regex: handles varied spacing/newlines around fences
    python_code_match = re.search(r'```python\s*\n(.*?)\n\s*```', clean_response, re.DOTALL)

    # Fallback: sometimes DeepSeek puts code inside <think> block itself
    if not python_code_match:
        python_code_match = re.search(r'```python\s*\n(.*?)\n\s*```', response, re.DOTALL)

    if python_code_match:
        poc_code = python_code_match.group(1).strip()
    else:
        # Fallback 1: code block without 'python' label (just ``` ... ```)
        plain_match = re.search(r'```\s*\n(.*?)\n\s*```', clean_response, re.DOTALL)
        if not plain_match:
            plain_match = re.search(r'```\s*\n(.*?)\n\s*```', response, re.DOTALL)
        if plain_match:
            poc_code = plain_match.group(1).strip()
            python_code_match = plain_match  # reuse flag below
        else:
            # Fallback 2: response is raw code (starts with import/#!/usr/bin)
            stripped = clean_response.strip()
            if stripped.startswith(("import ", "#!/", "import\n", "requests", "import requests")):
                poc_code = stripped
                python_code_match = True  # truthy sentinel
            else:
                poc_code = None

    if poc_code:
        # Always patch SSL verify=False regardless of what LLM generated
        poc_code = _patch_ssl_verify(poc_code)

        with open("exploit.py", "w", encoding="utf-8") as f:
            f.write(poc_code)
        print("[*] PoC script generated and saved as 'exploit.py'.")
        return "exploit.py"
    else:
        print("[!] Failed to extract Python code from the LLM response.")
        print(f"[*] Raw response (first 500 chars): {response[:500]}")
        with open("failed_exploit_generation.md", "w") as f:
            f.write(response)
        return None
