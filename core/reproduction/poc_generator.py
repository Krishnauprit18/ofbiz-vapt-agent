import re
from core.llm.client import OllamaClient, OllamaConnectionError

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
- The script MUST be robust, include necessary imports (like 'requests'), and handle potential connection errors or SSL warnings.
- Target URL must be "https://localhost:8443" by default.
- ALL payload strings containing curly braces like FreeMarker tags (${...}) MUST be defined as raw strings: r'...' or use a variable. NEVER use f-strings for payloads.
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
