import subprocess
import os
import sys

# Environment Setup for Kaggle
env = os.environ.copy()
env['OFBIZ_CODEBASE_PATH'] = '/kaggle/working/ofbiz-framework'
env['PYTHONPATH'] = '/kaggle/working/ofbiz-vapt-agent'
agent_dir = '/kaggle/working/ofbiz-vapt-agent'

# Vulnerability to Analyze
vuln_desc = (
    "Apache OFBiz Stored XSS via image upload extension bypass in Catalog Manager - CVE-2024-XXXX. "
    "The UploadProductImage endpoint in the /catalog webapp constructs the upload destination directory "
    "using user-supplied productId and up_load_file_type parameters. Directory creation via mkdirs() "
    "occurs before filename validation in SecuredUpload.isValidFileName(), allowing arbitrary directory "
    "traversal side effects. The final output filename extension is taken from the client-supplied "
    "filename= multipart parameter without re-validation at rename time, allowing prohibited extensions "
    "such as .htm and .jsp to be written. The image sanitization routine overwrites but does not truncate "
    "the file, so polyglot JPEG payloads with appended HTML fragments persist, and files like "
    "original.htm under /images/ are served as text/html triggering Stored XSS. "
    "Affected files: SecuredUpload.java, ImageUpload.groovy, UploadContentAndImage.java, DataServices.java"
)

def run_analysis():
    print(f"[*] Launching Agentic Analysis (Phase 1)...")
    
    # Run cli/analyze.py with the vulnerability description
    proc = subprocess.Popen(
        ['python3', '-u', 'cli/analyze.py', vuln_desc],
        cwd=agent_dir,
        env=env,
        stdout=subprocess.PIPE, 
        stderr=subprocess.STDOUT, 
        text=True
    )

    # Real-time output streaming for Kaggle logs
    try:
        for line in proc.stdout:
            print(line, end='', flush=True)
        proc.wait(timeout=900) # 15 minute timeout for complex agentic loops
    except subprocess.TimeoutExpired:
        print("\n[!] Analysis timed out after 15 minutes.")
        proc.kill()
    except KeyboardInterrupt:
        print("\n[!] Analysis interrupted by user.")
        proc.terminate()

    print(f"\n{'='*60}")
    print(f"Phase 1 finished with Exit Code: {proc.returncode}")
    print(f"{'='*60}")

if __name__ == "__main__":
    run_analysis()
