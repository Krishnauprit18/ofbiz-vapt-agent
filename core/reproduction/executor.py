import subprocess
import time

def run_exploit(script_path="exploit.py"):
    """
    Safely executes the generated exploit script and captures its output to verify success.
    """
    print(f"\n[*] Executing generated exploit: {script_path}")
    print("-" * 50)
    
    try:
        # Run the script with a timeout to prevent hanging
        result = subprocess.run(
            ["python3", script_path],
            capture_output=True,
            text=True,
            timeout=120  # 120 seconds — OFBiz is slow, exploits may wait for responses
        )
        
        stdout = result.stdout
        stderr = result.stderr
        exit_code = result.returncode
        
        print(stdout)
        if stderr:
             print(f"[!] Error Output:\n{stderr}")
             
        print("-" * 50)
        
        # Simple verification heuristic (can be expanded based on vulnerability type)
        if exit_code == 0:
            print("[✓] Execution completed without critical crashes. Review output for confirmation.")
            return True, stdout
        else:
            print(f"[x] Exploit failed or crashed with exit code {exit_code}.")
            return False, stderr
            
    except subprocess.TimeoutExpired:
        print("[-] Exploit execution timed out (120s). It might be a blind vulnerability or a hung process.")
        return False, "Timeout"
    except Exception as e:
        print(f"[!] Critical error executing exploit: {e}")
        return False, str(e)
