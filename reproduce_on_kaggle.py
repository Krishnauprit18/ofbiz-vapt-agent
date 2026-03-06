import subprocess
import os

# Environment Setup for Kaggle
env = os.environ.copy()
env['OFBIZ_CODEBASE_PATH'] = '/kaggle/working/ofbiz-framework'
env['PYTHONPATH'] = '/kaggle/working/ofbiz-vapt-agent'
agent_dir = '/kaggle/working/ofbiz-vapt-agent'

def run_reproduction():
    print(f"[*] Launching Vulnerability Reproduction (Phase 2)...")
    
    # Run cli/reproduce.py (skips Docker setup as OFBiz should already be running)
    proc = subprocess.Popen(
        ['python3', '-u', 'cli/reproduce.py', '--no-docker'],
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
        proc.wait(timeout=600) # 10 minute timeout for reproduction
    except subprocess.TimeoutExpired:
        print("\n[!] Reproduction timed out after 10 minutes.")
        proc.kill()
    except KeyboardInterrupt:
        print("\n[!] Reproduction interrupted by user.")
        proc.terminate()

    print(f"\n{'='*60}")
    print(f"Phase 2 finished with Exit Code: {proc.returncode}")
    print(f"{'='*60}")

if __name__ == "__main__":
    run_reproduction()
