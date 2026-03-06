import os
import subprocess
import time
import requests as req

# Configuration for Kaggle Environment
agent_path = '/kaggle/working/ofbiz-vapt-agent'
target_model = "qwen2.5-coder:7b" # Optimized for fast Agentic Tool Use on P100

def setup():
    print("--- Initializing Kaggle VAPT Agent Environment ---")
    
    # 1. Sync the Agent Codebase
    if not os.path.exists(agent_path):
        print("[*] Cloning ofbiz-vapt-agent...")
        subprocess.run(['git', 'clone', 'https://github.com/Krishnauprit18/ofbiz-vapt-agent.git', agent_path])
        print("✅ Agent Cloned")
    else:
        print("[*] Updating existing agent...")
        subprocess.run(['git', '-C', agent_path, 'pull'])
        print("✅ Agent Updated to latest")

    # 2. Install Python Dependencies
    print("[*] Installing requests, semgrep, and numpy...")
    subprocess.run(['pip', 'install', 'requests', 'semgrep', 'numpy', '-q'])

    # 3. Verify Ollama and Model Status
    try:
        print("[*] Checking Ollama server status...")
        r = req.get('http://localhost:11434/api/tags', timeout=10)
        models = [m['name'] for m in r.json().get('models', [])]
        print(f"✅ Ollama UP — models: {models}")
        
        # Check for the NEW target model (Qwen 2.5 Coder)
        if not any(target_model in m for m in models):
            print(f"⚠️ {target_model} not found, pulling (this is the fast model for our task)...")
            subprocess.run(['ollama', 'pull', target_model])
            print(f"✅ {target_model} installed successfully.")
        
        # Ensure embedding model is present
        if not any("nomic-embed-text" in m for m in models):
            print("[*] Pulling nomic-embed-text for RAG...")
            subprocess.run(['ollama', 'pull', 'nomic-embed-text'])

    except Exception as e:
        print(f"⚠️ Ollama server connection error ({e})")
        print("Attempting to start/restart Ollama serve in background...")
        os.makedirs('/kaggle/working/logs', exist_ok=True)
        subprocess.Popen(['ollama', 'serve'],
                         stdout=open('/kaggle/working/logs/ollama.log', 'a'),
                         stderr=open('/kaggle/working/logs/ollama.log', 'a'))
        time.sleep(12)
        print("✅ Restart signal sent.")

    # 4. Build Vector Index (New for Point 3)
    print("[*] Building Semantic Vector Index (RAG)...")
    env = os.environ.copy()
    env['PYTHONPATH'] = agent_path
    subprocess.run(['python3', 'core/codebase/indexer.py'], cwd=agent_path, env=env)
    print("✅ Indexing complete.")

if __name__ == "__main__":
    setup()
