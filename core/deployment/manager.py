import subprocess
import time
import requests
import os

_DEFAULT_TARGET_DIR = os.environ.get(
    "OFBIZ_CODEBASE_PATH",
    "/home/krishna/Pictures/ofbiz-framework"
)

class DeployManager:
    def __init__(self, target_dir=_DEFAULT_TARGET_DIR, image_name="ofbiz-docker", container_name="ofbiz-vapt-target", use_docker=True):
        self.target_dir = target_dir
        self.image_name = image_name
        self.container_name = container_name
        self.port = 8443
        self.use_docker = use_docker

    def build_image(self):
        """Builds the OFBiz docker image from the target directory."""
        print(f"[*] Building Docker image '{self.image_name}' from {self.target_dir}...")
        print("[*] This might take a few minutes if not already built.")
        
        try:
            result = subprocess.run(
                ["docker", "build", "--tag", self.image_name, "."],
                cwd=self.target_dir,
                capture_output=True,
                text=True,
                check=True
            )
            print("[✓] Docker image built successfully.")
            return True
        except subprocess.CalledProcessError as e:
            print(f"[!] Error building docker image:\n{e.stderr}")
            return False

    def check_container_running(self):
        """Checks if the container is already running."""
        try:
            result = subprocess.run(["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True, check=True)
            return self.container_name in result.stdout.split()
        except subprocess.CalledProcessError:
            return False

    def remove_existing_container(self):
         """Removes the container if it exists (running or exited)."""
         try:
            subprocess.run(["docker", "rm", "-f", self.container_name], capture_output=True, check=True)
         except subprocess.CalledProcessError:
            pass # Container didn't exist

    def run_container(self):
        """Runs the OFBiz docker container."""
        if self.check_container_running():
            print(f"[*] Container '{self.container_name}' is already running.")
            return True
            
        print(f"[*] Starting container '{self.container_name}'...")
        self.remove_existing_container()

        try:
            # Run detached, map ports, and load demo data as per DOCKER.adoc
            subprocess.run(
                [
                    "docker", "run", "-d", 
                    "-e", "OFBIZ_DATA_LOAD=demo", 
                    "--name", self.container_name, 
                    "-p", f"{self.port}:{self.port}", 
                    self.image_name
                ],
                capture_output=True,
                text=True,
                check=True
            )
            print(f"[✓] Container started on port {self.port}.")
            return True
        except subprocess.CalledProcessError as e:
            print(f"[!] Error starting container:\n{e.stderr}")
            return False

    def wait_for_health(self, timeout=300):
        """Polls the OFBiz login URL until it's ready or times out."""
        url = f"https://localhost:{self.port}/partymgr"
        print(f"[*] Waiting for OFBiz to become healthy at {url} (Timeout: {timeout}s)...")
        print("[*] Note: OFBiz takes a while to load demo data and start up on the first run.")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                # Disable warning for unverified HTTPS request (local self-signed certs)
                requests.packages.urllib3.disable_warnings()
                response = requests.get(url, verify=False, timeout=5)
                
                # If we get any valid HTTP response, it's up
                if response.status_code in [200, 302, 401]:
                     print("\n[✓] OFBiz is healthy and ready to accept connections!")
                     return True
                else:
                     print(f" (Status: {response.status_code}) ", end="", flush=True)
            except requests.exceptions.RequestException as e:
                # Still starting...
                pass
                
            time.sleep(10) # 10 seconds between checks is safer for heavy startups
            elapsed = int(time.time() - start_time)
            print(f"[{elapsed}s]", end="", flush=True)
            
        print("\n[!] Health check failed: OFBiz did not start within the timeout period.")
        return False

    def deploy(self):
        """Orchestrates the full deployment flow."""
        print("-" * 50)
        print(f"Starting Target Deployment Phase (Docker: {self.use_docker})")
        print("-" * 50)
        
        if self.use_docker:
            if not self.build_image(): return False
            if not self.run_container(): return False
        else:
            print("[*] Manual Mode: Skipping Docker build/run. Checking existing process...")

        if not self.wait_for_health(timeout=600): # Allow up to 10 mins for startup
            print("[!] Deployment failed. Cannot proceed with exploitation.")
            return False
            
        print("-" * 50)
        print("Target Environment Ready")
        print("-" * 50)
        return True
