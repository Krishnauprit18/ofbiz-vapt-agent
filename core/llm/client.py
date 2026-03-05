import requests
import json

OLLAMA_BASE_URL = "http://localhost:11434"

class OllamaConnectionError(Exception):
    """Raised when Ollama server is not reachable."""
    pass

class OllamaClient:
    def __init__(self, base_url=OLLAMA_BASE_URL, model="deepseek-r1:7b"):
        self.base_url = base_url
        self.generate_url = f"{base_url}/api/generate"
        self.model = model

    def health_check(self):
        """
        Verifies Ollama server is running. Raises OllamaConnectionError if not.
        """
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=5)
            resp.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            raise OllamaConnectionError(
                f"[!] Ollama is not running at {self.base_url}.\n"
                f"    Start it with: ollama serve\n"
                f"    Original error: {e}"
            )

    def analyze_vulnerability(self, description, code_context=None, system_prompt=None):
        """
        Sends the vulnerability description and optional code context to Ollama.
        Raises OllamaConnectionError if the server is unreachable.
        """
        # Pre-flight check — fail fast with a clear message
        self.health_check()

        context_str = f"\n\n--- ACTUAL CODE CONTEXT FROM CODEBASE ---\n{code_context}" if code_context else ""

        prompt = (
            f"You are a Senior Security Application Researcher. Carefully analyze the following vulnerability description "
            f"using the provided local codebase context as your primary source of truth. "
            f"Ensure your analysis maps exactly to the provided code and avoid hallucinating files or paths not present in the context.\n\n"
            f"Vulnerability Description: {description}"
            f"{context_str}\n\n"
            f"Provide your output in Markdown format, identifying exact files, potential root causes, and fix recommendations."
        )

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.2
            }
        }

        if system_prompt:
            payload["system"] = system_prompt

        try:
            response = requests.post(self.generate_url, json=payload, timeout=1800)
            response.raise_for_status()
            data = response.json()
            return data.get("response", "No response from LLM.")
        except requests.exceptions.ConnectionError as e:
            raise OllamaConnectionError(f"[!] Lost connection to Ollama mid-request: {e}")
        except requests.exceptions.RequestException as e:
            raise OllamaConnectionError(f"[!] Ollama request failed: {e}")

# Singleton helper
def get_analysis(description, code_context=None):
    client = OllamaClient()
    return client.analyze_vulnerability(description, code_context)
