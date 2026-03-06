import json
import re
import requests
import urllib3
from core.llm.client import OllamaClient
from core.codebase.retriever import CodebaseRetriever

# Suppress insecure request warnings for OFBiz self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CodebaseAgent:
    def __init__(self, model="qwen2.5-coder:7b"):
        self.client = OllamaClient(model=model)
        self.retriever = CodebaseRetriever()
        self.history = []
        self.max_steps = 15 # Increased steps since it can now interact with the live app
        self.session = requests.Session() # Persistent session for login cookies

    def run(self, vulnerability_description):
        print(f"[*] Starting agentic exploration for: {vulnerability_description[:50]}...")
        
        system_prompt = """You are an Expert Security Researcher and Penetration Tester. 
Your goal is to trace a vulnerability through the Apache OFBiz codebase AND verify it dynamically.

STRICT RULES:
1. Do NOT reason out loud. Do NOT explain your steps. 
2. If you need more information, output ONLY a JSON tool call.
3. If you have finished, output ONLY the FINAL ANALYSIS in Markdown.

TOOLS AVAILABLE (CODE EXPLORATION):
1. list_files(subdir: str) -> str
2. read_file(filename: str, start_line: int, end_line: int) -> str
3. get_method_body(filename: str, method_name: str) -> str
4. vector_search(query: str) -> str
5. grep_search(pattern: str, file_ext: str) -> str
6. find_route(route_path: str) -> str
7. semantic_search(pattern: str, language: str) -> str
8. taint_analysis(source: str, sink: str, language: str) -> str

TOOLS AVAILABLE (LIVE INTERACTION / "CURL" EQUIVALENT):
9. send_http_request(method: str, url: str, data: dict = None, params: dict = None) -> str
   - Use this to interact with the live OFBiz app (default runs on https://localhost:8443).
   - Example: To login, send POST to "https://localhost:8443/webtools/control/login" with data {"USERNAME": "admin", "PASSWORD": "ofbiz"}.
   - The session cookies are maintained automatically, so you stay logged in for future requests.

HOW TO USE TOOLS:
Output a JSON object in a code block like this:
```json
{
  "tool": "send_http_request",
  "params": {"method": "GET", "url": "https://localhost:8443/webtools/control/main"}
}
```

Start your final response with "FINAL ANALYSIS".
"""
        
        user_input = f"Vulnerability Description: {vulnerability_description}\n\nBegin your exploration."
        self.history.append({"role": "user", "content": user_input})

        for step in range(self.max_steps):
            print(f"\n[Step {step+1}/{self.max_steps}] Thinking...")
            
            # Combine history into a prompt for Ollama
            full_prompt = system_prompt + "\n\n"
            for msg in self.history:
                full_prompt += f"{msg['role'].upper()}: {msg['content']}\n\n"
            
            response = self.client.analyze_vulnerability(full_prompt, system_prompt=system_prompt)
            
            # Strip <think> tags if present
            clean_response = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL).strip()
            
            if "FINAL ANALYSIS" in clean_response:
                print("[✓] Agent reached a conclusion.")
                return clean_response

            # Try to extract tool call
            tool_call = self._extract_tool_call(clean_response)
            if tool_call:
                tool_name = tool_call.get("tool")
                params = tool_call.get("params", {})
                print(f"[*] Action: {tool_name}({params})")
                
                result = self._execute_tool(tool_name, params)
                # Cap the result size so it doesn't blow up the context window
                if len(result) > 5000:
                    result = result[:5000] + "\n... [Output Truncated]"
                
                print(f"[+] Result: {len(result)} chars")
                
                self.history.append({"role": "assistant", "content": response})
                self.history.append({"role": "user", "content": f"TOOL RESULT: {result}"})
            else:
                # If no tool call and not final, prompt it again.
                print("[!] No tool call detected. Prompting for action.")
                self.history.append({"role": "assistant", "content": response})
                self.history.append({"role": "user", "content": "Please use a tool to continue exploration or provide FINAL ANALYSIS."})

        return "Agent timed out without reaching a conclusion."

    def _extract_tool_call(self, text):
        match = re.search(r'```json\s*\n(.*?)\n\s*```', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except:
                return None
        return None

    def _execute_tool(self, name, params):
        try:
            if name == "list_files":
                return self.retriever.list_files(params.get("subdir", ""))
            elif name == "read_file":
                return self.retriever.read_file(params.get("filename"), params.get("start_line", 1), params.get("end_line", 300))
            elif name == "get_method_body":
                return self.retriever.get_method_body(params.get("filename"), params.get("method_name"))
            elif name == "vector_search":
                return self.retriever.vector_search(params.get("query"))
            elif name == "grep_search":
                return self.retriever.grep_search(params.get("pattern"), params.get("file_ext", ".java"))
            elif name == "find_route":
                return self.retriever.find_route(params.get("route_path"))
            elif name == "semantic_search":
                return self.retriever.semantic_search(params.get("pattern"), params.get("language", "java"))
            elif name == "taint_analysis":
                return self.retriever.taint_analysis(params.get("source"), params.get("sink"), params.get("language", "java"))
            elif name == "send_http_request":
                # NEW: Live interaction tool replacing the need for raw cURL
                method = params.get("method", "GET").upper()
                url = params.get("url")
                data = params.get("data")
                req_params = params.get("params")
                
                res = self.session.request(
                    method=method, 
                    url=url, 
                    data=data, 
                    params=req_params, 
                    verify=False, # OFBiz uses self-signed certs
                    timeout=10
                )
                
                output = f"Status Code: {res.status_code}\n"
                output += f"Headers: {dict(res.headers)}\n"
                output += f"Body Preview:\n{res.text[:1000]}"
                return output
            else:
                return f"Error: Unknown tool {name}"
        except Exception as e:
            return f"Error executing tool: {e}"
