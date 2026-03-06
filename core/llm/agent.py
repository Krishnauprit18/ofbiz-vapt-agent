import json
import re
from core.llm.client import OllamaClient
from core.codebase.retriever import CodebaseRetriever

class CodebaseAgent:
    def __init__(self, model="qwen2.5-coder:7b"):
        self.client = OllamaClient(model=model)
        self.retriever = CodebaseRetriever()
        self.history = []
        self.max_steps = 10

    def run(self, vulnerability_description):
        print(f"[*] Starting agentic exploration for: {vulnerability_description[:50]}...")
        
        system_prompt = """You are an Expert Security Researcher. Your goal is to trace a vulnerability through the Apache OFBiz codebase.
You have access to tools to navigate the code. Use them iteratively to find the root cause.

STRICT RULES:
1. Do NOT reason out loud. Do NOT explain your steps. 
2. If you need more information, output ONLY a JSON tool call.
3. If you have finished, output ONLY the FINAL ANALYSIS in Markdown.

TOOLS AVAILABLE:
1. list_files(subdir: str) -> str
2. read_file(filename: str, start_line: int, end_line: int) -> str
3. grep_search(pattern: str, file_ext: str) -> str
4. find_route(route_path: str) -> str

HOW TO USE TOOLS:
Output a JSON object in a code block like this:
```json
{
  "tool": "read_file",
  "params": {"filename": "SecuredFreemarker.java", "start_line": 1, "end_line": 100}
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
                print(f"[+] Result: {len(result)} chars")
                
                self.history.append({"role": "assistant", "content": response})
                self.history.append({"role": "user", "content": f"TOOL RESULT: {result}"})
            else:
                # If no tool call and not final, maybe it's just talking. Ask it to use a tool or finish.
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
                return self.retriever.read_file(
                    params.get("filename"), 
                    params.get("start_line", 1), 
                    params.get("end_line", 300)
                )
            elif name == "grep_search":
                return self.retriever.grep_search(
                    params.get("pattern"), 
                    params.get("file_ext", ".java")
                )
            elif name == "find_route":
                return self.retriever.find_route(params.get("route_path"))
            else:
                return f"Error: Unknown tool {name}"
        except Exception as e:
            return f"Error executing tool: {e}"
