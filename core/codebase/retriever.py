import os
import re
import json
import subprocess
import tempfile
from pathlib import Path

_DEFAULT_CODEBASE = os.environ.get(
    "OFBIZ_CODEBASE_PATH",
    "/home/krishna/Pictures/ofbiz-framework"
)

class CodebaseRetriever:
    def __init__(self, codebase_root=_DEFAULT_CODEBASE):
        self.codebase_root = Path(codebase_root)
        self._file_index = None

    def _build_index(self):
        if self._file_index is not None:
            return
        index = {}
        for root, dirs, files in os.walk(self.codebase_root):
            dirs[:] = [d for d in dirs if d not in ('build', '.gradle', '.git', 'node_modules', 'out', 'target')]
            for f in files:
                if f.endswith(('.java', '.groovy', '.xml', '.ftl', '.properties')):
                    key = f.lower()
                    index.setdefault(key, []).append(Path(root) / f)
        self._file_index = index

    def list_files(self, subdir=""):
        """Lists files in a subdirectory (relative to codebase root)."""
        target = self.codebase_root / subdir
        if not target.exists():
            return f"Error: Path {subdir} does not exist."
        try:
            items = os.listdir(target)
            return "\n".join(items[:100]) # Limit output
        except Exception as e:
            return str(e)

    def find_file(self, filename):
        self._build_index()
        paths = self._file_index.get(filename.lower(), [])
        return paths[0] if paths else None

    def read_file(self, filename, start_line=1, end_line=300):
        """Reads a specific line range from a file."""
        path = self.find_file(filename)
        if not path:
            # Try as absolute or relative path
            path = Path(filename)
            if not path.is_absolute():
                path = self.codebase_root / filename
            if not path.exists():
                return f"Error: File '{filename}' not found."
        
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            total = len(lines)
            start = max(0, start_line - 1)
            end = min(total, end_line)
            content = "\n".join(lines[start:end])
            header = f"--- {path.name} (Lines {start+1}-{end} of {total}) ---\n"
            return header + content
        except Exception as e:
            return f"Error reading file: {e}"

    def grep_search(self, pattern, file_ext=".java"):
        """Searches for a pattern in files with specific extension."""
        self._build_index()
        results = []
        count = 0
        for key, paths in self._file_index.items():
            if not key.endswith(file_ext):
                continue
            for p in paths:
                try:
                    content = p.read_text(encoding="utf-8", errors="replace")
                    if re.search(pattern, content, re.IGNORECASE):
                        rel_path = p.relative_to(self.codebase_root)
                        results.append(str(rel_path))
                        count += 1
                        if count >= 20: break
                except: continue
            if count >= 20: break
        return "\n".join(results) if results else "No matches found."

    def find_route(self, route_path):
        """
        Attempts to find which controller/request handles a specific path.
        Searches controller.xml files.
        """
        # route_path might be like "/catalog/control/UploadProductImage"
        parts = route_path.strip("/").split("/")
        # In OFBiz, usually: /webapp_name/control/request_uri
        request_uri = parts[-1] if parts else ""
        
        if not request_uri:
            return "Error: Invalid route path."

        # Search for <request-map uri="request_uri"> in all controller.xml files
        self._build_index()
        results = []
        for key, paths in self._file_index.items():
            if key == "controller.xml":
                for p in paths:
                    try:
                        content = p.read_text(encoding="utf-8", errors="replace")
                        if f'uri="{request_uri}"' in content:
                            # Extract the whole request-map block
                            match = re.search(rf'<request-map uri="{request_uri}">.*?</request-map>', content, re.DOTALL)
                            block = match.group(0) if match else "Found match but could not extract block."
                            results.append(f"File: {p.relative_to(self.codebase_root)}\n{block}")
                    except: continue
        
        return "\n\n".join(results) if results else f"No request-map found for uri='{request_uri}'"

    def semantic_search(self, pattern, language="java"):
        """
        Uses Semgrep to perform an Abstract Syntax Tree (AST) based search.
        Pattern example: 'class $CLASS implements $INTERFACE { ... }'
        """
        try:
            cmd = ["semgrep", "scan", "--lang", language, "--pattern", pattern, "--quiet", str(self.codebase_root)]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.stdout[:2000] if result.stdout else "No matches found."
        except FileNotFoundError:
            return "Error: Semgrep is not installed. Please run `pip install semgrep`."

    def get_method_body(self, filename, method_name):
        """
        Extracts the full body of a method using Semgrep line detection.
        """
        path = self.find_file(filename)
        if not path: return f"Error: File {filename} not found."
        
        # Semgrep pattern to find method and its line range
        pattern = f"... {method_name}(...) {{ ... }}"
        try:
            cmd = ["semgrep", "scan", "--lang", "java", "--pattern", pattern, "--json", str(path)]
            result = subprocess.run(cmd, capture_output=True, text=True)
            data = json.loads(result.stdout)
            
            if not data.get("results"):
                return f"Method {method_name} not found in {filename}."
            
            # Get start and end lines from the first match
            res = data["results"][0]
            start = res["start"]["line"]
            end = res["end"]["line"]
            
            return self.read_file(filename, start, end)
        except Exception as e:
            return f"Error extracting method: {e}"

    def vector_search(self, query, top_k=3):
        """
        Queries the local vector index (built via indexer.py).
        """
        index_path = Path("codebase_index.json")
        if not index_path.exists():
            return "Error: Vector index not found. Run `python core/codebase/indexer.py` first."
        
        try:
            # For simplicity without heavy DBs, we'll use our indexer's search logic
            from core.codebase.indexer import search_index
            results = search_index(query, top_k=top_k)
            return "\n\n".join(results) if results else "No semantic matches found."
        except Exception as e:
            return f"Vector search error: {e}"

    def taint_analysis(self, source, sink, language="java"):
        """
        Runs a Semgrep taint analysis dynamically by creating a temporary rule.
        """
        rule = {
            "rules": [
                {
                    "id": "dynamic-taint",
                    "languages": [language],
                    "message": "Taint flow found",
                    "severity": "WARNING",
                    "mode": "taint",
                    "pattern-sources": [{"pattern": source}],
                    "pattern-sinks": [{"pattern": sink}]
                }
            ]
        }
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(rule, f)
                rule_file = f.name

            cmd = ["semgrep", "scan", "-f", rule_file, "--quiet", str(self.codebase_root)]
            result = subprocess.run(cmd, capture_output=True, text=True)
            os.remove(rule_file)
            return result.stdout[:4000] if result.stdout else "No taint flows found."
        except FileNotFoundError:
            return "Error: Semgrep is not installed. Please run `pip install semgrep`."
        except Exception as e:
            if 'rule_file' in locals() and os.path.exists(rule_file):
                os.remove(rule_file)
            return f"Taint analysis error: {e}"

    def retrieve_context(self, description):
        """Old method kept for compatibility."""
        # Simple implementation for now to avoid breaking existing code
        exact_names, _ = self.extract_file_mentions(description)
        parts = []
        for name in exact_names[:5]:
            p = self.find_file(name)
            if p: parts.append(self.read_file(name))
        return "\n\n".join(parts) if parts else "No files found."

    def extract_file_mentions(self, text):
        exact = set()
        for m in re.finditer(r'\b([a-zA-Z0-9_]+\.(?:java|groovy|xml|ftl))\b', text):
            exact.add(m.group(1))
        # PascalCase
        for m in re.finditer(r'\b([A-Z][a-z]+(?:[A-Z][a-z0-9]+)+)\b', text):
            word = m.group(1)
            if word not in {"Apache", "OFBiz", "Java", "HTTP", "HTTPS"}:
                exact.add(f"{word}.java")
        return list(exact), []
