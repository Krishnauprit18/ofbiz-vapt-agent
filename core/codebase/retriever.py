import os
import re
from pathlib import Path

_DEFAULT_CODEBASE = os.environ.get(
    "OFBIZ_CODEBASE_PATH",
    "/home/krishna/Pictures/ofbiz-framework"
)

class CodebaseRetriever:
    def __init__(self, codebase_root=_DEFAULT_CODEBASE):
        self.codebase_root = Path(codebase_root)

    def extract_file_mentions(self, text):
        """
        Extract potential Java/Groovy/XML file names from the vulnerability description.
        """
        # Look for things that look like filenames or class names
        pattern = r'([a-zA-Z0-9_]+\.(?:java|groovy|xml|js|ftl))|(\b[A-Z][a-zA-Z0-9_]{3,}\b)'
        matches = re.findall(pattern, text)
        
        file_candidates = set()
        for file_match, class_match in matches:
            if file_match:
                file_candidates.add(file_match)
            if class_match:
                # If it's a class name, check if it matches a java/groovy file
                file_candidates.add(f"{class_match}.java")
                file_candidates.add(f"{class_match}.groovy")
        
        return list(file_candidates)

    def find_file(self, filename):
        """
        Locate a file within the codebase.
        """
        for root, dirs, files in os.walk(self.codebase_root):
            if filename in files:
                return Path(root) / filename
        return None

    def get_file_content(self, filename, line_no=None, keywords=None, window=50):
        """
        Read file content, optionally around a specific line number or based on keywords.
        """
        file_path = self.find_file(filename)
        if not file_path:
            return f"File '{filename}' not found in codebase."

        try:
            lines = file_path.read_text(encoding="utf-8").splitlines()
            result_lines = []

            if line_no is not None:
                start = max(0, line_no - window)
                end = min(len(lines), line_no + window)
                result_lines.append(f"--- {filename} (Lines {start+1}-{end}) ---")
                result_lines.extend(lines[start:end])
            elif keywords:
                # Search for keywords and extract surrounding lines
                matched_blocks = []
                for i, line in enumerate(lines):
                    for kw in keywords:
                        if kw.lower() in line.lower() and len(kw) > 4: # Only meaningful keywords
                            start = max(0, i - 15)
                            end = min(len(lines), i + 15)
                            matched_blocks.append((start, end))

                # Merge overlapping blocks
                if matched_blocks:
                    matched_blocks.sort()
                    merged = [matched_blocks[0]]
                    for curr in matched_blocks[1:]:
                        prev = merged[-1]
                        if curr[0] <= prev[1]:
                            merged[-1] = (prev[0], max(prev[1], curr[1]))
                        else:
                            merged.append(curr)
                    
                    result_lines.append(f"--- {filename} (Extracted relevant blocks) ---")
                    for start, end in merged:
                        result_lines.append(f"... line {start+1} ...")
                        result_lines.extend(lines[start:end])
                else:
                    # Fallback to top 150 lines
                    result_lines.append(f"--- {filename} (Top 150 lines) ---")
                    result_lines.extend(lines[:150])
            else:
                result_lines.append(f"--- {filename} (Top 150 lines) ---")
                result_lines.extend(lines[:150])

            content = "\n".join(result_lines)
            suffix = "\n... (truncated)" if len(lines) > 200 else ""
            return content + suffix
        except Exception as e:
            return f"Error reading '{filename}': {e}"

    def retrieve_context(self, description):
        """
        Orchestrate retrieval based on description keywords.
        """
        mentions = self.extract_file_mentions(description)
        # Extract keywords for inner-file search
        keywords = re.findall(r'\b[a-zA-Z]{5,}\b', description)
        # Also look for explicit line numbers like "filename:123"
        line_matches = re.findall(r'([a-zA-Z0-9_]+\.(?:java|groovy|xml|js|ftl)):(\d+)', description)
        
        context_parts = []
        seen_files = set()

        # Handle explicit file:line mentions first
        for filename, line in line_matches:
            context_parts.append(self.get_file_content(filename, int(line)))
            seen_files.add(filename)

        # Handle other mentions
        for mention in mentions:
            if mention not in seen_files:
                content = self.get_file_content(mention, keywords=keywords)
                if "not found" not in content:
                    context_parts.append(content)
                    seen_files.add(mention)

        if not context_parts:
            return "No relevant source code files found in the codebase matching the description."
        
        return "\n".join(context_parts)

def get_code_context(description):
    retriever = CodebaseRetriever()
    return retriever.retrieve_context(description)
