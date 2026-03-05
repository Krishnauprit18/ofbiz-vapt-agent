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
        # Cache all .java/.groovy file paths once to avoid repeated os.walk
        self._file_index = None

    def _build_index(self):
        """Walk the codebase once and index all Java/Groovy/XML/FTL files."""
        if self._file_index is not None:
            return
        index = {}  # lowercase_name → [actual Path, ...]
        for root, dirs, files in os.walk(self.codebase_root):
            # Skip build/test dirs — they're huge and irrelevant
            dirs[:] = [d for d in dirs if d not in ('build', '.gradle', '.git',
                                                      'node_modules', 'out', 'target')]
            for f in files:
                if f.endswith(('.java', '.groovy', '.xml', '.ftl')):
                    key = f.lower()
                    index.setdefault(key, []).append(Path(root) / f)
        self._file_index = index
        print(f"[*] Codebase index built: {len(index)} unique filenames")

    # Common English / OFBiz noise words that are NOT class names
    _NOISE_WORDS = {
        "Apache", "OFBiz", "Java", "HTTP", "HTTPS", "User", "Admin", "True", "False",
        "None", "This", "That", "When", "From", "With", "Path", "File", "Code",
        "Template", "Request", "Response", "Server", "Client", "Data", "Note",
        "Base", "Core", "Test", "View", "Main", "List", "Type", "Name", "Info",
        "Error", "Exception", "Class", "Method", "Object", "Value", "Check",
        "Allow", "Deny", "Null", "String", "Input", "Output", "Result", "Based",
        "Using", "Being", "After", "Before", "Whether", "Against", "Through",
        "CVE", "RCE", "SSTI", "SQL", "XSS", "CSRF", "SSRF", "API", "URL", "URI",
    }

    def extract_file_mentions(self, text):
        """
        Extract potential Java/Groovy file names from the vulnerability description.
        Returns (exact_names, class_stems) where stems are used for fuzzy search.
        """
        exact = set()
        stems = set()

        # 1. Explicit filenames with extensions e.g. FooBar.java
        for m in re.finditer(r'\b([a-zA-Z0-9_]+\.(?:java|groovy|xml|ftl))\b', text):
            exact.add(m.group(1))

        # 2. PascalCase compound class names — used for both exact + fuzzy
        for m in re.finditer(r'\b([A-Z][a-z]+(?:[A-Z][a-z0-9]+)+)\b', text):
            word = m.group(1)
            if word not in self._NOISE_WORDS:
                exact.add(f"{word}.java")
                exact.add(f"{word}.groovy")
                stems.add(word)

        return list(exact), list(stems)

    def find_file(self, filename):
        """
        Exact filename lookup (case-sensitive, first match).
        """
        self._build_index()
        paths = self._file_index.get(filename.lower(), [])
        return paths[0] if paths else None

    def find_file_fuzzy(self, stem):
        """
        Fuzzy lookup: find files whose name contains `stem` (case-insensitive).
        e.g. 'ViewHandlerExt' → finds 'AbstractViewHandler.java', 'FreeMarkerViewHandler.java'
        'FreemarkerViewHandler' → also finds 'FreeMarkerViewHandler.java' (ignores case)

        Strategy:
          1. Try stem as-is (case-insensitive contains)
          2. Try sub-stems: split PascalCase into parts, search for each part combo
        Returns list of Path objects (max 3 to avoid noise).
        """
        self._build_index()
        stem_lower = stem.lower()
        scored = {}  # path → best_score

        # Score 1: stem is contained in filename — only .java and .groovy (skip .xml/.ftl)
        for key, paths in self._file_index.items():
            if not (key.endswith('.java') or key.endswith('.groovy')):
                continue
            base = key.replace('.java', '').replace('.groovy', '')
            if stem_lower in base:
                # Score = what fraction of the filename the stem covers
                # Higher = more specific match (avoids BirtViewHandler for ViewHandler)
                coverage = len(stem_lower) / max(len(base), 1)
                for p in paths:
                    scored[p] = max(scored.get(p, 0), coverage)

        # Only keep results where match coverage >= 50% of filename
        # e.g. 'viewhandler'(11) in 'freemarkerviewhandler'(21) = 52% ✅
        #      'viewhandler'(11) in 'birtviewhandler'(15) = 73% ✅ but...
        # Extra check: prefer files where stem appears at end or start of name
        strong = {p: s for p, s in scored.items() if s >= 0.50}
        if strong:
            top = sorted(strong.items(), key=lambda x: x[1], reverse=True)[:2]
            return [p for p, _ in top]

        # Sub-stem fallback: split PascalCase into pairs of consecutive words
        # e.g. ViewHandlerExt → ViewHandler, HandlerExt
        words = re.findall(r'[A-Z][a-z0-9]*', stem)
        if len(words) >= 2:
            for i in range(len(words) - 1):
                sub = (words[i] + words[i+1]).lower()
                sub_scored = {}
                for key, paths in self._file_index.items():
                    if not (key.endswith('.java') or key.endswith('.groovy')):
                        continue
                    base = key.replace('.java', '').replace('.groovy', '')
                    if sub in base:
                        coverage = len(sub) / max(len(base), 1)
                        for p in paths:
                            sub_scored[p] = max(sub_scored.get(p, 0), coverage)
                top_sub = sorted(sub_scored.items(), key=lambda x: x[1], reverse=True)[:2]
                results = [p for p, _ in top_sub if sub_scored[p] >= 0.45]
                if results:
                    return results[:2]

        return []

    def _read_file_content(self, file_path, keywords=None):
        """
        Read a file and return relevant blocks based on keywords,
        or the top 300 lines if no keywords given.
        """
        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception as e:
            return f"Error reading '{file_path}': {e}"

        fname = file_path.name
        result_lines = []

        if keywords:
            matched_blocks = []
            for i, line in enumerate(lines):
                for kw in keywords:
                    if len(kw) > 4 and kw.lower() in line.lower():
                        start = max(0, i - 15)
                        end = min(len(lines), i + 15)
                        matched_blocks.append((start, end))
                        break

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

                result_lines.append(f"--- {fname} [relevant blocks from {file_path}] ---")
                for start, end in merged:
                    result_lines.append(f"... line {start+1} ...")
                    result_lines.extend(lines[start:end])
            else:
                # No keyword hits — fall back to top 300
                result_lines.append(f"--- {fname} (top 300 lines — no keyword hits) ---")
                result_lines.extend(lines[:300])
        else:
            result_lines.append(f"--- {fname} (top 300 lines) ---")
            result_lines.extend(lines[:300])

        content = "\n".join(result_lines)
        if len(lines) > 300:
            content += "\n... (truncated)"
        return content

    def _keyword_grep(self, keywords, max_files=5):
        """
        Last-resort fallback: grep ALL Java files for the keywords.
        Returns content of up to max_files matching files.
        """
        self._build_index()
        print(f"[*] Keyword grep fallback — scanning entire codebase for: {keywords[:5]}")
        hits = {}  # path → hit_count

        for key, paths in self._file_index.items():
            if not key.endswith('.java'):
                continue
            for p in paths:
                try:
                    text = p.read_text(encoding="utf-8", errors="replace")
                    count = sum(1 for kw in keywords if len(kw) > 5 and kw.lower() in text.lower())
                    if count > 0:
                        hits[p] = count
                except Exception:
                    continue

        # Sort by most keyword hits
        top_files = sorted(hits.items(), key=lambda x: x[1], reverse=True)[:max_files]
        results = []
        for p, count in top_files:
            print(f"  [grep] {p.name} ({count} keyword hits)")
            results.append(self._read_file_content(p, keywords=keywords))
        return results

    def get_file_content(self, filename, line_no=None, keywords=None, window=50):
        """
        Legacy interface — kept for compatibility.
        """
        file_path = self.find_file(filename)
        if not file_path:
            return f"File '{filename}' not found in codebase."
        return self._read_file_content(file_path, keywords=keywords)

    def retrieve_context(self, description):
        """
        3-stage retrieval:
          Stage 1 — Exact match on mentioned filenames
          Stage 2 — Fuzzy match on class name stems (case-insensitive, partial)
          Stage 3 — Keyword grep across ALL Java files (if Stage 1+2 fail)
        """
        self._build_index()

        exact_names, stems = self.extract_file_mentions(description)
        keywords = re.findall(r'\b[a-zA-Z]{5,}\b', description)
        line_matches = re.findall(r'([a-zA-Z0-9_]+\.(?:java|groovy|xml|ftl)):(\d+)', description)

        context_parts = []
        seen_paths = set()

        def add_path(p, kw=None):
            if str(p) not in seen_paths:
                seen_paths.add(str(p))
                context_parts.append(self._read_file_content(p, keywords=kw))
                # Show relative path from codebase root for clarity
                try:
                    rel = p.relative_to(self.codebase_root)
                except ValueError:
                    rel = p.name
                print(f"  [context] Added: {rel}")

        # Stage 1a: explicit file:line mentions
        for fname, lineno in line_matches:
            p = self.find_file(fname)
            if p:
                add_path(p, kw=keywords)

        # Stage 1b: exact filename lookup
        for name in exact_names:
            p = self.find_file(name)
            if p:
                add_path(p, kw=keywords)

        # Stage 2: fuzzy match on stems (catches FreeMarkerViewHandler for FreemarkerViewHandler)
        # Skip stems whose exact file was already found in Stage 1 to avoid duplicates like TechDataServices
        already_found_stems = {Path(sp).stem.lower() for sp in seen_paths}
        for stem in stems:
            if stem.lower() in already_found_stems:
                continue
            fuzzy_paths = self.find_file_fuzzy(stem)
            for p in fuzzy_paths:
                add_path(p, kw=keywords)
        # Stage 3: if still nothing, grep entire codebase by keywords
        if not context_parts:
            print("[!] No files found via name match — falling back to keyword grep")
            grep_results = self._keyword_grep(keywords)
            context_parts.extend(grep_results)

        if not context_parts:
            return "No relevant source code files found in the codebase matching the description."

        print(f"[✓] Total files in context: {len(context_parts)}")

        # Cap total context to ~80,000 chars
        MAX_CONTEXT_CHARS = 80000
        combined = "\n\n".join(context_parts)
        if len(combined) > MAX_CONTEXT_CHARS:
            combined = combined[:MAX_CONTEXT_CHARS] + "\n... [context truncated to fit LLM window]"
        return combined


def get_code_context(description):
    retriever = CodebaseRetriever()
    return retriever.retrieve_context(description)
