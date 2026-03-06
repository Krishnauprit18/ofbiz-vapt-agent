import os
import json
import requests
import numpy as np
from pathlib import Path

_DEFAULT_CODEBASE = os.environ.get("OFBIZ_CODEBASE_PATH", "/home/krishna/Pictures/ofbiz-framework")

def get_embedding(text):
    """Calls Ollama to get embeddings for a chunk of text."""
    try:
        res = requests.post(
            "http://localhost:11434/api/embeddings",
            json={"model": "nomic-embed-text", "prompt": text},
            timeout=30
        )
        return res.json().get("embedding")
    except:
        return None

def build_index(codebase_path=_DEFAULT_CODEBASE):
    """
    Walks the codebase, chunks files by methods (simple heuristic), 
    and builds a simple JSON-based vector index.
    """
    print(f"[*] Building semantic index for {codebase_path}...")
    root = Path(codebase_path)
    index = []
    
    for path in root.rglob("*.java"):
        if any(d in str(path) for d in ['build', '.gradle', 'test']): continue
        
        content = path.read_text(encoding="utf-8", errors="replace")
        
        # Simple chunking: split by methods (heuristic)
        # In a real system, we'd use tree-sitter to get perfect boundaries.
        chunks = re.split(r'\n\s*(?:public|protected|private|static)', content)
        
        for i, chunk in enumerate(chunks):
            if len(chunk) < 100: continue
            
            clean_chunk = chunk.strip()
            embedding = get_embedding(clean_chunk[:2000]) # Limit input for speed
            
            if embedding:
                index.append({
                    "file": str(path.relative_to(root)),
                    "content": clean_chunk[:1000], # Store preview
                    "embedding": embedding
                })
                if len(index) % 50 == 0:
                    print(f"  [+] Indexed {len(index)} chunks...")
        
        if len(index) >= 500: break # Safety cap for Kaggle speed

    with open("codebase_index.json", "w") as f:
        json.dump(index, f)
    print(f"[✓] Index built with {len(index)} chunks.")

def search_index(query, top_k=3):
    """
    Performs cosine similarity search on the local index.
    """
    query_emb = get_embedding(query)
    if not query_emb: return []
    
    with open("codebase_index.json", "r") as f:
        index = json.load(f)
        
    scores = []
    for item in index:
        # Simple cosine similarity
        dot = np.dot(query_emb, item["embedding"])
        norm_q = np.linalg.norm(query_emb)
        norm_i = np.linalg.norm(item["embedding"])
        score = dot / (norm_q * norm_i)
        scores.append((score, item))
        
    # Sort by highest score
    scores.sort(key=lambda x: x[0], reverse=True)
    
    results = []
    for score, item in scores[:top_k]:
        results.append(f"--- {item['file']} (Similarity: {score:.2f}) ---\n{item['content']}...")
        
    return results

if __name__ == "__main__":
    import re # Needed for the regex split above
    build_index()
