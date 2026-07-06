import os
import json
import chromadb
from chromadb.utils import embedding_functions

def build_vector_db():
    base_dir = os.path.dirname(os.path.dirname(__file__))
    processed_dir = os.path.join(base_dir, 'data', 'processed')
    db_path = os.path.join(base_dir, 'data', 'chroma_db')

    print("[+] Initializing ChromaDB...")
    
    # Create a persistent local database in data/chroma_db
    client = chromadb.PersistentClient(path=db_path)
    
    # We use a fast, lightweight sentence-transformer to convert code to math
    # Chroma will automatically download this ~90MB model on the first run
    sentence_transformer_ef = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
    
    # Create or load the collection
    collection = client.get_or_create_collection(
        name="vulnerabilities",
        embedding_function=sentence_transformer_ef
    )
    
    print(f"[+] Connected to collection: 'vulnerabilities'. Current size: {collection.count()} records.")

    # We will process them in order of importance
    files_to_process = [
        'bigvul_vulnerable.jsonl',      # Has exact patches!
        'securityeval_vulnerable.jsonl', # Great for Python
        'diversevul_vulnerable.jsonl'    # Massive C/C++ knowledge base
    ]
    
    for filename in files_to_process:
        filepath = os.path.join(processed_dir, filename)
        if not os.path.exists(filepath):
            continue
            
        print(f"\n[+] Loading {filename} into Vector DB...")
        
        documents = []
        metadatas = []
        ids = []
        
        with open(filepath, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                data = json.loads(line)
                
                code = data.get("code", "")
                if not code:
                    continue
                    
                # ChromaDB requires metadata to be strings, ints, floats, or bools
                # So we must convert our list of CWE tags into a single comma-separated string
                cwes = data.get("cwe_tags", [])
                cwe_str = ", ".join(cwes) if cwes else "Unknown"
                
                meta = {
                    "source": data.get("source", "Unknown"),
                    "cwe": cwe_str
                }
                
                # If the dataset contains the exact patch (like BigVul), save it in the metadata!
                if "patch" in data:
                    meta["patch"] = data["patch"]
                    
                documents.append(code)
                metadatas.append(meta)
                ids.append(f"{data.get('source', 'Unknown')}_{i}")
                
                # We batch insert every 500 records so we don't blow up system RAM
                if len(documents) >= 500:
                    collection.add(
                        documents=documents,
                        metadatas=metadatas,
                        ids=ids
                    )
                    print(f"    -> Embedded and inserted {i+1} records...")
                    documents = []
                    metadatas = []
                    ids = []
                    
        # Insert any remaining documents from the final batch
        if documents:
            collection.add(
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
            print(f"    -> Embedded and inserted remaining records.")
            
    print(f"\n[+] Vector DB build complete!")
    print(f"[+] Total embedded vulnerabilities in AI memory: {collection.count()}")

if __name__ == "__main__":
    print("=== Cypher Vector DB Builder ===")
    # Note: Depending on your CPU/GPU, embedding 22,000+ code snippets may take 5-15 minutes.
    build_vector_db()