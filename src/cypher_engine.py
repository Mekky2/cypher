import json
import os
import chromadb
from chromadb.utils import embedding_functions
from llama_cpp import Llama

def init_vector_db():
    """Connects to the local ChromaDB."""
    base_dir = os.path.dirname(os.path.dirname(__file__))
    db_path = os.path.join(base_dir, 'data', 'chroma_db')
    
    if not os.path.exists(db_path):
        return None
        
    client = chromadb.PersistentClient(path=db_path)
    sentence_transformer_ef = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
    
    try:
        collection = client.get_collection(name="vulnerabilities", embedding_function=sentence_transformer_ef)
        return collection
    except Exception:
        return None

def retrieve_similar_vulnerabilities(collection, target_code, n_results=1):
    """Queries the Vector DB for similar vulnerable functions."""
    if not collection:
        return []
        
    results = collection.query(
        query_texts=[target_code],
        n_results=n_results
    )
    
    examples = []
    if results['documents'] and results['documents'][0]:
        for i in range(len(results['documents'][0])):
            doc = results['documents'][0][i]
            meta = results['metadatas'][0][i]
            
            cwe = meta.get('cwe', 'Unknown Vulnerability')
            patch = meta.get('patch', '')
            
            # Format the historical vulnerability as a hint for the AI
            output_text = f"VULNERABILITY DETECTED: {cwe}.\n\n"
            if patch:
                output_text += f"Step 1: Apply the historical patch to fix this {cwe} vulnerability.\n\n```\n{patch}\n```"
            else:
                output_text += f"Step 1: Manually review the code to mitigate {cwe}."
                
            examples.append({
                "input": doc,
                "output": output_text
            })
    return examples

def load_golden_examples(filepath):
    """Loads the golden dataset to be used for Few-Shot prompting."""
    examples = []
    if not os.path.exists(filepath):
        print(f"Warning: Golden dataset not found at {filepath}")
        return examples
        
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            examples.append(json.loads(line.strip()))
    return examples

def build_prompt(system_instruction, golden_examples, target_code):
    """Constructs the prompt using the ChatML format required by Qwen."""
    prompt = f"<|im_start|>system\nYou are Cypher, an expert AI application security auditor. {system_instruction}\n<|im_end|>\n"
    
    # Inject 2 golden examples for Few-Shot learning
    for example in golden_examples[:2]:
        prompt += f"<|im_start|>user\n{example['input']}\n<|im_end|>\n"
        prompt += f"<|im_start|>assistant\n{example['output']}\n<|im_end|>\n"
    
    # Add the actual code we want to analyze
    prompt += f"<|im_start|>user\n{target_code}\n<|im_end|>\n"
    prompt += "<|im_start|>assistant\n"
    
    return prompt

def main():
    # Paths
    base_dir = os.path.dirname(os.path.dirname(__file__))
    model_path = os.path.join(base_dir, 'models', 'qwen2.5-coder-32b-instruct-q4_k_m.gguf')
    dataset_path = os.path.join(base_dir, 'data', 'golden_dataset.jsonl')
    
    if not os.path.exists(model_path):
        print(f"Error: Model not found at {model_path}. Please wait for the download to finish.")
        return

    print("Loading model into VRAM... (This may take a moment)")
    
    # Initialize the model
    # n_gpu_layers: offload a few layers to CPU to save VRAM (max is usually ~64)
    # flash_attn: drastically reduces VRAM usage for the context window
    llm = Llama(
        model_path=model_path,
        n_gpu_layers=50, # CHANGED: from -1 to 50 to free up GPU memory
        n_ctx=8192,
        flash_attn=True, # ADDED: Flash Attention saves massive amounts of VRAM
        verbose=True 
    )
    
    # Load examples and prepare the prompt
    examples = load_golden_examples(dataset_path)
    system_instruction = "Analyze the provided code for vulnerabilities. If found, provide a step-by-step patch."
    
    # A test case: Vulnerable C code (Format String Vulnerability)
    test_code = """
    void log_message(char *user_input) {
        printf(user_input); // Vulnerable to format string attacks
    }
    """
    
    print("\n[Cypher] Analyzing Target Code...")
    prompt = build_prompt(system_instruction, examples, test_code)
    
    # Run the model
    output = llm(
        prompt,
        max_tokens=512,
        temperature=0.2, # Low temperature for more deterministic/factual output
        stop=["<|im_end|>"]
    )
    
    print("\n--- CYPHER ANALYSIS REPORT ---")
    print(output['choices'][0]['text'].strip())
    print("------------------------------\n")

if __name__ == "__main__":
    main()