import os
import json

# Note: You will need to install the datasets library:
# pip install datasets
from datasets import load_dataset

def fetch_mega_dataset():
    print("[+] Connecting to Hugging Face Hub...")
    print("[+] Downloading DiverseVul dataset (This contains 300,000+ C/C++ functions)...")
    
    # DiverseVul is a massive dataset of vulnerable and safe C/C++ functions
    # We will load it in streaming mode so we don't nuke your RAM
    dataset = load_dataset("m-a-p/DiverseVul", split="train", streaming=True)
    
    base_dir = os.path.dirname(os.path.dirname(__file__))
    output_file = os.path.join(base_dir, 'data', 'mega_vulnerability_dataset.jsonl')
    
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    print(f"[+] Processing and filtering for vulnerable code...")
    print(f"[+] Saving to {output_file}")
    
    vulnerable_count = 0
    target_examples = 1000 # Let's grab the first 1,000 vulnerable functions to start
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for row in dataset:
            # target == 1 means the code contains a vulnerability
            if row.get('target') == 1:
                
                # Extract the vulnerable function and the CWE types
                func_code = row.get('func')
                cwes = row.get('cwe', [])
                
                # Format it for our AI Pipeline
                entry = {
                    "instruction": "Analyze this code for vulnerabilities. If found, provide a patch.",
                    "cwe_tags": cwes,
                    "input": func_code,
                    "output": f"VULNERABILITY DETECTED: {', '.join(cwes) if cwes else 'Unknown Vulnerability'}.\n\n(Patch requires generation)"
                }
                
                f.write(json.dumps(entry) + '\n')
                vulnerable_count += 1
                
                if vulnerable_count % 100 == 0:
                    print(f"    -> Extracted {vulnerable_count}/{target_examples} vulnerabilities...")
                    
                if vulnerable_count >= target_examples:
                    break
                    
    print(f"\n[+] Success! Mega dataset created with {vulnerable_count} real-world vulnerable functions.")

if __name__ == "__main__":
    fetch_mega_dataset()