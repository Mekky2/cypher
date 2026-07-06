import os
import glob
import pandas as pd
import json

def process_diversevul():
    base_dir = os.path.dirname(os.path.dirname(__file__))
    raw_dir = os.path.join(base_dir, 'data', 'raw', 'DiverseVul')
    output_file = os.path.join(base_dir, 'data', 'processed', 'diversevul_vulnerable.jsonl')
    
    # Ensure processed directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    print("[+] Searching for raw Parquet files in DiverseVul...")
    
    # Find all parquet files in the directory (and subdirectories)
    parquet_files = glob.glob(os.path.join(raw_dir, '**', '*.parquet'), recursive=True)
    
    if not parquet_files:
        print("[-] Error: No .parquet files found. Did the Hugging Face download succeed?")
        return

    print(f"[+] Found {len(parquet_files)} parquet file(s). Processing...")

    vulnerable_count = 0
    
    with open(output_file, 'w', encoding='utf-8') as f_out:
        for file in parquet_files:
            print(f"    -> Loading {os.path.basename(file)} into RAM...")
            
            # Load the parquet file using pandas
            df = pd.read_parquet(file)
            
            # DiverseVul uses 'target' = 1 for vulnerable code, 0 for safe code
            # Let's filter out all the safe code to save space
            vulnerable_df = df[df['target'] == 1]
            
            print(f"    -> Extracted {len(vulnerable_df)} vulnerable functions from this file.")
            
            # Convert each row into our AI JSONL format
            for _, row in vulnerable_df.iterrows():
                func_code = row.get('func', '')
                cwes = row.get('cwe', [])
                
                # Some datasets store CWEs as numpy arrays or lists
                if not isinstance(cwes, list):
                    cwes = list(cwes) if cwes is not None else []
                
                entry = {
                    "cwe_tags": cwes,
                    "code": func_code,
                    "source": "DiverseVul"
                }
                
                f_out.write(json.dumps(entry) + '\n')
                vulnerable_count += 1

    print(f"\n[+] Success! Saved {vulnerable_count} real-world vulnerable functions to:")
    print(f"    {output_file}")
    print("[+] This data is now ready for Fine-Tuning or RAG!")

def process_bigvul():
    base_dir = os.path.dirname(os.path.dirname(__file__))
    raw_dir = os.path.join(base_dir, 'data', 'raw', 'BigVul')
    output_file = os.path.join(base_dir, 'data', 'processed', 'bigvul_vulnerable.jsonl')
    
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    print("\n[+] Searching for raw Parquet files in BigVul...")
    
    parquet_files = glob.glob(os.path.join(raw_dir, '**', '*.parquet'), recursive=True)
    if not parquet_files:
        print("[-] Error: No .parquet files found for BigVul.")
        return

    vulnerable_count = 0
    with open(output_file, 'w', encoding='utf-8') as f_out:
        for file in parquet_files:
            print(f"    -> Loading {os.path.basename(file)} into RAM...")
            df = pd.read_parquet(file)
            
            # BigVul includes both the vulnerable code and the exact patched code!
            if 'vul' in df.columns:
                vulnerable_df = df[df['vul'] == 1]
            else:
                vulnerable_df = df
                
            for _, row in vulnerable_df.iterrows():
                func_code = row.get('func_before', '')
                patched_code = row.get('func_after', '')
                
                if not func_code:
                    continue
                    
                cwes = row.get('CWE ID', row.get('cwe', []))
                if not isinstance(cwes, list):
                    cwes = [str(cwes)] if pd.notna(cwes) else []
                    
                entry = {
                    "cwe_tags": cwes,
                    "code": func_code,
                    "patch": patched_code,  # The golden nugget: the fix!
                    "source": "BigVul"
                }
                
                f_out.write(json.dumps(entry) + '\n')
                vulnerable_count += 1
                
    print(f"[+] Success! Saved {vulnerable_count} BigVul functions to:")
    print(f"    {output_file}")

def process_securityeval():
    base_dir = os.path.dirname(os.path.dirname(__file__))
    raw_dir = os.path.join(base_dir, 'data', 'raw', 'SecurityEval')
    output_file = os.path.join(base_dir, 'data', 'processed', 'securityeval_vulnerable.jsonl')
    
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    print("\n[+] Searching for data files in SecurityEval...")
    
    # SecurityEval might be downloaded as parquet or jsonl depending on HF
    files = glob.glob(os.path.join(raw_dir, '**', '*.*'), recursive=True)
    data_files = [f for f in files if f.endswith(('.parquet', '.json', '.jsonl'))]
    
    if not data_files:
        print("[-] Error: No data files found for SecurityEval.")
        return

    vulnerable_count = 0
    with open(output_file, 'w', encoding='utf-8') as f_out:
        for file in data_files:
            print(f"    -> Loading {os.path.basename(file)}...")
            try:
                if file.endswith('.parquet'):
                    df = pd.read_parquet(file)
                elif file.endswith(('.json', '.jsonl')):
                    df = pd.read_json(file, lines=file.endswith('.jsonl'))
                else:
                    continue
                    
                for _, row in df.iterrows():
                    # SecurityEval focuses on Python
                    func_code = row.get('Insecure_code', row.get('code', ''))
                    
                    if not func_code:
                        continue
                        
                    cwes = row.get('Vulnerability', row.get('cwe', []))
                    if not isinstance(cwes, list):
                        cwes = [str(cwes)] if pd.notna(cwes) else []
                        
                    entry = {
                        "cwe_tags": cwes,
                        "code": func_code,
                        "source": "SecurityEval"
                    }
                    
                    f_out.write(json.dumps(entry) + '\n')
                    vulnerable_count += 1
            except Exception as e:
                print(f"    [-] Could not parse {os.path.basename(file)}: {e}")
                
    print(f"[+] Success! Saved {vulnerable_count} Python vulnerabilities to:")
    print(f"    {output_file}")

if __name__ == "__main__":
    print("=== Cypher Local Dataset Processor ===")
    process_diversevul()
    process_bigvul()
    process_securityeval()
    print("\n[+] All datasets successfully normalized for AI training!")