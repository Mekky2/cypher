import os
import sys
from llama_cpp import Llama

# Import our custom modules
# Because we are running from the src/ directory, we can import them directly
import parser as ast_parser
from cypher_engine import load_golden_examples, build_prompt

def scan_file(filepath, llm, system_instruction, examples):
    """
    Parses a single file, extracts its functions, and analyzes each one.
    """
    print(f"\n[+] Scanning file: {filepath}")
    
    # Extract functions using our AST parser
    functions = ast_parser.extract_functions(filepath)
    
    if not functions:
        print("    No functions found or unsupported file type.")
        return

    print(f"    Found {len(functions)} function(s). Analyzing...")
    
    for i, func in enumerate(functions):
        print(f"\n    -> Analyzing function {i+1}/{len(functions)}: {func['name']}")
        
        # Build the ChatML prompt
        prompt = build_prompt(system_instruction, examples, func['code'])
        
        # Run inference
        output = llm(
            prompt,
            max_tokens=512,
            temperature=0.2, # Keep it low for analytical consistency
            stop=["<|im_end|>"]
        )
        
        # Extract and format the result
        result = output['choices'][0]['text'].strip()
        
        print("    [Result]:")
        # Indent the result for readability in the terminal
        for line in result.split('\n'):
            print(f"        {line}")

def main():
    # Check for command line arguments
    if len(sys.argv) < 2:
        print("Usage: python src/cypher_scanner.py <path_to_file_or_directory>")
        sys.exit(1)
        
    target_path = sys.argv[1]
    
    # Setup paths relative to this script
    base_dir = os.path.dirname(os.path.dirname(__file__))
    model_path = os.path.join(base_dir, 'models', 'qwen2.5-coder-32b-instruct-q4_k_m.gguf')
    dataset_path = os.path.join(base_dir, 'data', 'golden_dataset.jsonl')
    
    if not os.path.exists(model_path):
        print(f"Error: Model not found at {model_path}.")
        sys.exit(1)

    print("Loading AI Engine into VRAM... (This may take a moment)")
    
    # Using the same VRAM optimizations we proved worked in the engine
    llm = Llama(
        model_path=model_path,
        n_gpu_layers=50,
        n_ctx=8192,
        flash_attn=True,
        verbose=False # Keep terminal output clean during scanning
    )
    
    examples = load_golden_examples(dataset_path)
    
    # Tell the model what to do. If the code is safe, we tell it to explicitly state that.
    system_instruction = (
        "Analyze the provided code for vulnerabilities. "
        "If found, provide a step-by-step patch. "
        "If no vulnerabilities are found, strictly output 'No vulnerabilities detected.'"
    )
    
    if os.path.isfile(target_path):
        scan_file(target_path, llm, system_instruction, examples)
    elif os.path.isdir(target_path):
        # Walk through the directory and scan all supported files
        for root, _, files in os.walk(target_path):
            for file in files:
                if file.endswith(('.py', '.c', '.cpp', '.cc', '.h', '.hpp')):
                    scan_file(os.path.join(root, file), llm, system_instruction, examples)
    else:
        print(f"Error: Path {target_path} does not exist.")

if __name__ == "__main__":
    main()