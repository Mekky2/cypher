# Cypher: Enterprise-Grade AI Security Scanner

Cypher is a local, AI-powered static application security testing (SAST) tool. It leverages the 32-billion parameter Qwen2.5-Coder model and precise Abstract Syntax Tree (AST) parsing to audit codebases for vulnerabilities without sending your proprietary code to the cloud.

# System Architecture

Cypher prevents LLM "context bloat" and hallucination by breaking down massive codebases into highly focused, analyzable chunks:

1. Context Chunker (src/parser.py): Uses tree-sitter to parse C, C++, and Python files exactly like a compiler does. It extracts individual functions and methods to prevent the AI from getting "lost in the middle" of massive files.

2. AI Inference Engine (src/cypher_engine.py): Uses llama.cpp with GPU offloading and Flash Attention to run the 32B Qwen model locally. It uses Few-Shot prompting to force the AI to output structured, actionable patches.

3. Master Scanner (src/cypher_scanner.py): Orchestrates the pipeline. It traverses target directories, chunks the files, feeds them to the AI, and generates the final vulnerability report.

# Data Strategy

Cypher uses a hybrid data approach to maximize accuracy:

* The Golden Dataset (golden_dataset.jsonl): A highly curated set of OWASP Top 10 vulnerabilities (Path Traversal, Hardcoded Secrets, SQLi, etc.) injected directly into the prompt to enforce strict output formatting.

* The Mega Datasets: Massive open-source vulnerability databases (DiverseVul, BigVul, SecurityEval) downloaded locally to build Cypher's vulnerability intuition for future Fine-Tuning or RAG (Retrieval-Augmented Generation).

# Getting Started

### 1. Prerequisites

* Python 3.10+

* NVIDIA GPU with ~24GB VRAM (e.g., RTX 3090 / 4090)

* CUDA Toolkit (for hardware acceleration)

* Hugging Face CLI (hf)

## 2. Installation
----------------------------------------------------------------------
### 1. Clone the repository

git clone https://github.com/yourusername/cypher.git
cd cypher

### 2. Set up virtual environment

python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate

### 3. Install dependencies (Requires CUDA build tools for GPU acceleration)

CMAKE_ARGS="-DGGML_CUDA=on" pip install -r requirements.txt

----------------------------------------------------------------------

## 3. Download Models & Datasets
----------------------------------------------------------------------
### 1. Authenticate with Hugging Face

hf auth login

### 2. Download the Qwen2.5-Coder 32B model (4-bit quantized)

hf download Qwen/Qwen2.5-Coder-32B-Instruct-GGUF qwen2.5-coder-32b-instruct-q4_k_m.gguf --local-dir models/

### 3. Download raw vulnerability datasets (DiverseVul, BigVul, SecurityEval)

chmod +x scripts/download_raw_datasets.sh
./scripts/download_raw_datasets.sh

----------------------------------------------------------------------

4. Setup the AI Brain
----------------------------------------------------------------------
### Generate the Few-Shot Golden Dataset

python src/generate_golden_dataset.py

----------------------------------------------------------------------

### Usage

To scan a specific file or an entire directory, use the Master Scanner:

----------------------------------------------------------------------
python src/cypher_scanner.py <path_to_file_or_directory>

----------------------------------------------------------------------

### Example:

----------------------------------------------------------------------
python src/cypher_scanner.py src/parser.py

----------------------------------------------------------------------

The scanner will output a step-by-step remediation plan and patched code blocks for any vulnerabilities it discovers.