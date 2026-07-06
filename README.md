# Cypher: AI Security Scanner

Cypher is a local, AI-powered static application security testing (SAST) tool. It leverages the 32-billion parameter Qwen2.5-Coder model and precise Abstract Syntax Tree (AST) parsing to audit codebases for vulnerabilities without sending your proprietary code to the cloud.

# System Architecture

#### Cypher prevents LLM "context bloat" and hallucination by breaking down massive codebases into highly focused chunks and providing the AI with exact historical context:

1. Context Chunker (src/parser.py): Uses tree-sitter to parse C, C++, and Python files exactly like a compiler does. It extracts individual functions to prevent the AI from getting "lost in the middle" of massive files.

2. AI Memory Bank (src/build_vector_db.py): A local ChromaDB vector database. It embeds tens of thousands of real-world vulnerabilities (CVEs) from open-source datasets into highly searchable mathematical vectors using sentence-transformers.

3. AI Inference Engine (src/cypher_engine.py): Uses llama.cpp with GPU offloading and Flash Attention to run the 32B Qwen model locally. It uses RAG (Retrieval-Augmented Generation) to fetch the closest matching historical vulnerability from ChromaDB and injects it into the prompt as a hint.

4. Master Scanner (src/cypher_scanner.py): Orchestrates the pipeline. It traverses target directories, chunks the files, queries the Vector DB, feeds the combined context to the AI, and prints the step-by-step remediation plan.

# Data Strategy

Cypher's accuracy comes from a hybrid data approach:

* The Golden Dataset: A curated set of highly formatted few-shot examples injected into the prompt to enforce strict output formatting (Step 1, Step 2, Patched Code).

* The Mega Datasets: Massive open-source vulnerability databases (DiverseVul, BigVul, SecurityEval) processed and stored in the AI's Vector Memory Bank to provide deep security intuition.

# Getting Started

### 1. Prerequisites

* Python 3.10+

* NVIDIA GPU with ~24GB VRAM (e.g., RTX 3090 / 4090)

* CUDA Toolkit (for hardware acceleration)

* Hugging Face CLI (hf)

## 2. Installation
----------------------------------------------------------------------
#### 1. Clone the repository

git clone https://github.com/yourusername/cypher.git
cd cypher

#### 2. Set up virtual environment

python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate

#### 3. Install dependencies (Requires CUDA build tools for GPU acceleration)

CMAKE_ARGS="-DGGML_CUDA=on" pip install -r requirements.txt

----------------------------------------------------------------------

## 3. Download Models & Datasets
----------------------------------------------------------------------
#### 1. Authenticate with Hugging Face

hf auth login

#### 2. Download the Qwen2.5-Coder 32B model (4-bit quantized)

hf download Qwen/Qwen2.5-Coder-32B-Instruct-GGUF qwen2.5-coder-32b-instruct-q4_k_m.gguf --local-dir models/

#### 3. Download raw vulnerability datasets (DiverseVul, BigVul, SecurityEval)

chmod +x scripts/download_raw_datasets.sh
./scripts/download_raw_datasets.sh

----------------------------------------------------------------------

## 4. Setup the AI Brain
----------------------------------------------------------------------
#### Generate the Few-Shot Golden Dataset

python src/generate_golden_dataset.py

#### Process raw datasets into AI-ready format

python src/process_local_data.py

#### Build the ChromaDB Vector Memory Bank (~5-15 mins)

python src/build_vector_db.py
----------------------------------------------------------------------

### Usage

To scan a specific file or an entire directory, use the Master Scanner:

----------------------------------------------------------------------
python src/cypher_scanner.py <path_to_file_or_directory>

----------------------------------------------------------------------

### Example:

----------------------------------------------------------------------
python src/cypher_scanner.py tests/test_vulnerable.py

----------------------------------------------------------------------

The scanner will output a step-by-step remediation plan and patched code blocks for any vulnerabilities it discovers.