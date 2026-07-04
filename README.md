# Cypher

Cypher is an AI-driven Static Application Security Testing (SAST) tool designed to analyze Python and C/C++ codebases. It detects vulnerabilities (such as buffer overflows, memory leaks, injection flaws) and generates clear, step-by-step instructions on how to patch them.

# Architecture & Tech Stack

Cypher is built to operate efficiently on local consumer hardware while maintaining enterprise-grade context windows for large codebases.

> Base Model: Qwen3-Coder 30B

> Quantization: 4-bit (Q4_K_M) via GGUF to fit within consumer VRAM limits.

> Inference Engine: llama.cpp / vLLM optimized for PagedAttention.

> Hardware Target: 24GB VRAM (e.g., RTX 3090 Ti).

> Context Window: Configured for 300,000+ tokens to ingest large, multi-file C++ repositories without context fragmentation.

> Orchestration: Python (Parsing, Prompting, and Patch Formatting).

# Project Structure

> src/: Python orchestrator code (AST parsing, chunking, and AI pipeline logic).

> models/: Directory for local open-weight model GGUF files and LoRA adapters. (Ignored in git)

> data/: Vulnerability datasets for fine-tuning and evaluation. (Ignored in git)

> tests/: Vulnerable C++ and Python scripts to verify model accuracy.

# Getting Started

1. Clone the repository.

2. Initialize the Python virtual environment:
----------------------------------------------
python -m venv venv
source venv/bin/activate

----------------------------------------------

3. Install dependencies (Requires CUDA build tools for GPU acceleration):
-------------------------------------------------------------
CMAKE_ARGS="-DGGML_CUDA=on" pip install -r requirements.txt

-------------------------------------------------------------

4. Download the Qwen2.5-Coder 32B model (4-bit quantized) using the Hugging Face CLI:
-------------------------------------------------------------------------------------------------------------
hf auth login  # (Requires a Hugging Face Read Token)
hf download Qwen/Qwen2.5-Coder-32B-Instruct-GGUF qwen2.5-coder-32b-instruct-q4_k_m.gguf --local-dir models/

-------------------------------------------------------------------------------------------------------------

5. Generate the Golden Dataset for Few-Shot Prompting:
-----------------------------------------
python src/generate_golden_dataset.py

-----------------------------------------

6. Run the Cypher Engine:
-----------------------------------------
python src/cypher_engine.py

-----------------------------------------