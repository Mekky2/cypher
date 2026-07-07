import os
import json
import re
from llama_cpp import Llama

# Import our custom tools
from taint_tracker import TaintTracker

class CypherAgent:
    def __init__(self):
        print("[+] Initializing Cypher Autonomous Agent...")
        base_dir = os.path.dirname(os.path.dirname(__file__))
        self.model_path = os.path.join(base_dir, 'models', 'qwen2.5-coder-32b-instruct-q4_k_m.gguf')
        self.graph_path = os.path.join(base_dir, 'data', 'knowledge_graph.json')
        
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Model not found at {self.model_path}")
            
        # Load the 32B model with the exact optimizations we proved earlier
        self.llm = Llama(
            model_path=self.model_path,
            n_gpu_layers=50,
            n_ctx=8192,
            flash_attn=True,
            verbose=False
        )
        
        self.taint_tracker = TaintTracker()
        
        # Load the Knowledge Graph
        self.graph = {"nodes": {}, "edges": []}
        if os.path.exists(self.graph_path):
            with open(self.graph_path, 'r', encoding='utf-8') as f:
                self.graph = json.load(f)

    # ==========================================
    # TOOL DEFINITIONS
    # ==========================================
    
    def tool_run_taint_tracker(self, filepath):
        """Tool: Runs the Taint Tracker on a specific file."""
        print(f"    [Tool Execution] Running Taint Tracker on {filepath}...")
        results = self.taint_tracker.trace_file(filepath)
        if not results or isinstance(results, str):
            return "Observation: No direct data flow vulnerabilities found."
        return f"Observation: Taint Tracker found potential issues: {json.dumps(results)}"

    def tool_query_knowledge_graph(self, target_file):
        """Tool: Queries the graph to see what a file imports or contains."""
        print(f"    [Tool Execution] Querying Knowledge Graph for {target_file}...")
        file_id = f"file:{target_file}"
        if file_id not in self.graph["nodes"]:
            return "Observation: File not found in Knowledge Graph."
            
        imports = [e["target"] for e in self.graph["edges"] if e["source"] == file_id and e["relationship"] == "imports"]
        functions = [e["target"] for e in self.graph["edges"] if e["source"] == file_id and e["relationship"] == "contains"]
        
        result = {
            "file": target_file,
            "imports_modules": imports,
            "contains_functions": functions
        }
        return f"Observation: Graph Query Results: {json.dumps(result)}"

    # ==========================================
    # ATTACKER AGENT LOGIC
    # ==========================================
    
    def run_attacker(self, target_filepath, target_code):
        print(f"\n[>>] SPAWNING ATTACKER AGENT...")
        
        system_prompt = """You are the Cypher Attacker Agent, an elite Autonomous AI Red Teamer. 
Your goal is to find exploitable vulnerabilities in the target code. Do NOT just guess. You must investigate using tools.

You have access to the following tools:
1. run_taint_tracker: Runs static data flow analysis to find sinks. Input should be the filepath.
2. query_knowledge_graph: Checks what modules the file imports and what functions it contains. Input should be the filepath.

You must use the following strict format for your thoughts:

Thought: Consider what you need to do next to verify a vulnerability.
Action: the action to take, should be one of [run_taint_tracker, query_knowledge_graph]
Action Input: the input to the action
Observation: the result of the action (provided by the system)
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I now have enough information to confirm the vulnerability.
Final Answer: A detailed vulnerability report containing the CWE, the exploit chain logic, and a patched code snippet.

Begin!"""

        prompt = f"<|im_start|>system\n{system_prompt}\n<|im_end|>\n"
        prompt += f"<|im_start|>user\nTarget File: {target_filepath}\n\nCode:\n```python\n{target_code}\n```\nAnalyze this.\n<|im_end|>\n"
        prompt += "<|im_start|>assistant\n"
        
        max_loops = 5
        loop_count = 0
        
        while loop_count < max_loops:
            loop_count += 1
            
            output = self.llm(
                prompt,
                max_tokens=512,
                temperature=0.1,
                stop=["Observation:", "<|im_end|>"]
            )
            
            response = output['choices'][0]['text']
            prompt += response
            
            print(f"\n--- Attacker Step {loop_count} ---")
            print(response.strip())
            
            if "Final Answer:" in response:
                print("\n[+] Attacker successfully completed the investigation!")
                return response.split("Final Answer:")[-1].strip()
                
            action_match = re.search(r"Action:\s*(.*?)\n", response)
            input_match = re.search(r"Action Input:\s*(.*?)(?:\n|$)", response)
            
            if action_match and input_match:
                action = action_match.group(1).strip()
                action_input = input_match.group(1).strip()
                
                observation = ""
                if action == "run_taint_tracker":
                    observation = self.tool_run_taint_tracker(action_input)
                elif action == "query_knowledge_graph":
                    observation = self.tool_query_knowledge_graph(action_input)
                else:
                    observation = f"Observation: Error - Tool '{action}' does not exist."
                    
                print(f"\n    {observation}")
                prompt += f"\n{observation}\n"
            else:
                prompt += "\nThought: I should provide my Final Answer now.\nFinal Answer:"

        print("\n[-] Attacker reached max loops without a final answer. Forcing conclusion.")
        return None

    # ==========================================
    # DEFENDER AGENT LOGIC
    # ==========================================
    
    def run_defender(self, target_filepath, target_code, attacker_report):
        print(f"\n[>>] SPAWNING DEFENDER AGENT...")
        
        system_prompt = """You are the Cypher Defender Agent, an expert Application Security Engineer.
Your job is to read an Attacker's Vulnerability Report and try to PROVE IT WRONG.
You must look at the provided source code and determine if the Attacker missed a mitigation, a sanitization step, a firewall rule, or a business logic constraint that would make their exploit fail.

Instructions:
1. Review the Attacker's Report and the Source Code carefully.
2. If the Attacker is right and the code is truly vulnerable, you must output exactly:
   VULNERABILITY CONFIRMED: [Followed by a brief explanation of why the attacker is right]
3. If the Attacker missed a mitigation and the exploit would fail, you must output exactly:
   FALSE POSITIVE: [Followed by a detailed explanation of why the attack would fail and how the code is already safe]

Do not provide patched code, only focus on the validity of the exploit."""

        prompt = f"<|im_start|>system\n{system_prompt}\n<|im_end|>\n"
        prompt += f"<|im_start|>user\nTarget File: {target_filepath}\n\nCode:\n
http://googleusercontent.com/immersive_entry_chip/0