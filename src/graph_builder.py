import os
import json
from tree_sitter import Language, Parser, Query
import tree_sitter_python as tspython
import tree_sitter_cpp as tscpp
import tree_sitter_c as tsc

class CodeGraphBuilder:
    def __init__(self, target_dir):
        self.target_dir = target_dir
        self.graph = {
            "nodes": {},  # Format: { "node_id": { "type": "file|function|class", "name": "...", "file": "...", "code": "..." } }
            "edges": []   # Format: [ {"source": "node_id", "target": "node_id", "relationship": "imports|contains"} ]
        }
        
        # Initialize Parsers
        self.parsers = {
            '.py': Language(tspython.language()),
            '.c': Language(tsc.language()),
            '.cpp': Language(tscpp.language()),
            '.h': Language(tsc.language()),
            '.hpp': Language(tscpp.language())
        }

    def add_node(self, node_id, node_type, name, filepath, code=""):
        """Registers an entity in the Knowledge Graph."""
        if node_id not in self.graph["nodes"]:
            self.graph["nodes"][node_id] = {
                "type": node_type,
                "name": name,
                "file": filepath,
                "code": code
            }

    def add_edge(self, source_id, target_id, relationship):
        """Creates a relationship between two entities."""
        self.graph["edges"].append({
            "source": source_id,
            "target": target_id,
            "relationship": relationship
        })

    def parse_python_file(self, filepath, source_bytes, language):
        """Extracts Imports, Classes, and Functions from a Python file."""
        parser = Parser(language)
        tree = parser.parse(source_bytes)
        
        file_id = f"file:{filepath}"
        self.add_node(file_id, "file", os.path.basename(filepath), filepath)

        # 1. Extract Imports (To track Cross-File Data Flow)
        import_query = Query(language, """
            (import_statement name: (dotted_name) @import_name)
            (import_from_statement module_name: (dotted_name) @from_name)
        """)
        
        # Handle different tree-sitter version APIs
        try:
            from tree_sitter import QueryCursor
            cursor = QueryCursor(import_query)
            import_captures = cursor.captures(tree.root_node)
        except ImportError:
            import_captures = import_query.captures(tree.root_node)

        # Process imports
        if isinstance(import_captures, dict):
            for node_list in import_captures.values():
                for node in node_list:
                    module_name = source_bytes[node.start_byte:node.end_byte].decode('utf-8')
                    module_id = f"module:{module_name}"
                    self.add_node(module_id, "module", module_name, "external")
                    self.add_edge(file_id, module_id, "imports")
        elif isinstance(import_captures, list):
            for node, _ in import_captures:
                module_name = source_bytes[node.start_byte:node.end_byte].decode('utf-8')
                module_id = f"module:{module_name}"
                self.add_node(module_id, "module", module_name, "external")
                self.add_edge(file_id, module_id, "imports")

        # 2. Extract Functions (To maintain business logic context)
        func_query = Query(language, """
            (function_definition name: (identifier) @func_name) @func_body
        """)
        
        try:
            cursor = QueryCursor(func_query)
            func_captures = cursor.captures(tree.root_node)
        except ImportError:
            func_captures = func_query.captures(tree.root_node)
            
        if isinstance(func_captures, dict) and "func_body" in func_captures and "func_name" in func_captures:
            for body_node, name_node in zip(func_captures["func_body"], func_captures["func_name"]):
                func_name = source_bytes[name_node.start_byte:name_node.end_byte].decode('utf-8')
                func_code = source_bytes[body_node.start_byte:body_node.end_byte].decode('utf-8')
                func_id = f"func:{filepath}:{func_name}"
                
                self.add_node(func_id, "function", func_name, filepath, func_code)
                self.add_edge(file_id, func_id, "contains")
                
        elif isinstance(func_captures, list):
            current_name = None
            for node, capture_name in func_captures:
                if capture_name == "func_name":
                    current_name = source_bytes[node.start_byte:node.end_byte].decode('utf-8')
                elif capture_name == "func_body" and current_name:
                    func_code = source_bytes[node.start_byte:node.end_byte].decode('utf-8')
                    func_id = f"func:{filepath}:{current_name}"
                    
                    self.add_node(func_id, "function", current_name, filepath, func_code)
                    self.add_edge(file_id, func_id, "contains")
                    current_name = None

    def build(self):
        """Walks the directory and builds the graph."""
        print(f"[+] Building Knowledge Graph for: {self.target_dir}")
        
        for root, _, files in os.walk(self.target_dir):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in self.parsers:
                    filepath = os.path.join(root, file)
                    print(f"    -> Parsing {file}...")
                    
                    with open(filepath, 'r', encoding='utf-8') as f:
                        source_bytes = f.read().encode('utf-8')
                        
                    if ext == '.py':
                        self.parse_python_file(filepath, source_bytes, self.parsers[ext])
                    # (C/C++ logic will follow the same pattern in future updates)

    def save_graph(self, output_path):
        """Exports the graph to a JSON file for the AI Agents to read."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.graph, f, indent=4)
        print(f"\n[+] Knowledge Graph successfully saved to {output_path}")
        print(f"[+] Discovered {len(self.graph['nodes'])} nodes and mapped {len(self.graph['edges'])} relationships.")

if __name__ == "__main__":
    # Test the Graph Builder on our own src folder!
    base_dir = os.path.dirname(os.path.dirname(__file__))
    src_dir = os.path.join(base_dir, 'src')
    output_file = os.path.join(base_dir, 'data', 'knowledge_graph.json')
    
    builder = CodeGraphBuilder(src_dir)
    builder.build()
    builder.save_graph(output_file)