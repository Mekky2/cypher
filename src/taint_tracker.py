import os
from tree_sitter import Language, Parser, Query
import tree_sitter_python as tspython

class TaintTracker:
    def __init__(self):
        # We define a list of known dangerous execution points (Sinks)
        self.dangerous_sinks = [
            "system", "popen", "run", "call",     # OS Command Injection Sinks
            "execute", "executemany",             # SQL Injection Sinks
            "eval", "exec",                       # Code Injection Sinks
            "send_file", "open"                   # Path Traversal Sinks
        ]
        
        # Initialize the Python parser
        self.language = Language(tspython.language())
        self.parser = Parser(self.language)

    def trace_file(self, filepath):
        """
        Scans a Python file for data flow from untrusted sources to dangerous sinks.
        """
        if not os.path.exists(filepath):
            return f"[-] Error: File {filepath} not found."

        with open(filepath, 'r', encoding='utf-8') as f:
            source_code = f.read()
            source_bytes = source_code.encode('utf-8')

        tree = self.parser.parse(source_bytes)
        findings = []

        # 1. Find all functions and their arguments (Potential Sources)
        func_query = Query(self.language, """
            (function_definition
                name: (identifier) @func_name
                parameters: (parameters (identifier) @param_name)
            ) @func_body
        """)

        # 2. Find all function calls (Potential Sinks)
        call_query = Query(self.language, """
            (call
                function: [
                    (identifier) @call_name
                    (attribute attribute: (identifier) @call_name)
                ]
                arguments: (argument_list (identifier) @arg_name)
            ) @call_expr
        """)

        try:
            from tree_sitter import QueryCursor
            func_cursor = QueryCursor(func_query)
            call_cursor = QueryCursor(call_query)
            func_captures = func_cursor.captures(tree.root_node)
            call_captures = call_cursor.captures(tree.root_node)
        except ImportError:
            func_captures = func_query.captures(tree.root_node)
            call_captures = call_query.captures(tree.root_node)

        # Map out the functions and their parameters
        function_params = {}
        if isinstance(func_captures, dict):
            if "func_name" in func_captures and "param_name" in func_captures:
                for f_node, p_node in zip(func_captures["func_name"], func_captures["param_name"]):
                    f_name = source_bytes[f_node.start_byte:f_node.end_byte].decode('utf-8')
                    p_name = source_bytes[p_node.start_byte:p_node.end_byte].decode('utf-8')
                    if f_name not in function_params:
                        function_params[f_name] = []
                    function_params[f_name].append(p_name)
        elif isinstance(func_captures, list):
            current_func = None
            for node, capture_name in func_captures:
                val = source_bytes[node.start_byte:node.end_byte].decode('utf-8')
                if capture_name == "func_name":
                    current_func = val
                    if current_func not in function_params:
                        function_params[current_func] = []
                elif capture_name == "param_name" and current_func:
                    function_params[current_func].append(val)

        # Look for dangerous sinks being called
        if isinstance(call_captures, dict):
            if "call_name" in call_captures and "arg_name" in call_captures and "call_expr" in call_captures:
                for call_n, arg_n, expr_n in zip(call_captures["call_name"], call_captures["arg_name"], call_captures["call_expr"]):
                    call_name = source_bytes[call_n.start_byte:call_n.end_byte].decode('utf-8')
                    arg_name = source_bytes[arg_n.start_byte:arg_n.end_byte].decode('utf-8')
                    
                    if call_name in self.dangerous_sinks:
                        line_number = expr_n.start_point[0] + 1
                        findings.append({
                            "sink": call_name,
                            "variable_traced": arg_name,
                            "line": line_number,
                            "status": "Tainted - Variable passed directly to dangerous sink."
                        })
                        
        elif isinstance(call_captures, list):
            current_call = None
            current_expr_node = None
            for node, capture_name in call_captures:
                val = source_bytes[node.start_byte:node.end_byte].decode('utf-8')
                if capture_name == "call_name":
                    current_call = val
                elif capture_name == "call_expr":
                    current_expr_node = node
                elif capture_name == "arg_name" and current_call in self.dangerous_sinks:
                    line_number = current_expr_node.start_point[0] + 1 if current_expr_node else node.start_point[0] + 1
                    findings.append({
                        "sink": current_call,
                        "variable_traced": val,
                        "line": line_number,
                        "status": f"Warning: Variable '{val}' flows into dangerous sink '{current_call}()'."
                    })
                    current_call = None
                    current_expr_node = None

        return findings

if __name__ == "__main__":
    tracker = TaintTracker()
    
    # Let's test it on our vulnerable honeypot file!
    base_dir = os.path.dirname(os.path.dirname(__file__))
    test_file = os.path.join(base_dir, 'tests', 'test_vulnerable.py')
    
    print(f"[+] Running Taint Tracker on {test_file}...")
    results = tracker.trace_file(test_file)
    
    if not results:
        print("    -> No direct taints found.")
    else:
        for res in results:
            print(f"\n[!] DATA FLOW VULNERABILITY DETECTED:")
            print(f"    -> Sink: {res['sink']}()")
            print(f"    -> Traced Variable: {res['variable_traced']}")
            print(f"    -> Line Number: {res['line']}")
            print(f"    -> Context: {res['status']}")