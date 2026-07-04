import os
from tree_sitter import Language, Parser, Query
import tree_sitter_python as tspython
import tree_sitter_cpp as tscpp
import tree_sitter_c as tsc

def extract_functions(filepath):
    """
    Parses a source file and returns a list of dictionaries containing
    function names and their raw code blocks.
    """
    if not os.path.exists(filepath):
        print(f"Error: File not found {filepath}")
        return []

    _, ext = os.path.splitext(filepath)
    ext = ext.lower()

    # Determine language based on extension
    if ext == '.py':
        language = Language(tspython.language())
        query_string = """
        (function_definition
            name: (identifier) @func_name) @func_body
        """
    elif ext in ['.cpp', '.cc', '.cxx', '.hpp', '.h']:
        language = Language(tscpp.language())
        query_string = """
        (function_definition
            declarator: (function_declarator 
                declarator: (identifier) @func_name)) @func_body
        """
    elif ext == '.c':
        language = Language(tsc.language())
        query_string = """
        (function_definition
            declarator: (function_declarator 
                declarator: (identifier) @func_name)) @func_body
        """
    else:
        print(f"Unsupported file type: {ext}")
        return []

    # Initialize parser
    parser = Parser(language)

    # Read the file content
    with open(filepath, 'r', encoding='utf-8') as f:
        source_code = f.read()
    
    source_bytes = source_code.encode('utf-8')
    tree = parser.parse(source_bytes)

    # Execute the Tree-sitter query
    query = Query(language, query_string)
    
    try:
        # tree-sitter 0.25+ moved captures to QueryCursor
        from tree_sitter import QueryCursor
        cursor = QueryCursor(query)
        captures = cursor.captures(tree.root_node)
    except (ImportError, AttributeError):
        # Fallback for older tree-sitter versions
        captures = query.captures(tree.root_node)

    functions = []
    
    # Handle dictionary return type (tree-sitter 0.22+ and 0.25+)
    if isinstance(captures, dict):
        if "func_body" in captures and "func_name" in captures:
            bodies = captures["func_body"]
            names = captures["func_name"]
            
            for body_node, name_node in zip(bodies, names):
                func_name = source_bytes[name_node.start_byte:name_node.end_byte].decode('utf-8')
                func_code = source_bytes[body_node.start_byte:body_node.end_byte].decode('utf-8')
                
                functions.append({
                    "file": filepath,
                    "name": func_name,
                    "code": func_code
                })
                
    # Handle list of tuples return type (older tree-sitter bindings)
    elif isinstance(captures, list):
        current_name = None
        for node, capture_name in captures:
            if capture_name == "func_name":
                current_name = source_bytes[node.start_byte:node.end_byte].decode('utf-8')
            elif capture_name == "func_body" and current_name:
                func_code = source_bytes[node.start_byte:node.end_byte].decode('utf-8')
                functions.append({
                    "file": filepath,
                    "name": current_name,
                    "code": func_code
                })
                current_name = None

    return functions

if __name__ == "__main__":
    # Test the parser by having it parse itself!
    test_file = __file__
    print(f"Parsing {test_file}...")
    
    extracted = extract_functions(test_file)
    
    for fn in extracted:
        print(f"\n--- Found Function: {fn['name']} ---")
        print(fn['code'])