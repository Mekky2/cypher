import json
import os

def generate_golden_dataset():
    # Define the dataset path
    data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
    output_file = os.path.join(data_dir, 'golden_dataset.jsonl')
    
    # Ensure the data directory exists
    os.makedirs(data_dir, exist_ok=True)

    instruction = "Analyze this code for vulnerabilities. If found, provide a step-by-step patch."

    dataset = [
        {
            "instruction": instruction,
            "input": """void process(char *user_input) {
    char buffer[50];
    strcpy(buffer, user_input);
}""",
            "output": """VULNERABILITY DETECTED: Buffer Overflow (CWE-120).

Step 1: Replace the unsafe `strcpy` function with `strncpy` to enforce bounds checking.
Step 2: Ensure the buffer is explicitly null-terminated, as `strncpy` does not guarantee this if the source exceeds the limit.

```cpp
void process(char *user_input) {
    char buffer[50];
    strncpy(buffer, user_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\\0';
}
```"""
        },
        {
            "instruction": instruction,
            "input": """import sqlite3

def get_user_data(username):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Vulnerable SQL query using f-strings
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()""",
            "output": """VULNERABILITY DETECTED: SQL Injection (CWE-89).

Step 1: Remove the f-string formatting from the SQL query to prevent user input from being evaluated as SQL commands.
Step 2: Use parameterized queries (using `?` in SQLite) and pass the user input as a tuple to the `execute` function.

```python
import sqlite3

def get_user_data(username):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Safe parameterized query
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchall()
```"""
        },
        {
            "instruction": instruction,
            "input": """#include <iostream>

void process_data() {
    int* ptr = new int(10);
    delete ptr;
    
    // Later in the code...
    std::cout << "Value: " << *ptr << std::endl;
}""",
            "output": """VULNERABILITY DETECTED: Use After Free (CWE-416).

Step 1: The pointer `ptr` is accessed after its memory has been deallocated, which can lead to undefined behavior or exploitation.
Step 2: Set the pointer to `nullptr` immediately after calling `delete` to prevent accidental reuse.
Step 3: Add a null check before accessing the pointer.

```cpp
#include <iostream>

void process_data() {
    int* ptr = new int(10);
    delete ptr;
    ptr = nullptr; // Prevent dangling pointer
    
    // Later in the code...
    if (ptr != nullptr) {
        std::cout << "Value: " << *ptr << std::endl;
    }
}
```"""
        },
        {
            "instruction": instruction,
            "input": """import os

def ping_server(ip_address):
    # Vulnerable to command injection if ip_address contains shell metacharacters
    os.system(f"ping -c 4 {ip_address}")""",
            "output": """VULNERABILITY DETECTED: Command Injection (CWE-78).

Step 1: Replace `os.system` with the `subprocess` module, which provides safer execution.
Step 2: Pass the command and its arguments as a list of strings rather than a single concatenated string. This prevents the shell from interpreting malicious metacharacters.

```python
import subprocess

def ping_server(ip_address):
    # Safe execution using subprocess with a list of arguments
    subprocess.run(["ping", "-c", "4", ip_address], check=True)
```"""
        },
        {
            "instruction": instruction,
            "input": """void create_array(int size) {
    int* arr = new int[size];
    if (size <= 0) {
        return; // Memory leak here
    }
    // Process array...
    delete[] arr;
}""",
            "output": """VULNERABILITY DETECTED: Memory Leak (CWE-401).

Step 1: If `size <= 0`, the function returns early without freeing the allocated memory for `arr`.
Step 2: Use modern C++ smart pointers like `std::unique_ptr` to automatically manage the memory lifecycle, ensuring it is freed regardless of how the function exits.

```cpp
#include <memory>

void create_array(int size) {
    if (size <= 0) {
        return;
    }
    // Automatically manages memory, deleting when going out of scope
    std::unique_ptr<int[]> arr(new int[size]);
    
    // Process array...
}
```"""
        }
    ]

    # Write the dataset to a JSONL file
    with open(output_file, 'w', encoding='utf-8') as f:
        for entry in dataset:
            f.write(json.dumps(entry) + '\n')
            
    print(f"Successfully generated {len(dataset)} golden examples at {output_file}")

if __name__ == "__main__":
    generate_golden_dataset()