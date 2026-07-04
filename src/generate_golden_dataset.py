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
        },
        {
            "instruction": instruction,
            "input": """from flask import request, send_file
import os

@app.route('/download')
def download_file():
    filename = request.args.get('file')
    # Vulnerable to Path Traversal
    filepath = os.path.join('/var/www/uploads', filename)
    return send_file(filepath)""",
            "output": """VULNERABILITY DETECTED: Path Traversal (CWE-22).

Step 1: The user input `filename` is directly concatenated into a file path, allowing attackers to use `../` to access files outside the intended directory.
Step 2: Use `os.path.basename()` to strip any directory traversal characters and ensure only the exact filename is used.
Step 3: Validate the final path explicitly.

```python
from flask import request, send_file, abort
import os

@app.route('/download')
def download_file():
    filename = request.args.get('file')
    # Secure: extract only the base file name
    safe_filename = os.path.basename(filename)
    filepath = os.path.join('/var/www/uploads', safe_filename)
    
    if not os.path.exists(filepath):
        abort(404)
        
    return send_file(filepath)
```"""
        },
        {
            "instruction": instruction,
            "input": """import hashlib

def hash_password(password):
    # Vulnerable: MD5 is cryptographically broken
    hasher = hashlib.md5()
    hasher.update(password.encode('utf-8'))
    return hasher.hexdigest()""",
            "output": """VULNERABILITY DETECTED: Use of a Broken or Risky Cryptographic Algorithm (CWE-327).

Step 1: The code uses MD5, which is vulnerable to collision attacks and is entirely unsuitable for hashing passwords.
Step 2: Replace MD5 with a secure, key-derivation function designed for passwords, such as `bcrypt` or `Argon2`.
Step 3: If general fast hashing is needed (not passwords), use SHA-256 or SHA-3.

```python
import bcrypt

def hash_password(password):
    # Secure: Generate a salt and hash using bcrypt
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed
```"""
        },
        {
            "instruction": instruction,
            "input": """#include <string>
#include <iostream>

void connect_to_database() {
    // Vulnerable: Hardcoded credentials
    std::string db_user = "admin";
    std::string db_pass = "SuperSecretPassword123!";
    
    std::cout << "Connecting as " << db_user << std::endl;
    // connection logic...
}""",
            "output": """VULNERABILITY DETECTED: Use of Hard-coded Credentials (CWE-798).

Step 1: Hardcoding passwords in source code exposes them to anyone who can read the repository or decompile the application.
Step 2: Remove the hardcoded strings and retrieve the credentials dynamically from environment variables or a secure secret manager.

```cpp
#include <string>
#include <iostream>
#include <cstdlib>

void connect_to_database() {
    // Secure: Retrieve credentials from environment variables
    const char* user_env = std::getenv("DB_USER");
    const char* pass_env = std::getenv("DB_PASS");
    
    if (!user_env || !pass_env) {
        std::cerr << "Error: Database credentials not set in environment." << std::endl;
        return;
    }
    
    std::string db_user(user_env);
    std::string db_pass(pass_env);
    
    std::cout << "Connecting as " << db_user << std::endl;
    // connection logic...
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