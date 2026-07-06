# Purpose: This is a test python file to demonstrate vulnerabilities for the Cypher AI engine.

import os
import sqlite3

def ping_server(ip_address):
    # CWE-78: Improper Neutralization of Special Elements used in an OS Command (Command Injection)
    # An attacker could pass "8.8.8.8; cat /etc/passwd" to take over the server.
    command = f"ping -c 4 {ip_address}"
    os.system(command)

def get_user_data(username):
    # CWE-89: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)
    # An attacker could pass "' OR 1=1 --" to dump the entire database.
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()