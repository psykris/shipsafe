# SAFE: parameterized queries and validated inputs
import sqlite3
import subprocess
import os
import yaml
from pathlib import Path

conn = sqlite3.connect("app.db")
cursor = conn.cursor()

BASE_UPLOAD_DIR = Path("/safe/uploads").resolve()


def get_user(username):
    # SAFE: parameterized query with tuple
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()


def search_products(name):
    # SAFE: bound parameter
    cursor.execute("SELECT * FROM products WHERE name = %s", (name,))
    return cursor.fetchall()


def run_command(allowed_args):
    # SAFE: no shell=True, explicit argument list
    result = subprocess.run(["convert", allowed_args, "output.pdf"], shell=False)
    return result.returncode


def read_file(filename):
    # SAFE: path confined to allowed base directory
    safe_path = BASE_UPLOAD_DIR / filename
    real_path = safe_path.resolve()
    if not str(real_path).startswith(str(BASE_UPLOAD_DIR)):
        raise ValueError("Path traversal detected")
    return real_path.read_text()


def load_config(path):
    with open(path) as f:
        # SAFE: yaml.safe_load prevents code execution
        return yaml.safe_load(f)
