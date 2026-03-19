# Vulnerable: LLM output used in dangerous execution contexts
import os
import subprocess
import sqlite3

def run_ai_code(llm_output: str):
    # AI005: eval of LLM response content
    result = eval(llm_output)
    return result


def execute_ai_code(model_output: str):
    # AI005: exec of LLM output
    exec(model_output)


def run_shell_command(llm_output: str):
    # AI005: LLM output passed to shell
    os.system(llm_output)


def run_subprocess(ai_output: str):
    # AI005: LLM output to subprocess
    subprocess.run(ai_output, shell=True)


def run_sql(cursor: sqlite3.Cursor, llm_output: str):
    # AI005: LLM output in SQL query
    cursor.execute(llm_output)
