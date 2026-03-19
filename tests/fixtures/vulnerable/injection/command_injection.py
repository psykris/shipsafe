# Intentionally vulnerable: command injection
import os
import subprocess
from flask import request


def ping_host():
    host = request.args.get("host")
    # VULNERABLE: user input passed directly to shell
    os.system("ping -c 4 " + host)


def convert_file():
    filename = request.args.get("filename")
    # VULNERABLE: shell=True with user input enables injection
    subprocess.run("convert " + filename + " output.pdf", shell=True)


def run_command():
    cmd = request.args.get("cmd")
    # VULNERABLE: Popen with shell=True
    result = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    return result.communicate()[0]
