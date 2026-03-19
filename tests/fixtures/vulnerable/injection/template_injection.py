# Intentionally vulnerable: server-side template injection (SSTI)
from flask import Flask, request, render_template_string
from jinja2 import Template

app = Flask(__name__)


@app.route("/greet")
def greet():
    # VULNERABLE: user input passed directly as template string
    name = request.args.get("name", "World")
    return render_template_string(request.args.get("template", "Hello!"))


def render_custom():
    # VULNERABLE: Template() with user-controlled string
    tmpl = Template(request.form.get("template"))
    return tmpl.render()


def execute_code():
    # VULNERABLE: eval() with request input
    expr = request.args.get("expr")
    result = eval(request.args.get("expr"))
    return str(result)
