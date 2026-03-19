"""Injection vulnerability detection rules for ShipSafe.

Detects SQL injection, NoSQL injection, command injection, path traversal,
cross-site scripting (XSS), template injection, and unsafe YAML loading.
Every pattern is a class-level constant so you can audit the full catalogue
with a single grep:

    grep -A5 "patterns = \\[" src/shipsafe/rules/injection.py

Design invariants
-----------------
- Patterns live on the class, never hidden inside methods.
- Every fix includes concrete safe alternatives.
- Every rule links to the input-validation educational guide.
"""

import re

from shipsafe.finding import Finding, Severity
from shipsafe.rules.base import Rule

# -- Shared constants -------------------------------------------------------

_GUIDE_URL = "guides/04-input-validation.md"


# -- INJ001  SQLInjection ---------------------------------------------------


class SQLInjection(Rule):
    """INJ001: SQL injection via string formatting."""

    id = "INJ001"
    name = "SQL injection via string formatting"
    severity = Severity.CRITICAL
    description = (
        "SQL query built using string formatting (f-strings, .format(), "
        "% formatting, or concatenation with user input). An attacker can "
        "inject arbitrary SQL to read, modify, or delete data."
    )
    fix = (
        "Use parameterized queries / prepared statements:\n"
        "  Python:     cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
        "  Node.js:    db.query('SELECT * FROM users WHERE id = $1', [userId])\n"
        "  SQLAlchemy: session.query(User).filter(User.id == user_id)\n"
        "Never interpolate user input directly into SQL strings."
    )
    guide_url = _GUIDE_URL
    owasp_id = "A03:2021"
    cwe_id = "CWE-89"
    confidence = "medium"
    file_extensions = [".py", ".js", ".ts", ".rb", ".php"]

    patterns: list[str] = [
        r'(?:execute|cursor\.execute|query)\s*\(\s*f["\']',
        r'(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*\%s.*\%\s*\(',
        r'(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*\.format\s*\(',
        r'(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*\+\s*(?:request|req|params|input)',
        # Phase 7: Django ORM raw() with string building
        r'\.raw\s*\(\s*["\'].*\+',
        r'\.raw\s*\(\s*f["\']',
        # Phase 7: execute() with string concatenation
        r'execute\s*\(\s*["\'].*["\']?\s*\+',
        # Phase 7: f-string SQL assigned to variable (multi-line execute pattern)
        r'=\s*f["\'](?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+',
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


# -- INJ002  NoSQLInjection -------------------------------------------------


class NoSQLInjection(Rule):
    """INJ002: NoSQL injection via unsanitized query operators."""

    id = "INJ002"
    name = "NoSQL injection"
    severity = Severity.HIGH
    description = (
        "MongoDB query operators or query methods used with unsanitized user "
        "input. An attacker can manipulate query operators ($gt, $ne, $regex, "
        "etc.) to bypass authentication or extract data."
    )
    fix = (
        "Validate and sanitize user input before using in queries:\n"
        "  1. Use an ODM (Mongoose, MongoEngine) with strict schemas.\n"
        "  2. Explicitly cast expected types: int(request.args['id'])\n"
        "  3. Strip keys starting with '$' from user input.\n"
        "  4. Use allowlists for query operators."
    )
    guide_url = _GUIDE_URL
    owasp_id = "A03:2021"
    cwe_id = "CWE-943"
    confidence = "medium"
    file_extensions = [".py", ".js", ".ts"]

    patterns: list[str] = [
        r'\$(?:where|regex|gt|lt|ne|in|nin|or|and|not)\b.*(?:request|req|params|body|input)',
        r'(?:find|findOne|aggregate|updateOne|deleteOne)\s*\(.*(?:request|req|params|body)\b',
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


# -- INJ003  CommandInjection ------------------------------------------------


class CommandInjection(Rule):
    """INJ003: Command injection via dangerous shell execution."""

    id = "INJ003"
    name = "Command injection"
    severity = Severity.CRITICAL
    description = (
        "Dangerous shell execution function detected. Functions like "
        "os.system(), subprocess with shell=True, and child_process.exec() "
        "pass input through a shell interpreter, enabling command injection."
    )
    fix = (
        "Use safe alternatives that avoid shell interpretation:\n"
        "  Python:  subprocess.run(['cmd', 'arg1', 'arg2'], shell=False)\n"
        "  Node.js: child_process.execFile('cmd', ['arg1', 'arg2'])\n"
        "Never pass user input to os.system() or shell=True."
    )
    guide_url = _GUIDE_URL
    owasp_id = "A03:2021"
    cwe_id = "CWE-78"
    confidence = "medium"

    patterns: list[str] = [
        r'os\.system\s*\(',
        r'subprocess\.(?:call|run|Popen)\s*\(.*shell\s*=\s*True',
        r'child_process\.exec\s*\(',
        r'child_process\.execSync\s*\(',
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


# -- INJ004  PathTraversal ---------------------------------------------------


class PathTraversal(Rule):
    """INJ004: Path traversal via unsanitized file path from user input."""

    id = "INJ004"
    name = "Path traversal"
    severity = Severity.HIGH
    description = (
        "File system operation uses unsanitized user input as a path. "
        "An attacker can use '../' sequences to access files outside the "
        "intended directory, potentially reading sensitive system files."
    )
    fix = (
        "Validate file paths and restrict to an allowed directory:\n"
        "  import os\n"
        "  base = '/safe/uploads'\n"
        "  path = os.path.realpath(os.path.join(base, user_input))\n"
        "  if not path.startswith(base):\n"
        "      raise ValueError('Path traversal detected')\n"
        "Use pathlib.Path.resolve() and check .is_relative_to() in Python 3.9+."
    )
    guide_url = _GUIDE_URL
    owasp_id = "A01:2021"
    cwe_id = "CWE-22"
    confidence = "medium"

    patterns: list[str] = [
        r'open\s*\(.*(?:request|req|params|input|args)\b',
        r'os\.path\.join\s*\(.*(?:request|req|params|input)\b',
        r'send_file\s*\(.*(?:request|req|params|input)\b',
        r'res\.sendFile\s*\(.*(?:req\.|params)',
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


# -- INJ005  CrossSiteScripting ---------------------------------------------


class CrossSiteScripting(Rule):
    """INJ005: Cross-site scripting (XSS) via unsafe HTML insertion."""

    id = "INJ005"
    name = "Cross-site scripting (XSS)"
    severity = Severity.HIGH
    description = (
        "Unsafe HTML insertion detected. innerHTML, dangerouslySetInnerHTML, "
        "v-html, and document.write() can execute attacker-controlled scripts "
        "if the content includes unsanitized user input."
    )
    fix = (
        "Use safe alternatives that automatically escape content:\n"
        "  DOM:     element.textContent = userInput\n"
        "  React:   Use JSX expressions {userInput} (auto-escaped)\n"
        "  Vue:     Use {{ userInput }} instead of v-html\n"
        "  Angular: Avoid [innerHTML], use interpolation {{ value }}\n"
        "If raw HTML is required, sanitize with DOMPurify:\n"
        "  element.innerHTML = DOMPurify.sanitize(userInput)"
    )
    guide_url = _GUIDE_URL
    owasp_id = "A03:2021"
    cwe_id = "CWE-79"
    confidence = "low"
    file_extensions = [".js", ".jsx", ".ts", ".tsx", ".vue", ".html"]

    patterns: list[str] = [
        r'\.innerHTML\s*=',
        r'dangerouslySetInnerHTML',
        r'v-html\s*=',
        r'document\.write\s*\(',
        r'\[innerHTML\]\s*=',
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


# -- INJ006  TemplateInjection ----------------------------------------------


class TemplateInjection(Rule):
    """INJ006: Server-side template injection (SSTI)."""

    id = "INJ006"
    name = "Template injection"
    severity = Severity.HIGH
    description = (
        "User input passed directly to a template constructor or "
        "render_template_string(). An attacker can inject template directives "
        "to execute arbitrary code on the server (SSTI)."
    )
    fix = (
        "Never pass user input as a template string:\n"
        "  # Dangerous: render_template_string(user_input)\n"
        "  # Safe:      render_template('page.html', data=user_input)\n"
        "Always use pre-defined template files with separate data context.\n"
        "If dynamic templates are required, use a sandboxed environment."
    )
    guide_url = _GUIDE_URL
    owasp_id = "A03:2021"
    cwe_id = "CWE-94"
    confidence = "medium"
    file_extensions = [".py", ".js", ".ts", ".rb"]

    patterns: list[str] = [
        r'render_template_string\s*\(.*(?:request|input|params)',
        r'Template\s*\(.*(?:request|input|params)',
        r'Jinja2.*from_string',
        r'eval\s*\(.*(?:request|req|params|body|input)\b',
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


# -- INJ007  UnsafeYAMLLoad -------------------------------------------------


class UnsafeYAMLLoad(Rule):
    """INJ007: Unsafe YAML loading allows arbitrary code execution."""

    id = "INJ007"
    name = "Unsafe YAML loading"
    severity = Severity.HIGH
    description = (
        "yaml.load() or yaml.unsafe_load() detected. Without SafeLoader, "
        "YAML deserialization can execute arbitrary Python code through "
        "specially crafted YAML payloads (e.g. !!python/object/apply)."
    )
    fix = (
        "Use yaml.safe_load() or specify SafeLoader explicitly:\n"
        "  # Dangerous: yaml.load(data)\n"
        "  # Safe:      yaml.safe_load(data)\n"
        "  # Safe:      yaml.load(data, Loader=yaml.SafeLoader)\n"
        "For dumping: use yaml.safe_dump() instead of yaml.dump()."
    )
    guide_url = _GUIDE_URL
    owasp_id = "A08:2021"
    cwe_id = "CWE-502"
    confidence = "medium"
    file_extensions = [".py"]

    patterns: list[str] = [
        r'yaml\.unsafe_load\s*\(',
        r'yaml\.load\s*\(',
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)
