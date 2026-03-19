"""Tests for the 7 injection rules (src/shipsafe/rules/injection.py).

Each rule is tested for:
    - True positive: scanning vulnerable fixture produces >= 1 finding.
    - True negative: scanning clean fixture produces 0 findings.
"""

from pathlib import Path

from shipsafe.rules.injection import (
    SQLInjection,
    NoSQLInjection,
    CommandInjection,
    PathTraversal,
    CrossSiteScripting,
    TemplateInjection,
    UnsafeYAMLLoad,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"
VULN_INJ = FIXTURES / "vulnerable" / "injection"
CLEAN_INJ = FIXTURES / "clean" / "injection"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


CLEAN_PY = _read(CLEAN_INJ / "safe_queries.py")
CLEAN_JSX = _read(CLEAN_INJ / "safe_html.jsx")


# ── INJ001: SQLInjection ─────────────────────────────────────────────

class TestSQLInjection:
    rule = SQLInjection()
    vuln = _read(VULN_INJ / "sql_injection.py")

    def test_true_positive(self):
        findings = self.rule.scan("sql_injection.py", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        # safe_queries.py uses parameterized queries with ?
        findings = self.rule.scan("safe_queries.py", CLEAN_PY)
        assert len(findings) == 0

    # Phase 7: extended patterns for Django .raw() and concat in execute()
    def test_django_raw_concat(self):
        code = 'results = Model.objects.raw("SELECT * FROM users WHERE id=" + user_id)'
        findings = self.rule.scan("views.py", code)
        assert len(findings) >= 1

    def test_execute_string_concat(self):
        code = 'cursor.execute("SELECT * FROM table WHERE col=" + var)'
        findings = self.rule.scan("db.py", code)
        assert len(findings) >= 1

    def test_execute_fstring(self):
        code = 'db.execute(f"SELECT * FROM users WHERE name={name}")'
        findings = self.rule.scan("db.py", code)
        assert len(findings) >= 1

    def test_parameterized_execute_clean(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])'
        findings = self.rule.scan("db.py", code)
        assert len(findings) == 0

    def test_django_raw_fstring(self):
        code = 'qs = MyModel.objects.raw(f"SELECT * FROM t WHERE id={pk}")'
        findings = self.rule.scan("views.py", code)
        assert len(findings) >= 1

    def test_fstring_sql_variable_assignment(self):
        """VAmPI pattern: SQL built with f-string, executed on next line."""
        code = """user_query = f"SELECT * FROM users WHERE username = '{username}'" """
        findings = self.rule.scan("models.py", code)
        assert len(findings) >= 1


# ── INJ002: NoSQLInjection ───────────────────────────────────────────

class TestNoSQLInjection:
    rule = NoSQLInjection()
    vuln = _read(VULN_INJ / "nosql_injection.js")

    def test_true_positive(self):
        findings = self.rule.scan("nosql_injection.js", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        # safe_queries.py has no MongoDB query operators
        findings = self.rule.scan("safe_queries.py", CLEAN_PY)
        assert len(findings) == 0


# ── INJ003: CommandInjection ─────────────────────────────────────────

class TestCommandInjection:
    rule = CommandInjection()
    vuln = _read(VULN_INJ / "command_injection.py")

    def test_true_positive(self):
        findings = self.rule.scan("command_injection.py", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        # safe_queries.py uses subprocess with shell=False
        findings = self.rule.scan("safe_queries.py", CLEAN_PY)
        assert len(findings) == 0


# ── INJ004: PathTraversal ────────────────────────────────────────────

class TestPathTraversal:
    rule = PathTraversal()
    vuln = _read(VULN_INJ / "path_traversal.py")

    def test_true_positive(self):
        findings = self.rule.scan("path_traversal.py", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        # safe_queries.py uses Path.resolve() and prefix checks
        findings = self.rule.scan("safe_queries.py", CLEAN_PY)
        assert len(findings) == 0


# ── INJ005: CrossSiteScripting ───────────────────────────────────────

class TestCrossSiteScripting:
    rule = CrossSiteScripting()
    vuln = _read(VULN_INJ / "xss.jsx")

    def test_true_positive(self):
        findings = self.rule.scan("xss.jsx", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        # safe_html.jsx uses textContent and DOMPurify
        findings = self.rule.scan("safe_html.jsx", CLEAN_JSX)
        assert len(findings) == 0


# ── INJ006: TemplateInjection ────────────────────────────────────────

class TestTemplateInjection:
    rule = TemplateInjection()
    vuln = _read(VULN_INJ / "template_injection.py")

    def test_true_positive(self):
        findings = self.rule.scan("template_injection.py", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        # safe_queries.py has no render_template_string or Template(user_input)
        findings = self.rule.scan("safe_queries.py", CLEAN_PY)
        assert len(findings) == 0


# ── INJ007: UnsafeYAMLLoad ───────────────────────────────────────────

class TestUnsafeYAMLLoad:
    rule = UnsafeYAMLLoad()
    vuln = _read(VULN_INJ / "unsafe_yaml.py")

    def test_true_positive(self):
        findings = self.rule.scan("unsafe_yaml.py", self.vuln)
        assert len(findings) >= 1

    def test_true_negative_safe_load(self):
        # yaml.safe_load() does NOT contain "yaml.load(" so won't match
        safe_content = (
            "import yaml\n"
            "def load_config(path):\n"
            "    with open(path) as f:\n"
            "        return yaml.safe_load(f)\n"
        )
        findings = self.rule.scan("safe_config.py", safe_content)
        assert len(findings) == 0

    def test_scanner_applies_extension_filter(self):
        # Extension filtering (file_extensions = [".py"]) is enforced by the
        # scanner's _applicable_rules(), not by rule.scan() itself. The rule's
        # applies_to() helper exists for the scanner to consult.
        assert ".py" in UnsafeYAMLLoad.file_extensions
        assert UnsafeYAMLLoad().applies_to("config.py") is True
        assert UnsafeYAMLLoad().applies_to("config.js") is False
