"""Tests for the ShipSafe CLI."""

from pathlib import Path

from shipsafe.cli import main

FIXTURES = Path(__file__).parent / "fixtures"
VULNERABLE = str(FIXTURES / "vulnerable")
CLEAN = str(FIXTURES / "clean")


class TestCLIScan:
    """Test the 'scan' subcommand."""

    def test_scan_vulnerable_returns_exit_1(self):
        """Scanning vulnerable fixtures with default --fail-on should return 1."""
        exit_code = main(["scan", VULNERABLE])
        assert exit_code == 1

    def test_scan_clean_returns_exit_0(self):
        """Scanning clean fixtures should return 0 (no critical/high)."""
        exit_code = main(["scan", CLEAN, "--severity", "critical"])
        # Clean fixtures should have no secret findings
        assert exit_code == 0

    def test_scan_with_profile_hobby(self):
        """Hobby profile should work without error."""
        exit_code = main(["scan", VULNERABLE, "--profile", "hobby"])
        assert exit_code in (0, 1)  # Either is valid

    def test_scan_with_json_format(self, tmp_path):
        """JSON format should produce valid output."""
        output_file = str(tmp_path / "report.json")
        exit_code = main(["scan", VULNERABLE, "--format", "json", "--output", output_file])
        import json
        with open(output_file) as f:
            data = json.load(f)
        assert "shipsafe_version" in data
        assert "findings" in data
        assert "score" in data

    def test_scan_with_severity_filter(self):
        """--severity flag should be accepted."""
        exit_code = main(["scan", VULNERABLE, "--severity", "critical"])
        assert exit_code in (0, 1)

    def test_scan_with_rule_id_filter(self):
        """--rule-id flag should be accepted."""
        exit_code = main(["scan", VULNERABLE, "--rule-id", "SEC001"])
        assert exit_code in (0, 1)

    def test_scan_nonexistent_path(self):
        """Scanning nonexistent path should not crash."""
        exit_code = main(["scan", "/nonexistent/path"])
        assert exit_code in (0, 1, 2)


class TestCLISubcommands:
    """Test other subcommands."""

    def test_check_secrets(self):
        """check-secrets subcommand should work."""
        exit_code = main(["check-secrets", VULNERABLE])
        assert exit_code in (0, 1)

    def test_check_gitignore(self):
        """check-gitignore subcommand should work."""
        exit_code = main(["check-gitignore", VULNERABLE])
        assert exit_code in (0, 1)

    def test_no_command_returns_2(self):
        """No subcommand should print help and return 2."""
        exit_code = main([])
        assert exit_code == 2

    def test_version_flag(self):
        """--version should work (exits via SystemExit)."""
        import pytest
        with pytest.raises(SystemExit) as exc_info:
            main(["--version"])
        assert exc_info.value.code == 0
