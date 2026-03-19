# ShipSafe v0.1.0

## What ShipSafe Does

ShipSafe is a deterministic security scanner for AI-generated codebases. It checks your Python, JavaScript, and configuration files against 77 regex-based vulnerability patterns — covering hardcoded secrets, injection flaws, misconfigurations, AI-specific risks, and supply chain threats. Your code never leaves your machine: there are zero dependencies, zero network calls, and zero cloud services.

## What ShipSafe Does NOT Do

- **No AST or semantic analysis.** ShipSafe uses regex pattern matching only. It cannot understand code structure, data flow, or business logic.
- **No runtime vulnerability detection.** Issues like mass assignment, ReDoS, race conditions, and authentication bypass that require program execution are out of scope.
- **No AI at scan time.** Despite being built for AI-generated code, ShipSafe itself uses no AI, no LLM calls, and no machine learning during scanning. Every detection is a deterministic regex match.

## Benchmark Results

| Benchmark | Result |
|-----------|--------|
| OWASP PyGoat | 90% true-positive rate across 10 vulnerability classes, 3.4% false-positive rate |
| VAmPI (REST API) | 100% true-positive rate (regex-detectable vulns), 0% false-positive rate |
| OWASP Juice Shop | 193 findings across 13 rules (1032 files scanned) |

Benchmark scripts and detailed reports are in the `benchmarks/` directory.

## How to Verify the Trust Contract

ShipSafe claims your code never leaves your machine. Verify it yourself:

```bash
# Confirm zero network module imports in the source
grep -rn "import socket\|import urllib\|import requests\|import httpx" src/shipsafe/
# Expected: zero matches

# Confirm zero runtime dependencies
grep "dependencies" pyproject.toml
# Expected: dependencies = []

# Confirm deterministic output
shipsafe scan tests/fixtures/vulnerable --format json > run1.json
shipsafe scan tests/fixtures/vulnerable --format json > run2.json
diff run1.json run2.json
# Expected: no differences
```

The automated trust tests in `tests/test_trust/` enforce these guarantees on every commit.

## Known Limitations

- **Self-scan false positives (~45).** Scanning ShipSafe's own source produces ~45 findings because rule source files contain regex patterns that describe vulnerabilities (e.g., a rule detecting `eval()` contains the string `eval(` in its pattern). These are pattern declarations, not actual vulnerable code.
- **No ReDoS detection.** Regular expression denial-of-service patterns are not yet detected (planned for a future release).
- **INJ001 f-string sensitivity.** The SQL injection rule may flag harmless f-string variable assignments that happen to contain SQL keywords.
- **Documentation file false positives.** Markdown files or comments describing vulnerabilities may trigger findings. Use `--exclude-path` to skip documentation directories.

## Install

```bash
pip install shipsafe
shipsafe scan .
```

Requires Python 3.12+. No API keys. No configuration. No cloud account.
