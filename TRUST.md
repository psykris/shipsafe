# Trust Verification Guide

You should not trust ShipSafe because we say it's trustworthy. You should trust it because you can **verify every claim yourself**. This document tells you exactly how.

## Claim 1: "Your code never leaves your machine"

### How to verify

ShipSafe makes zero network calls. The `src/shipsafe/` directory contains no imports of network modules — with one documented exception: `serve.py` uses Python's stdlib `http.server` to run a local-only web UI (`shipsafe ui`). It makes no outbound connections. Verify this yourself:

```bash
# Search for network-related imports, excluding serve.py (local-only UI server)
grep -rn --exclude serve.py \
  "import socket\|import urllib\|import http\.client\|import requests\|import httpx\|import aiohttp\|from socket\|from urllib\|from http\." \
  src/shipsafe/

# Expected result: zero matches
```

To verify that `serve.py` itself makes no outbound connections:

```bash
# Confirm serve.py only imports stdlib and makes no external calls
grep -n "import\|connect\|open\|send\|post\|get" src/shipsafe/serve.py
# Every line should reference only Python stdlib (http.server, socketserver, threading, etc.)
```

This check also runs automatically in CI on every commit. See `network-quarantine.yml`.

For deeper verification, the test suite uses Python's `ast` module to parse every source file and assert no network modules are imported:

```bash
pytest tests/test_trust/test_network_quarantine.py -v
```

## Claim 2: "No telemetry, no analytics, no tracking"

### How to verify

Same as Claim 1. No network modules = no way to send data anywhere. Additionally:

```bash
# Search for telemetry-related code
grep -rni "telemetry\|analytics\|tracking\|phone.home\|usage.data" src/shipsafe/

# Expected result: zero matches (except comments about not having telemetry)
```

## Claim 3: "Deterministic — same input, same output"

### How to verify

Run the same scan twice and compare the JSON output:

```bash
shipsafe scan tests/fixtures/vulnerable --format json > run1.json
shipsafe scan tests/fixtures/vulnerable --format json > run2.json
diff run1.json run2.json

# Expected result: no differences
```

The test `tests/test_trust/test_determinism.py` automates this check.

## Claim 4: "Every detection rule is readable"

### How to verify

Every regex pattern is declared as a class-level constant. See them all at once:

```bash
grep -A5 "patterns = \[" src/shipsafe/rules/*.py
```

Each rule class has:
- `id`: Unique identifier (e.g., SEC001)
- `name`: Human-readable name
- `severity`: Default severity level
- `patterns`: The exact regex patterns used for detection
- `fix`: Copy-paste fix instructions
- `description`: Plain-language explanation

## Claim 5: "This tool passes its own scan"

### How to verify

```bash
python -m shipsafe scan .
# Expected: Score 100/100, zero findings
```

ShipSafe uses a `.shipsafeignore` file to exclude its own rule source files from self-scans. Rule files contain regex patterns that describe vulnerabilities (e.g., a rule that detects `eval()` necessarily contains the string `eval(` in its pattern). These are pattern definitions, not vulnerable code. Excluding them is the correct and honest approach — a project that doesn't define security rules would also score 100/100.

This check runs in CI on every commit via the `self-scan.yml` workflow.

## Claim 6: "Zero external dependencies"

### How to verify

```bash
# Check pyproject.toml — the runtime dependencies list should be empty
grep "^dependencies" pyproject.toml
# Expected: dependencies = []

# Verify no third-party packages are imported at runtime
pip show shipsafe | grep Requires
# Expected: Requires: (empty)
```

## Claim 7: "The scanner never writes to your filesystem"

### How to verify

The test `tests/test_trust/test_no_file_writes.py` copies fixture files to a temp directory, takes a hash snapshot, runs a full scan, and verifies all file hashes are identical afterward.

```bash
pytest tests/test_trust/test_no_file_writes.py -v
```

## Claim 8: "Secrets are always redacted in output"

### How to verify

The test `tests/test_trust/test_redaction.py` scans fixture files containing known test secrets and verifies that none of those values appear in any finding's snippet, message, or fix text.

```bash
pytest tests/test_trust/test_redaction.py -v
```

## Build From Source

If you don't trust pre-built packages, build from source:

```bash
git clone https://github.com/psykris/shipsafe.git
cd shipsafe

# Read the source code
wc -l src/shipsafe/*.py

# Install from source (no binaries, no compiled extensions)
pip install -e .

# Run the full test suite including trust tests
pip install -e ".[test]"
pytest tests/ -v

# Run the self-scan
shipsafe scan .
```

## Still Not Sure?

Open an issue at https://github.com/psykris/shipsafe/issues. We'd rather answer hard questions than have you use a tool you don't trust.
