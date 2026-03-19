# ShipSafe

![PyPI](https://img.shields.io/pypi/v/shipsafe) ![Python](https://img.shields.io/pypi/pyversions/shipsafe) ![License](https://img.shields.io/github/license/psykris/shipsafe) ![Tests](https://img.shields.io/badge/tests-391%20passing-brightgreen)

**Catch security vulnerabilities in AI-generated code before they catch you.**

ShipSafe is a **deterministic** security scanner. It uses regex pattern matching — no AI, no LLM calls, no cloud services. Your code is analyzed locally and never transmitted anywhere.

---

## Trust Contract

Before you install, here's what ShipSafe guarantees — and how to verify each claim yourself:

| Guarantee | How to verify |
|-----------|--------------|
| Your code never leaves your machine | `grep -rn "import socket\|import urllib\|import requests" src/shipsafe/` → zero results |
| No telemetry, no analytics, no tracking | Same check. No network modules = nowhere to send data |
| Every detection rule is a readable regex pattern | `grep -A5 "patterns = \[" src/shipsafe/rules/*.py` |
| Same input always produces same output | Run `shipsafe scan . --format json` twice, `diff` the output |
| This tool passes its own scan | Check the Self-Scan CI badge above |
| This tool was written with AI assistance | We document exactly how. See [TRANSPARENCY.md](TRANSPARENCY.md) |

Full verification guide: [TRUST.md](TRUST.md)

---

## Who This Is For

- **Vibe coders** — You built something with Cursor, Lovable, Replit, or Claude Code and want to know if it's safe to deploy. ShipSafe gives you a plain-language report with copy-paste fixes.
- **Developers** — You want CI/CD-integrated security scanning that runs on every push, produces SARIF output, and costs nothing. ShipSafe is a single install with zero dependencies.
- **Security officers** — You need OWASP-mapped findings, severity scores, and compliance-ready reports. ShipSafe produces scored HTML and JSON reports with transparent methodology.

---

## Quickstart

### Installation

ShipSafe has **zero runtime dependencies** — it only uses the Python standard library. Pick whichever install method you prefer:

```bash
# Option 1: pip (simple, works everywhere)
pip install shipsafe

# Option 2: pipx (recommended — auto-isolates CLI tools in their own venv)
pipx install shipsafe

# Option 3: uv (fastest — modern Python package manager)
uv tool install shipsafe
```

> **Which should I choose?**
> - **pip** is fine if you're already in a virtual environment, or just want the fewest keystrokes.
> - **pipx** is the safest default for CLI tools. It installs ShipSafe into its own isolated environment so it never conflicts with your project's dependencies. Requires a one-time `pip install pipx`.
> - **uv** is the fastest option and handles isolation automatically, like pipx. If you already use `uv` for your Python workflow, this is the cleanest choice.
>
> Because ShipSafe has zero dependencies, `pip install` carries no real conflict risk — but isolation is still good hygiene.

### Scan

```bash
# Scan your project
shipsafe scan .

# Scan with a specific profile
shipsafe scan . --profile hobby       # Personal projects (CRITICAL + HIGH only)
shipsafe scan . --profile saas        # SaaS apps (full scan, default)
shipsafe scan . --profile enterprise  # Stricter privacy and supply-chain rules
```

That's it. No API keys. No cloud account. No configuration files.

### Launch the Visual UI

```bash
# Launch the interactive web dashboard (opens your browser automatically)
shipsafe ui
```

Drop a folder path into the dashboard, hit Scan, and get a fully scored report — CRITICAL findings first, copy-paste fixes included. This is the recommended starting point for vibe coders.

---

## What It Checks

ShipSafe detects **77 vulnerability patterns** across 11 categories:

### Secrets & Credentials
| Rule | What it catches |
|------|----------------|
| SEC001–SEC018 | Hardcoded API keys (OpenAI, AWS, Stripe, GitHub, Supabase, and 12 more) |
| AUTH001–AUTH006 | Hardcoded passwords, weak JWT secrets, insecure sessions, disabled CSRF |
| GIT002–GIT006 | Missing `.gitignore` entries, `.env` files in repo |

### Injection & Input Handling
| Rule | What it catches |
|------|----------------|
| INJ001–INJ007 | SQL injection, NoSQL injection, command injection, path traversal, XSS, template injection, unsafe YAML |
| CRY007–CRY009 | Dangerous functions (`eval()`, `exec()`, `pickle.loads()`) |

### Configuration & Deployment
| Rule | What it catches |
|------|----------------|
| CFG001–CFG005 | Debug mode, CORS wildcards, verbose errors |
| DEP001–DEP006 | Dockerfile root, exposed debug routes, build secrets, 0.0.0.0 binding |

### Cryptography & Data
| Rule | What it catches |
|------|----------------|
| CRY001–CRY006 | TLS verification disabled, weak hashing (MD5/SHA1), `Math.random()` |
| DAT001–DAT004 | Credentials in logs, verbose error responses |

### AI-Specific
| Rule | What it catches |
|------|----------------|
| AI001–AI007 | Prompt injection, unbounded cost, system prompt leakage, unpinned models, unsanitized model output |

### Dependencies & Supply Chain
| Rule | What it catches |
|------|----------------|
| DEP101–DEP105 | Extra index URLs, unpinned deps, wildcard specifiers, typosquatted packages |

### Privacy
| Rule | What it catches |
|------|----------------|
| PRI001–PRI005 | PII in logs, hardcoded SSN/email, PHI in logs, unencrypted PII storage |

Every finding includes a **concrete, copy-paste fix** and a link to an educational guide.

---

## Measured Accuracy

Tested against four OWASP benchmark applications:

| Benchmark | Precision | Recall | FPR | Details |
|-----------|-----------|--------|-----|---------|
| OWASP PyGoat (Django) | 96.6% | 90% (9/10 vuln classes) | 3.4% | 87 findings, 263 files |
| VAmPI (Flask API) | 100% | 100% (regex-detectable) | 0% | 10 findings, 22 files |
| OWASP Juice Shop (Node.js) | N/A | 13 rules fire | 0% | 193 findings, 1032 files |
| Self-scan | N/A | N/A | N/A | **100/100, 0 findings** |

ShipSafe is regex-only. It cannot detect runtime vulnerabilities, business logic flaws, or authorization bugs. Full methodology and reproduction steps: [ACCURACY.md](ACCURACY.md)

---

## Understanding Your Score

```
Score: 65/100  [Fix HIGH items before deploying]

  Score breakdown:
    CRITICAL  1 x -25 = -25  (cap -75)
    HIGH      1 x -10 = -10  (cap -40)
    MEDIUM    0 findings
    LOW       0 findings
```

| Score | Meaning |
|-------|---------|
| 90–100 | Ready to deploy |
| 70–89 | Fix HIGH items before deploying |
| 40–69 | Significant security issues. Do not deploy to production. |
| 0–39 | Critical vulnerabilities. Stop and fix before shipping. |

The scoring algorithm is fully transparent — see [scoring.py](src/shipsafe/scoring.py).

---

## Scan Profiles

| Profile | Use when | What it shows |
|---------|----------|---------------|
| `hobby` | Personal projects, learning, prototypes | CRITICAL + HIGH only |
| `saas` | Apps with users, deployed to production | All severities (default) |
| `enterprise` | Regulated industries, strict compliance | All severities + escalated privacy/supply-chain rules |

---

## Output Formats

```bash
shipsafe scan . --format terminal   # Colored terminal output (default)
shipsafe scan . --format json       # Machine-readable JSON
shipsafe scan . --format sarif      # SARIF 2.1.0 (GitHub Security tab)
shipsafe scan . --format html       # Single-file HTML report
shipsafe scan . --format html -o report.html  # Save to file
```

---

## How ShipSafe Compares to AI-Powered Code Review

ShipSafe is not a replacement for AI-powered code review tools (like Claude Code's `/security-review`). It is a **deterministic safety net**.

| | AI Code Review | ShipSafe |
|---|---|---|
| Engine | LLM (sends code to cloud) | Local regex (code stays on your machine) |
| Cost | Per-token API charges | Free, forever |
| Scope | Current diff only | Entire codebase |
| Determinism | Different result each time | Same input = identical output |
| CI/CD | Impractical | Native (GitHub Action, pre-commit, SARIF) |

Use ShipSafe in your CI pipeline to catch known patterns on every push. Use AI review tools for nuanced, context-dependent analysis. ShipSafe catches the 80% of vulnerabilities that follow known patterns — the hardcoded keys, the missing `.gitignore`, the `verify=False` — before they ever reach a reviewer.

---

## Guides

- [Before You Deploy](guides/00-before-you-deploy.md) — 5-minute pre-deployment checklist
- [Secrets Management](guides/01-secrets-management.md) — Environment variables, rotation, what to do after exposure
- [Authentication](guides/02-authentication.md) — Password handling, JWT, session security
- [Authorization](guides/03-authorization.md) — BOLA, RBAC, row-level security
- [Input Validation](guides/04-input-validation.md) — SQL injection, XSS, command injection prevention
- [API Security](guides/05-api-security.md) — Rate limiting, CORS, header hardening
- [Deployment Hardening](guides/06-deployment-hardening.md) — Dockerfiles, debug routes, binding
- [Dependency Safety](guides/07-dependency-safety.md) — Supply chain, pinning, typosquatting
- [Git Hygiene](guides/08-git-hygiene.md) — `.gitignore`, cleaning git history, secret rotation
- [AI Security](guides/09-ai-security.md) — Prompt injection, model output sanitization
- [Privacy](guides/10-privacy.md) — PII handling, logging, encryption

---

## FAQ

**Is my code uploaded anywhere?**
No. ShipSafe runs entirely locally. It makes zero network calls. This is [verified by CI](TRUST.md) on every commit.

**Do I need an API key?**
No. ShipSafe has zero external dependencies and requires no configuration.

**Does it work with my framework?**
ShipSafe scans source files regardless of framework. Detection rules cover Python, JavaScript, TypeScript, and configuration files (JSON, YAML, TOML, .env).

**How is this different from Snyk / SonarQube / Semgrep?**
ShipSafe is designed for people who have never used a security scanner before. It requires no configuration, produces plain-language output with copy-paste fixes, and runs with zero dependencies. It is also fully offline and free.

**This was written with AI. Why should I trust it?**
Because the detection engine is deterministic regex patterns — not AI. Every rule is readable, testable, and auditable. The tool passes its own scan. See [TRANSPARENCY.md](TRANSPARENCY.md) for the full story.

---

## CI/CD Integration

### GitHub Action

```yaml
- uses: ./  # or your published action path
  with:
    path: ./src
    profile: enterprise
    format: sarif
    output: security-report.sarif
    fail-on: critical,high
```

### Pre-commit Hook

```yaml
repos:
  - repo: local
    hooks:
      - id: shipsafe
        name: shipsafe
        entry: shipsafe scan . --fail-on critical,high
        language: python
        pass_filenames: false
```

---

## License

[MIT](LICENSE)
