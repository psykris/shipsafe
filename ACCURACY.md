# ShipSafe Accuracy Report

ShipSafe is a **regex-only** scanner. It does not use AST parsing, data-flow analysis, or AI. This report measures exactly what it catches and what it misses, tested against four OWASP benchmark applications.

---

## Summary

| Metric | Value |
|--------|-------|
| **Precision** (PyGoat) | 96.6% (84 TP / 87 total, 3 FP) |
| **Recall** (PyGoat, regex-detectable) | 90% (9/10 vulnerability classes) |
| **FPR** (VAmPI) | 0% (0 false positives in 10 findings) |
| **FPR** (PyGoat) | 3.4% (3 FP in 87 findings) |
| **Self-scan** | 100/100, 0 findings |

### What these numbers mean

ShipSafe catches **known vulnerability patterns** with high precision. When it flags something, it is almost certainly a real issue (96.6% precision). It detects 90% of regex-detectable vulnerability classes in a real Django application. It produces near-zero false positives.

ShipSafe **cannot detect** runtime vulnerabilities, business logic flaws, authorization bugs, or anything that requires understanding program execution. This is by design — it is a deterministic safety net, not a replacement for code review.

---

## Benchmark Results

### 1. OWASP PyGoat (Python/Django)

263 files scanned. 10 documented vulnerability classes.

| Vulnerability Class | Detected | Rule | Notes |
|---------------------|----------|------|-------|
| SQL Injection | No | — | Uses `.raw()` with generic var names; INJ001 gap |
| Command Injection | Yes | INJ003, CRY007 | 11 findings |
| CSRF Disabled | Yes | AUTH004 | 28 findings |
| XSS | Yes | INJ005 | 5 findings |
| JWT Weak Secret | Yes | AUTH002 | 3 findings |
| Broken Authentication | Yes | AUTH001 | 8 findings |
| Sensitive Data Exposure | Yes | DAT001, PRI001 | 10 findings |
| Security Misconfiguration | Yes | CFG001, CFG005 | 3 findings |
| Insecure Deserialization | Yes | INJ007 | 2 findings |
| Dockerfile Root | Yes | DEP001 | 4 findings |

**Result: 9/10 detected (90% recall), 3.4% false positive rate**

False positives: 2 from markdown documentation files describing vulnerabilities, 1 from PIL import flagged as typosquat (PIL is Pillow's namespace).

### 2. VAmPI (Python/Flask REST API)

22 files scanned. 9 documented OWASP API Security Top 10 vulnerabilities.

| Vulnerability | Regex-Detectable? | Detected | Rule |
|---------------|-------------------|----------|------|
| SQL Injection (f-string) | Yes | Yes | INJ001 |
| JWT Weak Key | Yes | Yes | AUTH002 |
| Mass Assignment | Partial | No | No rule yet |
| Excessive Data Exposure | Partial | No | High FP risk |
| RegexDOS | Partial | No | No rule yet |
| BOLA | No (runtime) | — | — |
| Password Change Auth | No (runtime) | — | — |
| User Enumeration | No (runtime) | — | — |
| Rate Limiting | No (architectural) | — | — |

**Result: 2/2 regex-detectable = 100% TPR, 0% FPR**

6 bonus findings (genuine issues not in documented list): Dockerfile root, missing gitignore entries, unpinned deps, hardcoded emails.

### 3. OWASP Juice Shop (JavaScript/TypeScript)

1,032 files scanned. 193 findings across 13 distinct rules.

Top detections: XSS patterns (32), Math.random() usage (20), NoSQL injection (19), hardcoded emails (99), eval() usage (4), CORS wildcards (3), private key in source (1).

This is a qualitative benchmark — Juice Shop has hundreds of vulnerabilities across many categories. ShipSafe fires 13 rules across 7 of 11 categories.

### 4. OWASP BenchmarkJava

2,740 Java test cases. **0 TP, 0 FP, 1,325 TN, 1,415 FN.**

Expected result: ShipSafe targets Python/JS/TS, not Java. The important metric is **0 false positives** — ShipSafe's patterns are precise enough not to hallucinate on code outside its target languages.

---

## What ShipSafe Cannot Detect

These vulnerability classes require runtime analysis, data-flow tracking, or semantic understanding that regex cannot provide:

- **Authorization bugs** (BOLA, IDOR, privilege escalation)
- **Business logic flaws** (price manipulation, race conditions)
- **Mass assignment** (requires understanding ORM field mappings)
- **Rate limiting absence** (detecting missing code, not present code)
- **ReDoS** (requires regex complexity analysis)
- **Authentication bypass** (requires understanding auth flow)
- **Data exposure** (requires understanding what is sensitive in context)

---

## Methodology

All benchmarks use ShipSafe's `saas` profile (default, all severities). Ground truth comes from each project's documented vulnerability list. A finding is a True Positive if it identifies a documented vulnerability or a genuine undocumented security issue. A finding is a False Positive if it flags code that is not actually vulnerable.

Benchmark scripts: `benchmarks/run_owasp_calibration.py`, `benchmarks/run_juice_shop_scan.py`

---

## How to Reproduce

```bash
# Clone a benchmark app and scan it
git clone https://github.com/adeyosemanputra/pygoat.git
shipsafe scan pygoat/ --format json -o pygoat-report.json

# Compare against documented vulnerabilities
# PyGoat documents 10 vulnerability classes in its README
```
