# Guide 07 — Dependency Safety

## What This Guide Covers

Supply-chain attacks via Python dependencies: typosquatting, hallucinated
package names, unpinned versions, `--extra-index-url` hijacking, and how to
lock your dependency graph for reproducible builds.

---

## Why Dependency Safety Matters

In 2023–2025, supply-chain attacks became the #1 vector for compromising
production AI applications. Common attack patterns:

1. **Typosquatting**: Publish `colourama` on PyPI to steal installs from `colorama`
2. **Dependency confusion**: Register a public package with the same name as your
   private package, with a higher version number
3. **AI hallucination**: LLMs invent plausible-sounding package names that attackers
   then register on PyPI (e.g. `langchainplus`, `openai-tools`)
4. **Maintainer account takeover**: Hijack a legitimate maintainer's PyPI credentials
   and publish a malicious release

---

## Rule: Avoid `--extra-index-url` (DEP101)

`--extra-index-url` tells pip to search a second index **in addition to PyPI**.
Because pip picks the **highest version** found across all indexes, an attacker
can publish a higher-versioned package on PyPI with the same name as your
private package.

```
# Vulnerable setup
pip install --extra-index-url https://my.private.index/simple/ my-private-lib

# Attack: attacker publishes my-private-lib==999.0.0 on PyPI
# pip installs the attacker's version instead of yours!
```

**Fix**: Use `--index-url` (replaces PyPI entirely) or `--find-links` for local
wheel files:

```bash
# Safe — only uses private index
pip install --index-url https://my.private.index/simple/ my-private-lib

# Safe — install from local wheel directory
pip install --find-links ./vendor/ my-private-lib
```

---

## Rule: Pin All Dependencies (DEP102, DEP103)

Unpinned and range-pinned dependencies lead to non-reproducible builds and allow
silent upgrades to malicious or broken releases.

```
# Bad: requirements.txt
flask               # DEP102 — any version
requests>=2.28.0    # DEP103 — any 2.28+ version
```

```
# Good: requirements.txt
flask==3.0.2
requests==2.31.0
```

### Using pip-tools for pinned lockfiles

```bash
# Install pip-tools
pip install pip-tools

# Create requirements.in with loose constraints (for libraries)
# flask>=3.0
# requests>=2.28

# Compile to fully-pinned requirements.txt
pip-compile requirements.in
# Output: flask==3.0.2, requests==2.31.0 + all transitive deps pinned

# Upgrade a single package
pip-compile --upgrade-package flask requirements.in

# Install from lockfile
pip install -r requirements.txt
```

### Using Poetry (recommended for new projects)

```bash
# Poetry generates poetry.lock automatically
poetry add flask                    # adds with pinned lockfile
poetry install --no-dev             # reproducible production install
poetry update flask                 # explicit controlled upgrade
```

---

## Rule: Version Constraints in `setup.py` (DEP104)

For libraries (not applications), `install_requires` should specify compatible
ranges, not pinned versions. But bare names with no constraint are still risky:

```python
# Bad — any version, including future breaking releases
install_requires=[
    "flask",           # DEP104: no version constraint
    "requests",
]

# Good — compatible ranges
install_requires=[
    "flask>=3.0,<4",   # accepts patch/minor upgrades within major
    "requests>=2.28,<3",
]
```

---

## Rule: Known Typosquats (DEP105)

ShipSafe maintains a bundled denylist of known typosquatted and AI-hallucinated
package names. These are packages that have been used in real attacks or that
LLMs commonly invent.

```
# Bad — typosquats
colourama      # should be: colorama
requets        # should be: requests
djago          # should be: django

# AI-hallucinated names
langchainplus  # should be: langchain
openai_tools   # should be: openai
hugging_face   # should be: huggingface-hub
```

**How to verify any package**:

1. Check [pypi.org](https://pypi.org) for the exact name
2. Verify the owner, description, and download count
3. Check the source repository link
4. Review the package's dependencies

---

## Security Checklist

```bash
# 1. Verify every package before adding it
pip index versions <package-name>          # check it exists
# Visit https://pypi.org/project/<name>/  # verify owner & repo

# 2. Generate a pinned lockfile
pip-compile requirements.in               # or: poetry lock

# 3. Check for known vulnerabilities in your dependencies
pip install pip-audit
pip-audit -r requirements.txt

# 4. Monitor for new vulnerabilities (CI integration)
# GitHub Dependabot, Snyk, or Safety:
pip install safety
safety check -r requirements.txt

# 5. Scan with ShipSafe before every deploy
shipsafe scan .
```

---

## Related Rules

| Rule | What it catches |
|------|-----------------|
| DEP101 | `--extra-index-url` supply-chain risk |
| DEP102 | Unpinned dependencies |
| DEP103 | Wildcard/unbounded version specifiers |
| DEP104 | Unpinned `install_requires` in setup.py |
| DEP105 | Known typosquatted or hallucinated packages |
