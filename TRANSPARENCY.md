# AI Transparency Report

ShipSafe believes in radical transparency about how this tool was built. This document explains exactly what role AI played in development, what role humans played, and why the distinction matters less than you might think.

## How This Tool Was Built

ShipSafe was developed using **Claude Code** (Anthropic) as an AI coding assistant. A human requirements engineer directed the architecture, designed the threat taxonomy, reviewed every detection rule, and validated every pattern against known-vulnerable codebases.

## What the AI Did vs. What the Human Did

| Component | Human contribution | AI contribution |
|-----------|-------------------|-----------------|
| **Threat taxonomy** | Researched real incidents (Moltbook, Enrichlead, Lovable breaches), designed the 4-tier classification | Helped format and organize |
| **Detection patterns** | Specified which API key formats to detect, sourced regex patterns from provider documentation | Implemented the Rule classes and test infrastructure |
| **Scoring algorithm** | Designed the weights, caps, and thresholds | Implemented the calculation |
| **Architecture** | Defined the trust contract, zero-dependency constraint, rule system | Wrote the implementation code |
| **Test fixtures** | Specified what vulnerable patterns to include | Generated the fixture files |
| **Guides** | Outlined content, reviewed for accuracy | Drafted prose |
| **CI workflows** | Specified the trust-enforcing checks | Wrote the YAML |

## Why This Doesn't Matter (And Why It Does)

### Why it doesn't matter

ShipSafe's detection engine is **deterministic**. It uses regex pattern matching — no AST, no AI at runtime, no LLM calls, no machine learning, no probabilistic decisions.

Every detection rule is a visible regex pattern declared as a class-level constant. You can read every single rule in under an hour. The question "is this rule correct?" is answerable by reading the pattern and running the test — not by trusting the AI that wrote it.

Whether a human typed `r'AKIA[0-9A-Z]{16}'` or an AI did, the regex either matches AWS keys or it doesn't. The test suite proves it does.

### Why it does matter

Transparency builds trust. We believe you should know:
- That AI helped write this code
- That every AI-generated contribution was reviewed by a human
- That the tool's correctness does not depend on AI — it depends on deterministic patterns and tests

## Ongoing AI Usage Policy

We will continue to use AI coding tools for development. Our policy:

1. **All AI-assisted commits** are marked with `Co-Authored-By:` tags
2. **All detection rules** must pass test fixtures regardless of who or what wrote them
3. **The trust contract** (no network calls, no telemetry, no file writes) is enforced by CI — not by trust in the author
4. **Human review** is required for all rule additions and severity changes

## The Bootstrapping Argument

"An AI-written tool that checks AI-written code — isn't that circular?"

No. Here's why:

1. ShipSafe passes its own scan. This proves the implementation avoids the specific patterns it detects.
2. The detection is deterministic, not AI-based. Whether a regex was written by a human or an AI, it either matches the pattern or it doesn't.
3. Every rule has test fixtures with known-vulnerable code. You can verify detection works by running `pytest`.
4. The tool's value comes from the **rules**, not the **implementation**. The rules are based on documented real-world incidents, not AI hallucinations.

We built ShipSafe with AI tools because we use AI tools daily — which means we've encountered firsthand every vulnerability pattern the tool detects. Every rule exists because we saw AI generate the pattern it catches.
