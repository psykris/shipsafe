"""AI-specific security rules for ShipSafe.

Detects prompt injection risks, unbounded LLM cost exposure, system prompt
leakage, unpinned model versions, LLM output trust violations, inline AI API
keys, and missing output moderation.

These rules are ShipSafe's unique capability — no other static scanner has
systematic, deterministic detection of AI-application vulnerabilities.

Every pattern is a class-level constant so you can audit the full catalogue
with a single grep:

    grep -A5 "patterns = \\[" src/shipsafe/rules/ai_specific.py

Design invariants
-----------------
- Patterns live on the class, never hidden inside methods.
- Matched values are always redacted before they appear in output.
- Every fix includes concrete, copy-pasteable remediation steps.
- owasp_llm_id maps to OWASP LLM Top 10 2025 identifiers.
"""

import re

from shipsafe.finding import Finding, Severity
from shipsafe.rules.base import Rule


# ── AI001  PromptInjectionRisk ────────────────────────────────────────


class PromptInjectionRisk(Rule):
    """Detect unsanitized user input passed directly to LLM prompts."""

    id = "AI001"
    name = "Prompt injection risk"
    severity = Severity.HIGH
    description = (
        "User-controlled input is passed directly into an LLM prompt or "
        "messages array without sanitization. An attacker can craft malicious "
        "input that overrides system instructions, leaks confidential context, "
        "or forces unintended model behaviour (prompt injection / jailbreak). "
        "This is OWASP LLM Top 10 #1."
    )
    fix = (
        "Never concatenate raw user input into prompts. Validate and bound it first:\n"
        "  user_input = request.json.get('message', '')[:1000]  # hard length cap\n"
        "  # Keep user content isolated in the 'user' role\n"
        "  messages = [\n"
        "      {'role': 'system', 'content': SYSTEM_PROMPT},  # you control this\n"
        "      {'role': 'user', 'content': user_input},        # sandboxed\n"
        "  ]\n"
        "  # Consider a guard model or content-filter API before sending."
    )
    guide_url = "guides/09-ai-security.md"
    owasp_id = "A03:2021"
    owasp_llm_id = "LLM01:2025"
    cwe_id = "CWE-74"
    confidence = "medium"

    file_extensions: list[str] = [".py", ".js", ".ts", ".jsx", ".tsx"]

    patterns: list[str] = [
        # Request data used directly as message content value
        r'"content"\s*:\s*(?:request\.|params\.|body\.|query\.)',
        r"'content'\s*:\s*(?:request\.|params\.|body\.|query\.)",
        # f-string prompt containing request or user input variables
        r'(?:prompt|content|messages)\s*=\s*f["\'].*\{(?:request\.|user_input|user_message|user_query)\b',
        # .format() with user-controlled args on prompt/content line
        r'(?:prompt|content)\s*=\s*["\'][^"\']*\{[^}]+\}[^"\']*["\']\s*\.format\(',
        # Direct augmented assignment of user-controlled data to prompt
        r'(?:prompt|system_prompt|user_prompt)\s*\+=\s*(?:request\.|user_input|user_query|user_message)',
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


# ── AI002  UnboundedLLMCost ───────────────────────────────────────────


class UnboundedLLMCost(Rule):
    """Detect LLM API calls that omit token limits."""

    id = "AI002"
    name = "Unbounded LLM token cost"
    severity = Severity.MEDIUM
    description = (
        "An LLM API call does not set a max_tokens (or max_completion_tokens) "
        "limit. Without this guard, a single malicious or buggy request can "
        "consume unlimited tokens, leading to runaway costs or denial-of-wallet "
        "attacks. This is OWASP LLM Top 10 #10."
    )
    fix = (
        "Always set an explicit token budget on every LLM call:\n"
        "  response = client.chat.completions.create(\n"
        "      model=MODEL,\n"
        "      messages=messages,\n"
        "      max_tokens=512,      # hard ceiling per request\n"
        "      timeout=30,          # network timeout in seconds\n"
        "  )\n"
        "Also set a per-user / per-day spend limit in your AI provider dashboard."
    )
    guide_url = "guides/09-ai-security.md"
    owasp_id = "A05:2021"
    owasp_llm_id = "LLM10:2025"
    cwe_id = "CWE-770"
    confidence = "medium"

    file_extensions: list[str] = [".py", ".js", ".ts", ".jsx", ".tsx"]

    # These patterns are used only for documentation / grepping.
    # The real detection runs in the custom scan() below.
    patterns: list[str] = [
        r"\.(?:create|complete|generate)\s*\(",
    ]

    # Candidate call patterns — lines that open an LLM API invocation
    _CALL_PATTERN: re.Pattern = re.compile(
        r"\.(?:chat\.completions?|completions?|messages?)\.(?:create|complete|stream)\s*\(",
        re.IGNORECASE,
    )
    # What a token-limit parameter looks like nearby
    _LIMIT_PATTERN: re.Pattern = re.compile(
        r"\bmax_(?:tokens|completion_tokens|output_tokens|new_tokens)\s*=\s*\d",
        re.IGNORECASE,
    )

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if not self._CALL_PATTERN.search(line):
                continue
            # Look in a window of ±10 lines for the token limit param
            window_start = max(0, i - 2)
            window_end = min(len(lines), i + 10)
            window = "\n".join(lines[window_start:window_end])
            if not self._LIMIT_PATTERN.search(window):
                findings.append(
                    self._make_finding(
                        file_path=file_path,
                        line_number=i + 1,
                        snippet=line.strip(),
                    )
                )
        return findings


# ── AI003  SystemPromptLeakage ────────────────────────────────────────


class SystemPromptLeakage(Rule):
    """Detect system prompt content returned in responses or written to logs."""

    id = "AI003"
    name = "System prompt leakage"
    severity = Severity.HIGH
    description = (
        "The LLM system prompt is exposed in an HTTP response, log statement, "
        "or print call. System prompts often contain confidential instructions, "
        "business logic, safety rules, or persona details. Leaking them lets "
        "attackers craft targeted jailbreaks and reverse-engineer your AI product."
    )
    fix = (
        "Never return system prompt content to end users or write it to logs:\n"
        "  # Store prompts as constants, never embed them in responses\n"
        "  SYSTEM_PROMPT = open('prompts/system.txt').read()  # keep server-side\n"
        "  return jsonify({'reply': assistant_message})  # user reply only\n"
        "  # Use structured logging that never touches SYSTEM_PROMPT variable\n"
        "  logger.info('Request processed', extra={'user_id': uid})"
    )
    guide_url = "guides/09-ai-security.md"
    owasp_id = "A01:2021"
    owasp_llm_id = "LLM07:2025"
    cwe_id = "CWE-200"
    confidence = "medium"

    file_extensions: list[str] = [".py", ".js", ".ts", ".jsx", ".tsx"]

    patterns: list[str] = [
        # System prompt returned directly in HTTP response
        r'return\s+.*(?:system_prompt|SYSTEM_PROMPT|systemPrompt)',
        r'["\']system_prompt["\']\s*:\s*(?:system_prompt|SYSTEM_PROMPT|systemPrompt)',
        # System prompt written to logs / stdout
        r'(?:print|logger\.\w+|logging\.\w+|console\.(?:log|error|warn))\s*\(.*(?:system_prompt|SYSTEM_PROMPT|systemPrompt)',
        # Response body directly embedding system prompt variable
        r'jsonify\s*\(.*(?:system_prompt|SYSTEM_PROMPT|systemPrompt)',
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


# ── AI004  UnpinnedModel ──────────────────────────────────────────────


class UnpinnedModel(Rule):
    """Detect LLM model identifiers without a specific version date."""

    id = "AI004"
    name = "Unpinned model version"
    severity = Severity.LOW
    description = (
        "An LLM model is referenced by an alias (e.g. 'gpt-4') rather than a "
        "fully-pinned version ID (e.g. 'gpt-4-0125-preview'). Model aliases "
        "silently upgrade to newer versions, breaking prompts, changing output "
        "formats, and potentially removing safety behaviours you relied upon. "
        "Pinning the version ensures deterministic, reproducible AI behaviour."
    )
    fix = (
        "Use a fully-pinned, date-stamped model identifier:\n"
        "  # Instead of:\n"
        '  model = "gpt-4"\n'
        "  # Use:\n"
        '  model = "gpt-4-0125-preview"   # or latest pinned stable\n'
        '  model = "claude-3-opus-20240229"\n'
        "  model = MODEL_VERSION  # defined as a constant with the full ID\n"
        "Review release notes when upgrading and test prompt behaviour."
    )
    guide_url = "guides/09-ai-security.md"
    owasp_id = "A08:2021"
    owasp_llm_id = "LLM09:2025"
    cwe_id = "CWE-829"
    confidence = "low"

    file_extensions: list[str] = [".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yaml", ".yml"]

    patterns: list[str] = [
        # OpenAI aliases without version date
        r'model\s*[=:]\s*["\'](?:gpt-4|gpt-3\.5-turbo|gpt-3\.5-turbo-instruct|gpt-4-turbo|gpt-4o)["\']',
        # Anthropic aliases without version date
        r'model\s*[=:]\s*["\'](?:claude-3-opus|claude-3-sonnet|claude-3-haiku|claude-2|claude-instant)["\']',
        # Generic latest/current alias patterns
        r'model\s*[=:]\s*["\'](?:text-davinci-003|text-davinci-002|davinci|curie|babbage|ada)["\']',
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


# ── AI005  LLMOutputTrust ─────────────────────────────────────────────


class LLMOutputTrust(Rule):
    """Detect LLM output used directly in dangerous execution contexts."""

    id = "AI005"
    name = "LLM output trust violation"
    severity = Severity.CRITICAL
    description = (
        "LLM-generated text is passed directly to a code execution function "
        "(eval, exec, os.system, subprocess) or a database cursor without "
        "validation. An attacker who controls the model prompt can generate "
        "malicious payloads achieving Remote Code Execution or SQL injection. "
        "Never trust LLM output as code or SQL."
    )
    fix = (
        "Treat all LLM output as untrusted user input:\n"
        "  # Validate and parse structured output — never eval/exec it\n"
        "  import json\n"
        "  result = json.loads(llm_output)   # strict schema validation\n"
        "  # For code generation, run in a sandboxed environment:\n"
        "  #   - Docker container with no network / filesystem access\n"
        "  #   - E2B or similar code sandbox API\n"
        "  # For SQL, use parameterised queries:\n"
        "  cursor.execute('SELECT * FROM t WHERE id = %s', (validated_id,))"
    )
    guide_url = "guides/09-ai-security.md"
    owasp_id = "A03:2021"
    owasp_llm_id = "LLM02:2025"
    cwe_id = "CWE-20"
    confidence = "medium"

    file_extensions: list[str] = [".py", ".js", ".ts", ".jsx", ".tsx"]

    patterns: list[str] = [
        # eval/exec of LLM response content
        r'(?:eval|exec)\s*\(.*(?:\.choices\[|message\.content|\.content\b|llm_output|ai_output|model_output)',
        # Shell execution with LLM output
        r'os\.system\s*\(.*(?:\.content\b|llm_output|ai_output|model_response)',
        r'subprocess\.(?:run|call|Popen|check_output)\s*\(.*(?:\.content\b|llm_output|ai_output)',
        # SQL query built from LLM output
        r'cursor\.execute\s*\(.*(?:\.content\b|llm_output|ai_response|model_output)',
        # JavaScript eval of LLM output
        r'eval\s*\(\s*(?:response\.|llmOutput|aiOutput|modelOutput)',
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


# ── AI006  InlineAIApiKey ─────────────────────────────────────────────


class InlineAIApiKey(Rule):
    """Detect AI provider API keys hardcoded in SDK constructor calls."""

    id = "AI006"
    name = "AI API key hardcoded in SDK call"
    severity = Severity.CRITICAL
    description = (
        "An AI provider API key is passed as a hardcoded string literal directly "
        "into the SDK client constructor (e.g. OpenAI(api_key='sk-...')). This "
        "exposes the key to anyone with repository access, in build logs, and in "
        "any artifact that bundles the source. Rotated keys leave old credentials "
        "visible in git history."
    )
    fix = (
        "Load the API key from an environment variable:\n"
        "  import os\n"
        "  from openai import OpenAI\n"
        '  client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])\n'
        "  # Or rely on the SDK's automatic env-var lookup:\n"
        "  client = OpenAI()  # reads OPENAI_API_KEY automatically\n"
        "Add .env to .gitignore and store secrets in a vault / CI secret store."
    )
    guide_url = "guides/09-ai-security.md"
    owasp_id = "A02:2021"
    owasp_llm_id = "LLM02:2025"
    cwe_id = "CWE-798"
    confidence = "high"

    file_extensions: list[str] = [".py", ".js", ".ts", ".jsx", ".tsx"]

    patterns: list[str] = [
        # OpenAI client with hardcoded sk- key
        r'OpenAI\s*\(\s*api_key\s*=\s*["\']sk-[A-Za-z0-9]{16,}',
        # Anthropic client with hardcoded key
        r'Anthropic\s*\(\s*api_key\s*=\s*["\']sk-ant-[A-Za-z0-9\-]{16,}',
        # Generic api_key= assignment with sk- prefix (AI SDK context)
        r'api_key\s*=\s*["\']sk-[A-Za-z0-9_\-]{20,}["\']',
        # openai.api_key = "sk-..." (legacy style)
        r'openai\.api_key\s*=\s*["\']sk-[A-Za-z0-9_\-]{20,}["\']',
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)

    def _redact(self, line: str, pattern: str) -> str:
        """Mask the API key value."""
        return re.sub(r'(["\'])sk-[A-Za-z0-9_\-]+\1', r'\1sk-[REDACTED]\1', line)


# ── AI007  MissingOutputModeration ───────────────────────────────────


class MissingOutputModeration(Rule):
    """Detect LLM output rendered as raw HTML without sanitization."""

    id = "AI007"
    name = "LLM output rendered without sanitization"
    severity = Severity.HIGH
    description = (
        "Raw LLM output is embedded directly in HTML (via dangerouslySetInnerHTML, "
        "innerHTML, or v-html) without sanitization. An attacker can craft prompts "
        "that make the model generate malicious HTML/JavaScript payloads, leading to "
        "Stored XSS. Always sanitize AI-generated content before rendering as HTML."
    )
    fix = (
        "Sanitize LLM output before inserting it into the DOM:\n"
        "  // React — use a sanitisation library instead\n"
        "  import DOMPurify from 'dompurify';\n"
        "  <div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(llmOutput)}} />\n"
        "  // Vanilla JS\n"
        "  element.innerHTML = DOMPurify.sanitize(llmOutput);\n"
        "  // Better: render as plain text, not HTML\n"
        "  element.textContent = llmOutput;  // never interpreted as HTML"
    )
    guide_url = "guides/09-ai-security.md"
    owasp_id = "A03:2021"
    owasp_llm_id = "LLM02:2025"
    cwe_id = "CWE-79"
    confidence = "medium"

    file_extensions: list[str] = [".js", ".ts", ".jsx", ".tsx", ".html", ".vue"]

    patterns: list[str] = [
        # React dangerouslySetInnerHTML with LLM output
        r'dangerouslySetInnerHTML\s*=\s*\{\s*\{[^}]*(?:llm|ai|model|gpt|claude|response)(?:Output|Response|Text|Content|Result)',
        # Direct innerHTML assignment with LLM output
        r'\.innerHTML\s*=\s*.*(?:llm|ai|model|gpt|claude)(?:Output|Response|Text|Content|Result)',
        # Vue v-html with LLM output
        r'v-html\s*=\s*["\'].*(?:llm|ai|model|response)(?:output|text|content|result)',
        # innerHTML with common LLM response variable names (no sanitize call)
        r'\.innerHTML\s*=\s*(?:aiOutput|llmOutput|modelOutput|aiResponse|llmResponse|gptResponse)',
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)
