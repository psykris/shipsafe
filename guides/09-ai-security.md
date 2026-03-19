# Guide 09 — AI Application Security

## What This Guide Covers

Security vulnerabilities specific to applications built on top of LLMs (ChatGPT,
Claude, Gemini, Llama, etc.): prompt injection, cost exposure, system prompt
leakage, unpinned models, output trust, and hardcoded API keys.

These risks do not appear in OWASP Top 10 but are covered by the
[OWASP LLM Top 10 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

---

## AI001 — Prompt Injection

**Risk**: User input overwrites your system prompt and causes the model to
perform unintended actions, reveal confidential context, or bypass restrictions.

```python
# Vulnerable — user input directly in message content
messages = [
    {"role": "system", "content": SYSTEM_PROMPT},
    {"role": "user", "content": request.json["message"]},  # AI001: direct
]

# Also vulnerable — f-string concatenation
prompt = f"Summarise this for me: {user_input}"   # AI001: f-string injection
```

**Fix**:

```python
# Validate, bound, and isolate user input
user_input = request.json.get("message", "")
if not isinstance(user_input, str):
    abort(400)
user_input = user_input[:2000].strip()   # hard length cap

messages = [
    {"role": "system", "content": SYSTEM_PROMPT},   # you control this
    {"role": "user", "content": user_input},          # sandboxed in user role
]

# For high-risk applications, add a guard model or content filter before
# sending the request to the primary model.
```

**OWASP LLM Top 10**: LLM01:2025 — Prompt Injection

---

## AI002 — Unbounded LLM Cost

**Risk**: A single API call with no `max_tokens` limit can consume thousands of
tokens, allowing a DoS-via-cost ("denial of wallet") attack.

```python
# Vulnerable — no max_tokens
response = client.chat.completions.create(
    model="gpt-4-0125-preview",
    messages=messages,
    # missing: max_tokens
)
```

**Fix**:

```python
response = client.chat.completions.create(
    model="gpt-4-0125-preview",
    messages=messages,
    max_tokens=512,    # hard ceiling per request
    timeout=30,        # network timeout in seconds
)

# Also set per-user quotas in your application layer:
if user.daily_tokens_used + estimated_tokens > DAILY_LIMIT:
    raise RateLimitError("Daily AI quota exceeded")
```

**OWASP LLM Top 10**: LLM10:2025 — Unbounded Consumption

---

## AI003 — System Prompt Leakage

**Risk**: Your system prompt contains business logic, safety rules, or persona
instructions. Leaking it lets attackers craft targeted jailbreaks.

```python
# Vulnerable — returning system prompt in API response
return jsonify({
    "reply": assistant_message,
    "system_prompt": SYSTEM_PROMPT,   # AI003: leaked
})

# Also vulnerable — logging the system prompt
logger.info("Sending request with system_prompt: %s", SYSTEM_PROMPT)  # AI003
```

**Fix**:

```python
# Only return the assistant's reply
return jsonify({"reply": assistant_message})

# Use structured logging with IDs, never prompt content
logger.info("LLM request sent", extra={"request_id": req_id, "user_id": user_id})
```

**OWASP LLM Top 10**: LLM07:2025 — System Prompt Leakage

---

## AI004 — Unpinned Model Version

**Risk**: Model aliases like `"gpt-4"` silently upgrade to newer model versions,
which can break your prompts, change output formats, and alter safety behaviours.

```python
# Vulnerable — unpinned alias
model = "gpt-4"            # AI004: silently upgrades
model = "claude-3-opus"    # AI004: unpinned
```

**Fix**:

```python
# Pinned with a version date — stable and reproducible
MODEL = "gpt-4-0125-preview"          # OpenAI pinned
MODEL = "claude-3-opus-20240229"       # Anthropic pinned

# Define as a constant; update intentionally after testing
response = client.chat.completions.create(model=MODEL, ...)
```

**OWASP LLM Top 10**: LLM09:2025 — Misinformation / Model Behaviour

---

## AI005 — LLM Output Trust Violation

**Risk**: LLM output is treated as trusted code or SQL. An attacker who controls
the prompt can make the model generate malicious payloads.

```python
# Critical vulnerability — eval/exec of LLM output
result = eval(response.choices[0].message.content)    # AI005: RCE
exec(llm_output)                                        # AI005: RCE
os.system(ai_response)                                  # AI005: RCE
cursor.execute(llm_output)                              # AI005: SQL injection
```

**Fix**:

```python
import json, ast

# Parse structured output — never execute it
raw = response.choices[0].message.content
try:
    data = json.loads(raw)   # strict schema, not eval
except json.JSONDecodeError:
    abort(422, "Invalid model output")

# For code generation, use a sandboxed environment:
# - Docker container with no network/filesystem access
# - E2B code sandbox API (https://e2b.dev)
# - Pyodide (WebAssembly, browser-isolated)

# For SQL, always use parameterised queries:
cursor.execute("SELECT * FROM t WHERE id = %s", (validated_id,))
```

**OWASP LLM Top 10**: LLM02:2025 — Insecure Output Handling

---

## AI006 — Hardcoded AI API Key

**Risk**: API keys hardcoded in source end up in git history, build logs, and
any artifact that bundles the source file.

```python
# Vulnerable — hardcoded key
client = OpenAI(api_key="sk-abcdef...")   # AI006: hardcoded
openai.api_key = "sk-abcdef..."           # AI006: legacy style
```

**Fix**:

```python
import os
from openai import OpenAI

# Rely on automatic env-var lookup (OPENAI_API_KEY)
client = OpenAI()

# Or explicit env-var reference
client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

# Store in .env for local dev:
# OPENAI_API_KEY=sk-...
# .env must be in .gitignore
```

**OWASP Top 10**: A02:2021 — Cryptographic Failures

---

## AI007 — LLM Output Rendered as Raw HTML

**Risk**: Raw LLM output embedded in HTML allows model-generated XSS. An
attacker crafts a prompt that makes the model output malicious JavaScript.

```jsx
// Vulnerable — unsanitized innerHTML
<div dangerouslySetInnerHTML={{__html: llmOutput}} />   {/* AI007 */}
element.innerHTML = aiResponse;                          // AI007
```

**Fix**:

```jsx
import DOMPurify from 'dompurify';

// Sanitize before rendering as HTML
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(llmOutput)}} />

// Better: render as plain text (never interpreted as HTML)
<div>{llmOutput}</div>
element.textContent = llmOutput;   // safe
```

---

## Complete AI Security Checklist

- [ ] User input validated, bounded (max length), and sandboxed in `user` role
- [ ] Every LLM call has `max_tokens` and `timeout` set
- [ ] System prompt never appears in HTTP responses or logs
- [ ] Model identifiers pinned with version dates
- [ ] LLM output never passed to `eval`, `exec`, shell, or raw SQL
- [ ] API keys loaded from env vars (never hardcoded)
- [ ] LLM output sanitized with DOMPurify before HTML rendering
- [ ] Per-user daily token quotas enforced in application layer
- [ ] Guard model or content filter for high-risk user-facing applications

## Related Rules

| Rule | OWASP LLM | What it catches |
|------|-----------|-----------------|
| AI001 | LLM01:2025 | Prompt injection via unsanitized user input |
| AI002 | LLM10:2025 | Missing `max_tokens` — cost exposure |
| AI003 | LLM07:2025 | System prompt in response or logs |
| AI004 | LLM09:2025 | Unpinned model alias |
| AI005 | LLM02:2025 | LLM output in `eval`/`exec`/SQL |
| AI006 | A02:2021 | Hardcoded AI API key in SDK call |
| AI007 | LLM02:2025 | Raw LLM output rendered as HTML |
