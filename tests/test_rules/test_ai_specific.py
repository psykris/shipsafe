"""Tests for AI-specific security rules (AI001–AI007)."""
from pathlib import Path

import pytest

from shipsafe.rules.ai_specific import (
    InlineAIApiKey,
    LLMOutputTrust,
    MissingOutputModeration,
    PromptInjectionRisk,
    SystemPromptLeakage,
    UnboundedLLMCost,
    UnpinnedModel,
)

VULN_DIR = Path(__file__).parent.parent / "fixtures" / "vulnerable" / "ai_specific"
CLEAN_DIR = Path(__file__).parent.parent / "fixtures" / "clean" / "ai_specific"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ── AI001 ─────────────────────────────────────────────────────────────


class TestPromptInjectionRisk:
    rule = PromptInjectionRisk()
    vuln = _read(VULN_DIR / "prompt_injection.py")
    clean = _read(CLEAN_DIR / "safe_ai_app.py")

    def test_true_positive(self):
        findings = self.rule.scan("app.py", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("app.py", self.clean)
        assert len(findings) == 0

    def test_request_content_pattern(self):
        code = '"content": request.json.get("message")'
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_fstring_pattern(self):
        code = 'prompt = f"Answer this: {user_input}"'
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_augmented_assignment_pattern(self):
        code = "system_prompt += user_input"
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_extension_filter(self):
        assert self.rule.applies_to("app.py") is True
        assert self.rule.applies_to("app.ts") is True
        assert self.rule.applies_to("readme.md") is False

    def test_rule_id(self):
        assert self.rule.id == "AI001"


# ── AI002 ─────────────────────────────────────────────────────────────


class TestUnboundedLLMCost:
    rule = UnboundedLLMCost()
    vuln = _read(VULN_DIR / "unbounded_cost.py")
    clean = _read(CLEAN_DIR / "safe_ai_app.py")

    def test_true_positive(self):
        findings = self.rule.scan("app.py", self.vuln)
        assert len(findings) >= 1

    def test_true_negative_with_max_tokens(self):
        code = (
            "response = client.chat.completions.create(\n"
            '    model="gpt-4-0125-preview",\n'
            "    messages=messages,\n"
            "    max_tokens=512,\n"
            ")\n"
        )
        findings = self.rule.scan("app.py", code)
        assert len(findings) == 0

    def test_true_negative_clean_file(self):
        findings = self.rule.scan("app.py", self.clean)
        assert len(findings) == 0

    def test_detects_missing_max_tokens(self):
        code = (
            "response = client.chat.completions.create(\n"
            '    model="gpt-4-0125-preview",\n'
            "    messages=messages,\n"
            "    temperature=0.7,\n"
            ")\n"
        )
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_extension_filter(self):
        assert self.rule.applies_to("app.py") is True
        assert self.rule.applies_to("app.ts") is True

    def test_rule_id(self):
        assert self.rule.id == "AI002"


# ── AI003 ─────────────────────────────────────────────────────────────


class TestSystemPromptLeakage:
    rule = SystemPromptLeakage()
    vuln = _read(VULN_DIR / "system_prompt_leak.py")
    clean = _read(CLEAN_DIR / "safe_ai_app.py")

    def test_true_positive(self):
        findings = self.rule.scan("app.py", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("app.py", self.clean)
        assert len(findings) == 0

    def test_jsonify_leakage(self):
        code = 'return jsonify({"system_prompt": SYSTEM_PROMPT})'
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_log_leakage(self):
        code = 'logger.info("Using system_prompt: %s", SYSTEM_PROMPT)'
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_return_leakage(self):
        code = "return system_prompt"
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_rule_id(self):
        assert self.rule.id == "AI003"


# ── AI004 ─────────────────────────────────────────────────────────────


class TestUnpinnedModel:
    rule = UnpinnedModel()
    vuln = _read(VULN_DIR / "unpinned_model.py")
    clean = _read(CLEAN_DIR / "safe_ai_app.py")

    def test_true_positive(self):
        findings = self.rule.scan("app.py", self.vuln)
        assert len(findings) >= 1

    def test_true_negative_pinned_model(self):
        # Pinned model with date — should not trigger
        code = 'model = "gpt-4-0125-preview"'
        findings = self.rule.scan("app.py", code)
        assert len(findings) == 0

    def test_true_negative_clean_file(self):
        findings = self.rule.scan("app.py", self.clean)
        assert len(findings) == 0

    def test_gpt4_alias(self):
        code = 'model = "gpt-4"'
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_gpt35_alias(self):
        code = 'model = "gpt-3.5-turbo"'
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_claude3_alias(self):
        code = 'model = "claude-3-opus"'
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_extension_filter(self):
        assert self.rule.applies_to("app.py") is True
        assert self.rule.applies_to("config.json") is True
        assert self.rule.applies_to("readme.md") is False

    def test_rule_id(self):
        assert self.rule.id == "AI004"


# ── AI005 ─────────────────────────────────────────────────────────────


class TestLLMOutputTrust:
    rule = LLMOutputTrust()
    vuln = _read(VULN_DIR / "output_trust.py")
    clean = _read(CLEAN_DIR / "safe_ai_app.py")

    def test_true_positive(self):
        findings = self.rule.scan("app.py", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("app.py", self.clean)
        assert len(findings) == 0

    def test_eval_pattern(self):
        code = "result = eval(llm_output)"
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_exec_pattern(self):
        code = "exec(model_output)"
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_os_system_pattern(self):
        code = "os.system(llm_output)"
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_subprocess_pattern(self):
        code = "subprocess.run(ai_output, shell=True)"
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_sql_pattern(self):
        code = "cursor.execute(llm_output)"
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_rule_id(self):
        assert self.rule.id == "AI005"


# ── AI006 ─────────────────────────────────────────────────────────────


class TestInlineAIApiKey:
    rule = InlineAIApiKey()
    vuln = _read(VULN_DIR / "inline_api_key.py")
    clean = _read(CLEAN_DIR / "safe_ai_app.py")

    def test_true_positive(self):
        findings = self.rule.scan("app.py", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("app.py", self.clean)
        assert len(findings) == 0

    def test_openai_client_pattern(self):
        code = 'client = OpenAI(api_key="sk-abcdefghijklmnopqrstuvwx")'
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_redaction(self):
        code = 'client = OpenAI(api_key="sk-abcdefghijklmnopqrstuvwx")'
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1
        for f in findings:
            assert "sk-abcdefghijklmnopqrstuvwx" not in f.snippet
            assert "[REDACTED]" in f.snippet

    def test_anthropic_pattern(self):
        code = 'client = Anthropic(api_key="sk-ant-abcdef1234567890123456")'
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_legacy_style(self):
        code = 'openai.api_key = "sk-oldstyle000011112222333344445555"'
        findings = self.rule.scan("app.py", code)
        assert len(findings) >= 1

    def test_env_var_is_safe(self):
        code = 'client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])'
        findings = self.rule.scan("app.py", code)
        assert len(findings) == 0

    def test_rule_id(self):
        assert self.rule.id == "AI006"


# ── AI007 ─────────────────────────────────────────────────────────────


class TestMissingOutputModeration:
    rule = MissingOutputModeration()
    vuln = _read(VULN_DIR / "missing_moderation.jsx")
    clean = _read(CLEAN_DIR / "safe_moderation.jsx")

    def test_true_positive(self):
        findings = self.rule.scan("app.jsx", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("app.jsx", self.clean)
        assert len(findings) == 0

    def test_dangerous_innerhtml_pattern(self):
        code = "dangerouslySetInnerHTML={{__html: llmOutput}}"
        findings = self.rule.scan("app.jsx", code)
        assert len(findings) >= 1

    def test_innerhtml_direct_pattern(self):
        code = "document.getElementById('out').innerHTML = aiResponse;"
        findings = self.rule.scan("app.js", code)
        assert len(findings) >= 1

    def test_textcontent_is_safe(self):
        code = "element.textContent = llmOutput;"
        findings = self.rule.scan("app.js", code)
        assert len(findings) == 0

    def test_extension_filter(self):
        assert self.rule.applies_to("app.jsx") is True
        assert self.rule.applies_to("app.js") is True
        assert self.rule.applies_to("app.vue") is True
        assert self.rule.applies_to("app.py") is False

    def test_rule_id(self):
        assert self.rule.id == "AI007"
