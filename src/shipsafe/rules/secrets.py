"""Secrets detection rules — the most critical ShipSafe module.

Detects hardcoded API keys, tokens, passwords, and private keys in source
code.  Every pattern is a class-level constant so you can audit the full
catalogue with a single grep:

    grep -A5 "patterns = \\[" src/shipsafe/rules/secrets.py

Design invariants
-----------------
- Patterns live on the class, never hidden inside methods.
- Matched values are **always** redacted before they appear in output.
- Every fix includes the rotation URL because the old key must be
  treated as compromised the moment it touches version control.
"""

import re

from shipsafe.finding import Finding, Severity
from shipsafe.rules.base import Rule

# ── Shared constants ────────────────────────────────────────────────

_GUIDE_URL = "guides/01-secrets-management.md"
_OWASP_ID = "A07:2021"


def _env_fix(var_name: str, rotation_url: str) -> str:
    """Build the standard copy-paste fix block."""
    return (
        "1. Remove the key from your source code immediately.\n"
        f"2. Create a `.env` file and add: {var_name}=your-key-here\n"
        "3. Add `.env` to your `.gitignore` file.\n"
        "4. In your code, load from environment:\n"
        f'   Python:     import os; key = os.environ.get("{var_name}")\n'
        f"   JavaScript: const key = process.env.{var_name};\n"
        f"5. Rotate your key at {rotation_url}\n"
        "   The old key is compromised — assume it has been scraped."
    )


# ── SEC001  HardcodedOpenAIKey ──────────────────────────────────────


class HardcodedOpenAIKey(Rule):
    """Detect hardcoded OpenAI API keys."""

    id = "SEC001"
    name = "HardcodedOpenAIKey"
    severity = Severity.CRITICAL
    description = (
        "An OpenAI API key is hardcoded in source code. Anyone with access "
        "to this repository can use the key to make API calls at your "
        "expense, exfiltrate model outputs, or abuse rate limits."
    )
    guide_url = _GUIDE_URL
    owasp_id = _OWASP_ID
    cwe_id = "CWE-798"
    confidence = "high"

    patterns: list[str] = [
        r"sk-proj-[a-zA-Z0-9_-]{40,}",
        r"sk-svcacct-[a-zA-Z0-9_-]{40,}",
        r"sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}",
    ]

    fix: str = _env_fix("OPENAI_API_KEY", "https://platform.openai.com/api-keys")

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)

    def _redact(self, line: str, pattern: str) -> str:
        def _replacer(m: re.Match) -> str:
            val = m.group()
            # Show recognisable prefix then redact the rest
            if val.startswith("sk-proj-"):
                return "sk-proj-...REDACTED"
            if val.startswith("sk-svcacct-"):
                return "sk-svcacct-...REDACTED"
            return "sk-...REDACTED"

        return re.sub(pattern, _replacer, line)


# ── SEC002  HardcodedAnthropicKey ───────────────────────────────────


class HardcodedAnthropicKey(Rule):
    """Detect hardcoded Anthropic API keys."""

    id = "SEC002"
    name = "HardcodedAnthropicKey"
    severity = Severity.CRITICAL
    description = (
        "An Anthropic API key is hardcoded in source code. Anyone with "
        "repository access can use the key to call Claude APIs at your "
        "expense and potentially access sensitive model outputs."
    )
    guide_url = _GUIDE_URL
    owasp_id = _OWASP_ID
    cwe_id = "CWE-798"
    confidence = "high"

    patterns: list[str] = [
        r"sk-ant-api03-[a-zA-Z0-9_-]{40,}",
    ]

    fix: str = _env_fix(
        "ANTHROPIC_API_KEY",
        "https://console.anthropic.com/settings/keys",
    )

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)

    def _redact(self, line: str, pattern: str) -> str:
        return re.sub(pattern, "sk-ant-api03-...REDACTED", line)


# ── SEC003  HardcodedAWSKey ─────────────────────────────────────────


class HardcodedAWSKey(Rule):
    """Detect hardcoded AWS access key IDs."""

    id = "SEC003"
    name = "HardcodedAWSKey"
    severity = Severity.CRITICAL
    description = (
        "An AWS access key ID is hardcoded in source code. Exposed AWS "
        "credentials can lead to full account compromise, data theft, "
        "and significant financial charges from unauthorized resource usage."
    )
    guide_url = _GUIDE_URL
    owasp_id = _OWASP_ID
    cwe_id = "CWE-798"
    confidence = "high"

    patterns: list[str] = [
        r"AKIA[0-9A-Z]{16}",
    ]

    fix: str = _env_fix("AWS_ACCESS_KEY_ID", "https://console.aws.amazon.com/iam/")

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)

    def _redact(self, line: str, pattern: str) -> str:
        def _replacer(m: re.Match) -> str:
            return m.group()[:8] + "...REDACTED"

        return re.sub(pattern, _replacer, line)


# ── SEC004  HardcodedGCPKey ─────────────────────────────────────────


class HardcodedGCPKey(Rule):
    """Detect hardcoded Google Cloud Platform API keys."""

    id = "SEC004"
    name = "HardcodedGCPKey"
    severity = Severity.CRITICAL
    description = (
        "A Google Cloud API key is hardcoded in source code. Exposed GCP "
        "keys can be used to consume quota, access enabled APIs, and "
        "potentially reach sensitive cloud resources."
    )
    guide_url = _GUIDE_URL
    owasp_id = _OWASP_ID
    cwe_id = "CWE-798"
    confidence = "high"

    patterns: list[str] = [
        r"AIza[0-9A-Za-z_-]{35}",
    ]

    fix: str = _env_fix(
        "GCP_API_KEY",
        "https://console.cloud.google.com/apis/credentials",
    )

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)

    def _redact(self, line: str, pattern: str) -> str:
        return re.sub(pattern, "AIza...REDACTED", line)


# ── SEC005  HardcodedStripeKey ──────────────────────────────────────


class HardcodedStripeKey(Rule):
    """Detect hardcoded Stripe secret keys."""

    id = "SEC005"
    name = "HardcodedStripeKey"
    severity = Severity.CRITICAL
    description = (
        "A Stripe secret key is hardcoded in source code. Exposed Stripe "
        "keys allow attackers to issue refunds, create charges, and access "
        "customer payment data."
    )
    guide_url = _GUIDE_URL
    owasp_id = _OWASP_ID
    cwe_id = "CWE-798"
    confidence = "high"

    patterns: list[str] = [
        r"sk_live_[0-9a-zA-Z]{24,}",
    ]

    fix: str = _env_fix(
        "STRIPE_SECRET_KEY",
        "https://dashboard.stripe.com/apikeys",
    )

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)

    def _redact(self, line: str, pattern: str) -> str:
        return re.sub(pattern, "sk_live_...REDACTED", line)


# ── SEC006  HardcodedGitHubToken ────────────────────────────────────


class HardcodedGitHubToken(Rule):
    """Detect hardcoded GitHub personal access and OAuth tokens."""

    id = "SEC006"
    name = "HardcodedGitHubToken"
    severity = Severity.CRITICAL
    description = (
        "A GitHub token is hardcoded in source code. Exposed tokens can "
        "grant read/write access to repositories, workflows, and "
        "organization data depending on the scopes assigned."
    )
    guide_url = _GUIDE_URL
    owasp_id = _OWASP_ID
    cwe_id = "CWE-798"
    confidence = "high"

    patterns: list[str] = [
        r"ghp_[0-9a-zA-Z]{36}",
        r"gho_[0-9a-zA-Z]{36}",
        r"ghu_[0-9a-zA-Z]{36}",
        r"ghs_[0-9a-zA-Z]{36}",
        r"ghr_[0-9a-zA-Z]{36}",
    ]

    fix: str = _env_fix(
        "GITHUB_TOKEN",
        "https://github.com/settings/tokens",
    )

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)

    def _redact(self, line: str, pattern: str) -> str:
        def _replacer(m: re.Match) -> str:
            prefix = m.group()[:4]  # ghp_, gho_, etc.
            return f"{prefix}...REDACTED"

        return re.sub(pattern, _replacer, line)


# ── SEC007  HardcodedGitLabToken ────────────────────────────────────


class HardcodedGitLabToken(Rule):
    """Detect hardcoded GitLab personal access tokens."""

    id = "SEC007"
    name = "HardcodedGitLabToken"
    severity = Severity.CRITICAL
    description = (
        "A GitLab personal access token is hardcoded in source code. "
        "Exposed tokens can grant full API access to repositories, CI/CD "
        "pipelines, and container registries."
    )
    guide_url = _GUIDE_URL
    owasp_id = _OWASP_ID
    cwe_id = "CWE-798"
    confidence = "high"

    patterns: list[str] = [
        r"glpat-[0-9a-zA-Z_-]{20,}",
    ]

    fix: str = _env_fix(
        "GITLAB_TOKEN",
        "https://gitlab.com/-/user_settings/personal_access_tokens",
    )

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)

    def _redact(self, line: str, pattern: str) -> str:
        return re.sub(pattern, "glpat-...REDACTED", line)


# ── SEC008  HardcodedSlackToken ─────────────────────────────────────


class HardcodedSlackToken(Rule):
    """Detect hardcoded Slack bot, user, and app-level tokens."""

    id = "SEC008"
    name = "HardcodedSlackToken"
    severity = Severity.CRITICAL
    description = (
        "A Slack token is hardcoded in source code. Exposed Slack tokens "
        "can be used to read messages, post as your bot, access files, and "
        "enumerate workspace members."
    )
    guide_url = _GUIDE_URL
    owasp_id = _OWASP_ID
    cwe_id = "CWE-798"
    confidence = "high"

    patterns: list[str] = [
        r"xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{20,}",
        r"xoxp-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{20,}",
        r"xapp-[0-9]-[a-zA-Z0-9]+-[0-9]+-[a-zA-Z0-9]+",
    ]

    fix: str = _env_fix("SLACK_TOKEN", "https://api.slack.com/apps")

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)

    def _redact(self, line: str, pattern: str) -> str:
        def _replacer(m: re.Match) -> str:
            val = m.group()
            prefix = val.split("-")[0]  # xoxb, xoxp, xapp
            return f"{prefix}-...REDACTED"

        return re.sub(pattern, _replacer, line)


# ── SEC009  HardcodedDatabaseURL ────────────────────────────────────


class HardcodedDatabaseURL(Rule):
    """Detect database connection strings with embedded credentials."""

    id = "SEC009"
    name = "HardcodedDatabaseURL"
    severity = Severity.CRITICAL
    description = (
        "A database connection string with embedded credentials is "
        "hardcoded in source code. This exposes database usernames and "
        "passwords, enabling direct unauthorized access to your data stores."
    )
    guide_url = _GUIDE_URL
    owasp_id = _OWASP_ID
    cwe_id = "CWE-798"
    confidence = "high"

    patterns: list[str] = [
        r"(postgres|postgresql|mysql|mongodb|redis|amqp)://[^:\s]+:[^@\s]+@",
    ]

    fix: str = _env_fix(
        "DATABASE_URL",
        "your database provider's credential management console",
    )

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)

    def _redact(self, line: str, pattern: str) -> str:
        def _replacer(m: re.Match) -> str:
            val = m.group()
            # Extract the scheme (postgres, mongodb, etc.)
            scheme = val.split("://")[0]
            return f"{scheme}://REDACTED:REDACTED@"

        return re.sub(pattern, _replacer, line)


# ── SEC010  PrivateKeyInSource ──────────────────────────────────────


class PrivateKeyInSource(Rule):
    """Detect private keys (RSA, EC, DSA, etc.) embedded in source code."""

    id = "SEC010"
    name = "PrivateKeyInSource"
    severity = Severity.CRITICAL
    description = (
        "A private key is embedded directly in source code. Private keys "
        "should never be committed to version control. Anyone with "
        "repository access can impersonate your service or decrypt traffic."
    )
    guide_url = _GUIDE_URL
    owasp_id = _OWASP_ID
    cwe_id = "CWE-798"
    confidence = "high"

    patterns: list[str] = [
        r"-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+|DSA\s+|ENCRYPTED\s+)?PRIVATE\s+KEY-----",
    ]

    fix: str = (
        "1. Remove the private key from your source code immediately.\n"
        "2. Move the key to a file outside your repository, e.g. ~/.ssh/ or a secrets vault.\n"
        "3. Add the key file path to `.gitignore`.\n"
        "4. Reference the key by file path or environment variable:\n"
        '   Python:     key_path = os.environ.get("PRIVATE_KEY_PATH")\n'
        "   JavaScript: const keyPath = process.env.PRIVATE_KEY_PATH;\n"
        "5. Generate a new key pair — the old private key is compromised.\n"
        "   Revoke and replace any certificates or authorized_keys entries\n"
        "   that used the exposed public key."
    )

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)

    def _redact(self, line: str, pattern: str) -> str:
        return re.sub(pattern, "-----BEGIN PRIVATE KEY----- ...REDACTED", line)


# ── SEC011  HardcodedTwilioKey ──────────────────────────────────────


class HardcodedTwilioKey(Rule):
    """Detect hardcoded Twilio API keys."""

    id = "SEC011"
    name = "HardcodedTwilioKey"
    severity = Severity.CRITICAL
    description = (
        "A Twilio API key is hardcoded in source code. Exposed Twilio keys "
        "can be used to send SMS/calls at your expense, access call logs, "
        "and read message history."
    )
    guide_url = _GUIDE_URL
    owasp_id = _OWASP_ID
    cwe_id = "CWE-798"
    confidence = "high"

    patterns: list[str] = [
        r"SK[0-9a-fA-F]{32}",
    ]

    fix: str = _env_fix(
        "TWILIO_API_KEY",
        "https://www.twilio.com/console",
    )

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)

    def _redact(self, line: str, pattern: str) -> str:
        def _replacer(m: re.Match) -> str:
            return m.group()[:6] + "...REDACTED"

        return re.sub(pattern, _replacer, line)


# ── SEC012  HardcodedSendGridKey ────────────────────────────────────


class HardcodedSendGridKey(Rule):
    """Detect hardcoded SendGrid API keys."""

    id = "SEC012"
    name = "HardcodedSendGridKey"
    severity = Severity.CRITICAL
    description = (
        "A SendGrid API key is hardcoded in source code. Exposed SendGrid "
        "keys allow attackers to send emails from your domain, potentially "
        "for phishing, and access your email sending history."
    )
    guide_url = _GUIDE_URL
    owasp_id = _OWASP_ID
    cwe_id = "CWE-798"
    confidence = "high"

    patterns: list[str] = [
        r"SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}",
    ]

    fix: str = _env_fix(
        "SENDGRID_API_KEY",
        "https://app.sendgrid.com/settings/api_keys",
    )

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)

    def _redact(self, line: str, pattern: str) -> str:
        return re.sub(pattern, "SG....REDACTED", line)


# ── SEC013  HardcodedMailgunKey ─────────────────────────────────────


class HardcodedMailgunKey(Rule):
    """Detect hardcoded Mailgun API keys."""

    id = "SEC013"
    name = "HardcodedMailgunKey"
    severity = Severity.CRITICAL
    description = (
        "A Mailgun API key is hardcoded in source code. Exposed Mailgun "
        "keys allow attackers to send emails from your domain, read "
        "inbound messages, and manage your sending infrastructure."
    )
    guide_url = _GUIDE_URL
    owasp_id = _OWASP_ID
    cwe_id = "CWE-798"
    confidence = "high"

    patterns: list[str] = [
        r"key-[0-9a-zA-Z]{32}",
    ]

    fix: str = _env_fix(
        "MAILGUN_API_KEY",
        "https://app.mailgun.com/settings/api_security",
    )

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)

    def _redact(self, line: str, pattern: str) -> str:
        return re.sub(pattern, "key-...REDACTED", line)


# ── SEC014  HardcodedNPMToken ───────────────────────────────────────


class HardcodedNPMToken(Rule):
    """Detect hardcoded npm access tokens."""

    id = "SEC014"
    name = "HardcodedNPMToken"
    severity = Severity.CRITICAL
    description = (
        "An npm access token is hardcoded in source code. Exposed npm "
        "tokens can be used to publish malicious packages under your "
        "account, potentially compromising downstream users."
    )
    guide_url = _GUIDE_URL
    owasp_id = _OWASP_ID
    cwe_id = "CWE-798"
    confidence = "high"

    patterns: list[str] = [
        r"npm_[0-9a-zA-Z]{36}",
    ]

    fix: str = _env_fix(
        "NPM_TOKEN",
        "https://www.npmjs.com/settings/tokens",
    )

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)

    def _redact(self, line: str, pattern: str) -> str:
        return re.sub(pattern, "npm_...REDACTED", line)


# ── SEC015  HardcodedPyPIToken ──────────────────────────────────────


class HardcodedPyPIToken(Rule):
    """Detect hardcoded PyPI API tokens."""

    id = "SEC015"
    name = "HardcodedPyPIToken"
    severity = Severity.CRITICAL
    description = (
        "A PyPI API token is hardcoded in source code. Exposed PyPI tokens "
        "can be used to publish malicious package versions, potentially "
        "compromising every project that depends on your package."
    )
    guide_url = _GUIDE_URL
    owasp_id = _OWASP_ID
    cwe_id = "CWE-798"
    confidence = "high"

    patterns: list[str] = [
        r"pypi-[0-9a-zA-Z_-]{40,}",
    ]

    fix: str = _env_fix(
        "PYPI_TOKEN",
        "https://pypi.org/manage/account/token/",
    )

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)

    def _redact(self, line: str, pattern: str) -> str:
        return re.sub(pattern, "pypi-...REDACTED", line)


# ── SEC016  HardcodedDockerHubToken ─────────────────────────────────


class HardcodedDockerHubToken(Rule):
    """Detect hardcoded Docker Hub personal access tokens."""

    id = "SEC016"
    name = "HardcodedDockerHubToken"
    severity = Severity.CRITICAL
    description = (
        "A Docker Hub token is hardcoded in source code. Exposed Docker "
        "Hub tokens can be used to push malicious images to your "
        "repositories, compromising your container supply chain."
    )
    guide_url = _GUIDE_URL
    owasp_id = _OWASP_ID
    cwe_id = "CWE-798"
    confidence = "high"

    patterns: list[str] = [
        r"dckr_pat_[0-9a-zA-Z_-]{20,}",
    ]

    fix: str = _env_fix(
        "DOCKER_HUB_TOKEN",
        "https://hub.docker.com/settings/security",
    )

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)

    def _redact(self, line: str, pattern: str) -> str:
        return re.sub(pattern, "dckr_pat_...REDACTED", line)


# ── SEC017  HardcodedVercelToken ────────────────────────────────────


class HardcodedVercelToken(Rule):
    """Detect hardcoded Vercel authentication tokens."""

    id = "SEC017"
    name = "HardcodedVercelToken"
    severity = Severity.CRITICAL
    description = (
        "A Vercel token is hardcoded in source code. Exposed Vercel tokens "
        "can be used to deploy code, modify environment variables, and "
        "access project settings on your behalf."
    )
    guide_url = _GUIDE_URL
    owasp_id = _OWASP_ID
    cwe_id = "CWE-798"
    confidence = "high"

    patterns: list[str] = [
        r"vercel_[0-9a-zA-Z_-]{20,}",
    ]

    fix: str = _env_fix(
        "VERCEL_TOKEN",
        "https://vercel.com/account/tokens",
    )

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)

    def _redact(self, line: str, pattern: str) -> str:
        return re.sub(pattern, "vercel_...REDACTED", line)


# ── SEC018  HardcodedSupabaseJWT ────────────────────────────────────


class HardcodedSupabaseJWT(Rule):
    """Detect hardcoded Supabase anon/service-role JWTs."""

    id = "SEC018"
    name = "HardcodedSupabaseJWT"
    severity = Severity.CRITICAL
    description = (
        "A Supabase JWT (anon key or service role key) is hardcoded in "
        "source code. Service role keys bypass Row Level Security and grant "
        "full database access. Even anon keys should be loaded from "
        "environment variables to enable key rotation."
    )
    guide_url = _GUIDE_URL
    owasp_id = _OWASP_ID
    cwe_id = "CWE-798"
    confidence = "high"

    patterns: list[str] = [
        r"(supabase|anon_key|service_role).*eyJ[a-zA-Z0-9_-]{20,}",
    ]

    fix: str = _env_fix(
        "SUPABASE_KEY",
        "https://supabase.com/dashboard/project/_/settings/api",
    )

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)

    def _redact(self, line: str, pattern: str) -> str:
        # Keep the keyword context but redact the JWT payload
        def _replacer(m: re.Match) -> str:
            val = m.group()
            # Find where the JWT starts
            jwt_start = val.find("eyJ")
            context = val[:jwt_start]
            return f"{context}eyJ...REDACTED"

        return re.sub(pattern, _replacer, line)
