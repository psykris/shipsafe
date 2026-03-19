# Guide 10 — Privacy and PII Protection

## What This Guide Covers

Detecting and preventing PII (Personally Identifiable Information) leakage in
AI-generated codebases: PII in logs, hardcoded SSNs, health data (PHI) exposure,
hardcoded email addresses, and unencrypted PII stored in plaintext files.

Regulations covered: GDPR (EU), CCPA (California), HIPAA (US health data),
PCI-DSS (payment card data).

---

## PRI001 — PII Written to Logs

**Risk**: Log aggregation systems (Datadog, CloudWatch, Splunk, ELK) retain data
indefinitely. PII in logs is rarely subject to the same access controls as your
database. A breach of your logging infrastructure exposes all historical PII.

```python
# Vulnerable — email, phone, and SSN written to logs
logger.info("User login: email=%s", email)         # PRI001
logging.warning("User phone: %s", phone)            # PRI001
print(f"Debug: password={password}")                # PRI001
```

**Fix**:

```python
import hashlib

def mask_email(email: str) -> str:
    """Return first 2 chars + *** + domain for logs."""
    local, domain = email.split("@", 1)
    return local[:2] + "***@" + domain

# Log only de-identified data
logger.info("User login", extra={"user_id": user.id})

# If you must reference a user, use a hash of the email (irreversible)
user_hash = hashlib.sha256(email.encode()).hexdigest()[:12]
logger.info("Login event", extra={"user_hash": user_hash})
```

Configure a log filter to strip PII fields automatically:

```python
class PIIFilter(logging.Filter):
    """Strip PII fields from all log records."""
    PII_KEYS = {"email", "phone", "ssn", "password", "credit_card"}

    def filter(self, record):
        if hasattr(record, "extra"):
            for key in self.PII_KEYS:
                record.extra.pop(key, None)
        return True

logging.getLogger().addFilter(PIIFilter())
```

**GDPR**: Article 5(1)(f) — integrity and confidentiality.
**CCPA**: Requires reasonable security for personal information.

---

## PRI002 — Hardcoded SSN

**Risk**: Social Security Numbers (SSNs) are the primary vector for US identity
theft. A single hardcoded SSN in git history can result in mandatory breach
notification and regulatory fines.

```python
# Vulnerable — real SSN hardcoded
test_ssn = "123-45-6789"    # PRI002: real SSN pattern
```

**Fix**:

```python
# In tests — use the officially invalid placeholder
TEST_SSN = "000-00-0000"   # 000-** and **-0000 are invalid by SSA rules

# In production — encrypt SSNs at rest
from cryptography.fernet import Fernet

key = Fernet.generate_key()   # store in secrets vault, not code
fernet = Fernet(key)
encrypted_ssn = fernet.encrypt(ssn.encode())
# Store encrypted_ssn; never store plaintext ssn

# Tokenization (preferred for analytics)
# Use a dedicated PII vault (AWS Macie, Vault, Skyflow, etc.)
token = pii_vault.tokenize(ssn)   # returns opaque token, not real SSN
```

**OWASP**: A02:2021 — Cryptographic Failures

---

## PRI003 — Health Data (PHI) in Logs

**Risk**: Logging Protected Health Information (diagnosis, medication, treatment)
violates HIPAA's Technical Safeguards requirement. Penalties can reach
$1.9 million per violation category per year.

```python
# Vulnerable — PHI in log statements
logger.info("Patient %s diagnosis: %s", patient_id, diagnosis)   # PRI003
logging.info("Medication: %s", medication)                         # PRI003
```

**Fix**:

```python
# Log only de-identified record identifiers
logger.info("Record updated", extra={"record_id": record_id})

# If you need to log for audit trail, use a HIPAA-compliant audit log:
# - Separate log stream with encryption at rest
# - Access limited to HIPAA-covered workforce members
# - Retention policy per HIPAA (6 years minimum)
audit_logger.info("PHI_ACCESS", extra={
    "actor_id": current_user.id,
    "record_id": record_id,
    "action": "read",
    "timestamp": datetime.utcnow().isoformat(),
})
```

**HIPAA**: 45 CFR §164.312(b) — Audit Controls technical safeguard.

---

## PRI004 — Hardcoded Email Address

**Risk**: Real email addresses in source code end up in git history, get scraped
by spam bots from public repos, and create maintenance burden (code change
needed to update a contact).

```python
# Vulnerable — real company email hardcoded
ADMIN_EMAIL = "admin@mycompany.com"    # PRI004
```

**Fix**:

```python
import os

# Load from environment variable
ADMIN_EMAIL = os.environ["ADMIN_EMAIL"]
SUPPORT_EMAIL = os.environ.get("SUPPORT_EMAIL", "support@example.com")

# In tests, use RFC 2606 reserved domains (safe, never real mailboxes):
# test@example.com
# user@test.invalid
# noreply@example.org
```

---

## PRI005 — Unencrypted PII Storage

**Risk**: PII written to plaintext CSV, JSON, or TXT files is unprotected if the
storage medium is compromised, misconfigured (e.g. S3 bucket set to public), or
accessed by an unauthorised employee.

```python
# Vulnerable — SSN and credit card to plaintext file
writer.writerow([name, ssn, credit_card])          # PRI005
json.dump({"credit_card": card_num}, f)            # PRI005
```

**Fix**:

```python
from cryptography.fernet import Fernet
import json

# Option 1: Encrypt before writing
key = load_key_from_vault()   # never hardcode the key
fernet = Fernet(key)

record = {"name": name, "ssn": ssn}
encrypted = fernet.encrypt(json.dumps(record).encode())
with open("records.enc", "wb") as f:
    f.write(encrypted)

# Option 2: Use an encrypted database column (PostgreSQL example)
# CREATE EXTENSION pgcrypto;
# INSERT INTO users (ssn) VALUES (pgp_sym_encrypt('123-45-6789', 'passphrase'));

# Option 3: Tokenize PII — store a token, not the raw value
# PII vault returns a token; your DB stores the token only
token = pii_vault.store(ssn)
db.save(user_id=uid, ssn_token=token)
```

**GDPR**: Article 32 — Security of processing; encryption is explicitly required.
**PCI-DSS**: Requirement 3.4 — Render PAN unreadable (applies to card numbers).

---

## Privacy by Design Checklist

- [ ] No PII in log statements — use IDs and hashes instead
- [ ] No real SSNs in source code — use `000-00-0000` in tests
- [ ] No health data (PHI) written to standard logs
- [ ] Email addresses loaded from env vars, not hardcoded
- [ ] PII files encrypted at rest with a key stored in a vault
- [ ] Database PII columns encrypted (pgcrypto, application-level)
- [ ] Data retention policy implemented (auto-delete after X days)
- [ ] GDPR deletion requests handled (right to erasure)

## Related Rules

| Rule | Regulation | What it catches |
|------|-----------|-----------------|
| PRI001 | GDPR, CCPA | PII field names (email, phone, SSN) in log calls |
| PRI002 | GDPR, CCPA | SSN pattern (`NNN-NN-NNNN`) hardcoded in source |
| PRI003 | HIPAA | PHI field names in log statements |
| PRI004 | GDPR | Real email addresses hardcoded in source |
| PRI005 | GDPR, PCI-DSS | PII written to unencrypted plaintext files |
