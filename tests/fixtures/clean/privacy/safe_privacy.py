import os
import logging
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

# Safe: email from environment variable
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@example.com")
SUPPORT_EMAIL = os.environ["SUPPORT_EMAIL"]

# Safe test SSN — 000-00-0000 is an invalid SSN, safe for test fixtures
TEST_SSN = "000-00-0000"


def process_user(user_id: str) -> None:
    # Safe: logging only non-PII identifiers
    logger.info("Processing user", extra={"user_id": user_id})
    logger.debug("Task complete for user_id=%s", user_id)


def update_patient(record_id: str, status: str) -> None:
    # Safe: only logging de-identified record IDs
    logger.info("Record updated", extra={"record_id": record_id, "status": status})


def save_sensitive_data(data: dict, key: bytes) -> None:
    # Safe: encrypt before writing to disk
    fernet = Fernet(key)
    encrypted = fernet.encrypt(str(data).encode())
    with open("data.enc", "wb") as f:
        f.write(encrypted)
