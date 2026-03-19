import logging

logger = logging.getLogger(__name__)


def process_user(email: str, phone: str, ssn: str) -> None:
    # PRI001: PII written to logs — email in logger call
    logger.info("Processing user with email: %s", email)

    # PRI001: phone in logging call
    logging.warning("User phone number: %s", phone)

    # PRI001: password in print
    password = "user_password"
    print(f"Debug: password={password}")

    # PRI001: SSN in logger
    logger.debug("User ssn for verification: %s", ssn)
