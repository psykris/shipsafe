# Correct: no sensitive data in logs
import logging
logger = logging.getLogger(__name__)

def login(username, password):
    logger.info(f"Login attempt: user={username}")
    logger.debug("Authentication request received")
