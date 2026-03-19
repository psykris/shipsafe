# Intentionally vulnerable: credentials in log statements
import logging
logger = logging.getLogger(__name__)

def login(username, password):
    logger.info(f"Login attempt: user={username}, password={password}")
    logger.debug(f"API key used: {api_key}")
    print(f"Connecting with token: {auth_token}")
