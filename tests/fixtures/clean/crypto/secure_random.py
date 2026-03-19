# Correct: secrets module for security-sensitive randomness
import secrets
token = secrets.token_urlsafe(32)
session_id = secrets.token_hex(16)
