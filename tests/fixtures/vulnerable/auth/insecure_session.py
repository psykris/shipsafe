# Intentionally vulnerable: insecure cookie/session configuration

# Django settings — VULNERABLE
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False
CSRF_COOKIE_SECURE = False

# Flask equivalent
class Config:
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = False
