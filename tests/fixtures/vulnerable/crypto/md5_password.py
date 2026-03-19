# Intentionally vulnerable: MD5 for password hashing
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()
