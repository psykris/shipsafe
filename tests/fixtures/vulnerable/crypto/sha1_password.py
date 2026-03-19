# Intentionally vulnerable: SHA1 for password hashing
import hashlib
hashed = hashlib.sha1(password.encode()).hexdigest()
