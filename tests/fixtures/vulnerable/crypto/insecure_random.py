# Intentionally vulnerable: random module for security
import random
token = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=32))
session_id = random.randint(100000, 999999)
