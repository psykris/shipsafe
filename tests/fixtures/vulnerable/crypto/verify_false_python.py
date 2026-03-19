# Intentionally vulnerable: TLS verification disabled
import requests
response = requests.get("https://api.example.com", verify=False)
