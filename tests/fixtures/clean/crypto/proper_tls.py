# Correct: TLS verification enabled (default)
import requests
response = requests.get("https://api.example.com")
response = requests.get("https://api.example.com", verify=True)
