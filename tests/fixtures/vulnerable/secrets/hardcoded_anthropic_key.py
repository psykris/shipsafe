# Intentionally vulnerable: hardcoded Anthropic key
import anthropic
client = anthropic.Anthropic(api_key="sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQR")
