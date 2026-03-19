# Intentionally vulnerable: hardcoded OpenAI key
import openai

api_key = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"
client = openai.OpenAI(api_key=api_key)
