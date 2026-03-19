# Correct: loading secrets from environment variables
import os

api_key = os.environ.get("OPENAI_API_KEY")
aws_key = os.environ["AWS_ACCESS_KEY_ID"]
db_url = os.getenv("DATABASE_URL")
