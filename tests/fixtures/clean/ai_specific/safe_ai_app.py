# Safe: properly designed AI application
import os
import json
from openai import OpenAI

# API key from environment — never hardcoded
client = OpenAI()  # reads OPENAI_API_KEY automatically

SYSTEM_PROMPT = "You are a helpful assistant."

MODEL = "gpt-4-0125-preview"  # pinned with version date


def safe_chat(user_message: str) -> str:
    # Validate and bound user input before passing to LLM
    if not isinstance(user_message, str):
        raise ValueError("Message must be a string")
    user_message = user_message[:1000]  # hard length cap

    # User content kept in 'user' role — sandboxed from system
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_message},
    ]

    # max_tokens set — cost bounded
    response = client.chat.completions.create(
        model=MODEL,
        messages=messages,
        max_tokens=512,
        timeout=30,
    )
    return response.choices[0].message.content


def safe_structured_output(prompt: str) -> dict:
    response = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=256,
    )
    raw = response.choices[0].message.content
    # Parse and validate — never eval/exec
    return json.loads(raw)


def get_config() -> dict:
    # System prompt never returned to users
    return {"status": "ok", "version": "1.0"}
