# Vulnerable: model names without version pins
import os
from openai import OpenAI
import anthropic

openai_client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
anthropic_client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

def openai_call(prompt: str) -> str:
    # AI004: unpinned gpt-4 alias
    response = openai_client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=256,
    )
    return response.choices[0].message.content


def gpt35_call(prompt: str) -> str:
    # AI004: unpinned gpt-3.5-turbo alias
    response = openai_client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=256,
    )
    return response.choices[0].message.content


def anthropic_call(prompt: str) -> str:
    # AI004: unpinned claude-3-opus alias
    message = anthropic_client.messages.create(
        model="claude-3-opus",
        max_tokens=256,
        messages=[{"role": "user", "content": prompt}],
    )
    return message.content[0].text
