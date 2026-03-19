# Vulnerable: LLM API calls without max_tokens limits
import os
from openai import OpenAI

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

def summarize(text: str) -> str:
    # AI002: .create() with model= but no max_tokens in surrounding window
    response = client.chat.completions.create(
        model="gpt-4-0125-preview",
        messages=[{"role": "user", "content": text}],
        temperature=0.5,
    )
    return response.choices[0].message.content


def stream_response(text: str):
    # AI002: streaming call, no max_tokens
    response = client.chat.completions.create(
        model="gpt-4-0125-preview",
        messages=[{"role": "user", "content": text}],
        stream=True,
    )
    for chunk in response:
        yield chunk.choices[0].delta.content
