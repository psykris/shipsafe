# Vulnerable: unsanitized user input passed directly to LLM
from flask import Flask, request, jsonify
from openai import OpenAI

app = Flask(__name__)
client = OpenAI()

@app.route("/chat", methods=["POST"])
def chat():
    user_input = request.json.get("message")

    # AI001: request data used directly as message content value
    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": request.json.get("message")},
    ]

    # AI001: f-string prompt with user_input variable
    prompt = f"Answer the following question: {user_input}"

    # AI001: augmented assignment with user input
    system_prompt = "You are an assistant."
    system_prompt += user_input

    response = client.chat.completions.create(
        model="gpt-4-0125-preview",
        messages=messages,
        max_tokens=256,
    )
    return jsonify({"reply": response.choices[0].message.content})
