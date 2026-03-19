# Vulnerable: AI API keys hardcoded in SDK calls
from openai import OpenAI
import anthropic

# AI006: OpenAI client with hardcoded sk- key
client = OpenAI(api_key="sk-abcdefghijklmnopqrstuvwxyz123456")

# AI006: Anthropic client with hardcoded key
anthropic_client = anthropic.Anthropic(api_key="sk-ant-abcdef12345678901234567890")

# AI006: generic api_key assignment with sk- prefix
api_key = "sk-proj-AAABBBCCCDDDEEEFFFGGG111222333444"

# AI006: legacy openai.api_key style
import openai
openai.api_key = "sk-oldstyle0000111122223333444455556666"
