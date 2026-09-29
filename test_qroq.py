import os
from dotenv import load_dotenv

load_dotenv()
import httpx

url = "https://api.groq.com/openai/v1/chat/completions"
headers = {
    "Authorization": f"Bearer {os.environ['GROQ_API_KEY']}",
    "Content-Type": "application/json"
}
payload = {
    "model": "llama-3.1-8b-instant",
    "messages": [{"role": "user", "content": "Test ping. Output one word: OK"}]
}

response = httpx.post(url, json=payload, headers=headers)
print(response.json()["choices"][0]["message"]["content"])