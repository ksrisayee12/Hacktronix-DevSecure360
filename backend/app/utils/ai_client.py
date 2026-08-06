import os
import requests
from typing import Optional

def generate_completion(prompt: str) -> Optional[str]:
    """
    Sends a prompt to the local Ollama instance and returns the generated response.
    """
    provider = os.getenv("AI_PROVIDER", "ollama")
    if provider != "ollama":
        raise ValueError(f"Unsupported AI provider: {provider}")

    base_url = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")
    model = os.getenv("OLLAMA_MODEL", "deepseek-coder:6.7b")
    timeout = int(os.getenv("OLLAMA_TIMEOUT", "300"))

    url = f"{base_url}/api/generate"
    payload = {
        "model": model,
        "system": "You are a senior security engineer. Your ONLY task is to FIX the vulnerability by rewriting the source code. YOU MUST MODIFY THE CODE TO REMOVE THE VULNERABILITY. If you return the exact same code, you fail. Return ONLY the complete patched source code inside a markdown block. Do NOT explain anything.",
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2
        }
    }

    try:
        response = requests.post(url, json=payload, timeout=timeout)
        response.raise_for_status()
        resp_json = response.json()
        return resp_json.get("response", "")
    except Exception as e:
        print(f"[AI Client] Error communicating with Ollama: {e}")
        return None
