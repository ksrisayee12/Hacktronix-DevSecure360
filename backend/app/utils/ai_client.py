import os
import requests
from typing import Optional

def _get_active_model(base_url: str) -> str:
    """Detect available Ollama models dynamically."""
    requested = os.getenv("OLLAMA_MODEL")
    try:
        r = requests.get(f"{base_url}/api/tags", timeout=3)
        if r.status_code == 200:
            models_data = r.json().get("models", [])
            installed = [m.get("name") for m in models_data if m.get("name")]
            if installed:
                if requested and requested in installed:
                    return requested
                # Preferred local/cloud coding models
                for pref in ["llama3:latest", "llama3", "qwen3-coder:480b-cloud", "deepseek-coder:6.7b", "codellama"]:
                    if pref in installed:
                        return pref
                return installed[0]
    except Exception:
        pass
    return requested or "llama3:latest"

def generate_completion(prompt: str) -> Optional[str]:
    """
    Sends a prompt to the local Ollama instance and returns the generated response.
    Automatically detects installed models if the target model is not available.
    """
    provider = os.getenv("AI_PROVIDER", "ollama")
    if provider != "ollama":
        raise ValueError(f"Unsupported AI provider: {provider}")

    base_url = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")
    model = _get_active_model(base_url)
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
        if response.status_code == 404:
            # Fallback if specific model name errored out
            fallback_model = "llama3:latest"
            if model != fallback_model:
                payload["model"] = fallback_model
                response = requests.post(url, json=payload, timeout=timeout)

        response.raise_for_status()
        resp_json = response.json()
        return resp_json.get("response", "")
    except Exception as e:
        print(f"[AI Client] Error communicating with Ollama (model={model}): {e}")
        return None
