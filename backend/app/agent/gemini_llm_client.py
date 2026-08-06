import os
import glob
import shutil
import time
import requests
from dotenv import load_dotenv

load_dotenv()

OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "deepseek-coder:6.7b")


def verify_ollama_server() -> None:
    """Verify that Ollama is running and the model is available."""
    print("Checking Ollama...")
    try:
        response = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException:
        raise RuntimeError("Ollama server is not running. Start it using: ollama serve")

    data = response.json()
    models = [m.get("name") for m in data.get("models", [])]
    
    has_model = False
    for m in models:
        if m == OLLAMA_MODEL or m == f"{OLLAMA_MODEL}:latest" or f"{m}:latest" == OLLAMA_MODEL:
            has_model = True
            break
            
    if not has_model:
        raise RuntimeError(f"Model '{OLLAMA_MODEL}' not found. Run: ollama pull {OLLAMA_MODEL}")
        
    print("Ollama server OK")
    print(f"Loaded Ollama model: {OLLAMA_MODEL}")


def read_prompt(prompt_path: str) -> str:
    """Read the content of a single prompt file."""
    with open(prompt_path, "r", encoding="utf-8") as f:
        return f.read()


def strip_markdown(text: str) -> str:
    """Robustly remove Markdown code fences from the LLM response."""
    lines = text.splitlines()
    
    has_fences = any(line.strip().startswith("```") for line in lines)
    if not has_fences:
        return text.strip() + "\n"
        
    code_lines = []
    in_code_block = False
    
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            if not in_code_block:
                in_code_block = True
                continue
            else:
                break
        if in_code_block:
            code_lines.append(line)
            
    if not code_lines:
        return text.strip() + "\n"
        
    return "\n".join(code_lines).strip() + "\n"


def is_valid_response(response_text: str) -> bool:
    """Validate the LLM response to ensure it's not a refusal or too short."""
    if not response_text:
        return False
        
    stripped_text = response_text.strip()
    if len(stripped_text) < 50:
        return False
        
    lower_text = stripped_text.lower()
    refusals = [
        "i can't",
        "i cannot",
        "i'm sorry",
        "as an ai",
        "this code"
    ]
    for refusal in refusals:
        if refusal in lower_text:
            return False
            
    return True


def call_ollama(prompt: str) -> str:
    """Send the prompt to Ollama LLM, measure time, and receive a response."""
    url = f"{OLLAMA_BASE_URL}/api/generate"
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "top_p": 0.9,
            "repeat_penalty": 1.1,
            "num_ctx": 8192
        }
    }
    
    print("Generating patch...")
    start_time = time.time()
    
    try:
        response = requests.post(url, json=payload, timeout=300)
    except requests.exceptions.RequestException:
        raise RuntimeError("Ollama server is not running. Start it using: ollama serve")

    if response.status_code == 404 and "model" in response.text.lower():
        raise RuntimeError(f"Model '{OLLAMA_MODEL}' not found. Run: ollama pull {OLLAMA_MODEL}")
        
    try:
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Ollama API error: {e}")

    data = response.json()
    raw_response = data.get("response", "")
    
    elapsed = time.time() - start_time
    print(f"Patch generated in {elapsed:.2f} seconds")
    
    return strip_markdown(raw_response)


def update_code_file(file_path: str, patched_code: str) -> None:
    """Overwrite the code file with the new patched code."""
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(patched_code)


def run_agent_on_prompts(prompts_dir: str) -> None:
    """Process each prompt file: send to Ollama, update the vulnerable file."""
    verify_ollama_server()
    
    prompt_files = sorted(glob.glob(os.path.join(prompts_dir, "prompt_*.txt")))
    for prompt_file in prompt_files:
        print(f"\nProcessing {os.path.basename(prompt_file)}")
        prompt_text = read_prompt(prompt_file)

        # Extract vulnerable file path from prompt text (assuming prompt includes 'File: ...' line)
        file_path = None
        for line in prompt_text.splitlines():
            if line.startswith("File:"):
                file_path = line[len("File:"):].strip()
                break

        if not file_path or not os.path.exists(file_path):
            print(f"File {file_path} not found. Skipping.")
            continue

        backup_path = f"{file_path}.bak"
        if not os.path.exists(backup_path):
            print("Creating backup...")
            shutil.copy2(file_path, backup_path)

        patched_code = call_ollama(prompt_text)
        
        print("Validating response...")
        if not is_valid_response(patched_code):
            print("Warning: LLM returned an invalid response or refusal. Skipping.")
            continue
            
        update_code_file(file_path, patched_code)
        print(f"Updated file {file_path}")


if __name__ == "__main__":
    prompts_dir = os.path.join(os.path.dirname(__file__), "prompts")
    run_agent_on_prompts(prompts_dir)