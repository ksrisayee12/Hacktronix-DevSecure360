import os
import glob
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()  # 🔥 THIS IS REQUIRED

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

if not GOOGLE_API_KEY:
    raise RuntimeError("GOOGLE_API_KEY not found in environment")

genai.configure(api_key=GOOGLE_API_KEY)
model = genai.GenerativeModel("models/gemini-flash-latest")

print("Gemini key loaded:", bool(GOOGLE_API_KEY))

def read_prompt(prompt_path):
    """Read the content of a single prompt file."""
    with open(prompt_path, "r", encoding="utf-8") as f:
        return f.read()

def call_gemini_llm(prompt):
    """Send the prompt to Gemini LLM and receive a response."""
    response = model.generate_content(prompt)
    # Response formatD may vary: often use response.text or response.candidates[0].content.parts[0].text
    return response.text if hasattr(response, "text") else response.candidates[0].content.parts[0].text

def update_code_file(file_path, patched_code):
    """Overwrite the code file with the new patched code from Gemini."""
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(patched_code)

def run_agent_on_prompts(prompts_dir):
    """Process each prompt file: send to Gemini, update the vulnerable file."""
    prompt_files = sorted(glob.glob(os.path.join(prompts_dir, "prompt_*.txt")))
    for prompt_file in prompt_files:
        print(f"Processing {prompt_file}")
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

        # Send prompt to Gemini LLM and receive patched code
        patched_code = call_gemini_llm(prompt_text)
        # Overwrite original file with suggested patch
        update_code_file(file_path, patched_code)
        print(f"Updated {file_path} with patch from Gemini.")

if __name__ == "__main__":
    prompts_dir = os.path.join(os.path.dirname(__file__), "prompts")
    run_agent_on_prompts(prompts_dir)