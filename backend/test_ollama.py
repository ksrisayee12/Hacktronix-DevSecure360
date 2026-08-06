from app.utils.ai_client import generate_completion
from app.shared.types import Finding, ScanType, Severity

print("Testing Ollama connection...")
response = generate_completion("Say 'Ollama is working perfectly!' and nothing else.")

if response:
    print(f"SUCCESS! Ollama responded with:\n{response}")
else:
    print("FAILED. Ollama did not respond. Check if it's running on http://127.0.0.1:11434")
