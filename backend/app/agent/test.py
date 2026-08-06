import google.generativeai as genai
from dotenv import load_dotenv
import os

load_dotenv()

genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))

models = genai.list_models()

for m in models:
    print(m.name, "→ supports generateContent:", "generateContent" in m.supported_generation_methods)
