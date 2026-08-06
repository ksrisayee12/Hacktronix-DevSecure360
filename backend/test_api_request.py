import requests
import os
import json

url = "http://127.0.0.1:8001/scan/code"
file_path = os.path.abspath("../vuln codes/vuln_flask.py")

with open(file_path, "rb") as f:
    response = requests.post(url, files={"file": f})
    
data = response.json()
print("Status Code:", response.status_code)
print("Findings Count:", len(data.get("findings", [])))
