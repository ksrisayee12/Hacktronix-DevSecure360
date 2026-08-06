import os
import json
import socket
import ssl
from typing import Optional

def generate_completion(prompt: str) -> Optional[str]:
    """
    Sends a prompt to the local Ollama instance and returns the generated response.
    Uses raw sockets to avoid the `requests` module dependency, adhering to the "no wrappers" philosophy.
    """
    provider = os.getenv("AI_PROVIDER", "ollama")
    if provider != "ollama":
        raise ValueError(f"Unsupported AI provider: {provider}")

    base_url = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")
    model = os.getenv("OLLAMA_MODEL", "deepseek-coder:6.7b")
    timeout = int(os.getenv("OLLAMA_TIMEOUT", "120"))

    # Parse URL
    if not base_url.startswith("http"):
        raise ValueError("OLLAMA_URL must start with http:// or https://")
    
    is_https = base_url.startswith("https://")
    host_port = base_url.split("://")[1]
    if ":" in host_port:
        host, port = host_port.split(":")
        port = int(port)
    else:
        host = host_port
        port = 443 if is_https else 80
        
    path = "/api/generate"

    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False
    }).encode("utf-8")

    request_headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(payload)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("utf-8")

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if is_https:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
        
        sock.sendall(request_headers + payload)

        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
            
        sock.close()
        
        # Parse HTTP response
        header_data, _, body_data = response.partition(b"\r\n\r\n")
        
        headers = header_data.decode("utf-8", errors="ignore").split("\r\n")
        status_line = headers[0]
        if " 200 " not in status_line:
            raise Exception(f"Ollama API error: {status_line}\n{body_data.decode('utf-8', errors='ignore')}")

        resp_json = json.loads(body_data.decode("utf-8"))
        return resp_json.get("response", "")
        
    except socket.timeout:
        print("[AI Client] Request to Ollama timed out.")
        return None
    except Exception as e:
        print(f"[AI Client] Error communicating with Ollama: {e}")
        return None
