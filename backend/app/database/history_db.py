import os
import json
from datetime import datetime

HISTORY_FILE = os.path.join(os.path.dirname(__file__), "scan_history.json")

def save_scan_result(scan_type: str, data: dict):
    entry = {
        "type": scan_type,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "score": data.get("score", {}).get("score") if isinstance(data.get("score"), dict) else data.get("score", 0),
        "findings": data.get("findings", [])
    }

    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                history = json.load(f)
        except json.JSONDecodeError:
            history = []

    history.insert(0, entry)  # newest first
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)


def get_scan_history(limit: int = None):
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r") as f:
            history = json.load(f)
            return history[:limit] if isinstance(limit, int) and limit > 0 else history
    except json.JSONDecodeError:
        return []
