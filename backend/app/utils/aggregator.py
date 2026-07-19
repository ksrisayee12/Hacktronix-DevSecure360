from datetime import datetime

WEIGHTS = {"High": 3, "Medium": 2, "Low": 1}

def compute_score(findings: list) -> dict:

    counts = {"High":0, "Medium":0, "Low":0}
    total_weight = 0
    for f in findings:
        sev = f.get("severity", "Low")
        counts[sev] = counts.get(sev,0) + 1
        total_weight += WEIGHTS.get(sev,1)

    max_possible = len(findings) * WEIGHTS["High"] if findings else 1
    score = 100 - (total_weight / max_possible) * 100
    score = max(0, min(100, int(score)))
    return {
        "score": score,
        "counts": counts,
        "calculated_at": datetime.utcnow().isoformat() + "Z"
    }
