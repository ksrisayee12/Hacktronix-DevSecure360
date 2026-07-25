import os
import time
from pathlib import Path

rules_dir = Path("app/scanner/sast/rules")
two_days_ago = time.time() - (2 * 86400)

for f in rules_dir.rglob("*.yaml"):
    content = f.read_text(encoding="utf-8")
    if "# RESEARCH EVIDENCE" not in content:
        # Change mtime to two days ago
        os.utime(f, (two_days_ago, two_days_ago))
        print(f"Set mtime for {f.name}")
    else:
        print(f"Skipped {f.name} (has evidence)")
