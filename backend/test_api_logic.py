import os
import tempfile
import shutil
from app.scanner.sast.engine import SASTEngine

tmpdir = tempfile.mkdtemp()
target_dir = os.path.join(tmpdir, "uploaded")
os.makedirs(target_dir, exist_ok=True)
src = os.path.abspath("../vuln codes/vuln_flask.py")
dst = os.path.join(target_dir, "vuln_flask.py")
shutil.copy(src, dst)

print(f"Scanning target: {target_dir}")
result = SASTEngine().scan(target_dir)
print(f"Status: {result.status}")
print(f"Findings: {len(result.findings)}")
for f in result.findings:
    print(f" - {f.vuln_class} : {f.rule_id} : {f.issue}")
