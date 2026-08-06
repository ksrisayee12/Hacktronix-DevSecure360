import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from app.scanner.sast.parser.base import parse_file
from app.scanner.sast.parser.python_pack import extract_python_info
from app.scanner.sast.taint.engine import TaintEngine
from app.scanner.sast.rules.loader import load_rules

code = """
from flask import request
import sqlite3

def get_name():
    return request.args.get('name')

def search():
    name = get_name()
    conn = sqlite3.connect('db')
    cur = conn.execute("SELECT * FROM users WHERE name='" + name + "'")
    return cur.fetchone()
"""

tree, _ = parse_file(code, '.py')
src = code.encode()
info = extract_python_info(tree, src)
print('Functions:', [(f.name, f.params, f.start_line, f.end_line) for f in info.functions])
print('Assignments:')
for a in info.assignments:
    print(f'  Line {a.line}: {a.target_name!r} = {a.value_text!r}')

rules = load_rules('python')
engine = TaintEngine(rules=rules)

# Check what function_returns_tainted would be
all_sources = []
for rule in rules.values():
    all_sources.extend(rule.get('sources', []))

function_returns_tainted = {}
for func_def in info.functions:
    func_assignments = [a for a in info.assignments
                        if func_def.start_line <= a.line <= func_def.end_line]
    print(f'  {func_def.name} assignments: {[(a.target_name, a.value_text) for a in func_assignments]}')
    for a in func_assignments:
        if any(src.lower() in a.value_text.lower() for src in all_sources):
            function_returns_tainted[func_def.name] = True
            print(f'  -> {func_def.name} marked as returning tainted')
            break

print('function_returns_tainted:', function_returns_tainted)
findings = engine.analyze(info, 'test.py', source_code=code)
print('Findings:', [(f.vuln_class, f.source_var, f.sink_line) for f in findings])
