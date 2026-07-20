# DevSecure360 — Phase 1 Agent Instructions
# SAST Engine: Parser → CFG → Taint → Rules → Reporter
#
# READ THIS ENTIRE DOCUMENT BEFORE WRITING A SINGLE LINE OF CODE.
# This document is your complete specification. Follow it exactly.
# Do not improvise. Do not use external security tools. Do not use regex for AST detection.

---

## 1. WHO YOU ARE AND WHAT YOU ARE BUILDING

You are a software engineer building the SAST (Static Analysis Security Testing) engine
for DevSecure360 — a proprietary security scanning SaaS platform.

Your job in Phase 1 is to build the complete SAST engine that:
- Parses Python source code into an AST using tree-sitter
- Builds a Control Flow Graph (CFG) from the AST
- Runs taint analysis to track user input from sources to dangerous sinks
- Applies YAML-based rules per vulnerability class
- Produces structured Finding objects with full taint traces
- Returns a ScanResult object that plugs directly into main.py

When you are done, the existing `/scan/code` endpoint in `backend/app/main.py`
will call your engine and return real vulnerability findings instead of stub results.

---

## 2. THE SINGLE MOST IMPORTANT RULE

NEVER call subprocess to run bandit, semgrep, or any external binary.
NEVER use regex to detect vulnerabilities (e.g. `re.search(r"eval\(", code)`).
NEVER return raw dicts from the engine. Always return ScanResult.
NEVER redefine Finding, ScanResult, Severity, TaintStep — they live in shared/types.py only.

All detection must go through: tree-sitter AST → CFG → taint engine → rule engine → Finding.

---

## 3. PROJECT STRUCTURE CONTEXT

The project root is DevSecure360/. The backend is at backend/.
All imports use the `app.` prefix (e.g. `from app.shared.types import Finding`).

The SAST engine lives entirely inside:
    backend/app/scanner/sast/

Current folder structure (already created, just needs files):
```
    backend/app/scanner/sast/
    ├── __init__.py                     (exists, empty)
    ├── engine.py                       (CREATE THIS — public entry point)
    ├── parser/
    │   ├── __init__.py                 (exists, empty)
    │   ├── base.py                     (CREATE THIS — tree-sitter setup)
    │   └── python_pack.py              (CREATE THIS — Python AST traversal)
    ├── cfg/
    │   ├── __init__.py                 (exists, empty)
    │   ├── graph.py                    (CREATE THIS — CFG data structures)
    │   └── builder.py                  (CREATE THIS — CFG construction)
    ├── taint/
    │   ├── __init__.py                 (exists, empty)
    │   ├── engine.py                   (CREATE THIS — taint propagation)
    │   └── aliases.py                  (CREATE THIS — alias tracking)
    ├── rules/
    │   ├── __init__.py                 (exists, empty)
    │   ├── loader.py                   (CREATE THIS — YAML rule loader)
    │   └── python/
    │       ├── sqli.yaml               (CREATE THIS)
    │       ├── cmdi.yaml               (CREATE THIS)
    │       ├── eval_injection.yaml     (CREATE THIS)
    │       ├── deserialization.yaml    (CREATE THIS)
    │       └── hardcoded_secrets.yaml  (CREATE THIS)
    └── reporter/
        ├── __init__.py                 (exists, empty)
        └── formatter.py               (CREATE THIS — Finding builder)
```
---

## 4. THE SHARED CONTRACT — READ ONLY, DO NOT MODIFY

This is backend/app/shared/types.py. Import from it. Never rewrite it.

```python
from dataclasses import dataclass
from typing import Optional
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH     = "High"
    MEDIUM   = "Medium"
    LOW      = "Low"
    INFO     = "Info"

class ScanType(str, Enum):
    SAST       = "sast"
    DAST       = "dast"
    PORT       = "port"
    SECRET     = "secret"
    DEPENDENCY = "dependency"

class ScanStatus(str, Enum):
    QUEUED    = "queued"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"

@dataclass
class TaintStep:
    step: int
    line: int
    file: str
    description: str

@dataclass
class Finding:
    id: str
    rule_id: str
    vuln_class: str
    scan_type: ScanType
    file: Optional[str]
    line: Optional[int]
    url: Optional[str]
    severity: Severity
    confidence: str
    cwe: Optional[str]
    owasp: Optional[str]
    issue: str
    description: str
    evidence: Optional[str]
    taint_trace: list        # list of TaintStep
    remediation: str
    tool: str

@dataclass
class ScanResult:
    scan_id: str
    scan_type: ScanType
    status: ScanStatus
    target: str
    findings: list           # list of Finding
    score: Optional[dict]
    started_at: str
    completed_at: Optional[str]
    error: Optional[str]
```

---

## 5. HOW THE ENGINE HOOKS INTO MAIN.PY

In backend/app/main.py, find these two lines (they exist as comments):

    Line 17:  # Phase 1: from app.scanner.sast.engine import SASTEngine
    Line 53:  # Phase 1: result = SASTEngine().scan(target_path=target)

After building the engine, uncomment line 17 and replace line 53.
The stub block between "# Phase 1:" and "# END STUB" gets replaced with:
    result = SASTEngine().scan(target_path=target)

That is the ONLY change to main.py. Do not touch anything else in main.py.

---

## 6. DEPENDENCIES TO INSTALL

Run this before writing any code:

    pip install tree-sitter==0.21.3
    pip install tree-sitter-python==0.21.0
    pip install tree-sitter-javascript==0.21.3
    pip install tree-sitter-java==0.21.0
    pip install networkx
    pip install pyyaml

Verify installation:
    python3 -c "import tree_sitter; print('tree-sitter ok')"
    python3 -c "import networkx; print('networkx ok')"
    python3 -c "import yaml; print('pyyaml ok')"

---

## 7. FILE 1 — parser/base.py

Purpose: Initialize tree-sitter and provide a single parse() function
that takes source code as a string and returns the root AST node.

```python
# backend/app/scanner/sast/parser/base.py

from tree_sitter import Language, Parser
import tree_sitter_python as tspython
import tree_sitter_javascript as tsjavascript
import tree_sitter_java as tsjava

# Build language objects
PY_LANGUAGE  = Language(tspython.language())
JS_LANGUAGE  = Language(tsjavascript.language())
JAVA_LANGUAGE = Language(tsjava.language())

LANGUAGE_MAP = {
    ".py":   PY_LANGUAGE,
    ".js":   JS_LANGUAGE,
    ".ts":   JS_LANGUAGE,
    ".java": JAVA_LANGUAGE,
}

def get_parser(extension: str) -> Parser | None:
    """Return a configured Parser for the given file extension, or None if unsupported."""
    lang = LANGUAGE_MAP.get(extension.lower())
    if not lang:
        return None
    parser = Parser(lang)
    return parser

def parse_file(source_code: str, extension: str):
    """
    Parse source code string into a tree-sitter tree.
    Returns (tree, parser) or (None, None) if unsupported extension.
    """
    parser = get_parser(extension)
    if not parser:
        return None, None
    tree = parser.parse(bytes(source_code, "utf-8"))
    return tree, parser

def get_node_text(node, source_bytes: bytes) -> str:
    """Extract the exact text a node covers in the source."""
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

def walk_tree(node):
    """Generator that yields every node in the tree via depth-first traversal."""
    yield node
    for child in node.children:
        yield from walk_tree(child)
```

---

## 8. FILE 2 — parser/python_pack.py

Purpose: Walk a Python AST and extract structured information:
function definitions, variable assignments, function calls, return statements.
This is the Python-specific knowledge layer.

```python
# backend/app/scanner/sast/parser/python_pack.py

from dataclasses import dataclass, field
from typing import Optional
from .base import get_node_text, walk_tree


@dataclass
class Assignment:
    """Represents: target = value"""
    target_name: str          # variable name on left side
    value_text: str           # full text of right side
    value_node_type: str      # tree-sitter node type of right side
    line: int                 # line number (1-indexed)


@dataclass
class Call:
    """Represents a function call: func(args)"""
    full_text: str            # full call text e.g. "request.args.get('name')"
    function_name: str        # just the function part e.g. "request.args.get"
    args_text: list[str]      # list of argument texts
    line: int


@dataclass
class FunctionDef:
    """Represents a function definition"""
    name: str
    params: list[str]
    start_line: int
    end_line: int
    body_node: object         # the tree-sitter node for the body


@dataclass
class PythonFileInfo:
    """All extracted information from one Python file"""
    assignments: list[Assignment] = field(default_factory=list)
    calls: list[Call]             = field(default_factory=list)
    functions: list[FunctionDef]  = field(default_factory=list)
    source_bytes: bytes           = b""


def extract_python_info(tree, source_bytes: bytes) -> PythonFileInfo:
    """
    Walk the Python AST and extract all assignments, calls, and function definitions.
    This is the main entry point for the Python language pack.
    """
    info = PythonFileInfo(source_bytes=source_bytes)
    _walk_node(tree.root_node, source_bytes, info)
    return info


def _walk_node(node, source_bytes: bytes, info: PythonFileInfo):
    """Recursively walk nodes and extract structured data."""

    if node.type == "assignment":
        _extract_assignment(node, source_bytes, info)

    elif node.type == "function_definition":
        _extract_function(node, source_bytes, info)

    elif node.type in ("call", "expression_statement"):
        _extract_calls_from_node(node, source_bytes, info)

    # Always recurse into children
    for child in node.children:
        _walk_node(child, source_bytes, info)


def _extract_assignment(node, source_bytes: bytes, info: PythonFileInfo):
    """Extract: target = value"""
    # Assignment node has: left (target) = right (value)
    target_node = node.child_by_field_name("left")
    value_node  = node.child_by_field_name("right")
    if not target_node or not value_node:
        return

    target_text = get_node_text(target_node, source_bytes).strip()
    value_text  = get_node_text(value_node, source_bytes).strip()

    # Only track simple name assignments (not complex destructuring)
    if target_node.type in ("identifier", "attribute"):
        info.assignments.append(Assignment(
            target_name=target_text,
            value_text=value_text,
            value_node_type=value_node.type,
            line=node.start_point[0] + 1  # tree-sitter is 0-indexed
        ))


def _extract_function(node, source_bytes: bytes, info: PythonFileInfo):
    """Extract function definition metadata."""
    name_node = node.child_by_field_name("name")
    params_node = node.child_by_field_name("parameters")
    body_node = node.child_by_field_name("body")

    if not name_node:
        return

    name = get_node_text(name_node, source_bytes)
    params = []
    if params_node:
        for child in params_node.children:
            if child.type == "identifier":
                params.append(get_node_text(child, source_bytes))

    info.functions.append(FunctionDef(
        name=name,
        params=params,
        start_line=node.start_point[0] + 1,
        end_line=node.end_point[0] + 1,
        body_node=body_node
    ))


def _extract_calls_from_node(node, source_bytes: bytes, info: PythonFileInfo):
    """Find all call nodes within an expression."""
    for child in walk_tree(node):
        if child.type == "call":
            function_node = child.child_by_field_name("function")
            args_node = child.child_by_field_name("arguments")
            if not function_node:
                continue

            func_text = get_node_text(function_node, source_bytes).strip()
            args_text = []
            if args_node:
                for arg in args_node.children:
                    if arg.type not in (",", "(", ")"):
                        args_text.append(get_node_text(arg, source_bytes).strip())

            info.calls.append(Call(
                full_text=get_node_text(child, source_bytes).strip(),
                function_name=func_text,
                args_text=args_text,
                line=child.start_point[0] + 1
            ))
```

---

## 9. FILE 3 — cfg/graph.py

Purpose: Data structures for the Control Flow Graph.

```python
# backend/app/scanner/sast/cfg/graph.py

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CFGNode:
    """
    A basic block in the control flow graph.
    A basic block is a straight-line sequence of statements with no branches.
    Execution enters at the top and exits at the bottom.
    """
    id: int
    statements: list        # list of tree-sitter nodes in this block
    source_lines: list[int] # line numbers covered
    label: str = ""         # optional label for debugging ("entry", "if_true", etc.)


@dataclass
class CFGEdge:
    """A directed edge between two CFG nodes."""
    from_id: int
    to_id: int
    condition: str = ""     # "true", "false", "unconditional", "exception"


class CFGGraph:
    """
    A Control Flow Graph for a single function.
    Nodes are basic blocks. Edges are possible execution paths.
    """
    def __init__(self, function_name: str):
        self.function_name = function_name
        self.nodes: dict[int, CFGNode] = {}
        self.edges: list[CFGEdge] = []
        self._next_id = 0

    def add_node(self, statements: list, source_lines: list[int], label: str = "") -> CFGNode:
        node = CFGNode(
            id=self._next_id,
            statements=statements,
            source_lines=source_lines,
            label=label
        )
        self.nodes[self._next_id] = node
        self._next_id += 1
        return node

    def add_edge(self, from_id: int, to_id: int, condition: str = "unconditional"):
        self.edges.append(CFGEdge(from_id=from_id, to_id=to_id, condition=condition))

    def successors(self, node_id: int) -> list[int]:
        return [e.to_id for e in self.edges if e.from_id == node_id]

    def all_node_ids_in_order(self) -> list[int]:
        return sorted(self.nodes.keys())
```

---

## 10. FILE 4 — cfg/builder.py

Purpose: Build a CFG from a Python function's AST body node.
Handles: sequential statements, if/elif/else, for/while loops, try/except.

```python
# backend/app/scanner/sast/cfg/builder.py

from .graph import CFGGraph, CFGNode
from ..parser.base import get_node_text


def build_cfg(function_def, source_bytes: bytes) -> CFGGraph:
    """
    Build a Control Flow Graph for a single function.
    function_def: a FunctionDef dataclass from python_pack.py
    """
    cfg = CFGGraph(function_name=function_def.name)
    body_node = function_def.body_node

    if body_node is None:
        return cfg

    # Create entry node
    entry = cfg.add_node([], [], label="entry")

    # Process the function body
    _process_block(body_node.children, cfg, entry.id, source_bytes)

    return cfg


def _process_block(statements, cfg: CFGGraph, predecessor_id: int, source_bytes: bytes) -> list[int]:
    """
    Process a list of statements, creating CFG nodes and edges.
    Returns list of exit node IDs from this block (may be multiple due to branches).
    """
    current_block_stmts = []
    current_block_lines = []
    current_pred_id = predecessor_id
    exit_ids = []

    for stmt in statements:
        if stmt.type in ("if_statement",):
            # Flush current block
            if current_block_stmts:
                block = cfg.add_node(current_block_stmts, current_block_lines)
                cfg.add_edge(current_pred_id, block.id)
                current_pred_id = block.id
                current_block_stmts = []
                current_block_lines = []

            # Process if statement — creates branch
            exits = _process_if(stmt, cfg, current_pred_id, source_bytes)
            # Create a merge node after the if
            merge = cfg.add_node([], [], label="merge")
            for exit_id in exits:
                cfg.add_edge(exit_id, merge.id)
            current_pred_id = merge.id

        elif stmt.type in ("for_statement", "while_statement"):
            if current_block_stmts:
                block = cfg.add_node(current_block_stmts, current_block_lines)
                cfg.add_edge(current_pred_id, block.id)
                current_pred_id = block.id
                current_block_stmts = []
                current_block_lines = []

            loop_header = cfg.add_node([stmt], [stmt.start_point[0] + 1], label="loop_header")
            cfg.add_edge(current_pred_id, loop_header.id)

            # Loop body
            body = stmt.child_by_field_name("body")
            if body:
                body_exits = _process_block(body.children, cfg, loop_header.id, source_bytes)
                # Back edge
                for exit_id in body_exits:
                    cfg.add_edge(exit_id, loop_header.id, condition="loop_back")

            # Loop exit
            loop_exit = cfg.add_node([], [], label="loop_exit")
            cfg.add_edge(loop_header.id, loop_exit.id, condition="false")
            current_pred_id = loop_exit.id

        elif stmt.type in ("try_statement",):
            if current_block_stmts:
                block = cfg.add_node(current_block_stmts, current_block_lines)
                cfg.add_edge(current_pred_id, block.id)
                current_pred_id = block.id
                current_block_stmts = []
                current_block_lines = []

            try_exit = _process_try(stmt, cfg, current_pred_id, source_bytes)
            current_pred_id = try_exit

        elif stmt.type not in ("comment", "decorator"):
            # Regular statement — add to current block
            line = stmt.start_point[0] + 1
            current_block_stmts.append(stmt)
            current_block_lines.append(line)

    # Flush remaining statements
    if current_block_stmts:
        block = cfg.add_node(current_block_stmts, current_block_lines)
        cfg.add_edge(current_pred_id, block.id)
        return [block.id]

    return [current_pred_id]


def _process_if(node, cfg: CFGGraph, predecessor_id: int, source_bytes: bytes) -> list[int]:
    """Process if/elif/else and return list of exit node IDs."""
    exits = []

    # True branch
    consequence = node.child_by_field_name("consequence")
    if consequence:
        true_node = cfg.add_node([], [], label="if_true")
        cfg.add_edge(predecessor_id, true_node.id, condition="true")
        true_exits = _process_block(consequence.children, cfg, true_node.id, source_bytes)
        exits.extend(true_exits)
    else:
        exits.append(predecessor_id)

    # False / elif / else branch
    alternative = node.child_by_field_name("alternative")
    if alternative:
        if alternative.type == "elif_clause":
            elif_exits = _process_if(alternative, cfg, predecessor_id, source_bytes)
            exits.extend(elif_exits)
        elif alternative.type == "else_clause":
            else_body = alternative.child_by_field_name("body")
            false_node = cfg.add_node([], [], label="if_false")
            cfg.add_edge(predecessor_id, false_node.id, condition="false")
            if else_body:
                false_exits = _process_block(else_body.children, cfg, false_node.id, source_bytes)
                exits.extend(false_exits)
            else:
                exits.append(false_node.id)
    else:
        exits.append(predecessor_id)

    return exits


def _process_try(node, cfg: CFGGraph, predecessor_id: int, source_bytes: bytes) -> int:
    """Process try/except and return exit node ID."""
    exits = []

    for child in node.children:
        if child.type == "block":
            # Try body
            try_node = cfg.add_node([], [], label="try_body")
            cfg.add_edge(predecessor_id, try_node.id)
            try_exits = _process_block(child.children, cfg, try_node.id, source_bytes)
            exits.extend(try_exits)
        elif child.type == "except_clause":
            # Exception handler
            except_node = cfg.add_node([], [], label="except_handler")
            cfg.add_edge(predecessor_id, except_node.id, condition="exception")
            body = child.child_by_field_name("body") or child
            except_exits = _process_block(
                [c for c in child.children if c.type == "block"],
                cfg, except_node.id, source_bytes
            )
            exits.extend(except_exits if except_exits else [except_node.id])

    merge = cfg.add_node([], [], label="try_merge")
    for exit_id in exits:
        cfg.add_edge(exit_id, merge.id)
    return merge.id
```

---

## 11. FILE 5 — taint/aliases.py

Purpose: Track variable aliases so taint propagates through assignments.
Example: if `a` is tainted and we see `b = a`, then `b` is also tainted.

```python
# backend/app/scanner/sast/taint/aliases.py


class AliasTracker:
    """
    Tracks which variables are aliases of which other variables.
    Used during taint propagation to spread taint through assignments.

    Handles:
        b = a                    → b aliases a
        c = {"key": b}           → c["key"] is tainted if b is tainted
        d = c["key"]             → d is tainted if c["key"] is tainted
        e = f(a)                 → e may be tainted if a is tainted (conservative)
        query = "SELECT " + user → query is tainted if user is tainted
    """

    def __init__(self):
        self.tainted: set[str] = set()

    def mark_tainted(self, var_name: str):
        self.tainted.add(var_name)

    def is_tainted(self, var_name: str) -> bool:
        return var_name in self.tainted

    def propagate_assignment(self, target: str, value_text: str):
        """
        Given an assignment `target = value_text`, check if the right-hand
        side contains any tainted variable. If so, mark target as tainted.
        """
        if self._value_contains_taint(value_text):
            self.tainted.add(target)

    def _value_contains_taint(self, value_text: str) -> bool:
        """
        Check if a value expression contains any tainted variable name.
        This is a conservative text-based check — if any tainted variable
        name appears anywhere in the value expression, we consider it tainted.
        """
        for var in self.tainted:
            # Check for the variable name as a word boundary match
            # to avoid false matches (e.g. "username" matching "name")
            import re
            if re.search(r'\b' + re.escape(var) + r'\b', value_text):
                return True
        return False

    def get_all_tainted(self) -> set[str]:
        return set(self.tainted)
```

---

## 12. FILE 6 — taint/engine.py

Purpose: Core taint propagation engine. Seeds sources, propagates through
assignments, checks sinks, verifies no sanitizer in the path.

```python
# backend/app/scanner/sast/taint/engine.py

from dataclasses import dataclass, field
from .aliases import AliasTracker
from ..parser.python_pack import PythonFileInfo, Assignment, Call


@dataclass
class TaintFinding:
    """
    A raw taint finding before it becomes a Finding dataclass.
    Contains everything needed to build the final Finding.
    """
    rule_id: str
    vuln_class: str
    sink_call: str          # the dangerous function call text
    sink_line: int          # line where the sink is
    source_var: str         # the tainted variable name
    source_line: int        # line where the source was introduced
    taint_path: list[dict]  # list of {line, var, description} dicts tracing the flow


class TaintEngine:
    """
    Runs taint analysis on a parsed Python file.

    Algorithm:
    1. Walk all assignments and calls in the file
    2. When a SOURCE call is seen (e.g. request.args.get()), mark the assigned
       variable as TAINTED
    3. For every subsequent assignment, check if the right-hand side contains
       a tainted variable. If yes, mark the target as tainted too.
    4. When a SINK call is seen (e.g. db.execute()), check if any argument
       contains a tainted variable.
    5. If yes — and no sanitizer was applied — emit a TaintFinding.
    """

    def __init__(self, rules: dict):
        """
        rules: dict loaded from YAML rule files.
        Structure: {
            "rule_id": {
                "vuln_class": str,
                "sources": [str, ...],
                "sinks": [str, ...],
                "sanitizers": [str, ...],
                "severity": str,
                "cwe": str,
                "owasp": str,
                "message": str,
                "remediation": str
            }
        }
        """
        self.rules = rules

    def analyze(self, file_info: PythonFileInfo, file_path: str) -> list[TaintFinding]:
        """
        Run taint analysis on a parsed file.
        Returns list of TaintFinding objects (one per confirmed vulnerability).
        """
        findings = []
        tracker = AliasTracker()

        # Build a combined ordered list of assignments and calls by line number
        events = []
        for a in file_info.assignments:
            events.append(("assignment", a.line, a))
        for c in file_info.calls:
            events.append(("call", c.line, c))
        events.sort(key=lambda x: x[1])

        # Track where each tainted variable was introduced (for taint trace)
        taint_origins: dict[str, dict] = {}  # var_name → {line, description}

        for event_type, line, obj in events:

            if event_type == "assignment":
                assignment = obj

                # Check if the right-hand side is a SOURCE call
                source_rule = self._matches_source(assignment.value_text)
                if source_rule:
                    tracker.mark_tainted(assignment.target_name)
                    taint_origins[assignment.target_name] = {
                        "line": line,
                        "description": f"Source: {assignment.value_text.strip()} → {assignment.target_name} is TAINTED"
                    }

                # Propagate taint through assignment
                elif tracker._value_contains_taint(assignment.value_text):
                    tracker.propagate_assignment(assignment.target_name, assignment.value_text)
                    # Find which source variable caused this
                    causing_var = self._find_causing_var(assignment.value_text, tracker)
                    taint_origins[assignment.target_name] = {
                        "line": line,
                        "description": f"Taint propagates: {assignment.value_text.strip()[:80]} → {assignment.target_name} is TAINTED"
                    }

            elif event_type == "call":
                call = obj

                # Check if this call is a SINK
                for rule_id, rule in self.rules.items():
                    sink_match = self._matches_sink(call.function_name, rule["sinks"])
                    if not sink_match:
                        continue

                    # Check if any argument is tainted
                    tainted_arg = self._find_tainted_arg(call, tracker)
                    if not tainted_arg:
                        continue

                    # Check if a sanitizer was applied
                    if self._is_sanitized(call.full_text, tainted_arg, rule.get("sanitizers", [])):
                        continue

                    # Build taint path
                    origin = taint_origins.get(tainted_arg, {"line": line, "description": f"{tainted_arg} is TAINTED"})
                    taint_path = [
                        {"line": origin["line"], "var": tainted_arg, "description": origin["description"]},
                        {"line": line, "var": tainted_arg, "description": f"Sink: {call.full_text[:100]} called with TAINTED data → {rule['vuln_class'].upper()} CONFIRMED"}
                    ]

                    findings.append(TaintFinding(
                        rule_id=rule_id,
                        vuln_class=rule["vuln_class"],
                        sink_call=call.full_text,
                        sink_line=line,
                        source_var=tainted_arg,
                        source_line=origin["line"],
                        taint_path=taint_path
                    ))

        return findings

    def _matches_source(self, value_text: str) -> bool:
        """Check if a value expression is a known source of user input."""
        all_sources = []
        for rule in self.rules.values():
            all_sources.extend(rule.get("sources", []))

        value_lower = value_text.lower()
        for source in all_sources:
            if source.lower() in value_lower:
                return True
        return False

    def _matches_sink(self, func_name: str, sinks: list[str]) -> bool:
        """Check if a function call matches a known sink."""
        func_lower = func_name.lower()
        for sink in sinks:
            if sink.lower() in func_lower or func_lower in sink.lower():
                return True
        return False

    def _find_tainted_arg(self, call, tracker: AliasTracker) -> str | None:
        """Return the name of the first tainted argument in a call, or None."""
        import re
        all_tainted = tracker.get_all_tainted()
        # Check full call text for any tainted variable
        for var in all_tainted:
            if re.search(r'\b' + re.escape(var) + r'\b', call.full_text):
                return var
        return None

    def _find_causing_var(self, value_text: str, tracker: AliasTracker) -> str:
        """Find which tainted variable caused the current propagation."""
        import re
        for var in tracker.get_all_tainted():
            if re.search(r'\b' + re.escape(var) + r'\b', value_text):
                return var
        return ""

    def _is_sanitized(self, call_text: str, tainted_var: str, sanitizers: list[str]) -> bool:
        """
        Check if the tainted variable was passed through a sanitizer before the sink.
        Conservative: checks if sanitizer wraps the tainted var in the call text.
        """
        for san in sanitizers:
            if san.lower() in call_text.lower():
                return True
        return False
```

---

## 13. FILE 7 — rules/loader.py

Purpose: Load all YAML rule files and return a combined rules dict.

```python
# backend/app/scanner/sast/rules/loader.py

import yaml
import os


def load_rules(language: str = "python") -> dict:
    """
    Load all YAML rule files for a given language.
    Returns a dict: {rule_id: rule_dict}

    Rule files live at: scanner/sast/rules/{language}/*.yaml
    """
    rules_dir = os.path.join(os.path.dirname(__file__), language)
    rules = {}

    if not os.path.exists(rules_dir):
        return rules

    for filename in os.listdir(rules_dir):
        if not filename.endswith(".yaml") and not filename.endswith(".yml"):
            continue
        filepath = os.path.join(rules_dir, filename)
        try:
            with open(filepath, "r") as f:
                rule = yaml.safe_load(f)
            if rule and "rule_id" in rule:
                rules[rule["rule_id"]] = rule
        except Exception as e:
            print(f"[rules] Warning: failed to load {filepath}: {e}")

    return rules
```

---

## 14. FILES 8-12 — YAML Rule Files

Create all five of these files exactly as specified.

### rules/python/sqli.yaml
```yaml
rule_id: python_sqli_001
language: python
vuln_class: SQLi
severity: High
cwe: CWE-89
owasp: A03:2021
confidence: Confirmed
sources:
  - request.args.get
  - request.form.get
  - request.json
  - request.values.get
  - request.data
  - request.get_json
  - os.environ.get
  - sys.argv
  - input(
sinks:
  - .execute(
  - cursor.execute
  - connection.execute
  - db.execute
  - engine.execute
  - session.execute
  - .raw(
sanitizers:
  - "?"
  - "%s"
  - ":param"
  - int(
  - float(
issue: "SQL Injection via unsanitized user input"
message: "User-controlled input flows into a SQL query without parameterization."
remediation: "Use parameterized queries: cursor.execute('SELECT * WHERE id=?', (user_id,)) — never use string concatenation or % formatting with user input in SQL."
```

### rules/python/cmdi.yaml
```yaml
rule_id: python_cmdi_001
language: python
vuln_class: CMDi
severity: High
cwe: CWE-78
owasp: A03:2021
confidence: Confirmed
sources:
  - request.args.get
  - request.form.get
  - request.json
  - request.values.get
  - os.environ.get
  - sys.argv
  - input(
sinks:
  - subprocess.call(
  - subprocess.run(
  - subprocess.check_output(
  - subprocess.Popen(
  - os.system(
  - os.popen(
  - commands.getoutput(
  - pty.spawn(
sanitizers:
  - shlex.quote(
  - pipes.quote(
issue: "Command Injection via unsanitized user input"
message: "User-controlled input flows into a shell command. shell=True with user input is always dangerous."
remediation: "Never pass user input to shell commands. Use subprocess with a list of arguments and shell=False: subprocess.run(['ls', user_dir], shell=False). If shell is required, use shlex.quote() on all user input."
```

### rules/python/eval_injection.yaml
```yaml
rule_id: python_eval_001
language: python
vuln_class: eval
severity: Critical
cwe: CWE-95
owasp: A03:2021
confidence: Confirmed
sources:
  - request.args.get
  - request.form.get
  - request.json
  - request.values.get
  - os.environ.get
  - sys.argv
  - input(
sinks:
  - eval(
  - exec(
  - compile(
  - __import__(
sanitizers: []
issue: "Code Injection via eval() with user input"
message: "User-controlled input is passed to eval() or exec(). This allows arbitrary Python code execution."
remediation: "Never pass user input to eval() or exec(). If mathematical evaluation is needed, use ast.literal_eval() for safe literals, or a sandboxed math library."
```

### rules/python/deserialization.yaml
```yaml
rule_id: python_deser_001
language: python
vuln_class: Deserialization
severity: Critical
cwe: CWE-502
owasp: A08:2021
confidence: Confirmed
sources:
  - request.data
  - request.body
  - request.get_data
  - request.json
  - request.form.get
  - request.args.get
  - os.environ.get
  - sys.argv
  - input(
sinks:
  - pickle.loads(
  - pickle.load(
  - yaml.load(
  - marshal.loads(
  - shelve.open(
  - jsonpickle.decode(
sanitizers:
  - yaml.safe_load(
issue: "Insecure Deserialization of untrusted data"
message: "User-controlled data is deserialized using an unsafe method. pickle.loads() on untrusted data enables arbitrary code execution."
remediation: "Never deserialize untrusted data with pickle. Use JSON (json.loads) for data exchange. If YAML is needed, use yaml.safe_load() instead of yaml.load()."
```

### rules/python/hardcoded_secrets.yaml
```yaml
rule_id: python_secret_001
language: python
vuln_class: Hardcoded Secret
severity: High
cwe: CWE-798
owasp: A07:2021
confidence: Confirmed
sources: []
sinks: []
sanitizers: []
# This rule uses pattern matching, not taint analysis
# Handled separately in the pattern engine, not the taint engine
secret_patterns:
  variable_names:
    - api_key
    - apikey
    - api_secret
    - secret_key
    - secret
    - password
    - passwd
    - pwd
    - token
    - auth_token
    - access_token
    - private_key
    - client_secret
  min_value_length: 8
  exclude_values:
    - ""
    - "your_key_here"
    - "change_me"
    - "example"
    - "placeholder"
    - "xxx"
    - "todo"
    - "test"
issue: "Hardcoded secret or credential in source code"
message: "A secret, API key, password, or token is hardcoded in the source code. This will be exposed if the code is ever shared, committed, or decompiled."
remediation: "Store secrets in environment variables and load them with os.environ.get('SECRET_KEY'). Use a secrets manager (AWS Secrets Manager, HashiCorp Vault) for production."
```

---

## 15. FILE 13 — reporter/formatter.py

Purpose: Convert TaintFinding objects into Finding dataclass objects
with full taint traces. Also handles the hardcoded secrets pattern rule.

```python
# backend/app/scanner/sast/reporter/formatter.py

import uuid
import re
from app.shared.types import Finding, TaintStep, Severity, ScanType
from ..taint.engine import TaintFinding

SEVERITY_MAP = {
    "Critical": Severity.CRITICAL,
    "High":     Severity.HIGH,
    "Medium":   Severity.MEDIUM,
    "Low":      Severity.LOW,
    "Info":     Severity.INFO,
}


def taint_finding_to_finding(
    taint_finding: TaintFinding,
    rule: dict,
    file_path: str,
    source_bytes: bytes
) -> Finding:
    """Convert a TaintFinding into a Finding dataclass."""

    # Build taint trace
    taint_trace = []
    for i, step in enumerate(taint_finding.taint_path):
        taint_trace.append(TaintStep(
            step=i + 1,
            line=step["line"],
            file=file_path,
            description=step["description"]
        ))

    # Extract code snippet around the sink line
    evidence = _extract_snippet(source_bytes, taint_finding.sink_line)

    severity = SEVERITY_MAP.get(rule.get("severity", "Medium"), Severity.MEDIUM)

    return Finding(
        id=str(uuid.uuid4()),
        rule_id=taint_finding.rule_id,
        vuln_class=taint_finding.vuln_class,
        scan_type=ScanType.SAST,
        file=file_path,
        line=taint_finding.sink_line,
        url=None,
        severity=severity,
        confidence=rule.get("confidence", "Confirmed"),
        cwe=rule.get("cwe"),
        owasp=rule.get("owasp"),
        issue=rule.get("issue", f"{taint_finding.vuln_class} vulnerability detected"),
        description=rule.get("message", ""),
        evidence=evidence,
        taint_trace=taint_trace,
        remediation=rule.get("remediation", ""),
        tool="devsecure_sast"
    )


def secret_finding(
    file_path: str,
    line: int,
    var_name: str,
    value_snippet: str,
    rule: dict
) -> Finding:
    """Create a Finding for a hardcoded secret detected by pattern matching."""
    return Finding(
        id=str(uuid.uuid4()),
        rule_id=rule.get("rule_id", "python_secret_001"),
        vuln_class="Hardcoded Secret",
        scan_type=ScanType.SAST,
        file=file_path,
        line=line,
        url=None,
        severity=Severity.HIGH,
        confidence="Confirmed",
        cwe=rule.get("cwe", "CWE-798"),
        owasp=rule.get("owasp", "A07:2021"),
        issue=rule.get("issue", "Hardcoded secret in source code"),
        description=rule.get("message", ""),
        evidence=f"{var_name} = \"{value_snippet[:40]}...\"" if len(value_snippet) > 40 else f"{var_name} = \"{value_snippet}\"",
        taint_trace=[],
        remediation=rule.get("remediation", "Use environment variables instead of hardcoded secrets."),
        tool="devsecure_sast"
    )


def _extract_snippet(source_bytes: bytes, line_number: int, context: int = 1) -> str:
    """Extract source code lines around a given line number."""
    try:
        lines = source_bytes.decode("utf-8", errors="replace").splitlines()
        start = max(0, line_number - 1 - context)
        end = min(len(lines), line_number + context)
        snippet_lines = []
        for i in range(start, end):
            prefix = "→ " if i == line_number - 1 else "  "
            snippet_lines.append(f"{prefix}{i + 1}: {lines[i]}")
        return "\n".join(snippet_lines)
    except Exception:
        return ""
```

---

## 16. FILE 14 — engine.py (THE PUBLIC ENTRY POINT)

This is the file that main.py imports. It ties everything together.

```python
# backend/app/scanner/sast/engine.py

import os
import uuid
from datetime import datetime

from app.shared.types import ScanResult, ScanStatus, ScanType, Finding, Severity

from .parser.base import parse_file, get_node_text, walk_tree
from .parser.python_pack import extract_python_info
from .cfg.builder import build_cfg
from .taint.engine import TaintEngine
from .rules.loader import load_rules
from .reporter.formatter import taint_finding_to_finding, secret_finding

SUPPORTED_EXTENSIONS = {".py"}   # Phase 1: Python only. JS/Java/PHP added later.


class SASTEngine:
    """
    DevSecure360 Proprietary SAST Engine.

    Usage:
        engine = SASTEngine()
        result: ScanResult = engine.scan(target_path="/path/to/code")

    Returns ScanResult with Finding objects, each containing a full taint trace.
    """

    def __init__(self):
        # Load rules once at engine initialization
        self.python_rules = load_rules("python")

    def scan(self, target_path: str) -> ScanResult:
        """
        Scan a file or directory for vulnerabilities.
        Returns ScanResult — never raises, errors go into result.error.
        """
        scan_id = str(uuid.uuid4())
        started_at = datetime.utcnow().isoformat()
        all_findings: list[Finding] = []

        try:
            # Collect all files to scan
            files = self._collect_files(target_path)

            for file_path in files:
                ext = os.path.splitext(file_path)[1].lower()
                try:
                    findings = self._scan_file(file_path, ext)
                    all_findings.extend(findings)
                except Exception as e:
                    print(f"[sast] Warning: failed to scan {file_path}: {e}")
                    continue

            return ScanResult(
                scan_id=scan_id,
                scan_type=ScanType.SAST,
                status=ScanStatus.COMPLETED,
                target=target_path,
                findings=all_findings,
                score=None,  # computed by aggregator in main.py
                started_at=started_at,
                completed_at=datetime.utcnow().isoformat(),
                error=None
            )

        except Exception as e:
            return ScanResult(
                scan_id=scan_id,
                scan_type=ScanType.SAST,
                status=ScanStatus.FAILED,
                target=target_path,
                findings=[],
                score=None,
                started_at=started_at,
                completed_at=datetime.utcnow().isoformat(),
                error=str(e)
            )

    def _collect_files(self, target_path: str) -> list[str]:
        """Collect all supported files from a path (file or directory)."""
        files = []
        if os.path.isfile(target_path):
            ext = os.path.splitext(target_path)[1].lower()
            if ext in SUPPORTED_EXTENSIONS:
                files.append(target_path)
        elif os.path.isdir(target_path):
            for root, dirs, filenames in os.walk(target_path):
                # Skip hidden dirs and common non-code dirs
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in
                           ('node_modules', '__pycache__', '.git', 'venv', '.venv', 'dist', 'build')]
                for filename in filenames:
                    ext = os.path.splitext(filename)[1].lower()
                    if ext in SUPPORTED_EXTENSIONS:
                        files.append(os.path.join(root, filename))
        return files

    def _scan_file(self, file_path: str, extension: str) -> list[Finding]:
        """Scan a single file and return its findings."""
        with open(file_path, "rb") as f:
            source_bytes = f.read()

        source_code = source_bytes.decode("utf-8", errors="replace")

        if extension == ".py":
            return self._scan_python(file_path, source_code, source_bytes)

        return []

    def _scan_python(self, file_path: str, source_code: str, source_bytes: bytes) -> list[Finding]:
        """Run the full SAST pipeline on a Python file."""
        findings = []

        # Step 1: Parse
        tree, parser = parse_file(source_code, ".py")
        if tree is None:
            return []

        # Step 2: Extract structured info (assignments, calls, functions)
        file_info = extract_python_info(tree, source_bytes)

        # Step 3: Run taint analysis
        taint_engine = TaintEngine(rules=self.python_rules)
        taint_findings = taint_engine.analyze(file_info, file_path)

        # Step 4: Convert taint findings to Finding objects
        for tf in taint_findings:
            rule = self.python_rules.get(tf.rule_id, {})
            finding = taint_finding_to_finding(tf, rule, file_path, source_bytes)
            findings.append(finding)

        # Step 5: Pattern-based rules (hardcoded secrets — no taint needed)
        secret_findings = self._detect_secrets(file_path, file_info, source_bytes)
        findings.extend(secret_findings)

        return findings

    def _detect_secrets(self, file_path: str, file_info, source_bytes: bytes) -> list[Finding]:
        """
        Detect hardcoded secrets using pattern matching on assignments.
        This does not require taint analysis — just variable name + string value pattern.
        """
        findings = []
        secret_rule = self.python_rules.get("python_secret_001", {})
        if not secret_rule:
            return []

        var_name_patterns = [p.lower() for p in secret_rule.get("secret_patterns", {}).get("variable_names", [])]
        exclude_values = [v.lower() for v in secret_rule.get("secret_patterns", {}).get("exclude_values", [])]
        min_length = secret_rule.get("secret_patterns", {}).get("min_value_length", 8)

        for assignment in file_info.assignments:
            var_lower = assignment.target_name.lower().replace("-", "_")

            # Check if variable name matches a secret pattern
            is_secret_var = any(pattern in var_lower for pattern in var_name_patterns)
            if not is_secret_var:
                continue

            # Check if value is a string literal with enough length
            value = assignment.value_text.strip()
            if not (value.startswith('"') or value.startswith("'")):
                continue

            # Strip quotes to get the actual value
            actual_value = value.strip('"\'')

            if len(actual_value) < min_length:
                continue

            # Skip placeholder/example values
            if any(excl in actual_value.lower() for excl in exclude_values):
                continue

            findings.append(secret_finding(
                file_path=file_path,
                line=assignment.line,
                var_name=assignment.target_name,
                value_snippet=actual_value,
                rule=secret_rule
            ))

        return findings
```

---

## 17. WIRING INTO MAIN.PY

After all files are created, make exactly these two changes to
`backend/app/main.py`:

**Change 1:** Find this line (line ~17) and uncomment it:
```python
# Phase 1: from app.scanner.sast.engine import SASTEngine
```
Change it to:
```python
from app.scanner.sast.engine import SASTEngine
```

**Change 2:** Find the scan_code function. It contains this block:
```python
        # Phase 1: result = SASTEngine().scan(target_path=target)
        # ─────────────────────────────────────────────────────────────────────

        # STUB — remove when Phase 1 is complete
        stub_result = ScanResult(
            ...
        )
        result = stub_result
        # END STUB
```

Replace that entire block (from `# Phase 1:` to `# END STUB`) with:
```python
        result = SASTEngine().scan(target_path=target)
```

Do NOT touch anything else in main.py.

---

## 18. VALIDATION — YOU MUST PASS ALL OF THESE

After building the engine, run this validation script.
All checks must pass before Phase 1 is considered complete.

```python
# Save as: backend/validate_phase1.py
# Run as:  python validate_phase1.py (from backend/ directory)

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from app.scanner.sast.engine import SASTEngine

engine = SASTEngine()

print("=" * 60)
print("DevSecure360 — Phase 1 SAST Validation")
print("=" * 60)

PASS = []
FAIL = []

def check(condition: bool, name: str):
    if condition:
        PASS.append(name)
        print(f"  PASS  {name}")
    else:
        FAIL.append(name)
        print(f"  FAIL  {name}")

# ── Test 1: vuln_flask.py ────────────────────────────────────────────────────
print("\n[1] Scanning vuln_codes/vuln_flask.py")
result = engine.scan("../vuln_codes/vuln_flask.py")
classes = [f.vuln_class for f in result.findings]
print(f"    Found: {classes}")

check("SQLi" in classes,             "vuln_flask.py → SQLi detected")
check("CMDi" in classes,             "vuln_flask.py → CMDi detected")
check("Hardcoded Secret" in classes, "vuln_flask.py → Hardcoded Secret detected")

for f in result.findings:
    check(len(f.taint_trace) > 0 or f.vuln_class == "Hardcoded Secret",
          f"vuln_flask.py → {f.vuln_class} has taint trace")
    check(f.line is not None,        f"vuln_flask.py → {f.vuln_class} has line number")
    check(f.cwe is not None,         f"vuln_flask.py → {f.vuln_class} has CWE")

# ── Test 2: vuln_py.py ───────────────────────────────────────────────────────
print("\n[2] Scanning vuln_codes/vuln_py.py")
result2 = engine.scan("../vuln_codes/vuln_py.py")
classes2 = [f.vuln_class for f in result2.findings]
print(f"    Found: {classes2}")

check("CMDi" in classes2,             "vuln_py.py → CMDi (shell=True) detected")
check("eval" in classes2,             "vuln_py.py → eval() injection detected")
check("Deserialization" in classes2,  "vuln_py.py → pickle.loads detected")
check("Hardcoded Secret" in classes2, "vuln_py.py → Hardcoded Secret detected")

# ── Test 3: Clean file (zero false positives) ─────────────────────────────────
print("\n[3] Scanning clean file (expecting zero findings)")
import tempfile, os
clean_code = '''
import os

def add(a, b):
    return a + b

def greet(name):
    return f"Hello, {name}"

DB_NAME = "myapp.db"

def get_user(user_id: int):
    import sqlite3
    conn = sqlite3.connect(DB_NAME)
    # Parameterized query — safe
    cur = conn.execute("SELECT * FROM users WHERE id=?", (user_id,))
    return cur.fetchone()
'''
with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
    f.write(clean_code)
    clean_path = f.name

result3 = engine.scan(clean_path)
os.unlink(clean_path)
check(len(result3.findings) == 0, f"Clean file → zero findings (got {len(result3.findings)})")

# ── Test 4: ScanResult structure ──────────────────────────────────────────────
print("\n[4] Checking ScanResult structure")
check(result.scan_id is not None,       "ScanResult has scan_id")
check(result.status == "completed",     "ScanResult status is completed")
check(result.started_at is not None,    "ScanResult has started_at")
check(result.completed_at is not None,  "ScanResult has completed_at")
check(isinstance(result.findings, list),"ScanResult.findings is a list")

# ── Test 5: Finding structure ─────────────────────────────────────────────────
print("\n[5] Checking Finding structure on first finding")
if result.findings:
    f = result.findings[0]
    check(f.id is not None,          "Finding has id")
    check(f.rule_id is not None,     "Finding has rule_id")
    check(f.vuln_class is not None,  "Finding has vuln_class")
    check(f.file is not None,        "Finding has file")
    check(f.severity is not None,    "Finding has severity")
    check(f.issue is not None,       "Finding has issue")
    check(f.remediation is not None, "Finding has remediation")
    check(f.tool == "devsecure_sast","Finding tool is devsecure_sast")

# ── Summary ───────────────────────────────────────────────────────────────────
print(f"\n{'='*60}")
print(f"Results: {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print(f"\nFAILED:")
    for f in FAIL:
        print(f"  - {f}")
    print("\nPhase 1 is NOT complete. Fix failures before proceeding.")
    sys.exit(1)
else:
    print("\nAll checks passed. Phase 1 is COMPLETE.")
    print("Uncomment SASTEngine in main.py and test via the frontend.")
```

---

## 19. WHAT SUCCESS LOOKS LIKE

When you run `python validate_phase1.py`, you should see:

```
============================================================
DevSecure360 — Phase 1 SAST Validation
============================================================

[1] Scanning vuln_codes/vuln_flask.py
    Found: ['SQLi', 'CMDi', 'Hardcoded Secret']
  PASS  vuln_flask.py → SQLi detected
  PASS  vuln_flask.py → CMDi detected
  PASS  vuln_flask.py → Hardcoded Secret detected
  PASS  vuln_flask.py → SQLi has taint trace
  PASS  vuln_flask.py → CMDi has taint trace
  ...

[2] Scanning vuln_codes/vuln_py.py
    Found: ['CMDi', 'eval', 'Deserialization', 'Hardcoded Secret']
  PASS  vuln_py.py → CMDi (shell=True) detected
  PASS  vuln_py.py → eval() injection detected
  PASS  vuln_py.py → pickle.loads detected
  PASS  vuln_py.py → Hardcoded Secret detected

[3] Scanning clean file (expecting zero findings)
  PASS  Clean file → zero findings (got 0)

[4] Checking ScanResult structure
  PASS  ScanResult has scan_id
  ...

[5] Checking Finding structure
  PASS  Finding has id
  ...

============================================================
Results: 25 passed, 0 failed

All checks passed. Phase 1 is COMPLETE.
```

---

## 20. COMMON MISTAKES — READ BEFORE STARTING

1. DO NOT call subprocess anywhere. No `subprocess.run(["bandit", ...])`.
   That is what we are replacing.

2. DO NOT use `re.search(r"eval\(", source_code)` to detect vulnerabilities.
   All detection must go through AST nodes.

3. DO NOT return a plain dict from scan(). Always return ScanResult.

4. DO NOT modify backend/app/shared/types.py.

5. DO NOT modify backend/app/main.py except the two changes in section 17.

6. If tree-sitter gives you a `None` tree (parse failed), skip that file silently
   and continue. Never crash the engine on a single file.

7. The taint engine works at the FILE level in Phase 1 (intraprocedural).
   You do not need to track taint across multiple files or function calls yet.
   That is interprocedural taint — Phase 1 extension, not core requirement.

8. The hardcoded secrets rule uses PATTERN MATCHING (variable name + string literal),
   NOT taint analysis. It has no sources or sinks. It is handled separately in
   the `_detect_secrets()` method of engine.py.

9. All findings must have `tool = "devsecure_sast"`. Never use "bandit" or "semgrep".

10. The validation script MUST pass with zero failures before you report Phase 1 done.

---

## 21. AFTER PHASE 1 IS COMPLETE — REPORT BACK

When all validation checks pass, report:
1. List of all files created
2. Output of running validate_phase1.py (copy the full terminal output)
3. Any deviations from this spec and why

Do not proceed to any other phase. The master will assign Phase 2 separately.
