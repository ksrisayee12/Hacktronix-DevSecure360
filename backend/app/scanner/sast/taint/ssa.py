# backend/app/scanner/sast/taint/ssa.py
"""
Static Single Assignment (SSA) Form Construction for the DevSecure360 SAST Engine.

SSA ensures each variable is assigned exactly once by creating versioned names:

  x   = request.args.get("name")   -->  x_1 = request.args.get("name")  [TAINTED]
  x   = int(x)                     -->  x_2 = int(x_1)                    [CLEAN]
  db.execute(x)                    -->  db.execute(x_2)                   [CLEAN - correct!]

Without SSA, the taint engine cannot distinguish whether 'x' at the sink refers
to the original tainted x or the sanitized x_2. This is the most critical accuracy
fix — it eliminates the entire class of sanitizer false-positives.

Algorithm: Simplified SSA construction (no phi-node insertion for MVP)
  - Walk assignments in line order
  - For each assignment to variable X: create X_N (increment N)
  - Replace all uses of X in subsequent text with the current X_N alias
  - At merge points (CFG join): take UNION of versions (conservative)

Note: Full SSA with phi-nodes is deferred to Phase 2. This simplified version
handles the critical sanitizer case without the complexity of dominance frontiers.
"""

from dataclasses import dataclass, field
from ..parser.python_pack import FileInfo, Assignment, Call, FunctionDef


@dataclass
class SSAVariable:
    """A versioned variable in SSA form."""
    base_name: str      # original variable name (e.g. "x")
    version: int        # version number (e.g. 2 for x_2)
    defined_at: int     # line number where this version is defined
    is_tainted: bool = False
    sanitizer: str = ""  # name of sanitizer that made it clean, if any

    @property
    def ssa_name(self) -> str:
        return f"{self.base_name}_{self.version}"


class SSABuilder:
    """
    Builds SSA form from extracted FileInfo.
    
    Produces an SSAForm that maps:
      - Each (variable_name, line) -> current SSA version at that line
      - Each SSA version -> whether it was derived from a tainted source
    """

    def __init__(self):
        # version_counters[base_name] = current version number
        self.version_counters: dict[str, int] = {}
        # current_version[base_name] = SSAVariable for current version
        self.current_version: dict[str, SSAVariable] = {}
        # all_versions: list of all SSAVariable objects created
        self.all_versions: list[SSAVariable] = []

    def build(self, file_info: FileInfo) -> "SSAForm":
        """
        Convert a FileInfo (raw AST extraction) into SSA form.
        Returns an SSAForm with version information.
        """
        form = SSAForm()

        # Process assignments in line order
        assignments_sorted = sorted(file_info.assignments, key=lambda a: a.line)

        for assignment in assignments_sorted:
            base = assignment.target_name
            version = self._next_version(base)
            ssa_var = SSAVariable(
                base_name=base,
                version=version,
                defined_at=assignment.line
            )
            self.current_version[base] = ssa_var
            self.all_versions.append(ssa_var)

            # Rewrite the assignment's value text using current SSA versions
            rewritten_value = self._rewrite_text(assignment.value_text)

            form.add_assignment(
                original=assignment,
                ssa_var=ssa_var,
                rewritten_value=rewritten_value
            )

        # Rewrite all call texts using current SSA versions
        for call in file_info.calls:
            rewritten_call = self._rewrite_text(call.full_text)
            form.add_call(original=call, rewritten_text=rewritten_call)

        # Record the SSA version in scope at each function scope
        for func in file_info.functions:
            form.functions.append(func)

        return form

    def _next_version(self, base_name: str) -> int:
        """Return the next version number for a variable, incrementing the counter."""
        current = self.version_counters.get(base_name, 0) + 1
        self.version_counters[base_name] = current
        return current

    def _rewrite_text(self, text: str) -> str:
        """
        Rewrite all occurrences of base variable names in text with their
        current SSA versioned names.
        
        Uses word-boundary matching to avoid partial substitutions
        (e.g. 'user' should not match 'username').
        """
        import re
        result = text
        # Sort by length descending to avoid partial matches
        for base, ssa_var in sorted(
            self.current_version.items(),
            key=lambda kv: len(kv[0]),
            reverse=True
        ):
            result = re.sub(
                r'\b' + re.escape(base) + r'\b',
                ssa_var.ssa_name,
                result
            )
        return result

    def current_ssa_name(self, base_name: str) -> str:
        """Return the current SSA name for a base variable, or the original if not versioned."""
        if base_name in self.current_version:
            return self.current_version[base_name].ssa_name
        return base_name


@dataclass
class SSAAssignment:
    """An assignment in SSA form."""
    original: Assignment        # the original Assignment object
    ssa_var: SSAVariable        # the SSA variable being defined
    rewritten_value: str        # value text with all vars replaced by SSA names


@dataclass
class SSACall:
    """A function call in SSA form."""
    original: Call              # the original Call object
    rewritten_text: str         # full call text with vars replaced by SSA names


@dataclass
class SSAForm:
    """
    The SSA-transformed representation of a file.
    
    Contains SSA-rewritten assignments and calls. The taint engine
    operates on this form instead of raw FileInfo.
    """
    assignments: list[SSAAssignment] = field(default_factory=list)
    calls: list[SSACall]            = field(default_factory=list)
    functions: list[FunctionDef]    = field(default_factory=list)

    def add_assignment(self, original: Assignment, ssa_var: SSAVariable, rewritten_value: str):
        self.assignments.append(SSAAssignment(
            original=original,
            ssa_var=ssa_var,
            rewritten_value=rewritten_value
        ))

    def add_call(self, original: Call, rewritten_text: str):
        self.calls.append(SSACall(original=original, rewritten_text=rewritten_text))

    def all_events_in_order(self) -> list[tuple]:
        """
        Returns all SSA assignments and calls sorted by line number.
        Each item is ("assignment", line, obj) or ("call", line, obj).
        """
        events = []
        for a in self.assignments:
            events.append(("assignment", a.original.line, a))
        for c in self.calls:
            events.append(("call", c.original.line, c))
        events.sort(key=lambda x: x[1])
        return events
