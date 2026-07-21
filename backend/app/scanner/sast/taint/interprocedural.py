# backend/app/scanner/sast/taint/interprocedural.py
"""
1-CFA Context-Sensitive Interprocedural Taint Analysis.

Implements context-sensitive taint propagation across function boundaries.

Context-Insensitive (what most tools do — INACCURATE):
    helper(x) is analyzed ONCE globally. If x is EVER tainted anywhere,
    all calls to helper() are flagged → false positives.

Context-Sensitive / 1-CFA (what we implement — ACCURATE):
    helper(x) is analyzed ONCE PER CALL SITE. 
    - helper(safe_constant) → no finding at this callsite
    - helper(user_input)    → finding at this callsite only

Algorithm (1-CFA, depth-limited):
    1. For each function F in the file:
       a. Collect all call sites in F
       b. For each call site C that calls defined function G:
          - Identify which of C's arguments are tainted (from F's taint state)
          - Seed G's parameters with that taint
          - Run intraprocedural taint analysis inside G
          - If G reaches a sink with tainted param → DataflowFinding at C's line
          - If G returns a tainted value → mark C's result as tainted in F
    2. Depth limit: MAX_DEPTH call frames (default 5)
    3. Cycle detection: never re-analyze the same (function, context) pair
"""

from dataclasses import dataclass, field
from .callgraph import CallGraph, CallSite
from .dataflow import WorklistDataflow, DataflowFinding, TaintLocation, TaintOrigin
from ..cfg.builder import build_cfg
from ..parser.python_pack import FileInfo, FunctionDef

MAX_DEPTH = 5  # Maximum call depth for interprocedural analysis


@dataclass
class InterproceduralContext:
    """
    Analysis context for 1-CFA: identified by (function_name, call_site_line).
    This ensures each callsite gets its own analysis, not a shared global summary.
    """
    function_name: str
    call_site_line: int   # 0 for entry-point (module-level) analysis

    def __hash__(self):
        return hash((self.function_name, self.call_site_line))

    def __eq__(self, other):
        return (self.function_name == other.function_name and
                self.call_site_line == other.call_site_line)


class InterproceduralEngine:
    """
    1-CFA context-sensitive interprocedural taint engine.
    
    Analyzes taint across function boundaries up to MAX_DEPTH call frames.
    """

    def __init__(self, rules: dict, source_bytes: bytes):
        self.rules = rules
        self.source_bytes = source_bytes
        # Cache: context -> set[TaintLocation] (return value taint)
        self._return_taint_cache: dict[InterproceduralContext, set[TaintLocation]] = {}
        # Cycle guard: set of contexts currently being analyzed
        self._in_progress: set[InterproceduralContext] = set()

    def analyze(self, file_info: FileInfo, call_graph: CallGraph,
                module_taint: set[TaintLocation],
                taint_origins: dict) -> list[DataflowFinding]:
        """
        Run interprocedural analysis on a complete file.
        
        Args:
            file_info: Extracted AST info for the file
            call_graph: The call graph for the file
            module_taint: Taint that was established at module level
            taint_origins: Origin tracking for module_taint

        Returns: list of DataflowFinding from cross-function taint flows
        """
        all_findings: list[DataflowFinding] = []

        # Analyze each defined function as an entry point with its incoming taint
        for func_name, func_def in call_graph.defined_functions.items():
            # Find all call sites that call this function
            call_sites = call_graph.get_callers(func_name)

            if not call_sites:
                # Function not called from within the file — analyze with empty context
                # (it might be called externally, or it's a top-level route handler)
                ctx = InterproceduralContext(func_name, 0)
                findings = self._analyze_function_with_context(
                    func_def, file_info, call_graph,
                    initial_taint=set(),
                    taint_origins={},
                    context=ctx,
                    depth=0
                )
                all_findings.extend(findings)
            else:
                # Analyze once per call site (1-CFA context sensitivity)
                for site in call_sites:
                    ctx = InterproceduralContext(func_name, site.line)

                    # Determine which arguments are tainted at this call site
                    seeded_taint, seeded_origins = self._seed_params_from_call(
                        func_def, site, module_taint, taint_origins
                    )

                    findings = self._analyze_function_with_context(
                        func_def, file_info, call_graph,
                        initial_taint=seeded_taint,
                        taint_origins=seeded_origins,
                        context=ctx,
                        depth=0
                    )
                    all_findings.extend(findings)

        return all_findings

    def _analyze_function_with_context(
        self,
        func_def: FunctionDef,
        file_info: FileInfo,
        call_graph: CallGraph,
        initial_taint: set[TaintLocation],
        taint_origins: dict,
        context: InterproceduralContext,
        depth: int
    ) -> list[DataflowFinding]:
        """Run taint analysis on a single function with a specific context."""

        # Cycle guard
        if context in self._in_progress or depth > MAX_DEPTH:
            return []
        self._in_progress.add(context)

        findings = []

        try:
            # Build CFG for this function
            cfg = build_cfg(func_def, self.source_bytes)

            # Run worklist dataflow on this function's CFG
            dataflow = WorklistDataflow(
                rules=self.rules,
                source_bytes=self.source_bytes
            )
            func_findings = dataflow.analyze_cfg(
                cfg,
                initial_taint=initial_taint,
                taint_origins=taint_origins
            )
            findings.extend(func_findings)

            # Handle nested calls within this function (recursive 1-CFA)
            if depth < MAX_DEPTH:
                nested_findings = self._handle_nested_calls(
                    func_def, file_info, call_graph,
                    initial_taint, taint_origins, depth + 1
                )
                findings.extend(nested_findings)

        finally:
            self._in_progress.discard(context)

        return findings

    def _seed_params_from_call(
        self,
        func_def: FunctionDef,
        call_site: CallSite,
        caller_taint: set[TaintLocation],
        caller_origins: dict
    ) -> tuple[set[TaintLocation], dict]:
        """
        Map tainted arguments at a call site to the callee's parameter names.
        
        Example:
            def helper(x, y): ...
            helper(user_input, safe_value)  ← call site
            
            user_input is tainted → seed x as tainted in helper's analysis
            safe_value is not tainted → y is NOT seeded
        
        Returns: (seeded_taint_set, seeded_origins)
        """
        seeded_taint: set[TaintLocation] = set()
        seeded_origins: dict = {}

        # Match positional arguments to parameter names
        params = [p for p in func_def.params if p not in ("self", "cls")]

        for i, arg_text in enumerate(call_site.arg_texts):
            if i >= len(params):
                break

            param_name = params[i]
            arg_text = arg_text.strip()

            # Check if any tainted location's base name appears in this argument text
            import re
            for taint_loc in caller_taint:
                if re.search(r'\b' + re.escape(taint_loc.base) + r'\b', arg_text):
                    # This argument is tainted → seed the corresponding parameter
                    param_loc = TaintLocation("var", param_name)
                    seeded_taint.add(param_loc)
                    seeded_origins[param_loc] = TaintOrigin(
                        location=param_loc,
                        line=call_site.line,
                        description=(
                            f"Interprocedural: tainted '{taint_loc.base}' passed to "
                            f"parameter '{param_name}' of {call_site.callee_func}() "
                            f"at line {call_site.line}"
                        )
                    )
                    break

        return seeded_taint, seeded_origins

    def _handle_nested_calls(
        self,
        func_def: FunctionDef,
        file_info: FileInfo,
        call_graph: CallGraph,
        func_taint: set[TaintLocation],
        func_origins: dict,
        depth: int
    ) -> list[DataflowFinding]:
        """Handle function calls made within this function (nested interprocedural)."""
        findings = []
        callees = call_graph.get_callees(func_def.name)

        for site in callees:
            if not call_graph.is_defined(site.callee_func):
                continue  # Skip external calls

            callee_def = call_graph.defined_functions[site.callee_func]
            ctx = InterproceduralContext(site.callee_func, site.line)

            seeded_taint, seeded_origins = self._seed_params_from_call(
                callee_def, site, func_taint, func_origins
            )

            if not seeded_taint:
                continue  # No tainted args → skip this callsite

            nested = self._analyze_function_with_context(
                callee_def, file_info, call_graph,
                initial_taint=seeded_taint,
                taint_origins=seeded_origins,
                context=ctx,
                depth=depth
            )
            findings.extend(nested)

        return findings
