# backend/app/scanner/sast/taint/callgraph.py
"""
Call Graph Builder for Interprocedural Taint Analysis.

Builds a per-file call graph that maps:
  function_name -> list of call sites (callers + arguments)

Used by the 1-CFA interprocedural engine to propagate taint
across function boundaries.
"""

import re
from dataclasses import dataclass, field
from ..parser.python_pack import FileInfo, FunctionDef, Call


@dataclass
class CallSite:
    """A single call to a function with argument information."""
    caller_func: str    # name of the function containing this call
    callee_func: str    # name of the function being called
    line: int           # line number of the call
    arg_texts: list[str]  # text of each argument
    full_text: str      # full call expression text


@dataclass
class CallGraph:
    """
    A call graph for a single file.
    Maps defined function names to their call sites and callers.
    """
    # defined_functions[name] = FunctionDef
    defined_functions: dict[str, FunctionDef] = field(default_factory=dict)
    # call_sites[callee_name] = list of CallSite objects
    call_sites: dict[str, list[CallSite]] = field(default_factory=dict)
    # caller_map[func_name] = list of CallSite objects this function makes
    caller_map: dict[str, list[CallSite]] = field(default_factory=dict)

    def add_function(self, func: FunctionDef):
        self.defined_functions[func.name] = func

    def add_call_site(self, site: CallSite):
        self.call_sites.setdefault(site.callee_func, []).append(site)
        self.caller_map.setdefault(site.caller_func, []).append(site)

    def get_callers(self, func_name: str) -> list[CallSite]:
        """Return all call sites where func_name is called."""
        return self.call_sites.get(func_name, [])

    def get_callees(self, func_name: str) -> list[CallSite]:
        """Return all functions that func_name calls."""
        return self.caller_map.get(func_name, [])

    def is_defined(self, func_name: str) -> bool:
        """Check if a function is defined in this file."""
        return func_name in self.defined_functions


class CallGraphBuilder:
    """
    Builds a call graph from a parsed FileInfo.
    
    Algorithm:
      1. Register all defined functions
      2. For each call in the file, determine which function contains it
         (by comparing line numbers with function start/end)
      3. If the callee matches a defined function name → add CallSite edge
    """

    def build(self, file_info: FileInfo) -> CallGraph:
        cg = CallGraph()

        # Step 1: Register all defined functions
        for func in file_info.functions:
            cg.add_function(func)

        # Step 2: Build a line → function mapping for quick lookup
        line_to_func = self._build_line_to_func_map(file_info.functions)

        # Step 3: For each call, determine caller and check if callee is defined
        for call in file_info.calls:
            caller_name = line_to_func.get(call.line, "<module>")
            callee_name = self._extract_callee_name(call.function_name)

            # Only add edges to defined functions (skip external calls)
            if callee_name in cg.defined_functions:
                site = CallSite(
                    caller_func=caller_name,
                    callee_func=callee_name,
                    line=call.line,
                    arg_texts=call.args_text,
                    full_text=call.full_text
                )
                cg.add_call_site(site)

        return cg

    def _build_line_to_func_map(self, functions: list[FunctionDef]) -> dict[int, str]:
        """Map each line number to the innermost function containing it."""
        line_to_func = {}
        for func in functions:
            for line in range(func.start_line, func.end_line + 1):
                # Inner functions override outer (last-write wins for nested)
                line_to_func[line] = func.name
        return line_to_func

    def _extract_callee_name(self, function_name: str) -> str:
        """
        Extract the bare callee name from a potentially qualified call.
        
        Examples:
            "helper"            -> "helper"
            "self.helper"       -> "helper"  (method calls)
            "obj.method"        -> "method"
            "module.func"       -> "func"
        """
        # Take the last part after any dots
        parts = function_name.split(".")
        return parts[-1].strip()
