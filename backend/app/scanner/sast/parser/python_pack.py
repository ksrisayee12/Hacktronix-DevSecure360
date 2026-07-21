# backend/app/scanner/sast/parser/python_pack.py
"""
Python language pack for the DevSecure360 SAST engine.
Walks a Python AST and extracts structured information:
    - Function definitions
    - Variable assignments
    - Function calls (including chained calls)
    - Return statements
"""

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
class ReturnStmt:
    """Represents a return statement"""
    value_text: str       # full text of the returned expression
    line: int
    enclosing_func: str = ""   # filled in by the function extractor


@dataclass
class StringLiteral:
    """Represents a string literal in the code"""
    text: str
    line: int


@dataclass
class FileInfo:
    """All extracted information from one Python file"""
    assignments: list[Assignment]   = field(default_factory=list)
    calls: list[Call]               = field(default_factory=list)
    functions: list[FunctionDef]    = field(default_factory=list)
    returns: list[ReturnStmt]       = field(default_factory=list)
    strings: list[StringLiteral]    = field(default_factory=list)
    source_bytes: bytes             = b""
    language: str                   = "python"


# Keep backward-compat alias
PythonFileInfo = FileInfo


def extract_python_info(tree, source_bytes: bytes) -> FileInfo:
    """
    Walk the Python AST and extract all assignments, calls, and function definitions.
    This is the main entry point for the Python language pack.
    """
    info = FileInfo(source_bytes=source_bytes, language="python")
    _walk_node(tree.root_node, source_bytes, info)
    return info


def _walk_node(node, source_bytes: bytes, info: FileInfo):
    """Recursively walk nodes and extract structured data."""

    if node.type == "assignment":
        _extract_assignment(node, source_bytes, info)

    elif node.type == "augmented_assignment":
        # Handle += style assignments (e.g. query += user_input)
        _extract_augmented_assignment(node, source_bytes, info)

    elif node.type == "function_definition":
        _extract_function(node, source_bytes, info)

    elif node.type == "return_statement":
        # Track return expressions for interprocedural taint analysis
        _extract_return(node, source_bytes, info)

    elif node.type in ("call", "expression_statement"):
        _extract_calls_from_node(node, source_bytes, info)
        
    elif node.type == "string":
        # Extract string literals for secret scanning
        info.strings.append(StringLiteral(
            text=get_node_text(node, source_bytes),
            line=node.start_point[0] + 1
        ))

    # Always recurse into children
    for child in node.children:
        _walk_node(child, source_bytes, info)


def _extract_assignment(node, source_bytes: bytes, info: FileInfo):
    """Extract: target = value"""
    target_node = node.child_by_field_name("left")
    value_node  = node.child_by_field_name("right")
    if not target_node or not value_node:
        return

    target_text = get_node_text(target_node, source_bytes).strip()
    value_text  = get_node_text(value_node, source_bytes).strip()

    # Track simple name assignments and attribute assignments
    if target_node.type in ("identifier", "attribute"):
        info.assignments.append(Assignment(
            target_name=target_text,
            value_text=value_text,
            value_node_type=value_node.type,
            line=node.start_point[0] + 1  # tree-sitter is 0-indexed
        ))


def _extract_augmented_assignment(node, source_bytes: bytes, info: FileInfo):
    """Extract: target += value (for string concatenation taint propagation)"""
    target_node = node.child_by_field_name("left")
    value_node  = node.child_by_field_name("right")
    if not target_node or not value_node:
        return

    target_text = get_node_text(target_node, source_bytes).strip()
    value_text  = get_node_text(value_node, source_bytes).strip()
    # Represent as target = target + value for taint tracking
    combined_value = f"{target_text} + {value_text}"

    if target_node.type in ("identifier", "attribute"):
        info.assignments.append(Assignment(
            target_name=target_text,
            value_text=combined_value,
            value_node_type=value_node.type,
            line=node.start_point[0] + 1
        ))


def _extract_function(node, source_bytes: bytes, info: FileInfo):
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


def _extract_calls_from_node(node, source_bytes: bytes, info: FileInfo):
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


def _extract_return(node, source_bytes: bytes, info: FileInfo):
    """
    Extract return statement value for interprocedural taint analysis.
    
    Example:
        return request.args.get("name")  →  ReturnStmt(value_text="request.args.get(\"name\")", line=6)
    
    The taint engine uses this to determine if a function's return value is tainted.
    """
    line = node.start_point[0] + 1
    # The return value is the first non-keyword child
    for child in node.children:
        if child.type not in ("return", "comment"):
            value_text = get_node_text(child, source_bytes).strip()
            if value_text:
                info.returns.append(ReturnStmt(
                    value_text=value_text,
                    line=line
                ))
            break

