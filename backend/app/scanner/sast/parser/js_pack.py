# backend/app/scanner/sast/parser/js_pack.py
"""
JavaScript/TypeScript language pack for the DevSecure360 SAST engine.
Extracts: variable declarations, function definitions, calls from JS/TS AST.
"""

from dataclasses import dataclass, field
from .base import get_node_text, walk_tree
from .python_pack import Assignment, Call, FunctionDef, FileInfo, ReturnStmt


@dataclass
class StringLiteral:
    """Represents a string literal in the code"""
    text: str
    line: int


@dataclass
class FileInfo:
    """All extracted information from one JS/TS file"""
    assignments: list[Assignment]   = field(default_factory=list)
    calls: list[Call]               = field(default_factory=list)
    functions: list[FunctionDef]    = field(default_factory=list)
    returns: list[ReturnStmt]       = field(default_factory=list)
    strings: list[StringLiteral]    = field(default_factory=list)
    source_bytes: bytes             = b""
    language: str                   = "javascript"


def extract_js_info(tree, source_bytes: bytes) -> FileInfo:
    """
    Walk the JavaScript AST and extract assignments, calls, and function definitions.
    Main entry point for the JavaScript/TypeScript language pack.
    """
    info = FileInfo(source_bytes=source_bytes, language="javascript")
    _walk_node(tree.root_node, source_bytes, info)
    return info


def _walk_node(node, source_bytes: bytes, info: FileInfo):
    """Recursively walk JS AST nodes."""

    # Variable declarations: var x = ..., let x = ..., const x = ...
    if node.type in ("variable_declaration", "lexical_declaration"):
        for child in node.children:
            if child.type == "variable_declarator":
                _extract_var_declarator(child, source_bytes, info)

    # Assignment expressions: x = ...
    elif node.type == "assignment_expression":
        _extract_assignment_expr(node, source_bytes, info)

    # Function declarations and arrow functions
    elif node.type in ("function_declaration", "function", "arrow_function",
                       "method_definition"):
        _extract_function(node, source_bytes, info)

    # Expression statements containing calls
    elif node.type in ("call_expression", "expression_statement"):
        _extract_calls_from_node(node, source_bytes, info)

    # String literals
    elif node.type in ("string", "template_string"):
        info.strings.append(StringLiteral(
            text=get_node_text(node, source_bytes),
            line=node.start_point[0] + 1
        ))

    for child in node.children:
        _walk_node(child, source_bytes, info)


def _extract_var_declarator(node, source_bytes: bytes, info: FileInfo):
    """Extract: let/const/var name = value"""
    name_node = node.child_by_field_name("name")
    value_node = node.child_by_field_name("value")
    if not name_node or not value_node:
        return

    target_text = get_node_text(name_node, source_bytes).strip()
    value_text = get_node_text(value_node, source_bytes).strip()

    info.assignments.append(Assignment(
        target_name=target_text,
        value_text=value_text,
        value_node_type=value_node.type,
        line=node.start_point[0] + 1
    ))


def _extract_assignment_expr(node, source_bytes: bytes, info: FileInfo):
    """Extract: x = value assignment expressions."""
    left_node = node.child_by_field_name("left")
    right_node = node.child_by_field_name("right")
    if not left_node or not right_node:
        return

    target_text = get_node_text(left_node, source_bytes).strip()
    value_text = get_node_text(right_node, source_bytes).strip()

    info.assignments.append(Assignment(
        target_name=target_text,
        value_text=value_text,
        value_node_type=right_node.type,
        line=node.start_point[0] + 1
    ))


def _extract_function(node, source_bytes: bytes, info: FileInfo):
    """Extract function definition metadata."""
    name_node = node.child_by_field_name("name")
    params_node = node.child_by_field_name("parameters") or node.child_by_field_name("parameter")
    body_node = node.child_by_field_name("body")

    name = get_node_text(name_node, source_bytes) if name_node else "<anonymous>"
    params = []
    if params_node:
        for child in walk_tree(params_node):
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
    """Find all call_expression nodes within an expression."""
    for child in walk_tree(node):
        if child.type == "call_expression":
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
