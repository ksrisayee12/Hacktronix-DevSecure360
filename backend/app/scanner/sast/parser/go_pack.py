# backend/app/scanner/sast/parser/go_pack.py
"""
Go language pack for the DevSecure360 SAST engine.
Extracts: variable assignments, function definitions, function calls from Go AST.
"""

from .base import get_node_text, walk_tree
from .python_pack import Assignment, Call, FunctionDef, FileInfo, StringLiteral


def extract_go_info(tree, source_bytes: bytes) -> FileInfo:
    """
    Walk the Go AST and extract assignments, calls, and function definitions.
    Main entry point for the Go language pack.
    """
    info = FileInfo(source_bytes=source_bytes, language="go")
    _walk_node(tree.root_node, source_bytes, info)
    return info


def _walk_node(node, source_bytes: bytes, info: FileInfo):
    """Recursively walk Go AST nodes."""

    # Assignment expressions: var = value OR var := value
    if node.type in ("assignment_statement", "short_var_declaration"):
        _extract_assignment(node, source_bytes, info)

    # Variable declarations (var x = y)
    elif node.type == "var_spec":
        _extract_var_spec(node, source_bytes, info)

    # Function definitions
    elif node.type in ("function_declaration", "method_declaration"):
        _extract_function(node, source_bytes, info)

    # Function calls
    elif node.type == "call_expression":
        _extract_call(node, source_bytes, info)

    # String literals
    elif node.type in ("interpreted_string_literal", "raw_string_literal"):
        info.strings.append(StringLiteral(
            text=get_node_text(node, source_bytes),
            line=node.start_point[0] + 1
        ))

    for child in node.children:
        _walk_node(child, source_bytes, info)


def _extract_assignment(node, source_bytes: bytes, info: FileInfo):
    """Extract Go variable assignment."""
    left_node = node.child_by_field_name("left")
    right_node = node.child_by_field_name("right")

    if not left_node or not right_node:
        return

    # In Go, left and right can be lists of expressions (e.g. x, y = 1, 2)
    # We will just map the entire left side to the right side string for simplicity,
    # or handle the most common single assignment case.
    target_text = get_node_text(left_node, source_bytes).strip()
    value_text = get_node_text(right_node, source_bytes).strip()

    info.assignments.append(Assignment(
        target_name=target_text,
        value_text=value_text,
        value_node_type=right_node.type,
        line=node.start_point[0] + 1
    ))


def _extract_var_spec(node, source_bytes: bytes, info: FileInfo):
    """Extract Go var declaration with initialization."""
    name_node = node.child_by_field_name("name")
    value_node = node.child_by_field_name("value")

    if name_node and value_node:
        target_text = get_node_text(name_node, source_bytes).strip()
        value_text = get_node_text(value_node, source_bytes).strip()

        info.assignments.append(Assignment(
            target_name=target_text,
            value_text=value_text,
            value_node_type=value_node.type,
            line=node.start_point[0] + 1
        ))


def _extract_function(node, source_bytes: bytes, info: FileInfo):
    """Extract Go function or method definition."""
    name_node = node.child_by_field_name("name")
    params_node = node.child_by_field_name("parameters")
    body_node = node.child_by_field_name("body")

    if not name_node:
        return

    name = get_node_text(name_node, source_bytes)
    
    # If it's a method declaration, prepend the receiver type to the name
    receiver_node = node.child_by_field_name("receiver")
    if receiver_node:
        receiver_text = get_node_text(receiver_node, source_bytes)
        name = f"({receiver_text}).{name}"

    params = []
    if params_node:
        for child in walk_tree(params_node):
            if child.type == "parameter_declaration":
                # Go parameters have a name and a type. Just grab the text
                params.append(get_node_text(child, source_bytes))

    info.functions.append(FunctionDef(
        name=name,
        params=params,
        start_line=node.start_point[0] + 1,
        end_line=node.end_point[0] + 1,
        body_node=body_node
    ))


def _extract_call(node, source_bytes: bytes, info: FileInfo):
    """Find a Go function call node."""
    function_node = node.child_by_field_name("function")
    args_node = node.child_by_field_name("arguments")

    if not function_node:
        return

    func_text = get_node_text(function_node, source_bytes).strip()

    args_text = []
    if args_node:
        for arg in args_node.children:
            if arg.type not in (",", "(", ")"):
                args_text.append(get_node_text(arg, source_bytes).strip())

    info.calls.append(Call(
        full_text=get_node_text(node, source_bytes).strip(),
        function_name=func_text,
        args_text=args_text,
        line=node.start_point[0] + 1
    ))
