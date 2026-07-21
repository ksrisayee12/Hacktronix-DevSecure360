# backend/app/scanner/sast/parser/csharp_pack.py
"""
C# language pack for the DevSecure360 SAST engine.
Extracts: variable assignments, function definitions, function calls from C# AST.
"""

from .base import get_node_text, walk_tree
from .python_pack import Assignment, Call, FunctionDef, FileInfo, StringLiteral


def extract_csharp_info(tree, source_bytes: bytes) -> FileInfo:
    """
    Walk the C# AST and extract assignments, calls, and method definitions.
    Main entry point for the C# language pack.
    """
    info = FileInfo(source_bytes=source_bytes, language="csharp")
    _walk_node(tree.root_node, source_bytes, info)
    return info


def _walk_node(node, source_bytes: bytes, info: FileInfo):
    """Recursively walk C# AST nodes."""

    # Assignment expressions: var = value
    if node.type == "assignment_expression":
        _extract_assignment(node, source_bytes, info)

    # Variable declarations (e.g. string x = "y";)
    elif node.type == "variable_declarator":
        _extract_var_declaration(node, source_bytes, info)

    # Method definitions
    elif node.type == "method_declaration":
        _extract_method(node, source_bytes, info)

    # Method invocations
    elif node.type == "invocation_expression":
        _extract_invocation(node, source_bytes, info)
        
    # Object creation (new Class(...)) which is similar to a call
    elif node.type == "object_creation_expression":
        _extract_object_creation(node, source_bytes, info)

    # String literals
    elif node.type in ("string_literal", "verbatim_string_literal", "interpolated_string_expression"):
        info.strings.append(StringLiteral(
            text=get_node_text(node, source_bytes),
            line=node.start_point[0] + 1
        ))

    for child in node.children:
        _walk_node(child, source_bytes, info)


def _extract_assignment(node, source_bytes: bytes, info: FileInfo):
    """Extract C# variable assignment."""
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


def _extract_var_declaration(node, source_bytes: bytes, info: FileInfo):
    """Extract C# variable declarator (with optional initialization)."""
    # Some tree-sitter grammars use child_by_field_name, others just flat children: identifier = expression
    if len(node.children) >= 3 and node.children[1].type == "=":
        name_node = node.children[0]
        expr_node = node.children[2]
        
        target_text = get_node_text(name_node, source_bytes).strip()
        value_text = get_node_text(expr_node, source_bytes).strip()

        info.assignments.append(Assignment(
            target_name=target_text,
            value_text=value_text,
            value_node_type=expr_node.type,
            line=node.start_point[0] + 1
        ))


def _extract_method(node, source_bytes: bytes, info: FileInfo):
    """Extract C# method definition."""
    name_node = node.child_by_field_name("name")
    params_node = node.child_by_field_name("parameters")
    body_node = node.child_by_field_name("body")

    if not name_node:
        return

    name = get_node_text(name_node, source_bytes)
    params = []
    if params_node:
        for child in walk_tree(params_node):
            if child.type == "parameter":
                # A parameter typically has a type and a name
                name_field = child.child_by_field_name("name")
                if name_field:
                    params.append(get_node_text(name_field, source_bytes))

    info.functions.append(FunctionDef(
        name=name,
        params=params,
        start_line=node.start_point[0] + 1,
        end_line=node.end_point[0] + 1,
        body_node=body_node
    ))


def _extract_invocation(node, source_bytes: bytes, info: FileInfo):
    """Find a C# method invocation node."""
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


def _extract_object_creation(node, source_bytes: bytes, info: FileInfo):
    """Find a C# object creation node ('new Class()')."""
    type_node = node.child_by_field_name("type")
    args_node = node.child_by_field_name("arguments")

    if not type_node:
        return

    type_text = get_node_text(type_node, source_bytes).strip()
    func_text = f"new {type_text}"

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
