# backend/app/scanner/sast/parser/c_pack.py
"""
C/C++ language pack for the DevSecure360 SAST engine.
Extracts: variable declarations, function definitions, function calls from C/C++ AST.

Key vulnerability classes for C/C++:
    - Buffer overflow (strcpy, gets, sprintf without bounds)
    - Command injection (system(), popen())
    - Format string vulnerabilities (printf with user input)
    - Use-after-free patterns
    - Hardcoded secrets/credentials
"""

from .base import get_node_text, walk_tree
from .python_pack import Assignment, Call, FunctionDef, FileInfo, StringLiteral


def extract_c_info(tree, source_bytes: bytes, language: str = "c") -> FileInfo:
    """
    Walk the C/C++ AST and extract assignments, calls, and function definitions.
    Main entry point for the C/C++ language pack.
    """
    info = FileInfo(source_bytes=source_bytes, language=language)
    _walk_node(tree.root_node, source_bytes, info)
    return info


def _walk_node(node, source_bytes: bytes, info: FileInfo):
    """Recursively walk C/C++ AST nodes."""

    # Variable declarations with initializers: int x = value;
    if node.type == "declaration":
        _extract_declaration(node, source_bytes, info)

    # Assignment expressions: x = value
    elif node.type == "assignment_expression":
        _extract_assignment_expr(node, source_bytes, info)

    # Function definitions
    elif node.type == "function_definition":
        _extract_function(node, source_bytes, info)

    # Call expressions
    elif node.type in ("call_expression", "expression_statement"):
        _extract_calls_from_node(node, source_bytes, info)

    # String literals
    elif node.type == "string_literal":
        info.strings.append(StringLiteral(
            text=get_node_text(node, source_bytes),
            line=node.start_point[0] + 1
        ))

    for child in node.children:
        _walk_node(child, source_bytes, info)


def _extract_declaration(node, source_bytes: bytes, info: FileInfo):
    """Extract C variable declarations: type name = value;"""
    # Find declarator(s) within the declaration
    for child in node.children:
        if child.type == "init_declarator":
            decl_node = child.child_by_field_name("declarator")
            value_node = child.child_by_field_name("value")

            if not decl_node or not value_node:
                continue

            target_text = get_node_text(decl_node, source_bytes).strip()
            value_text = get_node_text(value_node, source_bytes).strip()

            info.assignments.append(Assignment(
                target_name=target_text,
                value_text=value_text,
                value_node_type=value_node.type,
                line=node.start_point[0] + 1
            ))


def _extract_assignment_expr(node, source_bytes: bytes, info: FileInfo):
    """Extract C assignment expression: x = value"""
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
    """Extract C/C++ function definition."""
    declarator = node.child_by_field_name("declarator")
    body_node = node.child_by_field_name("body")

    if not declarator:
        return

    # Function name is inside the declarator
    name = ""
    params = []
    for child in walk_tree(declarator):
        if child.type == "identifier" and not name:
            name = get_node_text(child, source_bytes)
        elif child.type == "parameter_declaration":
            for sub in walk_tree(child):
                if sub.type == "identifier":
                    params.append(get_node_text(sub, source_bytes))
                    break  # Only first identifier is the param name

    if name:
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
