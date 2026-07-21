# backend/app/scanner/sast/parser/java_pack.py
"""
Java language pack for the DevSecure360 SAST engine.
Extracts: variable declarations, method definitions, method calls from Java AST.
"""

from dataclasses import dataclass, field
from .base import get_node_text, walk_tree
from .python_pack import Assignment, Call, FunctionDef, FileInfo, StringLiteral


def extract_java_info(tree, source_bytes: bytes) -> FileInfo:
    """
    Walk the Java AST and extract assignments, calls, and method definitions.
    Main entry point for the Java language pack.
    """
    info = FileInfo(source_bytes=source_bytes, language="java")
    _walk_node(tree.root_node, source_bytes, info)
    return info


def _walk_node(node, source_bytes: bytes, info: FileInfo):
    """Recursively walk Java AST nodes."""

    # Local variable declarations: String name = value;
    if node.type == "local_variable_declaration":
        _extract_local_var(node, source_bytes, info)

    # Assignment expressions: x = ...
    elif node.type == "assignment_expression":
        _extract_assignment_expr(node, source_bytes, info)

    # Method declarations
    elif node.type == "method_declaration":
        _extract_method(node, source_bytes, info)

    # Method invocations and expression statements
    elif node.type in ("method_invocation", "expression_statement"):
        _extract_calls_from_node(node, source_bytes, info)

    # String literals
    elif node.type == "string_literal":
        info.strings.append(StringLiteral(
            text=get_node_text(node, source_bytes),
            line=node.start_point[0] + 1
        ))

    for child in node.children:
        _walk_node(child, source_bytes, info)


def _extract_local_var(node, source_bytes: bytes, info: FileInfo):
    """Extract: Type varName = value;"""
    # Java local_variable_declaration: type declarator+
    declarators = [c for c in node.children if c.type == "variable_declarator"]
    for decl in declarators:
        name_node = decl.child_by_field_name("name")
        value_node = decl.child_by_field_name("value")
        if not name_node:
            continue

        target_text = get_node_text(name_node, source_bytes).strip()
        value_text = get_node_text(value_node, source_bytes).strip() if value_node else ""

        if value_text:
            info.assignments.append(Assignment(
                target_name=target_text,
                value_text=value_text,
                value_node_type=value_node.type if value_node else "unknown",
                line=node.start_point[0] + 1
            ))


def _extract_assignment_expr(node, source_bytes: bytes, info: FileInfo):
    """Extract: x = value"""
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


def _extract_method(node, source_bytes: bytes, info: FileInfo):
    """Extract Java method definition metadata."""
    name_node = node.child_by_field_name("name")
    params_node = node.child_by_field_name("parameters")
    body_node = node.child_by_field_name("body")

    if not name_node:
        return

    name = get_node_text(name_node, source_bytes)
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
    """Find all method_invocation nodes within an expression."""
    for child in walk_tree(node):
        if child.type == "method_invocation":
            # Java method invocation: [object.]method(args)
            name_node = child.child_by_field_name("name")
            object_node = child.child_by_field_name("object")
            args_node = child.child_by_field_name("arguments")

            if not name_node:
                continue

            method_name = get_node_text(name_node, source_bytes).strip()
            if object_node:
                obj_text = get_node_text(object_node, source_bytes).strip()
                func_text = f"{obj_text}.{method_name}"
            else:
                func_text = method_name

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
