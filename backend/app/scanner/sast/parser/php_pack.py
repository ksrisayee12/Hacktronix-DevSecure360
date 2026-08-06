# backend/app/scanner/sast/parser/php_pack.py
"""
PHP language pack for the DevSecure360 SAST engine.
Extracts: variable assignments, function definitions, function calls from PHP AST.

Note: PHP variables are prefixed with $. We strip $ for consistency in taint tracking.
"""

from .base import get_node_text, walk_tree
from .python_pack import Assignment, Call, FunctionDef, FileInfo, StringLiteral


def extract_php_info(tree, source_bytes: bytes) -> FileInfo:
    """
    Walk the PHP AST and extract assignments, calls, and function definitions.
    Main entry point for the PHP language pack.
    """
    info = FileInfo(source_bytes=source_bytes, language="php")
    _walk_node(tree.root_node, source_bytes, info)
    return info


def _walk_node(node, source_bytes: bytes, info: FileInfo):
    """Recursively walk PHP AST nodes."""

    # Assignment expressions: $var = value
    if node.type == "assignment_expression":
        _extract_assignment_expr(node, source_bytes, info)

    # Function definitions
    elif node.type in ("function_definition", "method_declaration"):
        _extract_function(node, source_bytes, info)

    # Function/method calls
    elif node.type in ("function_call_expression", "member_call_expression",
                       "expression_statement"):
        _extract_calls_from_node(node, source_bytes, info)

    # String literals
    elif node.type == "string":
        info.strings.append(StringLiteral(
            text=get_node_text(node, source_bytes),
            line=node.start_point[0] + 1
        ))

    for child in node.children:
        _walk_node(child, source_bytes, info)


def _extract_assignment_expr(node, source_bytes: bytes, info: FileInfo):
    """Extract PHP variable assignment: $var = value"""
    left_node = node.child_by_field_name("left")
    right_node = node.child_by_field_name("right")
    if not left_node or not right_node:
        # Try first and third children (some PHP grammars differ)
        children = [c for c in node.children if c.type not in ("=", "comment")]
        if len(children) >= 2:
            left_node = children[0]
            right_node = children[-1]
        else:
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
    """Extract PHP function/method definition."""
    name_node = node.child_by_field_name("name")
    params_node = node.child_by_field_name("parameters")
    body_node = node.child_by_field_name("body")

    if not name_node:
        return

    name = get_node_text(name_node, source_bytes)
    params = []
    if params_node:
        for child in walk_tree(params_node):
            if child.type == "variable_name":
                params.append(get_node_text(child, source_bytes))

    info.functions.append(FunctionDef(
        name=name,
        params=params,
        start_line=node.start_point[0] + 1,
        end_line=node.end_point[0] + 1,
        body_node=body_node
    ))


def _extract_calls_from_node(node, source_bytes: bytes, info: FileInfo):
    """Find all PHP function/method call nodes."""
    for child in walk_tree(node):
        if child.type in ("function_call_expression", "member_call_expression"):
            function_node = child.child_by_field_name("function") or \
                            child.child_by_field_name("name")
            args_node = child.child_by_field_name("arguments")

            if not function_node:
                continue

            func_text = get_node_text(function_node, source_bytes).strip()
            # Handle member calls: $obj->method(args)
            if child.type == "member_call_expression":
                obj_node = child.child_by_field_name("object")
                if obj_node:
                    obj_text = get_node_text(obj_node, source_bytes).strip()
                    func_text = f"{obj_text}->{func_text}"

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
