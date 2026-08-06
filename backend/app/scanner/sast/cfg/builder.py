# backend/app/scanner/sast/cfg/builder.py
"""
Control Flow Graph builder for the DevSecure360 SAST engine.

Builds a CFG from a Python function's AST body node.
Handles: sequential statements, if/elif/else, for/while loops, try/except.

The CFG is used by the taint engine to walk all possible execution paths
when propagating taint from sources to sinks.
"""

from .graph import CFGGraph, CFGNode
from ..parser.base import get_node_text


def build_cfg(function_def, source_bytes: bytes) -> CFGGraph:
    """
    Build a Control Flow Graph for a single function.
    function_def: a FunctionDef dataclass from any language pack
    """
    cfg = CFGGraph(function_name=function_def.name)
    body_node = function_def.body_node

    if body_node is None:
        return cfg

    # Create entry node
    entry = cfg.add_node([], [], label="entry")

    # Process the function body
    _process_block(body_node.children, cfg, entry.id, source_bytes)

    return cfg


def _process_block(statements, cfg: CFGGraph, predecessor_id: int, source_bytes: bytes) -> list[int]:
    """
    Process a list of statements, creating CFG nodes and edges.
    Returns list of exit node IDs from this block (may be multiple due to branches).
    """
    current_block_stmts = []
    current_block_lines = []
    current_pred_id = predecessor_id
    exit_ids = []

    for stmt in statements:
        if stmt.type in ("if_statement", "if"):
            # Flush current block
            if current_block_stmts:
                block = cfg.add_node(current_block_stmts, current_block_lines)
                cfg.add_edge(current_pred_id, block.id)
                current_pred_id = block.id
                current_block_stmts = []
                current_block_lines = []

            # Process if statement — creates branch
            exits = _process_if(stmt, cfg, current_pred_id, source_bytes)
            # Create a merge node after the if
            merge = cfg.add_node([], [], label="merge")
            for exit_id in exits:
                cfg.add_edge(exit_id, merge.id)
            current_pred_id = merge.id

        elif stmt.type in ("for_statement", "while_statement", "for", "while",
                           "for_in_statement", "enhanced_for_statement"):
            if current_block_stmts:
                block = cfg.add_node(current_block_stmts, current_block_lines)
                cfg.add_edge(current_pred_id, block.id)
                current_pred_id = block.id
                current_block_stmts = []
                current_block_lines = []

            loop_header = cfg.add_node([stmt], [stmt.start_point[0] + 1], label="loop_header")
            cfg.add_edge(current_pred_id, loop_header.id)

            # Loop body
            body = stmt.child_by_field_name("body")
            if body:
                body_exits = _process_block(body.children, cfg, loop_header.id, source_bytes)
                # Back edge
                for exit_id in body_exits:
                    cfg.add_edge(exit_id, loop_header.id, condition="loop_back")

            # Loop exit
            loop_exit = cfg.add_node([], [], label="loop_exit")
            cfg.add_edge(loop_header.id, loop_exit.id, condition="false")
            current_pred_id = loop_exit.id

        elif stmt.type in ("try_statement", "try"):
            if current_block_stmts:
                block = cfg.add_node(current_block_stmts, current_block_lines)
                cfg.add_edge(current_pred_id, block.id)
                current_pred_id = block.id
                current_block_stmts = []
                current_block_lines = []

            try_exit = _process_try(stmt, cfg, current_pred_id, source_bytes)
            current_pred_id = try_exit

        elif stmt.type not in ("comment", "decorator", "line_comment", "block_comment"):
            # Regular statement — add to current block
            line = stmt.start_point[0] + 1
            current_block_stmts.append(stmt)
            current_block_lines.append(line)

    # Flush remaining statements
    if current_block_stmts:
        block = cfg.add_node(current_block_stmts, current_block_lines)
        cfg.add_edge(current_pred_id, block.id)
        return [block.id]

    return [current_pred_id]


def _process_if(node, cfg: CFGGraph, predecessor_id: int, source_bytes: bytes) -> list[int]:
    """Process if/elif/else and return list of exit node IDs."""
    exits = []

    # True branch
    consequence = node.child_by_field_name("consequence")
    if consequence:
        true_node = cfg.add_node([], [], label="if_true")
        cfg.add_edge(predecessor_id, true_node.id, condition="true")
        true_exits = _process_block(consequence.children, cfg, true_node.id, source_bytes)
        exits.extend(true_exits)
    else:
        exits.append(predecessor_id)

    # False / elif / else branch
    alternative = node.child_by_field_name("alternative")
    if alternative:
        if alternative.type == "elif_clause":
            elif_exits = _process_if(alternative, cfg, predecessor_id, source_bytes)
            exits.extend(elif_exits)
        elif alternative.type in ("else_clause", "else"):
            else_body = alternative.child_by_field_name("body")
            false_node = cfg.add_node([], [], label="if_false")
            cfg.add_edge(predecessor_id, false_node.id, condition="false")
            if else_body:
                false_exits = _process_block(else_body.children, cfg, false_node.id, source_bytes)
                exits.extend(false_exits)
            else:
                exits.append(false_node.id)
    else:
        exits.append(predecessor_id)

    return exits


def _process_try(node, cfg: CFGGraph, predecessor_id: int, source_bytes: bytes) -> int:
    """Process try/except/catch and return exit node ID."""
    exits = []

    for child in node.children:
        if child.type in ("block", "compound_statement", "statement_block"):
            # Try body
            try_node = cfg.add_node([], [], label="try_body")
            cfg.add_edge(predecessor_id, try_node.id)
            try_exits = _process_block(child.children, cfg, try_node.id, source_bytes)
            exits.extend(try_exits)
        elif child.type in ("except_clause", "catch_clause"):
            # Exception handler
            except_node = cfg.add_node([], [], label="except_handler")
            cfg.add_edge(predecessor_id, except_node.id, condition="exception")
            # Process the handler body
            handler_blocks = [c for c in child.children if c.type in ("block", "compound_statement", "statement_block")]
            if handler_blocks:
                except_exits = _process_block(handler_blocks[0].children, cfg, except_node.id, source_bytes)
                exits.extend(except_exits)
            else:
                exits.append(except_node.id)

    merge = cfg.add_node([], [], label="try_merge")
    for exit_id in exits:
        cfg.add_edge(exit_id, merge.id)
    return merge.id
