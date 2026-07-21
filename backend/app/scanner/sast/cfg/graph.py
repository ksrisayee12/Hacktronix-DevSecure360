# backend/app/scanner/sast/cfg/graph.py
"""
Control Flow Graph data structures for the DevSecure360 SAST engine.

A CFG represents the possible execution paths through a function:
    - Nodes = basic blocks (straight-line sequences of statements, no branches)
    - Edges = possible execution paths (if/else branches, loop back-edges, exceptions)

Used by the taint engine to walk all possible execution paths when propagating taint.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CFGNode:
    """
    A basic block in the control flow graph.
    A basic block is a straight-line sequence of statements with no branches.
    Execution enters at the top and exits at the bottom.
    """
    id: int
    statements: list        # list of tree-sitter nodes in this block
    source_lines: list[int] # line numbers covered by this block
    label: str = ""         # optional label for debugging ("entry", "if_true", "loop_header", etc.)


@dataclass
class CFGEdge:
    """A directed edge between two CFG nodes representing a possible execution path."""
    from_id: int
    to_id: int
    condition: str = ""     # "true", "false", "unconditional", "exception", "loop_back"


class CFGGraph:
    """
    A Control Flow Graph for a single function.
    Nodes are basic blocks. Edges are possible execution paths.

    Usage:
        cfg = CFGGraph("my_function")
        entry = cfg.add_node([], [], label="entry")
        block1 = cfg.add_node([stmt1, stmt2], [10, 11])
        cfg.add_edge(entry.id, block1.id)
    """
    def __init__(self, function_name: str):
        self.function_name = function_name
        self.nodes: dict[int, CFGNode] = {}
        self.edges: list[CFGEdge] = []
        self._next_id = 0

    def add_node(self, statements: list, source_lines: list[int], label: str = "") -> CFGNode:
        """Add a new basic block node to the CFG. Returns the created node."""
        node = CFGNode(
            id=self._next_id,
            statements=statements,
            source_lines=source_lines,
            label=label
        )
        self.nodes[self._next_id] = node
        self._next_id += 1
        return node

    def add_edge(self, from_id: int, to_id: int, condition: str = "unconditional"):
        """Add a directed edge between two nodes."""
        self.edges.append(CFGEdge(from_id=from_id, to_id=to_id, condition=condition))

    def successors(self, node_id: int) -> list[int]:
        """Return list of node IDs reachable directly from the given node."""
        return [e.to_id for e in self.edges if e.from_id == node_id]

    def predecessors(self, node_id: int) -> list[int]:
        """Return list of node IDs that have an edge to the given node."""
        return [e.from_id for e in self.edges if e.to_id == node_id]

    def all_node_ids_in_order(self) -> list[int]:
        """Return all node IDs in ascending order (entry → exit)."""
        return sorted(self.nodes.keys())

    def all_statements(self) -> list:
        """Return all statements from all nodes in order."""
        stmts = []
        for node_id in self.all_node_ids_in_order():
            stmts.extend(self.nodes[node_id].statements)
        return stmts

    def all_source_lines(self) -> list[int]:
        """Return all source lines covered by this CFG, sorted."""
        lines = []
        for node in self.nodes.values():
            lines.extend(node.source_lines)
        return sorted(set(lines))
