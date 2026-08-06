# backend/app/scanner/sast/taint/dataflow.py
"""
Worklist-based Forward Dataflow Analysis for the DevSecure360 SAST Engine.

This implements the monotone dataflow algorithm used by industry SAST tools
(Checkmarx, CodeQL, Coverity). It replaces the line-by-line event walk.

Algorithm: Forward Dataflow (Taint Propagation variant)
============================================================
For each CFG basic block N:
    IN[N]  = UNION of OUT[P] for all predecessors P of N
    OUT[N] = GEN[N] UNION (IN[N] - KILL[N])

Where:
    GEN[N]  = taint locations introduced in this block
              (variables assigned from a source, or from a tainted var)
    KILL[N] = taint locations neutralized in this block
              (variables assigned from a verified sanitizer call)

Worklist Iteration:
    1. Initialize: all OUT = empty set, all IN = empty set
    2. Worklist = {entry node}
    3. While worklist not empty:
         N = pop from worklist
         new_IN  = UNION of OUT[P] for all predecessors P
         new_OUT = transfer(N, new_IN)   # apply GEN/KILL
         if new_OUT != OUT[N]:
             OUT[N] = new_OUT
             Add all successors of N to worklist
    4. Fixedpoint reached when worklist is empty.

The lattice is (PowerSet(TaintLocations), subset-ordering).
The transfer function is monotone, so convergence is guaranteed.
"""

import re
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from ..cfg.graph import CFGGraph
from ..parser.base import get_node_text


# ── Taint Location ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class TaintLocation:
    """
    A memory location that can be tainted. Immutable so it can be in a set.
    
    Types:
        "var"    - simple variable:           TaintLocation("var", "x")
        "field"  - dict/attr field:           TaintLocation("field", "d", "key")
        "index"  - list any-index:            TaintLocation("index", "lst", "*")
        "return" - function return value:     TaintLocation("return", "func_name")
        "param"  - function parameter:        TaintLocation("param", "func", "param_name")
    """
    kind: str           # "var", "field", "index", "return", "param"
    base: str           # variable or function name
    member: str = ""    # field name, key, or param name (optional)

    def __str__(self):
        if self.member:
            return f"{self.base}[{self.member}]"
        return self.base


@dataclass
class TaintOrigin:
    """Records where a taint was introduced for trace generation."""
    location: TaintLocation
    line: int
    description: str
    rule_id: str = ""


# ── Block Transfer Function ─────────────────────────────────────────────────────

class BlockTransfer:
    """
    Computes GEN and KILL sets for a CFG basic block.
    
    GEN[block]  = new taint introduced by statements in this block
    KILL[block] = taint removed by sanitizers in this block
    """

    def __init__(self, sources: list[str], sinks: list[str],
                 sanitizers: list[str], rules: dict, rule_index=None, ssa_map=None):
        self.sources = [s.lower() for s in sources]
        self.sinks = [s.lower() for s in sinks]
        self.sanitizers = [s.lower() for s in sanitizers]
        self.rules = rules
        self.rule_index = rule_index
        self.ssa_map = ssa_map or {}

    def compute(self, node_stmts: list, source_bytes: bytes,
                in_taint: set[TaintLocation]) -> tuple[set, set, list]:
        """
        Given the statements in a block and the incoming taint set,
        compute:
          - gen_set: new TaintLocations introduced in this block
          - kill_set: TaintLocations neutralized in this block
          - sinks_hit: list of (line, taint_loc, rule_id, call_text) for sink matches

        Returns: (gen_set, kill_set, sinks_hit)
        """
        gen_set: set[TaintLocation] = set()
        kill_set: set[TaintLocation] = set()
        sinks_hit: list[dict] = []

        # Working taint = incoming taint UNION gen so far (for within-block propagation)
        working_taint = set(in_taint)

        for stmt in node_stmts:
            stmt_text = get_node_text(stmt, source_bytes).strip()
            stmt_line = stmt.start_point[0] + 1

            # --- Check for source assignments: x = source_call() ---
            if stmt.type in ("assignment", "augmented_assignment",
                              "expression_statement", "local_variable_declaration",
                              "variable_declaration", "declaration", "lexical_declaration"):
                self._process_assignment_stmt(
                    stmt, stmt_text, stmt_line, source_bytes,
                    working_taint, gen_set, kill_set
                )
                # Update working taint with gen so far
                working_taint = working_taint | gen_set - kill_set

            # --- Check for sink calls ---
            sink_hits = self._check_sinks(stmt, stmt_text, stmt_line, source_bytes, working_taint)
            sinks_hit.extend(sink_hits)

        return gen_set, kill_set, sinks_hit

    def _process_assignment_stmt(self, stmt, stmt_text: str, stmt_line: int,
                                  source_bytes: bytes, working_taint: set,
                                  gen_set: set, kill_set: set):
        """Process an assignment statement, updating gen/kill sets."""

        # Get target variable name
        target_node = stmt.child_by_field_name("left") or stmt.child_by_field_name("name")
        value_node  = stmt.child_by_field_name("right") or stmt.child_by_field_name("value")

        if not target_node:
            # Try to extract from text as fallback
            if "=" in stmt_text:
                parts = stmt_text.split("=", 1)
                target_text = parts[0].strip()
                value_text = parts[1].strip()
<<<<<<< HEAD
                if target_text.startswith("let "): target_text = target_text[4:]
                if target_text.startswith("const "): target_text = target_text[6:]
                if target_text.startswith("var "): target_text = target_text[4:]
=======
>>>>>>> hackathon/dhrohit
            else:
                return
        else:
            target_text = get_node_text(target_node, source_bytes).strip()
            value_text  = get_node_text(value_node, source_bytes).strip() if value_node else stmt_text
            
        # Fix 1: Use SSA rewritten text if available
        value_text = self.ssa_map.get(stmt_line, value_text)

        # Determine target location
        target_loc = self._text_to_location(target_text)

        # Fix 4: Augmented assignment propagation
        if getattr(stmt, "type", "") == "augmented_assignment" or "+=" in stmt_text or "-=" in stmt_text:
            if target_loc in working_taint or self._find_tainted_in_text(value_text, working_taint):
                gen_set.add(target_loc)
                base = target_text.split("[")[0].split(".")[0].strip()
                if base != target_text:
                    gen_set.add(TaintLocation("var", base))
                return

        # --- Case 1: RHS is a source call → GEN ---
        if self._text_contains_source(value_text):
            gen_set.add(target_loc)
            # Also handle subscript/field targets
            base = target_text.split("[")[0].split(".")[0].strip()
            if "." in target_text or "[" in target_text:
                gen_set.add(TaintLocation("var", base))
            return

        # --- Case 2: RHS contains sanitizer wrapping the tainted var → KILL ---
        tainted_in_rhs = self._find_tainted_in_text(value_text, working_taint)
        if tainted_in_rhs:
            if self._sanitizer_wraps_tainted(value_text, tainted_in_rhs, source_bytes):
                # The sanitizer neutralized the taint — KILL old, target is clean
                kill_set.update(tainted_in_rhs)
                # Do NOT add target_loc to gen_set
                return

        # --- Case 3: RHS contains a tainted var (non-sanitized propagation) → GEN ---
        if tainted_in_rhs:
            gen_set.add(target_loc)
            # If container assignment: d["key"] = tainted → also taint d
            base = target_text.split("[")[0].split(".")[0].strip()
            if base != target_text:
                gen_set.add(TaintLocation("var", base))

    def _check_sinks(self, stmt, stmt_text: str, stmt_line: int,
                     source_bytes: bytes, working_taint: set) -> list[dict]:
        """Check if this statement calls a sink with tainted data."""
        hits = []
        if not working_taint:
            return hits

        stmt_lower = stmt_text.lower()

        # Fix 5: Use RuleIndex if available
        if self.rule_index:
            # We don't have function_name easily here, so we extract from text
            func_name = stmt_text.split("(")[0].split(".")[-1].strip() if "(" in stmt_text else ""
            candidate_rules = self.rule_index.get_candidate_rules(stmt_text, func_name)
        else:
            candidate_rules = self.rules.items()

        for rule_id, rule in candidate_rules:
            if not rule.get("sinks"):
                continue
            # Check if any sink pattern appears in the statement
            sink_match = ""
            for sink in rule.get("sinks", []):
                if sink.lower() in stmt_lower:
                    sink_match = sink
                    break
            if not sink_match:
                continue

            # Check if any tainted location appears in the statement
            tainted_in_call = self._find_tainted_in_text(stmt_text, working_taint)
            if not tainted_in_call:
                continue

            # Verify sanitizer did NOT wrap the tainted var in this call
            if self._sanitizer_wraps_tainted(stmt_text, tainted_in_call, source_bytes):
                continue

            hits.append({
                "rule_id": rule_id,
                "vuln_class": rule["vuln_class"],
                "sink_text": stmt_text[:200],
                "sink_line": stmt_line,
                "tainted_locs": list(tainted_in_call),
            })

        return hits

    def _text_contains_source(self, text: str) -> bool:
        """Check if text contains a known source pattern."""
        text_lower = text.lower()
        for src in self.sources:
            if src in text_lower:
                return True
        return False

    def _find_tainted_in_text(self, text: str,
                               taint_set: set[TaintLocation]) -> set[TaintLocation]:
        """Return the subset of taint_set whose base names appear in text."""
        found = set()
        for loc in taint_set:
            # Word-boundary match for the base name
            if re.search(r'\b' + re.escape(loc.base) + r'\b', text):
                found.add(loc)
            # Also check SSA name if it has a member (e.g. d["key"])
            if loc.member and loc.member != "*":
                pattern = re.escape(loc.base) + r'.*' + re.escape(loc.member)
                if re.search(pattern, text):
                    found.add(loc)
        return found

    def _sanitizer_wraps_tainted(self, call_text: str,
                                  tainted_locs: set[TaintLocation],
                                  source_bytes: bytes) -> bool:
        """
        AST-aware sanitizer check:
        Returns True ONLY if a sanitizer directly wraps the tainted variable.
        
        Pattern: sanitizer(tainted_var) or sanitizer(tainted_var, ...)
        
        This prevents the false-positive where int(other_var) is in the same
        call but the tainted var is still passed unsanitized.
        """
        call_lower = call_text.lower()

        for san in self.sanitizers:
            san_lower = san.lower().rstrip("(")
            if san_lower not in call_lower:
                continue

            # For each sanitizer occurrence, check if any tainted var is
            # the direct (first-level) argument
            for loc in tainted_locs:
                # Pattern: sanitizer_name(tainted_var
                # or: sanitizer_name(tainted_var, ...
                pattern = re.escape(san_lower) + r'\s*\(\s*' + re.escape(loc.base)
                if re.search(pattern, call_lower):
                    return True

        # Parameterized query check: ? or %s placeholder with tuple arg
        # e.g. execute("SELECT * WHERE id=?", (user_var,)) → safe
        if self._is_parameterized_query(call_text, tainted_locs):
            return True

        return False

    def _is_parameterized_query(self, call_text: str,
                                  tainted_locs: set[TaintLocation]) -> bool:
        """
        Detect parameterized SQL queries which are safe even with tainted data.
        
        Safe patterns:
            cursor.execute("SELECT * WHERE id=?", (user_id,))
            cursor.execute("SELECT * WHERE id=%s", [user_id])
            session.query(User).filter_by(name=user_name)
        """
        # Check for placeholder pattern
        has_placeholder = (
            "?" in call_text or
            "%s" in call_text or
            ":param" in call_text.lower() or
            "filter_by(" in call_text.lower() or
            "filter(" in call_text.lower()
        )
        if not has_placeholder:
            return False

        # Check that tainted vars appear in a tuple/list (second arg), not in the query string
        # Simple heuristic: tainted var appears after a comma in a parenthesized list
        for loc in tainted_locs:
            # If the tainted var appears INSIDE the query string literal, it's NOT safe
            # Query string is typically before the first comma in the call
            query_part = call_text.split(",")[0] if "," in call_text else call_text
            if re.search(r'\b' + re.escape(loc.base) + r'\b', query_part):
                return False  # tainted var is in the query string itself → not safe

        return True

    def _text_to_location(self, text: str) -> TaintLocation:
        """Convert a variable text to a TaintLocation."""
        text = text.strip()
        if "[" in text and text.endswith("]"):
            base = text.split("[")[0]
            member = text[text.find("[")+1:-1].strip("'\"")
            return TaintLocation("index", base, member)
        elif "." in text and not text.startswith('"'):
            parts = text.split(".", 1)
            return TaintLocation("field", parts[0].strip(), parts[1].strip())
        else:
            return TaintLocation("var", text)


# ── Worklist Dataflow Engine ────────────────────────────────────────────────────

@dataclass
class DataflowFinding:
    """A vulnerability found by the dataflow engine."""
    rule_id: str
    vuln_class: str
    sink_text: str
    sink_line: int
    tainted_locs: list[TaintLocation]
    taint_origins: dict   # loc -> TaintOrigin


class WorklistDataflow:
    """
    Forward dataflow analysis with worklist algorithm.
    
    This is the engine that replaces the line-by-line taint walk.
    It drives taint through the CFG respecting actual control flow.
    """

    def __init__(self, rules: dict, source_bytes: bytes, rule_index=None, ssa_map=None):
        self.rules = rules
        self.source_bytes = source_bytes
        self.rule_index = rule_index
        self.ssa_map = ssa_map or {}

        # Collect all sources/sinks/sanitizers across all rules
        all_sources = []
        all_sinks = []
        all_sanitizers = []
        for rule in rules.values():
            all_sources.extend(rule.get("sources", []))
            all_sinks.extend(rule.get("sinks", []))
            all_sanitizers.extend(rule.get("sanitizers", []))

        self.transfer = BlockTransfer(
            sources=list(set(all_sources)),
            sinks=list(set(all_sinks)),
            sanitizers=list(set(all_sanitizers)),
            rules=rules,
            rule_index=self.rule_index,
            ssa_map=self.ssa_map
        )

    def analyze_cfg(self, cfg: CFGGraph,
                    initial_taint: set[TaintLocation] = None,
                    taint_origins: dict = None) -> list[DataflowFinding]:
        """
        Run worklist dataflow analysis on a CFG.
        
        Args:
            cfg: The CFG for a single function
            initial_taint: Pre-seeded taint (e.g. from function parameters)
            taint_origins: Origin tracking for pre-seeded taint

        Returns: list of DataflowFinding objects
        """
        if initial_taint is None:
            initial_taint = set()
        if taint_origins is None:
            taint_origins = {}

        # Initialize IN/OUT sets for each node
        IN: dict[int, set[TaintLocation]] = {nid: set() for nid in cfg.nodes}
        OUT: dict[int, set[TaintLocation]] = {nid: set() for nid in cfg.nodes}

        # Entry node gets the initial taint
        entry_id = min(cfg.nodes.keys()) if cfg.nodes else None
        if entry_id is not None:
            IN[entry_id] = set(initial_taint)

        # Worklist: start with all nodes in topological order
        # Use BFS order since we may have cycles (loops)
        worklist = deque(sorted(cfg.nodes.keys()))
        all_findings: list[DataflowFinding] = []
        reported_sinks: set[tuple] = set()

        # Track taint origins for finding traces
        origin_map: dict[TaintLocation, TaintOrigin] = {}
        for loc, origin in taint_origins.items():
            origin_map[loc] = origin

        max_iterations = len(cfg.nodes) * 10  # safety bound
        iteration = 0

        while worklist and iteration < max_iterations:
            iteration += 1
            node_id = worklist.popleft()
            node = cfg.nodes[node_id]

            # Compute new IN[node] = UNION of OUT[predecessor]
            preds = cfg.predecessors(node_id)
            new_in = set()
            for pred_id in preds:
                new_in |= OUT.get(pred_id, set())

            # For entry node, also add initial taint
            if node_id == entry_id:
                new_in |= initial_taint

            IN[node_id] = new_in

            # Apply transfer function: compute GEN/KILL from node statements
            gen_set, kill_set, sinks_hit = self.transfer.compute(
                node.statements, self.source_bytes, new_in
            )

            # Record origins for newly generated taint
            for loc in gen_set:
                if loc not in origin_map:
                    line = node.source_lines[0] if node.source_lines else 0
                    origin_map[loc] = TaintOrigin(
                        location=loc,
                        line=line,
                        description=f"Source: {loc.base} becomes tainted"
                    )

            # Compute new OUT[node] = GEN UNION (IN - KILL)
            new_out = gen_set | (new_in - kill_set)

            # If OUT changed → add successors to worklist (fixedpoint condition)
            if new_out != OUT[node_id]:
                OUT[node_id] = new_out
                for succ_id in cfg.successors(node_id):
                    if succ_id not in worklist:
                        worklist.append(succ_id)

            # Collect sink findings from this block
            for hit in sinks_hit:
                dedup_key = (hit["rule_id"], hit["sink_line"], str(sorted(str(l) for l in hit["tainted_locs"])))
                if dedup_key in reported_sinks:
                    continue
                reported_sinks.add(dedup_key)

                # Build taint path from origins
                taint_origins_for_hit = {
                    loc: origin_map.get(loc, TaintOrigin(loc, 0, f"{loc.base} is tainted"))
                    for loc in hit["tainted_locs"]
                }
                all_findings.append(DataflowFinding(
                    rule_id=hit["rule_id"],
                    vuln_class=hit["vuln_class"],
                    sink_text=hit["sink_text"],
                    sink_line=hit["sink_line"],
                    tainted_locs=hit["tainted_locs"],
                    taint_origins=taint_origins_for_hit
                ))

        return all_findings
