"""
DevSecure360 — DAST Differential Response Analysis
====================================================
Helpers for comparing two HTTP responses to detect boolean-based SQLi
and other differential vulnerabilities.
"""

import difflib
from dataclasses import dataclass


@dataclass
class DiffResult:
    body_length_delta: int
    body_similarity: float      # 0.0 = completely different, 1.0 = identical
    status_code_changed: bool
    significant: bool           # True if difference is beyond noise threshold


def compare_responses(resp_a, resp_b,
                      min_length_delta: int = 20,
                      max_similarity: float = 0.95) -> DiffResult:
    """
    Compare two HttpResponse objects.
    Returns DiffResult indicating whether the responses are meaningfully different.

    Used for boolean-based SQLi: send true-condition vs false-condition;
    if responses differ significantly, one condition is executing differently.

    Args:
        resp_a: The true-condition response (e.g. OR 1=1)
        resp_b: The false-condition response (e.g. OR 1=2)
        min_length_delta: Minimum body length difference to consider significant
        max_similarity: Similarity ratio below which we call it significant
    """
    len_a = len(resp_a.body)
    len_b = len(resp_b.body)
    delta = abs(len_a - len_b)

    # SequenceMatcher gives a ratio between 0 and 1
    similarity = difflib.SequenceMatcher(
        None,
        resp_a.body[:5000],   # compare first 5000 chars to stay fast
        resp_b.body[:5000]
    ).ratio()

    status_changed = resp_a.status_code != resp_b.status_code

    significant = (
        status_changed or
        delta >= min_length_delta or
        similarity <= max_similarity
    )

    return DiffResult(
        body_length_delta=delta,
        body_similarity=similarity,
        status_code_changed=status_changed,
        significant=significant,
    )


def format_diff_evidence(resp_true, resp_false, param_name: str) -> str:
    """Build a human-readable evidence string for boolean SQLi findings."""
    return (
        f"Boolean-based SQL Injection via parameter '{param_name}':\n"
        f"  True condition:  {resp_true.url}  →  Status: {resp_true.status_code}, "
        f"Body length: {len(resp_true.body)}\n"
        f"  False condition: {resp_false.url}  →  Status: {resp_false.status_code}, "
        f"Body length: {len(resp_false.body)}\n"
        f"  Length delta: {abs(len(resp_true.body) - len(resp_false.body))} bytes  "
        f"Similarity: {difflib.SequenceMatcher(None, resp_true.body[:2000], resp_false.body[:2000]).ratio():.2%}"
    )
