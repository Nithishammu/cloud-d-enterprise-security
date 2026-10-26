"""Cloud-D Pure Minimax and Expectimax Search Logic.

Delivered for Cloud-D Enterprise Security (PSG College of Technology).
Pure Minimax (depth 2 without alpha-beta pruning) for deterministic zero-heuristic game tree evaluation.
Expectimax for stochastic SQL sanitization under AST uncertainty.
"""

from __future__ import annotations
from typing import Any, Dict, Optional, Tuple


def minimax(node: dict[str, Any], depth: int, stats: Optional[dict[str, int]] = None) -> Tuple[float, Optional[str], int]:
    """Evaluate a small deterministic max/min tree using pure Minimax without alpha-beta pruning.
    
    Returns:
        (value, root_action, visited_node_count)
    """
    stats = stats if stats is not None else {"nodes": 0}
    stats["nodes"] += 1

    if depth <= 0 or node.get("kind") == "leaf" or not node.get("children"):
        return float(node.get("value", 0.0)), node.get("action"), stats["nodes"]

    if node.get("kind") == "max":
        best_value = float("-inf")
        best_action = None
        for child in node.get("children", []):
            value, _, _ = minimax(child, depth - 1, stats)
            if value > best_value:
                best_value = value
                best_action = child.get("action")
        return best_value, best_action, stats["nodes"]

    # Minimizer (defender / sentinel)
    best_value = float("inf")
    best_action = None
    for child in node.get("children", []):
        value, action, _ = minimax(child, depth - 1, stats)
        if value < best_value:
            best_value = value
            best_action = action
    return best_value, best_action, stats["nodes"]


def expectimax(node: dict[str, Any], stats: Optional[dict[str, int]] = None) -> Tuple[float, Optional[str], int]:
    """Evaluate max and probability-weighted chance nodes without pruning.
    
    Used by QueryShield to calculate expected security containment utilities
    under syntax uncertainty.
    
    Returns:
        (expected_value, selected_root_action, visited_node_count)
    """
    stats = stats if stats is not None else {"nodes": 0}
    stats["nodes"] += 1

    kind = node.get("kind", "leaf")
    if kind == "leaf":
        return float(node.get("value", 0.0)), node.get("action"), stats["nodes"]

    if kind == "chance":
        value = 0.0
        probability_total = 0.0
        for child in node.get("children", []):
            prob = float(child.get("probability", 0.0))
            child_value, _, _ = expectimax(child, stats)
            value += prob * child_value
            probability_total += prob

        if probability_total <= 0:
            return 0.0, node.get("action"), stats["nodes"]
        return value / probability_total, node.get("action"), stats["nodes"]

    # Maximizer
    best_value = float("-inf")
    best_action = None
    for child in node.get("children", []):
        value, _, _ = expectimax(child, stats)
        if value > best_value:
            best_value = value
            best_action = child.get("action")
    return best_value, best_action, stats["nodes"]
