"""Cloud-D Pure Minimax and Expectimax Search Logic.

Delivered for Cloud-D Enterprise Security (PSG College of Technology).
Nithish M (Roll No. 24X064).

- Pure Minimax (depth 2 without alpha-beta pruning) for deterministic zero-heuristic game tree evaluation.
- Expectimax for stochastic chance-node SQL sanitization under AST uncertainty.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


def minimax(
    node: Dict[str, Any],
    depth: int,
    stats: Optional[Dict[str, int]] = None,
) -> Tuple[float, Optional[str], int]:
    """Evaluates a small deterministic game tree using pure Minimax without alpha-beta pruning.

    Explores 100% of game-tree states deterministically.
    Returns:
        (value, best_action, visited_node_count)
    """
    stats = stats if stats is not None else {"nodes": 0}
    stats["nodes"] += 1

    if depth <= 0 or node.get("kind") == "leaf" or not node.get("children"):
        return float(node.get("value", 0.0)), node.get("action"), stats["nodes"]

    is_max = node.get("player") == "max"
    best_action: Optional[str] = None

    if is_max:
        best_val = -float("inf")
        for child in node.get("children", []):
            val, _, _ = minimax(child, depth - 1, stats)
            if val > best_val:
                best_val = val
                best_action = child.get("action")
        return best_val, best_action, stats["nodes"]
    else:
        best_val = float("inf")
        for child in node.get("children", []):
            val, _, _ = minimax(child, depth - 1, stats)
            if val < best_val:
                best_val = val
                best_action = child.get("action")
        return best_val, best_action, stats["nodes"]


def expectimax(
    node: Dict[str, Any],
    depth: int,
    stats: Optional[Dict[str, int]] = None,
) -> Tuple[float, Optional[str], int]:
    """Evaluates game tree with chance nodes (probability-weighted stochastic expectations).

    Used by QueryShield to determine optimal sanitization under AST uncertainty.
    Returns:
        (expected_value, best_action, visited_node_count)
    """
    stats = stats if stats is not None else {"nodes": 0}
    stats["nodes"] += 1

    if depth <= 0 or node.get("kind") == "leaf" or not node.get("children"):
        return float(node.get("value", 0.0)), node.get("action"), stats["nodes"]

    player = node.get("player", "max")

    if player == "max":
        best_val = -float("inf")
        best_action: Optional[str] = None
        for child in node.get("children", []):
            val, _, _ = expectimax(child, depth - 1, stats)
            if val > best_val:
                best_val = val
                best_action = child.get("action")
        return best_val, best_action, stats["nodes"]

    elif player == "chance":
        # Compute probability-weighted expected utility
        expected_sum = 0.0
        children = node.get("children", [])
        total_p = sum(float(c.get("prob", 1.0 / len(children))) for c in children) if children else 1.0

        for child in children:
            prob = float(child.get("prob", 1.0 / len(children))) / total_p
            val, _, _ = expectimax(child, depth - 1, stats)
            expected_sum += prob * val

        return expected_sum, None, stats["nodes"]

    else:
        # Min node fallback
        best_val = float("inf")
        best_action = None
        for child in node.get("children", []):
            val, _, _ = expectimax(child, depth - 1, stats)
            if val < best_val:
                best_val = val
                best_action = child.get("action")
        return best_val, best_action, stats["nodes"]
