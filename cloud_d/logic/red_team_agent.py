"""Cloud-D Continuous Red-Teaming AI Agent (Reinforcement Learning).

Task 8: Continuous Red-Teaming AI Agent
Autonomously generates evolving adversarial attack payloads (SQLi mutations,
shard transplantation, nonce manipulation, rate bursts) to continuously
probe, train, and strengthen the Sentinel multi-agent defense network.
"""

from __future__ import annotations

import random
import time
from typing import Any, Dict, List, Optional, Tuple


class AttackPayload:
    """Represents a generated adversarial payload with mutation metadata."""

    def __init__(
        self,
        tactic: str,
        vector: str,
        raw_payload: str,
        target_node: int,
        mutation_depth: int = 1,
        stealth_factor: float = 0.5,
    ) -> None:
        self.tactic = tactic  # "sqli", "shard_transplant", "nonce_tamper", "rate_burst"
        self.vector = vector
        self.raw_payload = raw_payload
        self.target_node = target_node
        self.mutation_depth = mutation_depth
        self.stealth_factor = stealth_factor
        self.timestamp = time.time()

    def to_dict(self) -> dict[str, Any]:
        return {
            "tactic": self.tactic,
            "vector": self.vector,
            "raw_payload": self.raw_payload,
            "target_node": self.target_node,
            "mutation_depth": self.mutation_depth,
            "stealth_factor": round(self.stealth_factor, 3),
            "timestamp": self.timestamp,
        }


class RedTeamRLAgent:
    """Q-Learning Autonomous Reinforcement Learning Red-Teaming Agent.
    
    Explores the adversarial action space against Sentinel defenses (QueryShield,
    ShardSentry, AuthWall) to discover novel attack patterns and provide feedback
    for defender hardening.
    """

    TACTICS = ["sqli", "shard_transplant", "nonce_tamper", "rate_burst"]

    # Base payload templates for mutation
    SQLI_SEEDS = [
        "' OR '1'='1",
        "'; DROP TABLE cloud_files; --",
        "UNION SELECT NULL, username, password_hash FROM cloud_users --",
        "1' AND (SELECT COUNT(*) FROM cloud_threat_records) > 0 --",
        "admin' /*!50000OR*/ 1=1 --",
    ]

    MUTATION_ENCODINGS = [
        "raw",
        "hex_encode",
        "comment_pad",
        "stacked_delimiters",
        "tautology_expansion",
        "unicode_homoglyph",
    ]

    def __init__(self, learning_rate: float = 0.15, discount_factor: float = 0.85, epsilon: float = 0.25) -> None:
        self.lr = learning_rate
        self.gamma = discount_factor
        self.epsilon = epsilon
        # Q-Table: state (target_node, defense_strictness) -> tactic -> q_value
        self.q_table: dict[str, dict[str, float]] = {}
        self.generation_history: list[dict[str, Any]] = []
        self.reward_history: list[float] = []

    def _get_state_key(self, target_node: int, defense_strictness: str) -> str:
        return f"node_{target_node}:{defense_strictness}"

    def _ensure_state(self, state_key: str) -> None:
        if state_key not in self.q_table:
            self.q_table[state_key] = {tactic: 0.0 for tactic in self.TACTICS}

    def select_tactic(self, target_node: int, defense_strictness: str = "medium") -> str:
        """Epsilon-greedy tactic selection."""
        state_key = self._get_state_key(target_node, defense_strictness)
        self._ensure_state(state_key)

        if random.random() < self.epsilon:
            return random.choice(self.TACTICS)

        # Exploit best tactic
        tactics = self.q_table[state_key]
        return max(tactics, key=lambda t: tactics[t])

    def mutate_sqli(self, depth: int) -> Tuple[str, str]:
        """Apply sequential stochastic mutations to SQL injection payloads."""
        base = random.choice(self.SQLI_SEEDS)
        technique = random.choice(self.MUTATION_ENCODINGS)
        mutated = base

        for _ in range(depth):
            if technique == "comment_pad":
                mutated = mutated.replace(" ", "/**/")
            elif technique == "hex_encode":
                mutated = f"0x{mutated.encode('utf-8').hex()}"
            elif technique == "stacked_delimiters":
                mutated = f"WAITFOR DELAY '0:0:1'; {mutated}"
            elif technique == "tautology_expansion":
                mutated = f"({mutated}) OR ('x'='x')"
            elif technique == "unicode_homoglyph":
                mutated = mutated.replace("'", "\u2019").replace("=", "\u2550")
            elif technique == "raw":
                mutated = f"{mutated} -- probe-seq-{random.randint(100, 999)}"

        return mutated, technique

    def generate_payload(self, target_node: int, defense_strictness: str = "medium") -> AttackPayload:
        """Autonomously generate an evolved adversarial payload."""
        tactic = self.select_tactic(target_node, defense_strictness)
        mutation_depth = random.randint(1, 4)
        stealth_factor = random.uniform(0.3, 0.95)

        if tactic == "sqli":
            raw_payload, vector = self.mutate_sqli(mutation_depth)
        elif tactic == "shard_transplant":
            vector = "cross_node_aad_tamper"
            raw_payload = f"cloud-d|v1|{target_node}|transplant-shard-forge-{random.randint(1000, 9999)}"
        elif tactic == "nonce_tamper":
            vector = "reused_nonce_probe"
            raw_payload = f"000000000000000000000000::{random.randint(100000, 999999)}"
        else:  # rate_burst
            vector = "distributed_rate_burst"
            raw_payload = f"BURST_TRAIN_VOL_{random.randint(50, 500)}_OPS_NODE_{target_node}"

        payload = AttackPayload(
            tactic=tactic,
            vector=vector,
            raw_payload=raw_payload,
            target_node=target_node,
            mutation_depth=mutation_depth,
            stealth_factor=stealth_factor,
        )
        return payload

    def record_outcome(
        self,
        payload: AttackPayload,
        defense_strictness: str,
        blocked: bool,
        detected_by_sentinel: bool,
        response_time_ms: float,
    ) -> float:
        """Compute reinforcement reward and update the Q-Table.
        
        Reward Structure:
        - Payload bypassed defense undetected: +100
        - Payload bypassed defense but logged: +40
        - Payload intercepted by Sentinel Expectimax/Minimax: -50
        - Payload caused immediate rate-block / IP jail: -100
        """
        state_key = self._get_state_key(payload.target_node, defense_strictness)
        self._ensure_state(state_key)

        if not blocked and not detected_by_sentinel:
            reward = 100.0  # Zero-day penetration
        elif not blocked and detected_by_sentinel:
            reward = 40.0   # Partial evasion
        elif blocked and not detected_by_sentinel:
            reward = -20.0  # Blocked by passive generic rule
        else:
            reward = -50.0  # Defeated by autonomous Sentinel agent

        # Penalize slow payloads
        if response_time_ms > 200.0:
            reward -= 10.0

        # Q-learning update: Q(s, a) <- Q(s, a) + lr * (reward + gamma * max_a' Q(s', a') - Q(s, a))
        current_q = self.q_table[state_key][payload.tactic]
        # Next state approximation
        max_future_q = max(self.q_table[state_key].values())
        new_q = current_q + self.lr * (reward + (self.gamma * max_future_q) - current_q)
        self.q_table[state_key][payload.tactic] = round(new_q, 4)

        self.reward_history.append(reward)
        record = {
            **payload.to_dict(),
            "defense_strictness": defense_strictness,
            "blocked": blocked,
            "detected_by_sentinel": detected_by_sentinel,
            "response_time_ms": response_time_ms,
            "reward": reward,
            "q_value_after": round(new_q, 4),
        }
        self.generation_history.append(record)
        if len(self.generation_history) > 100:
            self.generation_history.pop(0)

        # Decay exploration epsilon slightly
        self.epsilon = max(0.05, self.epsilon * 0.995)
        return reward

    def get_summary(self) -> dict[str, Any]:
        """Return the training and tactical performance summary."""
        total_episodes = len(self.reward_history)
        avg_reward = (sum(self.reward_history[-20:]) / min(20, total_episodes)) if total_episodes > 0 else 0.0
        return {
            "total_episodes": total_episodes,
            "current_epsilon": round(self.epsilon, 4),
            "recent_avg_reward": round(avg_reward, 2),
            "q_table": self.q_table,
            "recent_payloads": self.generation_history[-10:],
        }
