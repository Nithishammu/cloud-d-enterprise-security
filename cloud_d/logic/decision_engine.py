class DecisionEngine:
    def __init__(self, defenders, threshold: float = .4):
        self.defenders = defenders
        self.threshold = threshold

    def joint_decision(self, attacks, state):
        proposals = []
        for defender in self.defenders:
            proposal = defender.propose(attacks, state)
            if proposal is not None:
                proposals.append(proposal)
        ranked = sorted(proposals, key=lambda proposal: proposal["utility"], reverse=True)
        joint_actions = [proposal for proposal in ranked if proposal["utility"] > self.threshold]
        return ranked, joint_actions

    @staticmethod
    def find_blocker(attack, joint_actions, target_defender_by_role=None):
        target_defender_by_role = target_defender_by_role or {}
        assigned_vector = target_defender_by_role.get(attack.get("target_role"))
        if assigned_vector:
            return next(
                (
                    action for action in joint_actions
                    if action.get("vector_id") == assigned_vector
                    and attack["type"] in action["counters"]
                ),
                None,
            )
        return next((action for action in joint_actions if attack["type"] in action["counters"]), None)
