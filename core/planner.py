import networkx as nx
from core.decision_ai import decide, explain_impact
from core.policy_guard import validate_action

MAX_STEPS = 10

class Planner:
    def __init__(self):
        self.history = []
        self.findings = {}
        self.attack_graph = nx.DiGraph()

    def record_finding(self, action, result):
        self.findings[action] = result
        self._add_node(action)

    def _add_node(self, step):
        if len(self.attack_graph.nodes) > 0:
            last = list(self.attack_graph.nodes)[-1]
            self.attack_graph.add_edge(last, step)
        self.attack_graph.add_node(step)

    def next_step(self, observation):
        if len(self.history) >= MAX_STEPS:
            print("[Planner] Max steps reached.")
            return None
        raw = decide(observation, self.history)
        action = validate_action(raw, self.history, observation)
        self.history.append(action)
        if action == "STOP":
            return None
        return action

    def get_attack_path(self):
        return list(self.attack_graph.nodes)

    def get_impact_summary(self):
        path = self.get_attack_path()
        if not path:
            return "No attack path identified."
        return explain_impact(path)
