"""
Attack Graph Generator - Visualizes attack paths
Creates graph visualization of the assessment flow
"""
import networkx as nx
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
from datetime import datetime
import os


class AttackGraph:
    """Generate visual attack path graphs"""
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.node_colors = {
            "START": "#00d4ff",
            "TEST_SESSION": "#4a9eff",
            "ENUM_USER": "#4a9eff",
            "TEST_RESET": "#4a9eff",
            "TEST_MFA": "#4a9eff",
            "CONTROLLED_SPRAY": "#ffb700",
            "STOP": "#00ff9d",
            "VULNERABLE": "#ff3e6c",
            "PASS": "#00ff9d"
        }
    
    def add_action(self, action, result=None):
        """Add an action node to the graph"""
        self.graph.add_node(action)
    
    def add_edge(self, from_action, to_action, label=""):
        """Add an edge between two actions"""
        self.graph.add_edge(from_action, to_action, label=label)
    
    def build_from_history(self, history):
        """
        Build graph from action history
        
        Args:
            history: List of actions like ["TEST_SESSION", "ENUM_USER", "TEST_RESET"]
        """
        if not history:
            return
        
        # Add START node
        self.graph.add_node("START")
        
        # Connect actions in sequence
        prev = "START"
        for i, action in enumerate(history):
            self.graph.add_node(action)
            self.graph.add_edge(prev, action, label=f"Step {i+1}")
            prev = action
        
        # Add STOP node if not already there
        if history[-1] != "STOP":
            self.graph.add_node("STOP")
            self.graph.add_edge(history[-1], "STOP", label="End")
    
    def build_from_findings(self, history, findings):
        """
        Build enhanced graph with finding results
        
        Args:
            history: List of actions
            findings: Dict of findings for each action
        """
        self.build_from_history(history)
        
        # Add finding nodes
        for action, result in findings.items():
            if result and isinstance(result, dict):
                # Check for vulnerabilities
                if result.get("enumeration_possible"):
                    vuln_node = f"{action}_VULN"
                    self.graph.add_node(vuln_node)
                    self.graph.add_edge(action, vuln_node, label="VULNERABLE")
                elif result.get("email_enumeration"):
                    vuln_node = f"{action}_VULN"
                    self.graph.add_node(vuln_node)
                    self.graph.add_edge(action, vuln_node, label="EMAIL ENUM")
    
    def get_node_color(self, node):
        """Get color for a node"""
        if "VULN" in node:
            return self.node_colors["VULNERABLE"]
        elif "PASS" in node:
            return self.node_colors["PASS"]
        else:
            return self.node_colors.get(node, "#4a9eff")
    
    def visualize(self, output_path="reports/attack_graph.png", title="ACASE Attack Path"):
        """
        Generate and save graph visualization
        
        Args:
            output_path: Where to save the image
            title: Graph title
        """
        if len(self.graph.nodes) == 0:
            print("[!] No nodes in graph - skipping visualization")
            return
        
        # Create figure
        plt.figure(figsize=(14, 8))
        plt.style.use('dark_background')
        
        # Layout
        pos = nx.spring_layout(self.graph, k=2, iterations=50)
        
        # Node colors
        node_colors = [self.get_node_color(node) for node in self.graph.nodes()]
        
        # Draw nodes
        nx.draw_networkx_nodes(
            self.graph,
            pos,
            node_color=node_colors,
            node_size=3000,
            alpha=0.9,
            edgecolors='white',
            linewidths=2
        )
        
        # Draw edges
        nx.draw_networkx_edges(
            self.graph,
            pos,
            edge_color='#4a7a99',
            arrows=True,
            arrowsize=20,
            arrowstyle='->',
            width=2,
            alpha=0.7
        )
        
        # Draw labels
        nx.draw_networkx_labels(
            self.graph,
            pos,
            font_size=9,
            font_color='white',
            font_family='monospace',
            font_weight='bold'
        )
        
        # Draw edge labels
        edge_labels = nx.get_edge_attributes(self.graph, 'label')
        nx.draw_networkx_edge_labels(
            self.graph,
            pos,
            edge_labels,
            font_size=7,
            font_color='#00d4ff'
        )
        
        # Title and styling
        plt.title(title, fontsize=16, color='white', fontfamily='monospace', pad=20)
        plt.axis('off')
        plt.tight_layout()
        
        # Save
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        plt.savefig(output_path, dpi=150, bbox_inches='tight', facecolor='#020b12')
        plt.close()
        
        print(f"[+] Attack graph saved: {output_path}")
    
    def export_dot(self, output_path="reports/attack_graph.dot"):
        """Export graph in DOT format for other tools"""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        nx.drawing.nx_pydot.write_dot(self.graph, output_path)
        print(f"[+] DOT file saved: {output_path}")
    
    def get_metrics(self):
        """Get graph metrics"""
        if len(self.graph.nodes) == 0:
            return {}
        
        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "longest_path": len(nx.dag_longest_path(self.graph)) if nx.is_directed_acyclic_graph(self.graph) else 0,
            "density": nx.density(self.graph)
        }


def generate_attack_graph(history, findings, output_path="reports/attack_graph.png"):
    """
    Convenience function to generate graph from history and findings
    
    Args:
        history: List of actions taken
        findings: Dict of findings
        output_path: Where to save the graph
        
    Returns:
        AttackGraph instance
    """
    graph = AttackGraph()
    graph.build_from_findings(history, findings)
    graph.visualize(output_path)
    return graph


def generate_simple_graph(history, output_path="reports/attack_path.png"):
    """
    Generate simple sequential graph from history only
    
    Args:
        history: List of actions
        output_path: Where to save
    """
    graph = AttackGraph()
    graph.build_from_history(history)
    graph.visualize(output_path, title="ACASE Assessment Flow")
    return graph
