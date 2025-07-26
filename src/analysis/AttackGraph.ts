export interface AttackNode {
  id: string;
  assetValue: number;
}

export interface AttackEdge {
  from: string;
  to: string;
  vulnerability: string; // CVE id
  technique?: string; // MITRE ATT&CK technique id
  risk: number; // computed risk weight
}

export class AttackGraph {
  private nodes: Map<string, AttackNode> = new Map();
  private edges: AttackEdge[] = [];

  addNode(node: AttackNode) {
    this.nodes.set(node.id, node);
  }

  addEdge(edge: AttackEdge) {
    if (!this.nodes.has(edge.from) || !this.nodes.has(edge.to)) {
      throw new Error('Both nodes must exist');
    }
    this.edges.push(edge);
  }

  getPathRisk(start: string, end: string): number {
    const visited = new Set<string>();
    let minRisk = Infinity;

    const dfs = (current: string, risk: number) => {
      if (current === end) {
        minRisk = Math.min(minRisk, risk);
        return;
      }
      visited.add(current);
      for (const edge of this.edges) {
        if (edge.from === current && !visited.has(edge.to)) {
          dfs(edge.to, risk + edge.risk + (this.nodes.get(edge.to)?.assetValue || 0));
        }
      }
      visited.delete(current);
    };

    dfs(start, this.nodes.get(start)?.assetValue || 0);
    return minRisk === Infinity ? 0 : minRisk;
  }
}
