import { describe, it, expect } from 'vitest';
import { AttackGraph } from './AttackGraph';

describe('AttackGraph', () => {
  it('calculates path risk', () => {
    const g = new AttackGraph();
    g.addNode({ id: 'A', assetValue: 2 });
    g.addNode({ id: 'B', assetValue: 3 });
    g.addNode({ id: 'C', assetValue: 1 });
    g.addEdge({ from: 'A', to: 'B', vulnerability: 'CVE-1', technique: 'T1000', risk: 5 });
    g.addEdge({ from: 'B', to: 'C', vulnerability: 'CVE-2', technique: 'T2000', risk: 4 });
    const risk = g.getPathRisk('A', 'C');
    expect(risk).toBe(2 + 5 + 3 + 4 + 1); // sum of node values and edge risks
  });
});
