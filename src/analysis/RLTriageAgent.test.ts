import { describe, it, expect } from 'vitest';
import { RLTriageAgent } from './RLTriageAgent';
import { VulnerabilityContext } from './VulnerabilityRanking';

describe('RLTriageAgent', () => {
  it('updates weights based on reward', () => {
    const agent = new RLTriageAgent();
    const ctx: VulnerabilityContext = {
      assetValue: 5,
      exploitability: 5,
      lateralMovement: 5,
      activeExploitation: false
    };
    const before = agent.score(ctx);
    agent.update(ctx, before + 10); // positive reward
    const after = agent.score(ctx);
    expect(after).toBeGreaterThan(before);
  });
});
