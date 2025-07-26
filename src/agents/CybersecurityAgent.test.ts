import { describe, it, expect, vi } from 'vitest';
import { CybersecurityAgent } from '../agents/CybersecurityAgent';

const groundedResult = { content: 'grounded', sources: [], confidence: 0.9 };

describe('CybersecurityAgent', () => {
  it('calls groundingEngine.search only once', async () => {
    const agent = new CybersecurityAgent();
    const searchSpy = vi
      .fn()
      .mockResolvedValue(groundedResult);
    (agent as any).groundingEngine = { search: searchSpy };

    const result = await agent.handleQuery('tell me something');

    expect(searchSpy).toHaveBeenCalledTimes(1);
    expect(result.text).toBe(groundedResult.content);
  });

  it('calls groundingEngine.learn when autoLearn is enabled', async () => {
    const agent = new CybersecurityAgent();
    const searchSpy = vi.fn().mockResolvedValue(groundedResult);
    const learnSpy = vi.fn();
    (agent as any).groundingEngine = { search: searchSpy, learn: learnSpy };
    (agent as any).groundingConfig = { autoLearn: true };

    await (agent as any).getGroundedInfo('example');

    expect(learnSpy).toHaveBeenCalledWith(groundedResult);
  });
});
