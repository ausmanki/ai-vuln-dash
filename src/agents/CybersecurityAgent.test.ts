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
});
