import { describe, it, expect, vi } from 'vitest';
import { CybersecurityAgent } from '../agents/CybersecurityAgent';

const groundedResult = { content: 'grounded', sources: [], confidence: 0.9 };

describe('CybersecurityAgent', () => {
  it('calls groundingEngine.search only once for security query', async () => {
    const agent = new CybersecurityAgent();
    const searchSpy = vi
      .fn()
      .mockResolvedValue(groundedResult);
    const learnSpy = vi.fn();
    (agent as any).groundingEngine = { search: searchSpy, learn: learnSpy };

    const result = await agent.handleQuery('explain vulnerability trends');

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

  it('verifies CVE responses against known sources', async () => {
    const agent = new CybersecurityAgent();
    const handleSpy = vi
      .spyOn(agent as any, 'handleCVEQuery')
      .mockResolvedValue({ text: 'report', sender: 'bot', id: '1' });
    const verifySpy = vi
      .spyOn(agent as any, 'verifyResponse')
      .mockResolvedValue({ overall: 0.9, flags: [] });

    const res = await agent.handleQuery('tell me about CVE-2024-0001');

    expect(handleSpy).toHaveBeenCalled();
    expect(verifySpy).toHaveBeenCalledWith('CVE-2024-0001', 'report');
    expect(res.data?.confidence.overall).toBe(0.9);

    handleSpy.mockRestore();
    verifySpy.mockRestore();
  });
});
