import { describe, it, expect, vi } from 'vitest';
import { CybersecurityAgent } from '../agents/CybersecurityAgent';
import { ragDatabase } from '../db/EnhancedVectorDatabase';
import { APIService } from '../services/APIService';

const groundedResult = { content: 'grounded', sources: [], confidence: 0.9 };

describe('CybersecurityAgent', () => {
  it('classifies queries for cybersecurity relevance', () => {
    const agent = new CybersecurityAgent();
    const isRelated = (agent as any).isCybersecurityRelated;
    expect(isRelated('Discuss ransomware trends')).toBe(true);
    expect(isRelated('How do I bake a cake?')).toBe(false);
  });

  it('filters out non-security queries before searching', async () => {
    const agent = new CybersecurityAgent();
    const ragSpy = vi.spyOn(ragDatabase, 'search');
    const webSpy = vi.spyOn(APIService, 'fetchGeneralAnswer');

    const result = await agent.handleQuery('What is the weather today?');

    expect(ragSpy).not.toHaveBeenCalled();
    expect(webSpy).not.toHaveBeenCalled();
    expect(result.text).toMatch(/cybersecurity/);

    ragSpy.mockRestore();
    webSpy.mockRestore();
  });

  it('returns RAG result when confidence high and skips web search', async () => {
    const agent = new CybersecurityAgent();
    const ragSpy = vi
      .spyOn(ragDatabase, 'search')
      .mockResolvedValue([{ content: 'rag answer', similarity: 0.8 } as any]);
    const webSpy = vi
      .spyOn(APIService, 'fetchGeneralAnswer')
      .mockResolvedValue({ answer: 'web answer' });

    const result = await agent.handleQuery('explain vulnerability trends');

    expect(ragSpy).toHaveBeenCalled();
    expect(webSpy).not.toHaveBeenCalled();
    expect(result.text).toBe('rag answer');

    ragSpy.mockRestore();
    webSpy.mockRestore();
  });

  it('falls back to web search when RAG confidence low', async () => {
    const agent = new CybersecurityAgent();
    const ragSpy = vi
      .spyOn(ragDatabase, 'search')
      .mockResolvedValue([{ content: 'rag low', similarity: 0.3 } as any]);
    const webSpy = vi
      .spyOn(APIService, 'fetchGeneralAnswer')
      .mockResolvedValue({ answer: 'web result' });

    const result = await agent.handleQuery('explain vulnerability trends');

    expect(ragSpy).toHaveBeenCalled();
    expect(webSpy).toHaveBeenCalledTimes(1);
    expect(result.text).toBe('web result');

    ragSpy.mockRestore();
    webSpy.mockRestore();
  });

  it('falls back to clarification when web search fails', async () => {
    const agent = new CybersecurityAgent();
    const ragSpy = vi
      .spyOn(ragDatabase, 'search')
      .mockResolvedValue([{ content: 'rag low', similarity: 0.3 } as any]);
    const webSpy = vi
      .spyOn(APIService, 'fetchGeneralAnswer')
      .mockRejectedValue(new Error('fail'));

    const result = await agent.handleQuery('explain vulnerability trends');

    expect(ragSpy).toHaveBeenCalled();
    expect(webSpy).toHaveBeenCalled();
    expect(result.text).toMatch(/could you please specify your question/);

    ragSpy.mockRestore();
    webSpy.mockRestore();
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
    const ragSpy = vi.spyOn(ragDatabase, 'search').mockResolvedValue([]);
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
    ragSpy.mockRestore();
  });
});
