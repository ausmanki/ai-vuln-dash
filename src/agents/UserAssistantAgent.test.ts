import { describe, it, expect, vi } from 'vitest';
import { UserAssistantAgent } from '../agents/UserAssistantAgent';
import { ragDatabase } from '../db/EnhancedVectorDatabase';
import type { BulkAnalysisResult, EnhancedVulnerabilityData } from '../types/cveData';
import * as AIEnhancementService from '../services/AIEnhancementService';

describe('UserAssistantAgent', () => {
  it('handleQuery returns help message for /help', async () => {
    const agent = new UserAssistantAgent();
    const result = await agent.handleQuery('/help');
    expect(result.text).toContain('cybersecurity assistant');
  });

  it('handleQuery delegates to generateBulkAnalysisSummary for /bulk_summary', async () => {
    const agent = new UserAssistantAgent();
    const spy = vi
      .spyOn(agent, 'generateBulkAnalysisSummary')
      .mockReturnValue({ text: 'bulk summary', sender: 'bot', id: '1' });
    await agent.handleQuery('/bulk_summary');
    expect(spy).toHaveBeenCalled();
    spy.mockRestore();
  });

  it('handleQuery delegates to generateBulkComponentImpactSummary for /component_summary', async () => {
    const agent = new UserAssistantAgent();
    const spy = vi
      .spyOn(agent, 'generateBulkComponentImpactSummary')
      .mockReturnValue({ text: 'component summary', sender: 'bot', id: '1' });
    await agent.handleQuery('/component_summary');
    expect(spy).toHaveBeenCalled();
    spy.mockRestore();
  });

  it('handleQuery delegates to handleCVEQuery when CVE present', async () => {
    const agent = new UserAssistantAgent({ aiProvider: 'test' });
    vi.spyOn(agent as any, 'summarizeConversation').mockResolvedValue('');
    const spy = vi
      .spyOn(agent as any, 'handleCVEQuery')
      .mockResolvedValue({ text: 'ok', sender: 'bot', id: '1' });
    await agent.handleQuery('Check CVE-2024-9999 details');
    expect(spy).toHaveBeenCalledWith('Check CVE-2024-9999 details', 'CVE-2024-9999');
    spy.mockRestore();
  });

  it('setContextualCVE updates current CVE and recent list', async () => {
    const agent = new UserAssistantAgent({ aiProvider: 'test' });
    vi.spyOn(agent as any, 'summarizeConversation').mockResolvedValue('');
    const res = await agent.setContextualCVE('CVE-2024-1111');
    expect(res?.text).toContain('CVE-2024-1111');
    expect((agent as any).currentCveIdForSession).toBe('CVE-2024-1111');
    expect((agent as any).conversationContext.recentCVEs[0]).toBe('CVE-2024-1111');
  });

  it('generateBulkAnalysisSummary summarizes results', async () => {
    const agent = new UserAssistantAgent();
    const results: BulkAnalysisResult[] = [
      {
        cveId: 'CVE-1',
        status: 'Complete',
        data: {
          cve: { cvssV3: { baseScore: 9.1 } } as any,
          kev: { listed: false } as any,
        } as EnhancedVulnerabilityData,
      },
      {
        cveId: 'CVE-2',
        status: 'Complete',
        data: {
          cve: { cvssV3: { baseScore: 5.0 } } as any,
          kev: { listed: true } as any,
        } as EnhancedVulnerabilityData,
      },
      {
        cveId: 'CVE-3',
        status: 'Error',
      },
    ];
    await agent.setBulkAnalysisResults(results);
    const summary = agent.generateBulkAnalysisSummary();
    expect(summary.text).toContain('Bulk Analysis Summary');
    expect(summary.text).toContain('3 vulnerabilities');
    expect(summary.text).toContain('2 successful analyses');
    expect(summary.text).toContain('2 vulnerabilities require immediate attention');
  });

  it('generateBulkAnalysisSummary handles empty results', () => {
    const agent = new UserAssistantAgent();
    const summary = agent.generateBulkAnalysisSummary();
    expect(summary.text).toContain("don't have any bulk analysis results");
  });

  it('attaches group summaries for deduplicated CVEs', async () => {
    const agent = new UserAssistantAgent({ aiProvider: 'openai' });
    const spy = vi
      .spyOn(AIEnhancementService, 'fetchGeneralAnswer')
      .mockResolvedValue({ answer: 'merged summary' } as any);

    const results: BulkAnalysisResult[] = [
      {
        cveId: 'CVE-1',
        status: 'Complete',
        data: { cve: { description: 'same desc' } } as any,
      },
      {
        cveId: 'CVE-2',
        status: 'Complete',
        data: { cve: { description: 'same desc' } } as any,
      },
    ];

    await agent.setBulkAnalysisResults(results);
    const stored = (agent as any).bulkAnalysisResults;
    expect(stored.length).toBe(1);
    expect(stored[0].group).toEqual(['CVE-1', 'CVE-2']);
    expect(stored[0].data.groupSummary).toBe('merged summary');
    spy.mockRestore();
  });

  it('respects custom cache TTL', async () => {
    const agent = new UserAssistantAgent({ cacheTTL: 0 });
    const fetcher = vi.fn().mockResolvedValueOnce('a').mockResolvedValueOnce('b');
    const res1 = await (agent as any).getCachedOrFetch('k', fetcher);
    const res2 = await (agent as any).getCachedOrFetch('k', fetcher);
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(res1).toBe('a');
    expect(res2).toBe('b');
  });

  it('clearCache forces refetch', async () => {
    const agent = new UserAssistantAgent({ cacheTTL: 10000 });
    const fetcher = vi.fn().mockResolvedValueOnce('a').mockResolvedValueOnce('b');
    await (agent as any).getCachedOrFetch('k', fetcher);
    agent.clearCache();
    const res = await (agent as any).getCachedOrFetch('k', fetcher);
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(res).toBe('b');
  });

  it('isActualDispute detects dispute keywords', () => {
    const agent = new UserAssistantAgent();
    const res = (agent as any).isActualDispute('Vendor disputes this issue and marked as false positive', 'CVE-2023-1234');
    expect(res).toBe(true);
  });

  it('handleGeneralQuery uses RAG results when available', async () => {
    const agent = new UserAssistantAgent({ aiProvider: 'test' });
    vi.spyOn(agent as any, 'summarizeConversation').mockResolvedValue('');
    const original = ragDatabase.initialized;
    ragDatabase.initialized = true;
    const ragSpy = vi
      .spyOn(ragDatabase, 'search')
      .mockResolvedValue([{ content: 'RAG answer', similarity: 0.9, metadata: {} } as any]);
    const groundSpy = vi.spyOn(agent as any, 'getGroundedInfo');
    const res = await (agent as any).handleGeneralQuery('general question');
    expect(res.text).toContain('RAG answer');
    expect(groundSpy).not.toHaveBeenCalled();
    ragSpy.mockRestore();
    groundSpy.mockRestore();
    ragDatabase.initialized = original;
  });

  it('handleGeneralQuery falls back to grounding engine when RAG misses', async () => {
    const agent = new UserAssistantAgent({ aiProvider: 'test' });
    const original = ragDatabase.initialized;
    ragDatabase.initialized = true;
    const ragSpy = vi.spyOn(ragDatabase, 'search').mockResolvedValue([]);
    const groundSpy = vi
      .spyOn(agent as any, 'getGroundedInfo')
      .mockResolvedValue({ content: 'grounded', sources: [], confidence: 0.8 });
    const res = await (agent as any).handleGeneralQuery('another question');
    expect(res.text).toBe("I couldn't find a direct answer in my knowledge base. Based on a web search, here's what I found:\n\ngrounded");
    expect(groundSpy).toHaveBeenCalled();
    ragSpy.mockRestore();
    groundSpy.mockRestore();
    ragDatabase.initialized = original;
  });

  it('includes google_search tool in Gemini API call', async () => {
    const agent = new UserAssistantAgent({
      aiProvider: 'gemini',
      geminiApiKey: 'test-key',
    });
    const ragSpy = vi.spyOn(ragDatabase, 'search').mockResolvedValue([]);
    const fetchSpy = vi.spyOn(global, 'fetch').mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ candidates: [{ content: { parts: [{ text: 'gemini answer' }] } }] }),
    } as any);

    await agent.handleQuery('tell me about CVE-2024-0001');

    const fetchCall = fetchSpy.mock.calls.find(call => call[0].toString().includes('/api/gemini'));
    expect(fetchCall).toBeDefined();
    if (fetchCall) {
      const body = JSON.parse(fetchCall[1].body as string);
      expect(body.tools).toBeDefined();
      expect(body.tools[0]).toHaveProperty('google_search');
    }

    ragSpy.mockRestore();
    fetchSpy.mockRestore();
  });

  it('storeConversation updates conversation summary', async () => {
    const agent = new UserAssistantAgent();
    const summarySpy = vi
      .spyOn(agent as any, 'summarizeConversation')
      .mockResolvedValue('This is a test summary.');

    await (agent as any).storeConversation('test query', 'test response');

    expect(summarySpy).toHaveBeenCalled();
    expect((agent as any).conversationContext.summary).toBe('This is a test summary.');

    summarySpy.mockRestore();
  });

  it('handleQuery prepends conversation summary to queries', async () => {
    const agent = new UserAssistantAgent({ aiProvider: 'test' });
    // Set a summary in the context
    (agent as any).conversationContext.summary = 'The user is interested in CVE-2024-1234.';

    const ragSpy = vi.spyOn(ragDatabase, 'search').mockResolvedValue([]);
    const groundSpy = vi
      .spyOn(agent as any, 'getGroundedInfo')
      .mockResolvedValue({ content: 'grounded answer', sources: [], confidence: 0.8 });

    // We need to ensure the query doesn't match a CVE, so it falls through to the general query handler
    await agent.handleQuery('Is there a patch for it?');

    expect(groundSpy).toHaveBeenCalledWith(expect.stringContaining('Conversation context: The user is interested in CVE-2024-1234.'));
    expect(groundSpy).toHaveBeenCalledWith(expect.stringContaining('User query: Is there a patch for it?'));

    ragSpy.mockRestore();
    groundSpy.mockRestore();
  });
});
