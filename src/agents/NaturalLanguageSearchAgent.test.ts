import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NaturalLanguageSearchAgent } from './NaturalLanguageSearchAgent';
import { ragDatabase } from '../db/EnhancedVectorDatabase';
import * as AIEnhancementService from '../services/AIEnhancementService';
import { AgentSettings } from '../types/cveData';

describe('NaturalLanguageSearchAgent', () => {
  let agent: NaturalLanguageSearchAgent;
  const mockSettings: AgentSettings = {
    aiProvider: 'gemini',
    geminiModel: 'gemini-2.5-flash',
    openAiModel: 'gpt-4.1',
    darkMode: false,
    nvdApiKey: '',
  };

  beforeEach(() => {
    agent = new NaturalLanguageSearchAgent();
    vi.spyOn(ragDatabase, 'initialize').mockResolvedValue(undefined);
  });

  it('should return results from RAG search if found', async () => {
    const ragSpy = vi.spyOn(ragDatabase, 'search').mockResolvedValue([
      {
        content: 'This is a test document.',
        metadata: { cveId: 'CVE-2024-1111', title: 'Test Doc', source: 'RAG DB' },
        similarity: 0.9,
      },
    ] as any);

    const webSearchSpy = vi.spyOn(AIEnhancementService, 'fetchGeneralAnswer');

    const results = await agent.search('test query', mockSettings);

    expect(ragSpy).toHaveBeenCalledWith('test query');
    expect(webSearchSpy).not.toHaveBeenCalled();
    expect(results).toHaveLength(1);
    expect(results[0].cveId).toBe('CVE-2024-1111');
    expect(results[0].source).toBe('RAG DB');

    ragSpy.mockRestore();
    webSearchSpy.mockRestore();
  });

  it('should fall back to web search when RAG returns no results', async () => {
    const ragSpy = vi.spyOn(ragDatabase, 'search').mockResolvedValue([]);
    const webSearchSpy = vi.spyOn(AIEnhancementService, 'fetchGeneralAnswer').mockResolvedValue({
      answer: 'The vulnerability you are asking about is CVE-2024-2222.',
    });

    const results = await agent.search('what is that new vulnerability?', mockSettings);

    expect(ragSpy).toHaveBeenCalled();
    expect(webSearchSpy).toHaveBeenCalled();
    expect(results).toHaveLength(1);
    expect(results[0].source).toBe('AI (gemini)');
  });

  it('should detect and return a CVE ID from the web search result', async () => {
    vi.spyOn(ragDatabase, 'search').mockResolvedValue([]);
    const webSearchSpy = vi.spyOn(AIEnhancementService, 'fetchGeneralAnswer').mockResolvedValue({
      answer: 'The vulnerability is CVE-2024-3333. It is critical.',
    });

    const results = await agent.search('tell me about the new critical bug', mockSettings);

    expect(results).toHaveLength(1);
    expect(results[0].detectedCveId).toBe('CVE-2024-3333');

    webSearchSpy.mockRestore();
  });

  it('should not return a detected CVE ID if none is found in the web search result', async () => {
    vi.spyOn(ragDatabase, 'search').mockResolvedValue([]);
    const webSearchSpy = vi.spyOn(AIEnhancementService, 'fetchGeneralAnswer').mockResolvedValue({
      answer: 'This is a general response about security vulnerabilities.',
    });

    const results = await agent.search('what are vulnerabilities?', mockSettings);

    expect(results).toHaveLength(1);
    expect(results[0].detectedCveId).toBeUndefined();

    webSearchSpy.mockRestore();
  });

  it('should return an empty array if web search also fails', async () => {
    vi.spyOn(ragDatabase, 'search').mockResolvedValue([]);
    const webSearchSpy = vi.spyOn(AIEnhancementService, 'fetchGeneralAnswer').mockRejectedValue(new Error('API Failure'));

    const results = await agent.search('any new bugs?', mockSettings);

    expect(results).toHaveLength(0);

    webSearchSpy.mockRestore();
  });
});
