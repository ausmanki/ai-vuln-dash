import { describe, it, expect, vi } from 'vitest';
import { fetchGeneralAnswer, parseDescriptionBasedResponse } from './AIEnhancementService';

// Simple mock response for OpenAI
const mockResponse = {
  ok: true,
  json: () => Promise.resolve({ choices: [{ message: { content: 'ok' } }] })
} as any;

describe('fetchGeneralAnswer', () => {
  it('includes web search tool when using OpenAI', async () => {
    const fetcher = vi.fn().mockResolvedValue(mockResponse);
    await fetchGeneralAnswer('hi', { openAiApiKey: 'key', openAiModel: 'gpt-4o' }, fetcher);
    const options = fetcher.mock.calls[0][1];
    const body = JSON.parse(options.body);
    expect(body.tools).toEqual([{ type: 'web_search' }]);
  });
});

describe('parseDescriptionBasedResponse', () => {
  it('extracts JSON surrounded by text', () => {
    const text = 'Intro text\n```json\n{ "patches": [], "advisories": [] }\n```\ntrailing';
    const result = parseDescriptionBasedResponse(text, 'CVE-TEST');
    expect(result.patches).toEqual([]);
    expect(result.advisories).toEqual([]);
    expect(result.searchSummary.patchesFound).toBe(0);
  });
});
