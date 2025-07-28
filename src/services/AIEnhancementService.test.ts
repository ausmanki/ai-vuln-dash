import { describe, it, expect, vi } from 'vitest';
import { fetchGeneralAnswer, parseDescriptionBasedResponse } from './AIEnhancementService';

// Simple mock response for OpenAI
const mockResponse = {
  ok: true,
  json: () =>
    Promise.resolve({
      output: [
        {
          type: 'message',
          content: [{ type: 'output_text', text: 'ok' }]
        }
      ]
    })
} as any;

describe('fetchGeneralAnswer', () => {
  it('includes web search tool when using OpenAI', async () => {
    const fetcher = vi.fn().mockResolvedValue(mockResponse);
    await fetchGeneralAnswer('hi', { aiProvider: 'openai', openAiModel: 'gpt-4.1' }, fetcher);
    const options = fetcher.mock.calls[0][1];
    const body = JSON.parse(options.body);
    expect(body.tools).toEqual([{ type: 'web_search_preview' }]);
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
