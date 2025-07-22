import { describe, it, expect, vi } from 'vitest';
import { fetchGeneralAnswer } from './AIEnhancementService';

// Simple mock response for OpenAI
const mockResponse = {
  ok: true,
  json: () => Promise.resolve({ choices: [{ message: { content: 'ok' } }] })
} as any;

describe('fetchGeneralAnswer', () => {
  it('omits unsupported tool field when using OpenAI', async () => {
    const fetcher = vi.fn().mockResolvedValue(mockResponse);
    await fetchGeneralAnswer('hi', { openAiApiKey: 'key', openAiModel: 'gpt-4o' }, fetcher);
    const options = fetcher.mock.calls[0][1];
    const body = JSON.parse(options.body);
    expect(body.tools).toBeUndefined();
  });
});
