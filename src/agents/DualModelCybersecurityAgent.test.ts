import { describe, it, expect } from 'vitest';
import { DualModelCybersecurityAgent } from './DualModelCybersecurityAgent';

describe('DualModelCybersecurityAgent', () => {
  it('combines outputs from both models', async () => {
    const agent = new DualModelCybersecurityAgent({
      openAiConnector: async prompt => `OA:${prompt}`,
      geminiConnector: async prompt => `G:${prompt}`,
    });

    const result = await agent.analyzeSecurity('test prompt');
    expect(result).toContain('[OpenAI]');
    expect(result).toContain('OA:test prompt');
    expect(result).toContain('[Gemini]');
    expect(result).toContain('G:test prompt');
  });

  it('works with a single model', async () => {
    const agent = new DualModelCybersecurityAgent({
      openAiConnector: async () => 'only openai',
    });
    const result = await agent.analyzeSecurity('hello');
    expect(result).toContain('[OpenAI]');
    expect(result).not.toContain('[Gemini]');
  });
});
