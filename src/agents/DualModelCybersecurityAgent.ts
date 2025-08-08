import { GoogleGenerativeAI } from '@google/generative-ai';

const fetch = typeof self === 'undefined' ? require('node-fetch') : self.fetch;

export type LLMConnector = (prompt: string) => Promise<string>;

export function createOpenAIConnector(apiKey: string, model = 'gpt-4o-mini'): LLMConnector {
  return async (prompt: string): Promise<string> => {
    const res = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        messages: [{ role: 'user', content: prompt }],
      }),
    });
    if (!res.ok) {
      throw new Error(`OpenAI error: ${res.status} ${res.statusText}`);
    }
    const data: any = await res.json();
    return data.choices?.[0]?.message?.content?.trim() || '';
  };
}

export function createGeminiConnector(apiKey: string, model = 'gemini-pro'): LLMConnector {
  const genAI = new GoogleGenerativeAI(apiKey);
  const geminiModel = genAI.getGenerativeModel({ model });
  return async (prompt: string): Promise<string> => {
    const result = await geminiModel.generateContent(prompt);
    return result.response.text();
  };
}

interface UserAgentOptions {
  openAiConnector?: LLMConnector;
  geminiConnector?: LLMConnector;
}

class UserAssistantAgent {
  constructor(private options: UserAgentOptions) {}

  async run(prompt: string): Promise<Record<string, string>> {
    const results: Record<string, string> = {};
    if (this.options.openAiConnector) {
      try {
        results.openai = await this.options.openAiConnector(prompt);
      } catch (e: any) {
        results.openai_error = e.message || String(e);
      }
    }
    if (this.options.geminiConnector) {
      try {
        results.gemini = await this.options.geminiConnector(prompt);
      } catch (e: any) {
        results.gemini_error = e.message || String(e);
      }
    }
    return results;
  }
}

interface AgentConfig {
  openAiApiKey?: string;
  geminiApiKey?: string;
  openAiConnector?: LLMConnector;
  geminiConnector?: LLMConnector;
}

export class DualModelCybersecurityAgent {
  private userAgent: UserAssistantAgent;

  constructor(config: AgentConfig) {
    const openAi = config.openAiConnector ?? (config.openAiApiKey ? createOpenAIConnector(config.openAiApiKey) : undefined);
    const gemini = config.geminiConnector ?? (config.geminiApiKey ? createGeminiConnector(config.geminiApiKey) : undefined);
    this.userAgent = new UserAssistantAgent({ openAiConnector: openAi, geminiConnector: gemini });
  }

  async analyzeSecurity(prompt: string): Promise<string> {
    const outputs = await this.userAgent.run(prompt);
    const combined: string[] = [];
    if (outputs.openai) {
      combined.push(`[OpenAI]\n${outputs.openai}`);
    }
    if (outputs.gemini) {
      combined.push(`[Gemini]\n${outputs.gemini}`);
    }
    return combined.join('\n\n') || 'No response from either model.';
  }
}

