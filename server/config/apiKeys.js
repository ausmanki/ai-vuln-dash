/* eslint-env node */
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const envPath = path.resolve(__dirname, '../../.env');
dotenv.config({ path: envPath });

export function getApiKeys() {
  return {
    openAiApiKey: process.env.OPENAI_API_KEY,
    googleApiKey: process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY,
  };
}

export function getClientConfig() {
  const { openAiApiKey, googleApiKey } = getApiKeys();
  const hasOpenAI = !!openAiApiKey;
  const hasGemini = !!googleApiKey;
  const provider = hasOpenAI ? 'openai' : hasGemini ? 'gemini' : null;

  return {
    hasOpenAI,
    hasGemini,
    provider,
    openAiModel: process.env.OPENAI_MODEL || 'gpt-4.1',
    geminiModel: process.env.GEMINI_MODEL || 'gemini-2.5-flash',
  };
}
