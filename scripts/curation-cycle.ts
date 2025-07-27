#!/usr/bin/env ts-node
import { fileURLToPath } from 'url';
import path from 'path';
import dotenv from 'dotenv';
import { RAGCuratorAgent } from '../src/agents/RAGCuratorAgent';
import { AgentSettings } from '../src/types/cveData';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.resolve(__dirname, '..', '.env') });

const apiKeys = {
  nvd: process.env.NVD_API_KEY,
  geminiApiKey: process.env.GEMINI_API_KEY
};

const settings: AgentSettings = {
  geminiApiKey: process.env.GEMINI_API_KEY,
  geminiModel: process.env.GEMINI_MODEL || 'gemini-2.5-flash',
  nvdApiKey: process.env.NVD_API_KEY,
  openAiApiKey: process.env.OPENAI_API_KEY,
  openAiModel: process.env.OPENAI_MODEL || 'gpt-4.1'
};

const agent = new RAGCuratorAgent();

async function run() {
  await agent.runCurationCycle(apiKeys, settings);
}

const intervalMinutes = parseInt(process.env.CURATION_INTERVAL_MINUTES || '1440', 10);

run().catch(err => console.error('Curation cycle failed:', err));

if (intervalMinutes > 0) {
  setInterval(() => {
    run().catch(err => console.error('Curation cycle failed:', err));
  }, intervalMinutes * 60 * 1000);
}
