#!/usr/bin/env ts-node
import { fileURLToPath } from 'url';
import path from 'path';
import readline from 'readline';
import dotenv from 'dotenv';
import { CybersecurityAgent } from '../src/agents/CybersecurityAgent';
import { AgentSettings } from '../src/types/cveData';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.resolve(__dirname, '..', '.env') });

const settings: AgentSettings = {
  openAiApiKey: process.env.OPENAI_API_KEY,
  geminiApiKey: process.env.GEMINI_API_KEY,
  nvdApiKey: process.env.NVD_API_KEY,
};

const agent = new CybersecurityAgent(settings);

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: '> '
});

console.log('Cybersecurity Agent CLI. Type "exit" to quit.');
rl.prompt();

rl.on('line', async line => {
  const input = line.trim();
  if (input.toLowerCase() === 'exit') {
    rl.close();
    return;
  }
  try {
    const res = await agent.handleQuery(input);
    console.log(res.text);
    if (res.sources && res.sources.length > 0) {
      console.log('\nSources:');
      res.sources.forEach((s, i) => console.log(`${i + 1}. ${s}`));
    }
  } catch (err: any) {
    console.error('Error:', err.message);
  }
  rl.prompt();
});

rl.on('close', () => {
  process.exit(0);
});
