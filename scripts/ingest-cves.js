#!/usr/bin/env -S node --loader ts-node/esm
/* eslint-env node */

import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

// Load environment variables from project root
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const envPath = path.resolve(__dirname, '..', '.env');
dotenv.config({ path: envPath });

import { ResearchAgent } from '../src/agents/ResearchAgent.ts';
import { ragDatabase } from '../src/db/EnhancedVectorDatabase.ts';

const DATA_DIR = path.resolve(__dirname, '..', 'data');
const STATE_FILE = path.join(DATA_DIR, 'ingested-cves.json');

async function readState() {
  try {
    const text = await fs.readFile(STATE_FILE, 'utf8');
    return JSON.parse(text);
  } catch {
    return [];
  }
}

async function saveState(list) {
  await fs.writeFile(STATE_FILE, JSON.stringify(list, null, 2));
}

async function fetchNvd() {
  try {
    const resp = await fetch('https://services.nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json');
    if (!resp.ok) return [];
    const data = await resp.json();
    return (data.vulnerabilities || []).map(v => v.cve.id);
  } catch (err) {
    console.error('NVD fetch error:', err);
    return [];
  }
}

async function fetchEpss() {
  try {
    const resp = await fetch('https://api.first.org/data/v1/epss?limit=1000');
    if (!resp.ok) return [];
    const data = await resp.json();
    return (data.data || []).map(e => e.cve);
  } catch (err) {
    console.error('EPSS fetch error:', err);
    return [];
  }
}

async function fetchCisaKev() {
  try {
    const resp = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
    if (!resp.ok) return [];
    const data = await resp.json();
    return (data.vulnerabilities || []).map(v => v.cveID);
  } catch (err) {
    console.error('CISA KEV fetch error:', err);
    return [];
  }
}

async function main() {
  const processed = await readState();

  // Initialize RAG DB if not already
  if (!ragDatabase.initialized) {
    await ragDatabase.initialize(process.env.GEMINI_API_KEY);
  }

  const all = new Set([
    ...(await fetchNvd()),
    ...(await fetchEpss()),
    ...(await fetchCisaKev())
  ]);

  const newCves = Array.from(all).filter(id => !processed.includes(id));
  if (newCves.length === 0) {
    console.log('No new CVEs to analyze');
    return;
  }

  const agent = new ResearchAgent();
  for (const cve of newCves) {
    try {
      console.log('Analyzing', cve);
      await agent.analyzeCVE(
        cve,
        { nvd: process.env.NVD_API_KEY, geminiApiKey: process.env.GEMINI_API_KEY },
        { geminiApiKey: process.env.GEMINI_API_KEY, openAiApiKey: process.env.OPENAI_API_KEY }
      );
      processed.push(cve);
    } catch (err) {
      console.error('Analysis failed for', cve, err);
    }
  }

  await saveState(processed);
}

main();
