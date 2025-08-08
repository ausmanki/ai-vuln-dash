import { AgentSettings } from '../types/cveData';
import { fetchGeneralAnswer } from '../services/AIEnhancementService';

export interface ConversationTurn {
  query: string;
  response: string;
}

export interface StoredConversationMemory {
  context: any;
  history: ConversationTurn[];
}

const STORAGE_KEY = 'conversation_memory';

export async function loadConversationMemory(): Promise<StoredConversationMemory | null> {
  try {
    if (typeof localStorage !== 'undefined') {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        return JSON.parse(raw);
      }
    } else {
      const res = await fetch('/api/memory');
      if (res.ok) {
        return await res.json();
      }
    }
  } catch (e) {
    console.error('Failed to load conversation memory:', e);
  }
  return null;
}

export function loadConversationMemorySync(): StoredConversationMemory | null {
  try {
    if (typeof localStorage !== 'undefined') {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        return JSON.parse(raw);
      }
    }
  } catch (e) {
    console.error('Failed to load conversation memory:', e);
  }
  return null;
}

export async function saveConversationMemory(data: StoredConversationMemory): Promise<void> {
  try {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
    } else {
      await fetch('/api/memory', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
    }
  } catch (e) {
    console.error('Failed to save conversation memory:', e);
  }
}

export async function summarizeHistory(history: ConversationTurn[], settings?: AgentSettings): Promise<string> {
  if (history.length === 0) return '';
  const historyText = history
    .map(turn => `User: ${turn.query}\nAssistant: ${turn.response}`)
    .join('\n\n');
  const prompt = `Summarize the key points from the following conversation between a user and a cybersecurity assistant:\n\n${historyText}`;
  try {
    const result: any = await fetchGeneralAnswer(prompt, settings, (input: any, init?: any) => fetch(input, init));
    return result.answer || '';
  } catch (e) {
    console.error('History summarization failed:', e);
    return '';
  }
}

