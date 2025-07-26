import { describe, it, expect, vi } from 'vitest';
import { CybersecurityAgent } from './CybersecurityAgent';
import { ragDatabase } from '../db/EnhancedVectorDatabase';

describe('CybersecurityAgent', () => {
  it('handleQuery returns RAG result when available', async () => {
    const agent = new CybersecurityAgent();
    ragDatabase.initialized = true;
    const searchSpy = vi
      .spyOn(ragDatabase, 'search')
      .mockResolvedValue([{ content: 'RAG info', similarity: 0.9 }] as any);
    const ensureSpy = vi
      .spyOn(ragDatabase, 'ensureInitialized')
      .mockResolvedValue();
    const res = await agent.handleQuery('CVE-2020-1234');
    expect(searchSpy).toHaveBeenCalled();
    expect(res.text).toContain('RAG info');
    searchSpy.mockRestore();
    ensureSpy.mockRestore();
  });
});
