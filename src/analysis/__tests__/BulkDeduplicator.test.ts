import { describe, it, expect, vi, beforeEach } from 'vitest';
import BulkDeduplicator from '../BulkDeduplicator';
import { generateAIAnalysis } from '../../services/AIEnhancementService';

vi.mock('../../services/AIEnhancementService', () => ({
  generateAIAnalysis: vi.fn().mockResolvedValue('AI conflict note')
}));

const sample = (id: string, score: number, exploited: boolean) => ({
  cve: { id, cvssV3: { baseScore: score } },
  exploits: { found: exploited }
}) as any;

describe('BulkDeduplicator conflict detection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('flags conflicts and calls AI analysis', async () => {
    const entries = [sample('CVE-1', 5, false), sample('CVE-1', 9, true)];
    const result = await BulkDeduplicator.deduplicate(entries, { aiProvider: 'mock' });
    expect(result).toHaveLength(1);
    expect(result[0].conflictNote).toBe('AI conflict note');
    expect(generateAIAnalysis).toHaveBeenCalledOnce();
    const callArgs = (generateAIAnalysis as any).mock.calls[0][0];
    expect(callArgs.primary).toBe(entries[0]);
    expect(callArgs.duplicate).toBe(entries[1]);
  });

  it('does not call AI when no significant differences', async () => {
    const entries = [sample('CVE-2', 5, false), sample('CVE-2', 5.2, false)];
    const result = await BulkDeduplicator.deduplicate(entries, { aiProvider: 'mock' });
    expect(result[0].conflictNote).toBeUndefined();
    expect(generateAIAnalysis).not.toHaveBeenCalled();
  });
});
